package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5 D4: one elected validator records each V8.2 anchor's outcome, write-once; an outcome already recorded is success
// when it is this validator's own derivation and a named contradiction when it is not.

func TestTheOutcomeRecorderElectionIsTheSameOnEveryValidator(t *testing.T) {
	bundle := common.HexToHash("0x692571219ee830e0374679ac99f960fbfee00be2c2f1ecb24da15ccc0137d736")
	sum := sha256.Sum256([]byte("certen:outcome:v1|11155111|692571219ee830e0374679ac99f960fbfee00be2c2f1ecb24da15ccc0137d736"))
	want := int(uint64(binary.BigEndian.Uint32(sum[:4])) % 7)
	if got := OutcomeLeaderIndex(11155111, bundle, 7); got != want {
		t.Fatalf("leader index %d, want %d", got, want)
	}
	if OutcomeLeaderIndex(84532, bundle, 7) == OutcomeLeaderIndex(11155111, bundle, 7) &&
		OutcomeLeaderIndex(421614, bundle, 7) == OutcomeLeaderIndex(11155111, bundle, 7) {
		t.Fatal("the chain is not in the election key")
	}
	roster := consensus.BatchLeaderRoster()
	resolved := time.Unix(1_790_000_000, 0)
	first := OutcomeRecorderFor(roster, 11155111, bundle, resolved, resolved.Add(time.Minute), OutcomeFailoverAfter)
	if first != roster[want] {
		t.Fatalf("the first recorder is %s, want %s", first, roster[want])
	}
	// Each failover interval past the resolving block hands the record to the next roster validator, on every clock alike.
	for k := 1; k <= 8; k++ {
		at := resolved.Add(time.Duration(k)*OutcomeFailoverAfter + time.Second)
		if got := OutcomeRecorderFor(roster, 11155111, bundle, resolved, at, OutcomeFailoverAfter); got != roster[(want+k)%7] {
			t.Fatalf("after %d intervals the recorder is %s, want %s", k, got, roster[(want+k)%7])
		}
	}
}

// recorderChain is a fakeOutcomeReader whose anchor views can change between reads, with the record transaction a
// pass reads once the registry records an outcome.
type recorderChain struct {
	*fakeOutcomeReader
	mu       sync.Mutex
	views    []OutcomeAnchorView // served in turn before the static view
	recorded *RecordedOutcomeTx
}

func (c *recorderChain) AnchorView(ctx context.Context, b [32]byte) (*OutcomeAnchorView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.views) > 0 {
		v := c.views[0]
		c.views = c.views[1:]
		return &v, nil
	}
	return c.fakeOutcomeReader.AnchorView(ctx, b)
}

func (c *recorderChain) RecordedOutcome(context.Context, [32]byte, uint64) (*RecordedOutcomeTx, error) {
	if c.recorded == nil {
		return nil, outcomeNotYet("no record")
	}
	return c.recorded, nil
}

type fakeOutcomeSubmitter struct {
	registry map[string]consensus.ValidatorRegistryEntry
	sub      *OutcomeSubmission
	err      error
	calls    int
	agg      *consensus.QuorumAggregate
}

func (f *fakeOutcomeSubmitter) ValidatorRegistry(context.Context, int64) (map[string]consensus.ValidatorRegistryEntry, error) {
	return f.registry, nil
}

func (f *fakeOutcomeSubmitter) Submit(_ context.Context, _ int64, _ common.Address, _, _ [32]byte, agg *consensus.QuorumAggregate, msg [32]byte) (*OutcomeSubmission, error) {
	f.calls++
	f.agg = agg
	if f.sub == nil {
		return nil, f.err
	}
	s := *f.sub
	s.Proof = contracts.CertenAnchorV4BLSProofData{AggregateSignature: []byte{0x9}, TotalVotingPower: agg.TotalVotingPower,
		SignedVotingPower: agg.SignedVotingPower, MessageHash: msg}
	for i, a := range agg.Signers {
		s.Proof.ValidatorAddresses = append(s.Proof.ValidatorAddresses, common.HexToAddress(a))
		s.Proof.VotingPowers = append(s.Proof.VotingPowers, agg.SignerPowers[i])
	}
	return &s, f.err
}

type memRecords struct {
	mu   sync.Mutex
	rows map[string]*database.BatchOutcomeRecord
}

func (m *memRecords) RecordBatchOutcome(_ context.Context, rec *database.BatchOutcomeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]*database.BatchOutcomeRecord{}
	}
	if old := m.rows[rec.BundleID]; old != nil && old.EvidenceSource == database.BatchOutcomeEvidenceRecorder {
		return nil
	}
	m.rows[rec.BundleID] = rec
	return nil
}

func (m *memRecords) BatchOutcome(_ context.Context, _ int64, b string) (*database.BatchOutcomeRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[b], nil
}

func (m *memRecords) AttestedAnchorsWithoutOutcome(context.Context, int64, int) ([]string, error) {
	return nil, nil
}

type recorderFixture struct {
	rec      *BatchOutcomeRecorder
	chain    *recorderChain
	sub      *fakeOutcomeSubmitter
	records  *memRecords
	kept     *OutcomeTree
	derived  *DerivedOutcome
	peerSeen *int
}

// newRecorderFixture is validator-1 holding a resolved two-member tree, with one peer (validator-2) that holds the same
// tree, in a three-validator registry where two signers are a quorum.
func newRecorderFixture(t *testing.T, elected bool) *recorderFixture {
	t.Helper()
	peer, reader, kept, _ := peerFixture(t)
	chain := &recorderChain{fakeOutcomeReader: reader}
	derived, err := DeriveOutcome(context.Background(), reader, kept, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]*bls.PrivateKey, 3)
	registry := map[string]consensus.ValidatorRegistryEntry{}
	for i := range keys {
		sk, _, err := bls.GenerateKeyPairFromSeed(bytes.Repeat([]byte{byte(10 + i)}, 32))
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = sk
		addr := fmt.Sprintf("0x%040x", i+1)
		registry[addr] = consensus.ValidatorRegistryEntry{EVMAddress: addr, PublicKeyHex: sk.PublicKey().Hex(), VotingPower: big.NewInt(100)}
	}
	peer.Key = func() *bls.PrivateKey { return keys[1] }
	seen := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OutcomeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		seen++
		_ = json.NewEncoder(w).Encode(peer.HandleOutcomeRequest(r.Context(), &req,
			BatchAttesterIdentity{ValidatorID: "validator-2", EVMAddress: fmt.Sprintf("0x%040x", 2)}))
	}))
	t.Cleanup(srv.Close)

	// The recorder's own kept tree, in its own store.
	own, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := own.Retain(kept); err != nil {
		t.Fatal(err)
	}
	roster := []string{"validator-1", "validator-2", "validator-3"}
	leader := roster[OutcomeLeaderIndex(84532, kept.BundleID, 3)]
	me := leader
	if !elected {
		me = roster[(OutcomeLeaderIndex(84532, kept.BundleID, 3)+1)%3]
	}
	sub := &fakeOutcomeSubmitter{registry: registry, sub: &OutcomeSubmission{Tx: "0x" + strings.Repeat("ab", 32), Block: 2100, Status: 1,
		Sender: fmt.Sprintf("0x%040x", 1)}}
	records := &memRecords{}
	rec := &BatchOutcomeRecorder{
		ValidatorID: me, Roster: func() []string { return roster }, Trees: own,
		Chains:     map[int64]OutcomeRecorderChain{84532: chain},
		Registries: map[int64]common.Address{84532: common.HexToAddress("0xd479841a17770D89Dae94B5b41C95D2117414c21")},
		Submitter:  sub, Records: records, Peers: []string{srv.URL},
		Key: func() *bls.PrivateKey { return keys[0] }, SetRoot: func() ([32]byte, error) { return peerSetRoot, nil },
		Timeout: 10 * time.Second, Now: func() time.Time { return derived.ResolvedAt.Add(time.Minute) },
	}
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	return &recorderFixture{rec: rec, chain: chain, sub: sub, records: records, kept: kept, derived: derived, peerSeen: &seen}
}

func TestTheElectedRecorderRecordsTheQuorumsOutcomeAndStoresItsEvidence(t *testing.T) {
	f := newRecorderFixture(t, true)
	steps := f.rec.Pass(context.Background())
	if steps[f.kept.BundleID] != OutcomeStepSent || f.sub.calls != 1 {
		t.Fatalf("step %s, %d submission(s)", steps[f.kept.BundleID], f.sub.calls)
	}
	if f.sub.agg.SignedVotingPower.Int64() != 200 || len(f.sub.agg.Signers) != 2 {
		t.Fatalf("the quorum folded %s power from %v", f.sub.agg.SignedVotingPower, f.sub.agg.Signers)
	}
	row := f.records.rows[hex32(f.kept.BundleID)]
	if row == nil || row.EvidenceSource != database.BatchOutcomeEvidenceRecorder || row.OutcomeRoot != hex32(f.derived.Root) ||
		len(row.Leaves) != 2 || row.AggregateSignature == "" || row.RecordBlock != 2100 {
		t.Fatalf("stored %+v", row)
	}
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, f.kept.BundleID, f.derived.Root, peerSetRoot, f.kept.AccumulateSetRoot, f.kept.Incarnation)
	if row.MessageHash != hex32(msg) {
		t.Fatalf("the stored message %s is not the outcome message %s", row.MessageHash, hex32(msg))
	}
}

func TestAValidatorNotElectedSendsNothing(t *testing.T) {
	f := newRecorderFixture(t, false)
	if steps := f.rec.Pass(context.Background()); steps[f.kept.BundleID] != OutcomeStepNotElected || f.sub.calls != 0 || *f.peerSeen != 0 {
		t.Fatalf("step %s, %d submission(s), %d peer request(s)", steps[f.kept.BundleID], f.sub.calls, *f.peerSeen)
	}
}

func TestAnOutcomeAlreadyRecordedEquallyIsSuccessAndReleasesTheTree(t *testing.T) {
	f := newRecorderFixture(t, true)
	f.chain.view.RecordedRoot, f.chain.view.RecordedIn = f.derived.Root, 1990 // final: at or below the finalized 2000
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, f.kept.BundleID, f.derived.Root, peerSetRoot, f.kept.AccumulateSetRoot, f.kept.Incarnation)
	f.chain.recorded = &RecordedOutcomeTx{BundleID: f.kept.BundleID, Tx: common.HexToHash("0xcc"), Block: 1990,
		Recorder: common.HexToAddress("0x03"), Root: f.derived.Root, MessageHash: msg,
		Proof: contracts.CertenAnchorV4BLSProofData{AggregateSignature: []byte{1}, ValidatorAddresses: []common.Address{common.HexToAddress("0x03"), common.HexToAddress("0x02")},
			VotingPowers: []*big.Int{big.NewInt(100), big.NewInt(100)}, TotalVotingPower: big.NewInt(300), SignedVotingPower: big.NewInt(200), MessageHash: msg}}
	steps := f.rec.Pass(context.Background())
	if steps[f.kept.BundleID] != OutcomeStepReleased || f.sub.calls != 0 {
		t.Fatalf("step %s, %d submission(s)", steps[f.kept.BundleID], f.sub.calls)
	}
	if row := f.records.rows[hex32(f.kept.BundleID)]; row == nil || row.EvidenceSource != database.BatchOutcomeEvidenceChain ||
		row.RecordTx != strings.ToLower(common.HexToHash("0xcc").Hex()) || row.AggregateSignature != "" {
		t.Fatalf("the record rebuilt from the chain: %+v", row)
	}
	if _, err := f.rec.Trees.Load(84532, f.kept.BundleID); !errors.Is(err, ErrOutcomeTreeNotHeld) {
		t.Fatalf("the tree of a final record was not released: %v", err)
	}
}

func TestARecordNotFinalYetKeepsTheTree(t *testing.T) {
	f := newRecorderFixture(t, true)
	f.chain.view.RecordedRoot, f.chain.view.RecordedIn = f.derived.Root, 2050 // above the finalized 2000
	msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, f.kept.BundleID, f.derived.Root, peerSetRoot, f.kept.AccumulateSetRoot, f.kept.Incarnation)
	f.chain.recorded = &RecordedOutcomeTx{BundleID: f.kept.BundleID, Tx: common.HexToHash("0xcc"), Block: 2050, Root: f.derived.Root,
		MessageHash: msg, Proof: contracts.CertenAnchorV4BLSProofData{AggregateSignature: []byte{1}, ValidatorAddresses: []common.Address{{1}},
			VotingPowers: []*big.Int{big.NewInt(200)}, TotalVotingPower: big.NewInt(300), SignedVotingPower: big.NewInt(200), MessageHash: msg}}
	if steps := f.rec.Pass(context.Background()); steps[f.kept.BundleID] != OutcomeStepRecorded {
		t.Fatalf("step %s", steps[f.kept.BundleID])
	}
	if _, err := f.rec.Trees.Load(84532, f.kept.BundleID); err != nil {
		t.Fatalf("the tree of a record not yet final was released: %v", err)
	}
}

func TestADifferentRecordedOutcomeIsANamedContradictionAndNothingIsSent(t *testing.T) {
	f := newRecorderFixture(t, true)
	var logged []string
	f.rec.Logf = func(format string, a ...interface{}) { logged = append(logged, fmt.Sprintf(format, a...)) }
	f.chain.view.RecordedRoot, f.chain.view.RecordedIn = [32]byte{0x66}, 1990
	if steps := f.rec.Pass(context.Background()); steps[f.kept.BundleID] != OutcomeStepContradiction || f.sub.calls != 0 {
		t.Fatalf("step %s, %d submission(s)", steps[f.kept.BundleID], f.sub.calls)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "CONTRADICTION") {
		t.Fatalf("not alarmed by name: %v", logged)
	}
	if _, err := f.rec.Trees.Load(84532, f.kept.BundleID); err != nil {
		t.Fatalf("the evidence of a contradiction was released: %v", err)
	}
	if len(f.records.rows) != 0 {
		t.Fatal("a contradicted record was stored")
	}
}

func TestTheRegistrysRefusalsAreHandledByName(t *testing.T) {
	t.Run("already recorded, by another validator, the same root", func(t *testing.T) {
		f := newRecorderFixture(t, true)
		msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, f.kept.BundleID, f.derived.Root, peerSetRoot, f.kept.AccumulateSetRoot, f.kept.Incarnation)
		recorded := *f.chain.view.Anchor
		after := f.chain.view
		after.Anchor, after.RecordedRoot, after.RecordedIn = &recorded, f.derived.Root, 2050
		// The pass reads: once to decide, once before sending; the refusal's re-read finds the record.
		f.chain.views = []OutcomeAnchorView{f.chain.view, f.chain.view, after, after}
		f.sub.sub, f.sub.err = &OutcomeSubmission{RevertName: "OutcomeAlreadyRecorded"}, errors.New("execution reverted")
		f.chain.recorded = &RecordedOutcomeTx{BundleID: f.kept.BundleID, Tx: common.HexToHash("0xcd"), Block: 2050, Root: f.derived.Root,
			MessageHash: msg, Proof: contracts.CertenAnchorV4BLSProofData{AggregateSignature: []byte{1}, ValidatorAddresses: []common.Address{{2}},
				VotingPowers: []*big.Int{big.NewInt(200)}, TotalVotingPower: big.NewInt(300), SignedVotingPower: big.NewInt(200), MessageHash: msg}}
		if steps := f.rec.Pass(context.Background()); steps[f.kept.BundleID] != OutcomeStepRecorded {
			t.Fatalf("step %s", steps[f.kept.BundleID])
		}
	})
	t.Run("quorum invalid because the set root moved", func(t *testing.T) {
		f := newRecorderFixture(t, true)
		moved := f.chain.view
		moved.CurrentSetRoot = [32]byte{0x01}
		f.chain.views = []OutcomeAnchorView{f.chain.view, f.chain.view, moved}
		f.sub.sub, f.sub.err = &OutcomeSubmission{RevertName: "QuorumAttestationInvalid"}, errors.New("execution reverted")
		steps := f.rec.Pass(context.Background())
		if steps[f.kept.BundleID] != OutcomeStepNoQuorum {
			t.Fatalf("step %s", steps[f.kept.BundleID])
		}
	})
	t.Run("quorum invalid under the same set root", func(t *testing.T) {
		f := newRecorderFixture(t, true)
		f.sub.sub, f.sub.err = &OutcomeSubmission{RevertName: "QuorumAttestationInvalid"}, errors.New("execution reverted")
		if steps := f.rec.Pass(context.Background()); steps[f.kept.BundleID] != OutcomeStepFailed {
			t.Fatalf("step %s", steps[f.kept.BundleID])
		}
	})
	t.Run("the set root moved while the quorum signed", func(t *testing.T) {
		f := newRecorderFixture(t, true)
		moved := f.chain.view
		moved.CurrentSetRoot = [32]byte{0x01}
		f.chain.views = []OutcomeAnchorView{f.chain.view, moved}
		if steps := f.rec.Pass(context.Background()); steps[f.kept.BundleID] != OutcomeStepNoQuorum || f.sub.calls != 0 {
			t.Fatalf("step %s, %d submission(s)", steps[f.kept.BundleID], f.sub.calls)
		}
	})
	t.Run("a reverted receipt after another validator's record landed", func(t *testing.T) {
		f := newRecorderFixture(t, true)
		msg := contracts.ComputeEvmMessageHashV8_2_Outcome(84532, f.kept.BundleID, f.derived.Root, peerSetRoot, f.kept.AccumulateSetRoot, f.kept.Incarnation)
		after := f.chain.view
		after.RecordedRoot, after.RecordedIn = f.derived.Root, 2050
		f.chain.views = []OutcomeAnchorView{f.chain.view, f.chain.view, after}
		f.sub.sub.Status = 0
		f.chain.recorded = &RecordedOutcomeTx{BundleID: f.kept.BundleID, Tx: common.HexToHash("0xce"), Block: 2050, Root: f.derived.Root,
			MessageHash: msg, Proof: contracts.CertenAnchorV4BLSProofData{AggregateSignature: []byte{1}, ValidatorAddresses: []common.Address{{2}},
				VotingPowers: []*big.Int{big.NewInt(200)}, TotalVotingPower: big.NewInt(300), SignedVotingPower: big.NewInt(200), MessageHash: msg}}
		if steps := f.rec.Pass(context.Background()); steps[f.kept.BundleID] != OutcomeStepRecorded {
			t.Fatalf("step %s", steps[f.kept.BundleID])
		}
	})
}

func TestARecorderMissingAPieceIsRefused(t *testing.T) {
	if err := (&BatchOutcomeRecorder{}).Validate(); err == nil || !strings.Contains(err.Error(), "submitter") {
		t.Fatalf("%v", err)
	}
}

// The calldata a record transaction carries decodes to the proof it submitted.
func TestARecordTransactionsCalldataDecodes(t *testing.T) {
	proof := contracts.CertenAnchorV4BLSProofData{AggregateSignature: []byte{1, 2}, ValidatorAddresses: []common.Address{{1}, {2}},
		VotingPowers: []*big.Int{big.NewInt(100), big.NewInt(100)}, TotalVotingPower: big.NewInt(300), SignedVotingPower: big.NewInt(200),
		ThresholdMet: true, MessageHash: [32]byte{3}}
	data, err := outcomeRegistryABI.Pack("recordBatchOutcome", [32]byte{4}, [32]byte{5}, proof)
	if err != nil {
		t.Fatal(err)
	}
	b, r, got, err := decodeRecordBatchOutcome(data)
	if err != nil || b != ([32]byte{4}) || r != ([32]byte{5}) || got.SignedVotingPower.Int64() != 200 || len(got.ValidatorAddresses) != 2 ||
		got.MessageHash != ([32]byte{3}) {
		t.Fatalf("(%x, %x, %+v, %v)", b, r, got, err)
	}
	if _, _, _, err := decodeRecordBatchOutcome(data[:40]); err == nil {
		t.Fatal("truncated calldata decoded")
	}
}
