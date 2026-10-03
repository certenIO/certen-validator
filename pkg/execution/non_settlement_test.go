package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB3-F49: a member that never settled was recorded nowhere - its record was a proof cycle with no
// transaction, which the adapter refused. It is now attested by quorum: at a finalized block past the
// member's deadline its leaf is not consumed, which every peer checks from its OWN copy of the member.

type fakeNSChain struct {
	finalized uint64
	times     map[uint64]int64 // block -> time
	consumed  map[uint64]bool  // block -> leaf consumed there
	readErr   error
}

func (f *fakeNSChain) header(n uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(n), Time: uint64(f.times[n]), Extra: []byte{byte(n)}}
}
func (f *fakeNSChain) FinalizedHeader(context.Context, int64) (*types.Header, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return f.header(f.finalized), nil
}
func (f *fakeNSChain) HeaderAt(_ context.Context, _ int64, n uint64) (*types.Header, error) {
	return f.header(n), nil
}
func (f *fakeNSChain) LeafConsumedAt(_ context.Context, _ int64, _ common.Address, _ [32]byte, n uint64) (bool, error) {
	return f.consumed[n], nil
}

// nsMember is a member whose deadline is commit + 1h (no declared leg deadline).
var nsCommit = time.Unix(1_800_000_000, 0).UTC()

var odChainStr = strconv.FormatInt(odChain, 10)

func nsMember() *PendingBatchIntent {
	p := odMember(1, odChain, 100)
	p.CommitTime = nsCommit
	return certifiedForTest(p)
}

func nsChainPast(deadline time.Time) *fakeNSChain {
	return &fakeNSChain{finalized: 500, times: map[uint64]int64{500: deadline.Add(nonSettlementFinality + time.Minute).Unix()}, consumed: map[uint64]bool{}}
}

func TestNonSettlement_NotAttestableBeforeItsDeadline(t *testing.T) {
	f, _ := memberFacts(nsMember())
	c := &fakeNSChain{finalized: 500, times: map[uint64]int64{500: f.Deadline.Unix()}, consumed: map[uint64]bool{}}
	if _, _, err := observeNonSettlement(context.Background(), c, f, "dropped"); !errors.Is(err, errNotYetAttestable) {
		t.Fatalf("at the deadline itself a settlement may still land: %v", err)
	}
}

func TestNonSettlement_AConsumedLeafIsNotAFailure(t *testing.T) {
	f, _ := memberFacts(nsMember())
	c := nsChainPast(f.Deadline)
	c.consumed[500] = true
	if _, _, err := observeNonSettlement(context.Background(), c, f, "dropped"); !errors.Is(err, errMemberSettled) {
		t.Fatalf("a member whose leaf is consumed settled: %v", err)
	}
}

func nsMessage(t *testing.T, own *PendingBatchIntent, c NonSettlementChain) (*attestation.AttestationMessage, *NonSettlementClaim) {
	t.Helper()
	f, err := memberFacts(own)
	if err != nil {
		t.Fatal(err)
	}
	claim, obs, err := observeNonSettlement(context.Background(), c, f, "its account cannot take part")
	if err != nil {
		t.Fatal(err)
	}
	return &attestation.AttestationMessage{IntentID: own.IntentID, ResultHash: obs.ResultHash,
		TargetChain: odChainStr, ChainID: odChainStr, Timestamp: time.Now().Unix(), NonSettlement: claim}, claim
}

func TestNonSettlement_APeerReproducesTheClaimFromItsOwnMember(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	c := nsChainPast(f.Deadline)
	msg, _ := nsMessage(t, own, c)
	if err := verifyNonSettlementClaim(context.Background(), c, nsMember(), msg); err != nil {
		t.Fatalf("an honest claim was not reproduced: %v", err)
	}
}

func TestNonSettlement_APeerRefusesWhatItCannotReproduce(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	for name, tc := range map[string]struct {
		mutate func(*attestation.AttestationMessage, *fakeNSChain)
		peer   func() *PendingBatchIntent
	}{
		"a leaf that is not this member's": {func(m *attestation.AttestationMessage, _ *fakeNSChain) {
			m.NonSettlement.Leaf = common.Hash{9}.Hex()
		}, nsMember},
		"a member this validator holds differently": {func(*attestation.AttestationMessage, *fakeNSChain) {}, func() *PendingBatchIntent {
			p := nsMember()
			p.Legs[0].Value = big.NewInt(7)
			return p
		}},
		"a block not finalized here":     {func(_ *attestation.AttestationMessage, c *fakeNSChain) { c.finalized = 400 }, nsMember},
		"a leaf consumed at the block":   {func(_ *attestation.AttestationMessage, c *fakeNSChain) { c.consumed[500] = true }, nsMember},
		"a result hash over other facts": {func(m *attestation.AttestationMessage, _ *fakeNSChain) { m.ResultHash = [32]byte{1} }, nsMember},
		"a block that is not past the deadline": {func(m *attestation.AttestationMessage, c *fakeNSChain) {
			m.NonSettlement.Block, m.NonSettlement.BlockTime = 450, f.Deadline.Unix()
			c.times[450] = f.Deadline.Unix()
			m.NonSettlement.BlockHash = c.header(450).Hash().Hex()
			m.ResultHash = nonSettlementResultHash(m.NonSettlement)
		}, nsMember},
	} {
		t.Run(name, func(t *testing.T) {
			c := nsChainPast(f.Deadline)
			msg, _ := nsMessage(t, own, c)
			tc.mutate(msg, c)
			if err := verifyNonSettlementClaim(context.Background(), c, tc.peer(), msg); err == nil {
				t.Fatal("the peer signed a non-settlement it did not reproduce")
			}
		})
	}
}

func nsOrchestrator(t *testing.T, held *PendingBatchIntent, c NonSettlementChain) *UnifiedOrchestrator {
	t.Helper()
	q, err := OpenNonSettlementQueue(filepath.Join(t.TempDir(), "ns.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := strategy.NewRegistry()
	bls, err := attestation.NewBLSStrategyWithNewKey("validator-2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterAttestationStrategy(bls); err != nil {
		t.Fatal(err)
	}
	return &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{
		ValidatorID: "validator-2", Registry: reg, ObservationTimeout: time.Minute,
		MemberLookup: func(chainID int64, op [32]byte) (*PendingBatchIntent, bool) {
			if held != nil && chainID == held.ChainID && op == held.OperationID {
				c := *held
				return &c, true
			}
			return nil, false
		},
		NonSettlementChain: c, NonSettlements: q,
	}}
}

// The failure record reaches the queue instead of being refused for having no transaction.
func TestNonSettlement_AFailureRecordIsQueuedNotRefused(t *testing.T) {
	own := nsMember()
	o := nsOrchestrator(t, own, nsChainPast(nsCommit.Add(maxGasDeferral)))
	a := NewUnifiedOrchestratorAdapter(o)
	commitment := map[string]interface{}{
		"outcome": "failed", "reason": "no settlement transaction reached the target chain: dropped from its batch",
		"targetChain": odChainStr, "memberChains": []int64{odChain}, "memberLegs": 1,
		commitmentNonSettlementOperationID: common.Hash(own.OperationID).Hex(), "proofClass": "on_demand",
	}
	err := a.StartProofCycleWithAccumulateRef(context.Background(), own.IntentID, "", [32]byte{},
		&struct{ RawTxHashes []string }{}, commitment, "acc://x.acme/data", "tx", "")
	if err != nil {
		t.Fatalf("the failure record was refused: %v", err)
	}
	recs := o.config.NonSettlements.All()
	if len(recs) != 1 || recs[0].Facts.IntentID != own.IntentID || !strings.Contains(recs[0].Cause, "dropped") || recs[0].ProofClass != "on_demand" {
		t.Fatalf("queued %+v", recs)
	}
}

// A peer signs a non-settlement it reproduces, through the Phase 8 handler.
func TestNonSettlement_PeerHandlerSignsAReproducedClaim(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	c := nsChainPast(f.Deadline)
	o := nsOrchestrator(t, own, c)
	msg, _ := nsMessage(t, own, c)
	resp, err := o.HandlePeerAttestationRequest(context.Background(), &PeerAttestationRequest{
		CycleID: "c", Message: msg, Scheme: attestation.AttestationSchemeBLS12381, RequestingID: "validator-1"})
	if err != nil || !resp.Success || resp.Attestation == nil {
		t.Fatalf("resp %+v err %v", resp, err)
	}
	// Not holding the member, it refuses.
	o2 := nsOrchestrator(t, nil, c)
	resp, _ = o2.HandlePeerAttestationRequest(context.Background(), &PeerAttestationRequest{
		CycleID: "c", Message: msg, Scheme: attestation.AttestationSchemeBLS12381, RequestingID: "validator-1"})
	if resp.Success || !strings.Contains(resp.Error, "not held") {
		t.Fatalf("a peer without the member signed: %+v", resp)
	}
}

// The queue: kept until attestable, withdrawn if the member turns out settled.
func TestNonSettlement_ProcessingKeepsWithdrawsAndSurvivesRestart(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	c := &fakeNSChain{finalized: 100, times: map[uint64]int64{100: f.Deadline.Unix() - 60}, consumed: map[uint64]bool{}}
	o := nsOrchestrator(t, own, c)
	if err := o.config.NonSettlements.Put(&NonSettlementRecord{Facts: f, Cause: "dropped", QueuedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	o.processNonSettlements(context.Background())
	if n := len(o.config.NonSettlements.All()); n != 1 {
		t.Fatalf("a record not yet attestable was not kept: %d", n)
	}
	reopened, err := OpenNonSettlementQueue(o.config.NonSettlements.path)
	if err != nil || len(reopened.All()) != 1 {
		t.Fatalf("the record did not survive a restart: %v", err)
	}
	c.finalized, c.times[600], c.consumed[600] = 600, f.Deadline.Add(time.Hour).Unix(), true
	o.processNonSettlements(context.Background())
	if n := len(o.config.NonSettlements.All()); n != 0 {
		t.Fatalf("a member that settled after all still has a failure record: %d", n)
	}
}

// The write-back of a non-settlement says so, after every positional entry; a settlement's is unchanged.
func TestNonSettlement_WriteBackStatesTheOutcome(t *testing.T) {
	plain := (&CertenDataEntry{EntryType: "x", Version: "2.0"}).ToDoubleHashFormat()
	ns := (&CertenDataEntry{EntryType: "x", Version: "2.0", Outcome: ResultOutcomeNotSettled, OutcomeReason: "dropped"}).ToDoubleHashFormat()
	if len(ns) != len(plain)+2 {
		t.Fatalf("entries %d vs %d", len(ns), len(plain))
	}
	if string(ns[len(ns)-2]) != "outcome=not_settled" || string(ns[len(ns)-1]) != "outcome_reason=dropped" {
		t.Fatalf("tail %q %q", ns[len(ns)-2], ns[len(ns)-1])
	}
	for i := range plain {
		if string(plain[i]) != string(ns[i]) {
			t.Fatalf("entry %d moved: %q vs %q", i, plain[i], ns[i])
		}
	}
}

// End to end through Phase 8: a requester and three peers, each verifying from its own copy of the
// member and its own chain reads, reach the registry quorum over the non-settlement.
func TestNonSettlement_IsAttestedByTheRegistryQuorum(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	c := nsChainPast(f.Deadline)

	nodes := make([]*UnifiedOrchestrator, 4)
	keys := make([]*attestation.BLSStrategy, 4)
	registry := map[string]consensus.ValidatorRegistryEntry{}
	for i := range nodes {
		nodes[i] = nsOrchestrator(t, own, c)
		s, _ := nodes[i].config.Registry.GetAttestationStrategy(attestation.AttestationSchemeBLS12381)
		keys[i] = s.(*attestation.BLSStrategy)
		addr := fmt.Sprintf("0x%040x", i+1)
		registry[addr] = consensus.ValidatorRegistryEntry{EVMAddress: addr, PublicKeyHex: hex.EncodeToString(keys[i].PublicKey()), VotingPower: big.NewInt(100)}
	}
	var peers []string
	for _, p := range nodes[1:] {
		peer := p
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req PeerAttestationRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp, _ := peer.HandlePeerAttestationRequest(r.Context(), &req)
			_ = json.NewEncoder(w).Encode(resp)
		}))
		t.Cleanup(srv.Close)
		peers = append(peers, srv.URL)
	}
	req := nodes[0]
	req.config.AttestationPeers = peers
	req.config.AttestationTimeout = 10 * time.Second
	req.config.ResultQuorumRegistry = func(context.Context, string) (map[string]consensus.ValidatorRegistryEntry, error) {
		return registry, nil
	}
	req.config.ThresholdConfig = attestation.DefaultThresholdConfig()
	req.httpClient = &http.Client{Timeout: 10 * time.Second}

	claim, obs, err := observeNonSettlement(context.Background(), c, f, "its batch quorum was never reached")
	if err != nil {
		t.Fatal(err)
	}
	rec := &NonSettlementRecord{Facts: f, Cause: claim.Cause, MemberChains: []int64{odChain}, MemberLegs: 1}
	cycle := nonSettlementCycle(rec, claim)
	cycle.Result.ObservationResults = []*chain.ObservationResult{obs}
	if err := req.executePhase8(context.Background(), cycle, keys[0]); err != nil {
		t.Fatal(err)
	}
	if !cycle.Result.ThresholdMet || cycle.Result.AggregatedAttestation.AchievedWeight != 400 {
		t.Fatalf("threshold met %v, achieved %d of 400", cycle.Result.ThresholdMet, cycle.Result.AggregatedAttestation.AchievedWeight)
	}
}

// RB3-F74: a cycle that names no settlement lane is refused, not labelled "on_demand".
func TestAdapterRefusesACycleThatNamesNoLane(t *testing.T) {
	own := nsMember()
	o := nsOrchestrator(t, own, nsChainPast(nsCommit.Add(maxGasDeferral)))
	a := NewUnifiedOrchestratorAdapter(o)
	for _, commitment := range []map[string]interface{}{
		{"targetChain": odChainStr, "memberChains": []int64{odChain}, "memberLegs": 1},
		{"targetChain": odChainStr, "memberChains": []int64{odChain}, "memberLegs": 1, "proofClass": "urgent"},
		{"outcome": "failed", "reason": "dropped", "targetChain": odChainStr, "memberChains": []int64{odChain}, "memberLegs": 1,
			commitmentNonSettlementOperationID: common.Hash(own.OperationID).Hex()},
	} {
		err := a.StartProofCycleWithAccumulateRef(context.Background(), own.IntentID, "", [32]byte{1},
			&struct{ RawTxHashes []string }{RawTxHashes: []string{"0x" + strings.Repeat("ab", 32)}}, commitment, "acc://x.acme/data", "tx", "")
		if err == nil || !strings.Contains(err.Error(), "names no settlement lane") {
			t.Fatalf("commitment %v: %v", commitment, err)
		}
	}
}

// RB5-F46: the claim is pinned at the block it was first observed at. A peer whose view of the chain trails the
// requester's - one load-balanced endpoint whose backends disagree on the finalized head - reaches that block and
// reproduces the claim, instead of refusing a claim that moves to the requester's newest finalized block on every
// attempt (intent bb72e258, 2026-10-02: claimed at 47608254, the peers finalized at 47608085).
func TestNonSettlement_TheClaimIsPinnedAtItsFirstBlock(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	past := f.Deadline.Add(nonSettlementFinality + time.Minute).Unix()
	requester := &fakeNSChain{finalized: 500, times: map[uint64]int64{500: past, 600: past + 1200}, consumed: map[uint64]bool{}}
	first, _, err := observeNonSettlementAt(context.Background(), requester, f, "dropped", 0)
	if err != nil || first.Block != 500 {
		t.Fatalf("first observation: %+v %v", first, err)
	}
	// The requester's backend moves on; the claim does not.
	requester.finalized = 600
	again, obs, err := observeNonSettlementAt(context.Background(), requester, f, "dropped", first.Block)
	if err != nil || again.Block != 500 || again.BlockHash != first.BlockHash || again.BlockTime != first.BlockTime {
		t.Fatalf("a later attempt moved the claim: %+v %v", again, err)
	}
	// A peer whose backend has finalized only 520 reproduces the pinned claim; it would refuse one at 600.
	peer := &fakeNSChain{finalized: 520, times: requester.times, consumed: map[uint64]bool{}}
	msg := &attestation.AttestationMessage{IntentID: own.IntentID, ResultHash: obs.ResultHash, TargetChain: odChainStr,
		ChainID: odChainStr, Timestamp: time.Now().Unix(), NonSettlement: again}
	if err := verifyNonSettlementClaim(context.Background(), peer, own, msg); err != nil {
		t.Fatalf("a trailing peer refused the pinned claim: %v", err)
	}
	moved, mobs, err := observeNonSettlementAt(context.Background(), requester, f, "dropped", 0)
	if err != nil {
		t.Fatal(err)
	}
	if verifyNonSettlementClaim(context.Background(), peer, own, &attestation.AttestationMessage{IntentID: own.IntentID,
		ResultHash: mobs.ResultHash, TargetChain: odChainStr, ChainID: odChainStr, Timestamp: time.Now().Unix(),
		NonSettlement: moved}) == nil {
		t.Fatal("the trailing peer reproduced a claim at a block it has not finalized")
	}
	// A pinned block this node has not finalized yet is waited for, not replaced.
	requester.finalized = 400
	if _, _, err := observeNonSettlementAt(context.Background(), requester, f, "dropped", 500); !errors.Is(err, errNotYetAttestable) {
		t.Fatalf("a pinned block not finalized here: %v", err)
	}
}

// The pin is durable: the first observation stores it on the record, and a restart keeps it.
func TestNonSettlement_ThePinSurvivesARestart(t *testing.T) {
	own := nsMember()
	f, _ := memberFacts(own)
	c := nsChainPast(f.Deadline)
	o := nsOrchestrator(t, own, c)
	if err := o.config.NonSettlements.Put(&NonSettlementRecord{Facts: f, Cause: "dropped", QueuedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	o.processNonSettlements(context.Background()) // no peers here: the cycle fails and the record is retried
	reopened, err := OpenNonSettlementQueue(o.config.NonSettlements.path)
	if err != nil {
		t.Fatal(err)
	}
	recs := reopened.All()
	if len(recs) != 1 || recs[0].ClaimBlock != 500 {
		t.Fatalf("the claim block was not kept across a restart: %+v", recs)
	}
}
