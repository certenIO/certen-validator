package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/database"
)

// The quorum a batch anchor carries was computed and discarded: prove() returned only `error`, so
// anchor_batches' Phase 5 columns were never written by any live path (70,236 rows, zero with
// quorum_reached) and proofs_service reported batch_quorum_met=false for every intent — including anchors
// that reached 7 of 7 voting power on-chain.
//
// These tests pin the evidence path: what is recorded is exactly what was proven, nothing is invented for
// a missing field, and the writer never blocks the prover or overwrites a disagreement.

func evidenceFixture() *AnchorQuorumEvidence {
	var bundle, root, opID, msg, setRoot [32]byte
	copy(bundle[:], mustHex("2fd899ae1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6"))
	copy(root[:], mustHex("d1c58b0d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80910203"))
	copy(opID[:], mustHex("0a0b0c0d0e0f1011121314151617181920212223242526272829303132333435"))
	copy(msg[:], mustHex("a1cdbb96d8a5a1d6000000000000000000000000000000000000000000000000"))
	copy(setRoot[:], mustHex("a85a6911183f5085000000000000000000000000000000000000000000000000"))

	var memberOp [32]byte
	copy(memberOp[:], mustHex("f6cea77e00000000000000000000000000000000000000000000000000000000"))
	var leaf, sibling [32]byte
	copy(leaf[:], mustHex("1111111111111111111111111111111111111111111111111111111111111111"))
	copy(sibling[:], mustHex("2222222222222222222222222222222222222222222222222222222222222222"))

	return &AnchorQuorumEvidence{
		ChainID:               84532,
		BundleID:              bundle,
		Root:                  root,
		BatchOperationID:      opID,
		MessageHash:           msg,
		SetRoot:               setRoot,
		VerifyTx:              "0x9e4ff6ab00000000000000000000000000000000000000000000000000000000",
		AggregateSignatureHex: "0xabcdef",
		AggregatePublicKeyHex: "0x123456",
		Signers:               []string{"0xaaa", "0xbbb", "0xccc"},
		SignerPowers:          []*big.Int{big.NewInt(100), big.NewInt(100), big.NewInt(100)},
		SignedVotingPower:     big.NewInt(300),
		TotalVotingPower:      big.NewInt(700),
		Lane:                  AnchorLaneOnDemand,
		AttestedAt:            time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		Members: []AnchorQuorumMember{{
			IntentID:    "f6cea77e-0000-0000-0000-000000000000",
			OperationID: memberOp,
			ADIURL:      "acc://fictional-payer.acme",
			Leaf:        leaf,
			LeafIndex:   0,
			Branch:      [][32]byte{sibling},
			Provenance: MemberProvenance{
				AccumTxHash: "3e595d2c526dfacb5e332cd11f4f0306d2648cf1291bed63a9bcfd6ef44a7a12",
				FromChain:   "accumulate",
				ToChain:     "base-sepolia",
			},
		}},
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestAnchorQuorumRecordCarriesWhatWasProven(t *testing.T) {
	ev := evidenceFixture()
	rec := AnchorQuorumRecordFrom(ev)

	if rec.ChainID != 84532 {
		t.Fatalf("chain id = %d", rec.ChainID)
	}
	if rec.BundleID != "0x"+hex.EncodeToString(ev.BundleID[:]) {
		t.Fatalf("bundle id = %s", rec.BundleID)
	}
	if hex.EncodeToString(rec.Root) != hex.EncodeToString(ev.Root[:]) {
		t.Fatalf("root = %x", rec.Root)
	}
	if rec.EvidenceSource != "live" || rec.Lane != AnchorLaneOnDemand {
		t.Fatalf("source=%s lane=%s", rec.EvidenceSource, rec.Lane)
	}
	if rec.VerifyTx != ev.VerifyTx || !rec.VerifiedAt.Equal(ev.AttestedAt) {
		t.Fatalf("verify tx/time not carried: %s %v", rec.VerifyTx, rec.VerifiedAt)
	}
	if rec.SignedVotingPower.Cmp(big.NewInt(300)) != 0 || rec.TotalVotingPower.Cmp(big.NewInt(700)) != 0 {
		t.Fatalf("voting power = %v / %v", rec.SignedVotingPower, rec.TotalVotingPower)
	}
	if len(rec.Signers) != 3 || rec.Signers[1].Address != "0xbbb" || rec.Signers[1].VotingPower.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("signers = %+v", rec.Signers)
	}
	if len(rec.Members) != 1 {
		t.Fatalf("members = %d", len(rec.Members))
	}
	m := rec.Members[0]
	if m.IntentID != "f6cea77e-0000-0000-0000-000000000000" || m.LeafIndex != 0 || len(m.Branch) != 1 {
		t.Fatalf("member = %+v", m)
	}
	if hex.EncodeToString(m.Leaf) != hex.EncodeToString(ev.Members[0].Leaf[:]) {
		t.Fatalf("member leaf = %x", m.Leaf)
	}
	// accumulate_tx_hash carries the ACCUMULATE TRANSACTION, not the operation id.
	//
	// This assertion previously required the opposite, which is how hex(operationID) came to sit in a
	// column named accumulate_tx_hash: the test encoded the defect, so the defect could not regress.
	// The operation id is still recorded — in OperationID, where it belongs.
	if m.AccumTxHash != ev.Members[0].Provenance.AccumTxHash {
		t.Fatalf("member accum tx = %q, want the Accumulate transaction %q",
			m.AccumTxHash, ev.Members[0].Provenance.AccumTxHash)
	}
	if m.OperationID != hexPrefixed(ev.Members[0].OperationID[:]) {
		t.Fatalf("member operation id = %q", m.OperationID)
	}
}

func TestAnchorQuorumRecordDoesNotInventMissingFields(t *testing.T) {
	ev := evidenceFixture()
	ev.AggregateSignatureHex = ""
	ev.AggregatePublicKeyHex = "not-hex"
	ev.SignerPowers = nil
	rec := AnchorQuorumRecordFrom(ev)

	if rec.AggregateSignature != nil || rec.AggregatePubKey != nil {
		t.Fatalf("absent/undecodable aggregate must stay absent: %x %x", rec.AggregateSignature, rec.AggregatePubKey)
	}
	for _, s := range rec.Signers {
		if s.VotingPower != nil {
			t.Fatalf("signer power invented: %+v", s)
		}
	}
	if AnchorQuorumRecordFrom(nil) != nil {
		t.Fatal("nil evidence must produce no record")
	}
}

// ─── writer ─────────────────────────────────────────────────────────────────────────────────────────

type fakeQuorumStore struct {
	mu       sync.Mutex
	calls    int
	records  []*database.AnchorQuorumRecord
	failN    int
	conflict bool
	// alreadyHeld reports the row as present without writing it — what every validator but the first sees.
	alreadyHeld bool
	gate        chan struct{}
}

func (f *fakeQuorumStore) RecordAnchorQuorum(ctx context.Context, rec *database.AnchorQuorumRecord) (bool, error) {
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.conflict {
		return false, &database.AnchorQuorumConflict{ChainID: rec.ChainID, BundleID: rec.BundleID}
	}
	if f.alreadyHeld {
		return false, nil
	}
	if f.failN > 0 {
		f.failN--
		return false, errors.New("fictional: database unavailable")
	}
	f.records = append(f.records, rec)
	return true, nil
}

func (f *fakeQuorumStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func waitForQuorum(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func startWriter(t *testing.T, store AnchorQuorumStore, queueCap int) *AnchorQuorumWriter {
	t.Helper()
	w := NewAnchorQuorumWriter(store, nil)
	if queueCap > 0 {
		w.queue = make(chan *database.AnchorQuorumRecord, queueCap)
	}
	w.retryBase, w.retryMax, w.callTimeout = time.Millisecond, 5*time.Millisecond, time.Second
	w.Start()
	t.Cleanup(w.Stop)
	return w
}

func TestWriterRecordsProvenEvidence(t *testing.T) {
	store := &fakeQuorumStore{}
	w := startWriter(t, store, 0)
	w.Hook()(context.Background(), evidenceFixture())

	waitForQuorum(t, "the record to be written", time.Second, func() bool { return len(store.records) == 1 })
	written, _, _, _, _ := w.Stats()
	if written != 1 {
		t.Fatalf("written = %d", written)
	}
	if store.records[0].EvidenceSource != "live" {
		t.Fatalf("source = %s", store.records[0].EvidenceSource)
	}
}

// The prover must never wait on the database: proving already costs a peer round trip, a transaction and a
// confirmation read, and a database outage must not stop anchors from being proven.
func TestHookNeverBlocksTheProver(t *testing.T) {
	store := &fakeQuorumStore{gate: make(chan struct{})} // never answers
	w := startWriter(t, store, 1)
	t.Cleanup(func() { close(store.gate) })

	hook := w.Hook()
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		for i := 0; i < 500; i++ {
			hook(context.Background(), evidenceFixture())
		}
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		if elapsed > 2*time.Second {
			t.Fatalf("hook took %v for 500 calls against a blocked database", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hook blocked on a database that never answers")
	}
	_, _, _, dropped, _ := w.Stats()
	if dropped == 0 {
		t.Fatal("expected refused hand-offs to be counted, not silently lost")
	}
}

func TestWriterRetriesTransportFailures(t *testing.T) {
	store := &fakeQuorumStore{failN: 3}
	w := startWriter(t, store, 0)
	w.Hook()(context.Background(), evidenceFixture())

	waitForQuorum(t, "the record after retries", 2*time.Second, func() bool { return len(store.records) == 1 })
	if store.count() != 4 {
		t.Fatalf("calls = %d, want 4 (3 failures + 1 success)", store.count())
	}
}

// A conflict is a disagreement about what the chain executed. Retrying cannot settle it, and overwriting
// would destroy the evidence that something is wrong.
func TestWriterNeverRetriesOrOverwritesAConflict(t *testing.T) {
	store := &fakeQuorumStore{conflict: true}
	w := startWriter(t, store, 0)
	w.Hook()(context.Background(), evidenceFixture())

	waitForQuorum(t, "the conflict to be counted", time.Second, func() bool {
		_, _, conflicts, _, _ := w.Stats()
		return conflicts == 1
	})
	time.Sleep(50 * time.Millisecond)
	if store.count() != 1 {
		t.Fatalf("calls = %d, want exactly 1 (no retry)", store.count())
	}
	if len(store.records) != 0 {
		t.Fatal("a conflict must not write a record")
	}
}

// ─── membership ─────────────────────────────────────────────────────────────────────────────────────

func TestMembersFromTreeCarryBranchesAndKnownIntentIDs(t *testing.T) {
	inputs := []BatchLeafInput{
		{ADIURL: "acc://a.acme", OperationID: [32]byte{1}, ExecutionCommitment: [32]byte{9}},
		{ADIURL: "acc://b.acme", OperationID: [32]byte{2}, ExecutionCommitment: [32]byte{8}},
		{ADIURL: "acc://c.acme", OperationID: [32]byte{3}, ExecutionCommitment: [32]byte{7}},
	}
	tree, err := BuildBatchTree(84532, inputs, 100)
	if err != nil {
		t.Fatal(err)
	}

	members := membersFromTree(tree, map[[32]byte]string{{2}: "intent-b"})
	if len(members) != 3 {
		t.Fatalf("members = %d", len(members))
	}
	for i, m := range members {
		if m.LeafIndex != i {
			t.Fatalf("member %d has index %d", i, m.LeafIndex)
		}
		if m.Leaf != tree.Leaves[i] {
			t.Fatalf("member %d leaf does not match the tree", i)
		}
		if !VerifyBranch(m.Branch, tree.Root, m.Leaf) {
			t.Fatalf("member %d branch does not prove its leaf under the root", i)
		}
	}
	if members[1].IntentID != "intent-b" {
		t.Fatalf("known intent id not carried: %q", members[1].IntentID)
	}
	// An unknown intent id stays EMPTY. The operation id is the durable identifier, and guessing here
	// would attach a quorum to the wrong intent.
	if members[0].IntentID != "" || members[2].IntentID != "" {
		t.Fatalf("intent ids invented: %q %q", members[0].IntentID, members[2].IntentID)
	}
}

// REGRESSION — the cadence lane must record member identity too.
//
// ProveBatchRoot passes a nil intentByOperation map by design: the prover does not hold intent ids. Before
// BatchLeafInput carried one, that left every CADENCE canonical row with members whose intent_id was
// empty — and since the layer-5 binding is keyed on intent_id, those intents could never find their
// canonical anchor and fell back to the settlement observation. That is the false binding this work
// removed, reappearing on the lane the live gate had not exercised.
func TestMembersFromTreeCarryTheIntentIdOnTheCadenceLane(t *testing.T) {
	inputs := []BatchLeafInput{
		{ADIURL: "acc://payer-one.acme", ExecutionCommitment: [32]byte{0xe1}, OperationID: [32]byte{0x01}, IntentID: "intent-one"},
		{ADIURL: "acc://payer-two.acme", ExecutionCommitment: [32]byte{0xe2}, OperationID: [32]byte{0x02}, IntentID: "intent-two"},
	}
	tree, err := BuildBatchTree(84532, inputs, 100)
	if err != nil {
		t.Fatalf("BuildBatchTree: %v", err)
	}

	// nil map: exactly what ProveBatchRoot passes.
	members := membersFromTree(tree, nil)
	if len(members) != 2 {
		t.Fatalf("got %d members", len(members))
	}
	for i, want := range []string{"intent-one", "intent-two"} {
		if members[i].IntentID != want {
			t.Fatalf("member %d intent_id = %q, want %q — an empty one makes the layer-5 binding fall "+
				"back to the settlement observation", i, members[i].IntentID, want)
		}
	}
}

// The explicit map still wins where a caller supplies it, and the leaf is unaffected by the new field.
func TestIntentIdOverrideAndLeafStability(t *testing.T) {
	in := BatchLeafInput{ADIURL: "acc://payer-one.acme", ExecutionCommitment: [32]byte{0xe1}, OperationID: [32]byte{0x01}}
	withID := in
	withID.IntentID = "intent-one"

	// The leaf must not move: IntentID is evidence, never part of the commitment.
	if ComputeBatchLeaf(84532, in) != ComputeBatchLeaf(84532, withID) {
		t.Fatal("adding an intent id changed the leaf; it must not be hashed")
	}

	tree, err := BuildBatchTree(84532, []BatchLeafInput{withID}, 100)
	if err != nil {
		t.Fatal(err)
	}
	members := membersFromTree(tree, map[[32]byte]string{{0x01}: "override"})
	if members[0].IntentID != "override" {
		t.Fatalf("explicit map did not win: %q", members[0].IntentID)
	}
}

// The plumbing itself: LeafInput is the single funnel both lanes build their leaves through, so the
// intent id has to survive that conversion or the cadence lane records nothing.
func TestLeafInputCarriesTheIntentIdIntoTheTree(t *testing.T) {
	p := &PendingBatchIntent{
		IntentID:    "intent-cadence-one",
		ADIURL:      "acc://payer-one.acme",
		ChainID:     84532,
		OperationID: [32]byte{0x01},
		Legs: []LegExecution{{
			LegID: "leg-1", ChainID: 84532,
			Target: common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
			Value:  big.NewInt(0),
		}},
	}
	in, err := p.LeafInput()
	if err != nil {
		t.Fatalf("LeafInput: %v", err)
	}
	if in.IntentID != "intent-cadence-one" {
		t.Fatalf("LeafInput dropped the intent id (%q); a cadence canonical row would record members with "+
			"no intent, and layer 5 could never bind them", in.IntentID)
	}
	if in.OperationID != p.OperationID {
		t.Fatal("LeafInput changed the operation id")
	}
}

// REGRESSION — the canonical member row must be no poorer than the shadow row it replaces.
//
// Until this, a canonical member carried hex(operationID) in a column named accumulate_tx_hash and
// nothing else. The retired per-validator shadow row carried the real Accumulate transaction plus the
// leg's from/to/amount, and the Transaction Center read those. Retiring the shadow pipeline while the
// canonical row was thinner would have silently emptied the console — so the row has to carry what it
// replaces BEFORE the old writer can be switched off.
//
// Observed live on intent a2e25171 (2026-09-18): canonical accumulate_tx_hash held e300dafb… (the
// operation id) with every display column empty, while the shadow row held 3e595d2c… (the real
// Accumulate transaction) and the full leg.
func TestLeafInputCarriesProvenanceForTheCanonicalRow(t *testing.T) {
	p := &PendingBatchIntent{
		IntentID:    "intent-prov-1",
		ADIURL:      "acc://payer-one.acme",
		ChainID:     84532,
		Account:     common.HexToAddress("0x9cc158f77DAdF9a605E141262338c89588825f6c"),
		OperationID: [32]byte{0x01},
		AccumTxHash: "3e595d2c526dfacb5e332cd11f4f0306d2648cf1291bed63a9bcfd6ef44a7a12",
		Legs: []LegExecution{{
			LegID: "leg-1", ChainID: 84532, Chain: "base-sepolia",
			Target: common.HexToAddress("0x12dD00C619C1Ac3F58eC68ed44ec1023fE33B9Ff"),
			Value:  big.NewInt(0),
		}},
	}
	in, err := p.LeafInput()
	if err != nil {
		t.Fatalf("LeafInput: %v", err)
	}

	pv := in.Provenance
	if pv.AccumTxHash != p.AccumTxHash {
		t.Fatalf("accum tx hash = %q, want the Accumulate transaction %q — an operation id here is the "+
			"mislabelling that broke the layer-5 join", pv.AccumTxHash, p.AccumTxHash)
	}
	if pv.AccumTxHash == hex.EncodeToString(p.OperationID[:]) {
		t.Fatal("the operation id is being recorded as the Accumulate transaction")
	}
	if pv.FromChain != "accumulate" || pv.ToChain != "base-sepolia" {
		t.Fatalf("chains = %s -> %s", pv.FromChain, pv.ToChain)
	}
	if pv.FromAddress != p.Account.Hex() || pv.ToAddress != p.Legs[0].Target.Hex() {
		t.Fatalf("addresses = %s -> %s", pv.FromAddress, pv.ToAddress)
	}
	if pv.Amount != "0" || pv.TokenSymbol != "ETH" || pv.UserID != p.ADIURL {
		t.Fatalf("amount=%q token=%q user=%q", pv.Amount, pv.TokenSymbol, pv.UserID)
	}

	// And it must survive into the member evidence, on BOTH lanes (nil map = cadence).
	tree, err := BuildBatchTree(84532, []BatchLeafInput{in}, 100)
	if err != nil {
		t.Fatalf("BuildBatchTree: %v", err)
	}
	members := membersFromTree(tree, nil)
	if len(members) != 1 || members[0].Provenance.AccumTxHash != p.AccumTxHash {
		t.Fatalf("provenance did not reach the member evidence: %+v", members)
	}
}

// Provenance must never move a leaf. If it could, adding a display field would change a bundle id.
func TestProvenanceDoesNotAffectTheLeaf(t *testing.T) {
	bare := BatchLeafInput{
		ADIURL: "acc://payer-one.acme", ExecutionCommitment: [32]byte{0xe1}, OperationID: [32]byte{0x01},
	}
	rich := bare
	rich.IntentID = "intent-prov-1"
	rich.Provenance = MemberProvenance{
		AccumTxHash: "3e595d2c", FromChain: "accumulate", ToChain: "base-sepolia",
		FromAddress: "0xaaa", ToAddress: "0xbbb", Amount: "12345", TokenSymbol: "ETH", UserID: "acc://x",
	}
	if ComputeBatchLeaf(84532, bare) != ComputeBatchLeaf(84532, rich) {
		t.Fatal("provenance changed the leaf; it must never be hashed")
	}
}
