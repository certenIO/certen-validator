package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// Kermit's committed Accumulate root under its v1 incarnation, pinned in contracts.TestV8_2_PinnedVector_KermitIncarnation
// and pkg/accumulateset: the fixture snapshot must reduce to exactly it.
func TestV8_2Batch_FixtureSnapshotCommitsKermitsRoot(t *testing.T) {
	if hex.EncodeToString(testAccSet[:]) != "afa6bd344b04b6ff9645c97b09254af9c25a214991e0b442538e9084d4136bf5" {
		t.Fatalf("fixture root %x", testAccSet)
	}
	got, err := testAtt.AccumulateSetRoot(testIncarnation)
	if err != nil || got != testAccSet {
		t.Fatalf("snapshot root %x (%v)", got, err)
	}
}

// The V8.2 batch anchor id, pinned for the Go<->Solidity check (certen-contracts CertenAnchorV8_2Binding.t.sol asserts
// the same value) and recomputed independently in Python (RUNLOG_RB5).
func TestV8_2Batch_BundleIDVector(t *testing.T) {
	got := contracts.DeriveV8_2BatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight, testAccSet, testIncarnation)
	const want = "866a856335f691a180b9dc858d3f1f4ee671dc26d69f9412666fb1e9fe4f9790"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("V8.2 batch bundle id: got %x want %s", got, want)
	}
}

func TestV8_2Batch_BundleIDBindsEveryField(t *testing.T) {
	base := contracts.DeriveV8_2BatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight, testAccSet, testIncarnation)
	other := testAccSet
	other[0] ^= 1
	otherInc := testIncarnation
	otherInc[31] ^= 1
	for name, v := range map[string][32]byte{
		"chain":       contracts.DeriveV8_2BatchBundleID(8453, vecRoot, 3, b32(7), vecHeight, testAccSet, testIncarnation),
		"root":        contracts.DeriveV8_2BatchBundleID(vecChainID, vecLeaf0, 3, b32(7), vecHeight, testAccSet, testIncarnation),
		"count":       contracts.DeriveV8_2BatchBundleID(vecChainID, vecRoot, 4, b32(7), vecHeight, testAccSet, testIncarnation),
		"op id":       contracts.DeriveV8_2BatchBundleID(vecChainID, vecRoot, 3, b32(8), vecHeight, testAccSet, testIncarnation),
		"height":      contracts.DeriveV8_2BatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight+1, testAccSet, testIncarnation),
		"set root":    contracts.DeriveV8_2BatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight, other, testIncarnation),
		"incarnation": contracts.DeriveV8_2BatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight, testAccSet, otherInc),
		"v1":          DeriveBatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight),
	} {
		if v == base {
			t.Errorf("%s does not move the V8.2 batch bundle id", name)
		}
	}
}

func v82Input(op byte) BatchLeafInput {
	return BatchLeafInput{ADIURL: "acc://a.acme", ExecutionCommitment: b32(uint64(op) + 100), OperationID: b32(uint64(op)),
		GovernanceCommitment: testGov, AccumulateSetRoot: testAccSet, AuthorityPage: 1,
		AuthorityBook: contracts.HashURLString("acc://a.acme/book")}
}

// A tree commits the one set its members share, under the incarnation, in its bundle id.
func TestV8_2Batch_TreeCommitsItsMembersSet(t *testing.T) {
	tree, err := BuildBatchTree(vecChainID, []BatchLeafInput{v82Input(1), v82Input(2)}, vecHeight, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	if tree.AccumulateSetRoot != testAccSet || tree.Incarnation != testIncarnation {
		t.Fatal("the tree does not carry its members' set and the incarnation")
	}
	want := contracts.DeriveV8_2BatchBundleID(vecChainID, tree.Root, 2, tree.BatchOperationID, vecHeight, testAccSet, testIncarnation)
	if tree.BundleID != want {
		t.Fatal("the tree's bundle id is not the V8.2 derivation")
	}
}

func TestV8_2Batch_TreeRefusesWhatOneAnchorCannotCommit(t *testing.T) {
	mixed := v82Input(2)
	mixed.AccumulateSetRoot[0] ^= 1
	if _, err := BuildBatchTree(vecChainID, []BatchLeafInput{v82Input(1), mixed}, vecHeight, testIncarnation); err == nil {
		t.Fatal("members verified against different Accumulate sets shared one anchor")
	}
	none := v82Input(2)
	none.AccumulateSetRoot = [32]byte{}
	if _, err := BuildBatchTree(vecChainID, []BatchLeafInput{v82Input(1), none}, vecHeight, testIncarnation); !errors.Is(err, ErrNoAccumulateSetRoot) {
		t.Fatalf("a member without a committable set was batched: %v", err)
	}
	if _, err := BuildBatchTree(vecChainID, []BatchLeafInput{v82Input(1)}, vecHeight, [32]byte{}); err == nil {
		t.Fatal("a tree was built without the incarnation")
	}
}

// Members verified against different sets are cut into separate trees, grouped in first-appearance order; within a
// group the period's order is kept. Every validator cuts the same chunks.
func TestV8_2Batch_PeriodChunksPerAccumulateSet(t *testing.T) {
	o := &BatchOrchestrator{incarnation: testIncarnation, screen: acceptEveryAccount}
	other := testAccSet
	other[5] ^= 0xff
	mk := func(id string, root [32]byte) *PendingBatchIntent {
		return &PendingBatchIntent{IntentID: id, ChainID: 11155111, GovernanceCommitment: testGov, AccumulateSetRoot: root}
	}
	members := []*PendingBatchIntent{mk("a", testAccSet), mk("b", other), mk("c", testAccSet), mk("d", other), mk("e", testAccSet)}
	chunks, excluded, err := o.periodChunks(context.Background(), members, 64)
	if err != nil || len(excluded) != 0 {
		t.Fatalf("err %v excluded %d", err, len(excluded))
	}
	if len(chunks) != 2 {
		t.Fatalf("%d chunks, want one per set", len(chunks))
	}
	ids := func(c []*PendingBatchIntent) (s string) {
		for _, p := range c {
			s += p.IntentID
		}
		return
	}
	if ids(chunks[0]) != "ace" || ids(chunks[1]) != "bd" {
		t.Fatalf("chunks %q %q", ids(chunks[0]), ids(chunks[1]))
	}
	// A member with no set is excluded by name, never batched.
	chunks, excluded, err = o.periodChunks(context.Background(), []*PendingBatchIntent{mk("x", [32]byte{})}, 64)
	if err != nil || len(chunks) != 0 || len(excluded) != 1 || !errors.Is(excluded[0].cause, ErrNoAccumulateSetRoot) {
		t.Fatalf("chunks %d excluded %d err %v", len(chunks), len(excluded), err)
	}
}

// Admission derives the member's set root from its round's own proof, under the stack's incarnation.
func TestV8_2Batch_AdmissionDerivesTheSetRootFromTheSnapshot(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 11155111, Target: tgt(0xAA), Value: big.NewInt(1)}}
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(0x11), opid(1), legs, testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	got := s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks)
	if len(got) != 1 || got[0].AccumulateSetRoot != testAccSet {
		t.Fatalf("admitted member's set root %x", got[0].AccumulateSetRoot)
	}
	// A different incarnation derives a different root: the root names its chain.
	s2 := stackForChain(t, 11155111)
	s2.Incarnation[0] ^= 1
	if err := s2.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(0x11), opid(1), legs, testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if m := s2.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks); m[0].AccumulateSetRoot == testAccSet {
		t.Fatal("the set root does not depend on the incarnation")
	}
}

// A round whose snapshot has no L1-L4 proof has no committable set: refused as CERTEN's outage (retried), never
// queued with a zero root.
func TestV8_2Batch_AdmissionRefusesASnapshotWithoutAProof(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 11155111, Target: tgt(0xAA), Value: big.NewInt(1)}}
	noProof := &consensus.PendingAttestation{GovDecision: testGovDecision}
	err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(0x11), opid(1), legs, noProof, testGov, 100, "", time.Time{}, "")
	if !errors.Is(err, ErrNoAccumulateSetRoot) || !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("got %v", err)
	}
	if s.Mempool.PendingCount() != 0 {
		t.Fatal("a member without a committable set was queued")
	}
}

func TestV8_2Batch_StackRequiresTheIncarnation(t *testing.T) {
	if _, err := NewBatchStack(&EVMChainResolverImpl{}, &stubProver{}, DefaultBatchMempoolConfig(), [32]byte{}, nil); err == nil {
		t.Fatal("a batch stack was assembled without the Accumulate incarnation")
	}
}

// THE batch message: the V8.2 pre-exec formula over the tree, identical to the consensus helper, and never a message
// over a tree without the Accumulate half. Pinned against an independent Python computation (RUNLOG_RB5).
func TestV8_2Batch_QuorumMessage(t *testing.T) {
	tree, err := BuildBatchTree(vecChainID, []BatchLeafInput{v82Input(1), v82Input(2)}, vecHeight, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	setRoot := b32(0x44)
	msg, err := ComputeBatchQuorumMessage(tree, setRoot)
	if err != nil {
		t.Fatal(err)
	}
	want := contracts.ComputeEvmMessageHashV8_2_Pre(vecChainID, tree.BundleID, tree.Root, tree.BatchOperationID, setRoot, testAccSet, testIncarnation)
	if msg != want {
		t.Fatal("the batch message is not the V8.2 pre-exec message")
	}
	if consensus.ComputeBatchPreExecMessage(vecChainID, tree.BundleID, tree.Root, tree.BatchOperationID, setRoot, testAccSet, testIncarnation) != msg {
		t.Fatal("the consensus helper computes a different batch message")
	}
	// A fixed tree's message, pinned: bundle/root/op/set/acc/inc as below on sepolia.
	fixed := &BatchTree{ChainID: vecChainID, BundleID: b32(1), Root: b32(2), BatchOperationID: b32(3), AccumulateSetRoot: testAccSet, Incarnation: testIncarnation}
	got, err := ComputeBatchQuorumMessage(fixed, b32(4))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != "265622b496437a77802078d8780f41d43a49a1963ea781b0455036fdd842d7d9" {
		t.Fatalf("pinned batch message: got %x", got)
	}
	for name, mut := range map[string]func(*BatchTree){
		"no set root":    func(x *BatchTree) { x.AccumulateSetRoot = [32]byte{} },
		"no incarnation": func(x *BatchTree) { x.Incarnation = [32]byte{} },
	} {
		c := *tree
		mut(&c)
		if _, err := ComputeBatchQuorumMessage(&c, setRoot); !errors.Is(err, ErrNoAccumulateSetRoot) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
