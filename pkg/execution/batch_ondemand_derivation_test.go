package execution

import (
	"testing"
)

// =============================================================================
// The derivation invariants intent-keying rests on
// =============================================================================
//
// These pin PROPERTIES, not new code — every function under test already ships. The
// intent-keyed on-demand path is sound only if all of them hold, and each one would fail
// silently: a wrong bundleId is not a crash, it is a quorum that never forms and an intent
// that is eventually attested as failed.
//
// TestBatchTree_SingleMemberRootIsTheLeaf already covers root == leaf and the empty branch.

// odTreeFor builds the one-member tree exactly as the on-demand submitter will: the member's
// own leaf, at the member's own CommitHeight.
func odTreeFor(t *testing.T, p *PendingBatchIntent) *BatchTree {
	t.Helper()
	in, err := p.LeafInput()
	if err != nil {
		t.Fatalf("LeafInput: %v", err)
	}
	tree, err := BuildBatchTree(p.ChainID, []BatchLeafInput{in}, p.CommitHeight)
	if err != nil {
		t.Fatalf("BuildBatchTree: %v", err)
	}
	return tree
}

// THE central claim. A one-member batch's bundleId depends on the intent and nothing else — not
// on what else the validator holds, not on arrival order, not on a period.
//
// This is what removes the settle grace. The period path needs one because a peer holding a
// DIFFERENT SUBSET of a period derives a different bundleId; here there is no subset to differ
// on, so a peer either has the intent (and agrees exactly) or does not (and says so).
func TestOnDemandBundleIDIsAPureFunctionOfTheIntent(t *testing.T) {
	// Two mempools in deliberately different states.
	lonely := NewBatchMempool(BatchMempoolConfig{})
	crowded := NewBatchMempool(BatchMempoolConfig{})
	for _, id := range []byte{7, 8, 9} {
		if err := crowded.AddOnDemand(odMember(id, odChain, 500+uint64(id))); err != nil {
			t.Fatalf("seeding crowded mempool: %v", err)
		}
		if err := crowded.Add(odMember(100+id, odChain, 500+uint64(id))); err != nil {
			t.Fatalf("seeding crowded period pool: %v", err)
		}
	}
	subject := odMember(1, odChain, 105)
	if err := lonely.AddOnDemand(subject); err != nil {
		t.Fatalf("AddOnDemand lonely: %v", err)
	}
	if err := crowded.AddOnDemand(odMember(1, odChain, 105)); err != nil {
		t.Fatalf("AddOnDemand crowded: %v", err)
	}

	a := odTreeFor(t, lonely.GetOnDemand(odChain, [32]byte{1}))
	b := odTreeFor(t, crowded.GetOnDemand(odChain, [32]byte{1}))

	if a.BundleID != b.BundleID {
		t.Fatalf("bundleId depends on mempool state: lonely=%x crowded=%x — a busy validator "+
			"and an idle one would derive different batches for the SAME intent and could never "+
			"co-sign", a.BundleID[:8], b.BundleID[:8])
	}
	if a.Root != b.Root || a.BatchOperationID != b.BatchOperationID {
		t.Fatal("root or batchOperationID depends on mempool state")
	}
	if a.Root != a.Leaves[0] {
		t.Fatal("N=1 root must equal the leaf")
	}
}

// I5: two intents committed at the SAME Accumulate height must not collide. Without a period
// to separate them, the leaf and the batchOperationID are the only things keeping them apart.
func TestDistinctIntentsAtSameHeightGetDistinctBundleIDs(t *testing.T) {
	const h = uint64(4242)
	a := odTreeFor(t, odMember(1, odChain, h))
	b := odTreeFor(t, odMember(2, odChain, h))

	if a.BundleID == b.BundleID {
		t.Fatal("two different intents at the same height derived the SAME bundleId — the second " +
			"would revert with AnchorAlreadyExists and never settle")
	}
	if a.Root == b.Root {
		t.Fatal("distinct intents produced the same root")
	}
	if a.BatchOperationID == b.BatchOperationID {
		t.Fatal("distinct intents produced the same batchOperationID")
	}
}

// I3: the same intent on two chains is two members. They share an operationID and an ADI, so
// only the chain binding separates them — on the leaf AND on the bundleId.
func TestSameIntentOnTwoChainsDerivesDistinctLeavesAndBundleIDs(t *testing.T) {
	a := odMember(1, odChain, 105)
	b := odMember(1, 84532, 105)
	b.Legs[0].ChainID = 84532

	ta := odTreeFor(t, a)
	tb := odTreeFor(t, b)

	if ta.Leaves[0] == tb.Leaves[0] {
		t.Fatal("the leaf does not bind the chain — one chain's anchor could authorise the other's")
	}
	if ta.BundleID == tb.BundleID {
		t.Fatal("the bundleId does not bind the chain")
	}
	// Same operationID on both, by construction — that is why the chain binding matters.
	if a.OperationID != b.OperationID {
		t.Fatal("test setup wrong: the two members must share an operationID")
	}
}

// The height a one-member batch binds is the member's OWN CommitHeight, and it must be part of
// the bundleId — an attester rebuilding at a different height must not accidentally agree.
func TestOnDemandBundleIDBindsTheMembersOwnHeight(t *testing.T) {
	a := odTreeFor(t, odMember(1, odChain, 105))
	b := odTreeFor(t, odMember(1, odChain, 106))

	if a.BundleID == b.BundleID {
		t.Fatal("bundleId does not bind the commit height — an attester whose copy of the member " +
			"carried a different height would co-sign a batch it did not reproduce")
	}
	if a.Root != b.Root {
		t.Fatal("the root should NOT depend on height; only the bundleId binds it")
	}
	if a.BlockHeight != 105 || b.BlockHeight != 106 {
		t.Fatalf("tree heights are %d and %d, want 105 and 106", a.BlockHeight, b.BlockHeight)
	}
}

// A multi-leg intent on ONE chain stays ONE member (I2). The cap of one is on intents; leg
// count is orthogonal and must flow into the multi-leg commitment, not split the member.
func TestMultiLegIntentIsStillOneOnDemandMember(t *testing.T) {
	p := odMember(1, odChain, 105)
	p.Legs = append(p.Legs, LegExecution{
		LegID:   "leg-1",
		ChainID: odChain,
		Target:  p.Legs[0].Target,
		Value:   p.Legs[0].Value,
		Data:    []byte{0xbe, 0xef},
	})
	if !p.IsMultiLeg() {
		t.Fatal("test setup: member should be multi-leg")
	}

	m := NewBatchMempool(BatchMempoolConfig{})
	if err := m.AddOnDemand(p); err != nil {
		t.Fatalf("AddOnDemand rejected a multi-leg member: %v", err)
	}
	if n := m.PendingOnDemandCount(); n != 1 {
		t.Fatalf("a multi-leg intent became %d members; it must stay one", n)
	}

	tree := odTreeFor(t, p)
	if len(tree.Leaves) != 1 {
		t.Fatalf("multi-leg member produced %d leaves, want 1", len(tree.Leaves))
	}
	// And its commitment must be the multi-leg form, distinct from the single-call form.
	single := odMember(1, odChain, 105)
	if a, b := mustCommitment(t, p), mustCommitment(t, single); a == b {
		t.Fatal("multi-leg and single-call commitments collide; the account would authorise the " +
			"wrong call set")
	}
}

func mustCommitment(t *testing.T, p *PendingBatchIntent) [32]byte {
	t.Helper()
	c, err := p.ExecutionCommitment()
	if err != nil {
		t.Fatalf("ExecutionCommitment: %v", err)
	}
	return c
}

// leafCount is bound into the bundleId, so a one-member batch cannot be restated as a larger
// one (or vice versa) under the same id. EVM-004 in batch form.
func TestOnDemandBundleIDBindsLeafCount(t *testing.T) {
	p := odMember(1, odChain, 105)
	tree := odTreeFor(t, p)

	// Same root, same opID, same height — but claiming two leaves.
	restated := DeriveBatchBundleID(p.ChainID, tree.Root, 2, tree.BatchOperationID, p.CommitHeight)
	if restated == tree.BundleID {
		t.Fatal("leafCount is not bound into the bundleId; a one-member batch could be restated")
	}
}
