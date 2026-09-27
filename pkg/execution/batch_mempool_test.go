package execution

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func pending(id, adi string, chainID int64, acct common.Address, opID uint64, legs ...LegExecution) *PendingBatchIntent {
	return &PendingBatchIntent{
		IntentID:    id,
		ADIURL:      adi,
		ChainID:     chainID,
		Account:     acct,
		OperationID: b32(opID),
		Legs:        legs,
		// A committed member: it belongs to period [0, periodBlocks). Height 0 belongs to no period.
		CommitHeight: 1,
	}
}

func oneLeg(chainID int64, to common.Address, wei int64) LegExecution {
	return LegExecution{
		LegID: "l", ChainID: chainID, Target: to, Value: big.NewInt(wei), Data: []byte{},
	}
}

var (
	acct1 = common.HexToAddress("0x01")
	acct2 = common.HexToAddress("0x02")
	dst   = common.HexToAddress("0xAA")
)

// =============================================================================
// Commitment selection: the two nesting levels
// =============================================================================

// A single-leg member must use the SINGLE-call commitment, so the on-demand shape is
// preserved exactly when an intent happens to be alone.
func TestPendingIntent_SingleLegUsesSingleCommitment(t *testing.T) {
	p := pending("i1", "acc://a.acme", 11155111, acct1, 1, oneLeg(11155111, dst, 7))
	got, err := p.ExecutionCommitment()
	if err != nil {
		t.Fatal(err)
	}
	want := computeExecutionCommitment(11155111, dst, big.NewInt(7), []byte{})
	if got != want {
		t.Fatal("single-leg member must use the single-call commitment")
	}
	if p.IsMultiLeg() {
		t.Fatal("one leg is not multi-leg")
	}
}

func TestPendingIntent_MultiLegUsesBatchCommitment(t *testing.T) {
	p := pending("i1", "acc://a.acme", 11155111, acct1, 1,
		oneLeg(11155111, dst, 7), oneLeg(11155111, acct2, 8))
	got, err := p.ExecutionCommitment()
	if err != nil {
		t.Fatal(err)
	}
	want := computeBatchExecutionCommitment(11155111, []BatchCall{
		{Target: dst, Value: big.NewInt(7), Data: []byte{}},
		{Target: acct2, Value: big.NewInt(8), Data: []byte{}},
	})
	if got != want {
		t.Fatal("multi-leg member must use the multi-leg batch commitment")
	}
	if !p.IsMultiLeg() {
		t.Fatal("two legs is multi-leg")
	}
}

// =============================================================================
// Add validation — reject at enqueue, not at tree-build time
// =============================================================================

func TestMempool_AddRejectsMalformed(t *testing.T) {
	m := NewBatchMempool(DefaultBatchMempoolConfig())

	cases := []struct {
		name string
		p    *PendingBatchIntent
	}{
		{"nil", nil},
		{"no id", &PendingBatchIntent{ADIURL: "a", Account: acct1, OperationID: b32(1),
			Legs: []LegExecution{oneLeg(1, dst, 1)}}},
		{"no adi", pending("i", "", 1, acct1, 1, oneLeg(1, dst, 1))},
		{"no account", pending("i", "acc://a.acme", 1, common.Address{}, 1, oneLeg(1, dst, 1))},
		{"zero opID", pending("i", "acc://a.acme", 1, acct1, 0, oneLeg(1, dst, 1))},
		{"no legs", pending("i", "acc://a.acme", 1, acct1, 1)},
	}
	for _, c := range cases {
		if err := m.Add(c.p); err == nil {
			t.Fatalf("%s must be rejected at Add", c.name)
		}
	}
	if m.PendingCount() != 0 {
		t.Fatal("rejected intents must not be queued")
	}
}

// A leg whose chain disagrees with the intent would land in the wrong tree — and the leaf
// binds chainid, so it could never be spent.
func TestMempool_AddRejectsChainMismatch(t *testing.T) {
	m := NewBatchMempool(DefaultBatchMempoolConfig())
	p := pending("i", "acc://a.acme", 11155111, acct1, 1, oneLeg(8453, dst, 1))
	if err := m.Add(p); err == nil {
		t.Fatal("a leg on a different chain than its intent must be rejected")
	}
}

func TestMempool_AddIsIdempotentPerIntentID(t *testing.T) {
	m := NewBatchMempool(DefaultBatchMempoolConfig())
	p := pending("dup", "acc://a.acme", 1, acct1, 1, oneLeg(1, dst, 1))
	if err := m.Add(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(p); err == nil {
		t.Fatal("the same intent must not queue twice")
	}
	if m.PendingCount() != 1 {
		t.Fatalf("pending=%d want 1", m.PendingCount())
	}
}

// =============================================================================
// Pooling by chain
// =============================================================================

// Members from different chains can never share a tree: the leaf binds block.chainid and the
// anchor is per-chain.
func TestMempool_PoolsAreSeparatedByChain(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	_ = m.Add(pending("a", "acc://a.acme", 11155111, acct1, 1, oneLeg(11155111, dst, 1)))
	_ = m.Add(pending("b", "acc://b.acme", 8453, acct2, 2, oneLeg(8453, dst, 1)))

	if m.PendingCountForChain(11155111) != 1 || m.PendingCountForChain(8453) != 1 {
		t.Fatal("pools must be keyed by chain")
	}
	got := m.PeriodMembers(11155111, 0, 100)
	if len(got) != 1 || got[0].IntentID != "a" {
		t.Fatal("a chain's period must hold only that chain's members")
	}
}

// A period with more members than a tree holds is cut into fixed trees, identically everywhere, and
// nothing is removed by cutting.
func TestMempool_PeriodIsCutIntoFixedTrees(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 3})
	for i := 0; i < 10; i++ {
		p := pending(string(rune('a'+i)), "acc://x.acme", 1, acct1, uint64(i+1), oneLeg(1, dst, 1))
		if err := m.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	chunks := chunkMembers(m.PeriodMembers(1, 0, 100), m.MaxBatchSize())
	sizes := []int{}
	for _, c := range chunks {
		sizes = append(sizes, len(c))
	}
	if fmt.Sprint(sizes) != "[3 3 3 1]" {
		t.Fatalf("trees = %v, want [3 3 3 1]", sizes)
	}
	if chunks[1][0].IntentID != "d" || chunks[3][0].IntentID != "j" {
		t.Fatalf("trees not cut in period order: %s, %s", chunks[1][0].IntentID, chunks[3][0].IntentID)
	}
	if m.PendingCountForChain(1) != 10 {
		t.Fatalf("cutting a period removed members: %d left", m.PendingCountForChain(1))
	}
	// Resolving the first tree's members does not change how the rest are cut.
	m.MarkOutcome(chunks[0], MemberSettled)
	again := chunkMembers(m.PeriodMembers(1, 0, 100), m.MaxBatchSize())
	if len(again) != 4 || again[1][0].IntentID != "d" {
		t.Fatal("a period's trees changed after some of its members settled")
	}
}

// Order is by (CommitHeight, IntentID), never by arrival: a validator that saw the members in
// another order must cut the same trees.
func TestMempool_PeriodOrderIgnoresArrival(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	now := time.Now()
	late := pending("b", "acc://x.acme", 1, acct1, 1, oneLeg(1, dst, 1))
	late.CommitHeight, late.EnqueuedAt = 5, now.Add(-time.Hour)
	early := pending("a", "acc://x.acme", 1, acct1, 2, oneLeg(1, dst, 1))
	early.CommitHeight, early.EnqueuedAt = 5, now
	first := pending("z", "acc://x.acme", 1, acct1, 3, oneLeg(1, dst, 1))
	first.CommitHeight, first.EnqueuedAt = 3, now
	for _, p := range []*PendingBatchIntent{late, early, first} {
		if err := m.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	got := m.PeriodMembers(1, 0, 100)
	if got[0].IntentID != "z" || got[1].IntentID != "a" || got[2].IntentID != "b" {
		t.Fatalf("order = %s %s %s, want z a b", got[0].IntentID, got[1].IntentID, got[2].IntentID)
	}
}

// A member with an outcome still holds its place in the dedupe index: the same intent arriving
// again (a workflow re-run) is queued already, never queued - and settled - a second time.
func TestMempool_AMemberWithAnOutcomeCannotBeQueuedAgain(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	p := pending("a", "acc://x.acme", 1, acct1, 1, oneLeg(1, dst, 1))
	if err := m.Add(p); err != nil {
		t.Fatal(err)
	}
	m.MarkOutcome([]*PendingBatchIntent{p}, MemberSettled)
	again := pending("a", "acc://x.acme", 1, acct1, 1, oneLeg(1, dst, 1))
	if err := m.Add(again); !errors.Is(err, ErrMemberAlreadyQueued) {
		t.Fatalf("a settled member was queued again: %v", err)
	}
	if m.PendingCount() != 0 {
		t.Fatalf("pending = %d, want 0", m.PendingCount())
	}
	if len(m.PendingPeriods(1, 100, 1000)) != 0 {
		t.Fatal("a period whose members all have outcomes is still pending")
	}
}

// =============================================================================
// Concurrency
// =============================================================================

func TestMempool_ConcurrentAddIsSafe(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 1000})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := pending(
				"intent-"+string(rune('a'+i%26))+string(rune('0'+i/26)),
				"acc://x.acme", 1, acct1, uint64(i+1), oneLeg(1, dst, 1))
			_ = m.Add(p)
		}(i)
	}
	wg.Wait()

	got := m.PendingCount()
	period := m.PeriodMembers(1, 0, 1000)
	if len(period) != got {
		t.Fatalf("PeriodMembers returned %d but PendingCount said %d", len(period), got)
	}
}

// =============================================================================
// Mempool -> tree, end to end (no chain)
// =============================================================================

// The whole point, checked without a chain: N members from N different ADIs form ONE tree
// whose every branch verifies.
func TestMempool_DrainsIntoAVerifiableTree(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 50})

	const N = 12
	adis := make([]string, N)
	for i := 0; i < N; i++ {
		adis[i] = "acc://adi" + string(rune('a'+i)) + ".acme"
		p := pending("intent-"+string(rune('a'+i)), adis[i], 11155111,
			common.BigToAddress(big.NewInt(int64(i+1))), uint64(i+100),
			oneLeg(11155111, dst, int64(i+1)))
		if err := m.Add(p); err != nil {
			t.Fatal(err)
		}
	}

	members := m.PeriodMembers(11155111, 0, 10000)
	if len(members) != N {
		t.Fatalf("took %d want %d", len(members), N)
	}

	inputs := make([]BatchLeafInput, 0, N)
	for _, p := range members {
		in, err := p.LeafInput()
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
	}

	tree, err := BuildBatchTree(11155111, inputs, 999)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Size() != N {
		t.Fatalf("tree size %d want %d", tree.Size(), N)
	}

	for i := range tree.Leaves {
		branch, err := tree.BranchFor(i)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyBranch(branch, tree.Root, tree.Leaves[i]) {
			t.Fatalf("member %d's branch does not verify", i)
		}
	}

	// Every member is individually addressable by its ADI.
	for i, adi := range adis {
		branch, idx, err := tree.BranchForADI(adi)
		if err != nil {
			t.Fatalf("%s: %v", adi, err)
		}
		if idx != i {
			t.Fatalf("%s resolved to index %d want %d", adi, idx, i)
		}
		if !VerifyBranch(branch, tree.Root, tree.Leaves[idx]) {
			t.Fatalf("%s branch invalid", adi)
		}
	}

	// And the bundleId is exactly what the anchor will require.
	want := DeriveBatchBundleID(11155111, tree.Root, uint64(N), tree.BatchOperationID, 999)
	if tree.BundleID != want {
		t.Fatal("bundleId must match the anchor's required derivation")
	}
}

// Mixed single-leg and multi-leg members in ONE tree — both nesting levels together.
func TestMempool_MixedSingleAndMultiLegMembers(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})

	single := pending("single", "acc://a.acme", 1, acct1, 1, oneLeg(1, dst, 5))
	multi := pending("multi", "acc://b.acme", 1, acct2, 2,
		oneLeg(1, dst, 1), oneLeg(1, acct1, 2), oneLeg(1, acct2, 3))

	if err := m.Add(single); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(multi); err != nil {
		t.Fatal(err)
	}

	members := m.PeriodMembers(1, 0, 100)
	inputs := make([]BatchLeafInput, 0, 2)
	for _, p := range members {
		in, err := p.LeafInput()
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
	}
	tree, err := BuildBatchTree(1, inputs, 1)
	if err != nil {
		t.Fatal(err)
	}

	// The two members must carry DIFFERENT commitment shapes inside their leaves.
	singleExec, _ := single.ExecutionCommitment()
	multiExec, _ := multi.ExecutionCommitment()
	if singleExec == multiExec {
		t.Fatal("single and multi-leg commitments must differ")
	}
	for i := range tree.Leaves {
		branch, _ := tree.BranchFor(i)
		if !VerifyBranch(branch, tree.Root, tree.Leaves[i]) {
			t.Fatalf("member %d branch invalid", i)
		}
	}
}
