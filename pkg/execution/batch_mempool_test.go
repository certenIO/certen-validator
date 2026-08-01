package execution

import (
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
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1})
	_ = m.Add(pending("a", "acc://a.acme", 11155111, acct1, 1, oneLeg(11155111, dst, 1)))
	_ = m.Add(pending("b", "acc://b.acme", 8453, acct2, 2, oneLeg(8453, dst, 1)))

	if m.PendingCountForChain(11155111) != 1 || m.PendingCountForChain(8453) != 1 {
		t.Fatal("pools must be keyed by chain")
	}
	taken := m.Take(11155111)
	if len(taken) != 1 || taken[0].IntentID != "a" {
		t.Fatal("Take must only drain the requested chain")
	}
	if m.PendingCountForChain(8453) != 1 {
		t.Fatal("the other chain's pool must be untouched")
	}
}

func TestMempool_TakeRespectsMaxBatchSize(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 3, MinBatchSize: 1})
	for i := 0; i < 10; i++ {
		p := pending(string(rune('a'+i)), "acc://x.acme", 1, acct1, uint64(i+1), oneLeg(1, dst, 1))
		if err := m.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	taken := m.Take(1)
	if len(taken) != 3 {
		t.Fatalf("took %d, want MaxBatchSize=3", len(taken))
	}
	if m.PendingCountForChain(1) != 7 {
		t.Fatalf("remaining=%d want 7", m.PendingCountForChain(1))
	}
}

// Oldest-first, or a busy chain could starve an early intent forever.
func TestMempool_TakeIsOldestFirst(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 2, MinBatchSize: 1})
	now := time.Now()

	newest := pending("newest", "acc://x.acme", 1, acct1, 1, oneLeg(1, dst, 1))
	newest.EnqueuedAt = now
	middle := pending("middle", "acc://x.acme", 1, acct1, 2, oneLeg(1, dst, 1))
	middle.EnqueuedAt = now.Add(-time.Minute)
	oldest := pending("oldest", "acc://x.acme", 1, acct1, 3, oneLeg(1, dst, 1))
	oldest.EnqueuedAt = now.Add(-time.Hour)

	for _, p := range []*PendingBatchIntent{newest, middle, oldest} {
		if err := m.Add(p); err != nil {
			t.Fatal(err)
		}
	}

	taken := m.Take(1)
	if len(taken) != 2 || taken[0].IntentID != "oldest" || taken[1].IntentID != "middle" {
		t.Fatalf("oldest-first violated: %s, %s", taken[0].IntentID, taken[1].IntentID)
	}
}

// =============================================================================
// Flush triggers
// =============================================================================

func TestMempool_DueOnMinBatchSize(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 3, MaxAge: time.Hour})
	for i := 0; i < 2; i++ {
		_ = m.Add(pending(string(rune('a'+i)), "acc://x.acme", 1, acct1, uint64(i+1), oneLeg(1, dst, 1)))
	}
	if len(m.DueChains(time.Now(), false)) != 0 {
		t.Fatal("below MinBatchSize and within MaxAge must not be due")
	}
	_ = m.Add(pending("c", "acc://x.acme", 1, acct1, 3, oneLeg(1, dst, 1)))
	if len(m.DueChains(time.Now(), false)) != 1 {
		t.Fatal("reaching MinBatchSize must make the chain due")
	}
}

// A quiet chain must not strand an intent behind a long interval.
func TestMempool_DueOnMaxAge(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 100, MaxAge: 50 * time.Millisecond})
	p := pending("old", "acc://x.acme", 1, acct1, 1, oneLeg(1, dst, 1))
	p.EnqueuedAt = time.Now().Add(-time.Hour)
	_ = m.Add(p)

	if len(m.DueChains(time.Now(), false)) != 1 {
		t.Fatal("an aged member must force its chain due")
	}
}

func TestMempool_ForceMakesAllNonEmptyChainsDue(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 100, MaxAge: time.Hour})
	_ = m.Add(pending("a", "acc://a.acme", 1, acct1, 1, oneLeg(1, dst, 1)))
	_ = m.Add(pending("b", "acc://b.acme", 2, acct2, 2, oneLeg(2, dst, 1)))

	due := m.DueChains(time.Now(), true)
	if len(due) != 2 {
		t.Fatalf("force must make every non-empty chain due, got %d", len(due))
	}
	if due[0] != 1 || due[1] != 2 {
		t.Fatal("due chains must be returned in deterministic order")
	}
}

// =============================================================================
// Requeue
// =============================================================================

// A failed flush before the anchor exists must lose nothing.
func TestMempool_RequeueRestoresMembers(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1})
	for i := 0; i < 3; i++ {
		_ = m.Add(pending(string(rune('a'+i)), "acc://x.acme", 1, acct1, uint64(i+1), oneLeg(1, dst, 1)))
	}
	taken := m.Take(1)
	if m.PendingCount() != 0 {
		t.Fatal("Take must drain")
	}
	m.Requeue(taken)
	if m.PendingCount() != 3 {
		t.Fatalf("requeued=%d want 3", m.PendingCount())
	}
	// And they can be taken again — the dedupe set must have been released.
	if len(m.Take(1)) != 3 {
		t.Fatal("requeued members must be takeable again")
	}
}

func TestMempool_RequeueIsIdempotent(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1})
	_ = m.Add(pending("a", "acc://x.acme", 1, acct1, 1, oneLeg(1, dst, 1)))
	taken := m.Take(1)

	m.Requeue(taken)
	m.Requeue(taken) // double requeue must not duplicate
	if m.PendingCount() != 1 {
		t.Fatalf("pending=%d want 1", m.PendingCount())
	}
}

// =============================================================================
// Concurrency
// =============================================================================

func TestMempool_ConcurrentAddIsSafe(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 1000, MinBatchSize: 1})
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
	taken := m.Take(1)
	if len(taken) != got {
		t.Fatalf("Take returned %d but PendingCount said %d", len(taken), got)
	}
}

// =============================================================================
// Mempool -> tree, end to end (no chain)
// =============================================================================

// The whole point, checked without a chain: N members from N different ADIs form ONE tree
// whose every branch verifies.
func TestMempool_DrainsIntoAVerifiableTree(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 50, MinBatchSize: 1})

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

	members := m.Take(11155111)
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
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10, MinBatchSize: 1})

	single := pending("single", "acc://a.acme", 1, acct1, 1, oneLeg(1, dst, 5))
	multi := pending("multi", "acc://b.acme", 1, acct2, 2,
		oneLeg(1, dst, 1), oneLeg(1, acct1, 2), oneLeg(1, acct2, 3))

	if err := m.Add(single); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(multi); err != nil {
		t.Fatal(err)
	}

	members := m.Take(1)
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
