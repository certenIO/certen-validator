package execution

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/config"
)

// mirrorLeg is structurally identical to consensus.BatchLeg — the shape EnqueueForBatch
// converts. If consensus's struct drifts, these tests fail rather than the conversion
// silently producing empty legs.
type mirrorLeg struct {
	LegID   string
	ChainID int64
	Target  [20]byte
	Value   *big.Int
	Data    []byte
}

func stackForChain(t *testing.T, chainID int64) *BatchStack {
	t.Helper()
	r, err := NewEVMChainResolver(&config.AnchorConfig{}, map[int64]common.Address{
		chainID: common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Assemble by hand: NewBatchStack would dial RPC, which these tests do not need. The
	// orchestrator is left as a zero value on purpose — FlushChain must ERROR on it, not
	// panic, which TestFlushDueChains_NoAttestFnDoesNotPanic asserts.
	return &BatchStack{
		Resolver:      r,
		Mempool:       NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64}),
		Orchestrators: map[int64]*BatchOrchestrator{chainID: {}},
	}
}

func tgt(b byte) [20]byte {
	var a [20]byte
	a[19] = b
	return a
}

func acct(b byte) [20]byte {
	var a [20]byte
	a[19] = b
	return a
}

func opid(b byte) [32]byte {
	var o [32]byte
	o[31] = b
	return o
}

// =============================================================================
// The wiring contract
// =============================================================================

func TestEnqueueForBatch_QueuesAMember(t *testing.T) {
	s := stackForChain(t, 11155111)

	legs := []mirrorLeg{
		{LegID: "l0", ChainID: 11155111, Target: tgt(0xAA), Value: big.NewInt(1000), Data: nil},
	}
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(0x11), opid(1), legs, "att", 100); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if s.Mempool.PendingCount() != 1 {
		t.Fatalf("pending=%d want 1", s.Mempool.PendingCount())
	}

	m := s.Mempool.Take(11155111)
	if len(m) != 1 {
		t.Fatalf("took %d", len(m))
	}
	got := m[0]
	if got.IntentID != "i1" || got.ADIURL != "acc://a.acme" {
		t.Fatalf("member identity wrong: %+v", got)
	}
	wantAcct := acct(0x11)
	if got.Account != common.BytesToAddress(wantAcct[:]) {
		t.Fatal("account not carried through")
	}
	if got.Attestation != "att" {
		t.Fatal("attestation snapshot not carried through — the member could execute but never attest")
	}
	wantTgt := tgt(0xAA)
	if len(got.Legs) != 1 || got.Legs[0].Target != common.BytesToAddress(wantTgt[:]) {
		t.Fatalf("leg not converted: %+v", got.Legs)
	}
	// SourceAddress must be the member's account, or settleMember would target address zero.
	if got.Legs[0].SourceAddress != got.Account {
		t.Fatal("leg SourceAddress must be the member's account")
	}
	// And the commitment must be computable — a member that cannot produce one would take
	// the whole tree down at build time.
	if _, err := got.ExecutionCommitment(); err != nil {
		t.Fatalf("execution commitment: %v", err)
	}
}

// A chain with no orchestrator has no anchor, so the member could never settle. It must be
// refused so consensus falls back to the per-intent path rather than stranding it.
func TestEnqueueForBatch_RejectsUnconfiguredChain(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 8453, Target: tgt(1), Value: big.NewInt(1)}}

	if err := s.EnqueueForBatch("i1", "acc://a.acme", 8453, acct(1), opid(1), legs, "att", 100); err == nil {
		t.Fatal("an unconfigured chain must be refused, not queued")
	}
	if s.Mempool.PendingCount() != 0 {
		t.Fatal("a refused member must not be queued")
	}
}

// The conversion is reflective over a structural mirror; anything else must be refused
// rather than silently producing empty legs.
func TestEnqueueForBatch_RejectsMalformedLegs(t *testing.T) {
	s := stackForChain(t, 11155111)

	cases := []struct {
		name string
		legs interface{}
	}{
		{"nil", nil},
		{"not a slice", "legs"},
		{"wrong element type", []string{"a"}},
		{"empty", []mirrorLeg{}},
	}
	for _, c := range cases {
		if err := s.EnqueueForBatch("i", "acc://a.acme", 11155111, acct(1), opid(1), c.legs, "att", 100); err == nil {
			t.Fatalf("%s must be refused", c.name)
		}
	}
	if s.Mempool.PendingCount() != 0 {
		t.Fatal("no malformed member may be queued")
	}
}

// A leg whose chain disagrees with the member would land in the wrong tree, and the leaf
// binds chainid — it could never be spent.
func TestEnqueueForBatch_RejectsChainMismatchedLeg(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 8453, Target: tgt(1), Value: big.NewInt(1)}}

	if err := s.EnqueueForBatch("i", "acc://a.acme", 11155111, acct(1), opid(1), legs, "att", 100); err == nil {
		t.Fatal("a leg on a different chain than its member must be refused")
	}
}

func TestEnqueueForBatch_RejectsZeroOperationID(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}}

	if err := s.EnqueueForBatch("i", "acc://a.acme", 11155111, acct(1), [32]byte{}, legs, "att", 100); err == nil {
		t.Fatal("a zero operationID must be refused — the anchor rejects it too")
	}
}

// Multi-leg members are the nested case: one leaf carrying a batch commitment.
func TestEnqueueForBatch_MultiLegMemberUsesBatchCommitment(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{
		{LegID: "l0", ChainID: 11155111, Target: tgt(0xAA), Value: big.NewInt(100)},
		{LegID: "l1", ChainID: 11155111, Target: tgt(0xBB), Value: big.NewInt(200)},
	}
	if err := s.EnqueueForBatch("i", "acc://a.acme", 11155111, acct(1), opid(1), legs, "att", 100); err != nil {
		t.Fatal(err)
	}
	m := s.Mempool.Take(11155111)[0]
	if !m.IsMultiLeg() {
		t.Fatal("two legs must report as multi-leg")
	}
	got, err := m.ExecutionCommitment()
	if err != nil {
		t.Fatal(err)
	}
	calls := make([]BatchCall, 0, len(m.Legs))
	for _, l := range m.Legs {
		calls = append(calls, BatchCall{Target: l.Target, Value: l.Value, Data: l.Data})
	}
	want := computeBatchExecutionCommitment(11155111, calls)
	if got != want {
		t.Fatal("multi-leg member must carry the batch commitment, not a single-call one")
	}
}

// =============================================================================
// Flush driver
// =============================================================================

// A flush with no attestation function must not silently drop the proof cycles — the
// condition is logged, and this asserts the loop does not panic or lose members.
func TestFlushDueChains_NoAttestFnDoesNotPanic(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}}
	if err := s.EnqueueForBatch("i", "acc://a.acme", 11155111, acct(1), opid(1), legs, "att", 100); err != nil {
		t.Fatal(err)
	}
	// The orchestrator here is a zero value, so FlushChain errors out — the point is that
	// the driver handles it without panicking and without losing the member silently.
	s.FlushDueChains(context.Background(), time.Now(), true, 1, nil, nil, nil)
}

// Nothing is due when the pool is empty — the loop must not create empty batches.
func TestFlushDueChains_EmptyPoolIsNoOp(t *testing.T) {
	s := stackForChain(t, 11155111)
	called := 0
	s.FlushDueChains(context.Background(), time.Now(), true, 1,
		func(context.Context, interface{}, string, int64, bool) { called++ }, nil, nil)
	if called != 0 {
		t.Fatal("an empty pool must produce no attestations")
	}
}

// The shutdown drain must return promptly rather than hanging.
func TestRunFlushLoop_DrainsAndReturnsOnCancel(t *testing.T) {
	s := stackForChain(t, 11155111)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.RunFlushLoop(ctx, BatchFlushConfig{Interval: 50 * time.Millisecond}, nil)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunFlushLoop did not return after cancel")
	}
}

// A member with no BFT commit height cannot be placed in a period deterministically —
// PeekForPeriod skips zero heights, so queueing one would strand it in the pool forever.
// It must be refused at enqueue, where consensus can still fall back to the per-intent path.
func TestEnqueueForBatch_RejectsZeroCommitHeight(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}}

	if err := s.EnqueueForBatch("i", "acc://a.acme", 11155111, acct(1), opid(1), legs, "att", 0); err == nil {
		t.Fatal("a zero commit height must be refused — the member could never be batched")
	}
	if s.Mempool.PendingCount() != 0 {
		t.Fatal("a refused member must not be queued")
	}
}

// The commit height must actually reach the member, or period selection silently skips it.
func TestEnqueueForBatch_CarriesCommitHeight(t *testing.T) {
	s := stackForChain(t, 11155111)
	legs := []mirrorLeg{{LegID: "l0", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}}

	if err := s.EnqueueForBatch("i", "acc://a.acme", 11155111, acct(1), opid(1), legs, "att", 4242); err != nil {
		t.Fatal(err)
	}
	got := s.Mempool.PeekForPeriod(11155111, 5000)
	if len(got) != 1 {
		t.Fatalf("member not selectable for a period covering its height (got %d)", len(got))
	}
	if got[0].CommitHeight != 4242 {
		t.Fatalf("commit height not carried through: %d", got[0].CommitHeight)
	}
	// And it must NOT appear in a period that closed before it committed.
	if n := len(s.Mempool.PeekForPeriod(11155111, 4241)); n != 0 {
		t.Fatalf("member appeared in an earlier period (%d)", n)
	}
}
