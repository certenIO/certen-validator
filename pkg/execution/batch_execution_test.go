package execution

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func leg(id string, chainID int64, from, to common.Address, wei int64) LegExecution {
	return LegExecution{
		LegID:         id,
		ChainID:       chainID,
		SourceAddress: from,
		Target:        to,
		Value:         big.NewInt(wei),
		Data:          []byte{},
	}
}

var (
	acctA = common.HexToAddress("0xA1")
	acctB = common.HexToAddress("0xB2")
	dstX  = common.HexToAddress("0x11")
	dstY  = common.HexToAddress("0x22")
)

// =============================================================================
// Authority ladder — must mirror CertenAccountV6._requiredLevelFor
// =============================================================================

func TestRequiredLevelForValue_MirrorsSolidityLadder(t *testing.T) {
	e := func(f float64) *big.Int {
		bf := new(big.Float).Mul(big.NewFloat(f), new(big.Float).SetInt(big.NewInt(1e18)))
		out, _ := bf.Int(nil)
		return out
	}
	cases := []struct {
		value *big.Int
		want  uint8
	}{
		{big.NewInt(0), AuthorityOperator},
		{e(0.09), AuthorityOperator},
		{e(0.1), AuthorityManager},
		{e(0.99), AuthorityManager},
		{e(1), AuthorityAdmin},
		{e(9.99), AuthorityAdmin},
		{e(10), AuthorityRoot},
		{e(1000), AuthorityRoot},
		{nil, AuthorityOperator},
	}
	for _, c := range cases {
		if got := requiredLevelForValue(c.value); got != c.want {
			t.Fatalf("value %v: got level %d want %d", c.value, got, c.want)
		}
	}
}

// A batch's level must cover its most demanding leg, or CertenAccountV6 rejects the whole
// batch after the anchor has already been paid for.
func TestRequiredLevelForLegs_TakesMaximum(t *testing.T) {
	twentyEther := new(big.Int).Mul(big.NewInt(20), big.NewInt(1e18))
	rootLeg := leg("l1", 1, acctA, dstY, 0)
	rootLeg.Value = twentyEther // 20 ETH -> ROOT

	legs := []LegExecution{
		leg("l0", 1, acctA, dstX, 1), // OPERATOR
		rootLeg,
		leg("l2", 1, acctA, dstX, 1), // OPERATOR
	}
	if got := requiredLevelForLegs(legs); got != AuthorityRoot {
		t.Fatalf("got %d, want ROOT(%d) — batch must cover its most demanding leg", got, AuthorityRoot)
	}
}

// =============================================================================
// Grouping
// =============================================================================

func TestGroupLegsForBatch_GroupsByAccountAndChain(t *testing.T) {
	legs := []LegExecution{
		leg("l0", 11155111, acctA, dstX, 1),
		leg("l1", 11155111, acctA, dstY, 2),
		leg("l2", 11155111, acctB, dstX, 3), // different account -> own group
		leg("l3", 84532, acctA, dstX, 4),    // different chain -> own group
	}

	groups, unbatchable := GroupLegsForBatch("acc://x.acme", legs)
	if len(unbatchable) != 0 {
		t.Fatalf("expected nothing unbatchable, got %d", len(unbatchable))
	}
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	if len(groups[0].Legs) != 2 || !groups[0].IsBatch() {
		t.Fatalf("first group should hold the 2 same-account same-chain legs, got %d", len(groups[0].Legs))
	}
	if groups[1].IsBatch() || groups[2].IsBatch() {
		t.Fatal("single-leg groups must not report as batches")
	}
}

// Order is significant — CertenAccountV6 rejects a reordered batch, so grouping must be
// order-stable or the commitment computed here won't match what executes.
func TestGroupLegsForBatch_PreservesOrder(t *testing.T) {
	legs := []LegExecution{
		leg("first", 1, acctA, dstX, 1),
		leg("second", 1, acctA, dstY, 2),
		leg("third", 1, acctA, dstX, 3),
	}
	groups, _ := GroupLegsForBatch("acc://x.acme", legs)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	want := []string{"first", "second", "third"}
	for i, id := range want {
		if groups[0].Legs[i].LegID != id {
			t.Fatalf("position %d: got %s want %s", i, groups[0].Legs[i].LegID, id)
		}
	}
}

func TestGroupLegsForBatch_SeparatesLegsWithoutAccount(t *testing.T) {
	legs := []LegExecution{
		leg("ok", 1, acctA, dstX, 1),
		leg("orphan", 1, common.Address{}, dstY, 2),
	}
	groups, unbatchable := GroupLegsForBatch("acc://x.acme", legs)
	if len(groups) != 1 || len(unbatchable) != 1 {
		t.Fatalf("got %d groups / %d unbatchable, want 1/1", len(groups), len(unbatchable))
	}
	if unbatchable[0].LegID != "orphan" {
		t.Fatalf("wrong leg reported unbatchable: %s", unbatchable[0].LegID)
	}
}

// A one-leg group must keep using the SINGLE-call commitment, so the on-demand path is
// bit-identical to pre-batch behaviour.
func TestBatchGroup_SingleLegUsesSingleCommitment(t *testing.T) {
	g := BatchGroup{
		Key:  BatchKey{ADIURL: "acc://x.acme", ChainID: 11155111, SourceAccount: acctA},
		Legs: []LegExecution{leg("l0", 11155111, acctA, dstX, 7)},
	}
	if g.IsBatch() {
		t.Fatal("one leg must not be a batch")
	}
	want := computeExecutionCommitment(11155111, dstX, big.NewInt(7), []byte{})
	if g.ExecutionCommitment() != want {
		t.Fatal("single-leg group must use the single-call commitment")
	}
}

func TestBatchGroup_MultiLegUsesBatchCommitment(t *testing.T) {
	g := BatchGroup{
		Key: BatchKey{ADIURL: "acc://x.acme", ChainID: 11155111, SourceAccount: acctA},
		Legs: []LegExecution{
			leg("l0", 11155111, acctA, dstX, 7),
			leg("l1", 11155111, acctA, dstY, 8),
		},
	}
	if !g.IsBatch() {
		t.Fatal("two legs must be a batch")
	}
	want := computeBatchExecutionCommitment(11155111, g.ToBatchCalls())
	if g.ExecutionCommitment() != want {
		t.Fatal("multi-leg group must use the batch commitment")
	}
	// And it must NOT collide with the single-call commitment of its first leg.
	single := computeExecutionCommitment(11155111, dstX, big.NewInt(7), []byte{})
	if g.ExecutionCommitment() == single {
		t.Fatal("batch commitment must differ from leg 0's single commitment")
	}
}

func TestBatchGroup_TotalValue(t *testing.T) {
	g := BatchGroup{Legs: []LegExecution{
		leg("l0", 1, acctA, dstX, 100),
		leg("l1", 1, acctA, dstY, 250),
	}}
	if got := g.TotalValue(); got.Cmp(big.NewInt(350)) != 0 {
		t.Fatalf("got %s want 350", got)
	}
}

// =============================================================================
// Cadence accumulator
// =============================================================================

type flushCollector struct {
	mu      sync.Mutex
	flushes []BatchFlush
}

func (c *flushCollector) fn(f BatchFlush) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushes = append(c.flushes, f)
}

func (c *flushCollector) all() []BatchFlush {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]BatchFlush(nil), c.flushes...)
}

func TestAccumulator_FlushOnCadenceGroupsPerADI(t *testing.T) {
	c := &flushCollector{}
	b := NewBatchAccumulator(BatchAccumulatorConfig{Interval: time.Hour, MaxBatchSize: 100}, c.fn)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	must(b.Add(PendingLeg{ADIURL: "acc://alice.acme", IntentID: "i1", Leg: leg("a0", 1, acctA, dstX, 1)}))
	must(b.Add(PendingLeg{ADIURL: "acc://alice.acme", IntentID: "i2", Leg: leg("a1", 1, acctA, dstY, 2)}))
	must(b.Add(PendingLeg{ADIURL: "acc://bob.acme", IntentID: "i3", Leg: leg("b0", 1, acctB, dstX, 3)}))

	if n := b.PendingCount(); n != 3 {
		t.Fatalf("pending=%d want 3", n)
	}

	out := b.FlushDue(time.Now(), true)
	if len(out) != 2 {
		t.Fatalf("expected 2 flushes (one per ADI), got %d", len(out))
	}
	// Alice's two legs batch together; Bob's is separate — different ADI can never share
	// an anchor or an account call.
	if len(out[0].Group.Legs) != 2 || out[0].Group.Key.ADIURL != "acc://alice.acme" {
		t.Fatalf("first flush wrong: adi=%s legs=%d", out[0].Group.Key.ADIURL, len(out[0].Group.Legs))
	}
	if len(out[1].Group.Legs) != 1 || out[1].Group.Key.ADIURL != "acc://bob.acme" {
		t.Fatalf("second flush wrong: adi=%s legs=%d", out[1].Group.Key.ADIURL, len(out[1].Group.Legs))
	}
	if out[0].Reason != "cadence" {
		t.Fatalf("reason=%s want cadence", out[0].Reason)
	}
	if b.PendingCount() != 0 {
		t.Fatal("queue must be empty after flush")
	}
	if len(c.all()) != 2 {
		t.Fatalf("callback fired %d times, want 2", len(c.all()))
	}
}

func TestAccumulator_MaxBatchSizeForcesEarlyFlush(t *testing.T) {
	c := &flushCollector{}
	b := NewBatchAccumulator(BatchAccumulatorConfig{Interval: time.Hour, MaxBatchSize: 3}, c.fn)

	for i := 0; i < 3; i++ {
		if err := b.Add(PendingLeg{ADIURL: "acc://a.acme", IntentID: "i", Leg: leg("l", 1, acctA, dstX, 1)}); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("expected 1 early flush at MaxBatchSize, got %d", len(got))
	}
	if got[0].Reason != "max_size" || len(got[0].Group.Legs) != 3 {
		t.Fatalf("reason=%s legs=%d", got[0].Reason, len(got[0].Group.Legs))
	}
	if b.PendingCount() != 0 {
		t.Fatal("queue must be drained by the early flush")
	}
}

// A low-traffic ADI must not be held hostage to a long cadence interval.
func TestAccumulator_MaxAgeForcesFlush(t *testing.T) {
	c := &flushCollector{}
	b := NewBatchAccumulator(
		BatchAccumulatorConfig{Interval: time.Hour, MaxBatchSize: 100, MaxAge: 50 * time.Millisecond}, c.fn)

	old := time.Now().Add(-time.Second)
	if err := b.Add(PendingLeg{ADIURL: "acc://a.acme", IntentID: "i", Leg: leg("l", 1, acctA, dstX, 1), EnqueuedAt: old}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Not forced, but the leg is older than MaxAge.
	out := b.FlushDue(time.Now(), false)
	if len(out) != 1 || out[0].Reason != "max_age" {
		t.Fatalf("expected a max_age flush, got %d flushes", len(out))
	}
}

func TestAccumulator_FreshLegNotFlushedBeforeMaxAge(t *testing.T) {
	b := NewBatchAccumulator(
		BatchAccumulatorConfig{Interval: time.Hour, MaxBatchSize: 100, MaxAge: time.Hour}, nil)

	if err := b.Add(PendingLeg{ADIURL: "acc://a.acme", IntentID: "i", Leg: leg("l", 1, acctA, dstX, 1)}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if out := b.FlushDue(time.Now(), false); len(out) != 0 {
		t.Fatalf("fresh leg must not flush, got %d", len(out))
	}
	if b.PendingCount() != 1 {
		t.Fatal("leg must remain queued")
	}
}

func TestAccumulator_RejectsUnbatchableLegs(t *testing.T) {
	b := NewBatchAccumulator(DefaultBatchAccumulatorConfig(), nil)

	if err := b.Add(PendingLeg{ADIURL: "acc://a.acme", Leg: leg("orphan", 1, common.Address{}, dstX, 1)}); err == nil {
		t.Fatal("leg without a source account must be rejected, not silently dropped")
	}
	if err := b.Add(PendingLeg{ADIURL: "  ", Leg: leg("noadi", 1, acctA, dstX, 1)}); err == nil {
		t.Fatal("leg without an ADI URL must be rejected")
	}
	if b.PendingCount() != 0 {
		t.Fatal("rejected legs must not be queued")
	}
}

// Shutdown must drain, never abandon queued legs.
func TestAccumulator_RunDrainsOnContextCancel(t *testing.T) {
	c := &flushCollector{}
	b := NewBatchAccumulator(BatchAccumulatorConfig{Interval: time.Hour, MaxBatchSize: 100, MaxAge: time.Hour}, c.fn)

	if err := b.Add(PendingLeg{ADIURL: "acc://a.acme", IntentID: "i", Leg: leg("l", 1, acctA, dstX, 1)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.Run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	if len(c.all()) != 1 {
		t.Fatalf("shutdown must drain the queue, got %d flushes", len(c.all()))
	}
	if b.PendingCount() != 0 {
		t.Fatal("queue must be empty after drain")
	}
}

func TestAccumulator_RunFlushesOnTick(t *testing.T) {
	c := &flushCollector{}
	b := NewBatchAccumulator(
		BatchAccumulatorConfig{Interval: 40 * time.Millisecond, MaxBatchSize: 100, MaxAge: time.Hour}, c.fn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(ctx)

	if err := b.Add(PendingLeg{ADIURL: "acc://a.acme", IntentID: "i", Leg: leg("l", 1, acctA, dstX, 1)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	deadline := time.After(2 * time.Second)
	for {
		if len(c.all()) > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cadence tick never flushed the queued leg")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := c.all()[0]; got.Reason != "cadence" {
		t.Fatalf("reason=%s want cadence", got.Reason)
	}
}

func TestAccumulator_ConcurrentAddIsSafe(t *testing.T) {
	c := &flushCollector{}
	b := NewBatchAccumulator(BatchAccumulatorConfig{Interval: time.Hour, MaxBatchSize: 1000, MaxAge: time.Hour}, c.fn)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = b.Add(PendingLeg{ADIURL: "acc://a.acme", IntentID: "i", Leg: leg("l", 1, acctA, dstX, int64(i))})
		}(i)
	}
	wg.Wait()

	if n := b.PendingCount(); n != 50 {
		t.Fatalf("pending=%d want 50 — concurrent Add lost legs", n)
	}
	out := b.FlushDue(time.Now(), true)
	if len(out) != 1 || len(out[0].Group.Legs) != 50 {
		t.Fatalf("expected one 50-leg group, got %d groups", len(out))
	}
}

func TestAccumulatorConfig_Defaults(t *testing.T) {
	b := NewBatchAccumulator(BatchAccumulatorConfig{}, nil)
	d := DefaultBatchAccumulatorConfig()
	if b.cfg.Interval != d.Interval || b.cfg.MaxBatchSize != d.MaxBatchSize || b.cfg.MaxAge != d.MaxAge {
		t.Fatalf("zero config must fall back to defaults, got %+v", b.cfg)
	}
}
