// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// ---- the backfill loop ----

type bfFakeCap struct {
	calls []uint64
}

func (b *bfFakeCap) CaptureBlockHash(_ context.Context, n uint64) ([32]byte, bool, error) {
	b.calls = append(b.calls, n)
	return [32]byte{0xcc, byte(n)}, false, nil
}

func newGapLoop(t *testing.T, st finality.CaptureStore, c baseposted.BlockCapturer) (*GapBackfillLoop, *rtLog) {
	t.Helper()
	lg := &rtLog{}
	now := time.Unix(1_800_000_000, 0).UTC()
	l := &GapBackfillLoop{
		ChainID: finality.ChainBaseSepolia, Store: st, Every: 12 * time.Second, PerTick: 8, Logf: lg.logf,
		Backfill: &baseposted.Backfiller{Chain: finality.ChainBaseSepolia, Store: st, Capturer: c, Now: func() time.Time { return now },
			Policy: baseposted.DefaultBackfillPolicy(), Pick: func(int) int { return 0 }, Logf: lg.logf},
		Clock: loopClock{Now: func() time.Time { return now }},
	}
	return l, lg
}

func TestRB12GapLoopFillsOpenGapsInBoundedTicksAndReportsMetricsAndLogsRanges(t *testing.T) {
	mem := finality.NewMemCaptureStore()
	ctx := context.Background()
	_ = finality.RecordGap(ctx, mem, finality.ChainBaseSepolia, 1000, 1019, finality.GapOutageUnscanned)
	c := &bfFakeCap{}
	l, lg := newGapLoop(t, mem, c)
	if l.Name() != "base-sepolia/gapfill" || l.Chain() != finality.ChainBaseSepolia {
		t.Fatalf("%s %d", l.Name(), l.Chain())
	}
	if err := l.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if len(c.calls) != 8 {
		t.Fatalf("one tick captures at most PerTick=8 blocks, got %v", c.calls)
	}
	if !lg.has("gap backfill") || !lg.has("1000-1019") {
		t.Fatalf("the open range is logged by name: %v", lg.lines)
	}
	for tick := 2; tick <= 4; tick++ {
		if err := l.Tick(ctx, tick); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.calls) != 20 {
		t.Fatalf("20 blocks after four ticks: %d", len(c.calls))
	}
	if open, _ := finality.GapsIn(ctx, mem, finality.ChainBaseSepolia, 0, finality.MaxCaptureBlock); len(open) != 0 {
		t.Fatalf("%v", open)
	}
	if !lg.has("closed") {
		t.Fatalf("a closed range is logged: %v", lg.lines)
	}
}

func TestRB12GapLoopSpacingAuditRunsOnTheFirstTickAndRecordsTheHoles(t *testing.T) {
	mem := finality.NewMemCaptureStore()
	ctx := context.Background()
	for _, n := range []uint64{100, 110, 120, 130, 400, 410, 420} { // a 270-block run with no captured inbox block
		_ = mem.Put(ctx, finality.CaptureKey{Chain: finality.ChainBaseSepolia, L1Block: n, L1Hash: [32]byte{byte(n)}, Item: baseposted.ItemInbox}, []byte{1})
	}
	c := &bfFakeCap{}
	l, lg := newGapLoop(t, mem, c)
	l.AuditSpacing = 40
	if err := l.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if !lg.has("spacing audit") || !lg.has("131-399") {
		t.Fatalf("the audit logs the range it records: %v", lg.lines)
	}
	if len(c.calls) != 8 || c.calls[0] != 131 {
		t.Fatalf("the audited range is backfilled from its first block: %v", c.calls)
	}
}

func TestRB12GapLoopMemoryBudgetRefusalSkipsTheTickByNameAndLosesNothing(t *testing.T) {
	mem := finality.NewMemCaptureStore()
	ctx := context.Background()
	_ = finality.RecordGap(ctx, mem, finality.ChainBaseSepolia, 1, 3, finality.GapOutageUnscanned)
	c := &bfFakeCap{}
	l, lg := newGapLoop(t, mem, c)
	l.Memory = finality.NewMemoryBudget(finality.MinMemoryBudget)
	l.BlockBytes = finality.MinMemoryBudget + 1 // more than the whole budget
	if err := l.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if len(c.calls) != 0 || !lg.has(finality.CodeMemoryBudget) {
		t.Fatalf("a refused reservation captures nothing and says so by name: calls=%v log=%v", c.calls, lg.lines)
	}
	l.BlockBytes = 1 << 20
	if err := l.Tick(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if len(c.calls) != 3 {
		t.Fatalf("with room in the budget the gap is filled: %v", c.calls)
	}
	if l.Memory.Used() != 0 {
		t.Fatalf("every reservation is released: %d bytes still held", l.Memory.Used())
	}
}

func TestRB12GapLoopRunWaitsEveryIntervalAndEndsNilOnCancel(t *testing.T) {
	mem := finality.NewMemCaptureStore()
	_ = finality.RecordGap(context.Background(), mem, finality.ChainBaseSepolia, 1, 100, finality.GapOutageUnscanned)
	c := &bfFakeCap{}
	l, _ := newGapLoop(t, mem, c)
	ctx, cancel := context.WithCancel(context.Background())
	sc := &rtScript{stopAfter: 3, cancel: cancel}
	l.Clock.After = sc.After
	if err := l.Run(ctx); err != nil {
		t.Fatalf("Run ends nil on cancel, got %v", err)
	}
	if len(sc.waits) != 3 || sc.waits[0] != 12*time.Second {
		t.Fatalf("waits %v", sc.waits)
	}
	if len(c.calls) < 24 || len(c.calls) > 32 {
		t.Fatalf("three or four ticks of 8 blocks: %d", len(c.calls))
	}
}
