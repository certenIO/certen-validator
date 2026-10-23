// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// L3: the step budget is checked against a clock the test controls; a store that is slow (every read costs 2 ms of fake time) cannot hold a
// step longer than its budget plus the one note it may finish and the repair of its cluster. The assertion CAN fail: a step that ignored the
// budget would take 100 notes x ~30 ms.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type slowStore struct {
	finality.CaptureStore
	clk *fakeClock
	per time.Duration
}

func (s slowStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	s.clk.Advance(s.per)
	return s.CaptureStore.Get(ctx, k)
}

func (s slowStore) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	s.clk.Advance(s.per)
	return s.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
}

func TestRB12StepBudgetIsMeasuredOnAClockThatCanFailIt(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	slow := slowStore{CaptureStore: st, clk: clk, per: 2 * time.Millisecond}
	budget := 200 * time.Millisecond
	ix := NewIndexer(slow, bp, 0, IndexConfig{BlocksPerStep: 1000, StepBudget: budget, ReconcileEvery: 1 << 30, Now: clk.Now})
	vPutBlock(t, st, bp, 1005, uniqueFrame("anchor", 1_790_000_000))
	stepAll(t, ix, 30_000)
	const N = 100
	for i := 0; i < N; i++ {
		b := 10_000 + uint64(i)*50
		vPutBlock(t, st, bp, b, uniqueFrame(fmt.Sprintf("slow%d", i), 1_790_100_000+uint64(i)*100))
		ix.NoteLate(b)
	}
	// the stated bound: the budget plus the one note a step may finish after it and the repair of its cluster (about 40 reads of 2 ms)
	bound := budget + 250*time.Millisecond
	steps, longest := 0, time.Duration(0)
	for ; pendingHints(ix) > 0 && steps < 200; steps++ {
		rep, err := ix.Step(context.Background(), 30_000)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Elapsed > longest {
			longest = rep.Elapsed
		}
		if rep.Elapsed > bound {
			t.Fatalf("step %d took %s of the store's time, its budget is %s (bound %s)", steps, rep.Elapsed, budget, bound)
		}
	}
	if pendingHints(ix) != 0 {
		t.Fatalf("not drained in %d steps", steps)
	}
	if steps < 3 {
		t.Fatalf("100 notes at ~30 ms each cannot fit one 200 ms step: %d steps", steps)
	}
	t.Logf("%d notes flushed in %d steps, the longest %s of a %s budget", N, steps, longest, budget)
}
