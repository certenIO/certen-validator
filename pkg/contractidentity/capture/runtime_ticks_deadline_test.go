// Copyright 2026 Certen Protocol

package capture_test

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/ethproof"
)

const deadlineChain = uint64(11155111)

// pacedClock is a replay clock whose Sleep only pauses: the test moves the time itself with advance, so a deadline is reached when the test
// says and not when the tick loop has polled often enough.
type pacedClock struct{ *ethproof.VirtualClock }

func newPacedClock(start time.Time) *pacedClock { return &pacedClock{ethproof.NewVirtualClock(start)} }

func (c *pacedClock) Sleep(ctx context.Context, _ time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Millisecond):
		return true
	}
}

func (c *pacedClock) advance(d time.Duration) { c.VirtualClock.Sleep(context.Background(), d) }

func newDeadlineWorld(t *testing.T) (*fakeChain, *headSource, *spyStore, []uint64) {
	t.Helper()
	h, _ := halfWindow(t, deadlineChain)
	fc := newFakeChainWith(t, deadlineChain, "hops", longEdit([]uint64{h, h, h, h, h + 2}))
	return fc, newHeadSource(fc, honest, honest), newSpy(), fc.tickHeads()
}

func startDeadlineRuntime(t *testing.T, fc *fakeChain, src *headSource, st *spyStore, clock ethproof.ReplayClock, dl func(uint64, [32]byte) (time.Time, bool)) *capture.Runtime {
	t.Helper()
	deps := capture.Deps{Store: st, Manifest: fc.w.Manifest, Clock: clock, TickPoll: 5 * time.Millisecond, Deadline: dl,
		SourceFor: func(uint64) (capture.AttestSource, error) { return src, nil }}
	rt, dis := capture.Start(context.Background(), enabled(), deps)
	if rt == nil || dis != nil {
		t.Fatalf("Start: %v", dis)
	}
	return rt
}

func attestAndWait(t *testing.T, rt *capture.Runtime, fc *fakeChain, st *spyStore) {
	t.Helper()
	facts := fc.facts(t)
	rt.AttestationObserved(int64(deadlineChain), facts.AnchorID, fc.attTx, 0)
	waitFor(t, "the attestation row", func() bool {
		_, ok, _ := st.Store.Get(context.Background(), capture.Key{Chain: deadlineChain, AnchorID: facts.AnchorID, BlockHash: fc.w.BlockHashes["attest"], Item: capture.ItemAttest})
		return ok
	})
}

func putCount(st *spyStore) int { st.mu.Lock(); defer st.mu.Unlock(); return len(st.puts) }

// tickTwice moves the head over the first two ticks and waits for their rows (one tick row each, and the first link with the first tick).
func tickTwice(t *testing.T, src *headSource, st *spyStore, heads []uint64, base int) int {
	t.Helper()
	if len(heads) < 4 {
		t.Fatalf("the world has %d tick heads, the test needs 4", len(heads))
	}
	for i := 0; i < 2; i++ {
		src.setHead(heads[i])
		want := base + (i + 1) + 1
		waitFor(t, "the tick row of the head", func() bool { return putCount(st) >= want })
	}
	return putCount(st)
}

// A tracked anchor whose deadline is reached is untracked by the loop at the deadline, with the head well inside the reach bound.
func TestRuntimeStopsTheTicksOfAnAnchorAtItsDeadlineNotAtTheReachBound(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	pc := newPacedClock(t0)
	deadline := t0.Add(time.Hour)
	var lastAskedAt atomic.Int64
	fc, src, st, heads := newDeadlineWorld(t)
	rt := startDeadlineRuntime(t, fc, src, st, pc, func(uint64, [32]byte) (time.Time, bool) {
		lastAskedAt.Store(pc.Now().UnixNano())
		return deadline, true
	})
	defer rt.Stop()
	attestAndWait(t, rt, fc, st)
	before := tickTwice(t, src, st, heads, putCount(st))
	pc.advance(2 * time.Hour) // the deadline is reached
	src.setHead(heads[2])     // a head the loop would tick for: it is far inside B_v + 16 ticks + W
	waitFor(t, "the loop to look at the anchor after its deadline", func() bool { return lastAskedAt.Load() >= deadline.UnixNano() })
	time.Sleep(300 * time.Millisecond)
	if got := putCount(st); got != before {
		t.Fatalf("%d rows were stored after the deadline (%d before): the anchor was still followed", got-before, before)
	}
}

// The same flow with no deadline known: the loop goes on ticking inside the reach bound, however late the clock is.
func TestRuntimeAnUnknownDeadlineKeepsFollowingTheAnchorToTheReachBound(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	pc := newPacedClock(t0)
	var asked atomic.Int64
	fc, src, st, heads := newDeadlineWorld(t)
	rt := startDeadlineRuntime(t, fc, src, st, pc, func(uint64, [32]byte) (time.Time, bool) {
		asked.Add(1)
		return time.Time{}, false
	})
	defer rt.Stop()
	attestAndWait(t, rt, fc, st)
	before := tickTwice(t, src, st, heads, putCount(st))
	pc.advance(1000 * time.Hour)
	src.setHead(heads[2])
	waitFor(t, "the third tick row", func() bool { return putCount(st) > before })
	if asked.Load() == 0 {
		t.Fatal("the loop never asked for the deadline")
	}
}

// A deadline source that panics, answers zero, answers the far future, or is slow changes neither the hop ticks nor the settlement row,
// and no goroutine outlives Stop.
func TestRuntimeHostileDeadlineSourcesChangeNeitherTheTicksNorTheSettlementNorLeakGoroutines(t *testing.T) {
	cases := []struct {
		name string
		dl   func(uint64, [32]byte) (time.Time, bool)
	}{
		{"panics", func(uint64, [32]byte) (time.Time, bool) { panic("hostile deadline source") }},
		{"zero_but_known", func(uint64, [32]byte) (time.Time, bool) { return time.Time{}, true }},
		{"far_future", func(uint64, [32]byte) (time.Time, bool) { return time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), true }},
		{"slow", func(uint64, [32]byte) (time.Time, bool) { time.Sleep(15 * time.Millisecond); return time.Time{}, false }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			fc, src, st, heads := newDeadlineWorld(t)
			goroutines := runtime.NumGoroutine()
			rt := startDeadlineRuntime(t, fc, src, st, ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)), c.dl)
			attestAndWait(t, rt, fc, st)
			base := putCount(st)
			for i, head := range heads {
				src.setHead(head)
				want := base + (i + 1) + 1
				waitFor(t, "the tick row of the head", func() bool { return putCount(st) >= want })
			}
			facts := fc.facts(t)
			rt.SettlementObserved(int64(deadlineChain), fc.tx.Hash())
			waitFor(t, "the settlement row", func() bool {
				_, ok, _ := st.Store.Get(context.Background(), capture.Key{Chain: deadlineChain, AnchorID: facts.AnchorID, BlockHash: fc.w.BlockHashes["settle"], Item: capture.ItemSettle})
				return ok
			})
			rt.Stop()
			waitFor(t, "the runtime's goroutines to end", func() bool { return runtime.NumGoroutine() <= goroutines })
		})
	}
}
