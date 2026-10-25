// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"testing"
	"time"
)

// This file sorts before every other test file of the package and every assertion in it is bounded (fixed small inputs, literal
// expected values, no loop whose count depends on a constant under test). pv2mut runs a mutant with -test.failfast, so a mutant of
// a spine constant or budget boundary fails HERE, in microseconds, and the long simulations of spine_test.go and its siblings (which
// loop until a budget or a backoff lets them finish, and exhausted memory when a constant became 0) never run for it.

func TestBoundedSpineConstantsArePinned(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want time.Duration
	}{
		{"DefaultSpineBudget", DefaultSpineBudget, 150 * time.Second},
		{"SpineResumeDelay", SpineResumeDelay, 2 * time.Second},
		{"SpineMinReserve", SpineMinReserve, 10 * time.Second},
		{"SpineErrorBase", SpineErrorBase, 30 * time.Second},
		{"SpineErrorMax", SpineErrorMax, 15 * time.Minute},
		{"MaxRetryAfterKept", MaxRetryAfterKept, 30 * time.Minute},
		{"SpineLegExpiry", SpineLegExpiry, time.Hour},
	} {
		if c.got != c.want {
			t.Fatalf("%s = %s, want %s", c.name, c.got, c.want)
		}
	}
	if SpineWindow != 40 || spineHeadCap != 64 {
		t.Fatalf("SpineWindow %d spineHeadCap %d", SpineWindow, spineHeadCap)
	}
}

func TestBoundedPlanSpansHasLiteralWindows(t *testing.T) {
	got := PlanSpans(1000, 1119)
	want := []Span{{1080, 1119, true}, {1040, 1079, true}, {1000, 1039, true}}
	if len(got) != len(want) {
		t.Fatalf("%d spans, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("span %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestBoundedBudgetDecisionsAtOneNanosecond(t *testing.T) {
	ns := time.Nanosecond
	for _, c := range []struct {
		spent, longest, budget time.Duration
		want                   bool
	}{
		{0, 0, ns, true}, {0, 0, 0, false}, {0, 0, -ns, false}, {ns, 0, ns, true}, {ns, ns, ns, false}, {time.Second, 2 * time.Second, 3 * time.Second, true},
	} {
		if got := BudgetAllows(c.spent, c.longest, c.budget); got != c.want {
			t.Fatalf("BudgetAllows(%s,%s,%s) = %v", c.spent, c.longest, c.budget, got)
		}
	}
	for _, c := range []struct{ left, want time.Duration }{
		{-ns, 0}, {-time.Second, 0}, {0, 10 * time.Second}, {49 * time.Second, 10 * time.Second}, {60 * time.Second, 12 * time.Second},
	} {
		if got := AttemptReserve(c.left); got != c.want {
			t.Fatalf("AttemptReserve(%s) = %s, want %s", c.left, got, c.want)
		}
	}
	for _, c := range []struct{ cap, left, want time.Duration }{
		{ns, -ns, ns}, {0, -ns, 150 * time.Second}, {-ns, -ns, 150 * time.Second}, {5 * time.Second, -ns, 5 * time.Second},
		{100 * time.Second, 30 * time.Second, 20 * time.Second}, {10 * time.Second, 100 * time.Second, 10 * time.Second}, {10 * time.Second, 10 * time.Second, 0},
	} {
		if got := AttemptBudget(c.cap, c.left); got != c.want {
			t.Fatalf("AttemptBudget(%s,%s) = %s, want %s", c.cap, c.left, got, c.want)
		}
	}
	for _, c := range []struct {
		left, reserve, longest time.Duration
		want                   bool
	}{
		{-ns, 10 * time.Second, time.Second, true}, {0, 0, 0, true}, {5 * time.Second, 10 * time.Second, time.Second, false}, {11 * time.Second, 10 * time.Second, time.Second, true},
	} {
		if got := FetchFits(c.left, c.reserve, c.longest); got != c.want {
			t.Fatalf("FetchFits(%s,%s,%s) = %v", c.left, c.reserve, c.longest, got)
		}
	}
}

func TestBoundedPauseAfterIsALiteralLadder(t *testing.T) {
	ns := time.Nanosecond
	for _, c := range []struct {
		kind   PauseKind
		retry  time.Duration
		stalls int
		want   time.Duration
	}{
		{PauseBudget, 0, 0, 2 * time.Second}, {PauseBudget, time.Hour, 9, 2 * time.Second},
		{PauseThrottled, ns, 0, 2 * time.Second}, {PauseThrottled, 5 * time.Second, 0, 5 * time.Second}, {PauseThrottled, time.Hour, 0, 30 * time.Minute},
		{PauseThrottled, 0, 0, 30 * time.Second}, {PauseThrottled, -ns, 1, time.Minute},
		{PauseError, 0, 0, 30 * time.Second}, {PauseError, 0, 1, time.Minute}, {PauseError, 0, 4, 480 * time.Second}, {PauseError, 0, 5, 15 * time.Minute}, {PauseError, 0, 50, 15 * time.Minute},
	} {
		if got := PauseAfter(c.kind, c.retry, c.stalls); got != c.want {
			t.Fatalf("PauseAfter(%d,%s,%d) = %s, want %s", c.kind, c.retry, c.stalls, got, c.want)
		}
	}
}

func TestBoundedHeadCacheEvictsTheOldestAndStaysAtItsCap(t *testing.T) {
	c := newSpineCore(func() time.Time { return time.Unix(1000, 0) })
	h := func(i int) [32]byte { return [32]byte{byte(i), byte(i >> 8), 0x77} }
	for i := 0; i <= spineHeadCap+2; i++ { // 67 distinct heads: 3 are evicted
		c.putHead(h(i), []byte{byte(i)})
	}
	for i := 0; i < 3; i++ {
		if _, ok := c.head(h(i)); ok {
			t.Fatalf("head %d should have been evicted", i)
		}
	}
	for i := 3; i <= spineHeadCap+2; i++ {
		if b, ok := c.head(h(i)); !ok || len(b) != 1 || b[0] != byte(i) {
			t.Fatalf("head %d missing or wrong", i)
		}
	}
	if len(c.heads) != spineHeadCap || len(c.order) != spineHeadCap || c.order[0] != h(3) {
		t.Fatalf("heads %d order %d first %x", len(c.heads), len(c.order), c.order[0])
	}
	c.putHead(h(3), []byte{0xff}) // a head already held is kept as it is
	if b, _ := c.head(h(3)); b[0] != 3 || len(c.order) != spineHeadCap {
		t.Fatal("a repeated head replaced the held one or grew the order")
	}
}

func TestBoundedNoteAndFetchCountExactNanoseconds(t *testing.T) {
	base := time.Unix(5000, 0)
	cur := base
	r := &spineRun{p: &Prover{Now: func() time.Time { return cur }}}
	cur = base.Add(-time.Nanosecond) // the clock stepped back by one nanosecond
	r.note(base)
	if r.spent != 0 || r.longest != 0 {
		t.Fatalf("a clock that stepped back counted %s / %s", r.spent, r.longest)
	}
	cur = base.Add(3 * time.Second)
	r.note(base)
	cur = base.Add(time.Second)
	r.note(base)
	if r.spent != 4*time.Second || r.longest != 3*time.Second {
		t.Fatalf("spent %s longest %s, want 4s and 3s", r.spent, r.longest)
	}

	// a chunk another leg already fetched: the wait for it is counted to the nanosecond
	var n int64
	tick := func() time.Time { n++; return base.Add(time.Duration(n)) }
	sc := newSpineCore(tick)
	k := spineKey{End: 1119, Count: 40}
	sc.chunks.put(k, &spineEntry{enc: []byte{1}})
	n = 0
	run := &spineRun{p: &Prover{Now: tick}, sc: sc, ctx: context.Background(), budget: time.Hour}
	e, err := run.fetch(Span{Start: 1080, End: 1119, Stored: true}, [32]byte{}, k)
	if err != nil || e == nil || run.reused != 1 {
		t.Fatalf("fetch of a chunk already held: %v %v reused=%d", e, err, run.reused)
	}
	if run.spent != time.Nanosecond {
		t.Fatalf("the wait counted %s, want exactly 1ns", run.spent)
	}
}
