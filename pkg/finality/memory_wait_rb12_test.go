// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"sync"
	"testing"
	"time"
)

// RB12-P0LIVE-FIX D2: a reservation the budget cannot cover does not fail at once, it waits (bounded) for a release; builds that all
// wait for each other are broken up by the youngest giving back what it holds; a request that waiting cannot help is refused at once.

func rb12Root(b *MemoryBudget) *Hold { // a hold of a build of its own
	return NewHold(WithMemoryBudget(context.Background(), b), 84532, "build")
}

func rb12AddAsync(h *Hold, n int64) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- h.Add(n) }()
	return ch
}

func rb12Pending(t *testing.T, ch <-chan error, what string) {
	t.Helper()
	select {
	case err := <-ch:
		t.Fatalf("%s: returned (%v) instead of waiting", what, err)
	case <-time.After(80 * time.Millisecond):
	}
}

func TestRB12AReservationThatDoesNotFitWaitsForARelease(t *testing.T) {
	b := NewMemoryBudget(1000)
	a, c := rb12Root(b), rb12Root(b)
	if err := a.Add(800); err != nil {
		t.Fatal(err)
	}
	got := rb12AddAsync(c, 500)
	rb12Pending(t, got, "a reservation of 500 with 200 left")
	a.Release()
	select {
	case err := <-got:
		if err != nil || b.Used() != 500 {
			t.Fatalf("the release lets the waiting reservation through: %v used=%d", err, b.Used())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting reservation was not woken by the release")
	}
	c.Release()
	if b.Used() != 0 {
		t.Fatalf("used %d", b.Used())
	}
}

func TestRB12TheWaitIsBoundedAndEndsWithItsContext(t *testing.T) {
	b := NewMemoryBudget(1000).WithWait(120 * time.Millisecond)
	a, c := rb12Root(b), rb12Root(b)
	if err := a.Add(800); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := c.Add(500)
	if se, ok := AsNamed(err); !ok || se.Code != CodeMemoryBudget || se.Fields["in_use"] != uint64(800) || se.Fields["requested"] != uint64(500) {
		t.Fatalf("after its wait the reservation is refused by name, with what was asked and held: %v", err)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 3*time.Second {
		t.Fatalf("the refusal came after %v; the wait is 120ms", d)
	}
	// a wait ends with the context of the reader
	long := NewMemoryBudget(1000).WithWait(time.Minute)
	x, y := rb12Root(long), rb12Root(long)
	if err := x.Add(800); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- y.AddCtx(ctx, 500) }()
	rb12Pending(t, done, "a reservation under a live context")
	cancel()
	select {
	case err := <-done:
		if _, ok := AsNamed(err); !ok {
			t.Fatalf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled reader kept waiting")
	}
	if long.Used() != 800 {
		t.Fatalf("used %d", long.Used())
	}
}

// Two builds that hold 500 each and ask for 100 more would wait for each other for ever. The younger gives back what it holds (its
// reservation is refused by name and the build is marked as yielded), so the older one goes on; the older one is never the one to give up.
func TestRB12WhenEveryBuildWaitsTheYoungestGivesBackWhatItHoldsAndTheOldestGoesOn(t *testing.T) {
	b := NewMemoryBudget(1000)
	old, young := rb12Root(b), rb12Root(b) // old was made first
	if err := old.Add(500); err != nil {
		t.Fatal(err)
	}
	if err := young.Add(500); err != nil {
		t.Fatal(err)
	}
	gotOld := rb12AddAsync(old, 100)
	rb12Pending(t, gotOld, "the older build asking for more with the budget full")
	gotYoung := rb12AddAsync(young, 100)
	select {
	case err := <-gotYoung:
		if se, ok := AsNamed(err); !ok || se.Code != CodeMemoryBudget {
			t.Fatalf("the younger build is refused by name: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("every build was waiting and none was asked to give up what it holds")
	}
	rb12Pending(t, gotOld, "the older build before the younger released")
	young.Release()
	if yielded, _ := young.Yielded(); !yielded {
		t.Fatal("the younger build is marked as yielded: it must be run again after another build has finished")
	}
	select {
	case err := <-gotOld:
		if err != nil {
			t.Fatalf("the older build was made to give up: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the older build was not let through after the younger released")
	}
	if yielded, _ := old.Yielded(); yielded {
		t.Fatal("the older build must never be the one to yield")
	}
	old.Release()
	if b.Used() != 0 {
		t.Fatalf("used %d", b.Used())
	}
}

// A yielded build is run again once another build has finished (or nobody else is in the budget); it does not spin.
func TestRB12AYieldedBuildWaitsForAnotherBuildToFinishBeforeItIsRunAgain(t *testing.T) {
	b := NewMemoryBudget(1000)
	old, young := rb12Root(b), rb12Root(b)
	_ = old.Add(500)
	_ = young.Add(500)
	gotOld := rb12AddAsync(old, 100)
	rb12Pending(t, gotOld, "older")
	if err := young.Add(100); err == nil {
		t.Fatal("the younger build was not asked to give up")
	}
	young.Release()
	_, mark := young.Yielded()
	ctx := context.Background()
	if b.waitFinished(ctx, mark, 80*time.Millisecond) {
		t.Fatal("the yielded build was told to run again while the older build is still working")
	}
	<-gotOld
	released := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		old.Release()
		close(released)
	}()
	if !b.waitFinished(ctx, mark, 5*time.Second) {
		t.Fatal("the yielded build was not told to run again when the older build finished")
	}
	<-released
	// nobody left: run at once
	if !b.waitFinished(ctx, mark+100, time.Millisecond) {
		t.Fatal("with no other build in the budget the yielded build runs at once")
	}
}

// Waiting cannot help a request larger than the whole budget, nor one a build makes when everything in use is its own: both are refused at
// once, not after the wait.
func TestRB12ARequestThatNoReleaseCanCoverIsRefusedAtOnce(t *testing.T) {
	b := NewMemoryBudget(1000).WithWait(time.Minute)
	a, other := rb12Root(b), rb12Root(b)
	start := time.Now()
	if err := a.Add(2000); err == nil {
		t.Fatal("a request larger than the whole budget was granted")
	}
	if err := a.Add(600); err != nil {
		t.Fatal(err)
	}
	if err := a.Add(500); err == nil { // 600 of its own, 400 left: nothing another build can release helps
		t.Fatal("a request that cannot fit even when every other build is gone was granted")
	}
	if err := other.Add(2000); err == nil {
		t.Fatal("a request larger than the whole budget was granted while another build holds bytes")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the refusals waited %v", d)
	}
}

// Many builds that together ask for far more than the budget all end: none is left waiting for ever, the budget is never over-committed
// and it is empty at the end (builds that yield are run again, as the upgrader does).
func TestRB12ManyBuildsOverOneBudgetAllEndAndNeverOvercommit(t *testing.T) {
	b := NewMemoryBudget(1000).WithWait(20 * time.Second)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var peak int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			age := b.newAge()
			for attempt := 0; attempt < 200; attempt++ {
				h := newHold(WithMemoryBudget(context.Background(), b), 1, "build", age)
				ok := true
				for k := 0; k < 8 && ok; k++ { // 8 x 100 = 800 of 1000 per build, 12 builds
					if err := h.Add(100); err != nil {
						ok = false
						break
					}
					mu.Lock()
					if u := b.Used(); u > peak {
						peak = u
					}
					mu.Unlock()
					time.Sleep(time.Millisecond)
				}
				h.Release()
				if ok {
					return
				}
				yielded, mark := h.Yielded()
				if !yielded || !b.waitFinished(context.Background(), mark, 20*time.Second) {
					t.Errorf("a build was refused without yielding (attempt %d)", attempt)
					return
				}
			}
			t.Errorf("a build never got through")
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("builds are left waiting for each other")
	}
	if peak > 1000 || b.Used() != 0 {
		t.Fatalf("peak %d used %d", peak, b.Used())
	}
}
