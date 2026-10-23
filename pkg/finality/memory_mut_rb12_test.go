// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
	"time"
)

// RB12-P0LIVE-FIX mutation gate (tools/pv2mut.ps1 over memory.go): each test below kills survivors of the first run; the mutants that
// cannot be killed are listed with their reasons in testdata/mutation_equivalents.json.

func TestRB12TheGateAndTheDefaultsOfTheBudget(t *testing.T) {
	if HeapGate(1<<30) != 2<<30 || HeapGate(3) != 6 {
		t.Fatalf("the heap gate is twice the budget: %d", HeapGate(1<<30))
	}
	if NewMemoryBudget(0).Limit() != DefaultMemoryBudget || NewMemoryBudget(-5).Limit() != DefaultMemoryBudget {
		t.Fatal("a budget of nothing is the default")
	}
	if NewMemoryBudget(1).Limit() != 1 {
		t.Fatal("a budget of one byte is one byte")
	}
	if NewMemoryBudget(7).Wait() != DefaultMemoryWait || DefaultMemoryWait != 45*time.Second {
		t.Fatal("the wait defaults to 45 seconds")
	}
}

// One byte is a reservation like any other.
func TestRB12OneByteIsReservedAndReleased(t *testing.T) {
	b := NewMemoryBudget(10)
	rel, err := b.Reserve(1, "x", 1)
	if err != nil || b.Used() != 1 {
		t.Fatalf("%v %d", err, b.Used())
	}
	rel()
	if b.Used() != 0 {
		t.Fatalf("%d", b.Used())
	}
	h := rb12Root(b)
	if err := h.Add(1); err != nil || b.Used() != 1 {
		t.Fatalf("a hold reserves one byte: %v %d", err, b.Used())
	}
	if err := h.Add(0); err != nil || b.Used() != 1 {
		t.Fatalf("a hold reserves nothing for nothing: %v %d", err, b.Used())
	}
	h.Release()
	if b.Used() != 0 {
		t.Fatalf("%d", b.Used())
	}
}

// A hold without a budget (no budget in its context: tests and one-shot recorders) reserves nothing and costs nothing.
func TestRB12AHoldWithoutABudgetReservesNothing(t *testing.T) {
	h := NewHold(context.Background(), 84532, "x")
	if err := h.Add(1 << 40); err != nil {
		t.Fatalf("%v", err)
	}
	h.Release()
	h.Release()
	if err := h.Add(5); err != nil {
		t.Fatalf("%v", err)
	}
}

// A hold made under another hold of the same build belongs to that build: it shares its place in the budget, so a build that holds all
// it can ever have is refused at once instead of waiting, and ending the inner hold does not end the build.
func TestRB12ANestedHoldBelongsToTheBuildOfItsParent(t *testing.T) {
	b := NewMemoryBudget(1000).WithWait(time.Minute)
	ctx := WithMemoryBudget(context.Background(), b)
	outer := NewHold(ctx, 84532, "build")
	inner := NewHold(WithHold(ctx, outer), 84532, "window")
	if err := outer.Add(600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := inner.Add(600); err == nil { // 600 held by this very build, 400 left: no release by another build can help
		t.Fatal("granted past the budget")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the nested hold waited %v for a release that cannot come: it is not part of its build", d)
	}
	if err := inner.Add(300); err != nil {
		t.Fatal(err)
	}
	if err := inner.Add(1); err != nil {
		t.Fatal(err)
	}
	if b.Used() != 901 {
		t.Fatalf("used %d", b.Used())
	}
	inner.Release()
	if b.Used() != 600 {
		t.Fatalf("releasing the inner hold gives back its 301 bytes and not the outer hold's: used %d", b.Used())
	}
	if err := outer.Add(10); err != nil {
		t.Fatalf("ending an inner hold must not end the build: %v", err)
	}
	if err := inner.Add(1); err == nil {
		t.Fatal("a released inner hold reserved")
	}
	outer.Release()
	if b.Used() != 0 {
		t.Fatalf("used %d", b.Used())
	}
}

// A build that holds nothing is never asked to give anything back, even when it is the youngest; when nobody holds anything of its own
// there is nobody to ask.
func TestRB12OnlyABuildThatHoldsSomethingIsAskedToYield(t *testing.T) {
	b := NewMemoryBudget(1000)
	plain, err := b.Reserve(1, "other", 300) // bytes of no build: they come back when their owner says so
	if err != nil {
		t.Fatal(err)
	}
	a, c := rb12Root(b), rb12Root(b) // a is older; c is younger and holds nothing
	if err := a.Add(400); err != nil {
		t.Fatal(err)
	}
	gotC := rb12AddAsync(c, 400)
	rb12Pending(t, gotC, "the build that holds nothing, with 300 left")
	gotA := rb12AddAsync(a, 400)
	select {
	case err := <-gotA:
		if err == nil {
			t.Fatal("granted past the budget")
		}
	case err := <-gotC:
		t.Fatalf("the youngest build holds nothing, so giving back would free nothing; the build that holds bytes must be the one asked: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("every build was waiting and none was asked to give up what it holds")
	}
	rb12Pending(t, gotC, "the build that holds nothing after the other was asked")
	a.Release()
	select {
	case err := <-gotC:
		if err != nil {
			t.Fatalf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not woken")
	}
	c.Release()
	plain()
	if b.Used() != 0 {
		t.Fatalf("used %d", b.Used())
	}

	// nobody holds anything of its own: both wait for the bytes of no build, nobody is asked, nothing panics
	plain2, err := b.Reserve(1, "other", 900)
	if err != nil {
		t.Fatal(err)
	}
	x, y := rb12Root(b), rb12Root(b)
	gotX, gotY := rb12AddAsync(x, 200), rb12AddAsync(y, 200)
	rb12Pending(t, gotX, "x")
	rb12Pending(t, gotY, "y")
	plain2()
	for _, ch := range []<-chan error{gotX, gotY} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatalf("%v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("not woken")
		}
	}
	x.Release()
	y.Release()
}

// Being granted a reservation does not mark a build as the one to give up: it waits like any other when its next reservation does not
// fit and the others are working.
func TestRB12ABuildThatWasGrantedWaitsForTheNextOneAndIsNotAskedToYield(t *testing.T) {
	b := NewMemoryBudget(1000)
	a, other := rb12Root(b), rb12Root(b)
	if err := other.Add(400); err != nil {
		t.Fatal(err)
	}
	if err := a.Add(500); err != nil {
		t.Fatal(err)
	}
	got := rb12AddAsync(a, 200) // 900 in use: does not fit; the other build is not waiting
	rb12Pending(t, got, "a build whose first reservation was granted")
	other.Release()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not woken by the release")
	}
	a.Release()
}

// A request for exactly the whole budget is not refused at once: it waits for the others to give theirs back.
func TestRB12ARequestForExactlyTheWholeBudgetWaitsForTheOthers(t *testing.T) {
	b := NewMemoryBudget(1000)
	x, y := rb12Root(b), rb12Root(b)
	if err := x.Add(400); err != nil {
		t.Fatal(err)
	}
	got := rb12AddAsync(y, 1000)
	rb12Pending(t, got, "a request for the whole budget with 600 left")
	x.Release()
	select {
	case err := <-got:
		if err != nil || b.Used() != 1000 {
			t.Fatalf("%v %d", err, b.Used())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not woken")
	}
	y.Release()
}

// A reader waiting inside a reservation is released the moment its build ends: it does not sit out the wait, and it keeps nothing.
func TestRB12AReaderWaitingForBytesStopsWhenItsBuildEnds(t *testing.T) {
	b := NewMemoryBudget(1000).WithWait(time.Minute)
	holder, waiter := rb12Root(b), rb12Root(b)
	if err := holder.Add(800); err != nil {
		t.Fatal(err)
	}
	got := rb12AddAsync(waiter, 500)
	rb12Pending(t, got, "the reader")
	waiter.Release()
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("a reservation for an ended build was granted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reader of an ended build went on waiting")
	}
	if b.Used() != 800 {
		t.Fatalf("used %d", b.Used())
	}
	holder.Release()
}

// A build ends once: releasing its hold twice does not count it twice among the builds that have finished.
func TestRB12AHoldIsCountedOnceAmongTheFinishedBuilds(t *testing.T) {
	b := NewMemoryBudget(1000)
	h := rb12Root(b)
	_ = h.Add(10)
	h.Release()
	h.Release()
	h.Release()
	b.mu.Lock()
	n := b.finished
	b.mu.Unlock()
	if n != 1 {
		t.Fatalf("one build finished, counted %d", n)
	}
	if yielded, finished := h.Yielded(); yielded || finished != 1 {
		t.Fatalf("%v %d", yielded, finished)
	}
}

// waitFinished returns true for a build that ended without yielding, false for none, and does not count a yielded build as finished.
func TestRB12AYieldedBuildRunsAgainOnlyWhenAnotherBuildHasFinished(t *testing.T) {
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
	yielded, mark := young.Yielded()
	if !yielded {
		t.Fatal("not marked as yielded")
	}
	idle := rb12Root(b) // a third build that is in the budget and holds nothing: the budget is not empty when the older one ends
	ctx := context.Background()
	if b.waitFinished(ctx, mark, 60*time.Millisecond) {
		t.Fatal("told to run again before any other build finished (a yielded build is no finished build)")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if b.waitFinished(cancelled, mark, time.Minute) {
		t.Fatal("a cancelled wait said the build may run again")
	}
	<-gotOld
	go func() {
		time.Sleep(40 * time.Millisecond)
		old.Release()
	}()
	if !b.waitFinished(ctx, mark, 5*time.Second) {
		t.Fatal("the older build finished and the yielded one was not told to run again")
	}
	idle.Release()
}

// A build that holds a single byte is a build that holds something: it is the one asked to yield when every build is blocked.
func TestRB12ABuildHoldingOneByteIsAskedToYieldWhenEveryBuildIsBlocked(t *testing.T) {
	b := NewMemoryBudget(1000)
	plain, err := b.Reserve(1, "other", 980)
	if err != nil {
		t.Fatal(err)
	}
	a, c := rb12Root(b), rb12Root(b) // a is older and holds one byte; c is younger and holds nothing
	if err := a.Add(1); err != nil {
		t.Fatal(err)
	}
	gotC := rb12AddAsync(c, 20)
	rb12Pending(t, gotC, "the build that holds nothing")
	gotA := rb12AddAsync(a, 25)
	select {
	case err := <-gotA:
		if err == nil {
			t.Fatal("granted past the budget")
		}
	case err := <-gotC:
		t.Fatalf("the build that holds the byte is the one to be asked: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("a build holding one byte was not asked to yield")
	}
	a.Release()
	plain()
	if err := <-gotC; err != nil {
		t.Fatal(err)
	}
	c.Release()
}

// Being asked to yield is a one-shot signal: the build's next reservation waits like any other when the others are working again.
func TestRB12AYieldIsASignalForOneRefusalOnly(t *testing.T) {
	b := NewMemoryBudget(1000)
	plain, err := b.Reserve(1, "other", 100)
	if err != nil {
		t.Fatal(err)
	}
	old, young := rb12Root(b), rb12Root(b)
	_ = old.Add(450)
	_ = young.Add(450)
	gotOld := rb12AddAsync(old, 100)
	rb12Pending(t, gotOld, "older, with the budget full")
	if err := young.Add(100); err == nil { // every build is blocked: the younger gives way
		t.Fatal("the younger build was not asked to yield")
	}
	plain() // 100 free again: the older build's 100 fits and it works on
	if err := <-gotOld; err != nil {
		t.Fatal(err)
	}
	got := rb12AddAsync(young, 200) // the budget is full again and the older build is not blocked: this one waits
	rb12Pending(t, got, "the build that yielded, asking again while the older build works")
	old.Release()
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	young.Release()
}

// A reservation through a released hold is refused AS released (the token says so), not as an ordinary shortage.
func TestRB12AReleasedHoldIsRefusedAsReleased(t *testing.T) {
	b := NewMemoryBudget(1000)
	h := rb12Root(b)
	_ = h.Add(10)
	h.Release()
	err := h.Add(10)
	if se, ok := AsNamed(err); !ok || se.Fields["what"] != "build/released" {
		t.Fatalf("%v", err)
	}
	// a nested hold that is released: the same, and the build goes on
	ctx := WithMemoryBudget(context.Background(), b)
	outer := NewHold(ctx, 84532, "build")
	inner := NewHold(WithHold(ctx, outer), 84532, "window")
	if err := inner.Add(1); err != nil || b.Used() != 1 {
		t.Fatalf("%v %d", err, b.Used())
	}
	inner.Release()
	if b.Used() != 0 {
		t.Fatalf("the single byte of the inner hold is given back: %d", b.Used())
	}
	err = inner.Add(10)
	if se, ok := AsNamed(err); !ok || se.Fields["what"] != "window/released" || b.Used() != 0 {
		t.Fatalf("%v used=%d", err, b.Used())
	}
	outer.Release()
}
