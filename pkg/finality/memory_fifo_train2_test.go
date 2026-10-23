// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12-GO-INT D3 (V-T2): the budget had no admission order. A request that fits was granted while an OLDER build's request waited, so
// two younger builds rolling 450-900 bytes through a 1000-byte budget refused an older 600-byte request after the full wait (77 younger
// grants were made meanwhile), and every new attempt of the same leg took a NEW age, so a hold (which charges no back-off) lost again at
// the next poll.
//
// THE RULE: builds are admitted in age order. A request by build T is granted when it fits AND no build older than T is waiting in a
// reservation; the oldest waiter is granted as soon as it fits, and the bytes only fall while it waits (younger builds cannot take them),
// so the delay of the oldest request is bounded by the time its holders take to finish or, when every build is blocked, by the yield rule
// (the youngest holder gives back everything). A plain Reserve (no build: the backfill's 16 MiB) is not ordered and is not delayed by
// it; it never waits and is bounded in size. A smaller younger request therefore never passes an older one that waits.

func rb12WaitUntil(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestRB12GOINTAYoungerRequestNeverPassesAnOlderOneThatWaits(t *testing.T) {
	b := NewMemoryBudget(1000).WithWait(5 * time.Second)
	ctx := WithMemoryBudget(context.Background(), b)
	old := newHold(ctx, 84532, "old", b.newAge())
	y1 := newHold(ctx, 84532, "y1", b.newAge())
	y2 := newHold(ctx, 84532, "y2", b.newAge())
	y3 := newHold(ctx, 84532, "y3", b.newAge())
	if err := y1.Add(450); err != nil {
		t.Fatal(err)
	}
	if err := y2.Add(450); err != nil {
		t.Fatal(err)
	}
	// the OLDER build asks for 600: it does not fit (900 in use)
	var oldErr error
	var oldDone sync.WaitGroup
	oldGranted := make(chan struct{})
	oldDone.Add(1)
	go func() {
		defer oldDone.Done()
		oldErr = old.Add(600)
		close(oldGranted)
	}()
	rb12WaitUntil(t, "the older request to wait", func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.waiting == 1 })
	y1.Release() // 450 in use: the older 600 still does not fit, a younger 450 does
	var y3Err error
	y3Granted := make(chan struct{})
	go func() {
		y3Err = y3.Add(450)
		close(y3Granted)
	}()
	select {
	case <-y3Granted:
		t.Fatalf("a younger request was granted while an older one waited (used %d): the older one starves under rolling younger holders", b.Used())
	case <-time.After(150 * time.Millisecond):
	}
	y2.Release() // nothing else is in use: the older request is next
	select {
	case <-oldGranted:
	case <-time.After(3 * time.Second):
		t.Fatalf("the older request was not granted although everything was released (used %d)", b.Used())
	}
	if oldErr != nil {
		t.Fatalf("the older request was refused: %v", oldErr)
	}
	select {
	case <-y3Granted:
		t.Fatalf("the younger request fits beside the older one's 600 only by exceeding the budget (used %d)", b.Used())
	case <-time.After(100 * time.Millisecond):
	}
	old.Release() // now the younger one is next
	select {
	case <-y3Granted:
	case <-time.After(3 * time.Second):
		t.Fatal("the younger request was not granted after the older build ended")
	}
	if y3Err != nil {
		t.Fatal(y3Err)
	}
	oldDone.Wait()
	y3.Release()
	if b.Used() != 0 {
		t.Fatalf("used %d after everything was released", b.Used())
	}
}

// Order does not cost the deadlock-freedom of the yield rule: an older build waiting for what a younger build holds, with the younger
// build blocked behind the older one, ends with the youngest holder giving back.
func TestRB12GOINTOrderedAdmissionStillYieldsWhenEveryBuildIsBlocked(t *testing.T) {
	b := NewMemoryBudget(1000).WithWait(2 * time.Second)
	ctx := WithMemoryBudget(context.Background(), b)
	old := newHold(ctx, 84532, "old", b.newAge())
	young := newHold(ctx, 84532, "young", b.newAge())
	if err := young.Add(600); err != nil {
		t.Fatal(err)
	}
	oldErr := make(chan error, 1)
	go func() { oldErr <- old.Add(600) }() // does not fit: waits for the younger build's 600
	rb12WaitUntil(t, "the older request to wait", func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.waiting == 1 })
	youngErr := make(chan error, 1)
	go func() { // would fit, but an older build waits: it waits behind it, and now every build is blocked; a refused build is released by its prover
		err := young.Add(100)
		if err != nil {
			young.Release()
		}
		youngErr <- err
	}()
	select {
	case err := <-oldErr:
		if err != nil {
			t.Fatalf("the older request must be granted once the youngest holder gave back: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock: the older and the younger build wait for each other")
	}
	if err := <-youngErr; err == nil {
		t.Fatal("the younger build gave back its bytes (it yielded); its request cannot be granted")
	}
	yielded, _ := young.Yielded()
	if !yielded {
		t.Fatal("the younger build was not marked as having yielded")
	}
	old.Release()
	young.Release()
	if b.Used() != 0 {
		t.Fatalf("used %d", b.Used())
	}
}

// A build that is held (refused after its full wait) keeps its age for its next attempt: a hold charges no back-off, so the leg is asked
// again after PendingRetry and must not queue behind every build that started in between.
func TestRB12GOINTAHeldLegKeepsItsAgeAcrossAttempts(t *testing.T) {
	budget := NewMemoryBudget(1 << 20)
	u, src, clock, _, logs := rb12Fixture(t, rb12HoldCfg(budget),
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, _ *ethproof.Settlement, _ LevelSet, _ Level) (*Addendum, *PendingState, error) {
				return nil, nil, ReserveRow(ctx, 10<<20) // larger than the whole budget: refused at once, a hold
			}
		})
	src.add(leg(1))
	for pass := 1; pass <= 6; pass++ {
		if rep := u.RunOnce(context.Background()); rep.Attempts != 1 || rep.Failed != 0 {
			t.Fatalf("pass %d: %+v\n%s", pass, rep, logs.Joined())
		}
		clock.Advance(2*time.Minute + time.Second)
	}
	budget.mu.Lock()
	issued := budget.age
	budget.mu.Unlock()
	// one age per level asked (l1_posted and finalized), not one per ask
	if issued != 2 {
		t.Fatalf("%d ages were issued for 12 held asks of one leg's two levels: every attempt took a new age and queued behind the builds that started in between", issued)
	}
	// a build that ends otherwise gives its age up: the next attempt of the leg is a new build
	u2, src2, clock2, _, _ := rb12Fixture(t, rb12HoldCfg(NewMemoryBudget(1<<20)),
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
				return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: target, Reason: "game_unresolved"}, nil
			}
		})
	src2.add(leg(1))
	b2 := u2.cfg.Memory
	for pass := 1; pass <= 3; pass++ {
		u2.RunOnce(context.Background())
		clock2.Advance(3 * time.Minute)
	}
	b2.mu.Lock()
	n := b2.age
	b2.mu.Unlock()
	if n != 6 {
		t.Fatalf("a build that finished without a hold takes a new age each time: %d ages for 3 passes x 2 levels", n)
	}
}
