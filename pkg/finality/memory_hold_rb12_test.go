// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12-P0LIVE-FIX D3 / F7 (independent verifier V-RB12-P0-LIVE, 2026-10-23): a Hold is terminal once released and is safe against
// concurrent use; an abandoned prover is still counted by the budget until it returns. These tests use only the configuration surface
// and the API that exist at the verified commit 85c252b, so each one runs there and fails by its assertion.

func rb12HoldCfg(budget *MemoryBudget) UpgraderConfig {
	return UpgraderConfig{Memory: budget, HeapInUse: func() uint64 { return 0 }, BuildTimeout: 20 * time.Second}
}

// D3: Release is terminal. Nothing reserved after it is held; the budget is not leaked.
func TestRB12AReleasedHoldIsTerminalAndReleasingTwiceIsHarmless(t *testing.T) {
	b := NewMemoryBudget(10_000)
	h := NewHold(WithMemoryBudget(context.Background(), b), 84532, "x")
	if err := h.Add(1000); err != nil || b.Used() != 1000 {
		t.Fatalf("%v %d", err, b.Used())
	}
	h.Release()
	if b.Used() != 0 {
		t.Fatalf("used %d after Release", b.Used())
	}
	err := h.Add(1000)
	if se, ok := AsNamed(err); !ok || se.Code != CodeMemoryBudget {
		t.Fatalf("an Add after Release is refused by name: %v", err)
	}
	if b.Used() != 0 {
		t.Fatalf("an Add after Release leaked %d bytes into the budget for the life of the process", b.Used())
	}
	h.Release()
	h.Release()
	if b.Used() != 0 {
		t.Fatalf("used %d", b.Used())
	}
}

// D3: Release racing with reservations (a prover's own goroutines keep reading while the build ends) leaves nothing held: whatever an
// Add took before the Release is given back by it, whatever came after is refused.
func TestRB12ReleaseDuringReservationsLeavesNothingHeld(t *testing.T) {
	for round := 0; round < 20; round++ {
		b := NewMemoryBudget(1 << 30)
		h := NewHold(WithMemoryBudget(context.Background(), b), 84532, "x")
		var released atomic.Bool
		var started, wg sync.WaitGroup
		started.Add(8)
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				started.Done()
				for !released.Load() {
					_ = h.Add(1)
				}
				for i := 0; i < 200; i++ { // reads that go on after the build ended
					_ = h.Add(1)
				}
			}()
		}
		started.Wait()
		time.Sleep(time.Millisecond)
		h.Release()
		released.Store(true)
		wg.Wait()
		if b.Used() != 0 {
			t.Fatalf("round %d: %d bytes are still reserved after Release returned and every reader stopped", round, b.Used())
		}
	}
}

// F7: a prover that ignores its context keeps running after the build was abandoned at BuildTimeout. What it has read is still in the
// process, so the budget still counts it until the prover really returns.
func TestRB12AnAbandonedProverKeepsItsReservationUntilItReturns(t *testing.T) {
	budget := NewMemoryBudget(1 << 20)
	unblock := make(chan struct{})
	var calls atomic.Int64
	cfg := rb12HoldCfg(budget)
	cfg.BuildTimeout = 50 * time.Millisecond
	u, src, _, _, logs := rb12Fixture(t, cfg,
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, _ *ethproof.Settlement, _ LevelSet, _ Level) (*Addendum, *PendingState, error) {
				calls.Add(1)
				if err := ReserveRow(ctx, 200_000); err != nil { // cost 300000
					return nil, nil, err
				}
				<-unblock // ignores ctx
				return nil, nil, ctx.Err()
			}
		})
	src.add(leg(1))
	rep := u.RunOnce(context.Background())
	if rep.Failed != 1 {
		t.Fatalf("the abandoned build is the named timeout: %+v\n%s", rep, logs.Joined())
	}
	// one abandoned prover per level the leg lacks (l1_posted and finalized), each with 300000 bytes of rows in memory
	if n := calls.Load(); n < 1 {
		t.Fatalf("the prover was not asked")
	} else if got := budget.Used(); got != 300_000*n {
		t.Fatalf("the %d provers are still running with their rows in memory: the budget must still count %d, counts %d", n, 300_000*n, got)
	}
	close(unblock)
	deadline := time.Now().Add(5 * time.Second)
	for budget.Used() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if budget.Used() != 0 {
		t.Fatalf("the reservation is given back when the prover returns: %d", budget.Used())
	}
}
