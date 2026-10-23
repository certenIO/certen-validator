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

// RB12-P0LIVE-FIX D2 (independent verifier V-RB12-P0-LIVE, 2026-10-23): a memory refusal is a hold of the process, not a failure of the
// leg. These tests use only the configuration surface and the API that exist at the verified commit 85c252b, so each one runs there
// and fails by its assertion.

// D2: a refusal of the memory budget is not a failure of the leg. It advances no back-off exponent, makes the leg no suspect, is
// asked again at PendingRetry, and the status row names the state (pending class: the leg waits) with the time of the next ask.
func TestRB12AMemoryRefusalIsAProcessHoldNotALegFailure(t *testing.T) {
	budget := NewMemoryBudget(1 << 20)
	u, src, clock, rec, logs := rb12Fixture(t, rb12HoldCfg(budget),
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, _ *ethproof.Settlement, _ LevelSet, _ Level) (*Addendum, *PendingState, error) {
				return nil, nil, ReserveRow(ctx, 10<<20) // 15 MiB against a 1 MiB budget
			}
		})
	status := newRB12Status()
	u.cfg.Status = status
	src.add(leg(1))
	reg := loadRegistry(t)

	retry := 2 * time.Minute // the default PendingRetry
	for pass := 1; pass <= 6; pass++ {
		at := clock.Now()
		rep := u.RunOnce(context.Background())
		if rep.Attempts != 1 || rep.Failed != 0 {
			t.Fatalf("pass %d: a memory refusal is a hold, not a failed attempt, and the leg is asked again at PendingRetry: %+v\n%s", pass, rep, logs.Joined())
		}
		if u.isSuspect(leg(1)) {
			t.Fatalf("pass %d: a memory refusal made the leg a suspect", pass)
		}
		if n := rec.failures[CodeMemoryBudget]; n != 0 {
			t.Fatalf("pass %d: the refusal was counted as a build failure %d times", pass, n)
		}
		row, ok := status.row(leg(1), LevelL1Posted)
		if !ok || row.State == nil || row.State.Code != CodeMemoryBudget || row.Class != BuilderPending {
			t.Fatalf("pass %d: the status row names the hold (class pending, finality_memory_budget_exceeded): %+v", pass, row)
		}
		if _, has := row.State.Fields["attempt"]; has {
			t.Fatalf("pass %d: a hold is no failed attempt and carries no attempt ordinal: %v", pass, row.State.Fields)
		}
		want := at.Add(retry).UTC().Format(time.RFC3339)
		if got := row.State.Fields["next_attempt_at"]; got != want {
			t.Fatalf("pass %d: next_attempt_at=%v want %s (PendingRetry, never an exponent)", pass, got, want)
		}
		if !row.ETA.Equal(at.Add(retry)) {
			t.Fatalf("pass %d: the pending row carries the retry time as its eta: %v want %v", pass, row.ETA, at.Add(retry))
		}
		if msg := conforms(reg, row.State); msg != "" {
			t.Fatalf("pass %d: the stored state is not in the registry: %s", pass, msg)
		}
		// not asked before the recorded time
		clock.Advance(retry - time.Second)
		if rep := u.RunOnce(context.Background()); rep.Attempts != 0 {
			t.Fatalf("pass %d: asked again before next_attempt_at: %+v", pass, rep)
		}
		clock.Advance(2 * time.Second)
	}
}

// D2: four builds that together need more than the budget are not all refused. A build that cannot reserve waits for a release; when
// every build waits, the youngest gives up what it holds and waits for another build to finish; none of them fails, backs off or
// becomes a suspect, and all four complete in one pass.
func TestRB12FourContendingBuildsWaitForEachOtherAndNoneFailsOrBacksOff(t *testing.T) {
	budget := NewMemoryBudget(1000) // each build needs 600: four at once need 2400
	var done sync.Map
	var doneN atomic.Int64
	var peak atomic.Int64
	cfg := rb12HoldCfg(budget)
	cfg.Concurrency = 4
	u, src, _, rec, logs := rb12Fixture(t, cfg,
		func(src *rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
				id := src.legOf(s)
				if _, ok := done.Load(id); !ok {
					for i := 0; i < 6; i++ {
						if err := ReserveRow(ctx, 67); err != nil { // RowCost(67) = 100
							return nil, nil, err
						}
						if u := budget.Used(); u > peak.Load() {
							peak.Store(u)
						}
						time.Sleep(3 * time.Millisecond)
					}
					time.Sleep(20 * time.Millisecond)
					if _, loaded := done.LoadOrStore(id, true); !loaded {
						doneN.Add(1)
					}
				}
				return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: target, Reason: "game_unresolved"}, nil
			}
		})
	status := newRB12Status()
	u.cfg.Status = status
	for i := 1; i <= 4; i++ {
		src.add(leg(i))
	}
	rep := u.RunOnce(context.Background())
	if rep.Failed != 0 || rep.BuildHeld != 0 || rec.failures[CodeMemoryBudget] != 0 {
		t.Fatalf("contention for memory failed legs: %+v failures=%v\n%s", rep, rec.failures, logs.Joined())
	}
	if doneN.Load() != 4 {
		t.Fatalf("%d of 4 builds completed in the pass (none may be left refused): %+v\n%s", doneN.Load(), rep, logs.Joined())
	}
	for i := 1; i <= 4; i++ {
		if u.isSuspect(leg(i)) {
			t.Fatalf("leg %d is a suspect", i)
		}
		if row, ok := status.row(leg(i), LevelL1Posted); ok && row.State != nil {
			if _, has := row.State.Fields["attempt"]; has || row.Class == BuilderUnavailable {
				t.Fatalf("leg %d: a failure row from memory contention: %+v", i, row)
			}
		}
	}
	if peak.Load() > 1000 || budget.Used() != 0 {
		t.Fatalf("the budget bound held (peak %d of 1000) and everything is given back (used %d)", peak.Load(), budget.Used())
	}
}
