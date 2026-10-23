// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12-P0LIVE-FIX mutation gate (tools/pv2mut.ps1 over the hold path of upgrader.go and over status.go): each test kills survivors of
// the first run.

func rb12Hold() error {
	return NewState(CodeMemoryBudget, "chain", uint64(ChainBaseSepolia), "what", "x", "requested", uint64(2), "in_use", uint64(1), "limit", uint64(3))
}

// A hold leaves the failure count of the leg as it was: it neither adds to it nor clears it. A later ask that pends clears it.
func TestRB12AHoldLeavesTheFailureCountAndALaterPendingClearsIt(t *testing.T) {
	var phase atomic.Int64
	prover := &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, _ *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		switch phase.Load() {
		case 1, 3:
			return nil, nil, errors.New("provider down")
		case 2:
			return nil, nil, rb12Hold()
		}
		return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: target, Reason: "game_unresolved"}, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{}, nil)
	status := newRB12Status()
	f.u.cfg.Status = status
	ctx := context.Background()
	attempt := func() uint64 {
		row, ok := status.row(legID, LevelL1Posted)
		if !ok || row.State == nil {
			t.Fatalf("no row: %+v", row)
		}
		a, _ := row.State.Fields["attempt"].(uint64)
		return a
	}

	phase.Store(1)
	if rep := f.u.RunOnce(ctx); rep.Failed != 1 || !f.u.isSuspect(legID) || attempt() != 1 {
		t.Fatalf("first failure: %+v attempt=%d", rep, attempt())
	}
	f.clock.Advance(5*time.Minute + time.Second)
	phase.Store(2)
	if rep := f.u.RunOnce(ctx); rep.Failed != 0 || rep.BuildHeld != 1 {
		t.Fatalf("a hold: %+v", rep)
	}
	if !f.u.isSuspect(legID) {
		t.Fatal("a hold cleared the failure count of the leg")
	}
	if row, _ := status.row(legID, LevelL1Posted); row.Class != BuilderPending || row.State.Code != CodeMemoryBudget {
		t.Fatalf("%+v", row)
	}
	f.clock.Advance(2*time.Minute + time.Second)
	phase.Store(3)
	if rep := f.u.RunOnce(ctx); rep.Failed != 1 {
		t.Fatalf("second failure: %+v", rep)
	}
	if got := attempt(); got != 2 {
		t.Fatalf("the hold between two failures neither counted nor reset: the second failure is attempt 2, got %d", got)
	}
	f.clock.Advance(10*time.Minute + time.Second)
	phase.Store(4)
	if rep := f.u.RunOnce(ctx); rep.Failed != 0 {
		t.Fatalf("pending: %+v", rep)
	}
	if f.u.isSuspect(legID) {
		t.Fatal("a leg whose ask has pended is no suspect any more")
	}
}

// A hold never replaces the status of a failure: when one prover failed (unavailable) or its evidence was refused and another prover is
// held, the row says what failed.
func TestRB12AHoldDoesNotReplaceTheStatusOfAFailure(t *testing.T) {
	ctx := context.Background()
	// unavailable first, held second
	failing := &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return nil, nil, errors.New("provider down")
	}}
	holding := &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return nil, nil, rb12Hold()
	}}
	f := newFixture(t, failing, UpgraderConfig{}, nil)
	if err := f.reg.RegisterProver(holding); err != nil {
		t.Fatal(err)
	}
	status := newRB12Status()
	f.u.cfg.Status = status
	rep := f.u.RunOnce(ctx)
	row, _ := status.row(legID, LevelL1Posted)
	if rep.Failed != 1 || row.Class != BuilderUnavailable || row.State == nil || row.State.Code != CodeBuilderError {
		t.Fatalf("the failure of the first prover is the row: %+v %+v", rep, row)
	}
	if got := row.State.Fields["attempt"]; got != uint64(1) {
		t.Fatalf("attempt %v", got)
	}

	// evidence refused by the registered Kind first, held second
	ok := allLevels(t)
	g := newFixture(t, ok, UpgraderConfig{}, nil)
	if err := g.reg.RegisterProver(holding); err != nil {
		t.Fatal(err)
	}
	g.u.store = &errStore{memStore: g.store, appendErr: NewState("some_other_state")}
	st2 := newRB12Status()
	g.u.cfg.Status = st2
	rep = g.u.RunOnce(ctx)
	row, _ = st2.row(legID, LevelL1Posted)
	if rep.Failed != 1 || row.Class != BuilderRefused || row.State == nil || row.State.Code != "some_other_state" {
		t.Fatalf("the refusal of the built evidence is the row: %+v %+v", rep, row)
	}
}

// A plain error of the addendum store is a builder error of the append stage, class unavailable (not a refusal of evidence).
func TestRB12APlainStoreErrorIsABuilderErrorOfTheAppendStage(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	f.u.store = &errStore{memStore: f.store, appendErr: errors.New("disk full")}
	status := newRB12Status()
	f.u.cfg.Status = status
	f.u.RunOnce(context.Background())
	row, ok := status.row(legID, LevelL1Posted)
	if !ok || row.Class != BuilderUnavailable || row.State == nil || row.State.Code != CodeBuilderError || row.State.Fields["stage"] != StageAppend {
		t.Fatalf("%+v", row)
	}
}

func TestRB12AtStageMarksOnlyUnnamedErrorsAndTheStatusReadsTheStage(t *testing.T) {
	if AtStage(StageAppend, nil) != nil {
		t.Fatal("no error stays no error")
	}
	named := NewState(CodeVerifierFailed, "chain", uint64(1), "kind", "k", "cause", "c")
	if AtStage(StageAppend, named) != error(named) {
		t.Fatal("an error that has a name is returned as it is")
	}
	plain := errors.New("disk full")
	staged := AtStage(StageAppend, plain)
	if staged == nil || staged.Error() != "disk full" || !errors.Is(staged, plain) || errors.Unwrap(staged) != plain {
		t.Fatalf("%v", staged)
	}
	s := BuilderStatusOf("p", 1, LevelL1Posted, LevelIncluded, nil, staged, false, time.Unix(1, 0))
	if s.State.Code != CodeBuilderError || s.State.Fields["stage"] != StageAppend {
		t.Fatalf("%+v", s.State)
	}
	if s := BuilderStatusOf("p", 1, LevelL1Posted, LevelIncluded, nil, plain, false, time.Unix(1, 0)); s.State.Fields["stage"] != StageBuild {
		t.Fatalf("an unmarked error is a build-stage error: %+v", s.State)
	}
}

func TestRB12TheAttemptNotesDoNothingToAStatusWithoutAState(t *testing.T) {
	s := VerifiedBuilderStatus("p", 1, LevelL1Posted, 1, time.Unix(1, 0))
	s.noteAttempt(3, time.Unix(100, 0))
	s.noteRetry(time.Unix(100, 0))
	if s.State != nil || !s.ETA.IsZero() {
		t.Fatalf("%+v", s)
	}
}

// contendedBuildFixture: two legs, a budget that holds one build at a time; each build reserves 4 x 250 with a pause. The prover's behaviour on
// a refusal is the parameter.
func rb12Contended(t *testing.T, onRefusal func(err error) error) (u *Upgrader, calls *sync.Map, ages *sync.Map, rep PassReport) {
	t.Helper()
	budget := NewMemoryBudget(1000)
	calls, ages = &sync.Map{}, &sync.Map{}
	cfg := UpgraderConfig{Memory: budget, HeapInUse: func() uint64 { return 0 }, Concurrency: 2, BuildTimeout: 30 * time.Second}
	u, src, _, _, _ := rb12Fixture(t, cfg, func(src *rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return func(ctx context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
			id := src.legOf(s)
			h, _ := ctx.Value(holdKey{}).(*Hold)
			n, _ := calls.LoadOrStore(id+target.String(), new(atomic.Int64))
			n.(*atomic.Int64).Add(1)
			a, _ := ages.LoadOrStore(id+target.String(), new([]uint64))
			*a.(*[]uint64) = append(*a.(*[]uint64), h.t.age)
			for i := 0; i < 4; i++ {
				if err := ReserveRow(ctx, 167); err != nil { // RowCost(167) = 250
					return nil, nil, onRefusal(err)
				}
				time.Sleep(4 * time.Millisecond)
			}
			time.Sleep(15 * time.Millisecond)
			return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: target, Reason: "game_unresolved"}, nil
		}
	})
	src.add(leg(1))
	src.add(leg(2))
	// only the l1_posted level is asked (the finalized level of the fixture is above this prover's ceiling)
	rep = u.RunOnce(context.Background())
	return u, calls, ages, rep
}

// A build that is run again keeps its place in the budget (its age), so it is not made to wait behind younger builds.
func TestRB12ABuildThatIsRunAgainKeepsItsAge(t *testing.T) {
	_, calls, ages, rep := rb12Contended(t, func(err error) error { return err })
	if rep.Failed != 0 {
		t.Fatalf("%+v", rep)
	}
	restarted := 0
	calls.Range(func(k, v any) bool {
		if v.(*atomic.Int64).Load() > 1 {
			restarted++
			a, _ := ages.Load(k)
			list := *a.(*[]uint64)
			for _, x := range list {
				if x != list[0] {
					t.Errorf("%v: a build that was run again changed its age: %v", k, list)
				}
			}
		}
		return true
	})
	if restarted == 0 {
		t.Fatal("no build was run again: the scenario does not exercise the restart")
	}
}

// A prover that swallows the refusal and fails with something else is not run again: only a refusal of the budget is.
func TestRB12AYieldedBuildThatFailsForAnotherReasonIsNotRunAgain(t *testing.T) {
	for name, other := range map[string]error{
		"unnamed": errors.New("gave up"),
		"named":   NewState(CodeVerifierFailed, "chain", uint64(ChainBaseSepolia), "kind", "k", "cause", "gave up"),
	} {
		other := other
		_, calls, _, rep := rb12Contended(t, func(error) error { return other })
		if rep.Failed < 1 {
			t.Fatalf("%s: no build yielded (the scenario is vacuous): %+v", name, rep)
		}
		calls.Range(func(k, v any) bool {
			if n := v.(*atomic.Int64).Load(); n != 1 {
				t.Errorf("%s: %v was run %d times; a build that failed for another reason is not run again", name, k, n)
			}
			return true
		})
	}
}

// A genuine pending of another prover keeps its own row: the retry note of a hold is added to a hold row only.
func TestRB12AGenuinePendingOutranksAHoldAndKeepsItsOwnRow(t *testing.T) {
	holding := &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return nil, nil, rb12Hold()
	}}
	f := newFixture(t, holding, UpgraderConfig{}, nil)
	eta := f.clock.Now().Add(30 * time.Second)
	if err := f.reg.RegisterProver(pendingProver(func(Level) time.Time { return eta })); err != nil {
		t.Fatal(err)
	}
	status := newRB12Status()
	f.u.cfg.Status = status
	f.u.RunOnce(context.Background())
	row, ok := status.row(legID, LevelL1Posted)
	if !ok || row.Class != BuilderPending || row.State == nil || row.State.Code != CodePending {
		t.Fatalf("the pending of the second prover is the row: %+v", row)
	}
	if _, has := row.State.Fields[FieldNextAttemptAt]; has {
		t.Fatalf("the retry note belongs to a hold row only: %v", row.State.Fields)
	}
	if !row.ETA.Equal(eta) {
		t.Fatalf("the eta is the prover's own: %v want %v", row.ETA, eta)
	}
}

// The wait of a build that has to give way is the wait of the budget counted from its FIRST yield, not from each one; when it has passed the
// refusal stands (the leg is held) and the build is not run again. Yields are made deterministic by marking the build's ticket, as the
// budget does when every build is blocked.
func TestRB12ABuildThatKeepsGivingWayIsHeldWhenTheWaitOfTheBudgetHasPassed(t *testing.T) {
	budget := NewMemoryBudget(1000).WithWait(1500 * time.Millisecond)
	var tries atomic.Int64
	prover := &finalProver{chain: ChainBaseSepolia, mode: func(ctx context.Context, _ *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		h := ctx.Value(holdKey{}).(*Hold)
		if tries.Add(1) > 4 { // a build that is run again without end is a failure of this test, not a hang
			return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: target, Reason: "game_unresolved"}, nil
		}
		budget.mu.Lock()
		h.t.yielded = true
		budget.mu.Unlock()
		return nil, nil, rb12Hold()
	}}
	f := newFixture(t, prover, UpgraderConfig{BuildTimeout: time.Minute}, nil)
	other, other2 := rb12Root(budget), rb12Root(budget) // two builds in the budget that hold nothing
	ctx := WithMemoryBudget(context.Background(), budget)
	type res struct {
		err error
		d   time.Duration
	}
	done := make(chan res, 1)
	start := time.Now()
	go func() {
		_, _, err := f.u.build(ctx, prover, nil, 0, LevelL1Posted)
		done <- res{err, time.Since(start)}
	}()
	// first yield at about 0; the first other build ends at 0.6 s: the build is run again and gives way a second time; its wait still ends
	// at 1.5 s, 1.5 s after the FIRST yield (a wait restarted at the second yield would end at 2.1 s)
	time.Sleep(600 * time.Millisecond)
	other.Release()
	r := <-done
	other2.Release()
	if se, ok := AsNamed(r.err); !ok || se.Code != CodeMemoryBudget {
		t.Fatalf("the build is held by name after the wait of the budget: %v after %v, %d tries", r.err, r.d, tries.Load())
	}
	if r.d < 1400*time.Millisecond || r.d > 1800*time.Millisecond {
		t.Fatalf("the refusal came after %v; the wait of the budget is 1.5 s from the first yield", r.d)
	}
	if tries.Load() != 2 {
		t.Fatalf("the build is run again once, when another build has finished, and not after its wait has passed: %d tries", tries.Load())
	}
}
