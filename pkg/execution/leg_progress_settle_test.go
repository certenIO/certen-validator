package execution

import (
	"context"
	"testing"
)

// A settled member has completed ALL of its legs, not one.
//
// Measured on base-sepolia 2026-08-07 with a controlled calibration run: a 2-leg intent settled
// in ONE transaction of 144,813 gas and a 5-leg intent in ONE transaction of 281,407 gas. Legs
// do not get their own transactions — they ride together, one transaction per destination
// chain. So when a member settles, every leg it carries on that chain has executed.
//
// Reporting 1 here would leave a 5-leg intent recording a fifth of its work, which is the same
// class of error as the lifecycle columns nothing wrote: a number that looks plausible, is
// wrong, and is the first thing an analysis reads.

type legProgressCall struct {
	intentID  string
	completed int
	failed    int
}

func captureLegProgress(o *BatchOrchestrator) *[]legProgressCall {
	calls := []legProgressCall{}
	o.SetLegProgressHook(func(_ context.Context, id string, c, f int) {
		calls = append(calls, legProgressCall{id, c, f})
	})
	return &calls
}

func TestSettledMemberReportsEveryLeg(t *testing.T) {
	o := &BatchOrchestrator{}
	calls := captureLegProgress(o)

	settled := []*PendingBatchIntent{
		{IntentID: "intent-5leg", Legs: make([]LegExecution, 5)},
		{IntentID: "intent-1leg", Legs: make([]LegExecution, 1)},
	}
	o.recordLegProgress(context.Background(), settled, nil)

	if len(*calls) != 2 {
		t.Fatalf("expected 2 progress reports, got %d", len(*calls))
	}
	if got := (*calls)[0]; got.completed != 5 || got.failed != 0 {
		t.Fatalf("5-leg member reported %+v; a settled member completes ALL its legs", got)
	}
	if got := (*calls)[1]; got.completed != 1 {
		t.Fatalf("1-leg member reported %+v, want 1 completed", got)
	}
}

// A failed member executed none of its legs — but it still has legs, and recording that is what
// distinguishes "failed with 5 legs outstanding" from "was never a multi-leg intent".
func TestFailedMemberReportsItsLegsAsFailed(t *testing.T) {
	o := &BatchOrchestrator{}
	calls := captureLegProgress(o)

	o.recordLegProgress(context.Background(), nil, []*PendingBatchIntent{
		{IntentID: "intent-3leg", Legs: make([]LegExecution, 3)},
	})

	if len(*calls) != 1 {
		t.Fatalf("expected 1 progress report, got %d", len(*calls))
	}
	if got := (*calls)[0]; got.completed != 0 || got.failed != 3 {
		t.Fatalf("failed member reported %+v, want 0 completed / 3 failed", got)
	}
}

// Settlement must not depend on the hook. An unwired validator settles exactly as before and
// only the durable counters go unwritten — a reporting gap, never a settlement failure.
func TestLegProgressHookIsOptional(t *testing.T) {
	o := &BatchOrchestrator{}
	o.recordLegProgress(context.Background(),
		[]*PendingBatchIntent{{IntentID: "intent-1", Legs: make([]LegExecution, 2)}}, nil)
}

// A nil member in either slice must not panic the settle path. Cost attribution already skips
// members with no transaction; this keeps the parallel path equally forgiving, because a panic
// here would abort settlement over a bookkeeping detail.
func TestLegProgressToleratesNilMembers(t *testing.T) {
	o := &BatchOrchestrator{}
	calls := captureLegProgress(o)

	o.recordLegProgress(context.Background(),
		[]*PendingBatchIntent{nil, {IntentID: "ok", Legs: make([]LegExecution, 1)}},
		[]*PendingBatchIntent{nil})

	if len(*calls) != 1 || (*calls)[0].intentID != "ok" {
		t.Fatalf("nil members should be skipped, got %+v", *calls)
	}
}
