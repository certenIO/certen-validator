package main

import "testing"

// The window mode is the instrument the G1 activation's first precondition reads: exit 0 means "zero disagreements over a live window".
// It must be unable to say that about a window in which nothing was compared, and must not count a decision that was not run as agreement.

func TestAnEmptyOrUncomparedWindowIsNeverAZeroDisagreementResult(t *testing.T) {
	cases := []struct {
		name                                       string
		rows, compared, dis, fail, notRun, notComp int
		want                                       int
	}{
		{"an empty window", 0, 0, 0, 0, 0, 0, exitNothingCompared},
		{"captures but none could be compared", 5, 0, 0, 0, 0, 5, exitNothingCompared},
		{"captures, none compared, nothing else to report", 3, 0, 0, 0, 0, 0, exitNothingCompared},
		{"everything compared and agreed", 4, 4, 0, 0, 0, 0, 0},
		{"a disagreement", 4, 4, 1, 0, 0, 0, 1},
		{"a verification failure", 4, 4, 0, 1, 0, 0, 1},
		{"a disagreement outranks an empty comparison count", 2, 0, 1, 0, 0, 0, 1},
		{"a decision was not run", 4, 4, 0, 0, 2, 0, 3},
		{"some intents could not be compared", 4, 2, 0, 0, 0, 2, 3},
	}
	for _, c := range cases {
		if got := windowExit(c.rows, c.compared, c.dis, c.fail, c.notRun, c.notComp); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

func TestADecisionThatWasNotRunIsNotAgreement(t *testing.T) {
	if agrees(false, 0, 0) {
		t.Fatal("an intent whose v15 decision was not run was counted as agreement")
	}
	if !agrees(true, 0, 0) {
		t.Fatal("an intent whose both decisions ran with nothing differing was not counted as agreement")
	}
	if agrees(true, 1, 0) || agrees(true, 0, 1) {
		t.Fatal("a disagreement or a verification failure was counted as agreement")
	}
}
