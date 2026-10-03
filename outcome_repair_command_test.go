package main

import "testing"

// RB5 D4: `repair outcome-trees` takes --apply and nothing else; anything else is the usage, never a run.
func TestTheOutcomeTreeRepairTakesOnlyApply(t *testing.T) {
	for _, args := range [][]string{{"outcome-trees", "--force"}, {"outcome-trees", "--apply", "--apply"}} {
		if code := runRepairCommand(args); code != 1 {
			t.Fatalf("%v: exit %d, want the usage (1)", args, code)
		}
	}
}
