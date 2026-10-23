// Copyright 2026 Certen Protocol

package finality

import (
	"sort"
	"testing"
)

// RB12-GO-INT F17: what a refused build means for the retry schedule is decided by ONE table (code -> failure | environment). A state
// that is a verdict on the leg or its providers backs off (FailureRetry doubling to MaxFailureRetry); a state that is a fact about the
// process or the capture store holds the leg at PendingRetry. A code that is registered but not classified is a defect found by this
// test, not by a leg that waits six hours: whoever registers a state (Train 3: index_inconsistent) adds its row.

func TestRB12F17EveryRegisteredCodeHasExactlyOneClass(t *testing.T) {
	reg := loadRegistry(t)
	for code := range reg.States {
		c, ok := ClassOfState(code)
		if !ok {
			t.Errorf("the registered code %s has no class in the retry table (add a row: failure or environment)", code)
			continue
		}
		if c != ClassFailure && c != ClassEnvironment {
			t.Errorf("%s: class %q", code, c)
		}
	}
	for code := range StateClasses() {
		if _, ok := reg.States[code]; !ok {
			t.Errorf("the retry table classifies %s, which is not registered in states.json", code)
		}
	}
	if len(StateClasses()) != len(reg.States) {
		t.Errorf("the retry table has %d rows, the registry %d states", len(StateClasses()), len(reg.States))
	}
}

// The environment class is exactly the states that are facts about this process or its capture store. A change to the set is a decision
// the reviewer sees here: it is not made by adding a code.
func TestRB12F17TheEnvironmentClassIsExactlyTheProcessAndStoreStates(t *testing.T) {
	var got []string
	for code, c := range StateClasses() {
		if c == ClassEnvironment {
			got = append(got, code)
		}
	}
	sort.Strings(got)
	want := []string{"finality_memory_budget_exceeded", "l1_capture_gap"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("environment states: %v, want %v", got, want)
	}
	for _, code := range want {
		if !IsEnvironmentState(code) {
			t.Errorf("%s is not seen as an environment state", code)
		}
	}
	// states that look similar but are verdicts or permanent facts keep the failure back-off
	for _, code := range []string{"l1_capture_not_covering", "capture_row_conflict", "finality_build_timeout", "finality_source_unavailable",
		"finality_builder_error", "finality_evidence_too_large", "l1_blob_unavailable", "finality_verifier_failed"} {
		if IsEnvironmentState(code) {
			t.Errorf("%s must keep the failure back-off", code)
		}
	}
}

// A code the table does not know is judged as a failure (the stronger protection of the providers) and says it is unknown.
func TestRB12F17AnUnknownCodeIsAFailureAndSaysItIsUnknown(t *testing.T) {
	c, ok := ClassOfState("not_a_registered_code")
	if ok || c != ClassFailure || IsEnvironmentState("not_a_registered_code") {
		t.Fatalf("(%q, %v)", c, ok)
	}
}

// The memory refusal constant and the table cannot drift apart.
func TestRB12F17TheMemoryCodeConstantIsInTheTable(t *testing.T) {
	if c, ok := ClassOfState(CodeMemoryBudget); !ok || c != ClassEnvironment {
		t.Fatalf("%s: (%q, %v)", CodeMemoryBudget, c, ok)
	}
}
