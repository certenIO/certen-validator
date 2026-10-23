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
	want := []string{"finality_index_disabled", "finality_memory_budget_exceeded", "l1_capture_gap"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
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

// Train 3: index_inconsistent is classified by its REASON. Only a missing row can clear by a retry (reconcile or a capture backfill writes
// it); a corrupt, quarantined, overflowing, re-pinned or disagreeing row is persistent until a new index generation, so it keeps the
// failure back-off. Every reason of the registry's closed set must be decided by name.
func TestRB12F17IndexInconsistentIsClassifiedByItsReason(t *testing.T) {
	reg := loadRegistry(t)
	set := reg.States["index_inconsistent"].Enums["reason"]
	by := StateReasonClasses()["index_inconsistent"]
	if len(set) == 0 || len(by) != len(set) {
		t.Fatalf("every reason of the closed set %v must have a class, the table has %v", set, by)
	}
	for _, reason := range set {
		want, ok := by[reason]
		if !ok {
			t.Errorf("reason %s has no class", reason)
			continue
		}
		st := IndexInconsistent(84532, "bi", reason)
		got, known := ClassOfStateError(st)
		if !known || got != want {
			t.Errorf("%s: class %q, want %q", reason, got, want)
		}
		wantEnv := reason == IndexRowMissing
		if IsEnvironmentStateError(st) != wantEnv {
			t.Errorf("%s: environment=%v, want %v (only row_missing clears by a retry)", reason, IsEnvironmentStateError(st), wantEnv)
		}
	}
	// a reason the table does not know keeps the failure back-off (the stronger protection)
	if c, _ := ClassOfStateError(NewState("index_inconsistent", "chain", uint64(84532), "family", "bi", "reason", "unheard_of")); c != ClassFailure {
		t.Errorf("an unknown reason keeps the failure back-off, got %q", c)
	}
	// a code that is not refined keeps its own class
	if c, _ := ClassOfStateError(NewState("l1_capture_gap", "chain", uint64(84532), "gap_state", "open")); c != ClassEnvironment {
		t.Errorf("l1_capture_gap is an environment state, got %q", c)
	}
}
