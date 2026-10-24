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

// D1 (V-T2): some states are environment only for some values of one of their fields (l1_capture_gap: an OPEN gap heals, a terminal one
// never does). The rule is a table too, and it names EVERY value of the field the registry names, no more, no fewer.
func TestRB12F17EveryValueOfAFieldWithAClassRuleHasAClass(t *testing.T) {
	reg := loadRegistry(t)
	rules := FieldClassRules()
	if len(rules) == 0 {
		t.Fatal("no field rule: l1_capture_gap is environment only while the gap is open")
	}
	for code, rule := range rules {
		spec, ok := reg.States[code]
		if !ok {
			t.Errorf("the rule names %s, which is not registered", code)
			continue
		}
		if base, _ := ClassOfState(code); base != ClassEnvironment {
			t.Errorf("%s: a field rule refines an environment state; its base class is %q", code, base)
		}
		enum := spec.Enums[rule.Field]
		if len(enum) == 0 {
			t.Errorf("%s: the registry names no closed set for %s", code, rule.Field)
		}
		for _, v := range enum {
			if _, ok := rule.Classes[v]; !ok {
				t.Errorf("%s: %s=%s has no class", code, rule.Field, v)
			}
		}
		for v := range rule.Classes {
			found := false
			for _, e := range enum {
				found = found || e == v
			}
			if !found {
				t.Errorf("%s: the rule classifies %s=%s, which the registry does not name", code, rule.Field, v)
			}
		}
	}
	gs := func(v string) *StateError { return NewState("l1_capture_gap", "gap_state", v) }
	if ClassOfStateError(gs("open")) != ClassEnvironment || ClassOfStateError(gs("unavailable_proven")) != ClassFailure ||
		ClassOfStateError(gs("retention_expired")) != ClassFailure {
		t.Fatal("open is environment, the two terminal gap states are failures")
	}
	if ClassOfStateError(NewState("l1_capture_gap")) != ClassFailure || ClassOfStateError(gs("invented")) != ClassFailure {
		t.Fatal("a gap whose state is missing or unknown is not known to heal: failure")
	}
	if ClassOfStateError(nil) != ClassFailure || ClassOfStateError(NewState("finality_memory_budget_exceeded")) != ClassEnvironment {
		t.Fatal("nil is a failure; a code without a field rule is classed by its code")
	}
}
