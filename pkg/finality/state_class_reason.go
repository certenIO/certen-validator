// Copyright 2026 Certen Protocol

package finality

// RB12-INDEX-FIX (F17 follow-up): the retry class of a state may depend on its reason. index_inconsistent is a family of facts: a row
// that is MISSING can arrive (the index reconcile or a capture backfill writes it) and the leg is asked again at the bounded poll; every
// other reason is persistent until a NEW INDEX GENERATION replaces the rows (a corrupt or quarantined entry, a coverage overflow, a pins
// change, a channel broken by a late frame, rows that disagree), and a prompt retry would be a bounded hot loop, so those keep the failure
// back-off. Every reason of the registry's closed set is named here (state_class_rb12_test.go fails when one is not).
var stateReasonClasses = map[string]map[string]StateClass{
	"index_inconsistent": {
		"row_missing":                 ClassEnvironment,
		"entry_corrupt":               ClassFailure,
		"rows_disagree":               ClassFailure,
		"pins_changed":                ClassFailure,
		"coverage_overflow":           ClassFailure,
		"duplicate_frame_after_close": ClassFailure,
		"self_check_mismatch":         ClassFailure,
	},
}

// ClassOfStateError is the retry class of a state, by its code and, for a code whose class depends on it, its reason. A reason the
// refinement does not name takes the class of the code (the failure back-off: the stronger protection of the providers).
func ClassOfStateError(st *StateError) (StateClass, bool) {
	c, ok := ClassOfState(st.Code)
	if by, has := stateReasonClasses[st.Code]; has {
		if reason, _ := st.Fields["reason"].(string); reason != "" {
			if rc, known := by[reason]; known {
				return rc, ok
			}
		}
	}
	return c, ok
}

// IsEnvironmentStateError reports whether a state is, by its code and reason, a fact about the process or the capture store.
func IsEnvironmentStateError(st *StateError) bool {
	c, _ := ClassOfStateError(st)
	return c == ClassEnvironment
}

// StateReasonClasses returns a copy of the reason refinements (for the conformance test and for review).
func StateReasonClasses() map[string]map[string]StateClass {
	out := map[string]map[string]StateClass{}
	for code, by := range stateReasonClasses {
		cp := map[string]StateClass{}
		for r, c := range by {
			cp[r] = c
		}
		out[code] = cp
	}
	return out
}
