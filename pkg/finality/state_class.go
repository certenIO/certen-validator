// Copyright 2026 Certen Protocol

package finality

import "fmt"

// RB12-GO-INT F17. What a refused build means for the retry schedule of a leg is decided by this ONE table (code -> class), and a test
// (state_class_rb12_test.go) fails when a code of testdata/finality/states.json has no row here or a row names a code that is not
// registered: whoever registers a state classifies it. Train 3 adds index_inconsistent to the registry and one row here.

// StateClass says what a named state returned by a prover means for the schedule of the leg it was returned for.
type StateClass string

const (
	// ClassFailure: the state is a verdict on the leg, its evidence or the providers it depends on. The leg backs off: FailureRetry after
	// the first such answer, doubling for every consecutive one up to MaxFailureRetry, so a leg that cannot be built is asked ever less
	// often and the providers are not hammered. Every state that is not a fact about this process or its capture store is a failure.
	ClassFailure StateClass = "failure"
	// ClassEnvironment: the state is a fact about THIS process or its capture store, not a verdict: the process memory budget could not
	// cover the build (finality_memory_budget_exceeded) or the capture store has a recorded hole in the window of the leg (l1_capture_gap),
	// which the backfill closes. The leg is unjudged: no failure is counted, the back-off exponent does not advance, the leg does not
	// become a suspect, and it is asked again at the bounded poll PendingRetry. The status row names the state with the time of the next
	// ask (next_attempt_at). There is no event from the capture loops to the upgrader; the bounded poll is the retry, and it is what
	// makes a leg whose hole was just closed buildable within one retry interval.
	ClassEnvironment StateClass = "environment"
)

var stateClasses = map[string]StateClass{
	"adiri_incarnation_mismatch":           ClassFailure,
	"assertion_history_unavailable":        ClassFailure,
	"assertion_machine_not_finished":       ClassFailure,
	"assertion_not_confirmed":              ClassFailure,
	"assertion_preimage_mismatch":          ClassFailure,
	"assertion_unknown":                    ClassFailure,
	"batch_binding_mismatch":               ClassFailure,
	"batch_format_unsupported":             ClassFailure,
	"batch_not_found":                      ClassFailure,
	"batch_outside_sequencing_window":      ClassFailure,
	"batcher_sender_mismatch":              ClassFailure,
	"batcher_state_unavailable":            ClassFailure,
	"batcher_tx_not_to_inbox":              ClassFailure,
	"blob_commitment_mismatch":             ClassFailure,
	"capture_row_conflict":                 ClassFailure,
	"channel_incomplete":                   ClassFailure,
	"channel_malformed":                    ClassFailure,
	"channel_timed_out":                    ClassFailure,
	"committee_chain_broken":               ClassFailure,
	"committee_shrunk":                     ClassFailure,
	"confirmation_path_unproven":           ClassFailure,
	"confirmed_by_owner_force":             ClassFailure,
	"contract_identity_unproven":           ClassFailure,
	"epoch_record_codec_unsupported":       ClassFailure,
	"evidence_pin_mismatch":                ClassFailure,
	"finality_addendum_malformed":          ClassFailure,
	"finality_append_conflict":             ClassFailure,
	"finality_block_header_unreadable":     ClassFailure,
	"finality_block_mismatch":              ClassFailure,
	"finality_block_not_covered":           ClassFailure,
	"finality_bootstrap_invalid":           ClassFailure,
	"finality_build_timeout":               ClassFailure,
	"finality_builder_error":               ClassFailure,
	"finality_chain_broken":                ClassFailure,
	"finality_chain_unsupported":           ClassFailure,
	"finality_covering_game_unavailable":   ClassFailure,
	"finality_evidence_malformed":          ClassFailure,
	"finality_evidence_too_large":          ClassFailure,
	"finality_evidence_unrecognised":       ClassFailure,
	"finality_finalized_block_unavailable": ClassFailure,
	"finality_fork_unsupported":            ClassFailure,
	"finality_game_source_unavailable":     ClassFailure,
	"finality_guard_refused":               ClassFailure,
	"finality_header_chain_broken":         ClassFailure,
	"finality_included_invalid":            ClassFailure,
	"finality_included_unavailable":        ClassFailure,
	"finality_ledger_behind":               ClassFailure,
	"finality_ledger_extension_invalid":    ClassFailure,
	"finality_link_broken":                 ClassFailure,
	"finality_link_invalid":                ClassFailure,
	"finality_memory_budget_exceeded":      ClassEnvironment,
	"finality_network_mismatch":            ClassFailure,
	"finality_participation_insufficient":  ClassFailure,
	"finality_pending":                     ClassFailure,
	"finality_period_gap":                  ClassFailure,
	"finality_pin_mismatch":                ClassFailure,
	"finality_pin_unknown":                 ClassFailure,
	"finality_pin_window":                  ClassFailure,
	"finality_pins_corrupt":                ClassFailure,
	"finality_prover_panicked":             ClassFailure,
	"finality_signature_invalid":           ClassFailure,
	"finality_source_unavailable":          ClassFailure,
	"finality_upgrader_disabled":           ClassFailure,
	"finality_verifier_failed":             ClassFailure,
	"game_blacklisted":                     ClassFailure,
	"game_challenger_wins":                 ClassFailure,
	"game_not_registered":                  ClassFailure,
	"game_not_resolved":                    ClassFailure,
	"game_not_respected":                   ClassFailure,
	"game_retired":                         ClassFailure,
	"game_type_unsupported":                ClassFailure,
	"game_unrecognised":                    ClassFailure,
	"game_within_finality_delay":           ClassFailure,
	"header_chain_exceeds_bound":           ClassFailure,
	"l1_batch_data_off_l1":                 ClassFailure,
	"l1_batch_header_unknown":              ClassFailure,
	"l1_blob_unavailable":                  ClassFailure,
	"l1_capture_gap":                       ClassEnvironment,
	"l1_capture_not_covering":              ClassFailure,
	"l1_finality_unproven":                 ClassFailure,
	"l1_posted_content_not_found":          ClassFailure,
	"l1_posted_delayed_origin_unproven":    ClassFailure,
	"l1_state_proof_invalid":               ClassFailure,
	"l1_system_paused":                     ClassFailure,
	"l1_tx_proof_invalid":                  ClassFailure,
	"l2_block_not_canonical":               ClassFailure,
	"l2_header_unavailable":                ClassFailure,
	"l2_headers_unavailable":               ClassFailure,
	"level_already_present":                ClassFailure,
	"level_not_applicable":                 ClassFailure,
	"output_root_mismatch":                 ClassFailure,
	"pin_mismatch":                         ClassFailure,
	"pre_bold_block":                       ClassFailure,
	"rollup_unpinned":                      ClassFailure,
}

// ClassOfState is the retry class of a state code. A code the table does not know is judged as a failure (the stronger protection of the
// providers) and the second result says it is unknown; the conformance test makes that unreachable for every registered code.
func ClassOfState(code string) (StateClass, bool) {
	c, ok := stateClasses[code]
	if !ok {
		return ClassFailure, false
	}
	return c, true
}

// IsEnvironmentState reports whether a state is a fact about the process or the capture store (ClassEnvironment).
func IsEnvironmentState(code string) bool {
	c, _ := ClassOfState(code)
	return c == ClassEnvironment
}

// StateClasses returns a copy of the table (for the conformance test and for review).
func StateClasses() map[string]StateClass {
	out := make(map[string]StateClass, len(stateClasses))
	for k, v := range stateClasses {
		out[k] = v
	}
	return out
}

// FieldClassRule refines the class of a state whose class depends on one field of it (RB12-GO-INT D1): l1_capture_gap is a fact about the
// capture store ONLY while the gap is open - the backfill closes it, so the leg is asked again at the bounded poll; a terminal gap
// (unavailable_proven: the providers proved the data unavailable; retention_expired: it is past retention) never heals, no fill can come,
// and polling it every PendingRetry for ever is a load without an end: it backs off like the failure it is. Classes names EVERY value of
// the field that the registry names (a test reads states.json); a value the rule does not know is a failure.
type FieldClassRule struct {
	Field   string
	Classes map[string]StateClass
}

var fieldClassRules = map[string]FieldClassRule{
	"l1_capture_gap": {Field: "gap_state", Classes: map[string]StateClass{
		"open":               ClassEnvironment,
		"unavailable_proven": ClassFailure,
		"retention_expired":  ClassFailure,
	}},
}

// FieldClassRules returns a copy of the field rules (for the conformance test and for review).
func FieldClassRules() map[string]FieldClassRule {
	out := make(map[string]FieldClassRule, len(fieldClassRules))
	for code, r := range fieldClassRules {
		c := FieldClassRule{Field: r.Field, Classes: make(map[string]StateClass, len(r.Classes))}
		for k, v := range r.Classes {
			c.Classes[k] = v
		}
		out[code] = c
	}
	return out
}

// ClassOfStateError is the retry class of a returned state: the class of its code, refined by its field rule when it has one. A state
// without the field, or with a value the rule does not name, is not known to heal and is a failure; so is nil.
func ClassOfStateError(st *StateError) StateClass {
	if st == nil {
		return ClassFailure
	}
	base, _ := ClassOfState(st.Code)
	rule, ok := fieldClassRules[st.Code]
	if !ok {
		return base
	}
	v, has := st.Fields[rule.Field]
	if !has {
		return ClassFailure
	}
	c, ok := rule.Classes[fmt.Sprint(v)]
	if !ok {
		return ClassFailure
	}
	return c
}

// IsEnvironment reports whether a returned state is held by the environment (ClassOfStateError is ClassEnvironment).
func IsEnvironment(st *StateError) bool { return ClassOfStateError(st) == ClassEnvironment }
