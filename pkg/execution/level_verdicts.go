// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/json"

	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// =============================================================================
// What each stored governance level says it verified (RB3-F73)
// =============================================================================
//
// The governance level rows used to say "verified" by construction: G0 was verified whenever the cycle
// had an observation, its flags said "inclusion_verified": true, G1 was verified whenever the VALIDATOR
// quorum was met - which says nothing about the key page - and G2 "outcome_bound" and "binding_enforced"
// were constants. Each verdict now comes from the proof it names.

// levelProven reports whether a governance level's proven result establishes that level: G0 its
// execution inclusion proof complete; G1 its authority proof complete with the key page threshold
// satisfied; G2 its outcome binding complete with payload and effect verified. A missing or
// unreadable result establishes nothing.
func levelProven(level string, raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	switch level {
	case "G0":
		var g certenproof.G0Result
		return json.Unmarshal(raw, &g) == nil && g.G0ProofComplete
	case "G1":
		var g certenproof.G1Result
		return json.Unmarshal(raw, &g) == nil && g.G1ProofComplete && g.ThresholdSatisfied
	case "G2":
		var g certenproof.G2Result
		return json.Unmarshal(raw, &g) == nil && g.G2ProofComplete && g.PayloadVerified && g.EffectVerified
	}
	return false
}

// governedExecutionProven is the proven G1 result's own execution verdict: that the governed Accumulate transaction
// executed, which G1 states as its G0 inclusion proof being complete. False when the cycle carries no G1 result, or
// one that does not state it. It is never the write-back's success: the bundle that states it is stored before
// Phase 9 runs (RB5-F18).
func governedExecutionProven(in *GovernanceLevelInputs) bool {
	raw := in.ResultFor("G1")
	if len(raw) == 0 {
		return false
	}
	var g certenproof.G1Result
	return json.Unmarshal(raw, &g) == nil && g.ExecutionSuccess && g.G0ProofComplete
}

// settlementInclusionProven reports whether the cycle's settlement is proven included in its block:
// the gate's own observation of it carries a transaction and a receipt inclusion proof that verify.
func settlementInclusionProven(cycle *activeCycle) bool {
	if cycle == nil || cycle.SettlementProof == nil {
		return false
	}
	return cycle.SettlementProof.VerifyInclusionProofs() == nil
}
