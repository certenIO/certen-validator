// Copyright 2026 Certen Protocol
//
// Governance level_json construction — ONE implementation, used by every
// G-level writer.
//
// # WHAT WAS WRONG
//
// governance_proof_levels did not contain the governance proof. Measured
// 2026-08-25 against production: 0 of 401 G0 rows carried "entries", and the
// keys the rows actually held were
//
//	threshold_m, threshold_n, authority_url, confirmations,
//	finality_achieved, inclusion_verified
//
// — verdict flags about an EVM settlement, built from
// result.ObservationResults[0] plus key-page thresholds. The real
// G0Result/G1Result/G2Result existed upstream on PendingAttestation and died at
// the persistence boundary.
//
// Two distinct defects produced that:
//
//  1. The legacy writer read ComprehensiveData["g0Proof"], a key that is read in
//     exactly one place and WRITTEN IN ZERO. The only writer in the tree emits
//     "att.G0Proof". So g0Data was always "" and that function always took its
//     stub fallback. Both ends now use the same constant.
//  2. The production writer (unified_orchestrator, two sites) never looked for
//     the G-results at all.
//
// # WHY ONE HELPER
//
// There are THREE G-level writers: proof_cycle_orchestrator.storeGovernanceLevels
// and two in unified_orchestrator. Two copies of a thing that must agree is how
// L4 came to be missing from one path already. A change made here cannot land on
// one writer and not the others.
//
// # ADDITIVE, ALWAYS
//
// Every existing key survives. The evidence report and the approval console read
// inclusion_verified, finality_achieved, threshold_m/n, authority_url and
// confirmations; this adds "result" and "receipt" BESIDE them and never renames,
// retypes or removes anything. A row that gains keys keeps working for every
// reader that predates them.
package execution

import (
	"encoding/json"
	"fmt"

	"github.com/certen/independant-validator/pkg/consensus"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// Keys added to level_json by this package. They are additive: nothing that was
// already in the object is touched.
const (
	// GovLevelResultKey holds the real G0Result / G1Result / G2Result.
	//
	// The CONCLUSION, in the exact shape the govRoot commits to, so a reader can
	// recompute the canonical hash from the stored row and compare it against
	// what was signed.
	GovLevelResultKey = "result"

	// GovLevelReceiptKey holds the GovReceiptEvidence — the merkle path.
	//
	// The EVIDENCE. Its presence is what separates a checkable row from a
	// summary-only one, and GovernanceLevelsFromStorage keys ErrGovernanceSummaryOnly
	// on exactly this.
	GovLevelReceiptKey = "receipt"

	// GovLevelTimingBasisKey holds []SignatureTimingBasis — which counted
	// signatures' ordering before execution was RE-DERIVED here and which was
	// INHERITED from the fact of execution because signer and principal sit on
	// different partitions.
	//
	// The QUALIFIER. "result" carries timingVerified: true for every counted
	// signature; this says which of those trues rest on the weaker basis. It is
	// beside "result" rather than inside it because the flag lives in G1Result,
	// which is inside the govRoot preimage.
	//
	// Absent means the generator recorded none — which is NOT the same as "every
	// signature was locally ordered", and must never be read that way.
	GovLevelTimingBasisKey = "timingBasis"
)

// GovernanceLevelInputs is what the persistence layer could recover about the
// governance proof from the commitment map.
//
// Every field is optional. A writer holding none of it still writes its row —
// with the flags it always wrote — and that row is honestly summary-only rather
// than absent.
type GovernanceLevelInputs struct {
	// G0/G1/G2 are the raw marshalled G*Result, exactly as the attestation
	// captured them. Kept as raw JSON rather than decoded and re-encoded: a
	// round trip through the Go structs could silently normalise a field, and
	// what must be stored is what was HASHED.
	G0 json.RawMessage
	G1 json.RawMessage
	G2 json.RawMessage

	// Receipts is the merkle path per level.
	Receipts []certenproof.GovReceiptEvidence

	// TimingBasis is the per-signature timing basis, across all levels. Filed
	// per level by TimingBasisFor when the row is built.
	TimingBasis []certenproof.SignatureTimingBasis

	// Level is the governance level actually achieved ("G0"|"G1"|"G2").
	Level string
}

// ResultFor returns the raw result for one level, or nil.
func (in *GovernanceLevelInputs) ResultFor(level string) json.RawMessage {
	if in == nil {
		return nil
	}
	switch level {
	case "G0":
		return in.G0
	case "G1":
		return in.G1
	case "G2":
		return in.G2
	}
	return nil
}

// TimingBasisFor returns the timing-basis records filed under one level.
//
// No fallback to another level, unlike ReceiptFor. The three levels share one
// execution receipt, so relabelling G0's path for G1 records the same fact; the
// timing basis is per SIGNATURE, and G0 evaluates none. Borrowing across levels
// here would attach one level's signature set to another's row.
func (in *GovernanceLevelInputs) TimingBasisFor(level string) []certenproof.SignatureTimingBasis {
	if in == nil {
		return nil
	}
	return certenproof.TimingBasisFor(in.TimingBasis, level)
}

// ReceiptFor returns the receipt evidence for one level, or nil.
//
// Falls back to G0's evidence for G1 and G2 when they carry none of their own:
// G1 embeds G0 and G2 embeds G1, so all three describe the SAME execution
// receipt, and a generator that emitted the path once has not thereby made the
// higher levels unverifiable. The returned copy is relabelled so the stored row
// never claims to be evidence for a level it was not filed under.
func (in *GovernanceLevelInputs) ReceiptFor(level string) *certenproof.GovReceiptEvidence {
	if in == nil {
		return nil
	}
	if ev := certenproof.GovReceiptEvidenceFor(in.Receipts, level); ev != nil {
		return ev
	}
	if level == "G1" || level == "G2" {
		if ev := certenproof.GovReceiptEvidenceFor(in.Receipts, "G0"); ev != nil {
			relabelled := *ev
			relabelled.Level = level
			return &relabelled
		}
	}
	return nil
}

// GovernanceInputsFromCommitment recovers the governance results and receipt
// evidence from the commitment map RunProofCycle built.
//
// Returns nil when the map carries nothing governance-related, so a caller can
// tell "this cycle had no governance data" apart from "it had empty governance
// data" — the first is a plumbing state, the second would be a claim.
func GovernanceInputsFromCommitment(cm map[string]interface{}) *GovernanceLevelInputs {
	if cm == nil {
		return nil
	}
	in := &GovernanceLevelInputs{}
	found := false

	if s, ok := cm[consensus.G0ProofCommitmentKey].(string); ok && s != "" {
		in.G0 = json.RawMessage(s)
		found = true
	}
	if s, ok := cm[consensus.G1ProofCommitmentKey].(string); ok && s != "" {
		in.G1 = json.RawMessage(s)
		found = true
	}
	if s, ok := cm[consensus.G2ProofCommitmentKey].(string); ok && s != "" {
		in.G2 = json.RawMessage(s)
		found = true
	}
	if s, ok := cm[consensus.GovernanceLevelCommitmentKey].(string); ok && s != "" {
		in.Level = s
		found = true
	}
	if s, ok := cm[consensus.GovReceiptsCommitmentKey].(string); ok && s != "" {
		var receipts []certenproof.GovReceiptEvidence
		if err := json.Unmarshal([]byte(s), &receipts); err == nil && len(receipts) > 0 {
			in.Receipts = receipts
			found = true
		}
	}
	if s, ok := cm[consensus.GovTimingBasisCommitmentKey].(string); ok && s != "" {
		var tb []certenproof.SignatureTimingBasis
		if err := json.Unmarshal([]byte(s), &tb); err == nil && len(tb) > 0 {
			in.TimingBasis = tb
			found = true
		}
	}
	if !found {
		return nil
	}
	return in
}

// BuildGovernanceLevelJSON returns level_json for one governance level.
//
// existing is whatever the caller already built — the verdict flags — and every
// key in it survives untouched. result is the raw G*Result and ev is its merkle
// path; either may be absent, and an absent one simply does not add its key.
//
// The two added keys are deliberately independent:
//
//	"result"  present  => the conclusion can be re-hashed and compared to the
//	                      govRoot that was signed.
//	"receipt" present  => the receipt can be RECOMPUTED from this row alone.
//
// A row with the first and not the second is a stronger record than the flags
// alone and is still summary-only, because it cannot be checked. Saying so is
// the whole point; a row that carries a conclusion and calls itself verified is
// the condition this stage exists to end.
func BuildGovernanceLevelJSON(
	level string,
	result json.RawMessage,
	ev *certenproof.GovReceiptEvidence,
	timingBasis []certenproof.SignatureTimingBasis,
	existing map[string]interface{},
) json.RawMessage {
	obj := map[string]interface{}{}
	for k, v := range existing {
		obj[k] = v
	}

	if len(result) > 0 && json.Valid(result) {
		obj[GovLevelResultKey] = json.RawMessage(result)
	}
	if ev.HasPath() {
		if raw, err := json.Marshal(ev); err == nil {
			obj[GovLevelReceiptKey] = json.RawMessage(raw)
		}
	}
	// Written only when there is something to write. An empty array would
	// assert "we looked and none were weakened", which is a different claim
	// from "this generator did not record it".
	if len(timingBasis) > 0 {
		if raw, err := json.Marshal(timingBasis); err == nil {
			obj[GovLevelTimingBasisKey] = json.RawMessage(raw)
		}
	}

	out, err := json.Marshal(obj)
	if err != nil {
		// Fall back to the flags alone rather than dropping the row. A row that
		// describes the level is worth more than no row, and its lack of the
		// evidence key is exactly what makes it read summary-only downstream —
		// the read path will not mistake it for a verified one.
		if fallback, ferr := json.Marshal(existing); ferr == nil {
			return fallback
		}
		return json.RawMessage(`{}`)
	}
	return out
}

// LogGovernanceLevelEvidence reports, per level, whether real evidence was
// stored — because a silent stub is how this went unnoticed for 401 rows.
func LogGovernanceLevelEvidence(logf func(string, ...interface{}), proofID fmt.Stringer, level string,
	result json.RawMessage, ev *certenproof.GovReceiptEvidence,
	timingBasis []certenproof.SignatureTimingBasis) {

	// Said separately from the result/receipt verdict below, because it is a
	// separate claim: a row can carry a full merkle path and still not say which
	// of its counted signatures were only ordered by execution inclusion.
	if weak := certenproof.WeakenedTimingBasis(timingBasis); len(weak) > 0 {
		logf("⚠️ [GOV-LEVEL] proof %s %s: %d of %d counted signature(s) are CROSS-PARTITION — their "+
			"ordering before execution rests on execution inclusion, NOT on a local block "+
			"comparison; recorded under %q",
			proofID, level, len(weak), len(timingBasis), GovLevelTimingBasisKey)
	}

	switch {
	case len(result) > 0 && ev.HasPath():
		logf("✅ [GOV-LEVEL] proof %s %s: stored the real result AND its %d-step merkle path — "+
			"this row recomputes from level_json alone", proofID, level, len(ev.Entries))
	case len(result) > 0:
		logf("⚠️ [GOV-LEVEL] proof %s %s: stored the real result but NO merkle path — the conclusion "+
			"is recorded and cannot be checked, so this row is summary-only", proofID, level)
	default:
		logf("🚨 [GOV-LEVEL] proof %s %s: no governance result reached persistence; storing verdict "+
			"flags only. This row does NOT contain the governance proof", proofID, level)
	}
}
