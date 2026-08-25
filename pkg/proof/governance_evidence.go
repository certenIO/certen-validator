// Copyright 2026 Certen Protocol
//
// Stage 2 — the governance receipt's merkle path, stored BESIDE the hashed
// summary rather than inside it.
//
// # THE DEFECT, MEASURED
//
// governance_proof_levels did not contain the governance proof. The rows that
// exist were built from EVM observation results plus key-page thresholds:
//
//	threshold_m, threshold_n, authority_url, confirmations,
//	finality_achieved, inclusion_verified
//
// Those are verdict flags about an EVM settlement. 0 of 401 G0 rows contained
// "entries" (measured 2026-08-25). The real G0Result/G1Result/G2Result existed
// upstream on PendingAttestation and never reached the database.
//
// Separately, the merkle path was discarded AT THE SOURCE.
// txRecord.SourceReceipt is a *merkle.Receipt that HAS .Entries, and
// buildG0Result copied Start, Anchor and LocalBlock out of it and dropped the
// path one line from where it was needed. Nothing needed re-querying; the
// evidence was in memory and was thrown away.
//
// # THE TRAP, AND WHY THIS TYPE IS SEPARATE
//
// GovReceiptData is the Receipt field of G0Result. G0Result is embedded in
// G1Result, which is embedded in G2Result, and all three are hashed into the
// govRoot (v6_1_signing.go: SetG0FromJSON / SetG1FromJSON / SetG2FromJSON).
// CanonicalJSONMarshal is json.Marshal, so struct layout IS the wire format.
//
// ADDING Entries TO GovReceiptData WOULD MOVE EVERY govROOT EVER SIGNED.
// It is the obvious move and it is wrong. TestP6_CanonicalShapesUnchanged
// blocks it, correctly; that test is the specification, not a snapshot.
//
// So the evidence lives here, in a type that is deliberately NOT reachable
// from any canonical hash — the same shape Phase 6 used for the L4 legs, where
// layer4Bvn/layer4Dn went onto CompleteProof and e23ce107… did not move.
package proof

import (
	"encoding/json"
	"fmt"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// ReceiptStep is one step of a receipt's merkle path.
//
// A type ALIAS, not a copy: a stored governance receipt and a working-proof
// testdata fixture must be the same document, and two structurally identical
// declarations are two things that can drift. Right reports that the sibling is
// on the right, matching Accumulate's encoding, which OMITS the field when
// false — do not invent omitempty semantics of your own here.
type ReceiptStep = chained_proof.ReceiptStep

// GovReceiptEvidence is the merkle path for one governance receipt.
//
// It is deliberately NOT a field of GovReceiptData: that struct is inside
// G0Result and therefore inside the G0/G1/G2 canonical hash, so widening it
// would move every govRoot ever signed. This type lives BESIDE the hashed
// summary, never inside it.
//
// Start/Anchor/LocalBlock are RESTATED rather than referenced so the evidence
// is self-contained: a verifier reading level_json must be able to recompute
// the receipt from that row alone, without trusting that someone paired it with
// the right summary. If the restated values disagree with the hashed summary,
// that disagreement is itself detectable — which it would not be if this only
// carried the path.
type GovReceiptEvidence struct {
	Level      string        `json:"level"`      // "G0" | "G1" | "G2"
	Start      string        `json:"start"`      // hex32, the leaf
	Anchor     string        `json:"anchor"`     // hex32, the root
	LocalBlock int64         `json:"localBlock"` // the receipt's local block
	Entries    []ReceiptStep `json:"entries"`    // the merkle path, leaf -> anchor
}

// HasPath reports whether any evidence was captured at all.
//
// An evidence record with no start/anchor is not a short path — it is an absent
// record, and callers must treat it as summary-only rather than as a receipt
// that happens to verify.
func (e *GovReceiptEvidence) HasPath() bool {
	return e != nil && e.Start != "" && e.Anchor != ""
}

// VerifyMerkle recomputes the receipt from THIS RECORD ALONE and requires it to
// reach the record's own anchor.
//
// The walk itself is chained_proof.ReceiptVerifier.ValidateIntegrity — the same
// SHA-256 hashPair implementation L1-L3 have always used, and the only receipt
// recomputation in the tree. Nothing is re-implemented here; a second walk would
// be a second thing to keep correct.
//
// FAIL CLOSED. An empty path is valid ONLY when start == anchor (a single-leaf
// tree, where the leaf IS the anchor). Any other empty path is rejected: accept
// it and every receipt verifies vacuously, which is indistinguishable from not
// verifying at all. ValidateIntegrity already enforces this — with an empty path
// it compares start to anchor directly — and the explicit branch here exists
// only to say WHY, since "recomputation mismatch" is a misleading way to report
// "there was nothing to recompute".
func (e *GovReceiptEvidence) VerifyMerkle() error {
	if e == nil {
		return fmt.Errorf("governance receipt evidence is absent")
	}
	if e.Start == "" || e.Anchor == "" {
		return fmt.Errorf("%s receipt evidence: missing start or anchor", e.levelLabel())
	}
	if len(e.Entries) == 0 && e.Start != e.Anchor {
		return fmt.Errorf(
			"%s receipt evidence: no merkle path, and start != anchor (%s != %s) — "+
				"the leaf is NOT proven to be under the anchor",
			e.levelLabel(), truncHex(e.Start), truncHex(e.Anchor))
	}

	rec := chained_proof.Receipt{
		Start:      e.Start,
		Anchor:     e.Anchor,
		LocalBlock: uint64(e.LocalBlock),
		Entries:    e.Entries,
	}
	if err := chained_proof.NewReceiptVerifier(false).ValidateIntegrity(rec); err != nil {
		return fmt.Errorf("%s receipt evidence: %w", e.levelLabel(), err)
	}
	return nil
}

func (e *GovReceiptEvidence) levelLabel() string {
	if e == nil || e.Level == "" {
		return "governance"
	}
	return e.Level
}

func truncHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}

// =============================================================================
// Extraction from a governance result's raw JSON
// =============================================================================

// rawReceiptEnvelope is the minimum shape needed to lift a receipt's path out
// of a governance result's JSON.
//
// Only the receipt is declared. Everything else in the result is ignored on
// purpose: this is a SIDE read, taken alongside the ordinary unmarshal into
// G0Result/G1Result/G2Result, and it must never influence what those structs
// contain. The hashed structs are parsed exactly as before; this pass simply
// keeps the field they are not allowed to have.
type rawReceiptEnvelope struct {
	Receipt struct {
		Start      string        `json:"start"`
		Anchor     string        `json:"anchor"`
		LocalBlock int64         `json:"localBlock"`
		Entries    []ReceiptStep `json:"entries"`
	} `json:"receipt"`
}

// GovReceiptEvidenceFromRaw lifts the receipt evidence out of a governance
// result's raw JSON.
//
// Returns nil — not an error — when the result carries no receipt or no path.
// A generator that never emitted entries is a proof written before this
// evidence existed, and the honest record for it is ABSENCE, marked
// summary-only downstream. Manufacturing an empty path here would produce a
// record that reads like evidence and cannot be checked.
func GovReceiptEvidenceFromRaw(level string, raw json.RawMessage) *GovReceiptEvidence {
	if len(raw) == 0 {
		return nil
	}
	var env rawReceiptEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil
	}
	if env.Receipt.Start == "" || env.Receipt.Anchor == "" {
		return nil
	}
	return &GovReceiptEvidence{
		Level:      level,
		Start:      env.Receipt.Start,
		Anchor:     env.Receipt.Anchor,
		LocalBlock: env.Receipt.LocalBlock,
		Entries:    env.Receipt.Entries,
	}
}

// GovReceiptEvidenceFor returns the evidence recorded for one level, or nil.
func GovReceiptEvidenceFor(receipts []GovReceiptEvidence, level string) *GovReceiptEvidence {
	for i := range receipts {
		if receipts[i].Level == level {
			return &receipts[i]
		}
	}
	return nil
}
