// Copyright 2026 Certen Protocol
//
// WHICH counted signatures' timing rests on a weaker basis — recorded BESIDE
// the hashed summary, never inside it.
//
// # THE CLAIM THAT COULD NOT BE READ
//
// Every counted signature in a G1 result carries `timingVerified: true`. For a
// signer on the principal's own partition that is a real re-derivation:
// receipt.localBlock <= execMBI, two indices on one chain, the rule Accumulate
// itself enforces, checked again from this proof's own data.
//
// For a CROSS-PARTITION signer the comparison is skipped, and correctly — the
// two indices count different chains, so subtracting them is not a weak check
// but a meaningless one that returns a confident answer. (Measured on Kermit,
// corpus case F: a delegated signer on BVN2 with localBlock 10200307 against an
// execMBI of 10199460 on BVN1 was rejected as "signed after execution" — a
// false governance rejection of a signature the network had accepted.)
//
// Ordering still holds for that signer: Accumulate does not execute a
// transaction whose signatures came after execution, and G0 proves this one
// executed. But that is INHERITED from the fact of execution rather than
// re-derived here, and it is strictly the weaker claim.
//
// That distinction lived in a comment and in a local variable called
// `sameClock`. Both signatures printed `timingVerified: true` and a reader
// could not tell them apart. `summary_only` exists in this codebase precisely
// so a weaker claim cannot read as the stronger one; this is the same rule
// applied to timing.
//
// # WHY THIS TYPE IS SEPARATE
//
// `TimingVerified` is a field of ValidatedSignature, which is inside G1Result,
// which is hashed into the govRoot (v6_1_signing.go: SetG1FromJSON, over
// CanonicalJSONMarshal of THIS package's G1Result). Struct layout IS the wire
// format, so widening ValidatedSignature — the obvious move — would move every
// govRoot ever signed. TestP6_CanonicalShapesUnchanged blocks it, correctly.
//
// So the record lives here, in a type deliberately NOT reachable from any
// canonical hash, and rides on the GovernanceProof WRAPPER — exactly where
// GovReceiptEvidence rides, and for the identical reason. The govproof CLI
// emits it as a top-level `timingBasis` array on the G1 document; the
// unmarshal into G1Result ignores it (there is no such field), and a SIDE READ
// keeps it. The preimage is byte-identical with or without this file.
package proof

import (
	"encoding/json"
	"sort"
	"strings"
)

// The two bases, mirroring the govproof constants they are read from. Restated
// rather than imported: consolidated_governance-proof is `package main` and
// ships as a separate binary, so there is nothing to import. The strings are
// the contract between the two, and TestP8_TimingBasisConstantsMatchGovproof
// pins them.
const (
	// TimingBasisLocalOrdering — receipt.localBlock <= execMBI was computed, on
	// one partition's clock. Re-derived from this proof's own data.
	TimingBasisLocalOrdering = "local-ordering"

	// TimingBasisExecutionInclusion — the local comparison was NOT applicable
	// because signer and principal are different identities whose block indices
	// count different chains. Ordering rests on the transaction having executed,
	// which G0 proves. Inherited, not re-derived.
	TimingBasisExecutionInclusion = "execution-inclusion"
)

// SignatureTimingBasis is how ONE counted signature's ordering before
// execution was established.
//
// SignerPartition and PrincipalPartition are filled in HERE and are empty in
// what the CLI emits. The govproof binary decides comparability on ADI
// identity, not on a routing table — the table lives in this module, which that
// package cannot import, and a second copy of the prefix arithmetic there would
// be a thing that can drift from the one the proof legs are built with. So the
// generator records the identities it actually compared, and this side, which
// does hold the table, names the partitions. Neither invents what it lacks.
type SignatureTimingBasis struct {
	Level       string `json:"level"` // "G1" | "G2"
	MessageID   string `json:"messageID"`
	MessageHash string `json:"messageHash"`

	SignerPage         string `json:"signerPage"`
	SignerIdentity     string `json:"signerIdentity"`
	SignerPartition    string `json:"signerPartition,omitempty"`
	PrincipalPage      string `json:"principalPage"`
	PrincipalIdentity  string `json:"principalIdentity"`
	PrincipalPartition string `json:"principalPartition,omitempty"`

	// LocalOrderingChecked is the point of the record. False means
	// timingVerified rests on execution inclusion, not on a comparison.
	LocalOrderingChecked bool `json:"localOrderingChecked"`

	// The two indices. Comparable to each other ONLY when
	// LocalOrderingChecked is true; restated when it is false so a reader can
	// see the numbers that were deliberately NOT compared.
	ReceiptLocalBlock int64 `json:"receiptLocalBlock"`
	ExecMBI           int64 `json:"execMBI"`

	Basis string `json:"basis"`
}

// Weakened reports whether this signature's ordering was inherited rather than
// re-derived.
func (t SignatureTimingBasis) Weakened() bool { return !t.LocalOrderingChecked }

// WeakenedTimingBasis returns the records whose ordering rests on execution
// inclusion.
func WeakenedTimingBasis(in []SignatureTimingBasis) []SignatureTimingBasis {
	var out []SignatureTimingBasis
	for _, t := range in {
		if t.Weakened() {
			out = append(out, t)
		}
	}
	return out
}

// TimingBasisFor returns the records filed under one level, or nil.
func TimingBasisFor(in []SignatureTimingBasis, level string) []SignatureTimingBasis {
	var out []SignatureTimingBasis
	for _, t := range in {
		if t.Level == level {
			out = append(out, t)
		}
	}
	return out
}

// rawTimingBasisEnvelope is the minimum shape needed to lift the array out of a
// governance result's raw JSON.
//
// Only timingBasis is declared. Everything else is ignored on purpose: this is
// a SIDE read taken alongside the ordinary unmarshal into G1Result/G2Result,
// and it must never influence what those structs contain. The hashed structs
// are parsed exactly as before; this pass keeps the field they are not allowed
// to have.
type rawTimingBasisEnvelope struct {
	TimingBasis []SignatureTimingBasis `json:"timingBasis"`
}

// TimingBasisFromRaw lifts the timing-basis records out of a governance
// result's raw JSON and names each signer's partition from this module's
// routing table.
//
// Returns nil — not an error — when the result carries none. A generator that
// never emitted them is a govproof build predating this evidence, and the
// honest record for it is ABSENCE. Manufacturing empty records would produce
// something that reads like evidence and says nothing, and an absent record
// must not read as "every signature was locally ordered".
func TimingBasisFromRaw(level string, raw json.RawMessage) []SignatureTimingBasis {
	if len(raw) == 0 {
		return nil
	}
	var env rawTimingBasisEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil
	}
	if len(env.TimingBasis) == 0 {
		return nil
	}

	out := make([]SignatureTimingBasis, 0, len(env.TimingBasis))
	for _, t := range env.TimingBasis {
		t.Level = level
		// Named from the routing table production actually routes with, so a
		// record that says "bvn2" means the same thing the proof's legs mean.
		// An account that does not route leaves the field EMPTY rather than
		// guessing: an unnamed partition is honest, a wrong one is not.
		t.SignerPartition = CalculateBVNFromAccountURL(t.SignerPage)
		t.PrincipalPartition = CalculateBVNFromAccountURL(t.PrincipalPage)
		out = append(out, t)
	}
	sortTimingBasis(out)
	return out
}

// sortTimingBasis puts records in a canonical order: level, then message hash,
// then message ID.
//
// Discovery order is not stable — two extraction routes reach the same
// signatures by different queries, and which one survives depends on which
// degraded — so unordered records would make two validators reading identical
// chain data produce different bytes for the same evidence.
func sortTimingBasis(in []SignatureTimingBasis) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Level != in[j].Level {
			return in[i].Level < in[j].Level
		}
		a, b := strings.ToLower(in[i].MessageHash), strings.ToLower(in[j].MessageHash)
		if a != b {
			return a < b
		}
		return strings.ToLower(in[i].MessageID) < strings.ToLower(in[j].MessageID)
	})
}
