// Copyright 2026 Certen Protocol
//
// HOW each counted signature's ordering-before-execution was established.
//
// # THE CLAIM THAT WAS NOT WRITTEN DOWN
//
// A counted signature carries TimingVerified: true. For a signer on the
// principal's own partition that means something specific and checkable:
// receipt.localBlock <= execMBI, two indices on one chain, a real
// re-derivation of a rule Accumulate enforces.
//
// For a CROSS-PARTITION signer that comparison is skipped, and correctly so —
// those indices count different chains, and subtracting them is not a weak
// check but a meaningless one that produces a confident answer. (Observed live
// on Kermit, corpus case F: the delegated signer on BVN2 had localBlock
// 10200307 against an execMBI of 10199460 on BVN1, and the signature was
// rejected as "signed after execution" — a false governance rejection of a
// signature the network had accepted.)
//
// The ordering still holds for that signer. Accumulate does not execute a
// transaction whose signatures came after execution, and G0 proves this one
// executed, so the ordering is established BY EXECUTION INCLUSION rather than
// by comparing indices. That is a strictly weaker basis: it is inherited from
// the fact of execution instead of re-derived locally.
//
// Until this file that distinction lived in a comment and in a local variable
// named sameClock. A reader of the proof saw TimingVerified: true on both kinds
// of signature and could not tell them apart. This package already refuses to
// let a weaker claim read as a stronger one — SigUnavailable is not
// SigRejected, a summary-only row is not a verified one — and this is the same
// rule applied to timing.
//
// # WHY IT IS NOT A FIELD OF ValidatedSignature
//
// TimingVerified is a field of ValidatedSignature, which is inside G1Result,
// which the validator hashes into the govRoot (SetG1FromJSON). Widening the
// shape the govRoot commits to would move every govRoot ever signed.
//
// So this travels BESIDE that shape, in its own top-level array on the emitted
// G1 document, exactly where GovReceiptEvidence put the receipt merkle path for
// the same reason. The validator lifts it with a side read into a wrapper that
// no canonical hash can reach; its own G1Result has no such field, so the
// preimage is byte-identical with or without this.
//
// # WHY IDENTITIES AND NOT PARTITION NAMES
//
// sameRoutingPartition answers on ADI identity, not on a routing table: the
// table lives in the validator's module, which this package cannot import, and
// a second copy of the prefix arithmetic here would be a thing that can drift
// from the one the proof legs are built with. So this records the identities
// that were actually compared and the answer that comparison gave. The
// validator, which does hold the table, names the partitions when it lifts the
// record. Neither side invents what it does not have.

package main

import (
	"sort"
	"strings"
)

// Basis values. Exactly two, because there are exactly two ways this package
// establishes that a signature preceded execution.
const (
	// TimingBasisLocalOrdering: receipt.localBlock <= execMBI was computed, on
	// one partition's clock. Re-derived here, from this proof's own data.
	TimingBasisLocalOrdering = "local-ordering"

	// TimingBasisExecutionInclusion: the local comparison was NOT applicable,
	// because the signer and the principal are different identities and their
	// block indices count different chains. Ordering rests on the transaction
	// having executed at all, which G0 proves. Inherited, not re-derived.
	TimingBasisExecutionInclusion = "execution-inclusion"
)

// SignatureTimingBasis records, for ONE counted signature, how its
// ordering-before-execution was established.
//
// Every field is what was actually observed at evaluation time. LocalBlock and
// ExecMBI are restated even when the comparison did not run, so a reader can
// see the two numbers that were NOT compared and why — the alternative is a
// record that says "we skipped it" and gives no way to check that skipping was
// right.
type SignatureTimingBasis struct {
	MessageID   string `json:"messageID"`
	MessageHash string `json:"messageHash"`

	// The two accounts whose clocks were in question, and the identities
	// sameRoutingPartition actually compared.
	SignerPage        string `json:"signerPage"`
	SignerIdentity    string `json:"signerIdentity"`
	PrincipalPage     string `json:"principalPage"`
	PrincipalIdentity string `json:"principalIdentity"`

	// LocalOrderingChecked is the whole point of this record. False means
	// TimingVerified rests on execution inclusion, not on a comparison.
	LocalOrderingChecked bool `json:"localOrderingChecked"`

	// The two indices. Comparable to each other ONLY when
	// LocalOrderingChecked is true.
	ReceiptLocalBlock int64 `json:"receiptLocalBlock"`
	ExecMBI           int64 `json:"execMBI"`

	// Basis is one of the two constants above. Stated explicitly rather than
	// left to be inferred from LocalOrderingChecked: a reader should not have
	// to know which boolean means which claim.
	Basis string `json:"basis"`
}

// Weakened reports whether this signature's timing rests on the weaker basis.
func (t SignatureTimingBasis) Weakened() bool {
	return !t.LocalOrderingChecked
}

// newTimingBasis records one evaluation. localChecked comes from the same
// expression that decides whether the comparison runs, so the record cannot
// describe a different decision than the one taken.
func newTimingBasis(messageID, messageHash, signerPage, principalPage string,
	localChecked bool, receiptLocalBlock, execMBI int64) SignatureTimingBasis {

	basis := TimingBasisExecutionInclusion
	if localChecked {
		basis = TimingBasisLocalOrdering
	}
	return SignatureTimingBasis{
		MessageID:            messageID,
		MessageHash:          messageHash,
		SignerPage:           signerPage,
		SignerIdentity:       identityOf(signerPage),
		PrincipalPage:        principalPage,
		PrincipalIdentity:    identityOf(principalPage),
		LocalOrderingChecked: localChecked,
		ReceiptLocalBlock:    receiptLocalBlock,
		ExecMBI:              execMBI,
		Basis:                basis,
	}
}

// sortTimingBasis puts the records in a canonical order.
//
// Discovery order is not stable — two routes reach the same signatures by
// different queries, and the surviving route depends on which one degraded —
// so two validators reading identical chain data would otherwise emit these in
// different orders. Sorted by message hash, then message ID, which are content,
// not response ordering.
func sortTimingBasis(in []SignatureTimingBasis) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := strings.ToLower(in[i].MessageHash), strings.ToLower(in[j].MessageHash)
		if a != b {
			return a < b
		}
		return strings.ToLower(in[i].MessageID) < strings.ToLower(in[j].MessageID)
	})
}

// countWeakened returns how many of the records rest on execution inclusion.
func countWeakened(in []SignatureTimingBasis) int {
	n := 0
	for _, t := range in {
		if t.Weakened() {
			n++
		}
	}
	return n
}
