// Copyright 2026 Certen Protocol
//
// WHICH PARTITION'S BLOCK NUMBERS A KEY PAGE IS JUDGED IN (DAX-1G-R2, G-85).
//
// # THE DEFECT
//
// A block number is a position on ONE partition's chain. G0's EXEC_MBI is the block of the PRINCIPAL's partition in which the governed
// transaction executed. A key page's history (authority_history.go) is a sequence of blocks of the PAGE's partition. Until this file
// the snapshot of the key page was `timeline.At(EXEC_MBI)` whichever partition the page lives on, so a key page on another partition
// than the principal was replayed to a number that counts a different chain:
//
//	acc://dax1-r6a-erp.acme/book/1 did not exist at block 16972068: its genesis is at block 16981650
//
// (the principal on bvn3, EXEC_MBI 16,972,068; the page on bvn2, created at 16,981,650: bvn2 counts 9,582 ahead). It had never shown
// because the key page of every proof until then was on the principal's partition; the erp initiator of decision 0042 of the
// transaction-controls lab (a separate identity that is no authority of anything, which the intent declares as its signer) is on
// whichever partition its name routes to. g7 passed because its two ADIs happen to route to the same partition (bvn1), not because of
// the partitions' heights.
//
// # THE RULE (docs/proof/G1_CROSS_PARTITION.md D9)
//
// The partition that holds a signer's page "judges the key signature, page version, thresholds and delegate entries at Y's own arrival
// block" (G1_CROSS_PARTITION.md section 1, fact 1). So:
//
//   - a key page on the PRINCIPAL's partition is replayed to EXEC_MBI exactly as before (same frame; nothing changes, byte for byte);
//   - a key page on ANOTHER partition is replayed to F, the last block of its own partition in which a counted signature of this
//     transaction was recorded on it (a signature whose signer is the page, or a delegated vote cast through it). Each such block is the
//     receipt.localBlock of the message on that page's own signature chain, bound to the message by its receipt; it is the same block the
//     vote model judges the message at. A page with no counted signature of the transaction has no such block and is REFUSED by name:
//     there is no fallback to EXEC_MBI, to the page's head or to its genesis.
//
// The order of two numbers is compared only where both count one chain: a signer is compared with the PRINCIPAL's EXEC_MBI when it
// shares the principal's identity (evaluateCandidate, unchanged), and the account the timing record names as the clock is the principal
// when the key page is on another partition.
//
// # NOTHING THAT IS HASHED MOVES
//
// G1Result, AuthoritySnapshot, ValidatedSignature and SignatureTimingBasis gain no field. For a key page on the principal's partition
// every byte is what it was (g1_frame_dump_test.go proves it on every fixture). For a key page on another partition the proof did not
// exist before (it failed) or, where the page's partition counts lower than the principal's, was a snapshot at a meaningless block.

package main

import (
	"fmt"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
)

// keyPageFrame says whether the key page G1 is about counts blocks on the principal's partition.
type keyPageFrame struct {
	principal string
	page      string

	// foreign is true when the key page is on another partition than the principal: EXEC_MBI is not a block of the page's chain.
	foreign bool
	// The partitions the network's routing table names (lower case, "bvn2"); empty when the two accounts share an ADI identity, which
	// needs no table because Accumulate routes by root identity.
	principalPartition string
	pagePartition      string
}

// frameOfKeyPage decides, once per proof, whether the key page is on the principal's partition.
//
// Two accounts of one ADI identity certainly route to one partition (sameRoutingPartition: no table read, and the answer every proof
// to date rests on). Two different identities may or may not; then the network's own routing table decides, read through networkInfo
// (the read the gated signature types already make). A table that cannot be read is an outage, named, never a guess in either
// direction: a wrong "same" would replay a page to a number of another chain, a wrong "foreign" would take the page's state at a block
// that is not the execution block for a page that shares the principal's chain.
func (g1 *G1Layer) frameOfKeyPage(principal, keyPage string) (keyPageFrame, error) {
	f := keyPageFrame{principal: normalizeAccURL(principal), page: normalizeAccURL(keyPage)}
	if f.principal == "" || sameRoutingPartition(f.principal, f.page) {
		return f, nil
	}
	pp, err := g1.partitionOf(f.principal)
	if err != nil {
		return f, frameUnavailable(keyPage, fmt.Errorf("the partition of the principal %s: %w", principal, err))
	}
	kp, err := g1.partitionOf(f.page)
	if err != nil {
		return f, frameUnavailable(keyPage, fmt.Errorf("the partition of the key page %s: %w", keyPage, err))
	}
	f.principalPartition, f.pagePartition = pp, kp
	f.foreign = pp != kp
	return f, nil
}

// frameUnavailable is the outage of not being able to tell which partition the key page is on: not a governance verdict.
func frameUnavailable(keyPage string, err error) error {
	return &SignatureEvidenceIncomplete{Route: "key-page-frame", Requested: 0, Unavailable: []UnavailableSignature{{
		MessageID: keyPage, Stage: RoutingUnavailable{}.Reason(),
		Err: err.Error() + ". Whether the key page counts blocks on the principal's partition is not established. This is NOT a governance rejection"}}}
}

// clockAccount is the account whose block counter EXEC_MBI is compared against signers' receipts: the key page when it is on the
// principal's partition (every record to date), the principal itself when the key page is on another partition.
func (g1 *G1Layer) clockAccount(snapshotPage string) string {
	if f := g1.keyFrame; f != nil && f.foreign {
		return f.principal
	}
	return snapshotPage
}

// lastBlockOnPage is F: the last block, on the page's own partition, in which a counted signature of the transaction was recorded on
// the page. The evidence holds two kinds of message a page records: a user signature whose signer is the page (Signatures) and a
// delegated vote recorded on the page that delegated it (Arrivals). Each Fact.Block is the receipt.localBlock of the message on that
// page's own signature chain, so a verifier that holds the evidence derives F without asking the network.
func lastBlockOnPage(ev *govvote.Evidence, page string) (int64, bool) {
	if ev == nil {
		return 0, false
	}
	page = normalizeAccURL(page)
	var last int64
	for _, s := range ev.Signatures {
		if normalizeAccURL(s.Fact.Signer) == page && s.Fact.Block > last {
			last = s.Fact.Block
		}
	}
	for _, a := range ev.Arrivals {
		if normalizeAccURL(a.Fact.Page) == page && a.Fact.Block > last {
			last = a.Fact.Block
		}
	}
	return last, last > 0
}

// preliminarySnapshot is what the signature routes need of a key page on another partition BEFORE any signature is counted: its
// identity, the principal's execution terms and the delegate entries of the page as the network holds it (the enumeration route seeds
// its walk from them, as it does for every authority page: spec 1.2.2, "queried once and their current state used"). It is never
// emitted and notes no page rule; the snapshot G1 returns is foreignPageSnapshot's.
func (ab *AuthorityBuilder) preliminarySnapshot(tl *pageTimeline, keyPage string, terms ExecTerms) *AuthoritySnapshot {
	head := stateFromPage(tl.States[len(tl.States)-1].Page)
	return &AuthoritySnapshot{
		Page:      keyPage,
		ExecTerms: terms,
		StateExec: head,
		Genesis:   *tl.Genesis,
		Validation: ValidationSummary{GenesisFound: true, TotalEntries: tl.Entries, FinalVersion: head.Version,
			FinalThreshold: head.Threshold, FinalKeyCount: len(head.Keys)},
	}
}

// foreignPageSnapshot is the snapshot G1 emits for a key page on another partition: the page's state after every change recorded at or
// before F, in the page's own block numbers, with the principal's execution terms. The page must have a counted signature of this
// transaction: it is the only thing that places the page in time on its own chain.
func (g1 *G1Layer) foreignPageSnapshot(tl *pageTimeline, f keyPageFrame, g0 *G0Result, ev *govvote.Evidence) (*AuthoritySnapshot, error) {
	block, ok := lastBlockOnPage(ev, f.page)
	if !ok {
		return nil, ValidationError{Msg: fmt.Sprintf("the key page %s (partition %s) carries no counted signature of this transaction, "+
			"so its state at execution in its own partition's block numbers is not established: EXEC_MBI %d counts the blocks of %s, "+
			"not of %s. A key page on another partition than the principal is judged at the block in which its own signature was "+
			"recorded; without one there is no such block, and the state is not taken at EXEC_MBI, at its head or at its genesis",
			f.page, f.pagePartition, g0.ExecMBI, f.principalPartition, f.pagePartition)}
	}
	fmt.Printf("[G1] [FRAME] key page %s routes to %s, the principal %s to %s: EXEC_MBI %d is a block of %s, so the page's state is "+
		"taken at block %d of %s, the last block in which a counted signature of this transaction was recorded on it\n",
		f.page, f.pagePartition, f.principal, f.principalPartition, g0.ExecMBI, f.principalPartition, block, f.pagePartition)
	return g1.authorityBuilder.snapshotAt(tl, f.page, block, ExecTerms{MBI: g0.ExecMBI, Witness: g0.ExecWitness}, g0.TxHash)
}

// String is the frame in one line, for the log.
func (f keyPageFrame) String() string {
	if !f.foreign {
		return "same partition as the principal"
	}
	return strings.Join([]string{"another partition than the principal: page on", f.pagePartition, "principal on", f.principalPartition}, " ")
}
