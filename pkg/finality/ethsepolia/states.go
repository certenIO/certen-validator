// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// Names of the pending reasons of this kind (finality_pending{reason}; the closed set of testdata/finality/states.json).
const (
	PendingBlockNotYetCovered = "block_not_yet_covered"
	PendingLCUnavailable      = "finality_lc_unavailable"
	PendingLedgerIncomplete   = "finality_ledger_incomplete"
	PendingHistoryProof       = "history_proof_unavailable"
	// PendingAwaitingSpine is the progress of the execution-header spine fetch (RB12-SEPOLIA-SPINE): finality_pending{reason: awaiting_spine,
	// have, need, next_attempt_at}. The headers fetched so far are kept, so the next attempt starts where this one stopped.
	PendingAwaitingSpine = "awaiting_spine"
)

// CodeSpineRowInvalid is the named state of a kept spine chunk that is not what its key says (go_operational, class U, never a verdict):
// the build stops, nothing is verified from it. Its reason is a CLOSED set (testdata/finality/states.json enums.reason).
const CodeSpineRowInvalid = "finality_spine_row_invalid"

// Reasons of finality_spine_row_invalid.
const (
	SpineRowMalformed   = "row_malformed"    // not an RLP list of the item's header count, or a header that cannot be read
	SpineRowNumbers     = "row_numbers"      // the header numbers do not run start..end
	SpineRowNotChained  = "row_not_chained"  // a header is not the parent of the next one
	SpineRowTopMismatch = "row_top_mismatch" // the last header is not the one the key (and the finalized head) names
	SpineRowConflict    = "row_conflict"     // the store holds other bytes under the key these bytes belong to
)

// HeaderChainReason values of finality_header_chain_broken{spine:"l1"}: the registry's closed set (shared with Adiri).
const (
	SpineL1          = "l1"
	reasonParentHash = "parent_hash_mismatch"
	reasonNumberGap  = "number_gap"
)

// stateOf adapts an L1-head fault (pkg/finality/ethl1) to the framework's StateError with the SAME code and fields (l1adapt's conversion). The
// header-chain reasons of ethl1 ("hash", "number", "rlp") are mapped onto the registry's closed set (parent_hash_mismatch,
// number_gap); an unreadable header cannot reach here because Verify reads every spine header first, but if it did it would be
// finality_evidence_malformed, never a header-chain reason outside the set.
func stateOf(err error) error {
	f, ok := err.(*ethl1.Fault)
	if !ok {
		return err
	}
	s := l1adapt.FaultState(f)
	if f.Code == ethl1.CodeHeaderChainBroken {
		switch f.Fields["reason"] {
		case "hash":
			s.Fields["reason"] = reasonParentHash
		case "number":
			s.Fields["reason"] = reasonNumberGap
		default:
			return finality.Malformed("spine", finality.ReasonHeaderBadItem, 0, 0)
		}
	}
	return s
}
