// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Names of the pending reasons of this kind (finality_pending{reason}; the closed set of testdata/finality/states.json).
const (
	PendingBlockNotYetCovered = "block_not_yet_covered"
	PendingLCUnavailable      = "finality_lc_unavailable"
	PendingLedgerIncomplete   = "finality_ledger_incomplete"
	PendingHistoryProof       = "history_proof_unavailable"
)

// HeaderChainReason values of finality_header_chain_broken{spine:"l1"}: the registry's closed set (shared with Adiri).
const (
	SpineL1          = "l1"
	reasonParentHash = "parent_hash_mismatch"
	reasonNumberGap  = "number_gap"
)

// stateOf adapts an L1-head fault (pkg/finality/ethl1) to the framework's StateError with the SAME code and fields. The
// header-chain reasons of ethl1 ("hash", "number", "rlp") are mapped onto the registry's closed set (parent_hash_mismatch,
// number_gap); an unreadable header cannot reach here because Verify reads every spine header first, but if it did it would be
// finality_evidence_malformed, never a header-chain reason outside the set.
func stateOf(err error) error {
	f, ok := err.(*ethl1.Fault)
	if !ok {
		return err
	}
	s := finality.NewState(f.Code)
	for k, v := range f.Fields {
		s.Fields[k] = v
	}
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
