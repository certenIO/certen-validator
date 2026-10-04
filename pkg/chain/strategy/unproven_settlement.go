// Copyright 2026 Certen Protocol

package strategy

import "fmt"

// UnprovenSettlementError is a settlement the finalized chain holds - its receipt read from agreeing providers, final and
// canonical - that could not be proven in its block (pkg/ethproof refused it, or the providers did not agree on its
// block's bodies before the deadline). The transaction executed on chain with Status; what is missing is the proof.
//
// It is the named state settled_unproven: never an unobserved settlement (the receipt was read) and never an observation
// (there is no proof to carry). Err says why the block was not proven.
type UnprovenSettlementError struct {
	ChainID     int64
	TxHash      string
	BlockHash   string
	BlockNumber uint64
	Status      uint64 // the receipt's status: 1 executed, 0 reverted
	Err         error
}

func (e *UnprovenSettlementError) Error() string {
	return fmt.Sprintf("settled_unproven: %s is final in block %d (%s) on chain %d with receipt status %d, but cannot be proven in its block: %v",
		e.TxHash, e.BlockNumber, e.BlockHash, e.ChainID, e.Status, e.Err)
}

func (e *UnprovenSettlementError) Unwrap() error { return e.Err }
