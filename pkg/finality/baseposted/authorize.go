// Copyright 2026 Certen Protocol

package baseposted

import (
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
)

// THE authorization of an inbox transaction. One rule, one function, three callers (RB12-GO-INT D2 and RB12-INDEX-FIX F19): the live capture and
// the gap backfill (Capturer.CaptureBlock) keep only the batcher's transactions, the window reader and the index writer skip the rest in rows
// that were stored before that rule existed, and both reproduce the verifier's rule (verify.go verifyChannel, "Authentication"): a frame
// transaction is accepted only if its sender, recovered with the signer of the L1 chain, is SystemConfig.batcherHash as proven by
// systemConfigAt under the state root of the transaction's own L1 block. Nothing else decides who the batcher is.

// batcherAuthorizer says which transactions of one captured block the batcher sent.
type batcherAuthorizer struct {
	want   [20]byte
	signer types.Signer
}

// authorizerAt proves the batcher of a block: the SystemConfig proof nodes verified under the block's state root (systemConfigAt). An error
// is the verifier's own refusal of the proof (contract_identity_unproven, l1_state_proof_invalid, batcher_sender_mismatch ...).
func authorizerAt(bp *Pins, nodes [][]byte, stateRoot [32]byte, number uint64) (*batcherAuthorizer, error) {
	want, err := systemConfigAt(newNodeDB(nodes), bp, stateRoot, number)
	if err != nil {
		return nil, err
	}
	return &batcherAuthorizer{want: want, signer: types.LatestSignerForChainID(new(big.Int).SetUint64(bp.L1ChainID))}, nil
}

// sent reports whether raw is a transaction the batcher sent: it parses and its recovered sender is the batcher. A transaction that does not
// parse, or whose sender cannot be recovered, is not the batcher's.
func (a *batcherAuthorizer) sent(raw []byte) bool {
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return false
	}
	from, err := a.signer.Sender(&tx)
	return err == nil && [20]byte(from) == a.want
}

// foreign is the reader's question: the batcher did not send raw. A nil authorizer (the rows of the block cannot establish the batcher)
// filters nothing, and a transaction that does not parse is not judged here: the reader that parsed it first fails on it by name.
func (a *batcherAuthorizer) foreign(raw []byte) bool {
	if a == nil {
		return false
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return false
	}
	return !a.sent(raw)
}
