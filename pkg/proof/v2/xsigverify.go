// Copyright 2026 Certen Protocol
//
// Key-signature verification of evidence 2.1 (RB9 verifier round VA, note (a)): one function, the one the vote model's evidence
// (liteclient govvote) and RB8 use - govsig.Verify. A counted or initiating key signature is accepted exactly as Accumulate's executor
// accepts it: after unwrapping at most DelegationDepthLimit delegations the innermost value is one of the nine key-signature types,
// protocol.VerifyUserSignature accepts the outermost signature over the transaction (typedData over the whole transaction, with the chain
// id of the PROVEN network's name), and the executor version in force on the signature's partition at its block admits its type (the
// pinned activation table, xexecutor_table.go over govsig.KermitActivations).
package proofv2

import (
	"errors"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// verifyKeySignature verifies sig over txn as it was recorded on the page pa proves, in the block given, and returns what was
// established. A refusal is a named state with the partition and block of the page: g1_executor_version_unproven for a type the pinned
// table does not show to be registered there, g1_delegation_depth_exceeded for a delegation chain over the limit, g1_signature_invalid
// for everything else (the detail carries govsig's own reason).
func verifyKeySignature(sig protocol.Signature, txn *protocol.Transaction, network string, pa *provenAcct, page string, block uint64) (*govsig.Verified, error) {
	v, err := govsig.Verify(sig, govsig.Env{TxHash: txn.Hash(), Transaction: txn, NetworkName: network,
		Where: govsig.Where{Partition: strings.ToLower(pa.anchor.id), Block: int64(block)}})
	if err == nil {
		return v, nil
	}
	var un govsig.ExecutorVersionUnproven
	var de govsig.DepthExceeded
	switch {
	case errors.As(err, &un):
		return nil, refusal21(StateExecutorVersionUnproven, pa.anchor.id, pa.anchor.block, "the signature on %s: %v", page, err)
	case errors.As(err, &de):
		return nil, refusal21(StateDelegationDepthExceeded, pa.anchor.id, pa.anchor.block, "the signature on %s: %v", page, err)
	}
	return nil, refusal21(StateSignatureInvalid, pa.anchor.id, pa.anchor.block, "the signature on %s: %v", page, err)
}
