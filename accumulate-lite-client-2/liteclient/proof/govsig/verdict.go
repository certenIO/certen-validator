// Copyright 2026 Certen Protocol

package govsig

import "errors"

// Verdict names the outcome of Verify in the vocabulary the shared conformance vectors (testdata/sigtypes) and the
// TypeScript verifier use. "accepted" is the only success; "refused:*" is a genuine rejection of the signature or of
// the evidence's consistency; "named:*" is the verifier saying it cannot judge, with the state's name - never a weaker
// answer shaped like the strong one.
func Verdict(err error) string {
	if err == nil {
		return "accepted"
	}
	var (
		inv      SignatureInvalid
		nk       NotKeySignature
		de       DepthExceeded
		cid      TypedDataChainIDMismatch
		notMet   ExecutorGateNotMet
		unproven ExecutorVersionUnproven
		noTxn    TransactionUnavailableForTypedData
		noName   NetworkNameUnproven
	)
	switch {
	case errors.As(err, &inv):
		return "refused:signature_invalid"
	case errors.As(err, &nk):
		return "refused:not_a_key_signature"
	case errors.As(err, &de):
		return "refused:delegation_depth_exceeded"
	case errors.As(err, &cid):
		return "refused:typed_data_chain_id_mismatch"
	case errors.As(err, &notMet):
		return "refused:executor_gate_not_met"
	case errors.As(err, &unproven):
		return "named:g1_executor_version_unproven"
	case errors.As(err, &noTxn):
		return "named:transaction_unavailable_for_typed_data"
	case errors.As(err, &noName):
		return "named:network_name_unproven"
	}
	return "refused:other"
}
