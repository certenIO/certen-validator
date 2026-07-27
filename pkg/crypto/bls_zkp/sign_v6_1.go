// V6.1 A+++ BLS signing helper. Uses the EXACT hash-to-G1 function the
// BLSZKVerifierV2 SNARK circuit applies internally (HashMessageToG1V2 in
// circuitv2.go). The on-chain V2 verifier recomputes the same curve point
// during the pairing check, so a signature produced here is the only kind
// the V2 Groth16 prover can actually satisfy.
//
// Pre-V6.1 the validator path signed via bls.KeyManager.SignWithDomain,
// which uses RFC-9380 ExpandMsgXmd hash-to-curve. That produces a different
// G1 point than HashMessageToG1V2 → the BLS pairing constraint inside the
// V2 circuit becomes unsatisfiable (constraint #774716 in our log) → proof
// generation fails → empty proof submitted → contract reverts with
// "BLS signature verification failed."
//
// This helper lives in bls_zkp (not bls) because it needs HashMessageToG1V2
// which is defined here. Keeping it out of pkg/crypto/bls also keeps that
// package free of any V2-circuit dependency.
package bls_zkp

import (
	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// SignV6_1PreExec computes sig = sk · HashMessageToG1V2(messageHash). The
// messageHash MUST be the 32-byte V6.1 A+++ pre-execution hash produced by
// contracts.ComputeEvmMessageHashV6_1_Pre — no domain prefixing or further
// hashing here, because the V6.1 design already binds the domain via the
// "certen:bls:v1:pre" bytes32 inside the messageHash preimage.
//
// Pairs with the on-chain BLSZKVerifierV2 pairing check:
//
//	e(sig, G2) == e(HashMessageToG1V2(messageHash), pk_aggregate)
//
// Returns nil if sk is nil — callers MUST check.
func SignV6_1PreExec(sk *bls.PrivateKey, messageHash [32]byte) *bls.Signature {
	if sk == nil {
		return nil
	}
	h := HashMessageToG1V2(messageHash)
	return sk.SignG1(h)
}

// SignV6_1PreExecBLS12381 is the Cardano-parity signing helper. It computes
// sig = sk · HashMessageToG1V2BLS381(messageHash), where the hash-to-G1
// reduces the messageHash mod BLS12-381 Fr (NOT BN254 Fr). This matches the
// in-circuit MapToG1 of BLSSignatureCircuitV2BLS381, so the signature
// satisfies the pairing constraint the Cardano on-chain V2 verifier checks.
//
// Pairs with: e(sig, G2) == e(HashMessageToG1V2BLS381(messageHash), pk).
//
// Returns nil if sk is nil — callers MUST check.
func SignV6_1PreExecBLS12381(sk *bls.PrivateKey, messageHash [32]byte) *bls.Signature {
	if sk == nil {
		return nil
	}
	h := HashMessageToG1V2BLS381(messageHash)
	return sk.SignG1(h)
}
