//go:build slow_bls_zkp_v2

// Slow integration tests for BLSSignatureCircuitV2. Run with:
//
//   go test -tags slow_bls_zkp_v2 ./pkg/crypto/bls_zkp/ -run TestV2 -v -timeout 60m
//
// These tests use test.IsSolved which evaluates the entire constraint system
// against a real witness. On the emulated BLS12-381 pairing circuit this is
// expected to take several minutes per case, so the build tag keeps them out of
// the default test run.

package bls_zkp

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/test"
)

// TestV2_ValidWitnessIsAccepted is the positive case: an honestly-generated BLS
// signature plus matching pubkey commitment must satisfy the V2 constraints.
func TestV2_ValidWitnessIsAccepted(t *testing.T) {
	var msg [32]byte
	if _, err := rand.Read(msg[:]); err != nil {
		t.Fatalf("rand.Read msg: %v", err)
	}
	// Keep the bytes inside BN254 Fr by clearing the top two bits — matches what
	// the on-chain Solidity does when it casts bytes32 → uint256 → Fr.
	msg[0] &= 0x3f

	sig, pk, _ := signBLS(t, msg)
	witness, _, err := BuildV2Witness(msg, sig, pk, 7, 10) // 7/10 > 2/3
	if err != nil {
		t.Fatalf("BuildV2Witness: %v", err)
	}

	if err := test.IsSolved(&BLSSignatureCircuitV2{}, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("test.IsSolved on valid witness: %v", err)
	}
}

// TestV2_WrongMessageHashIsRejected demonstrates Gap A is fixed: a proof generated
// for one message must NOT satisfy the circuit when the public MessageHash is
// changed afterwards. With V1, this test would pass (which is the vulnerability).
func TestV2_WrongMessageHashIsRejected(t *testing.T) {
	var msgSigned, msgAttacker [32]byte
	if _, err := rand.Read(msgSigned[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if _, err := rand.Read(msgAttacker[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	msgSigned[0] &= 0x3f
	msgAttacker[0] &= 0x3f

	sig, pk, _ := signBLS(t, msgSigned)
	witness, _, err := BuildV2Witness(msgAttacker, sig, pk, 7, 10)
	if err != nil {
		t.Fatalf("BuildV2Witness: %v", err)
	}

	if err := test.IsSolved(&BLSSignatureCircuitV2{}, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatalf("Gap A regression: circuit accepted a witness where MessageHash != message signed")
	}
}

// TestV2_BelowThresholdIsRejected confirms the threshold guard still works.
func TestV2_BelowThresholdIsRejected(t *testing.T) {
	var msg [32]byte
	if _, err := rand.Read(msg[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	msg[0] &= 0x3f

	sig, pk, _ := signBLS(t, msg)
	witness, _, err := BuildV2Witness(msg, sig, pk, 1, 10) // 1/10 << 2/3
	if err != nil {
		t.Fatalf("BuildV2Witness: %v", err)
	}

	if err := test.IsSolved(&BLSSignatureCircuitV2{}, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatalf("threshold check regression: circuit accepted signed=1, total=10")
	}
}

// TestV2_WrongPubkeyCommitmentIsRejected forces the PubkeyCommitment public input
// off the actual pubkey's MiMC hash. The circuit must catch this — otherwise the
// validator-set binding doesn't actually bind.
func TestV2_WrongPubkeyCommitmentIsRejected(t *testing.T) {
	var msg [32]byte
	if _, err := rand.Read(msg[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	msg[0] &= 0x3f

	sig, pk, _ := signBLS(t, msg)
	witness, _, err := BuildV2Witness(msg, sig, pk, 7, 10)
	if err != nil {
		t.Fatalf("BuildV2Witness: %v", err)
	}
	// Replace the commitment with a random other Fr element.
	bogus, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	witness.PubkeyCommitment = bogus

	if err := test.IsSolved(&BLSSignatureCircuitV2{}, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatalf("pubkey-commitment binding regression: circuit accepted mismatched commitment")
	}
}

// Compile-time interface checks — ensure helpers stay importable from outside.
var (
	_ bls12381.G1Affine // make sure the import lands in a coverage-counted file
	_ = big.NewInt
)
