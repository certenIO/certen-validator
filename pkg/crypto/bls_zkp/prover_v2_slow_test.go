//go:build slow_bls_zkp_v2

// Slow round-trip tests for the V2 prover. These exercise the full
// Initialize → GenerateProof → VerifyProofLocally chain plus the ABI
// serialization round-trip. Each test runs groth16.Setup + Prove on the
// ~775k-constraint V2 circuit and is therefore slow (several minutes per
// test). Run with:
//
//   go test -tags slow_bls_zkp_v2 ./pkg/crypto/bls_zkp/ \
//       -run TestProverV2_ -v -timeout 30m
//
// Plan reference: audit-reports/EVM-NEW-001-EVM-003-EVM-004-completion-plan.md §4.

package bls_zkp

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// proverV2Singleton holds a single Setup output shared across the slow tests
// so we don't pay the multi-minute Setup cost per test. Test order is not
// guaranteed in Go, so each test that needs it calls getProverV2().
var proverV2Singleton *BLSZKProver

// proverV2WitnessSingleton is a known-good V2 witness (built from a real
// BLS12-381 signature) that the prover can sign deterministically. Shared
// across tests for the same reason.
var proverV2WitnessSingleton *BLSSignatureWitness

func getProverV2(t *testing.T) (*BLSZKProver, *BLSSignatureWitness) {
	t.Helper()
	if proverV2Singleton != nil && proverV2WitnessSingleton != nil {
		return proverV2Singleton, proverV2WitnessSingleton
	}

	t.Log("[V2-prover] Initialize() — this triggers Compile + Setup (slow)")
	p := NewBLSZKProver()
	if err := p.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Build a real BLS12-381 signature so Prove succeeds against the V2
	// pairing constraints. The constants here mirror the TestV2_Groth16Roundtrip
	// setup in circuitv2_roundtrip_test.go so future maintenance is symmetric.
	testSK := new(big.Int)
	testSK.SetString("1357913579246802468013579246802468013579246802468013579246802468013", 10)
	testSK.Mod(testSK, bls12381.ID.ScalarField())
	if testSK.Sign() == 0 {
		testSK.SetUint64(42)
	}

	var msgHash [32]byte
	for i := range msgHash {
		msgHash[i] = byte((i * 17) & 0xFF)
	}
	msgHash[0] &= 0x3f // ensure < BN254 Fr

	hm := HashMessageToG1V2(msgHash)
	var sig bls12381.G1Affine
	sig.ScalarMultiplication(&hm, testSK)

	_, _, _, g2Gen := bls12381.Generators()
	var pkG2 bls12381.G2Affine
	pkG2.ScalarMultiplication(&g2Gen, testSK)

	// Marshal signature + pubkey to compressed bytes so CreateWitnessFromBLSData
	// can drive the production decode path (same the validator runs at runtime).
	sigBytes := sig.Bytes()
	pkBytes := pkG2.Bytes()
	witness, err := CreateWitnessFromBLSData(msgHash, sigBytes[:], pkBytes[:], 7, 10)
	if err != nil {
		t.Fatalf("CreateWitnessFromBLSData: %v", err)
	}

	proverV2Singleton = p
	proverV2WitnessSingleton = witness
	return p, witness
}

func TestProverV2_GenerateProof_PopulatesPedersenCommitments(t *testing.T) {
	p, witness := getProverV2(t)

	zkProof, err := p.GenerateProof(witness)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	// Phase 2.1 assertion: extractProofComponents stored the Pedersen
	// commitment + PoK into the BLSZKProof struct.
	if !hasV2Commitments(zkProof) {
		t.Fatalf("V2 proof should carry non-zero Commitments; got %v", zkProof.Commitments)
	}
	if zkProof.CommitmentPok[0] == nil || zkProof.CommitmentPok[1] == nil {
		t.Fatalf("CommitmentPok must be populated")
	}
	if zkProof.CommitmentPok[0].Sign() == 0 && zkProof.CommitmentPok[1].Sign() == 0 {
		t.Fatalf("CommitmentPok should be non-zero on a real V2 proof")
	}
}

func TestProverV2_VerifyProofLocally_AcceptsValidProof(t *testing.T) {
	p, witness := getProverV2(t)

	zkProof, err := p.GenerateProof(witness)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	ok, err := p.VerifyProofLocally(zkProof)
	if err != nil {
		t.Fatalf("VerifyProofLocally error: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyProofLocally returned false on a freshly-generated valid proof")
	}
}

func TestProverV2_VerifyProofLocally_RejectsTamperedProof(t *testing.T) {
	p, witness := getProverV2(t)

	zkProof, err := p.GenerateProof(witness)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	// Flip a single bit in ProofA[0]. The reconstructed point will either
	// fail curve membership or fail the pairing check; either way Verify
	// must return false.
	tampered := *zkProof
	a0 := new(big.Int).Set(zkProof.ProofA[0])
	a0.Xor(a0, big.NewInt(1))
	tampered.ProofA = [2]*big.Int{a0, zkProof.ProofA[1]}

	ok, _ := p.VerifyProofLocally(&tampered)
	if ok {
		t.Fatalf("VerifyProofLocally accepted a tampered proof")
	}
}

func TestProverV2_ABIRoundTrip_VerifyFromABIBytes(t *testing.T) {
	p, witness := getProverV2(t)

	zkProof, err := p.GenerateProof(witness)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	abiBytes, err := zkProof.ToSolidityCalldata()
	if err != nil {
		t.Fatalf("ToSolidityCalldata: %v", err)
	}
	if len(abiBytes) != v2ABIByteSize {
		t.Fatalf("V2 calldata size = %d, want %d", len(abiBytes), v2ABIByteSize)
	}

	// VerifyFromABIBytes decodes the wire bytes, reconstructs the gnark
	// proof, and runs groth16.Verify with WithVerifierHashToFieldFunction.
	// This is the diagnostic that catches serialization bugs before the
	// bytes are submitted on-chain.
	ok, err := p.VerifyFromABIBytes(abiBytes)
	if err != nil {
		t.Fatalf("VerifyFromABIBytes error: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyFromABIBytes returned false on freshly-encoded valid proof")
	}
}

func TestProverV2_ABIRoundTrip_RejectsFlippedByte(t *testing.T) {
	p, witness := getProverV2(t)

	zkProof, err := p.GenerateProof(witness)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	abiBytes, err := zkProof.ToSolidityCalldata()
	if err != nil {
		t.Fatalf("ToSolidityCalldata: %v", err)
	}

	tampered := bytes.Clone(abiBytes)
	tampered[v2OffMessageHash] ^= 0xff // flip a byte inside messageHash

	ok, _ := p.VerifyFromABIBytes(tampered)
	if ok {
		t.Fatalf("VerifyFromABIBytes accepted a proof with a flipped messageHash byte")
	}
}
