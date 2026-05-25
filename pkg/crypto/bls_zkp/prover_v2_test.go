// Fast tests for the V2 prover changes in prover.go.
//
// "Fast" means no groth16.Setup (which takes several minutes on the emulated
// BLS12-381 pairing circuit). These tests cover the V2 plumbing that does NOT
// require a real proving key:
//   - BLSZKProof V2 fields exist and zero-default correctly
//   - hasV2Commitments classifier returns the right verdict
//   - reconstructProof passes commitments through when present, skips when absent
//   - ToSolidityCalldata produces the V2 wire size and round-trip-decodes
//     to the same field values via VerifyFromABIBytes' decoder shape
//
// The slow tests (full Setup + Prove + Verify) live in prover_v2_slow_test.go
// behind the slow_bls_zkp_v2 build tag.
//
// Plan reference: audit-reports/EVM-NEW-001-EVM-003-EVM-004-completion-plan.md §4.

package bls_zkp

import (
	"bytes"
	"math/big"
	"testing"

	bn254_curve "github.com/consensys/gnark-crypto/ecc/bn254"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

func TestBLSZKProof_V2FieldsZeroByDefault(t *testing.T) {
	var p BLSZKProof
	if p.Commitments[0] != nil || p.Commitments[1] != nil {
		t.Fatalf("Commitments default should be nil pointers, got %v", p.Commitments)
	}
	if p.CommitmentPok[0] != nil || p.CommitmentPok[1] != nil {
		t.Fatalf("CommitmentPok default should be nil pointers, got %v", p.CommitmentPok)
	}
}

func TestHasV2Commitments_Classifier(t *testing.T) {
	tests := []struct {
		name string
		c    [2]*big.Int
		want bool
	}{
		{"both nil", [2]*big.Int{nil, nil}, false},
		{"both zero", [2]*big.Int{big.NewInt(0), big.NewInt(0)}, false},
		{"x non-zero", [2]*big.Int{big.NewInt(1), big.NewInt(0)}, true},
		{"y non-zero", [2]*big.Int{big.NewInt(0), big.NewInt(2)}, true},
		{"both non-zero", [2]*big.Int{big.NewInt(7), big.NewInt(11)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &BLSZKProof{Commitments: tt.c}
			if got := hasV2Commitments(p); got != tt.want {
				t.Fatalf("hasV2Commitments(%v) = %v, want %v", tt.c, got, tt.want)
			}
		})
	}
}

func TestReconstructProof_OmitsCommitmentsWhenAbsent(t *testing.T) {
	// V1-shape zkProof (no commitments) → reconstructed proof must have
	// empty Commitments slice (gnark accepts this as "no BSB22 used").
	zk := newDummyV1Proof()
	proof, err := reconstructProof(zk)
	if err != nil {
		t.Fatalf("reconstructProof: %v", err)
	}
	bn254Proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		t.Fatalf("not a bn254 proof: %T", proof)
	}
	if len(bn254Proof.Commitments) != 0 {
		t.Fatalf("expected no commitments, got %d", len(bn254Proof.Commitments))
	}
}

func TestReconstructProof_RestoresCommitmentsWhenPresent(t *testing.T) {
	zk := newDummyV1Proof()
	zk.Commitments = [2]*big.Int{big.NewInt(123), big.NewInt(456)}
	zk.CommitmentPok = [2]*big.Int{big.NewInt(789), big.NewInt(987)}

	proof, err := reconstructProof(zk)
	if err != nil {
		t.Fatalf("reconstructProof: %v", err)
	}
	bn254Proof, ok := proof.(*groth16_bn254.Proof)
	if !ok {
		t.Fatalf("not a bn254 proof: %T", proof)
	}
	if len(bn254Proof.Commitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d", len(bn254Proof.Commitments))
	}
	var cx, cy big.Int
	bn254Proof.Commitments[0].X.BigInt(&cx)
	bn254Proof.Commitments[0].Y.BigInt(&cy)
	if cx.Cmp(big.NewInt(123)) != 0 || cy.Cmp(big.NewInt(456)) != 0 {
		t.Fatalf("commitment coords lost: x=%s y=%s", cx.String(), cy.String())
	}
	var px, py big.Int
	bn254Proof.CommitmentPok.X.BigInt(&px)
	bn254Proof.CommitmentPok.Y.BigInt(&py)
	if px.Cmp(big.NewInt(789)) != 0 || py.Cmp(big.NewInt(987)) != 0 {
		t.Fatalf("commitmentPok coords lost: x=%s y=%s", px.String(), py.String())
	}
}

func TestToSolidityCalldata_V2WireSize(t *testing.T) {
	// V2 BLSSignatureProof is 18 × 32-byte slots = 576 bytes.
	zk := newDummyV2Proof()
	bytesOut, err := zk.ToSolidityCalldata()
	if err != nil {
		t.Fatalf("ToSolidityCalldata: %v", err)
	}
	if got := len(bytesOut); got != v2ABIByteSize {
		t.Fatalf("V2 calldata size = %d, want %d", got, v2ABIByteSize)
	}
}

func TestToSolidityCalldata_RoundTripFieldValues(t *testing.T) {
	// Pack with known values, then read back at the documented byte offsets
	// (matches the VerifyFromABIBytes reader). This is a Go-only sanity check
	// — no groth16.Verify yet. Asserts the ABI shape matches our offset map.
	zk := newDummyV2Proof()
	bytesOut, err := zk.ToSolidityCalldata()
	if err != nil {
		t.Fatalf("ToSolidityCalldata: %v", err)
	}
	if len(bytesOut) != v2ABIByteSize {
		t.Fatalf("size: %d != %d", len(bytesOut), v2ABIByteSize)
	}

	readBI := func(off int) *big.Int {
		return new(big.Int).SetBytes(bytesOut[off : off+32])
	}
	readB32 := func(off int) [32]byte {
		var out [32]byte
		copy(out[:], bytesOut[off:off+32])
		return out
	}

	checks := []struct {
		name string
		got  *big.Int
		want *big.Int
	}{
		{"proofA[0]", readBI(v2OffProofAX), zk.ProofA[0]},
		{"proofA[1]", readBI(v2OffProofAY), zk.ProofA[1]},
		{"proofB[0][0]", readBI(v2OffProofBX0), zk.ProofB[0][0]},
		{"proofB[0][1]", readBI(v2OffProofBX1), zk.ProofB[0][1]},
		{"proofB[1][0]", readBI(v2OffProofBY0), zk.ProofB[1][0]},
		{"proofB[1][1]", readBI(v2OffProofBY1), zk.ProofB[1][1]},
		{"proofC[0]", readBI(v2OffProofCX), zk.ProofC[0]},
		{"proofC[1]", readBI(v2OffProofCY), zk.ProofC[1]},
		{"commitments[0]", readBI(v2OffCommitmentX), zk.Commitments[0]},
		{"commitments[1]", readBI(v2OffCommitmentY), zk.Commitments[1]},
		{"commitmentPok[0]", readBI(v2OffCommitmentPokX), zk.CommitmentPok[0]},
		{"commitmentPok[1]", readBI(v2OffCommitmentPokY), zk.CommitmentPok[1]},
	}
	for _, c := range checks {
		if c.got.Cmp(c.want) != 0 {
			t.Errorf("%s: got %s, want %s", c.name, c.got, c.want)
		}
	}

	if got := readB32(v2OffMessageHash); got != zk.MessageHash {
		t.Errorf("messageHash mismatch: got %x, want %x", got, zk.MessageHash)
	}
	if got := readB32(v2OffPubkeyCommit); got != zk.PubkeyCommitment {
		t.Errorf("pubkeyCommitment mismatch: got %x, want %x", got, zk.PubkeyCommitment)
	}
	if got := readBI(v2OffSignedVP).Uint64(); got != zk.SignedVotingPower {
		t.Errorf("signedVotingPower: got %d, want %d", got, zk.SignedVotingPower)
	}
	if got := readBI(v2OffTotalVP).Uint64(); got != zk.TotalVotingPower {
		t.Errorf("totalVotingPower: got %d, want %d", got, zk.TotalVotingPower)
	}
}

func TestToSolidityCalldata_NilCoordsCoerceToZero(t *testing.T) {
	// nonNilBI defends Pack from nil dereferences when the proof was built
	// without V2 commitments (legacy path). Verify a V1-shape proof packs.
	zk := newDummyV1Proof() // V2 commitments left nil
	bytesOut, err := zk.ToSolidityCalldata()
	if err != nil {
		t.Fatalf("ToSolidityCalldata with nil V2 commitments: %v", err)
	}
	if len(bytesOut) != v2ABIByteSize {
		t.Fatalf("size: %d", len(bytesOut))
	}
	zeroSlot := make([]byte, 32)
	if !bytes.Equal(bytesOut[v2OffCommitmentX:v2OffCommitmentX+32], zeroSlot) {
		t.Errorf("nil commitments should pack as zero slot")
	}
}

func TestToSolidityCalldata_ZeroThresholdsDefaultTo23(t *testing.T) {
	// ThresholdNumerator / ThresholdDenominator zero in the struct → packed
	// as 2/3 (backward-compat with V1 callers that omit them).
	zk := newDummyV2Proof()
	zk.ThresholdNumerator = 0
	zk.ThresholdDenominator = 0
	bytesOut, err := zk.ToSolidityCalldata()
	if err != nil {
		t.Fatalf("ToSolidityCalldata: %v", err)
	}
	num := new(big.Int).SetBytes(bytesOut[v2OffThresholdNum : v2OffThresholdNum+32])
	denom := new(big.Int).SetBytes(bytesOut[v2OffThresholdDenom : v2OffThresholdDenom+32])
	if num.Uint64() != 2 || denom.Uint64() != 3 {
		t.Errorf("zero thresholds should default to 2/3, got %s/%s", num, denom)
	}
}

// =============================================================================
// Helpers for the fast tests
// =============================================================================

// newDummyV1Proof returns a BLSZKProof with non-zero A, B, C and public inputs
// but no V2 Pedersen fields. Used to validate the V1-compatibility paths.
func newDummyV1Proof() *BLSZKProof {
	return &BLSZKProof{
		ProofA: [2]*big.Int{big.NewInt(11), big.NewInt(12)},
		ProofB: [2][2]*big.Int{
			{big.NewInt(21), big.NewInt(22)},
			{big.NewInt(23), big.NewInt(24)},
		},
		ProofC:               [2]*big.Int{big.NewInt(31), big.NewInt(32)},
		MessageHash:          [32]byte{1, 2, 3},
		PubkeyCommitment:     [32]byte{4, 5, 6},
		SignedVotingPower:    7,
		TotalVotingPower:     10,
		ThresholdNumerator:   2,
		ThresholdDenominator: 3,
	}
}

// newDummyV2Proof extends V1 with non-zero Commitments / CommitmentPok.
func newDummyV2Proof() *BLSZKProof {
	p := newDummyV1Proof()
	p.Commitments = [2]*big.Int{big.NewInt(101), big.NewInt(102)}
	p.CommitmentPok = [2]*big.Int{big.NewInt(201), big.NewInt(202)}
	return p
}

// Compile-time check that bn254 imports resolve and the types are usable in
// helpers (referenced for documentation; not directly hit by the tests above).
var _ = (&bn254_curve.G1Affine{})
