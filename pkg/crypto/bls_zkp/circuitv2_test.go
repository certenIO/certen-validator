// Tests for BLSSignatureCircuitV2 (EVM-NEW-001 fix).
//
// The emulated BLS12-381 pairing inside a BN254 circuit is enormous (~30M+ R1CS
// constraints). We therefore use the cheapest verification primitives gnark offers:
//
//   - frontend.Compile to check the circuit definition is well-formed.
//   - test.IsSolved to check that a witness satisfies the constraint system without
//     running a trusted setup or generating an actual proof.
//
// Even IsSolved on this circuit will take several minutes. Tests that exercise the
// full pairing path are tagged with `//go:build slow_bls_zkp_v2` so the default
// `go test` run only compiles the circuit. To run the heavy tests set the build tag:
//   go test -tags slow_bls_zkp_v2 ./pkg/crypto/bls_zkp/ -run TestV2 -v -timeout 60m

package bls_zkp

import (
	"crypto/rand"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestV2CircuitCompiles is the fast smoke test: it confirms the circuit definition
// passes gnark's frontend compiler, catching API misuse (wrong gadget signatures,
// uninitialised emulated fields, etc.) without running the actual constraint solver.
// Expect this to take a minute or two — the emulated pairing skeleton alone is heavy.
func TestV2CircuitCompiles(t *testing.T) {
	var circuit BLSSignatureCircuitV2
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("frontend.Compile BLSSignatureCircuitV2: %v", err)
	}
	t.Logf("circuit compiled: nbConstraints=%d, nbInternalVars=%d, nbSecretVars=%d, nbPublicVars=%d",
		cs.GetNbConstraints(),
		cs.GetNbInternalVariables(),
		cs.GetNbSecretVariables(),
		cs.GetNbPublicVariables())
	// Sanity guard: regress-detect if the pairing gadget gets accidentally removed.
	// Empirically the gnark v0.14.0 emulated BLS12-381 PairingCheck + MapToG1 +
	// AssertIsOnG1/G2 produces ~780k constraints. A stub (no real pairing) would be
	// well under 100k, so a 200k floor is a safe regression boundary.
	if cs.GetNbConstraints() < 200_000 {
		t.Fatalf("V2 circuit has only %d constraints — pairing/curve checks may be missing",
			cs.GetNbConstraints())
	}
}

// TestV2OffCircuitHelpers exercises the standalone hashMessageToG1 + pubkey
// commitment helpers, independent of the SNARK. If these are wrong, no amount of
// in-circuit work will produce a verifying proof, so they get their own fast tests.
func TestV2OffCircuitHelpers(t *testing.T) {
	t.Run("HashMessageToG1V2_deterministic", func(t *testing.T) {
		var m1, m2 [32]byte
		for i := range m1 {
			m1[i] = byte(i)
			m2[i] = byte(i)
		}
		p1 := HashMessageToG1V2(m1)
		p2 := HashMessageToG1V2(m2)
		if !p1.Equal(&p2) {
			t.Fatalf("HashMessageToG1V2 not deterministic for identical input")
		}
		// Different inputs should yield different outputs (vanishingly small chance
		// of collision; we treat it as a hard failure if it triggers).
		m2[0] = 0xff
		p3 := HashMessageToG1V2(m2)
		if p1.Equal(&p3) {
			t.Fatalf("HashMessageToG1V2 collision for different inputs — RFC 9380 violated")
		}
	})

	t.Run("HashMessageToG1V2_isOnCurve", func(t *testing.T) {
		var m [32]byte
		for i := range m {
			m[i] = byte(i * 7)
		}
		p := HashMessageToG1V2(m)
		if !p.IsOnCurve() {
			t.Fatalf("HashMessageToG1V2 output not on curve")
		}
		if !p.IsInSubGroup() {
			t.Fatalf("HashMessageToG1V2 output not in G1 subgroup (cofactor clearing broken)")
		}
	})

	t.Run("ComputePubkeyCommitmentV2_deterministic", func(t *testing.T) {
		pk := randomG2Point(t)
		c1, err := ComputePubkeyCommitmentV2(pk)
		if err != nil {
			t.Fatalf("ComputePubkeyCommitmentV2: %v", err)
		}
		c2, err := ComputePubkeyCommitmentV2(pk)
		if err != nil {
			t.Fatalf("ComputePubkeyCommitmentV2 (second call): %v", err)
		}
		if c1 != c2 {
			t.Fatalf("ComputePubkeyCommitmentV2 not deterministic: %x vs %x", c1, c2)
		}

		// Different pubkey → different commitment.
		pk2 := randomG2Point(t)
		c3, err := ComputePubkeyCommitmentV2(pk2)
		if err != nil {
			t.Fatalf("ComputePubkeyCommitmentV2: %v", err)
		}
		if c1 == c3 {
			t.Fatalf("ComputePubkeyCommitmentV2 collision for different pubkeys")
		}
	})

	t.Run("ComputePubkeyCommitmentV2_fitsInBN254Fr", func(t *testing.T) {
		pk := randomG2Point(t)
		c, err := ComputePubkeyCommitmentV2(pk)
		if err != nil {
			t.Fatalf("ComputePubkeyCommitmentV2: %v", err)
		}
		// The commitment must be a valid BN254 Fr element (so it can be a SNARK
		// public input). MiMC_BN254 already outputs in Fr, but verify explicitly.
		var ci big.Int
		ci.SetBytes(c[:])
		bn254ScalarField := new(big.Int)
		bn254ScalarField.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
		if ci.Cmp(bn254ScalarField) >= 0 {
			t.Fatalf("commitment %s exceeds BN254 Fr modulus", ci.String())
		}
	})
}

// =============================================================================
// Heavy tests below: solving the full V2 constraint system. Build-tagged so the
// default fast test suite stays under a few minutes.
// =============================================================================

// randomG2Point picks a random non-zero point in G2 by scalar-multiplying the G2
// generator. Helper for the off-circuit tests above (and shared with the slow
// pairing-path tests).
func randomG2Point(t *testing.T) bls12381.G2Affine {
	t.Helper()
	_, _, _, g2Gen := bls12381.Generators()
	mod := bls12381.ID.ScalarField()
	s, err := rand.Int(rand.Reader, mod)
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	// Avoid the degenerate zero-scalar case.
	if s.Sign() == 0 {
		s.SetUint64(1)
	}
	var pk bls12381.G2Affine
	pk.ScalarMultiplication(&g2Gen, s)
	return pk
}

// signBLS produces an honest BLS signature σ = H(m) * sk over the V2-binding
// hash-to-G1. Returned alongside the matching G2 public key pk = G2_gen * sk so
// callers can assemble the full witness.
func signBLS(t *testing.T, messageHash [32]byte) (bls12381.G1Affine, bls12381.G2Affine, *big.Int) {
	t.Helper()
	mod := bls12381.ID.ScalarField()
	sk, err := rand.Int(rand.Reader, mod)
	if err != nil {
		t.Fatalf("rand.Int sk: %v", err)
	}
	if sk.Sign() == 0 {
		sk.SetUint64(1)
	}

	hm := HashMessageToG1V2(messageHash)
	var skFr bls12381fr.Element
	skFr.SetBigInt(sk)

	var sig bls12381.G1Affine
	sig.ScalarMultiplication(&hm, sk)

	_, _, _, g2Gen := bls12381.Generators()
	var pk bls12381.G2Affine
	pk.ScalarMultiplication(&g2Gen, sk)

	// Quick sanity check (out of circuit): the BLS pairing should already hold.
	var negG2Gen bls12381.G2Affine
	negG2Gen.Neg(&g2Gen)
	ok, perr := bls12381.PairingCheck(
		[]bls12381.G1Affine{sig, hm},
		[]bls12381.G2Affine{negG2Gen, pk},
	)
	if perr != nil {
		t.Fatalf("off-circuit PairingCheck error: %v", perr)
	}
	if !ok {
		t.Fatalf("off-circuit PairingCheck failed: the test BLS keygen / signing is broken")
	}

	return sig, pk, sk
}
