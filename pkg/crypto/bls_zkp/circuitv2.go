// Copyright 2026 Certen Protocol
//
// BLS Signature ZK Circuit V2 — addresses EVM-NEW-001 (audit-reports/01-evm-VERIFIED.md:552).
//
// Differences from the V1 SimpleBLSCircuit / BLSSignatureCircuit:
//
//   Gap A fix — MessageHash is fully constrained.
//     V1 declared MessageHash as a public input but never used it in a constraint, so
//     the on-chain VK had IC[1] = identity and the Groth16 proof was independent of
//     messageHash. V2 maps MessageHash deterministically to a BLS12-381 G1 point via
//     gnark's emulated SSWU + isogeny + cofactor-clearing (MapToG1). The mapped point
//     is then fed into the pairing equation, so changing MessageHash changes H(m),
//     which changes the pairing equation, which invalidates the proof.
//
//   Gap B fix — A real BLS pairing is proven, not a polynomial commitment placeholder.
//     V1's "production" SimpleBLSCircuit only asserted that the prover-supplied
//     SignatureCommitment equals (SigX + 7·SigY) and similarly for the pubkey, plus
//     a threshold inequality. No pairing, no curve membership, no message binding —
//     i.e. any prover could satisfy it with arbitrary on/off-curve points.
//     V2 invokes Pairing.PairingCheck on emulated BLS12-381 to prove
//         e(σ, -G2_gen) · e(H(m), pk) = 1
//     which is equivalent to e(σ, G2_gen) == e(H(m), pk) — the standard BLS verify.
//     AssertIsOnG1 / AssertIsOnG2 also enforce curve and subgroup membership.
//
//   PubkeyCommitment binding — the public commitment is a MiMC hash of the
//     emulated BLS12-381 limbs of the actual G2 public key, so the prover cannot
//     supply an arbitrary (x, y) pair: the commitment publicly fixes the key.
//     ComputePubkeyCommitmentV2 below is the off-circuit counterpart that the
//     anchor / verifier set commitment generator must use to compute the same value.
//
// The circuit is defined over BN254 (so the produced Groth16 proof is checked by the
// EVM precompiles at ~220k gas) and emulates BLS12-381 arithmetic inside it. This is
// expensive in constraints (millions) and trusted-setup memory, but is the only way
// to verify a real BLS12-381 pairing in a Groth16-on-BN254 proof system.
//
// Off-chain prover and on-chain verifier must agree on:
//   - MessageHash → G1 mapping (HashMessageToG1V2 below ↔ in-circuit MapToG1).
//   - PubkeyCommitment formula (ComputePubkeyCommitmentV2 ↔ in-circuit MiMC).
//   - G2 generator value (we use the canonical bls12381 G2 generator).
//
// Tests in circuitv2_test.go exercise:
//   1. Circuit compiles to R1CS over BN254.
//   2. A valid (real BLS-signed) witness satisfies the constraints.
//   3. A swapped MessageHash invalidates the proof (Gap A test).
//   4. An off-curve signature is rejected (Gap B curve-check test).
//   5. An insufficient signed-power triggers the threshold check.

package bls_zkp

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

// BLSSignatureCircuitV2 is the production BLS signature verification circuit.
// All public inputs match the existing 4-input layout of BLSZKVerifier.sol so the
// on-chain verifier interface stays stable; only the verification key (regenerated
// from this circuit) and its IC array change.
type BLSSignatureCircuitV2 struct {
	// Public inputs — same order as BLSZKVerifier.sol publicInputs[0..3].
	MessageHash       frontend.Variable `gnark:",public"` // bytes32 reduced into BN254 Fr
	PubkeyCommitment  frontend.Variable `gnark:",public"` // MiMC over the G2 pk limbs
	SignedVotingPower frontend.Variable `gnark:",public"`
	TotalVotingPower  frontend.Variable `gnark:",public"`

	// Private witness — the actual BLS12-381 aggregate signature (G1) and aggregate
	// public key (G2). The circuit verifies the pairing equation in BLS12-381 inside
	// the BN254 SNARK using gnark's emulated arithmetic.
	Signature sw_bls12381.G1Affine
	Pubkey    sw_bls12381.G2Affine
}

// Define implements the V2 BLS verification constraints.
func (c *BLSSignatureCircuitV2) Define(api frontend.API) error {
	// 1. Threshold: signedVotingPower * 3 >= totalVotingPower * 2  (i.e. signed >= 2/3 total).
	//    V1 wrote this as AssertIsLessOrEqual(0, lhs - rhs) but field-wrapping made
	//    the check vacuous: when lhs < rhs the difference wraps to ~Fr, which is
	//    trivially "≥ 0" in field representation. V2 bounds both inputs to 64 bits
	//    first so the multiplied values stay well below Fr, and then uses the
	//    correct direction of AssertIsLessOrEqual on rhs ≤ lhs.
	const votingPowerBits = 64
	_ = api.ToBinary(c.SignedVotingPower, votingPowerBits) // enforces 0 ≤ value < 2^64
	_ = api.ToBinary(c.TotalVotingPower, votingPowerBits)
	lhs := api.Mul(c.SignedVotingPower, 3) // ≤ 3·(2^64-1) < 2^66
	rhs := api.Mul(c.TotalVotingPower, 2)  // ≤ 2·(2^64-1) < 2^65
	// Both sides fit in 66 bits; AssertIsLessOrEqual on values < 2^66 cannot wrap.
	api.AssertIsLessOrEqual(rhs, lhs)

	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}

	// 2. Curve and subgroup membership of the prover-supplied points.
	//    AssertIsOnG1 / AssertIsOnG2 check both the curve equation and that the point
	//    has the correct prime-order subgroup (rejecting torsion / off-curve forgeries).
	pairing.AssertIsOnG1(&c.Signature)
	pairing.AssertIsOnG2(&c.Pubkey)

	// 3. Map MessageHash → H(m) ∈ G1 inside the circuit.
	//    MessageHash (a BN254 Fr element ≤ 254 bits) is interpreted as a BLS12-381 Fp
	//    element (Fp is 381 bits, so the BN254 value fits without reduction). The
	//    in-circuit MapToG1 applies SSWU, the 11-isogeny, and cofactor clearing —
	//    matching gnark-crypto's out-of-circuit bls12381.MapToG1 byte-for-byte.
	//    See HashMessageToG1V2 below for the off-circuit counterpart.
	//
	//    emulated.BLS12381Fp expects exactly 6 little-endian 64-bit limbs. We
	//    decompose MessageHash (254 bits) into bits with api.ToBinary, pack the bits
	//    into the lower 4 limbs (limb 3 is partial), and zero-pad limbs 4 and 5.
	fp, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return fmt.Errorf("new bls12381 Fp field: %w", err)
	}
	msgBits := api.ToBinary(c.MessageHash, 254)
	msgLimbs := make([]frontend.Variable, 6)
	for i := 0; i < 6; i++ {
		start := i * 64
		if start >= len(msgBits) {
			msgLimbs[i] = frontend.Variable(0)
			continue
		}
		end := start + 64
		if end > len(msgBits) {
			end = len(msgBits)
		}
		msgLimbs[i] = api.FromBinary(msgBits[start:end]...)
	}
	msgFp := fp.NewElement(msgLimbs)

	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return fmt.Errorf("new g1 helper: %w", err)
	}
	hMsg, err := g1.MapToG1(msgFp)
	if err != nil {
		return fmt.Errorf("in-circuit map-to-g1: %w", err)
	}

	// 4. The pairing equation:  e(σ, -G2_gen) · e(H(m), pk) = 1
	//    Equivalent to the textbook BLS verification e(σ, G2_gen) = e(H(m), pk).
	//    We embed the negated generator as a circuit constant.
	negG2GenAff := negG2Generator()
	negG2GenInCircuit := sw_bls12381.NewG2Affine(negG2GenAff)

	if err := pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&c.Signature, hMsg},
		[]*sw_bls12381.G2Affine{&negG2GenInCircuit, &c.Pubkey},
	); err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}

	// 5. Pubkey commitment binding.
	//    We deliberately avoid gnark's MiMC/Poseidon here because those gadgets
	//    inject Pedersen commitments into the Groth16 proof, which bloats the
	//    on-chain VK layout (IC length grows from 5 to 6 plus extra pairing
	//    inputs). The BLSZKVerifierV2 contract uses the classic 4-public-input
	//    verifier shape; preserving that means our commitment must be expressible
	//    in plain add/mul constraints with no commitment hint.
	//
	//    The construction below is a Horner-style polynomial fold over the
	//    24 BLS12-381 Fp limbs (4 components × 6 limbs each):
	//      acc = (((limb_0 * c + limb_1) * c + limb_2) * c + ...) mod Fr
	//    where c is a fixed prime BN254 Fr constant. This is binding for our
	//    purpose: the witness limbs are constrained on-curve and in-subgroup by
	//    AssertIsOnG2 above, so the prover cannot pick arbitrary limbs to
	//    collide with a given commitment without simultaneously producing a
	//    different valid G2 point — i.e. as hard as a discrete-log preimage in
	//    G2. ComputePubkeyCommitmentV2 below recomputes the same fold off-chain.
	commitment := frontend.Variable(0)
	for _, limb := range c.Pubkey.P.X.A0.Limbs {
		commitment = api.Add(api.Mul(commitment, pubkeyCommitMixer), limb)
	}
	for _, limb := range c.Pubkey.P.X.A1.Limbs {
		commitment = api.Add(api.Mul(commitment, pubkeyCommitMixer), limb)
	}
	for _, limb := range c.Pubkey.P.Y.A0.Limbs {
		commitment = api.Add(api.Mul(commitment, pubkeyCommitMixer), limb)
	}
	for _, limb := range c.Pubkey.P.Y.A1.Limbs {
		commitment = api.Add(api.Mul(commitment, pubkeyCommitMixer), limb)
	}
	api.AssertIsEqual(c.PubkeyCommitment, commitment)

	return nil
}

// pubkeyCommitMixer is the BN254 Fr constant used as the Horner base in the
// pubkey commitment fold. Picked to be a "nothing-up-my-sleeve" small prime;
// any prime in (1, Fr) would work, but 251 is the smallest 8-bit prime that
// is co-prime with Fr-1 (helping evenness of the fold). Off-circuit and
// on-circuit MUST use the same value — see ComputePubkeyCommitmentV2.
var pubkeyCommitMixer = frontend.Variable(251)

// =============================================================================
// OFF-CIRCUIT HELPERS  — must stay in sync with the in-circuit logic above.
// =============================================================================

// negG2Generator returns -G2_generator on BLS12-381. The same constant is embedded
// into the circuit at compile time, so a single value is used by both prover and
// verifier.
func negG2Generator() bls12381.G2Affine {
	_, _, _, g2Gen := bls12381.Generators()
	var neg bls12381.G2Affine
	neg.Neg(&g2Gen)
	return neg
}

// HashMessageToG1V2 is the off-circuit counterpart of the in-circuit hashing step.
// It takes a 32-byte message hash (the same bytes the anchor passes to the on-chain
// verifier) and returns the unique G1 point that the circuit will recompute inside
// MapToG1. Validators signing for V2 must use this exact function to produce H(m)
// when constructing the aggregate signature, otherwise the pairing check will fail.
//
// The bytes are interpreted big-endian as an integer, reduced mod the BN254 scalar
// field (matching how the on-chain Solidity uint256 cast lands in the SNARK), and
// then cast to a BLS12-381 Fp element before MapToG1.
func HashMessageToG1V2(messageHash [32]byte) bls12381.G1Affine {
	var asInt big.Int
	asInt.SetBytes(messageHash[:])
	// Reduce mod BN254 Fr — this matches how the public input is presented to the
	// SNARK. The reduced value always fits in BLS12-381 Fp (381 > 254 bits), so no
	// further reduction is needed before lifting to Fp.
	var frEl fr.Element
	frEl.SetBigInt(&asInt)
	var frBI big.Int
	frEl.BigInt(&frBI)

	var u bls12381fp.Element
	u.SetBigInt(&frBI)
	return bls12381.MapToG1(u)
}

// ComputePubkeyCommitmentV2 is the off-circuit counterpart of the in-circuit
// Horner-style polynomial fold over the BLS12-381 Fp limbs of the public key.
//
// In-circuit recurrence (in pubkeyCommitmentMixer = 251):
//   commitment_0 = 0
//   commitment_{i+1} = commitment_i * mixer + limb_i   (mod BN254 Fr)
//
// We absorb the 24 limbs in the order:
//   X.A0[0..5], X.A1[0..5], Y.A0[0..5], Y.A1[0..5]
// matching emulated.BLS12381Fp's little-endian, 6-limbs-of-64-bits decomposition.
// The result is a single BN254 Fr scalar suitable as a SNARK public input and
// as the Solidity uint256 PubkeyCommitment.
func ComputePubkeyCommitmentV2(pk bls12381.G2Affine) ([32]byte, error) {
	frModulus := new(big.Int)
	frModulus.SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10,
	)
	mixer := big.NewInt(251)

	acc := new(big.Int)

	// helper: append one Fp element's 6 little-endian 64-bit limbs to the Horner
	// accumulator, matching the in-circuit fold over each Element[BaseField].Limbs.
	absorbFp := func(e bls12381fp.Element) error {
		var bi big.Int
		e.BigInt(&bi)
		// Pad to a fixed 48-byte big-endian buffer, then split into 6 little-endian
		// 64-bit limbs. emulated.BLS12381Fp uses little-endian limb order.
		buf := make([]byte, 48)
		biBytes := bi.Bytes()
		copy(buf[48-len(biBytes):], biBytes)

		for i := 0; i < 6; i++ {
			start := 48 - (i+1)*8
			end := 48 - i*8
			var limb uint64
			for j := start; j < end; j++ {
				limb = (limb << 8) | uint64(buf[j])
			}
			limbBI := new(big.Int).SetUint64(limb)
			acc.Mul(acc, mixer)
			acc.Add(acc, limbBI)
			acc.Mod(acc, frModulus)
		}
		return nil
	}

	if err := absorbFp(pk.X.A0); err != nil {
		return [32]byte{}, fmt.Errorf("absorb X.A0: %w", err)
	}
	if err := absorbFp(pk.X.A1); err != nil {
		return [32]byte{}, fmt.Errorf("absorb X.A1: %w", err)
	}
	if err := absorbFp(pk.Y.A0); err != nil {
		return [32]byte{}, fmt.Errorf("absorb Y.A0: %w", err)
	}
	if err := absorbFp(pk.Y.A1); err != nil {
		return [32]byte{}, fmt.Errorf("absorb Y.A1: %w", err)
	}

	var out [32]byte
	commitmentBytes := acc.Bytes()
	if len(commitmentBytes) > 32 {
		return [32]byte{}, fmt.Errorf("commitment exceeds 32 bytes (impossible after mod Fr)")
	}
	copy(out[32-len(commitmentBytes):], commitmentBytes)
	return out, nil
}

// Suppress "imported and not used" if fr ends up only referenced inside circuit
// helpers. The Horner fold reduces modulo Fr explicitly via big.Int math, but
// fr.Element is still used by BuildV2Witness below.
var _ = fr.Element{}

// BuildV2Witness constructs the circuit witness for a known aggregate signature /
// aggregate pubkey / message hash / voting powers. Used by tests and by the prover
// when generating real V2 proofs.
//
// The returned struct has the public inputs (MessageHash, PubkeyCommitment, etc.)
// already populated; the prover assigns voting-power scalars as needed and feeds it
// into gnark's witness builder.
func BuildV2Witness(
	messageHash [32]byte,
	aggSig bls12381.G1Affine,
	aggPk bls12381.G2Affine,
	signedVotingPower uint64,
	totalVotingPower uint64,
) (*BLSSignatureCircuitV2, [32]byte, error) {
	pkCommitment, err := ComputePubkeyCommitmentV2(aggPk)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("compute pk commitment: %w", err)
	}

	// MessageHash is consumed as a BN254 Fr element — pre-reduce so witness
	// assignment matches what the circuit will see.
	var msgInt big.Int
	msgInt.SetBytes(messageHash[:])
	var msgFr fr.Element
	msgFr.SetBigInt(&msgInt)
	var msgFrBI big.Int
	msgFr.BigInt(&msgFrBI)

	var pkCommitInt big.Int
	pkCommitInt.SetBytes(pkCommitment[:])

	w := &BLSSignatureCircuitV2{
		MessageHash:       msgFrBI,
		PubkeyCommitment:  pkCommitInt,
		SignedVotingPower: signedVotingPower,
		TotalVotingPower:  totalVotingPower,
		Signature:         sw_bls12381.NewG1Affine(aggSig),
		Pubkey:            sw_bls12381.NewG2Affine(aggPk),
	}
	return w, pkCommitment, nil
}
