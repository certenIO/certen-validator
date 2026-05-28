// BLS12-381 V2 circuit — the Cardano-parity analogue of BLSSignatureCircuitV2.
//
// Identical verification logic to the BN254 V2 circuit (real BLS pairing +
// in-circuit MapToG1 messageHash binding + pubkey-commitment fold), but
// compiled over the BLS12-381 scalar field so the resulting Groth16 proof is
// verifiable by Cardano's Plutus V3 bls12_381_* builtins.
//
// Why a separate struct instead of reusing BLSSignatureCircuitV2:
//   - MessageHash decomposition must be 255 bits here (BLS12-381 Fr is
//     ~2^254.86, so a reduced messageHash can exceed 2^254). The BN254
//     circuit uses 254 bits (BN254 Fr is ~2^253.6). Sharing the struct
//     would either truncate (BLS12-381) or overflow (BN254).
//   - The off-circuit pubkey-commitment fold + messageHash reduction must
//     use the BLS12-381 Fr modulus, not BN254's.
//
// Everything else — the emulated BLS12-381 pairing, MapToG1, subgroup
// checks, threshold check, Horner pubkey-commitment fold — is byte-for-byte
// the same as the BN254 V2 circuit. This is what gives Cardano FULL parity
// with EVM/NEAR: the messageHash is a constrained public input (IC[1] is a
// real point, not infinity), so the BLS proof attests to the exact
// messageHash the validators signed.

package bls_zkp

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

// BLSSignatureCircuitV2BLS381 — the BLS12-381-SNARK V2 circuit. Same public
// input order as the BN254 V2 circuit and the on-chain Aiken verifier:
// [MessageHash, PubkeyCommitment, SignedVotingPower, TotalVotingPower].
type BLSSignatureCircuitV2BLS381 struct {
	MessageHash       frontend.Variable `gnark:",public"`
	PubkeyCommitment  frontend.Variable `gnark:",public"`
	SignedVotingPower frontend.Variable `gnark:",public"`
	TotalVotingPower  frontend.Variable `gnark:",public"`

	Signature sw_bls12381.G1Affine
	Pubkey    sw_bls12381.G2Affine
}

func (c *BLSSignatureCircuitV2BLS381) Define(api frontend.API) error {
	// 1. Threshold: signedVotingPower * 3 >= totalVotingPower * 2.
	const votingPowerBits = 64
	_ = api.ToBinary(c.SignedVotingPower, votingPowerBits)
	_ = api.ToBinary(c.TotalVotingPower, votingPowerBits)
	lhs := api.Mul(c.SignedVotingPower, 3)
	rhs := api.Mul(c.TotalVotingPower, 2)
	api.AssertIsLessOrEqual(rhs, lhs)

	pairing, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}

	// 2. Curve + subgroup membership.
	pairing.AssertIsOnG1(&c.Signature)
	pairing.AssertIsOnG2(&c.Pubkey)

	// 3. Map MessageHash → H(m) ∈ G1 in-circuit. 255-bit decomposition for
	//    BLS12-381 Fr (vs 254 for BN254). The reduced messageHash fits in
	//    Fp (381 bits) without further reduction.
	fp, err := emulated.NewField[sw_bls12381.BaseField](api)
	if err != nil {
		return fmt.Errorf("new bls12381 Fp field: %w", err)
	}
	msgBits := api.ToBinary(c.MessageHash, 255)
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

	// 4. Pairing equation: e(σ, -G2_gen) · e(H(m), pk) = 1.
	negG2GenAff := negG2Generator()
	negG2GenInCircuit := sw_bls12381.NewG2Affine(negG2GenAff)
	if err := pairing.PairingCheck(
		[]*sw_bls12381.G1Affine{&c.Signature, hMsg},
		[]*sw_bls12381.G2Affine{&negG2GenInCircuit, &c.Pubkey},
	); err != nil {
		return fmt.Errorf("pairing check: %w", err)
	}

	// 5. Pubkey commitment Horner fold (mod BLS12-381 Fr in the native field).
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

// (bls12381FrModulus — the BLS12-381 scalar field order — is already
// declared in prover_bls12381.go and reused here as the native field the
// BLS12-381 V2 circuit operates over.)

// ComputePubkeyCommitmentV2BLS381 is the off-circuit counterpart of the
// in-circuit Horner fold, reducing mod BLS12-381 Fr (not BN254 Fr). Same
// limb order as ComputePubkeyCommitmentV2.
func ComputePubkeyCommitmentV2BLS381(pk bls12381.G2Affine) ([32]byte, error) {
	mixer := big.NewInt(251)
	acc := new(big.Int)

	absorbFp := func(e bls12381fp.Element) {
		var bi big.Int
		e.BigInt(&bi)
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
			acc.Mul(acc, mixer)
			acc.Add(acc, new(big.Int).SetUint64(limb))
			acc.Mod(acc, bls12381FrModulus)
		}
	}

	absorbFp(pk.X.A0)
	absorbFp(pk.X.A1)
	absorbFp(pk.Y.A0)
	absorbFp(pk.Y.A1)

	var out [32]byte
	b := acc.Bytes()
	if len(b) > 32 {
		return [32]byte{}, fmt.Errorf("commitment exceeds 32 bytes")
	}
	copy(out[32-len(b):], b)
	return out, nil
}

// HashMessageToG1V2BLS381 is the off-circuit counterpart of the BLS12-381 V2
// circuit's in-circuit MapToG1. It reduces the messageHash mod BLS12-381 Fr
// (NOT BN254 Fr — the BLS12-381 V2 circuit's native field is BLS12-381 Fr),
// then lifts to Fp and maps to G1. Validators signing for the Cardano V2
// verifier MUST use this exact function so the in-circuit pairing check is
// satisfiable.
func HashMessageToG1V2BLS381(messageHash [32]byte) bls12381.G1Affine {
	var asInt big.Int
	asInt.SetBytes(messageHash[:])
	var frEl bls12381fr.Element
	frEl.SetBigInt(&asInt)
	var frBI big.Int
	frEl.BigInt(&frBI)

	var u bls12381fp.Element
	u.SetBigInt(&frBI)
	return bls12381.MapToG1(u)
}

// BuildV2WitnessBLS381 constructs the BLS12-381 V2 circuit witness. Mirrors
// BuildV2Witness but reduces the messageHash mod BLS12-381 Fr and uses the
// BLS12-381 pubkey commitment.
func BuildV2WitnessBLS381(
	messageHash [32]byte,
	aggSig bls12381.G1Affine,
	aggPk bls12381.G2Affine,
	signedVotingPower uint64,
	totalVotingPower uint64,
) (*BLSSignatureCircuitV2BLS381, [32]byte, error) {
	pkCommitment, err := ComputePubkeyCommitmentV2BLS381(aggPk)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("compute pk commitment: %w", err)
	}

	var msgInt big.Int
	msgInt.SetBytes(messageHash[:])
	var msgFr bls12381fr.Element
	msgFr.SetBigInt(&msgInt)
	var msgFrBI big.Int
	msgFr.BigInt(&msgFrBI)

	var pkCommitInt big.Int
	pkCommitInt.SetBytes(pkCommitment[:])

	w := &BLSSignatureCircuitV2BLS381{
		MessageHash:       msgFrBI,
		PubkeyCommitment:  pkCommitInt,
		SignedVotingPower: signedVotingPower,
		TotalVotingPower:  totalVotingPower,
		Signature:         sw_bls12381.NewG1Affine(aggSig),
		Pubkey:            sw_bls12381.NewG2Affine(aggPk),
	}
	return w, pkCommitment, nil
}
