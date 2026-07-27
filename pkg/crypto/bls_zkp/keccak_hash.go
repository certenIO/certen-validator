// Copyright 2025 Certen Protocol
//
// Keccak-mod-R hash-to-field for gnark's BSB22 commitment derivation.
//
// gnark's DEFAULT Groth16 prover/verifier uses RFC 9380 ExpandMsgXmd over
// SHA-256 with the "bsb22-commitment" DST for the Pedersen-commitment-derived
// public input. The gnark-generated Solidity verifier
// (BLSZKVerifierV2Generated.sol) instead computes
//
//   publicCommitments[i] = uint256(keccak256(input)) % R
//
// where R is the BN254 scalar field modulus. Without overriding the prover
// to use the same hash, the off-chain proof verifies under gnark but is
// rejected on-chain — the two sides disagree about what `publicCommitments[i]`
// should be.
//
// `backend.WithProverHashToFieldFunction(NewKeccakToFieldHash())` and
// `backend.WithVerifierHashToFieldFunction(NewKeccakToFieldHash())` make
// gnark use this implementation. This file is the production home for the
// helper; `circuitv2_roundtrip_test.go` contains a copy that is kept in sync
// with this one and is used by the test-only fixture generator.
//
// The implementation buffers incoming bytes (gnark issues a single Write
// followed by Sum, but the hash.Hash contract allows multiple Writes), then
// computes keccak256 once on Sum and reduces the digest mod R into a 32-byte
// big-endian Fr element.

package bls_zkp

import (
	"hash"
	"math/big"

	bls12381_kh "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp_kh "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr_kh "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

// keccakToFieldHash implements hash.Hash producing a 32-byte BN254 Fr element
// from `keccak256(buf) mod R`. See file-level comment for why this exists.
type keccakToFieldHash struct {
	buf []byte
}

// NewKeccakToFieldHash returns a fresh keccakToFieldHash. Pass the returned
// hash.Hash to backend.WithProverHashToFieldFunction / WithVerifierHashToFieldFunction.
func NewKeccakToFieldHash() hash.Hash { return &keccakToFieldHash{} }

func (h *keccakToFieldHash) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

func (h *keccakToFieldHash) Sum(b []byte) []byte {
	k := sha3.NewLegacyKeccak256()
	k.Write(h.buf)
	digest := k.Sum(nil) // 32 bytes
	var bi big.Int
	bi.SetBytes(digest)
	var fe bn254fr.Element
	fe.SetBigInt(&bi)
	out := fe.Bytes() // 32-byte big-endian Fr value
	return append(b, out[:]...)
}

func (h *keccakToFieldHash) Reset()         { h.buf = nil }
func (h *keccakToFieldHash) Size() int      { return 32 }
func (h *keccakToFieldHash) BlockSize() int { return 32 }

// =============================================================================
// BLS12-381 V2 (Cardano) commitment hash-to-field.
// =============================================================================
//
// Cardano's Plutus V3 CIP-381 builtins expose NO way to read a G1 point's
// (x, y) coordinates — only bls12_381_g1_compress (→ 48-byte compressed
// form). gnark's default BSB22 commitment hashing feeds the UNCOMPRESSED
// 96-byte marshaling (x‖y) to the hash, which the on-chain Aiken verifier
// therefore cannot reproduce.
//
// This hash makes the publicCommitment derivable on-chain: on Sum it parses
// the buffered uncompressed commitment, re-serializes it COMPRESSED (48
// bytes — exactly what bls12_381_g1_compress yields on-chain), keccak256's
// that, and reduces mod the BLS12-381 scalar field. The Aiken verifier
// computes the identical value via
//
//	reduce_be(keccak_256(bls12_381_g1_compress(commitments)))
//
// giving sound BSB22 (publicCommitment bound to the commitment) on Cardano.
type keccakToFieldHashBLS12381 struct {
	buf []byte
}

// NewKeccakToFieldHashBLS12381Compressed returns the Cardano-compatible
// BSB22 commitment hash. Use for BOTH prove and verify of the BLS12-381 V2
// circuit so the publicCommitment matches the on-chain derivation.
func NewKeccakToFieldHashBLS12381Compressed() hash.Hash {
	return &keccakToFieldHashBLS12381{}
}

func (h *keccakToFieldHashBLS12381) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

func (h *keccakToFieldHashBLS12381) Sum(b []byte) []byte {
	// gnark feeds the commitment's uncompressed marshaling (96 bytes for a
	// single BLS12-381 G1: x[48] ‖ y[48]). Reconstruct the point and
	// re-serialize compressed so the input matches what Cardano hashes.
	hashInput := h.buf
	if len(h.buf) == 96 {
		var pt bls12381_kh.G1Affine
		var xfe, yfe bls12381fp_kh.Element
		xfe.SetBytes(h.buf[0:48])
		yfe.SetBytes(h.buf[48:96])
		pt.X = xfe
		pt.Y = yfe
		compressed := pt.Bytes() // 48-byte compressed
		hashInput = compressed[:]
	}
	k := sha3.NewLegacyKeccak256()
	k.Write(hashInput)
	digest := k.Sum(nil)
	var bi big.Int
	bi.SetBytes(digest)
	var fe bls12381fr_kh.Element
	fe.SetBigInt(&bi)
	out := fe.Bytes()
	return append(b, out[:]...)
}

func (h *keccakToFieldHashBLS12381) Reset()         { h.buf = nil }
func (h *keccakToFieldHashBLS12381) Size() int      { return 32 }
func (h *keccakToFieldHashBLS12381) BlockSize() int { return 32 }
