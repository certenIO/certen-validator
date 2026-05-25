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
