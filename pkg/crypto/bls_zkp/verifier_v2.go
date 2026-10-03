// Copyright 2026 Certen Protocol

package bls_zkp

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
)

// The V2 quorum proof checked offline (RB5-F15).
//
// A CertenAnchorV8_2 accepts a quorum's BLS aggregate only as a Groth16 proof (BLSZKVerifierV2_1) that a BLS12-381
// signature over the message verifies under a key whose commitment the proof states. A verifier that wants to repeat
// that check without the chain needs exactly two things: the proof bytes the chain was given, and the verification key
// the deployed verifier was compiled from. The proof travels with the evidence; the key is fixed per verifier
// deployment and public, so it is embedded here and pinned by its SHA-256 - the hash deploy/bls_zk_keys.SHA256SUMS
// holds for the key the validators prove with and the deployed verifiers accept (vkcheck; the live test
// TestTheQuorumProofPathIsAcceptedByTheDeployedVerifiers).

//go:embed deployed_v2_verification_key.bin
var deployedV2VerificationKey []byte

// DeployedV2VerificationKeySHA256 is the SHA-256 of the embedded key, the verification_key.bin line of
// deploy/bls_zk_keys.SHA256SUMS.
const DeployedV2VerificationKeySHA256 = "1ab8f7f12ba0f11b83dd3226ba5ac930600f18fcd488b467061a079cd811097a"

// V2Verifier checks V2 quorum proofs (the bytes BLSProofData.aggregateSignature carries) against one verification key.
// It holds no proving key and cannot prove.
type V2Verifier struct {
	vk groth16.VerifyingKey
}

// NewV2Verifier reads a gnark BN254 Groth16 verification key.
func NewV2Verifier(r io.Reader) (*V2Verifier, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read verification key: %w", err)
	}
	return &V2Verifier{vk: vk}, nil
}

var (
	deployedV2Once     sync.Once
	deployedV2Verifier *V2Verifier
	deployedV2Err      error
)

// DeployedV2Verifier is the verifier of the deployed BLSZKVerifierV2_1 key, refused when the embedded bytes are not the
// pinned key.
func DeployedV2Verifier() (*V2Verifier, error) {
	deployedV2Once.Do(func() {
		sum := sha256.Sum256(deployedV2VerificationKey)
		if hex.EncodeToString(sum[:]) != DeployedV2VerificationKeySHA256 {
			deployedV2Err = fmt.Errorf("the embedded verification key hashes to %x, not the deployed key %s",
				sum, DeployedV2VerificationKeySHA256)
			return
		}
		deployedV2Verifier, deployedV2Err = NewV2Verifier(bytes.NewReader(deployedV2VerificationKey))
	})
	return deployedV2Verifier, deployedV2Err
}

// Verify reports whether the V2 proof blob verifies under the key, with the public inputs the blob itself states
// (message hash, pubkey commitment, signed and total voting power). The caller compares those inputs with what it
// expects (DecodeV2PublicInputs): a proof that verifies says nothing about a message it was not made for.
func (v *V2Verifier) Verify(abiBytes []byte) (bool, error) {
	if v == nil {
		return false, errors.New("no verifier")
	}
	return verifyV2ABIBytes(v.vk, abiBytes)
}

// V2PublicInputs are the public inputs a V2 proof blob states, and the threshold words it carries (which the circuit
// does not constrain: the anchor computes its threshold from its own registry).
type V2PublicInputs struct {
	MessageHash          [32]byte
	PubkeyCommitment     [32]byte
	SignedVotingPower    uint64
	TotalVotingPower     uint64
	ThresholdNumerator   uint64
	ThresholdDenominator uint64
}

// DecodeV2PublicInputs reads the public inputs out of a V2 proof blob.
func DecodeV2PublicInputs(abiBytes []byte) (*V2PublicInputs, error) {
	p, err := decodeV2ABIProof(abiBytes)
	if err != nil {
		return nil, err
	}
	return &V2PublicInputs{MessageHash: p.MessageHash, PubkeyCommitment: p.PubkeyCommitment, SignedVotingPower: p.SignedVotingPower,
		TotalVotingPower: p.TotalVotingPower, ThresholdNumerator: p.ThresholdNumerator, ThresholdDenominator: p.ThresholdDenominator}, nil
}
