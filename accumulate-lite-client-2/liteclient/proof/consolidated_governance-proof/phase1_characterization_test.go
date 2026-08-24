// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"encoding/hex"
	"testing"
)

// Phase 1.2 — signature digest fixture.
//
// This pins the verified vector from L4_DESIGN.md §4. It is an OFFLINE test:
// no network access is required. It characterises the digest that
// ComputeAccumulateDigest produces today, so any later refactor that changes
// the preimage is caught immediately.
//
// The signed hash is the hash of the SequencedMessage that wraps the anchor
// transaction, NOT the anchor transaction's own hash. See
// TestPhase1_AnchorSignedHashIsSequencedMessage in the chained_proof package.
const (
	fixtureTxHash    = "e6dd1988102e29aa5206cc1c5fcb0f3ff5b4cac0b4580928029d03ed93035572"
	fixturePubKey    = "40e6e8b96de7e7ed4c38815448abe22ab555236418d813b3a02cb6a7bc42871b"
	fixtureSignature = "f9b81b4634ab6280ef423aa70133962a41a6b70985ef9703778868a9f3a298fb" +
		"5f3c7626e376e19173d34e12b4721ec3dde77b696ee94954f6d8b18b5423500b"
	fixtureSigner        = "acc://dn.acme/network"
	fixtureTimestamp     = int64(1787562303142)
	fixtureSignerVersion = int64(0)

	// Pinned outputs, captured from the unmodified implementation.
	fixtureMetadataHash = "ede23f2b6f318ade74b1431597845fc30c0308f40262fee3d885ea847e38b746"
	fixtureDigest       = "d2c14a457d31297551670bfebae28f04efa2f1cf615e99d368e7c6afd14e5ee6"
)

func fixtureSignatureData() SignatureData {
	ts := fixtureTimestamp
	return SignatureData{
		Type:            "ed25519",
		PublicKey:       fixturePubKey,
		Signature:       fixtureSignature,
		Signer:          fixtureSigner,
		SignerVersion:   fixtureSignerVersion,
		Timestamp:       &ts,
		TransactionHash: fixtureTxHash,
	}
}

func TestPhase1_SignatureDigestFixture(t *testing.T) {
	sv := NewSignatureVerifier("") // in-process protocol digest, no external tool

	digest, err := sv.ComputeAccumulateDigest(context.Background(), fixtureSignatureData(), fixtureTxHash)
	if err != nil {
		t.Fatalf("ComputeAccumulateDigest: %v", err)
	}
	if got := hex.EncodeToString(digest); got != fixtureDigest {
		t.Fatalf("digest drift:\n got  %s\n want %s", got, fixtureDigest)
	}

	if err := sv.VerifyEd25519(fixturePubKey, fixtureSignature, digest); err != nil {
		t.Fatalf("VerifyEd25519 on the known-good vector must succeed, got: %v", err)
	}
}

// Negative controls: the fixture must not verify under a mutated preimage.
// These guard against a digest function that ignores its inputs.
func TestPhase1_SignatureDigestFixture_Negatives(t *testing.T) {
	sv := NewSignatureVerifier("")
	ctx := context.Background()

	mutations := map[string]func(*SignatureData){
		"wrong timestamp":      func(s *SignatureData) { v := fixtureTimestamp + 1; s.Timestamp = &v },
		"wrong signer version": func(s *SignatureData) { s.SignerVersion = 1 },
		"wrong signer url":     func(s *SignatureData) { s.Signer = "acc://dn.acme/oracle" },
		"wrong tx hash": func(s *SignatureData) {
			s.TransactionHash = "00" + fixtureTxHash[2:]
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			sig := fixtureSignatureData()
			mutate(&sig)

			digest, err := sv.ComputeAccumulateDigest(ctx, sig, sig.TransactionHash)
			if err != nil {
				return // rejecting outright is also a valid fail-closed outcome
			}
			if hex.EncodeToString(digest) == fixtureDigest {
				t.Fatalf("mutation %q produced the unmutated digest — digest ignores this input", name)
			}
			if err := sv.VerifyEd25519(fixturePubKey, fixtureSignature, digest); err == nil {
				t.Fatalf("mutation %q still verified — FAIL-OPEN", name)
			}
		})
	}
}
