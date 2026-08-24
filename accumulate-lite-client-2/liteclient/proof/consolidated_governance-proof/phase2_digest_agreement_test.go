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

	cp "github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// Runbook rule 9 says to reuse the existing verified signature machinery rather
// than write a second copy of the digest.
//
// L4 lives in package chained_proof and the governance signature verifier lives
// in package main, so a literal shared call is not possible across the two. What
// is possible - and stronger than a shared helper, because it is checked - is to
// pin both to identical output. Both build their preimage from
// protocol.ED25519Signature.Metadata().Hash(), so the algorithm itself lives in
// the protocol package; this test proves neither caller has drifted from it.
//
// If this test ever fails, one of the two has changed and L4 signatures will
// stop agreeing with governance signatures. Do not "fix" it by adjusting the
// expected value.
func TestPhase2_DigestAgreesWithGovernanceVerifier(t *testing.T) {
	ctx := context.Background()
	sv := NewSignatureVerifier("")

	type vector struct {
		name          string
		pub           string
		signer        string
		signerVersion int64
		timestamp     int64
		txHash        string
	}
	vectors := []vector{
		{"kermit fixture", fixturePubKey, fixtureSigner, 0, fixtureTimestamp, fixtureTxHash},
		{"nonzero signer version", fixturePubKey, fixtureSigner, 7, fixtureTimestamp, fixtureTxHash},
		{"zero timestamp", fixturePubKey, fixtureSigner, 0, 0, fixtureTxHash},
		{"different signer", fixturePubKey, "acc://dn.acme/oracle", 3, 42, fixtureTxHash},
		{"different tx hash", fixturePubKey, fixtureSigner, 0, fixtureTimestamp,
			"0000000000000000000000000000000000000000000000000000000000000001"},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			ts := v.timestamp
			govSig := SignatureData{
				Type:            "ed25519",
				PublicKey:       v.pub,
				Signer:          v.signer,
				SignerVersion:   v.signerVersion,
				Timestamp:       &ts,
				TransactionHash: v.txHash,
			}
			govDigest, err := sv.ComputeAccumulateDigest(ctx, govSig, v.txHash)
			if err != nil {
				t.Fatalf("governance digest: %v", err)
			}

			l4Sig := cp.AnchorSignature{
				PublicKey:     v.pub,
				Signer:        v.signer,
				SignerVersion: uint64(v.signerVersion),
				Timestamp:     uint64(v.timestamp),
			}
			l4Digest, err := cp.ComputeAnchorSignatureDigest(l4Sig, v.txHash)
			if err != nil {
				t.Fatalf("L4 digest: %v", err)
			}

			if hex.EncodeToString(govDigest) != hex.EncodeToString(l4Digest) {
				t.Fatalf("digest implementations have DIVERGED:\n governance %x\n L4         %x",
					govDigest, l4Digest)
			}
		})
	}
}
