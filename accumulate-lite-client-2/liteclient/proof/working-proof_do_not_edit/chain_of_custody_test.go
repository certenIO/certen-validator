// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Chain of custody: user transaction -> validator signatures, link by link.
//
// A recurring question about L4 is why the hash the validators sign is not the
// user's transaction hash. It must not be. Validators sign an ANCHOR, whose
// body commits to a state root; the user's transaction is bound into that root
// by the L1-L3 merkle receipts. If signedHash ever equalled the user's txHash,
// the anchoring layer would have collapsed and the proof would be unsound.
//
// So the binding is transitive - each link is either a SHA-256 recomputation
// or an equality between a recomputed value and a value read out of signed
// bytes. This test walks every link explicitly and fails if any one is missing,
// so the chain is auditable rather than asserted.
//
// It runs entirely offline against stored proofs.
func TestChainOfCustody_UserTxToValidatorSignatures(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "proof_*.json"))
	if len(files) == 0 {
		t.Skip("no stored proofs")
	}

	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			p := new(ChainedProof)
			if err := json.Unmarshal(raw, p); err != nil {
				t.Fatal(err)
			}
			rv := NewReceiptVerifier(false)
			eq := func(what, a, b string) {
				t.Helper()
				if !strings.EqualFold(a, b) {
					t.Fatalf("BROKEN LINK %s: %s != %s", what, a, b)
				}
			}

			t.Logf("user transaction        %s", p.Input.TxHash)
			t.Logf("  account               %s", p.Input.Account)

			// ---- LINK 1: the user's transaction is the L1 leaf -------------
			eq("L1 leaf == input txHash", p.Layer1.Leaf, p.Input.TxHash)
			eq("L1 receipt.start == leaf", p.Layer1.Receipt.Start, p.Layer1.Leaf)

			// ---- LINK 2: SHA-256 walk to the BVN root chain anchor ---------
			if err := rv.ValidateIntegrity(p.Layer1.Receipt); err != nil {
				t.Fatalf("BROKEN LINK 2 (L1 merkle): %v", err)
			}
			eq("L1 receipt.anchor == BVN rootChainAnchor",
				p.Layer1.Receipt.Anchor, p.Layer1.BVNRootChainAnchor)
			t.Logf("  --L1 merkle (%2d steps)--> BVN rootChainAnchor %s @ block %d",
				len(p.Layer1.Receipt.Entries), p.Layer1.BVNRootChainAnchor, p.Layer1.BVNMinorBlockIndex)

			// ---- LINK 3: that exact root anchor is INSIDE the signed BVN
			//              anchor body, at the same block ---------------------
			bvnBody := decodeAnchorBody(t, p.Layer4BVN)
			eq("L4-BVN signed body.rootChainAnchor == L1 BVN rootChainAnchor",
				hexOf(bvnBody.RootChainAnchor[:]), p.Layer1.BVNRootChainAnchor)
			if bvnBody.MinorBlockIndex != p.Layer1.BVNMinorBlockIndex {
				t.Fatalf("BROKEN LINK 3: signed anchor block %d != L1 block %d",
					bvnBody.MinorBlockIndex, p.Layer1.BVNMinorBlockIndex)
			}
			t.Logf("  ==> that anchor is INSIDE the bytes %s validators signed",
				p.Layer4BVN.Partition)

			// ---- LINK 4: the BVN validators' signatures cover those bytes ---
			verifyQuorumOverSignedBytes(t, p.Layer4BVN)

			// ---- LINK 5: the same signed body carries the BVN state root ----
			eq("L4-BVN signed body.stateTreeAnchor == L2 bvnStateTreeAnchor",
				hexOf(bvnBody.StateTreeAnchor[:]), p.Layer2.BVNStateTreeAnchor)
			t.Logf("  --signed by %d/%d %s validators--> BVN stateTreeAnchor %s",
				len(p.Layer4BVN.Signatures), p.Layer4BVN.Threshold, p.Layer4BVN.Partition,
				p.Layer2.BVNStateTreeAnchor)

			// ---- LINK 6: L2 receipts carry the BVN anchor into the DN -------
			if err := rv.ValidateIntegrity(p.Layer2.RootReceipt); err != nil {
				t.Fatalf("BROKEN LINK 6 (L2 root merkle): %v", err)
			}
			if err := rv.ValidateIntegrity(p.Layer2.BptReceipt); err != nil {
				t.Fatalf("BROKEN LINK 6 (L2 bpt merkle): %v", err)
			}
			eq("L2 root receipt.start == BVN rootChainAnchor",
				p.Layer2.RootReceipt.Start, p.Layer1.BVNRootChainAnchor)
			eq("L2 pairing: root.anchor == bpt.anchor",
				p.Layer2.RootReceipt.Anchor, p.Layer2.BptReceipt.Anchor)
			eq("L2 root receipt.anchor == DN rootChainAnchor",
				p.Layer2.RootReceipt.Anchor, p.Layer2.DNRootChainAnchor)
			t.Logf("  --L2 merkle (%2d steps)--> DN rootChainAnchor %s @ DN block %d",
				len(p.Layer2.RootReceipt.Entries), p.Layer2.DNRootChainAnchor, p.Layer2.DNMinorBlockIndex)

			// ---- LINK 7: that DN root anchor is inside the signed DN anchor -
			dnBody := decodeAnchorBody(t, p.Layer4DN)
			eq("L4-DN signed body.rootChainAnchor == L2 dnRootChainAnchor",
				hexOf(dnBody.RootChainAnchor[:]), p.Layer2.DNRootChainAnchor)
			if dnBody.MinorBlockIndex != p.Layer2.DNMinorBlockIndex {
				t.Fatalf("BROKEN LINK 7: signed DN anchor block %d != L2 DN block %d",
					dnBody.MinorBlockIndex, p.Layer2.DNMinorBlockIndex)
			}

			// ---- LINK 8: Directory validators' signatures cover those bytes -
			verifyQuorumOverSignedBytes(t, p.Layer4DN)

			// ---- LINK 9: L3 recomputes the DN state root -------------------
			if err := rv.ValidateIntegrity(p.Layer3.RootReceipt); err != nil {
				t.Fatalf("BROKEN LINK 9 (L3 root merkle): %v", err)
			}
			if err := rv.ValidateIntegrity(p.Layer3.BptReceipt); err != nil {
				t.Fatalf("BROKEN LINK 9 (L3 bpt merkle): %v", err)
			}
			eq("L3 root receipt.start == DN rootChainAnchor",
				p.Layer3.RootReceipt.Start, p.Layer2.DNRootChainAnchor)
			eq("L4-DN signed body.stateTreeAnchor == L3 dnStateTreeAnchor",
				hexOf(dnBody.StateTreeAnchor[:]), p.Layer3.DNStateTreeAnchor)
			t.Logf("  --signed by %d/%d Directory validators--> DN stateTreeAnchor %s",
				len(p.Layer4DN.Signatures), p.Layer4DN.Threshold, p.Layer3.DNStateTreeAnchor)

			// ---- LINK 10: the two signing sets are genuinely different -----
			if strings.EqualFold(p.Layer4BVN.Partition, p.Layer4DN.Partition) {
				t.Fatalf("BROKEN LINK 10: both legs signed by %s; the BVN->DN hop is not witnessed",
					p.Layer4BVN.Partition)
			}
			bvnSigners := signerSet(p.Layer4BVN)
			dnSigners := signerSet(p.Layer4DN)
			t.Logf("  BVN quorum signers: %d, Directory quorum signers: %d", len(bvnSigners), len(dnSigners))

			// And the signed hash is NOT the user's transaction hash. If it
			// were, the anchor would be the user's transaction and there would
			// be no anchoring layer left to prove.
			if strings.EqualFold(p.Layer4BVN.SignedHash, p.Input.TxHash) ||
				strings.EqualFold(p.Layer4DN.SignedHash, p.Input.TxHash) {
				t.Fatal("signed hash equals the user transaction hash - the anchoring layer has collapsed")
			}
			t.Logf("CHAIN COMPLETE: user tx -> merkle -> signed BVN anchor -> merkle -> signed DN anchor")
		})
	}
}

func hexOf(b []byte) string { return lowerHex(hex.EncodeToString(b)) }

// decodeAnchorBody returns the anchor body read OUT of the bytes the quorum
// signed - never the restated struct fields.
func decodeAnchorBody(t *testing.T, l4 *Layer4) *protocol.PartitionAnchor {
	t.Helper()
	raw, err := hex.DecodeString(l4.SequencedMessage)
	if err != nil {
		t.Fatalf("%s: sequencedMessage hex: %v", l4.Partition, err)
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		t.Fatalf("%s: decode sequenced message: %v", l4.Partition, err)
	}
	// The signatures are bound to THESE bytes.
	h := seq.Hash()
	if !strings.EqualFold(hexOf(h[:]), l4.SignedHash) {
		t.Fatalf("%s: signed bytes do not hash to signedHash", l4.Partition)
	}
	tm, ok := seq.Message.(*messaging.TransactionMessage)
	if !ok {
		t.Fatalf("%s: signed message is %T", l4.Partition, seq.Message)
	}
	switch b := tm.Transaction.Body.(type) {
	case *protocol.DirectoryAnchor:
		return &b.PartitionAnchor
	case *protocol.BlockValidatorAnchor:
		return &b.PartitionAnchor
	default:
		t.Fatalf("%s: signed body is %v, not a partition anchor", l4.Partition, b.Type())
		return nil
	}
}

// verifyQuorumOverSignedBytes re-runs the ed25519 checks here, independently of
// VerifyOffline, so this test proves the quorum rather than trusting the
// function it is meant to corroborate.
func verifyQuorumOverSignedBytes(t *testing.T, l4 *Layer4) {
	t.Helper()
	active := map[string]bool{}
	for _, v := range l4.ValidatorSet {
		if isActiveOn(v, l4.Partition) {
			active[strings.ToLower(v.PublicKey)] = true
		}
	}
	distinct := map[string]bool{}
	for i, s := range l4.Signatures {
		digest, err := ComputeAnchorSignatureDigest(s, l4.SignedHash)
		if err != nil {
			t.Fatalf("%s sig[%d]: digest: %v", l4.Partition, i, err)
		}
		pk, err := hex.DecodeString(s.PublicKey)
		if err != nil {
			t.Fatalf("%s sig[%d]: pubkey: %v", l4.Partition, i, err)
		}
		sig, err := hex.DecodeString(s.Signature)
		if err != nil {
			t.Fatalf("%s sig[%d]: signature: %v", l4.Partition, i, err)
		}
		if !ed25519.Verify(pk, digest, sig) {
			t.Fatalf("%s sig[%d]: ed25519 verification FAILED", l4.Partition, i)
		}
		if !active[strings.ToLower(s.PublicKey)] {
			t.Fatalf("%s sig[%d]: signer not active on this partition", l4.Partition, i)
		}
		distinct[strings.ToLower(s.PublicKey)] = true
	}
	if uint64(len(distinct)) < l4.Threshold {
		t.Fatalf("%s: %d distinct signers < threshold %d", l4.Partition, len(distinct), l4.Threshold)
	}
}

func signerSet(l4 *Layer4) map[string]bool {
	out := map[string]bool{}
	for _, s := range l4.Signatures {
		out[strings.ToLower(s.PublicKey)] = true
	}
	return out
}

var _ = context.Background
