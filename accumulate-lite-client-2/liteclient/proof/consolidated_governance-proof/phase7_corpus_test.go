// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Phase 7, Gate 1 - the corpus, and what today's code does with it.
//
// PHASE7_RUNBOOK.md section 1.3 requires the corpus to FAIL against unmodified
// code before a line of the fix is written: "Writing the verifier first and the
// tests second produces an implementation that is self-consistent and wrong,
// and nothing downstream will catch it." This file is that proof.
//
// It is a CHARACTERIZATION test. It asserts what the code does today, not what
// it should do. Phases 2 and 3 will make these assertions false on purpose, and
// this file must then be rewritten to assert the new behaviour - deliberately,
// with the change visible in the diff, rather than quietly deleted.
//
// The traces come from docs/l4/phase7_corpus/traces.json, produced by
// cmd/p7corpus against Kermit. Every one is a real signature over a real
// transaction, built with accumulate-core's own signing.Builder and verdicted
// with protocol.VerifyUserSignature. Nothing in this file computes a verdict.

type corpusTrace struct {
	Case                   string   `json:"case"`
	Shape                  string   `json:"shape"`
	Label                  string   `json:"label"`
	Why                    string   `json:"why"`
	Expect                 string   `json:"expect"`
	RefusalKind            string   `json:"refusalKind"`
	KeyIsDirectOnOuterPage *bool    `json:"keyIsDirectOnOuterPage"`
	Principal              string   `json:"principal"`
	TransactionHash        string   `json:"transactionHash"`
	Type                   string   `json:"type"`
	KeyType                string   `json:"keyType"`
	Delegators             []string `json:"delegators"`
	PublicKey              string   `json:"publicKey"`
	Signature              string   `json:"signature"`
	Signer                 string   `json:"signer"`
	SignerVersion          uint64   `json:"signerVersion"`
	Timestamp              uint64   `json:"timestamp"`
	SignerPartition        string   `json:"signerPartition"`
	CoreVerdict            bool     `json:"coreVerdict"`
	DigestForm             string   `json:"digestForm"`
	Digest                 string   `json:"digest"`
	Submitted              bool     `json:"submitted"`
	SubmitError            string   `json:"submitError"`
	TxID                   string   `json:"txID"`
	ExecStatus             string   `json:"execStatus"`
}

type corpusFile struct {
	Endpoint       string        `json:"endpoint"`
	ProtocolModule string        `json:"protocolModule"`
	CapturedAt     string        `json:"capturedAt"`
	Traces         []corpusTrace `json:"traces"`
}

// corpusPath walks up to the repository root rather than hardcoding a depth,
// so the test keeps working if the package moves.
func corpusPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, "docs", "l4", "phase7_corpus", "traces.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("docs/l4/phase7_corpus/traces.json not found - run `go run ./cmd/p7corpus -stage capture`")
	return ""
}

func loadCorpus(t *testing.T) corpusFile {
	t.Helper()
	b, err := os.ReadFile(corpusPath(t))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var cf corpusFile
	if err := json.Unmarshal(b, &cf); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(cf.Traces) == 0 {
		t.Fatal("corpus is empty")
	}
	return cf
}

// TestP7_1_CorpusIsWellFormed checks the corpus before anything is measured
// against it. A corpus that does not exercise what it claims to exercise makes
// every gate after it meaningless, and the failure is silent.
func TestP7_1_CorpusIsWellFormed(t *testing.T) {
	cf := loadCorpus(t)

	var (
		delegated      int
		merkleForm     int
		partitions     = map[string]bool{}
		refusalKinds   = map[string]bool{}
		discriminating int
	)
	for _, tr := range cf.Traces {
		if len(tr.Delegators) > 0 {
			delegated++
		}
		if tr.DigestForm == "initiator-merkle" {
			merkleForm++
		}
		if tr.SignerPartition != "" {
			partitions[tr.SignerPartition] = true
		}
		if tr.RefusalKind != "" {
			refusalKinds[tr.RefusalKind] = true
		}
		if len(tr.Delegators) > 0 && tr.KeyIsDirectOnOuterPage != nil && !*tr.KeyIsDirectOnOuterPage {
			discriminating++
		}
	}

	if delegated == 0 {
		t.Fatal("no delegated signatures in the corpus - it is not exercising delegation at all")
	}
	if merkleForm == 0 {
		t.Fatal("no signature in the corpus uses the Initiator() merkle digest form. " +
			"Gate 2 requires at least one, or the second half of AcceptedDigests is never tested")
	}
	if len(partitions) < 2 {
		t.Fatalf("every corpus signer is on one partition (%v) - nothing here justifies a "+
			"leg per partition, which is the largest change in this phase", partitions)
	}
	// Runbook Gate 3 requires each refusal to carry its own distinct reason. The
	// corpus has to name them, or "each with its own reason" cannot be checked.
	for _, want := range []string{"depth-limit", "cycle", "duplicate-key", "path-binding", "unsupported-type"} {
		if !refusalKinds[want] {
			t.Errorf("the corpus has no case whose refusal reason is %q", want)
		}
	}
	// A delegated case whose inner key ALSO sits on the outer page is passed by
	// an implementation that ignores delegation entirely. At least one case must
	// not have that property or Gate 3 proves nothing about delegation.
	if discriminating == 0 {
		t.Fatal("every delegated corpus case has its signing key directly on the outer page, " +
			"so an implementation that ignores delegation passes all of them")
	}

	t.Logf("corpus: %d traces, %d delegated (%d discriminating), %d merkle-form, partitions %v",
		len(cf.Traces), delegated, discriminating, merkleForm, partitions)
	t.Logf("verdicts from %s via %s", cf.ProtocolModule, cf.Endpoint)
}

// TestP7_1_DelegatedSignaturesAreRefusedBeforeAnyCryptography is defect D1.
//
// signature_verifier.go rejects every signature whose type is not "ed25519",
// and a delegated signature's type is "delegated". The refusal happens during
// EXTRACTION, before a digest is computed or a key is checked - so a delegated
// signature never reaches the cryptography at all.
func TestP7_1_DelegatedSignaturesAreRefusedBeforeAnyCryptography(t *testing.T) {
	cf := loadCorpus(t)
	sv := &SignatureVerifier{}

	var checked int
	for _, tr := range cf.Traces {
		if tr.Type == "ed25519" {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			_, err := sv.ExtractSignatureFromMessageResult(messageResultFor(tr))
			if err == nil {
				t.Fatalf("a %s signature was extracted successfully - the corpus is not "+
					"exercising the type check this case exists for", tr.Type)
			}
			t.Logf("%s refused at extraction: %v", tr.Type, err)
		})
	}
	if checked == 0 {
		t.Fatal("no non-ed25519 signature in the corpus, so D1 is untested")
	}
}

// TestP7_1_DelegatedDigestIsWrongToday is defect D3, and it is the one that
// would survive a naive fix.
//
// Removing the type check is not enough. DelegatedSignature.Metadata() recurses
// and verifySigSplit hashes the OUTERMOST metadata, so the inner ed25519 key
// signs a digest that commits to every Delegator URL in the chain.
// ComputeAccumulateDigest builds a bare protocol.ED25519Signature and hashes
// that, so for a delegated signature it produces a digest the key never signed
// - a well-formed digest that never verifies.
//
// The corpus records the digest accumulate-core accepted. This test shows ours
// is a different number, and that the signature does not verify against it.
func TestP7_1_DelegatedDigestIsWrongToday(t *testing.T) {
	cf := loadCorpus(t)
	sv := NewSignatureVerifier("")
	ctx := context.Background()

	var checked int
	for _, tr := range cf.Traces {
		// KeyType, not Type. A delegated signature's Type is "delegated"; the
		// ed25519 key is at the centre of the nesting, and filtering on the
		// outer type finds none of them.
		if tr.KeyType != "ed25519" || len(tr.Delegators) == 0 || tr.Digest == "" {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			digest, err := sv.ComputeAccumulateDigest(ctx, signatureDataFor(tr), tr.TransactionHash)
			if err != nil {
				t.Logf("digest refused outright: %v (also fail-closed)", err)
				return
			}
			ours := hex.EncodeToString(digest)
			if ours == tr.Digest {
				t.Fatalf("our digest already matches the one accumulate-core accepted (%s). "+
					"Either the delegation is not in the signed bytes, or this corpus case "+
					"is not delegated - both mean the case proves nothing", ours[:16])
			}
			if err := sv.VerifyEd25519(tr.PublicKey, tr.Signature, digest); err == nil {
				t.Fatal("the signature verified against our digest, which cannot be true if " +
					"the digest differs from the one that was signed - FAIL-OPEN")
			}
			t.Logf("core accepted %s (%s form); we compute %s - refused",
				tr.Digest[:16], tr.DigestForm, ours[:16])
		})
	}
	if checked == 0 {
		t.Fatal("no delegated ed25519 signature in the corpus, so D3 is untested")
	}
}

// TestP7_1_MerkleFormIsRefusedToday is defect D4.
//
// accumulate-core accepts the metadata digest OR the Initiator() merkle digest.
// ComputeAccumulateDigest implements only the first, so a signature valid under
// the second is counted invalid - and because G1 fails closed, that surfaces as
// a governance REJECTION, indistinguishable from "the institution did not
// authorize this".
//
// The corpus specimen is a signature Kermit DELIVERED. There is no ambiguity
// about whether the network considers it authorized.
func TestP7_1_MerkleFormIsRefusedToday(t *testing.T) {
	cf := loadCorpus(t)
	sv := NewSignatureVerifier("")
	ctx := context.Background()

	var checked int
	for _, tr := range cf.Traces {
		if tr.DigestForm != "initiator-merkle" {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			if !tr.CoreVerdict {
				t.Fatalf("corpus says this is a merkle-form signature but accumulate-core " +
					"does not accept it - the corpus is wrong")
			}
			if tr.ExecStatus != "delivered" {
				t.Logf("note: this specimen's transaction is %q, not delivered", tr.ExecStatus)
			}
			digest, err := sv.ComputeAccumulateDigest(ctx, signatureDataFor(tr), tr.TransactionHash)
			if err != nil {
				t.Logf("digest refused outright: %v", err)
				return
			}
			verifyErr := sv.VerifyEd25519(tr.PublicKey, tr.Signature, digest)
			if verifyErr == nil {
				t.Fatal("a merkle-form signature verified under the metadata digest - " +
					"the two forms are not distinct and this case proves nothing")
			}
			t.Logf("a signature Kermit delivered is refused by our digest: %v", verifyErr)
		})
	}
	if checked == 0 {
		t.Fatal("no merkle-form signature in the corpus, so D4 is untested")
	}
}

// TestP7_1_PlainEd25519StillPasses is case A's guarantee, checked on the plain
// signatures the corpus does contain.
//
// Everything above is a defect. This is the thing that must NOT change: a
// 1-of-1, non-delegated ed25519 signature is what all 400 production proofs
// used, and it verifies today. If a later phase breaks it, the fix has cost
// more than it bought.
func TestP7_1_PlainEd25519StillPasses(t *testing.T) {
	cf := loadCorpus(t)
	sv := NewSignatureVerifier("")
	ctx := context.Background()

	var checked int
	for _, tr := range cf.Traces {
		if tr.Type != "ed25519" || len(tr.Delegators) > 0 || !tr.CoreVerdict {
			continue
		}
		if tr.DigestForm != "metadata" {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			// The extractor must accept it.
			got, err := sv.ExtractSignatureFromMessageResult(messageResultFor(tr))
			if err != nil {
				t.Fatalf("a plain ed25519 signature was refused at extraction: %v", err)
			}
			if got.PublicKey != tr.PublicKey {
				t.Fatalf("extracted the wrong public key: %s != %s", got.PublicKey, tr.PublicKey)
			}

			// And the digest must be the one accumulate-core accepted.
			digest, err := sv.ComputeAccumulateDigest(ctx, signatureDataFor(tr), tr.TransactionHash)
			if err != nil {
				t.Fatalf("ComputeAccumulateDigest: %v", err)
			}
			if got := hex.EncodeToString(digest); got != tr.Digest {
				t.Fatalf("digest disagrees with accumulate-core:\n ours %s\n core %s", got, tr.Digest)
			}
			if err := sv.VerifyEd25519(tr.PublicKey, tr.Signature, digest); err != nil {
				t.Fatalf("a signature accumulate-core accepts does not verify for us: %v", err)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no plain ed25519 signature in the corpus - case A's shape is untested")
	}
	t.Logf("%d plain ed25519 signatures agree with accumulate-core", checked)
}

// TestP7_1_CorpusSignaturesAreRealEd25519 is a control on the corpus itself.
//
// Every claim above rests on the corpus carrying real key material. If the
// public keys and signatures were the wrong length or not hex, the failures
// above would happen for uninteresting reasons and look identical.
func TestP7_1_CorpusSignaturesAreRealEd25519(t *testing.T) {
	cf := loadCorpus(t)
	for _, tr := range cf.Traces {
		if tr.KeyType != "ed25519" {
			continue
		}
		pub, err := hex.DecodeString(tr.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Errorf("%s: public key is not %d bytes of hex", tr.Label, ed25519.PublicKeySize)
		}
		sig, err := hex.DecodeString(tr.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			t.Errorf("%s: signature is not %d bytes of hex", tr.Label, ed25519.SignatureSize)
		}
		if len(tr.TransactionHash) != 64 {
			t.Errorf("%s: transaction hash is not 32 bytes of hex", tr.Label)
		}
	}
}

// signatureDataFor renders a corpus trace as the SignatureData the verifier
// consumes. The delegation is deliberately NOT represented: SignatureData has
// nowhere to put it today, which is the shape defect D3 lives in.
func signatureDataFor(tr corpusTrace) SignatureData {
	ts := int64(tr.Timestamp)
	return SignatureData{
		Type:            tr.Type,
		PublicKey:       tr.PublicKey,
		Signature:       tr.Signature,
		Signer:          tr.Signer,
		SignerVersion:   int64(tr.SignerVersion),
		Timestamp:       &ts,
		TransactionHash: tr.TransactionHash,
	}
}

// messageResultFor renders a corpus trace as the v3 message result the
// extractor parses, in the same nesting Kermit returns.
func messageResultFor(tr corpusTrace) map[string]interface{} {
	sig := map[string]interface{}{
		"type":            tr.Type,
		"publicKey":       tr.PublicKey,
		"signature":       tr.Signature,
		"signer":          tr.Signer,
		"signerVersion":   float64(tr.SignerVersion),
		"timestamp":       float64(tr.Timestamp),
		"transactionHash": tr.TransactionHash,
	}
	// A delegated signature nests the signature it wraps and names the delegator,
	// outermost first - the shape Accumulate returns and the shape the extractor
	// has no vocabulary for.
	for i := len(tr.Delegators) - 1; i >= 0; i-- {
		sig = map[string]interface{}{
			"type":      "delegated",
			"delegator": tr.Delegators[i],
			"signature": sig,
		}
	}
	return map[string]interface{}{
		"message": map[string]interface{}{
			"type":      "signature",
			"txID":      "acc://" + tr.TransactionHash + "@" + tr.Principal,
			"signature": sig,
		},
	}
}
