// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"encoding/hex"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Phase 7, Gate 2 - digest parity with accumulate-core.
//
// PHASE7_RUNBOOK.md: "Gate 2 (digest parity) is the one everything else rests
// on - if it is not green, nothing after it means anything."
//
// The claim being tested is narrow and total: for EVERY corpus signature, the
// set of digests AcceptedDigests produces contains the digest accumulate-core
// actually verified against. Not "matches for the cases we thought about" -
// every one, including the refusal cases, whose signatures are cryptographically
// valid even where the governance decision is to refuse them.
//
// The expected digests are in the corpus, computed by cmd/p7corpus with
// protocol.VerifyUserSignature. Nothing in this file decides what is correct.

func corpusTxHash(t *testing.T, tr corpusTrace) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(tr.TransactionHash)
	if err != nil || len(b) != 32 {
		t.Fatalf("%s: transaction hash is not 32 bytes of hex", tr.Label)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// corpusSignatureData renders a trace as the SignatureData the verifier
// consumes, delegation chain included. This is the shape Phase 2 added, so
// unlike signatureDataFor in the Gate 1 tests it carries the chain.
func corpusSignatureData(tr corpusTrace) SignatureData {
	ts := int64(tr.Timestamp)
	sig := SignatureData{
		Type:            tr.Type,
		PublicKey:       tr.PublicKey,
		Signature:       tr.Signature,
		Signer:          tr.Signer,
		SignerVersion:   int64(tr.SignerVersion),
		Timestamp:       &ts,
		TransactionHash: tr.TransactionHash,
	}
	for _, d := range tr.Delegators {
		sig.Chain = append(sig.Chain, SignerLink{Delegator: d})
	}
	return sig
}

// TestP7_DigestParity is Gate 2.
func TestP7_DigestParity(t *testing.T) {
	cf := loadCorpus(t)

	var checked, merkleMatched int
	for _, tr := range cf.Traces {
		if tr.KeyType != "ed25519" {
			// A non-ed25519 signature has no digest of ours to compare: it is
			// refused on its type before any digest is computed. That refusal is
			// Gate 3's subject, and TestP7_UnsupportedTypeIsRefusedByItsOwnReason
			// below checks it here so the case is not silently skipped.
			continue
		}
		if tr.Digest == "" {
			t.Errorf("%s: the corpus records no accepted digest for an ed25519 signature "+
				"accumulate-core verdicted %t - the corpus is incomplete", tr.Label, tr.CoreVerdict)
			continue
		}
		checked++

		t.Run(tr.Label, func(t *testing.T) {
			digests, err := AcceptedDigests(corpusSignatureData(tr), corpusTxHash(t, tr))
			if err != nil {
				t.Fatalf("AcceptedDigests: %v", err)
			}

			var found string
			for _, d := range digests {
				if hex.EncodeToString(d.Digest) == tr.Digest {
					found = d.Form
					break
				}
			}
			if found == "" {
				forms := make([]string, 0, len(digests))
				for _, d := range digests {
					forms = append(forms, d.Form+"="+hex.EncodeToString(d.Digest)[:16])
				}
				t.Fatalf("our digest set does not contain the digest accumulate-core accepted.\n"+
					" core accepted %s (%s form)\n ours: %v",
					tr.Digest[:16], tr.DigestForm, forms)
			}

			// Agreeing on the value but disagreeing on WHICH form produced it
			// would mean the two forms had collided, which cannot happen for
			// distinct preimages - so a mismatch here is a labelling bug that
			// would make the recorded evidence wrong.
			if found != tr.DigestForm {
				t.Fatalf("digest matches but under the wrong form: we call it %q, "+
					"accumulate-core used %q", found, tr.DigestForm)
			}
			if found == DigestFormMerkle {
				merkleMatched++
			}
		})
	}

	if checked == 0 {
		t.Fatal("no ed25519 signature was checked - Gate 2 tested nothing")
	}
	// Gate 2's second condition: at least one case valid ONLY under the merkle
	// form. Without it the second half of AcceptedDigests is unexecuted code.
	if merkleMatched == 0 {
		t.Fatal("no corpus signature matched under the Initiator() merkle form. " +
			"PHASE7_RUNBOOK.md Gate 2 requires at least one, or defect D4 is unfixed and untested")
	}
	t.Logf("Gate 2: %d signatures agree with accumulate-core, %d under the merkle form",
		checked, merkleMatched)
}

// TestP7_DigestParity_DelegationIsInTheDigest is the negative control on Gate 2.
//
// Matching digests prove agreement; they do not prove the delegation chain is
// what made them agree. If AcceptedDigests ignored the chain, a delegated
// signature would produce the same digest as a bare one and the test above
// would still pass. This shows that changing the chain changes the digest, so
// the chain really is inside the signed bytes.
func TestP7_DigestParity_DelegationIsInTheDigest(t *testing.T) {
	cf := loadCorpus(t)

	var checked int
	for _, tr := range cf.Traces {
		if tr.KeyType != "ed25519" || len(tr.Delegators) == 0 {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			txHash := corpusTxHash(t, tr)
			base := corpusSignatureData(tr)

			good, err := AcceptedDigests(base, txHash)
			if err != nil {
				t.Fatalf("AcceptedDigests: %v", err)
			}

			mutations := map[string]func(*SignatureData){
				"chain removed": func(s *SignatureData) { s.Chain = nil },
				"one delegator changed": func(s *SignatureData) {
					s.Chain[0].Delegator = "acc://not-the-delegator.acme/book/1"
				},
			}
			if len(base.Chain) > 1 {
				mutations["chain reversed"] = func(s *SignatureData) {
					for i, j := 0, len(s.Chain)-1; i < j; i, j = i+1, j-1 {
						s.Chain[i], s.Chain[j] = s.Chain[j], s.Chain[i]
					}
				}
			}

			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					mutated := corpusSignatureData(tr)
					mutate(&mutated)

					got, err := AcceptedDigests(mutated, txHash)
					if err != nil {
						return // refusing outright is also fail-closed
					}
					for _, g := range got {
						for _, w := range good {
							if g.Form == w.Form && hex.EncodeToString(g.Digest) == hex.EncodeToString(w.Digest) {
								t.Fatalf("%q produced the unmutated %s digest - the delegation "+
									"chain is NOT in the digest, and every delegated signature "+
									"would verify against the wrong path", name, g.Form)
							}
						}
					}
				})
			}
		})
	}
	if checked == 0 {
		t.Fatal("no delegated signature to mutate - this control tested nothing")
	}
}

// TestP7_UnsupportedTypeIsRefusedByItsOwnReason is runbook rule 7.
//
// A signature type we cannot verify must be refused with a reason of its own.
// Refusing it as "invalid" or dropping it silently shrinks the counted set,
// which reads as an unmet threshold, which reads as "the institution did not
// authorize this" - and the corpus's case K is a signature Kermit DELIVERED, so
// that reading would be flatly wrong.
func TestP7_UnsupportedTypeIsRefusedByItsOwnReason(t *testing.T) {
	cf := loadCorpus(t)

	var checked int
	for _, tr := range cf.Traces {
		if tr.KeyType == "ed25519" {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			if !tr.CoreVerdict {
				t.Fatalf("case %s is meant to be a signature that is VALID and unsupported; "+
					"accumulate-core does not accept it, so it cannot distinguish "+
					"'unsupported' from 'invalid'", tr.Case)
			}

			_, err := AcceptedDigests(corpusSignatureData(tr), corpusTxHash(t, tr))
			if err == nil {
				t.Fatalf("a %s signature produced digests - it must be refused on its type",
					tr.KeyType)
			}
			u, ok := IsUnsupportedSignatureType(err)
			if !ok {
				t.Fatalf("refused, but not with the unsupported-type reason: %v", err)
			}
			if u.Reason() != "unsupported-signature-type" {
				t.Fatalf("unexpected reason code %q", u.Reason())
			}
			if u.Type != tr.KeyType {
				t.Fatalf("reason names type %q, signature is %q", u.Type, tr.KeyType)
			}
			t.Logf("%s refused: %v", tr.KeyType, err)
		})
	}
	if checked == 0 {
		t.Fatal("no unsupported-type signature in the corpus - rule 7 is untested")
	}
}

// TestP7_DepthLimitIsAccumulatesNumber checks the bound is protocol's, not ours,
// and that it refuses with its own reason rather than as a bad signature.
//
// Kermit refuses corpus case G at submission with "delegated signature exceeded
// the depth limit (20)". We must refuse the same chain, for the same reason.
//
// The refusal is tested where it lives: the EXTRACTOR, which is what turns an
// untrusted response into a chain and so is the place an unbounded walk would
// happen. AcceptedDigests deliberately has no depth check - see the note in
// buildProtocolSignature - and the parity test above proves we still compute the
// same digest accumulate-core did for this signature. Refusing something we can
// read is a much stronger position than refusing something we cannot.
func TestP7_DepthLimitIsAccumulatesNumber(t *testing.T) {
	cf := loadCorpus(t)
	sv := &SignatureVerifier{}

	var checked int
	for _, tr := range cf.Traces {
		if tr.RefusalKind != "depth-limit" {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			_, err := sv.ExtractSignatureFromMessageResult(messageResultFor(tr))
			if err == nil {
				t.Fatalf("a %d-deep delegation chain was extracted", len(tr.Delegators))
			}
			d, ok := err.(DelegationDepthExceeded)
			if !ok {
				t.Fatalf("refused, but not with the depth reason: %v", err)
			}
			if d.Limit != protocol.DelegationDepthLimit {
				t.Fatalf("the bound is %d, not Accumulate's %d", d.Limit, protocol.DelegationDepthLimit)
			}
			t.Logf("refused: %v", err)
		})
	}
	if checked == 0 {
		t.Fatal("the corpus has no over-depth case, so the bound is untested")
	}
}

// TestP7_ExtractorReadsDelegation proves the parser and the digest agree.
//
// Gate 2 is about digests, but a correct digest built from a chain the extractor
// never populated is worth nothing: the chain has to survive the journey from
// the v3 response into SignatureData. This runs each corpus trace through the
// real extractor and checks the chain it recovers is the one that was signed.
func TestP7_ExtractorReadsDelegation(t *testing.T) {
	cf := loadCorpus(t)
	sv := &SignatureVerifier{}

	var checked int
	for _, tr := range cf.Traces {
		if tr.KeyType != "ed25519" {
			continue
		}
		if tr.RefusalKind == "depth-limit" {
			// The extractor refuses this one by design, which is its own test
			// (TestP7_DepthLimitIsAccumulatesNumber). Its digest parity is still
			// checked, by TestP7_DigestParity.
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			got, err := sv.ExtractSignatureFromMessageResult(messageResultFor(tr))
			if err != nil {
				t.Fatalf("extraction failed: %v", err)
			}
			chain := got.DelegatorChain()
			if len(chain) != len(tr.Delegators) {
				t.Fatalf("recovered %d delegator(s), signature has %d", len(chain), len(tr.Delegators))
			}
			for i := range chain {
				if chain[i] != tr.Delegators[i] {
					t.Fatalf("delegator %d is %q, expected %q - the ORDER is inside the digest, "+
						"so a reordered chain is a different signature", i, chain[i], tr.Delegators[i])
				}
			}

			// And the extracted signature must produce the digest that was
			// accepted - the end-to-end claim, response bytes to digest.
			digests, err := AcceptedDigests(got, corpusTxHash(t, tr))
			if err != nil {
				t.Fatalf("AcceptedDigests on the extracted signature: %v", err)
			}
			for _, d := range digests {
				if hex.EncodeToString(d.Digest) == tr.Digest {
					return
				}
			}
			t.Fatalf("the extracted signature does not produce the accepted digest %s", tr.Digest[:16])
		})
	}
	if checked == 0 {
		t.Fatal("no ed25519 signature was extracted - this tested nothing")
	}
}
