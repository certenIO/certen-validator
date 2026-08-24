// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Regression tests for classifier bugs found by running the system, not by
// reading it. Each pins the exact behaviour that was wrong.
//
// The shared failure mode: a string matcher written against error text I
// assumed, rather than the error text the code actually produces. Both
// directions of that mistake are dangerous - calling a rejection an outage
// wastes retries and destroys the cross-check; calling an outage a rejection
// is the original defect that cost nine proofs.
//
// These drive the REAL extractor so the strings cannot drift apart.

// buildMsgResult wraps a message body the way the v3 API returns it.
func buildMsgResult(msg interface{}) map[string]interface{} {
	return map[string]interface{}{"message": msg}
}

// BUG 1: isNotASignatureMessage was matched against invented strings
// ("not a signature", "missing signature", ...) and missed the real ones. On
// live Kermit an entry of type "authority" produced
//
//	Not an ed25519 signature (type: authority)
//
// which was classified SigUnavailable. The enumeration route was then marked
// unavailable, the two-route cross-check was lost, and three retries were burnt
// on a permanently non-signature entry.
func TestRegression_NonSignatureMessagesClassifyAsRejected(t *testing.T) {
	sv := NewSignatureVerifier("")

	// Entries a key page's P#signature chain legitimately carries. None is an
	// ed25519 transaction signature; every one is a REJECTION, not an outage.
	rejections := []struct {
		name string
		msg  interface{}
	}{
		{"authority signature (the live case)", map[string]interface{}{
			"type": "signature", "signature": map[string]interface{}{"type": "authority"}}},
		{"signatureRequest message", map[string]interface{}{"type": "signatureRequest"}},
		{"creditPayment message", map[string]interface{}{"type": "creditPayment"}},
		{"transaction message", map[string]interface{}{"type": "transaction"}},
		{"blockAnchor message", map[string]interface{}{"type": "blockAnchor"}},
		{"delegated signature", map[string]interface{}{
			"type": "signature", "signature": map[string]interface{}{"type": "delegated"}}},
		{"rcd1 signature", map[string]interface{}{
			"type": "signature", "signature": map[string]interface{}{"type": "rcd1"}}},
		{"btc signature", map[string]interface{}{
			"type": "signature", "signature": map[string]interface{}{"type": "btc"}}},
		{"signature with no payload", map[string]interface{}{"type": "signature"}},
		{"signature payload not an object", map[string]interface{}{
			"type": "signature", "signature": "not-an-object"}},
		{"signature payload with no type", map[string]interface{}{
			"type": "signature", "signature": map[string]interface{}{}}},
	}

	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sv.ExtractSignatureFromMessageResult(buildMsgResult(tc.msg))
			if err == nil {
				t.Fatal("expected extraction to fail on a non-ed25519 entry")
			}
			if !isNotASignatureMessage(err) {
				t.Fatalf("CRITICAL: %q classified as an OUTAGE.\n"+
					"A routine non-signature chain entry must be a REJECTION - misclassifying it "+
					"destroys the two-route cross-check and burns retries on a permanent condition.\n"+
					"error: %v", tc.name, err)
			}
		})
	}
}

// The other direction: a genuinely broken response must NOT be waved through as
// "just not a signature". Those are outages and must fail closed as such.
func TestRegression_BrokenResponsesClassifyAsOutage(t *testing.T) {
	sv := NewSignatureVerifier("")

	outages := []struct {
		name   string
		result map[string]interface{}
	}{
		{"no message object at all", map[string]interface{}{}},
		{"message is not an object", buildMsgResult("garbage")},
		{"message has no type", buildMsgResult(map[string]interface{}{"foo": "bar"})},
		{"message type is not a string", buildMsgResult(map[string]interface{}{"type": 42})},
	}

	for _, tc := range outages {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sv.ExtractSignatureFromMessageResult(tc.result)
			if err == nil {
				t.Fatal("expected extraction to fail")
			}
			if isNotASignatureMessage(err) {
				t.Fatalf("CRITICAL: a malformed response %q was classified as a routine REJECTION.\n"+
					"That is the original defect - an outage recorded as a governance verdict.\nerror: %v",
					tc.name, err)
			}
		})
	}
}

// A well-formed ed25519 signature message must extract cleanly, or the tests
// above prove only that everything fails.
func TestRegression_RealEd25519SignatureStillExtracts(t *testing.T) {
	sv := NewSignatureVerifier("")
	res := buildMsgResult(map[string]interface{}{
		"type": "signature",
		"signature": map[string]interface{}{
			"type":            "ed25519",
			"publicKey":       fixturePubKey,
			"signature":       fixtureSignature,
			"signer":          fixtureSigner,
			"signerVersion":   float64(0),
			"timestamp":       float64(fixtureTimestamp),
			"transactionHash": fixtureTxHash,
		},
	})
	sig, err := sv.ExtractSignatureFromMessageResult(res)
	if err != nil {
		t.Fatalf("a real ed25519 signature must extract: %v", err)
	}
	if !strings.EqualFold(sig.PublicKey, fixturePubKey) {
		t.Fatalf("public key drift: %s", sig.PublicKey)
	}
	if !strings.EqualFold(sig.TransactionHash, fixtureTxHash) {
		t.Fatalf("transaction hash drift: %s", sig.TransactionHash)
	}
}

// BUG 2: messageIDMatches trimmed the "acc://" prefix BEFORE lowercasing, so an
// uppercase scheme survived the trim and compared unequal to the same ID.
func TestRegression_MessageIDSchemeCaseInsensitive(t *testing.T) {
	id := "acc://" + h32(3) + "@example.acme/data"
	for _, variant := range []string{
		id,
		strings.ToUpper(id),
		strings.ToUpper("ACC://") + h32(3) + "@example.acme/data",
		"  " + id + "  ",
		strings.TrimPrefix(id, "acc://"),
	} {
		if !messageIDMatches(variant, id) {
			t.Fatalf("CRITICAL: %q did not match the same ID - scheme/case normalization is broken", variant)
		}
	}
	// And it must still reject a genuinely different ID.
	if messageIDMatches("acc://"+h32(4)+"@example.acme/data", id) {
		t.Fatal("CRITICAL: a different ENTRY_HASH matched")
	}
}

// BUG 3: the G2 payload query had no retry, and a transport outage was folded
// into PayloadVerification{Verified:false, GoVerifierErrors:"Transaction query
// failed: ..."} - which reads downstream as "the payload is wrong". Observed
// live during the backfill: a context deadline reported itself as "payload
// verification failed".
//
// Two things must hold now: a transient outage is retried, and a persistent one
// is returned as an ERROR so the caller reports unavailable evidence rather
// than a payload verdict.
func TestRegression_PayloadQueryOutageIsNotAPayloadVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	ep := os.Getenv("ACC_V3_ENDPOINT")
	if ep == "" {
		ep = faultV3Endpoint
	}

	// A G1 result good enough for the payload query: it needs the expanded
	// message ID and the expected transaction hash.
	g1res := &G1Result{}
	g1res.ExpandedMessageID = "acc://" + faultTxHash + "@" + strings.TrimPrefix(faultAccount, "acc://")
	g1res.TxHash = faultTxHash

	newG2 := func(failOn func(string, map[string]interface{}, int) bool) (*G2Layer, *faultyClient) {
		real := NewRPCClient(RPCConfig{Endpoint: ep, Timeout: 60 * time.Second, Backend: "http", UseHTTP: true})
		fc := &faultyClient{inner: real, failOn: failOn}
		am, err := NewArtifactManager(t.TempDir())
		if err != nil {
			t.Fatalf("artifact manager: %v", err)
		}
		return NewG2Layer(fc, am, "", "", "/nonexistent-verifier"), fc
	}

	t.Run("control: the payload query succeeds unfaulted", func(t *testing.T) {
		g2, _ := newG2(nil)
		raw, err := g2.queryRawTransactionJSONWithRetry(context.Background(), g1res)
		if err != nil {
			t.Fatalf("unfaulted payload query must succeed: %v", err)
		}
		if len(raw) == 0 {
			t.Fatal("expected transaction JSON")
		}
		t.Logf("control: got %d bytes of transaction JSON", len(raw))
	})

	t.Run("a transient outage is retried, not fatal", func(t *testing.T) {
		var once sync.Once
		var tripped bool
		g2, fc := newG2(func(string, map[string]interface{}, int) bool {
			fail := false
			once.Do(func() { fail = true; tripped = true })
			return fail
		})
		raw, err := g2.queryRawTransactionJSONWithRetry(context.Background(), g1res)
		if !tripped {
			t.Fatal("test setup: the fault never fired")
		}
		if err != nil {
			t.Fatalf("CRITICAL: a single transient outage killed the payload query: %v", err)
		}
		if len(raw) == 0 {
			t.Fatal("expected transaction JSON after retry")
		}
		calls, failed := fc.stats()
		t.Logf("recovered: %d/%d calls faulted", failed, calls)
	})

	t.Run("a persistent outage is an error, never a payload verdict", func(t *testing.T) {
		g2, fc := newG2(func(string, map[string]interface{}, int) bool { return true })

		// The retrying query must surface an error...
		if _, err := g2.queryRawTransactionJSONWithRetry(context.Background(), g1res); err == nil {
			t.Fatal("CRITICAL: a persistent outage produced no error")
		}

		// ...and verifyTransactionPayload must propagate it as an error rather
		// than returning a PayloadVerification the caller would read as
		// "payload failed verification".
		pv, err := g2.verifyTransactionPayload(context.Background(), g1res)
		if err == nil {
			t.Fatalf("CRITICAL: an outage was returned as a payload RESULT (verified=%v, errors=%q). "+
				"Downstream this reads as a failed payload, not unavailable evidence.",
				pv != nil && pv.Verified, func() string {
					if pv == nil {
						return ""
					}
					return pv.GoVerifierErrors
				}())
		}
		if pv != nil {
			t.Fatal("CRITICAL: an outage must not also produce a PayloadVerification")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "unavailable") {
			t.Fatalf("the outage must name itself as unavailable evidence, got: %v", err)
		}
		_, failed := fc.stats()
		t.Logf("rejected correctly after %d faulted calls: %s", failed, SafeTruncate(err.Error(), 200))
	})
}
