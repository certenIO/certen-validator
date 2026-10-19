// Copyright 2026 Certen Protocol

package main

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The ONLINE layer judges every shared conformance vector the way the vector - and so the offline evidence layer and the
// TypeScript verifier - judge it: from the signature JSON the network serves, through the extractor G1 uses.
func TestRB8_OnlineLayerAgreesWithEveryVector(t *testing.T) {
	vs, _, err := sigfixture.LoadVectors("../govsig/testdata/sigtypes")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Run(v.ID, func(t *testing.T) {
			got, keyHash := onlineVerdict(t, v)
			want := v.Expect.Verdict
			switch {
			case want == "accepted":
				if got != "accepted" || !strings.EqualFold(keyHash, v.Expect.KeyHash) {
					t.Fatalf("online %q (key hash %s), the vector expects accepted with %s", got, keyHash, v.Expect.KeyHash)
				}
			case strings.HasPrefix(want, "named:"):
				if got != want {
					t.Fatalf("online %q, the vector expects the named state %q", got, want)
				}
			default:
				// a refusal: the online layer may refuse EARLIER (a shape the type does not have) but must never accept,
				// and must refuse by name where the vector names a structural refusal.
				if got == "accepted" || strings.HasPrefix(got, "named:") {
					t.Fatalf("online %q, the vector expects the refusal %q", got, want)
				}
				if (want == "refused:not_a_key_signature" || want == "refused:delegation_depth_exceeded" || want == "refused:key_not_on_page") && got != want {
					t.Fatalf("online %q, expected %q", got, want)
				}
			}
		})
	}
}

// onlineVerdict runs one vector through ExtractSignatureFromMessageResult and the location-aware verifier.
func onlineVerdict(t *testing.T, v sigfixture.Vector) (string, string) {
	t.Helper()
	var obj map[string]interface{}
	if err := json.Unmarshal(v.SignatureJSON, &obj); err != nil {
		t.Fatal(err)
	}
	sv := &SignatureVerifier{}
	if v.Transaction != "" {
		tb, _ := hex.DecodeString(v.Transaction)
		txn := new(protocol.Transaction)
		if err := txn.UnmarshalBinary(tb); err != nil {
			t.Fatal(err)
		}
		sv.governed = func(string) (*protocol.Transaction, error) { return txn, nil }
	}
	table := &protocol.RoutingTable{Routes: []protocol.Route{{Length: 1, Value: 0, Partition: "BVN1"}, {Length: 1, Value: 1, Partition: "BVN2"}}}
	var block int64
	if v.Where != nil {
		block = v.Where.Block
		// route the signer's identity to the partition the vector names
		u, err := url.Parse(signerOf(obj))
		if err != nil {
			t.Fatal(err)
		}
		table.Overrides = append(table.Overrides, protocol.RouteOverride{Account: u.RootIdentity(), Partition: v.Where.Partition})
	}
	n, err := govsig.NewNetwork(v.NetworkName, table)
	if err != nil {
		t.Fatal(err)
	}
	sv.network = func() (*govsig.Network, error) { return n, nil }

	sd, err := sv.ExtractSignatureFromMessageResult(rb8MessageFromObject(obj, v.TxHash))
	if err != nil {
		return verdictOfOnline(err), ""
	}
	// the step classifyMessage takes before any verification: a signature covers THIS transaction or it is rejected
	if !sv.ValidateTransactionHash(sd, v.TxHash) {
		return "refused:other", ""
	}
	if _, err := sv.VerifySignature(ValidatedSignature{Signature: sd, Receipt: ReceiptData{LocalBlock: block}}, v.TxHash); err != nil {
		return verdictOfOnline(err), ""
	}
	kh, err := sv.KeyHashOf(sd)
	if err != nil {
		return "refused:other", ""
	}
	if v.Page != nil {
		member := false
		for _, e := range v.Page.Entries {
			member = member || strings.EqualFold(e, kh)
		}
		if !member {
			return "refused:key_not_on_page", kh
		}
	}
	return "accepted", kh
}

// signerOf is the innermost signer of a (possibly delegated) signature object.
func signerOf(obj map[string]interface{}) string {
	for {
		if s, ok := obj["signature"].(map[string]interface{}); ok && obj["type"] == "delegated" {
			obj = s
			continue
		}
		s, _ := obj["signer"].(string)
		return s
	}
}

func verdictOfOnline(err error) string {
	if _, ok := err.(NotAKeySignature); ok {
		return "refused:not_a_key_signature"
	}
	if _, ok := err.(DelegationDepthExceeded); ok {
		return "refused:delegation_depth_exceeded"
	}
	if v := govsig.Verdict(err); v != "refused:other" {
		return v
	}
	if reason, _, named := namedState(err); named {
		return "named:" + reason
	}
	return "refused:other"
}
