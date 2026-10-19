// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// C5-D3, end to end on real bytes: G1 over the five live Kermit transactions of the delegation fixtures, replayed from
// the exact exchanges recorded off the network (testdata/g1_delegation, recorded by g1_record_fixtures_test.go).
//
// Four of the five put the delegation on a page of an authority book OTHER than the page G1 is asked about (the
// principal's second authority - a bank - delegates to a custodian), which the enumeration route did not follow, so the
// signatureSet route found the delegated signature and the enumeration route did not and G1 refused the proof as a
// route disagreement. The fifth has no delegation and must be unchanged.

type delegationFixture struct {
	name        string
	description string
	account     string
	txHash      string
	keyPage     string

	// delegatedSigner is the page whose key made the delegated signature, "" for none; chainLen how many delegators
	// the signature carries (the executor accepts at most 20).
	delegatedSigner string
	chainLen        int
}

var delegationFixtures = []delegationFixture{
	{
		name: "depth1_three_partitions_537",
		description: "Kermit pv2-cust-537: authorities cust-537/book and bank-537/book; bank-537/book/1 holds only a delegate " +
			"entry to deleg-537/book-d1; the signature is delegated (signer deleg-537/book-d1/1, delegator bank-537/book/1)",
		account:         "acc://pv2-cust-537.acme/data",
		txHash:          "79fcf0be89a0532366b8c2742b3e89823904830decd0ed807f017bfb165f595c",
		keyPage:         "acc://pv2-cust-537.acme/book/1",
		delegatedSigner: "acc://pv2-deleg-537.acme/book-d1/1",
		chainLen:        1,
	},
	{
		name: "depth2_515",
		description: "Kermit pv2-cust-515: bank-515/book/1 delegates to deleg-515/book-d1, whose page delegates to " +
			"deleg-511/book-d2; the signer is deleg-511/book-d2/1",
		account:         "acc://pv2-cust-515.acme/data",
		txHash:          "62688d88fd3adbdae6322f2c435f25bc506adee9231f98a7845aea6ab4158071",
		keyPage:         "acc://pv2-cust-515.acme/book/1",
		delegatedSigner: "acc://pv2-deleg-511.acme/book-d2/1",
		chainLen:        2,
	},
	{
		name: "depth20_532",
		description: "Kermit pv2-cust-532: bank-532/book/1 starts a chain of twenty delegators across deleg-532, deleg-502 " +
			"and deleg-518; the signer is deleg-518/book-d20/1 (the executor's DelegationDepthLimit)",
		account:         "acc://pv2-cust-532.acme/data",
		txHash:          "a19dfa46db1ff057f66c0fc9d1a29693e5c8c31fd3c665b5a74816876831c40a",
		keyPage:         "acc://pv2-cust-532.acme/book/1",
		delegatedSigner: "acc://pv2-deleg-518.acme/book-d20/1",
		chainLen:        20,
	},
	{
		name: "depth1_same_partition_555",
		description: "Kermit pv2-cust-555 (all three identities on BVN2: the defect is not cross-partition specific): " +
			"bank-555/book/1 delegates to deleg-555/book-d1",
		account:         "acc://pv2-cust-555.acme/data",
		txHash:          "78ef78b1950d45d96f15aae7a519822b6a50036ead5f4f6c93e49a92473129dd",
		keyPage:         "acc://pv2-cust-555.acme/book/1",
		delegatedSigner: "acc://pv2-deleg-555.acme/book-d1/1",
		chainLen:        1,
	},
	{
		name: "control_cross_partition_no_delegation_508",
		description: "Kermit pv2-cust-508: cross-partition, cross-identity authorities and no delegation; both routes agreed " +
			"before the fix and must still",
		account: "acc://pv2-cust-508.acme/data",
		txHash:  "51027af8e1108e38f36edb47fa29693eb1d75864d4c645a28f5f014e59ea522b",
		keyPage: "acc://pv2-cust-508.acme/book/1",
	},
}

func proveReplayed(t *testing.T, fx delegationFixture, rewrite func(scope string, query map[string]interface{}, raw []byte) []byte) (*G1Result, *replayClient, error) {
	t.Helper()
	capture := loadCapture(t, fx.name+".json.gz")
	if capture.TxHash != fx.txHash || capture.Account != fx.account || capture.KeyPage != fx.keyPage {
		t.Fatalf("capture %s is for %s %s %s, not the fixture's", fx.name, capture.Account, capture.TxHash, capture.KeyPage)
	}
	rc := newReplayClient(t, capture)
	rc.rewrite = rewrite
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatalf("artifact manager: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := NewG1Layer(rc, am, "").ProveG1(ctx, G1Request{
		G0Request: G0Request{Account: fx.account, TxHash: fx.txHash, Chain: "main"}, KeyPage: fx.keyPage})
	return res, rc, err
}

// Both routes find the same signatures and G1 holds: the delegated signature is counted, it is the one the fixture says,
// and the proof is neither refused nor degraded.
func TestG1DelegationReplay_BothRoutesAgreeOnTheLiveTransactions(t *testing.T) {
	for _, fx := range delegationFixtures {
		t.Run(fx.name, func(t *testing.T) {
			res, rc, err := proveReplayed(t, fx, nil)
			if err != nil {
				t.Fatalf("G1 over the live transaction must hold: %v", err)
			}
			rc.requireNoUnrecorded(t)
			st := res.SignatureRouteStatus
			if st == nil || !st.RoutesAgreed || st.Degraded {
				t.Fatalf("both routes must run, agree and not degrade: %+v", st)
			}
			if !res.ThresholdSatisfied {
				t.Fatal("the authority threshold must be satisfied")
			}
			if len(res.ValidatedSignatures) != 2 {
				t.Fatalf("counted %d signatures, want the principal's and one more", len(res.ValidatedSignatures))
			}
			var delegated []ValidatedSignature
			for _, v := range res.ValidatedSignatures {
				if v.Signature.IsDelegated() {
					delegated = append(delegated, v)
				}
			}
			if fx.delegatedSigner == "" {
				if len(delegated) != 0 {
					t.Fatalf("the control carries %d delegated signatures", len(delegated))
				}
				return
			}
			if len(delegated) != 1 {
				t.Fatalf("counted %d delegated signatures, want 1", len(delegated))
			}
			d := delegated[0].Signature
			if normalizeAccURL(d.Signer) != normalizeAccURL(fx.delegatedSigner) || len(d.Chain) != fx.chainLen {
				t.Fatalf("delegated signature by %s through %d delegator(s); want %s through %d",
					d.Signer, len(d.Chain), fx.delegatedSigner, fx.chainLen)
			}
		})
	}
}

// The cross-check is still a cross-check: when the enumeration route genuinely does not see a signature the
// signatureSet route does, the routes disagree and G1 fails closed. The signatureSet route does not win.
//
// The delegated signer's page is served with an empty signature chain, which the enumeration route reads as "that page
// did not sign" - a real disagreement about real bytes.
func TestG1DelegationReplay_ARealDisagreementStillFailsClosed(t *testing.T) {
	fx := delegationFixtures[0]
	page := strings.TrimPrefix(fx.delegatedSigner, "acc://")
	hideSignatures := func(scope string, query map[string]interface{}, raw []byte) []byte {
		if !strings.EqualFold(strings.TrimPrefix(scope, "acc://"), page) || query["name"] != "signature" {
			return raw
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return raw
		}
		res, _ := resp["result"].(map[string]interface{})
		if res == nil || res["recordType"] != "chain" {
			return raw
		}
		res["count"] = float64(0)
		out, _ := json.Marshal(resp)
		return out
	}
	_, _, err := proveReplayed(t, fx, hideSignatures)
	if err == nil {
		t.Fatal("an enumeration route that does not see the delegated signature must make G1 fail, not pass")
	}
	var dis *RouteDisagreement
	if !asRouteDisagreement(err, &dis) {
		t.Fatalf("expected a fail-closed route disagreement, got: %v", err)
	}
	if dis.RouteA != routeSignatureSet || len(dis.OnlyInA) != 1 || len(dis.OnlyInB) != 0 {
		t.Fatalf("the signatureSet route must be the only one holding the delegated signature: %+v", dis)
	}
}
