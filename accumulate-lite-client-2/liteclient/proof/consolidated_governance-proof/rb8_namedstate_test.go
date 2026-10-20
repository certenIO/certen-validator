// Copyright 2026 Certen Protocol

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// A signature that cannot be judged is UNAVAILABLE evidence with the reason of the state that stopped it - never a
// rejection, because a rejection lets the threshold be computed over the remainder. Permanent states are not retried.
func TestRB8_NamedStatesAreUnavailableNeverRejected(t *testing.T) {
	for name, tc := range map[string]struct {
		err       error
		stage     string
		permanent bool
	}{
		"executor version unproven": {govsig.ExecutorVersionUnproven{Type: "ecdsaSha256", Partition: "bvn1", Block: 5}, "g1_executor_version_unproven", true},
		"gate not met":              {govsig.ExecutorGateNotMet{Type: "eth(der)"}, "executor_gate_not_met", true},
		"typedData, no transaction": {govsig.TransactionUnavailableForTypedData{}, "transaction_unavailable_for_typed_data", false},
		"typedData, no name":        {govsig.NetworkNameUnproven{}, "network_name_unproven", false},
		"routing unavailable":       {RoutingUnavailable{Err: errors.New("down")}, "compute-digest", false}, // an infrastructure outage: unavailable and retried
		"bytes absent":              {SignatureBytesAbsent{Type: "btc"}, "signature_bytes_absent", true},
		"undecodable":               {SignatureUndecodable{Type: "btc", Err: errors.New("x")}, "signature_undecodable", true},
		"fields disagree":           {SignatureFieldsDisagree{Field: "type"}, "signature_fields_disagree", true},
		"unsupported type":          {UnsupportedSignatureType{Type: "dsa"}, "unsupported-signature-type", true},
		"wrapped":                   {fmt.Errorf("verify: %w", govsig.ExecutorVersionUnproven{}), "g1_executor_version_unproven", true},
	} {
		res := classifyVerificationError(tc.err)
		if res.Outcome != SigUnavailable || res.Stage != tc.stage || res.Permanent != tc.permanent {
			t.Errorf("%s: outcome %v stage %q permanent %v; want unavailable %q permanent %v", name, res.Outcome, res.Stage, res.Permanent, tc.stage, tc.permanent)
		}
	}
	// a genuine rejection is a rejection
	for _, err := range []error{govsig.SignatureInvalid{Type: "ecdsaSha256", Forms: []string{"metadata"}}, govsig.TypedDataChainIDMismatch{Want: "1", Got: "2"},
		errors.New("signature verification failed against all 2 accepted digest form(s)")} {
		if res := classifyVerificationError(err); res.Outcome != SigRejected {
			t.Errorf("%v must be a rejection, got %v", err, res.Outcome)
		}
	}
}

// The gate through the verifier a G1 layer builds: before the activation of the signer page's partition it is the
// named state carrying the partition and block; routing that cannot be read is unavailable, not a guess; a verifier with
// no network at all cannot prove any gated type.
func TestRB8_VerifierAppliesTheGateWhereTheSignatureWasRecorded(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "gate")
	sd, err := rb8Extract(t, rb8Sign(t, rb8Key(t, protocol.SignatureTypeEcdsaSha256), txn, sigfixture.Opts{}), txn)
	if err != nil {
		t.Fatal(err)
	}
	part, err := rb8Network(t).Partition(sd.Signer)
	if err != nil {
		t.Fatal(err)
	}
	act := govsig.KermitActivations()[part].Block
	sv := rb8Verifier(t)

	_, err = sv.VerifySignature(ValidatedSignature{Signature: sd, Receipt: ReceiptData{LocalBlock: act - 1}}, rb8Hex(txn))
	var un govsig.ExecutorVersionUnproven
	if !errors.As(err, &un) || un.Block != act-1 || un.Partition != part || un.Type != "ecdsaSha256" {
		t.Fatalf("before the activation: %v", err)
	}
	if _, err := sv.VerifySignature(ValidatedSignature{Signature: sd, Receipt: ReceiptData{LocalBlock: act + 1}}, rb8Hex(txn)); err != nil {
		t.Fatalf("after the activation: %v", err)
	}
	if _, err := sv.VerifySignature(ValidatedSignature{Signature: sd}, rb8Hex(txn)); !errors.As(err, new(govsig.ExecutorVersionUnproven)) {
		t.Fatalf("no block recorded: %v", err)
	}
	if _, err := (&SignatureVerifier{}).VerifySignature(ValidatedSignature{Signature: sd, Receipt: ReceiptData{LocalBlock: act + 1}}, rb8Hex(txn)); !errors.As(err, new(govsig.ExecutorVersionUnproven)) {
		t.Fatalf("a verifier with no network cannot prove a gated type: %v", err)
	}
	down := &SignatureVerifier{network: func() (*govsig.Network, error) { return nil, errors.New("connection refused") }}
	_, err = down.VerifySignature(ValidatedSignature{Signature: sd, Receipt: ReceiptData{LocalBlock: act + 1}}, rb8Hex(txn))
	if !errors.As(err, new(RoutingUnavailable)) {
		t.Fatalf("routing that cannot be read: %v", err)
	}
	if res := classifyVerificationError(err); res.Outcome != SigUnavailable || res.Permanent {
		t.Fatalf("an outage is unavailable and retried: %+v", res)
	}
	// an always-registered type needs no network at all
	ed, err := rb8Extract(t, rb8Sign(t, rb8Key(t, protocol.SignatureTypeBTC), txn, sigfixture.Opts{}), txn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&SignatureVerifier{}).VerifySignature(ValidatedSignature{Signature: ed}, rb8Hex(txn)); err != nil {
		t.Fatalf("btc needs no gate: %v", err)
	}
}

// The superseded name list and the new classifier agree on every name the old one knew.
func TestRB8_NonKeyNamesAgreeWithGovsig(t *testing.T) {
	for name := range nonKeySignatureTypes {
		if _, class := govsig.Classify(name); class != govsig.ClassNotKey {
			t.Errorf("%q was a non-key name and govsig.Classify says %v", name, class)
		}
	}
}
