// Copyright 2026 Certen Protocol

package govsig_test

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// A delegated typedData signature with no delegator makes Accumulate's own NewEIP712Call dereference a nil Delegator
// (protocol/signature_eip712.go:110). The executor never records such a signature, so it can never count, but a
// validator that crashes on it is a remote crash. It must be a named refusal and the process must keep running.
func TestRB8_AccumulatePanicOnAMalformedSignatureIsANamedRefusalNotACrash(t *testing.T) {
	k, err := sigfixture.NewKey(protocol.SignatureTypeTypedData, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	txn := sigfixture.Txn("acc://probe.acme/data", "malformed")
	inner, err := sigfixture.Sign(k, txn, sigfixture.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	bad := &protocol.DelegatedSignature{Signature: inner, Delegator: nil}
	env := govsig.Env{TxHash: txn.Hash(), Transaction: txn, NetworkName: "DevNet", Where: kourou}

	_, verr := govsig.Verify(bad, env)
	if verr == nil {
		t.Fatal("a delegated typedData signature with no delegator was accepted")
	}
	if got := govsig.Verdict(verr); got != "refused:signature_malformed" {
		t.Fatalf("verdict %q (%v), want refused:signature_malformed", got, verr)
	}
	var mal govsig.SignatureMalformed
	if !errors.As(verr, &mal) {
		t.Fatalf("error %T is not a SignatureMalformed", verr)
	}
}
