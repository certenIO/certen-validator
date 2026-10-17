// Copyright 2026 Certen Protocol

package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// typedData signs the EIP-712 encoding of the WHOLE transaction under the network's chain id. The online layer
// verifies it with the governed transaction G0 carried forward and the network's name, and says so by name when it
// has neither.

func rb8TypedVerifier(t testing.TB, txn *protocol.Transaction) *SignatureVerifier {
	t.Helper()
	sv := rb8Verifier(t)
	sv.governed = func(string) (*protocol.Transaction, error) { return txn, nil }
	return sv
}

func TestRB8_TypedDataIsVerifiedFromTheWholeTransaction(t *testing.T) {
	k := rb8Key(t, protocol.SignatureTypeTypedData)
	for nd := 0; nd <= 2; nd++ {
		txn := sigfixture.Txn("acc://probe.acme/data", "typed")
		sig := rb8Sign(t, k, txn, sigfixture.Opts{Delegators: []string{"acc://a.acme/book/1", "acc://b.acme/book/1"}[:nd]})
		sd, err := rb8Extract(t, sig, txn)
		if err != nil {
			t.Fatalf("delegators=%d: %v", nd, err)
		}
		if sd.Raw == "" {
			t.Fatal("a typedData record carries Accumulate's encoding: it cannot be rebuilt from its fields")
		}
		wantType, wantInner := "typeddata", ""
		if nd > 0 {
			wantType, wantInner = "delegated", "typeddata"
		}
		if sd.Type != wantType || sd.InnerType != wantInner {
			t.Fatalf("recorded %q/%q, want %q/%q", sd.Type, sd.InnerType, wantType, wantInner)
		}
		form, err := rb8Verify(t, rb8TypedVerifier(t, txn), sd, rb8Hex(txn))
		if err != nil || form != govsig.FormEIP712 {
			t.Fatalf("delegators=%d: form %q err %v", nd, form, err)
		}
	}
}

func TestRB8_TypedDataNamedStatesAndRefusals(t *testing.T) {
	k := rb8Key(t, protocol.SignatureTypeTypedData)
	txn := sigfixture.Txn("acc://probe.acme/data", "typed")
	other := sigfixture.Txn("acc://probe.acme/data", "a different transaction")
	sd, err := rb8Extract(t, rb8Sign(t, k, txn, sigfixture.Opts{}), txn)
	if err != nil {
		t.Fatal(err)
	}

	// no transaction at hand: the named state, not a rejection
	if _, err := rb8Verify(t, rb8Verifier(t), sd, rb8Hex(txn)); !errors.As(err, new(govsig.TransactionUnavailableForTypedData)) {
		t.Errorf("no governed transaction: %v", err)
	}
	if reason, _, named := namedState(err0(rb8Verify(t, rb8Verifier(t), sd, rb8Hex(txn)))); !named || reason != "transaction_unavailable_for_typed_data" {
		t.Errorf("namedState: %q %v", reason, named)
	}

	// a different transaction's body: the signature does not sign it
	if _, err := rb8Verify(t, rb8TypedVerifier(t, other), sd, rb8Hex(txn)); err == nil {
		t.Error("typedData verified over a different transaction")
	}

	// no network name: the named state
	sv := rb8TypedVerifier(t, txn)
	n := rb8Network(t)
	n.Name = ""
	sv.network = func() (*govsig.Network, error) { return n, nil }
	if _, err := rb8Verify(t, sv, sd, rb8Hex(txn)); !errors.As(err, new(govsig.NetworkNameUnproven)) {
		t.Errorf("no network name: %v", err)
	}

	// another network: the chain id differs
	n2 := rb8Network(t)
	n2.Name = "mainnet"
	sv.network = func() (*govsig.Network, error) { return n2, nil }
	if _, err := rb8Verify(t, sv, sd, rb8Hex(txn)); !errors.As(err, new(govsig.TypedDataChainIDMismatch)) {
		t.Errorf("another network: %v", err)
	}

	// signed under chain id 1: verifies cryptographically, refused for its chain id
	wrong, err := rb8Extract(t, rb8Sign(t, k, txn, sigfixture.Opts{ChainID: big.NewInt(1)}), txn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rb8Verify(t, rb8TypedVerifier(t, txn), wrong, rb8Hex(txn)); !errors.As(err, new(govsig.TypedDataChainIDMismatch)) {
		t.Errorf("chain id 1: %v", err)
	}

	// AcceptedDigests cannot form a digest from a hash for typedData
	if _, err := AcceptedDigests(sd, txn.Hash()); !errors.As(err, new(govsig.TransactionUnavailableForTypedData)) {
		t.Errorf("AcceptedDigests for typedData: %v", err)
	}
}

func err0(_ string, err error) error { return err }

// flipLastNibble changes the last hex digit whatever it is, so a tamper can never be a no-op on a random key or signature.
func flipLastNibble(h string) string {
	last := h[len(h)-1]
	if last == '0' {
		return h[:len(h)-1] + "1"
	}
	return h[:len(h)-1] + "0"
}

// The raw encoding is the ONE source: every field beside it must agree, and a tampered record is a named state.
func TestRB8_RawIsCheckedAgainstEveryField(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "raw")
	k := rb8Key(t, protocol.SignatureTypeEcdsaSha256)
	good, err := rb8Extract(t, rb8Sign(t, k, txn, sigfixture.Opts{Delegators: []string{"acc://a.acme/book/1"}}), txn)
	if err != nil {
		t.Fatal(err)
	}
	if good.Raw == "" || good.Type != "delegated" || good.InnerType != "ecdsasha256" {
		t.Fatalf("record %q/%q raw=%v", good.Type, good.InnerType, good.Raw != "")
	}
	ts := int64(5)
	for field, mutate := range map[string]func(*SignatureData){
		"type":          func(s *SignatureData) { s.Type = "ed25519" },
		"innerType":     func(s *SignatureData) { s.InnerType = "rsasha256" },
		"publicKey":     func(s *SignatureData) { s.PublicKey = flipLastNibble(s.PublicKey) },
		"signature":     func(s *SignatureData) { s.Signature = flipLastNibble(s.Signature) },
		"signer":        func(s *SignatureData) { s.Signer = "acc://other.acme/book/1" },
		"signerVersion": func(s *SignatureData) { s.SignerVersion += 1 },
		"timestamp":     func(s *SignatureData) { s.Timestamp = &ts },
		"vote":          func(s *SignatureData) { s.Vote = "reject" },
		"chain":         func(s *SignatureData) { s.Chain = nil },
		"chain[0]":      func(s *SignatureData) { s.Chain = []SignerLink{{Delegator: "acc://z.acme/book/1"}} },
	} {
		bad := good
		bad.Chain = append([]SignerLink(nil), good.Chain...)
		mutate(&bad)
		_, err := buildProtocolSignature(bad)
		var d SignatureFieldsDisagree
		if !errors.As(err, &d) || d.Field != field {
			t.Errorf("tampering %s: want signature_fields_disagree{%s}, got %v", field, field, err)
		}
	}
	// undecodable raw bytes
	bad := good
	bad.Raw = "zz"
	if _, err := buildProtocolSignature(bad); !errors.As(err, new(SignatureUndecodable)) {
		t.Errorf("raw that is not hex: %v", err)
	}
	bad.Raw = "0102030405"
	if _, err := buildProtocolSignature(bad); !errors.As(err, new(SignatureUndecodable)) {
		t.Errorf("raw that is not a signature: %v", err)
	}
	// a non-ed25519 record with no raw is the named state, not an ed25519 mis-read
	bad = good
	bad.Raw = ""
	if _, err := buildProtocolSignature(bad); !errors.As(err, new(SignatureBytesAbsent)) {
		t.Errorf("no raw: %v", err)
	}
	bare := SignatureData{Type: "ecdsasha256", PublicKey: good.PublicKey, Signature: good.Signature, Signer: good.Signer}
	if _, err := buildProtocolSignature(bare); !errors.As(err, new(SignatureBytesAbsent)) {
		t.Errorf("a bare ecdsa record: %v", err)
	}
	// each named state is unavailable evidence by its reason code
	for _, e := range []error{SignatureBytesAbsent{Type: "btc"}, SignatureUndecodable{Type: "btc", Err: errors.New("x")},
		SignatureFieldsDisagree{Field: "type"}, govsig.ExecutorVersionUnproven{}, govsig.NetworkNameUnproven{},
		govsig.TransactionUnavailableForTypedData{}, RoutingUnavailable{Err: errors.New("x")}} {
		if reason, _, named := namedState(fmt.Errorf("wrapped: %w", e)); !named || reason == "" {
			t.Errorf("%T is not a named state", e)
		}
	}
	if _, _, named := namedState(errors.New("signature verification failed")); named {
		t.Error("a genuine rejection is not a named state")
	}
}

// Records that the fields describe completely carry no raw and no innerType, so the shape hashed into the govRoot for
// every ed25519 signature is what it was before RB8-B; an ed25519 signature carrying memo or data cannot be described by
// the fields and carries raw.
func TestRB8_RawIsCarriedExactlyWhenTheFieldsCannotRebuildTheSignature(t *testing.T) {
	txn := sigfixture.Txn("acc://probe.acme/data", "when")
	ed := rb8Key(t, protocol.SignatureTypeED25519)
	for name, tc := range map[string]struct {
		o       sigfixture.Opts
		wantRaw bool
	}{
		"plain":                {sigfixture.Opts{}, false},
		"delegated":            {sigfixture.Opts{Delegators: []string{"acc://a.acme/book/1", "acc://b.acme/book/1"}}, false},
		"reject vote":          {sigfixture.Opts{Vote: protocol.VoteTypeReject}, false},
		"abstain vote":         {sigfixture.Opts{Vote: protocol.VoteTypeAbstain}, false},
		"memo":                 {sigfixture.Opts{Memo: "m"}, true},
		"data":                 {sigfixture.Opts{Data: []byte{1}}, true},
		"delegated with memo":  {sigfixture.Opts{Memo: "m", Delegators: []string{"acc://a.acme/book/1"}}, true},
		"merkle initiator":     {sigfixture.Opts{Merkle: true}, false},
		"delegated + rejected": {sigfixture.Opts{Vote: protocol.VoteTypeReject, Delegators: []string{"acc://a.acme/book/1"}}, false},
	} {
		sd, err := rb8Extract(t, rb8Sign(t, ed, txn, tc.o), txn)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (sd.Raw != "") != tc.wantRaw {
			t.Errorf("%s: raw carried=%v, want %v", name, sd.Raw != "", tc.wantRaw)
		}
		if sd.InnerType != "" {
			t.Errorf("%s: an ed25519 record must not carry innerType, got %q", name, sd.InnerType)
		}
	}
	for _, ty := range []protocol.SignatureType{protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeRCD1, protocol.SignatureTypeBTC,
		protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH, protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256} {
		sd, err := rb8Extract(t, rb8Sign(t, rb8Key(t, ty), txn, sigfixture.Opts{}), txn)
		if err != nil || sd.Raw == "" {
			t.Errorf("%v: raw carried=%v err=%v; every non-ed25519 key type carries Accumulate's encoding", ty, sd.Raw != "", err)
		}
	}
	_ = rand.Reader
}
