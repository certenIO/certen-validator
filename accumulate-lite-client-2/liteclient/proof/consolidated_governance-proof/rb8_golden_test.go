// Copyright 2026 Certen Protocol

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// rb8GoldenFile is the SignatureData records this package wrote for ed25519 signatures at 979a03c, before RB8-B. It is a
// golden: it is never regenerated. New evidence gets a new file.
const rb8GoldenFile = "testdata/rb8_ed25519_signaturedata_979a03c.golden.json"

// rb8GoldenRecords extracts deterministic ed25519 signatures - a fixed seed, a fixed transaction, ed25519 being
// deterministic - and records exactly what ExtractSignatureFromMessageResult and VerifyAgainstAcceptedDigests produce.
// It uses only API that exists at 979a03c, so the golden could be produced there.
func rb8GoldenRecords(t *testing.T) []byte {
	t.Helper()
	seed := sha256.Sum256([]byte("rb8-b byte identity golden"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	k := sigfixture.Key{Type: protocol.SignatureTypeED25519, Priv: priv}
	type record struct {
		Case string        `json:"case"`
		Data SignatureData `json:"data"`
		Form string        `json:"form,omitempty"`
	}
	cases := []struct {
		name   string
		o      sigfixture.Opts
		verify bool
	}{
		{"direct", sigfixture.Opts{Timestamp: 1790000000000000, Version: 3, Signer: "acc://golden.acme/book/1"}, true},
		{"direct merkle", sigfixture.Opts{Timestamp: 1790000000000001, Version: 3, Signer: "acc://golden.acme/book/1", Merkle: true}, true},
		{"delegated two hops", sigfixture.Opts{Timestamp: 1790000000000002, Version: 3, Signer: "acc://golden.acme/book/1",
			Delegators: []string{"acc://outer.acme/book/1", "acc://middle.acme/book/1"}}, true},
		{"reject vote", sigfixture.Opts{Timestamp: 1790000000000003, Version: 3, Signer: "acc://golden.acme/book/1", Vote: protocol.VoteTypeReject}, false},
	}
	txn := sigfixture.Txn("acc://golden.acme/data", "rb8-b byte identity")
	var out []record
	for _, c := range cases {
		sig, err := sigfixture.Sign(k, txn, c.o)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := rb8Extract(t, sig, txn)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		r := record{Case: c.name, Data: sd}
		if c.verify {
			form, err := NewSignatureVerifier("").VerifyAgainstAcceptedDigests(sd, hex.EncodeToString(txn.GetHash()))
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			r.Form = form
		}
		out = append(out, r)
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every ed25519 record the fields describe completely is byte-identical to what 979a03c wrote: no raw, no innerType, the
// same digest form. This is the proof that adding the two omit-if-empty fields moves no hash that existed.
func TestRB8_Ed25519RecordsAreByteIdenticalToTheBase(t *testing.T) {
	want, err := os.ReadFile(rb8GoldenFile)
	if err != nil {
		t.Fatal(err)
	}
	got := rb8GoldenRecords(t)
	if string(got) != string(want) {
		t.Fatalf("the ed25519 SignatureData records changed from the 979a03c golden.\n--- want\n%s\n--- got\n%s", want, got)
	}
}
