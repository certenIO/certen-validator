package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The live cases are the accepted set plus the delegated ECDSA-inner case, so the day govsig's accepted set grows this
// fails until a live case exists for the new type.
func TestLiveCasesCoverAcceptedSet(t *testing.T) {
	have := map[protocol.SignatureType]bool{}
	delegated := 0
	for _, c := range liveCases() {
		if c.Delegated {
			delegated++
			if c.Type != protocol.SignatureTypeEcdsaSha256 {
				t.Errorf("the delegated case must have an ecdsaSha256 inner key, has %v", c.Type)
			}
			continue
		}
		have[c.Type] = true
	}
	for _, ty := range govsig.AcceptedKeyTypes() {
		if !have[ty] {
			t.Errorf("no live case for the accepted type %v", ty)
		}
	}
	if len(have) != len(govsig.AcceptedKeyTypes()) || delegated != 1 {
		t.Errorf("%d direct cases for %d accepted types, %d delegated cases", len(have), len(govsig.AcceptedKeyTypes()), delegated)
	}
}

// Accumulate refuses a transaction whose binary body is exactly 32 or 64 bytes ("body is 64 bytes long"; it would be
// indistinguishable from a transaction hash). CreateDataAccount for /data-btc and /data-eth hit 64 on Kermit, which cost a
// setup run; no case's data account may land on either length for any identity number.
func TestNoLiveDataAccountCreationHasAnAmbiguousBodyLength(t *testing.T) {
	for n := 1; n <= 999; n++ {
		adi := fmt.Sprintf("acc://pv2-sig-%d.acme", n)
		for _, c := range liveCases() {
			body := &protocol.CreateDataAccount{Url: mustURL(c.data(adi)), Authorities: []*url.URL{mustURL(c.book(adi))}}
			b, err := body.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if len(b) == 32 || len(b) == 64 {
				t.Errorf("%s: CreateDataAccount body is %d bytes - Accumulate refuses that length", c.data(adi), len(b))
			}
		}
	}
}

// The intent is the CERTEN four-blob shape and names the live anchor's own call: the batch path refused the first run's
// five-argument createBatchAnchor selector ("declared anchor is not the chain's live anchor", seen in the validators' logs).
func TestIntentIsFourBlobsAndDeclaresTheLiveAnchorCall(t *testing.T) {
	adi := "acc://pv2-sig-1.acme"
	for _, c := range liveCases() {
		in, err := buildIntent(adi, c, "0x3850C52C22Eb5ac1d727784DeFdCa7C5DB050389", testLeg(t, "base-sepolia"))
		if err != nil {
			t.Fatal(err)
		}
		var cc struct {
			Legs []struct {
				AnchorContract struct {
					FunctionSelector string `json:"functionSelector"`
					Address          string `json:"address"`
				} `json:"anchorContract"`
				ChainID int `json:"chainId"`
			} `json:"legs"`
		}
		if err := json.Unmarshal(in.Blobs[1], &cc); err != nil {
			t.Fatal(err)
		}
		if len(cc.Legs) != 1 || cc.Legs[0].ChainID != 84532 || !strings.EqualFold(cc.Legs[0].AnchorContract.Address, liveAnchorEnv["CERTEN_ANCHOR_V8_84532"]) {
			t.Fatalf("%s: legs %+v", c.Name, cc.Legs)
		}
		if got, want := cc.Legs[0].AnchorContract.FunctionSelector, "createBatchAnchor(bytes32,bytes32,uint256,bytes32,uint256,bytes32,bytes32)"; got != want {
			t.Errorf("%s: functionSelector %q, the live anchor takes %q", c.Name, got, want)
		}
		var gov struct {
			Authorization struct {
				Book string `json:"required_key_book"`
				Page string `json:"required_key_page"`
				Hash string `json:"authorization_hash"`
			} `json:"authorization"`
		}
		if err := json.Unmarshal(in.Blobs[2], &gov); err != nil {
			t.Fatal(err)
		}
		if gov.Authorization.Book != c.book(adi) || gov.Authorization.Page != c.page(adi) || gov.Authorization.Hash != in.OperationID {
			t.Errorf("%s: governance blob names %+v", c.Name, gov.Authorization)
		}
		for i, b := range in.Blobs {
			if !json.Valid(b) {
				t.Errorf("%s: blob %d is not JSON", c.Name, i)
			}
		}
	}
}
