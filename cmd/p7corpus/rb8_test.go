package main

import (
	"encoding/hex"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB8-B: the capture program makes, registers and classifies a signature of every key-signature type Accumulate's
// executor accepts, and its multi-leg capture no longer skips every type but ed25519.

func rb8Seeds() map[string]string {
	return map[string]string{"x1": "0101010101010101010101010101010101010101010101010101010101010101"}
}

func TestRB8_CorpusBuildsAndClassifiesEveryAcceptedType(t *testing.T) {
	for _, ty := range govsig.AcceptedKeyTypes() {
		for _, delegators := range [][]string{nil, {"acc://outer.acme/book/1"}} {
			for _, initiator := range []bool{true, false} {
				txn := sigfixture.Txn("acc://p.acme/data", "corpus "+ty.String())
				sp := signaturePlan{Seed: "x1", SignerPage: "acc://p.acme/book/1", Type: ty, Delegators: delegators}
				sig, err := buildSignature(rb8Seeds(), sp, 2, 1790000000000000, txn, initiator)
				if err != nil {
					t.Fatalf("%v: build: %v", ty, err)
				}
				var h [32]byte
				copy(h[:], txn.GetHash())
				verdict, form, _, err := classifyTxn(sig, h, txn)
				if err != nil || !verdict {
					t.Fatalf("%v initiator=%v delegators=%d: accumulate-core's verdict is %v (%v)", ty, initiator, len(delegators), verdict, err)
				}
				if form == "" || form == formNone && ty != protocol.SignatureTypeED25519 {
					t.Errorf("%v: no digest form recorded (%q)", ty, form)
				}
				ks, path, err := innerKeySig(sig)
				if err != nil || ks.Type() != ty || len(path) != len(delegators) {
					t.Fatalf("%v: inner %v path %d err %v", ty, ks.Type(), len(path), err)
				}
				if initiator {
					if ok, _ := protocol.SignatureDidInitiate(sig, txn.Header.Initiator[:], nil); !ok {
						t.Errorf("%v: the signature is not the transaction's initiator", ty)
					}
				}
				// the page entry ensureKeyRegistered writes is the signature's own key hash
				k, err := keyOfType(rb8Seeds(), "x1", ty)
				if err != nil {
					t.Fatal(err)
				}
				pub, _ := sigfixture.PublicKey(k)
				want, _ := protocol.PublicKeyHash(pub, ty)
				if hex.EncodeToString(want) != hex.EncodeToString(ks.GetPublicKeyHash()) {
					t.Errorf("%v: registered key hash %x, signature's %x", ty, want, ks.GetPublicKeyHash())
				}
			}
		}
	}
}

// Without the transaction a typedData verdict is false - the defect the RB8-A finding names - and with it, true.
func TestRB8_TypedDataVerdictNeedsTheTransaction(t *testing.T) {
	txn := sigfixture.Txn("acc://p.acme/data", "typed")
	sig, err := buildSignature(rb8Seeds(), signaturePlan{Seed: "x1", SignerPage: "acc://p.acme/book/1", Type: protocol.SignatureTypeTypedData}, 1, 5, txn, true)
	if err != nil {
		t.Fatal(err)
	}
	var h [32]byte
	copy(h[:], txn.GetHash())
	if _, _, _, err := classify(sig, h); err == nil {
		t.Error("classify with a bare hash must refuse to judge a typedData signature, not call it invalid")
	}
	if v, _, _, err := classifyTxn(sig, h, txn); err != nil || !v {
		t.Errorf("classifyTxn: %v %v", v, err)
	}
}

func TestRB8_CaptureFilterIsTheAcceptedSet(t *testing.T) {
	for _, name := range append(govsig.AcceptedKeyTypeNames(), "delegated", "ECDSASHA256") {
		if !capturesVote(name) {
			t.Errorf("%s is a vote and must be captured", name)
		}
	}
	for _, name := range []string{"authority", "partition", "receipt", "signatureRequest", "creditPayment", "", "blsSignature"} {
		if capturesVote(name) {
			t.Errorf("%q is not a vote", name)
		}
	}
	if _, err := keyOfType(rb8Seeds(), "x1", protocol.SignatureTypeAuthority); err == nil {
		t.Error("a non-key type has no key")
	}
}
