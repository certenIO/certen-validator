// Copyright 2026 Certen Protocol

package proofv2

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig"
	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Note (a): the activation table of the evidence is a view over govsig's - the same rows, through the same function.
func TestJ1ExecutorTableIsAViewOverGovsig(t *testing.T) {
	src, view := govsig.KermitActivations(), KermitExecutorActivations()
	if len(src) != len(view) || len(src) != 4 {
		t.Fatalf("%d rows in govsig, %d in the view", len(src), len(view))
	}
	for k, a := range src {
		if v, ok := view[k]; !ok || v.Version != a.Version || v.Block != uint64(a.Block) {
			t.Fatalf("%s: govsig %+v, view %+v", k, a, v)
		}
		for _, b := range []uint64{uint64(a.Block) - 1, uint64(a.Block), uint64(a.Block) + 1} {
			gv, gok := govsig.ExecutorFloor(k, int64(b))
			vv, vok := ExecutorFloorAt("acc://bvn-"+k+".acme", b)
			if k == "directory" {
				vv, vok = ExecutorFloorAt("acc://dn.acme", b)
			}
			if gv != vv || gok != vok {
				t.Fatalf("%s block %d: govsig %v %v, view %v %v", k, b, gv, gok, vv, vok)
			}
		}
	}
}

// Note (a): a counted key signature is verified by govsig.Verify with the executor-version gate: an rsaSha256 signature exists only from
// executor version v2-vandenberg on, so it is refused by name where the pinned table does not show the version, and accepted above the
// activation block of its partition.
func TestJ1KeySignatureIsGatedByTheExecutorVersion(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	page := url.MustParse("acc://pv2-bank-5.acme/book/1")
	txn := &protocol.Transaction{Header: protocol.TransactionHeader{Principal: url.MustParse("acc://pv2-cust-5.acme/data")},
		Body: &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("gate")}}}}
	sig, err := new(signing.Builder).SetType(protocol.SignatureTypeRsaSha256).SetUrl(page).SetVersion(1).SetTimestamp(1700000000000).SetPrivateKey(x509PKCS1(priv)).Sign(txn.GetHash())
	if err != nil {
		t.Fatal(err)
	}
	pa := &provenAcct{anchor: &xAnchor{id: "BVN2", block: 65}}
	_, err = verifyKeySignature(sig, txn, "DevNet", pa, page.String(), 65)
	var ns *NamedState
	if !errors.As(err, &ns) || ns.Code != StateExecutorVersionUnproven || ns.Partition != "BVN2" || ns.Block != 65 {
		t.Fatalf("an rsaSha256 signature at BVN2 block 65: %v", err)
	}
	pa = &provenAcct{anchor: &xAnchor{id: "BVN2", block: 12_492_100}}
	v, err := verifyKeySignature(sig, txn, "DevNet", pa, page.String(), 12_492_100)
	if err != nil || v == nil || v.Inner.Type() != protocol.SignatureTypeRsaSha256 {
		t.Fatalf("an rsaSha256 signature above BVN2's activation: %v", err)
	}
}

func x509PKCS1(k *rsa.PrivateKey) []byte { return x509MarshalPKCS1(k) }
