// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/client/signing"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// fakeQuerier answers every query with one record: the transaction on its principal, as the node serves it with its signature sets.
type fakeQuerier struct{ rec api.Record }

func (q fakeQuerier) Query(context.Context, *url.URL, api.Query) (api.Record, error) {
	return q.rec, nil
}

func sigMessage(t *testing.T, signer *url.URL, key byte, initiator bool, txn *protocol.Transaction) (*messaging.SignatureMessage, *url.TxID) {
	t.Helper()
	seed := make([]byte, 32)
	seed[0] = key
	b := new(signing.Builder).SetType(protocol.SignatureTypeED25519).SetUrl(signer).SetVersion(1).SetTimestamp(1700000000000 + uint64(key)).
		SetPrivateKey(ed25519.NewKeyFromSeed(seed))
	_ = initiator
	sig, err := b.Sign(txn.GetHash())
	if err != nil {
		t.Fatal(err)
	}
	msg := &messaging.SignatureMessage{Signature: sig, TxID: txn.ID()}
	h := msg.Hash()
	id, err := url.ParseTxID("acc://" + hex.EncodeToString(h[:]) + "@" + signer.Authority + signer.Path)
	if err != nil {
		t.Fatal(err)
	}
	return msg, id
}

// ReadTxFacts keeps the signature that initiated the transaction: the first message of the record's signature sets whose signature satisfies
// SignatureDidInitiate against Header.Initiator, with its id on the page that holds it. A signature that did not initiate (a later cosign of the
// same page, another page's) is not it.
func TestReadTxFactsKeepsTheInitiatingSignature(t *testing.T) {
	erp := url.MustParse("acc://erp.acme/book/1")
	bank := url.MustParse("acc://bank.acme/book/1")
	txn := &protocol.Transaction{Header: protocol.TransactionHeader{Principal: url.MustParse("acc://cust.acme/pay")},
		Body: &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("x")}}}}
	// The initiator's metadata is the first signature's: sign once to learn it, then set the header and sign again over the final hash.
	first, _ := sigMessage(t, erp, 1, true, txn)
	copy(txn.Header.Initiator[:], first.Signature.Metadata().Hash())
	initMsg, initID := sigMessage(t, erp, 1, true, txn)
	laterMsg, laterID := sigMessage(t, erp, 2, false, txn) // the same page, another key: does not initiate
	otherMsg, otherID := sigMessage(t, bank, 3, false, txn)
	if did, _ := protocol.SignatureDidInitiate(laterMsg.Signature, txn.Header.Initiator[:], nil); did {
		t.Fatal("the cosign initiates")
	}

	rec := func(m *messaging.SignatureMessage, id *url.TxID) *api.MessageRecord[messaging.Message] {
		return &api.MessageRecord[messaging.Message]{ID: id, Message: m}
	}
	set := func(account protocol.Account, recs ...*api.MessageRecord[messaging.Message]) *api.SignatureSetRecord {
		return &api.SignatureSetRecord{Account: account.(protocol.Signer), Signatures: &api.RecordRange[*api.MessageRecord[messaging.Message]]{Records: recs, Total: uint64(len(recs))}}
	}
	mr := &api.MessageRecord[messaging.Message]{ID: txn.ID(), Message: &messaging.TransactionMessage{Transaction: txn},
		Signatures: &api.RecordRange[*api.SignatureSetRecord]{Total: 2, Records: []*api.SignatureSetRecord{
			// the bank's page first and the erp page's later cosign before the initiating message: the initiating one is found by what it is, not where it sits
			set(&protocol.KeyPage{Url: bank}, rec(otherMsg, otherID)),
			set(&protocol.KeyPage{Url: erp}, rec(laterMsg, laterID), rec(initMsg, initID)),
		}}}
	f, err := ReadTxFacts(context.Background(), fakeQuerier{mr}, "acc://cust.acme/pay", hex.EncodeToString(txn.GetHash()))
	if err != nil {
		t.Fatal(err)
	}
	if f.Initiating == nil || f.Initiating.ID == nil || f.Initiating.ID.String() != initID.String() {
		t.Fatalf("the initiating message is %+v, want %s", f.Initiating, initID)
	}
	if did, _ := protocol.SignatureDidInitiate(f.Initiating.Sig, txn.Header.Initiator[:], nil); !did {
		t.Fatal("the kept signature does not initiate the transaction")
	}
	if len(f.Initiators) != 1 || f.Initiators[0].String() != erp.String() {
		t.Fatalf("initiator pages %v", f.Initiators)
	}
}
