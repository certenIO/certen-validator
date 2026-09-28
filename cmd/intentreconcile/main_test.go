package main

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	acmerrors "gitlab.com/accumulatenetwork/accumulate/pkg/errors"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// fakeChain answers chain queries for accounts it holds; a page larger than maxPage fails, as the endpoint's
// response cut does.
type fakeChain struct {
	entries map[string][]messaging.Message
	maxPage uint64
	short   bool // answer one record fewer than asked
}

func (f *fakeChain) Query(_ context.Context, u *url.URL, q api.Query) (api.Record, error) {
	es, ok := f.entries[strings.ToLower(u.String())]
	if !ok {
		return nil, acmerrors.NotFound.With("no such account")
	}
	cq := q.(*api.ChainQuery)
	if cq.Range == nil {
		return &api.ChainRecord{Name: "main", Count: uint64(len(es))}, nil
	}
	n := *cq.Range.Count
	if n > f.maxPage {
		return nil, errors.New("response cut")
	}
	rr := &api.RecordRange[api.Record]{}
	for i := cq.Range.Start; i < cq.Range.Start+n && i < uint64(len(es)); i++ {
		rr.Records = append(rr.Records, &api.ChainEntryRecord[api.Record]{Index: i, Value: &api.MessageRecord[messaging.Message]{Message: es[i]}})
	}
	if f.short && len(rr.Records) > 0 {
		rr.Records = rr.Records[:len(rr.Records)-1]
	}
	return rr, nil
}

func writeData(account, memo string, n byte) (*messaging.TransactionMessage, string) {
	txn := &protocol.Transaction{
		Header: protocol.TransactionHeader{Principal: protocol.AccountUrl(strings.TrimPrefix(account, "acc://")), Memo: memo},
		Body:   &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{{n}, {1}, {2}, {3}}}},
	}
	return &messaging.TransactionMessage{Transaction: txn}, hex.EncodeToString(txn.GetHash())
}

// RB3-F125: every intent written to a data account is found, and the ones discovery never recorded are
// reported; entries that are not intents are not; a page the endpoint cannot deliver is halved.
func TestTheIntentsDiscoveryMissedAreReported(t *testing.T) {
	const acct = "acc://orchid.acme/data"
	var msgs []messaging.Message
	var hashes []string
	for i := byte(0); i < 7; i++ {
		memo := "CERTEN_INTENT"
		if i == 3 {
			memo = "certen-intent" // legacy form
		}
		m, h := writeData(acct, memo, i)
		msgs = append(msgs, m)
		hashes = append(hashes, h)
	}
	plain, _ := writeData(acct, "not an intent", 99) // a writeData without the marker
	msgs = append(msgs, plain)

	known := map[string]bool{hashes[0]: true, hashes[2]: true, hashes[3]: true, hashes[5]: true}
	q := &fakeChain{entries: map[string][]messaging.Message{acct: msgs}, maxPage: 3}
	rep, err := reconcile(context.Background(), q, []string{acct}, known, 8)
	if err != nil {
		t.Fatal(err)
	}
	ar := rep.Accounts[0]
	if ar.Entries != 8 || ar.Intents != 7 || ar.Discovered != 4 || len(ar.Missing) != 3 {
		t.Fatalf("entries=%d intents=%d discovered=%d missing=%d", ar.Entries, ar.Intents, ar.Discovered, len(ar.Missing))
	}
	for i, want := range []int{1, 4, 6} {
		if ar.Missing[i].TxHash != hashes[want] || ar.Missing[i].ChainIndex != uint64(want) {
			t.Fatalf("missing[%d] = %+v, want entry %d", i, ar.Missing[i], want)
		}
	}
	if len(rep.KnownNotFound) != 0 {
		t.Fatalf("known intents found in no account: %v", rep.KnownNotFound)
	}
}

// Reading short, or an account list that misses where a known intent lives, is never reported as "nothing
// missing".
func TestAnIncompleteReadIsAFailureNotAnEmptyReport(t *testing.T) {
	const acct = "acc://harbor.acme/data"
	m, h := writeData(acct, "CERTEN_INTENT", 1)
	q := &fakeChain{entries: map[string][]messaging.Message{acct: {m, m}}, maxPage: 10, short: true}
	if _, err := reconcile(context.Background(), q, []string{acct}, map[string]bool{}, 10); err == nil {
		t.Fatal("a range answered short was accepted")
	}

	q = &fakeChain{entries: map[string][]messaging.Message{acct: {m}}, maxPage: 10}
	rep, err := reconcile(context.Background(), q, []string{"acc://nowhere.acme/data"}, map[string]bool{h: true}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Accounts[0].Absent || len(rep.KnownNotFound) != 1 || rep.KnownNotFound[0] != h {
		t.Fatalf("absent=%v knownNotFound=%v; want the account absent and the known intent flagged", rep.Accounts[0].Absent, rep.KnownNotFound)
	}
}
