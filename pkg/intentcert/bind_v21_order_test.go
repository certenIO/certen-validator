package intentcert

import (
	"encoding/hex"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9-L: more than one page proven at a block other than the transaction's anchor block, and the binding names the first of them in
// ascending order of the pages' canonical URLs, whatever order a map is walked in: the same report is refused with the same text.
func TestCheckBlocksRefusesTheFirstPageInURLOrder(t *testing.T) {
	const part = "acc://bvn-BVN1.acme"
	page := func(u string, block uint64) *provenPage {
		return &provenPage{proof: proofv2.ProvenPage{URL: u, Partition: part, Block: block}}
	}
	b := &binder{
		rep: &proofv2.Report{Partition: part, AnchorBlock: 5},
		pages: map[string]*provenPage{
			"acc://c.acme/book/1": page("acc://c.acme/book/1", 30),
			"acc://a.acme/book/1": page("acc://a.acme/book/1", 10),
			"acc://b.acme/book/1": page("acc://b.acme/book/1", 20),
			"acc://d.acme/book/1": page("acc://d.acme/book/1", 5),
		},
	}
	const want = "g1_page_block_mismatch{acc://bvn-BVN1.acme,10}: acc://a.acme/book/1 is on the transaction's partition and must be proven at its anchor block 5"
	for run := 0; run < 60; run++ {
		if err := b.checkBlocks(); err == nil || err.Error() != want {
			t.Fatalf("run %d: %v, want %q", run, err, want)
		}
	}
}

// RB9-L: the governed transaction of the intent's vote evidence names an authority with no URL (an operation whose authority is absent):
// refused by name, never read as a nil URL. The evidence is the proposer's, read before anything binds it to a proven transaction.
func TestGoverningFactsRefuseAnAuthorityWithNoURL(t *testing.T) {
	const account = "acc://rb9l.acme/account"
	txn := &protocol.Transaction{
		Header: protocol.TransactionHeader{Principal: url.MustParse(account)},
		Body:   &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{&protocol.AddAccountAuthorityOperation{}}},
	}
	raw, err := txn.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, err = GoverningFactsFromVoteEvidence(&govvote.Evidence{Account: account, Transaction: hex.EncodeToString(raw)})
	const want = "proof v2 binding: the governed transaction names an authority with no URL"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}
