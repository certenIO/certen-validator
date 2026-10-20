// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func kp(u string, version uint64, accept uint64, keys ...string) *protocol.KeyPage {
	p := &protocol.KeyPage{Url: url.MustParse(u), Version: version, AcceptThreshold: accept}
	for _, k := range keys {
		h := make([]byte, 32)
		copy(h, k)
		p.Keys = append(p.Keys, &protocol.KeySpec{PublicKeyHash: h})
	}
	return p
}

func capturedPage(t *testing.T, p *protocol.KeyPage, partition string, block uint64) CapturedPage {
	t.Helper()
	st, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return CapturedPage{PageState: proofv2.PageState{URL: p.Url.String(), State: hex.EncodeToString(st), Partition: partition}, Block: block}
}

// v1's replayed page equals v2's served page for every page both read: the transaction's own partition's and a foreign
// partition's, each at its own block; any difference in what decides who may sign is named.
func TestCrossCheckComparesEveryPageBothCaptured(t *testing.T) {
	own1, own2 := kp("acc://cust.acme/book/1", 1, 1, "a"), kp("acc://cust.acme/book/1", 2, 2, "a", "b")
	bank1, bank2 := kp("acc://bank.acme/book/2", 3, 1, "x"), kp("acc://bank.acme/book/2", 4, 1, "y")
	del := kp("acc://deleg.acme/book/1", 1, 1, "d")
	del.Keys[0].Delegate = url.MustParse("acc://hub.acme/book")
	v1 := map[string]govvote.States{
		"acc://cust.acme/book/1":  {{Block: 100, Page: own1}, {Block: 900, Page: own2}},
		"acc://bank.acme/book/2":  {{Block: 5000, Page: bank1}, {Block: 5200, Page: bank2}},
		"acc://deleg.acme/book/1": {{Block: 70, Page: del}},
	}
	c := &Capture{Pages: []CapturedPage{
		capturedPage(t, own2, "acc://bvn-BVN1.acme", 1000),
		capturedPage(t, bank2, "acc://bvn-BVN2.acme", 5300), // as of its own partition's block, later than the transaction's
		capturedPage(t, del, "acc://bvn-BVN3.acme", 3015),
		{PageState: proofv2.PageState{URL: "acc://cust.acme/book", State: "00"}}, // v1 read no history of a book: not compared
	}}
	// A book has no history in v1, and "00" would not decode: it must be skipped before it is decoded.
	res := CrossCheckPages(v1, c)
	if !res.OK() || res.Compared != 3 {
		t.Fatalf("agreeing pages: %s", res)
	}

	// The page as of an earlier block of its partition is the earlier state.
	c2 := &Capture{Pages: []CapturedPage{capturedPage(t, bank1, "acc://bvn-BVN2.acme", 5100)}}
	if r := CrossCheckPages(map[string]govvote.States{"acc://bank.acme/book/2": v1["acc://bank.acme/book/2"]}, c2); !r.OK() {
		t.Fatalf("the earlier state at the earlier block: %s", r)
	}

	// v2 serves the page's stale state for the later block: v1 and v2 disagree, naming the fields, the partition and the block.
	stale := &Capture{Pages: []CapturedPage{capturedPage(t, bank1, "acc://bvn-BVN2.acme", 5300)}}
	r := CrossCheckPages(map[string]govvote.States{"acc://bank.acme/book/2": v1["acc://bank.acme/book/2"]}, stale)
	if r.OK() || len(r.Disagreements) != 2 {
		t.Fatalf("a stale foreign page: %s", r)
	}
	if d := r.Disagreements[0]; d.Field != "version" || d.V1 != "4" || d.V2 != "3" || d.Partition != "acc://bvn-BVN2.acme" || d.Block != 5300 {
		t.Fatalf("first disagreement %+v", d)
	}
	if d := r.Disagreements[1]; d.Field != "keys[0].publicKeyHash" {
		t.Fatalf("second disagreement %+v", d)
	}
}

func TestCrossCheckNamesThresholdDelegateEntryCountAndUncapturedDifferences(t *testing.T) {
	base := kp("acc://p.acme/book/1", 1, 1, "a", "b")
	v1 := map[string]govvote.States{"acc://p.acme/book/1": {{Block: 10, Page: base}}}
	var cases = []struct {
		name  string
		serve *protocol.KeyPage
		field string
	}{
		{"accept threshold", kp("acc://p.acme/book/1", 1, 2, "a", "b"), "acceptThreshold"},
		{"response threshold", func() *protocol.KeyPage {
			p := kp("acc://p.acme/book/1", 1, 1, "a", "b")
			p.ResponseThreshold = 3
			return p
		}(), "responseThreshold"},
		{"entry added", kp("acc://p.acme/book/1", 1, 1, "a", "b", "c"), "entries"},
		{"delegate added", func() *protocol.KeyPage {
			p := kp("acc://p.acme/book/1", 1, 1, "a", "b")
			p.Keys[1].Delegate = url.MustParse("acc://hub.acme/book")
			return p
		}(), "keys[1].delegate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := CrossCheckPages(v1, &Capture{Pages: []CapturedPage{capturedPage(t, tc.serve, "acc://bvn-BVN1.acme", 20)}})
			if r.OK() || r.Disagreements[0].Field != tc.field {
				t.Fatalf("got %s, want a %s disagreement", r, tc.field)
			}
		})
	}
	// The key's last use changes without changing who may sign: not a difference.
	used := kp("acc://p.acme/book/1", 1, 1, "a", "b")
	used.Keys[0].LastUsedOn = 1791594540118000
	if r := CrossCheckPages(v1, &Capture{Pages: []CapturedPage{capturedPage(t, used, "acc://bvn-BVN1.acme", 20)}}); !r.OK() {
		t.Fatalf("LastUsedOn is a difference: %s", r)
	}
	// A page v1 evaluated that v2 did not capture is a gap in v2's closure, named; so is a page that did not exist yet.
	r := CrossCheckPages(v1, &Capture{})
	if r.OK() || r.Disagreements[0].Field != "uncaptured" || !strings.Contains(r.String(), "acc://p.acme/book/1") {
		t.Fatalf("an uncaptured page: %s", r)
	}
	early := &Capture{Pages: []CapturedPage{capturedPage(t, base, "acc://bvn-BVN1.acme", 5)}}
	if r := CrossCheckPages(v1, early); r.OK() || r.Disagreements[0].Field != "history" {
		t.Fatalf("a page captured before v1 says it existed: %s", r)
	}
}

// The comparison is the verifier's (proofv2.AuthorityFieldDiffs, RB9-C1b-1-F3): a transaction blacklist decides who may sign, so a
// page whose blacklist differs between v1's replay and v2's capture is a disagreement.
func TestPageDifferencesSeesTheTransactionBlacklist(t *testing.T) {
	mk := func() *protocol.KeyPage {
		return &protocol.KeyPage{Url: mustURL("acc://a.acme/book/1"), Version: 1, AcceptThreshold: 1, Keys: []*protocol.KeySpec{{PublicKeyHash: []byte{1}}}}
	}
	a, b := mk(), mk()
	if d := pageDifferences(a, b); len(d) != 0 {
		t.Fatalf("equal pages differ: %v", d)
	}
	b.TransactionBlacklist = new(protocol.AllowedTransactions)
	bit, _ := protocol.TransactionTypeWriteData.AllowedTransactionBit()
	b.TransactionBlacklist.Set(bit)
	d := pageDifferences(a, b)
	if len(d) != 1 || d[0].Field != "transactionBlacklist" {
		t.Fatalf("a blacklist difference was not reported: %v", d)
	}
}
