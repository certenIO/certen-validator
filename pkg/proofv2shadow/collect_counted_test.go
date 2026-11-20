// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func txidAt(hexByte, account string) *url.TxID {
	id, err := url.ParseTxID("acc://" + strings.Repeat(hexByte, 32) + "@" + strings.TrimPrefix(account, "acc://"))
	if err != nil {
		panic(err)
	}
	return id
}

func countedOf(c *Capture, authority string) []proofv2.VoteHop {
	for _, v := range c.Votes {
		if strings.EqualFold(v.Authority, authority) {
			return v.Counted
		}
	}
	return nil
}

func countedHas(hops []proofv2.VoteHop, id *url.TxID) bool {
	h := id.Hash()
	for _, c := range hops {
		if strings.EqualFold(c.Page, id.Account().String()) && strings.EqualFold(c.Message, strings.ToLower(hexOf(h[:]))) {
			return true
		}
	}
	return false
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}

// A page of threshold 2 delegates to two books, each casting a delegated vote (AGT A-03, intent 0c720b71: two officers through the
// principal's book/3). The vote's cause chain runs through the second delegate; the first delegate's vote is a counted authority
// signature on the page. The verifier recomputes every delegated vote from that delegate's own signatures (govvote), so the capture must
// carry the first delegate's own signature chain - and count the other signatures of the pages it reaches - or the evidence fails with
// g1_vote_not_reproduced.
func TestCollectCapturesTheCauseChainOfACountedDelegatedVote(t *testing.T) {
	w := tclWorld()
	w.delegate("bank.acme", "erp.acme") // bank/book/1 now delegates to deleg.acme/book and erp.acme/book
	f := newFakeNet(t, w)
	f.facts = facts("acc://cust.acme/pay")
	v := vote("acc://bank.acme/book", "acc://bank.acme/book/1")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2015}

	// erp.acme's delegated vote, recorded on bank/book/1 before the deciding one; its cause is erp's own key signature.
	erpKey := txidAt("e1", "acc://erp.acme/book/1")
	erpVote := txidAt("e2", "acc://bank.acme/book/1")
	f.arrivals[erpVote.String()] = fakeArrival{"BVN2", 2012}
	f.arrivals[erpKey.String()] = fakeArrival{"BVN3", 3010}
	f.dels[erpKey.String()] = []*url.URL{url.MustParse("acc://bank.acme/book/1")}
	// a second signature erp's page recorded for the transaction: the worklist counts it too
	erpOther := txidAt("e3", "acc://erp.acme/book/1")
	f.arrivals[erpOther.String()] = fakeArrival{"BVN3", 3012}

	f.facts.PageSigs = map[string][]SigRecord{
		"acc://bank.acme/book/1": {
			{ID: v.Cause},
			{ID: erpVote, Sig: &protocol.AuthoritySignature{Origin: url.MustParse("acc://erp.acme/book/1"), Authority: url.MustParse("acc://erp.acme/book"),
				Vote: protocol.VoteTypeAccept, Cause: erpKey, Delegator: []*url.URL{url.MustParse("acc://bank.acme/book/1")}}},
		},
		"acc://erp.acme/book/1": {
			{ID: erpKey},
			{ID: erpOther, Sig: &protocol.ED25519Signature{Signer: url.MustParse("acc://erp.acme/book/1"), SignerVersion: 1}},
		},
	}

	c, err := f.collect()
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	counted := countedOf(c, "acc://bank.acme/book")
	if !countedHas(counted, erpVote) {
		t.Fatalf("the counted delegated vote is missing: %+v", counted)
	}
	if !countedHas(counted, erpKey) {
		t.Fatalf("the counted delegated vote was captured without its own key signature: %+v", counted)
	}
	if !countedHas(counted, erpOther) {
		t.Fatalf("the other signature of the delegate's page was not counted: %+v", counted)
	}
	if len(counted) != 3 {
		t.Fatalf("counted %d hops, want 3 (no duplicates): %+v", len(counted), counted)
	}
	if !hasRoleOf(c, "acc://erp.acme/book/1", proofv2.RoleVoter) {
		t.Fatalf("the delegate's page is not a voter in the capture")
	}
}

// A counted delegated vote that records no cause cannot be followed: the capture names it rather than carrying half a vote.
func TestCollectRefusesACountedDelegatedVoteWithNoCause(t *testing.T) {
	w := tclWorld()
	w.delegate("bank.acme", "erp.acme")
	f := newFakeNet(t, w)
	f.facts = facts("acc://cust.acme/pay")
	v := vote("acc://bank.acme/book", "acc://bank.acme/book/1")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2015}
	erpVote := txidAt("e2", "acc://bank.acme/book/1")
	f.arrivals[erpVote.String()] = fakeArrival{"BVN2", 2012}
	f.facts.PageSigs = map[string][]SigRecord{"acc://bank.acme/book/1": {
		{ID: erpVote, Sig: &protocol.AuthoritySignature{Origin: url.MustParse("acc://erp.acme/book/1"), Authority: url.MustParse("acc://erp.acme/book"),
			Vote: protocol.VoteTypeAccept, Delegator: []*url.URL{url.MustParse("acc://bank.acme/book/1")}}},
	}}
	_, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateCompletenessUnproven {
		t.Fatalf("a causeless counted delegated vote gave %v", err)
	}
}

// Accumulate records signatures on a transaction that has already executed (AGT-0 scene 4b, intent 84216735: a third signature on a 2-of-2
// page, 8 blocks after execution). A counted signature on the transaction's own partition after the transaction's block counted for
// nothing: the capture discloses it and goes on, instead of failing with g1_block_before_signature.
func TestCollectDisclosesASignatureRecordedAfterExecution(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	own := vote("acc://cust.acme/book", "acc://cust.acme/book/1")
	f.facts.Votes = []VoteFact{own}
	f.arrivals[own.Cause.String()] = fakeArrival{"BVN1", 1000}
	late := txidAt("c7", "acc://cust.acme/book/1")
	f.arrivals[late.String()] = fakeArrival{"BVN1", 1008}
	early := txidAt("c6", "acc://cust.acme/book/1")
	f.arrivals[early.String()] = fakeArrival{"BVN1", 999}
	sig := &protocol.ED25519Signature{Signer: url.MustParse("acc://cust.acme/book/1"), SignerVersion: 1}
	f.facts.PageSigs = map[string][]SigRecord{"acc://cust.acme/book/1": {{ID: own.Cause}, {ID: early, Sig: sig}, {ID: late, Sig: sig}}}

	c, err := f.collect()
	if err != nil {
		t.Fatalf("a signature after execution stopped the capture: %v", err)
	}
	counted := countedOf(c, "acc://cust.acme/book")
	if countedHas(counted, late) {
		t.Fatalf("the signature recorded after execution was counted: %+v", counted)
	}
	if !countedHas(counted, early) {
		t.Fatalf("the signature recorded before execution was not counted: %+v", counted)
	}
	found := false
	for _, n := range c.Notes {
		if strings.Contains(n, proofv2.StateSignatureAfterExecution) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the late signature was not disclosed: %v", c.Notes)
	}
	// The cause chain itself is still bound: a deciding signature after the transaction's block remains a refusal.
	f.arrivals[own.Cause.String()] = fakeArrival{"BVN1", 1001}
	_, err = f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateBlockBeforeArrival {
		t.Fatalf("a cause after the transaction's block gave %v", err)
	}
}
