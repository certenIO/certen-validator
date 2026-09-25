// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Each test encodes one rule of accumulate-core's vote (see g1_votes.go) and
// drives the model with page timelines built from protocol.KeyPage states.

type memTimelines map[string]*pageTimeline

func (m memTimelines) Timeline(_ context.Context, page string) (*pageTimeline, error) {
	tl, ok := m[normalizeAccURL(page)]
	if !ok {
		return nil, fmt.Errorf("no history for %s", page)
	}
	return tl, nil
}

// vPage is a page state: keys by name, delegates by book, thresholds.
type vPage struct {
	version, accept, reject, response uint64
	keys                              []string
	delegates                         []string
	deny                              []protocol.TransactionType
}

func (p vPage) build(t *testing.T, url string) *protocol.KeyPage {
	t.Helper()
	kp := &protocol.KeyPage{Url: mustURL(t, url), Version: p.version, AcceptThreshold: p.accept,
		RejectThreshold: p.reject, ResponseThreshold: p.response}
	for _, k := range p.keys {
		kp.AddKeySpec(&protocol.KeySpec{PublicKeyHash: keyHash(k)})
	}
	for _, d := range p.delegates {
		kp.AddKeySpec(&protocol.KeySpec{Delegate: mustURL(t, d)})
	}
	for _, typ := range p.deny {
		bit, _ := typ.AllowedTransactionBit()
		if kp.TransactionBlacklist == nil {
			kp.TransactionBlacklist = new(protocol.AllowedTransactions)
		}
		kp.TransactionBlacklist.Set(bit)
	}
	return kp
}

// timeline builds a page's history: states[i] begins at blocks[i].
func timeline(t *testing.T, url string, blocks []int64, states ...vPage) *pageTimeline {
	t.Helper()
	tl := &pageTimeline{Page: normalizeAccURL(url)}
	var prev *protocol.KeyPage
	for i, s := range states {
		p := s.build(t, url)
		ts := timedState{Block: blocks[i], Page: p}
		if prev != nil {
			ts.Event = &pageEvent{EntryHash: fmt.Sprintf("%064d", i)}
			ts.Prev = prev
		}
		tl.States = append(tl.States, ts)
		prev = p
	}
	return tl
}

func kh(name string) string { return strings.ToLower(fmt.Sprintf("%x", keyHash(name))) }

func sig(signer, key string, version uint64, block int64, path ...string) sigFact {
	return sigFact{ID: fmt.Sprintf("sig-%s-%s-%d", key, signer, block), Signer: normalizeAccURL(signer),
		Path: normPath(path), Version: version, KeyHash: kh(key), Vote: protocol.VoteTypeAccept, Block: block}
}

func vote(s sigFact, v protocol.VoteType) sigFact { s.Vote = v; return s }

func arrival(page, authority string, block int64, path ...string) arrivalFact {
	return arrivalFact{ID: fmt.Sprintf("arr-%s-%s", authority, page), Page: normalizeAccURL(page),
		Authority: normalizeAccURL(authority), Path: normPath(path), Block: block}
}

func normPath(p []string) []string {
	out := make([]string, len(p))
	for i, s := range p {
		out[i] = normalizeAccURL(s)
	}
	return out
}

const (
	pBook = "acc://p.acme/book"
	pPage = "acc://p.acme/book/1"
	dBook = "acc://d.acme/book"
	dPage = "acc://d.acme/book/1"
	eBook = "acc://e.acme/book"
	ePage = "acc://e.acme/book/1"
)

func account(t *testing.T, tls memTimelines, facts voteFacts, auths ...string) (*AccountVote, error) {
	t.Helper()
	var aa []AccountAuthority
	for _, a := range auths {
		aa = append(aa, AccountAuthority{URL: a})
	}
	if facts.TxType == 0 {
		facts.TxType = protocol.TransactionTypeWriteData
	}
	return newVoteModel(facts, tls).accountVote(context.Background(), "acc://p.acme/data", aa, nil, false)
}

func requireSatisfied(t *testing.T, av *AccountVote, err error, want bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if av.Satisfied != want {
		t.Fatalf("satisfied = %v, want %v: %+v", av.Satisfied, want, av)
	}
}

func requireUnevaluable(t *testing.T, err error) {
	t.Helper()
	var u *VoteUnevaluable
	if !errors.As(err, &u) {
		t.Fatalf("want an unevaluable vote, got %v", err)
	}
	t.Logf("unevaluable: %v", err)
}

// ---- delegation ---------------------------------------------------------

// NEW-E. One signature from a 2-of-2 delegate page: the delegate never votes,
// so the network records no arrival and the principal is not satisfied.
func TestVotes_DelegateThresholdEnforced(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"d1", "d2"}}),
	}
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(dPage, "d1", 1, 10, pPage)}}, pBook)
	requireSatisfied(t, av, err, false)
}

// And an endpoint that reports a delegated vote the delegate's signatures do
// not add up to is caught, not believed.
func TestVotes_ForgedArrivalIsNotBelieved(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"d1", "d2"}}),
	}
	_, err := account(t, tls, voteFacts{
		Sigs:     []sigFact{sig(dPage, "d1", 1, 10, pPage)},
		Arrivals: []arrivalFact{arrival(pPage, dBook, 11)},
	}, pBook)
	requireUnevaluable(t, err)
}

func TestVotes_DelegateMeetingItsThresholdVotes(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"d1", "d2"}}),
	}
	av, err := account(t, tls, voteFacts{
		Sigs:     []sigFact{sig(dPage, "d1", 1, 10, pPage), sig(dPage, "d2", 1, 11, pPage)},
		Arrivals: []arrivalFact{arrival(pPage, dBook, 12)},
	}, pBook)
	requireSatisfied(t, av, err, true)
}

// At the outermost page a delegated vote and a direct signature share the
// empty path, and combine.
func TestVotes_DirectAndDelegatedCombineAtThePrincipal(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"p1"}, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"d1"}}),
	}
	av, err := account(t, tls, voteFacts{
		Sigs:     []sigFact{sig(pPage, "p1", 1, 10), sig(dPage, "d1", 1, 10, pPage)},
		Arrivals: []arrivalFact{arrival(pPage, dBook, 11)},
	}, pBook)
	requireSatisfied(t, av, err, true)
}

// On an intermediate page, votes on different paths do not combine.
func TestVotes_PathsDoNotCombine(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"d1", "d2"}}),
	}
	// d1 signs for d's own account (empty path), d2 for p (path [p]).
	av, err := account(t, tls, voteFacts{
		Sigs: []sigFact{sig(dPage, "d1", 1, 10), sig(dPage, "d2", 1, 10, pPage)},
	}, pBook)
	requireSatisfied(t, av, err, false)
}

// Two levels: p <- d <- e, with e's threshold enforced.
func TestVotes_TwoLevelDelegation(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{eBook}}),
		normalizeAccURL(ePage): timeline(t, ePage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"e1", "e2"}}),
	}
	facts := voteFacts{
		Sigs: []sigFact{sig(ePage, "e1", 1, 10, pPage, dPage), sig(ePage, "e2", 1, 10, pPage, dPage)},
		Arrivals: []arrivalFact{
			arrival(dPage, eBook, 11, pPage),
			arrival(pPage, dBook, 12),
		},
	}
	av, err := account(t, tls, facts, pBook)
	requireSatisfied(t, av, err, true)

	facts.Sigs = facts.Sigs[:1]
	_, err = account(t, tls, facts, pBook)
	requireUnevaluable(t, err) // arrivals recorded, but e never reached 2 of 2
}

// A delegated vote recorded where the page has no delegate entry for it.
func TestVotes_ArrivalWithoutDelegateEntry(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"p1"}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"d1"}}),
	}
	_, err := account(t, tls, voteFacts{
		Sigs:     []sigFact{sig(dPage, "d1", 1, 10, pPage)},
		Arrivals: []arrivalFact{arrival(pPage, dBook, 11)},
	}, pBook)
	requireUnevaluable(t, err)
}

// ---- vote types -----------------------------------------------------------

func TestVotes_RejectIsNotAnAcceptance(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, keys: []string{"a", "b", "c"}})}
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{
		sig(pPage, "a", 1, 10), vote(sig(pPage, "b", 1, 10), protocol.VoteTypeReject)}}, pBook)
	requireSatisfied(t, av, err, false)
}

func TestVotes_RejectThresholdRejects(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, reject: 1, keys: []string{"a", "b", "c"}})}
	m := newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData, Sigs: []sigFact{
		vote(sig(pPage, "b", 1, 10), protocol.VoteTypeReject)}}, tls)
	pv, err := m.pageVote(context.Background(), pPage, nil, 0)
	if err != nil || !pv.Voted || pv.vote != protocol.VoteTypeReject {
		t.Fatalf("want a reject vote, got %+v %v", pv, err)
	}
}

func TestVotes_Abstain(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, keys: []string{"a", "b"}})}
	m := newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData, Sigs: []sigFact{
		sig(pPage, "a", 1, 10), vote(sig(pPage, "b", 1, 10), protocol.VoteTypeReject)}}, tls)
	pv, err := m.pageVote(context.Background(), pPage, nil, 0)
	if err != nil || !pv.Voted || pv.vote != protocol.VoteTypeAbstain {
		t.Fatalf("want an abstention, got %+v %v", pv, err)
	}
}

func TestVotes_ResponseThreshold(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 1, response: 2, keys: []string{"a", "b", "c"}})}
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "a", 1, 10)}}, pBook)
	requireSatisfied(t, av, err, false)
	av, err = account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "a", 1, 10), sig(pPage, "b", 1, 11)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// ---- versions and timing --------------------------------------------------

func TestVotes_NewerVersionReplacesTheSet(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 20},
		vPage{version: 1, accept: 2, keys: []string{"a", "b"}},
		vPage{version: 2, accept: 2, keys: []string{"a", "b", "c"}})}
	// a signed at v1 before the update, b at v2 after: a was discarded.
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "a", 1, 10), sig(pPage, "b", 2, 30)}}, pBook)
	requireSatisfied(t, av, err, false)
	av, err = account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "b", 2, 30), sig(pPage, "c", 2, 31)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// A signature recorded at a version the page did not hold during its block.
func TestVotes_SignatureAtAVersionNotHeldThen(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 20},
		vPage{version: 1, accept: 1, keys: []string{"a"}},
		vPage{version: 2, accept: 1, keys: []string{"a"}})}
	_, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "a", 2, 10)}}, pBook)
	requireUnevaluable(t, err)
}

// A key the page did not carry when the signature was processed - though it
// carries it by execution. Judged at the signature's block, not the
// execution's.
func TestVotes_KeyAddedAfterTheSignature(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 20},
		vPage{version: 1, accept: 1, keys: []string{"a"}},
		vPage{version: 2, accept: 1, keys: []string{"a", "late"}})}
	_, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "late", 1, 10)}}, pBook)
	requireUnevaluable(t, err)
}

// An UpdateKey in the same block as a signature by the rotated key: which
// state the signature saw is not recorded.
func TestVotes_RotationInsideABlock(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 50},
		vPage{version: 1, accept: 1, keys: []string{"a", "old"}},
		vPage{version: 1, accept: 1, keys: []string{"a", "new"}})}
	// Decisive: the rotated key's signature is the only one.
	_, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "old", 1, 50)}}, pBook)
	requireUnevaluable(t, err)
	// Not decisive: another definite signature already meets the threshold.
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "old", 1, 50), sig(pPage, "a", 1, 50)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// A page that updates itself: the governed updateKeyPage was signed at v1 and
// its execution in the same block produced v2. The signature saw v1.
func TestVotes_SelfUpdateInItsOwnBlock(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 40},
		vPage{version: 1, accept: 1, keys: []string{"a"}},
		vPage{version: 2, accept: 1, keys: []string{"a", "b"}})}
	av, err := account(t, tls, voteFacts{TxType: protocol.TransactionTypeUpdateKeyPage,
		Sigs: []sigFact{sig(pPage, "a", 1, 40)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// ---- blacklist ------------------------------------------------------------

func TestVotes_BlacklistedTypeCannotBeSigned(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 1, keys: []string{"a"}, deny: []protocol.TransactionType{protocol.TransactionTypeUpdateKeyPage}})}
	_, err := account(t, tls, voteFacts{TxType: protocol.TransactionTypeUpdateKeyPage,
		Sigs: []sigFact{sig(pPage, "a", 1, 10)}}, pBook)
	requireUnevaluable(t, err)
	av, err := account(t, tls, voteFacts{TxType: protocol.TransactionTypeWriteData,
		Sigs: []sigFact{sig(pPage, "a", 1, 10)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// ---- books and accounts ---------------------------------------------------

// A book votes with its FIRST page that votes, even if a later page would
// have voted otherwise.
func TestVotes_BookVotesWithItsFirstVotingPage(t *testing.T) {
	p2 := "acc://p.acme/book/2"
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, reject: 1, keys: []string{"a"}}),
		normalizeAccURL(p2):    timeline(t, p2, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"b"}}),
	}
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{
		vote(sig(pPage, "a", 1, 10), protocol.VoteTypeReject), sig(p2, "b", 1, 10)}}, pBook)
	requireSatisfied(t, av, err, false)
	if av.Authorities[0].Vote.By != normalizeAccURL(pPage) {
		t.Fatalf("book voted by %s, want page 1", av.Authorities[0].Vote.By)
	}
}

func TestVotes_EveryRequiredAuthority(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"p1"}}),
		normalizeAccURL(ePage): timeline(t, ePage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"e1"}}),
	}
	one := voteFacts{Sigs: []sigFact{sig(pPage, "p1", 1, 10)}}
	av, err := account(t, tls, one, pBook, eBook)
	requireSatisfied(t, av, err, false)

	both := voteFacts{Sigs: []sigFact{sig(pPage, "p1", 1, 10), sig(ePage, "e1", 1, 10)}}
	av, err = account(t, tls, both, pBook, eBook)
	requireSatisfied(t, av, err, true)

	m := newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData, Sigs: one.Sigs}, tls)
	disabled := []AccountAuthority{{URL: pBook}, {URL: eBook, Disabled: true}}
	av, err = m.accountVote(context.Background(), "acc://p.acme/data", disabled, nil, false)
	requireSatisfied(t, av, err, true)
	m = newVoteModel(voteFacts{TxType: protocol.TransactionTypeUpdateAccountAuth, Sigs: one.Sigs}, tls)
	av, err = m.accountVote(context.Background(), "acc://p.acme/data", disabled, nil, true)
	requireSatisfied(t, av, err, false) // a type requiring authorization counts the disabled one

	m = newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData, Sigs: one.Sigs}, tls)
	av, err = m.accountVote(context.Background(), "acc://p.acme/data",
		[]AccountAuthority{{URL: pBook}}, []string{eBook}, false)
	requireSatisfied(t, av, err, false) // an extra authority the transaction names
}

func TestVotes_DepthLimit(t *testing.T) {
	tls := memTimelines{}
	path := []string{}
	for i := 0; i <= protocol.DelegationDepthLimit+1; i++ {
		path = append(path, fmt.Sprintf("acc://x%d.acme/book/1", i))
	}
	m := newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData}, tls)
	_, err := m.pageVote(context.Background(), pPage, path, protocol.DelegationDepthLimit+1)
	requireUnevaluable(t, err)
}
