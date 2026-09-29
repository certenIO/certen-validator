// Copyright 2026 Certen Protocol

package govvote

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Each test encodes one rule of accumulate-core's vote (see model.go) and
// drives the model with page timelines built from protocol.KeyPage states.

type memTimelines map[string]States

func (m memTimelines) Timeline(_ context.Context, page string) (Timeline, error) {
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
func timeline(t *testing.T, url string, blocks []int64, states ...vPage) States {
	t.Helper()
	var tl States
	for i, s := range states {
		tl = append(tl, State{Block: blocks[i], Page: s.build(t, url)})
	}
	return tl
}

func kh(name string) string { return strings.ToLower(fmt.Sprintf("%x", keyHash(name))) }

func sig(signer, key string, version uint64, block int64, path ...string) SigFact {
	return SigFact{ID: fmt.Sprintf("sig-%s-%s-%d", key, signer, block), Signer: normalizeAccURL(signer),
		Path: normPath(path), Version: version, KeyHash: kh(key), Vote: protocol.VoteTypeAccept, Block: block}
}

func vote(s SigFact, v protocol.VoteType) SigFact { s.Vote = v; return s }

func arrival(page, authority string, block int64, path ...string) ArrivalFact {
	return ArrivalFact{ID: fmt.Sprintf("arr-%s-%s", authority, page), Page: normalizeAccURL(page),
		Authority: normalizeAccURL(authority), Path: normPath(path), Block: block}
}

// from is the arrival as core records it: naming the delegate's page that cast the vote.
func from(a ArrivalFact, origin string) ArrivalFact { a.Origin = normalizeAccURL(origin); return a }

// cast is a book's vote as core records it on the principal.
func cast(book, origin string, block int64, v protocol.VoteType) RecordedVote {
	r := recorded(book, origin, block)
	r.Vote = v
	return r
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

func account(t *testing.T, tls memTimelines, facts Facts, auths ...string) (*AccountVote, error) {
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
	av, err := account(t, tls, Facts{Sigs: []SigFact{sig(dPage, "d1", 1, 10, pPage)}}, pBook)
	requireSatisfied(t, av, err, false)
}

// And an endpoint that reports a delegated vote the delegate's signatures do
// not add up to is caught, not believed.
func TestVotes_ForgedArrivalIsNotBelieved(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"d1", "d2"}}),
	}
	_, err := account(t, tls, Facts{
		Sigs:     []SigFact{sig(dPage, "d1", 1, 10, pPage)},
		Arrivals: []ArrivalFact{from(arrival(pPage, dBook, 11), dPage)},
		Votes:    []RecordedVote{recorded(pBook, pPage, 12)},
	}, pBook)
	requireUnevaluable(t, err)
}

func TestVotes_DelegateMeetingItsThresholdVotes(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 2, keys: []string{"d1", "d2"}}),
	}
	av, err := account(t, tls, Facts{
		Sigs:     []SigFact{sig(dPage, "d1", 1, 10, pPage), sig(dPage, "d2", 1, 11, pPage)},
		Arrivals: []ArrivalFact{from(arrival(pPage, dBook, 12), dPage)},
		Votes:    []RecordedVote{recorded(pBook, pPage, 13)},
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
	av, err := account(t, tls, Facts{
		Sigs:     []SigFact{sig(pPage, "p1", 1, 10), sig(dPage, "d1", 1, 10, pPage)},
		Arrivals: []ArrivalFact{from(arrival(pPage, dBook, 11), dPage)},
		Votes:    []RecordedVote{recorded(pBook, pPage, 11)},
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
	av, err := account(t, tls, Facts{
		Sigs: []SigFact{sig(dPage, "d1", 1, 10), sig(dPage, "d2", 1, 10, pPage)},
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
	facts := Facts{
		Sigs: []SigFact{sig(ePage, "e1", 1, 10, pPage, dPage), sig(ePage, "e2", 1, 10, pPage, dPage)},
		Arrivals: []ArrivalFact{
			from(arrival(dPage, eBook, 11, pPage), ePage),
			from(arrival(pPage, dBook, 12), dPage),
		},
		Votes: []RecordedVote{recorded(pBook, pPage, 13)},
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
	_, err := account(t, tls, Facts{
		Sigs:     []SigFact{sig(dPage, "d1", 1, 10, pPage)},
		Arrivals: []ArrivalFact{from(arrival(pPage, dBook, 11), dPage)},
		Votes:    []RecordedVote{recorded(pBook, pPage, 12)},
	}, pBook)
	requireUnevaluable(t, err)
}

// ---- vote types -----------------------------------------------------------

func TestVotes_RejectIsNotAnAcceptance(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, keys: []string{"a", "b", "c"}})}
	av, err := account(t, tls, Facts{Sigs: []SigFact{
		sig(pPage, "a", 1, 10), vote(sig(pPage, "b", 1, 10), protocol.VoteTypeReject)}}, pBook)
	requireSatisfied(t, av, err, false)
}

func TestVotes_RejectThresholdRejects(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, reject: 1, keys: []string{"a", "b", "c"}})}
	m := newVoteModel(Facts{TxType: protocol.TransactionTypeWriteData, Sigs: []SigFact{
		vote(sig(pPage, "b", 1, 10), protocol.VoteTypeReject)}}, tls)
	pv, err := m.pageVote(context.Background(), pPage, nil, 0)
	if err != nil || !pv.Voted || pv.vote != protocol.VoteTypeReject {
		t.Fatalf("want a reject vote, got %+v %v", pv, err)
	}
}

func TestVotes_Abstain(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, keys: []string{"a", "b"}})}
	m := newVoteModel(Facts{TxType: protocol.TransactionTypeWriteData, Sigs: []SigFact{
		sig(pPage, "a", 1, 10), vote(sig(pPage, "b", 1, 10), protocol.VoteTypeReject)}}, tls)
	pv, err := m.pageVote(context.Background(), pPage, nil, 0)
	if err != nil || !pv.Voted || pv.vote != protocol.VoteTypeAbstain {
		t.Fatalf("want an abstention, got %+v %v", pv, err)
	}
}

func TestVotes_ResponseThreshold(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 1, response: 2, keys: []string{"a", "b", "c"}})}
	av, err := account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10)}}, pBook)
	requireSatisfied(t, av, err, false)
	av, err = account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10), sig(pPage, "b", 1, 11)},
		Votes: []RecordedVote{recorded(pBook, pPage, 11)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// ---- versions and timing --------------------------------------------------

func TestVotes_NewerVersionReplacesTheSet(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 20},
		vPage{version: 1, accept: 2, keys: []string{"a", "b"}},
		vPage{version: 2, accept: 2, keys: []string{"a", "b", "c"}})}
	// a signed at v1 before the update, b at v2 after: a was discarded.
	av, err := account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10), sig(pPage, "b", 2, 30)}}, pBook)
	requireSatisfied(t, av, err, false)
	av, err = account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "b", 2, 30), sig(pPage, "c", 2, 31)},
		Votes: []RecordedVote{recorded(pBook, pPage, 31)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// A signature recorded at a version the page did not hold during its block.
func TestVotes_SignatureAtAVersionNotHeldThen(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 20},
		vPage{version: 1, accept: 1, keys: []string{"a"}},
		vPage{version: 2, accept: 1, keys: []string{"a"}})}
	_, err := account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "a", 2, 10)}}, pBook)
	requireUnevaluable(t, err)
}

// A key the page did not carry when the signature was processed - though it
// carries it by execution. Judged at the signature's block, not the
// execution's.
func TestVotes_KeyAddedAfterTheSignature(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 20},
		vPage{version: 1, accept: 1, keys: []string{"a"}},
		vPage{version: 2, accept: 1, keys: []string{"a", "late"}})}
	_, err := account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "late", 1, 10)}}, pBook)
	requireUnevaluable(t, err)
}

// An UpdateKey in the same block as a signature by the rotated key: which
// state the signature saw is not recorded.
func TestVotes_RotationInsideABlock(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 50},
		vPage{version: 1, accept: 1, keys: []string{"a", "old"}},
		vPage{version: 1, accept: 1, keys: []string{"a", "new"}})}
	// Decisive: the rotated key's signature is the only one.
	_, err := account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "old", 1, 50)}}, pBook)
	requireUnevaluable(t, err)
	// Not decisive: another definite signature already meets the threshold.
	av, err := account(t, tls, Facts{Sigs: []SigFact{sig(pPage, "old", 1, 50), sig(pPage, "a", 1, 50)},
		Votes: []RecordedVote{recorded(pBook, pPage, 50)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// A page that updates itself: the governed updateKeyPage was signed at v1 and
// its execution in the same block produced v2. The signature saw v1.
func TestVotes_SelfUpdateInItsOwnBlock(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 40},
		vPage{version: 1, accept: 1, keys: []string{"a"}},
		vPage{version: 2, accept: 1, keys: []string{"a", "b"}})}
	av, err := account(t, tls, Facts{TxType: protocol.TransactionTypeUpdateKeyPage,
		Sigs: []SigFact{sig(pPage, "a", 1, 40)}, Votes: []RecordedVote{recorded(pBook, pPage, 40)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// A delegate page on another partition, whose block numbers run far ahead of
// the principal's. It rotated d-old out at its own block 900; the principal
// executed at its block 50. Judged on its own clock, d-old signed at 850 while
// it was held and counts, and d-new signing at 850 had not been added yet.
// Judged at the principal's block 50, both answers would be backwards.
func TestVotes_SignerPageOnAnotherPartitionUsesItsOwnBlocks(t *testing.T) {
	tls := func() memTimelines {
		return memTimelines{
			normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
			normalizeAccURL(dPage): timeline(t, dPage, []int64{1, 900},
				vPage{version: 1, accept: 1, keys: []string{"d-old"}},
				vPage{version: 2, accept: 1, keys: []string{"d-new"}}),
		}
	}
	av, err := account(t, tls(), Facts{
		Sigs:     []SigFact{sig(dPage, "d-old", 1, 850, pPage)},
		Arrivals: []ArrivalFact{from(arrival(pPage, dBook, 40), dPage)},
		Votes:    []RecordedVote{recorded(pBook, pPage, 41)},
	}, pBook)
	requireSatisfied(t, av, err, true)

	_, err = account(t, tls(), Facts{
		Sigs:     []SigFact{sig(dPage, "d-new", 2, 850, pPage)},
		Arrivals: []ArrivalFact{from(arrival(pPage, dBook, 40), dPage)},
		Votes:    []RecordedVote{recorded(pBook, pPage, 41)},
	}, pBook)
	requireUnevaluable(t, err)
}

// ---- blacklist ------------------------------------------------------------

func TestVotes_BlacklistedTypeCannotBeSigned(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 1, keys: []string{"a"}, deny: []protocol.TransactionType{protocol.TransactionTypeUpdateKeyPage}})}
	_, err := account(t, tls, Facts{TxType: protocol.TransactionTypeUpdateKeyPage,
		Sigs: []SigFact{sig(pPage, "a", 1, 10)}}, pBook)
	requireUnevaluable(t, err)
	av, err := account(t, tls, Facts{TxType: protocol.TransactionTypeWriteData,
		Sigs: []SigFact{sig(pPage, "a", 1, 10)}, Votes: []RecordedVote{recorded(pBook, pPage, 10)}}, pBook)
	requireSatisfied(t, av, err, true)
}

// ---- books and accounts ---------------------------------------------------

// A book votes with the page that decided first, even if another page would have voted otherwise. Here both decide
// in block 10; which came first is not in the block number and is in the network's record, which names page 1.
func TestVotes_BookVotesWithItsFirstVotingPage(t *testing.T) {
	p2 := "acc://p.acme/book/2"
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, reject: 1, keys: []string{"a"}}),
		normalizeAccURL(p2):    timeline(t, p2, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"b"}}),
	}
	av, err := account(t, tls, Facts{Sigs: []SigFact{
		vote(sig(pPage, "a", 1, 10), protocol.VoteTypeReject), sig(p2, "b", 1, 10)},
		Votes: []RecordedVote{cast(pBook, pPage, 10, protocol.VoteTypeReject)}}, pBook)
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
	one := Facts{Sigs: []SigFact{sig(pPage, "p1", 1, 10)}, Votes: []RecordedVote{recorded(pBook, pPage, 10)}}
	av, err := account(t, tls, one, pBook, eBook)
	requireSatisfied(t, av, err, false)

	both := Facts{Sigs: []SigFact{sig(pPage, "p1", 1, 10), sig(ePage, "e1", 1, 10)},
		Votes: []RecordedVote{recorded(pBook, pPage, 10), recorded(eBook, ePage, 10)}}
	av, err = account(t, tls, both, pBook, eBook)
	requireSatisfied(t, av, err, true)

	m := newVoteModel(Facts{TxType: protocol.TransactionTypeWriteData, Sigs: one.Sigs, Votes: one.Votes}, tls)
	disabled := []AccountAuthority{{URL: pBook}, {URL: eBook, Disabled: true}}
	av, err = m.accountVote(context.Background(), "acc://p.acme/data", disabled, nil, false)
	requireSatisfied(t, av, err, true)
	m = newVoteModel(Facts{TxType: protocol.TransactionTypeUpdateAccountAuth, Sigs: one.Sigs, Votes: one.Votes}, tls)
	av, err = m.accountVote(context.Background(), "acc://p.acme/data", disabled, nil, true)
	requireSatisfied(t, av, err, false) // a type requiring authorization counts the disabled one

	m = newVoteModel(Facts{TxType: protocol.TransactionTypeWriteData, Sigs: one.Sigs, Votes: one.Votes}, tls)
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
	m := newVoteModel(Facts{TxType: protocol.TransactionTypeWriteData}, tls)
	_, err := m.pageVote(context.Background(), pPage, path, protocol.DelegationDepthLimit+1)
	requireUnevaluable(t, err)
}

func keyHash(name string) []byte {
	h := sha256.Sum256([]byte(name))
	return h[:]
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
