// Copyright 2026 Certen Protocol

package govvote

import (
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB4-F67, the book. A book votes with whichever of its pages decides FIRST (AuthorityWillVote asks each page at the
// moment a signature is processed), and Accumulate records which page that was: the authority signature it produces
// names it as its origin - on the principal for the account's own authorities, on the delegator page for a delegate.
// The model took the lowest-numbered page that EVER voted, so a page that decided after the transaction executed
// could displace the one that did, and it never compared its answer with the network's record. The book's vote is
// now the page the network names, provided replaying that page reaches the recorded vote and no page of the book
// decided in an earlier block; anything else is a disagreement with the network and stops the vote.

const pPage2 = "acc://p.acme/book/2"

func twoPages(t *testing.T, accept1 uint64) memTimelines {
	return memTimelines{
		normalizeAccURL(pPage):  timeline(t, pPage, []int64{1}, vPage{version: 1, accept: accept1, keys: []string{"a", "a2"}}),
		normalizeAccURL(pPage2): timeline(t, pPage2, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"b"}}),
	}
}

func recorded(book, origin string, block int64) RecordedVote {
	return RecordedVote{ID: "vote-" + origin, Authority: normalizeAccURL(book), Origin: normalizeAccURL(origin),
		Vote: protocol.VoteTypeAccept, Block: block}
}

func TestVotes_TheBookVotesWithThePageThatDecidedFirst(t *testing.T) {
	facts := Facts{Sigs: []SigFact{sig(pPage2, "b", 1, 10), sig(pPage, "a", 1, 70)},
		Votes: []RecordedVote{recorded(pBook, pPage2, 10)}}
	av, err := account(t, twoPages(t, 1), facts, pBook)
	requireSatisfied(t, av, err, true)
	if by := av.Authorities[0].Vote.By; by != normalizeAccURL(pPage2) {
		t.Fatalf("the book's vote is attributed to %s; page 2 decided first and the network records it", by)
	}
}

// Two pages deciding in the same block: which reached its threshold first is not in the block number, and is in the
// network's record.
func TestVotes_TheNetworksRecordNamesTheDecidingPageWithinABlock(t *testing.T) {
	facts := Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10), sig(pPage2, "b", 1, 10)},
		Votes: []RecordedVote{recorded(pBook, pPage2, 10)}}
	av, err := account(t, twoPages(t, 1), facts, pBook)
	requireSatisfied(t, av, err, true)
	if by := av.Authorities[0].Vote.By; by != normalizeAccURL(pPage2) {
		t.Fatalf("the book's vote is attributed to %s; the network records page 2", by)
	}
}

func TestVotes_ARecordTheReplayDoesNotReproduceStopsTheVote(t *testing.T) {
	// The network names page 1, whose one signature does not reach its threshold of 2.
	facts := Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10)}, Votes: []RecordedVote{recorded(pBook, pPage, 11)}}
	_, err := account(t, twoPages(t, 2), facts, pBook)
	requireUnevaluable(t, err)
}

func TestVotes_AnEarlierDecisionOnAnotherPageContradictsTheRecord(t *testing.T) {
	facts := Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10), sig(pPage2, "b", 1, 20)},
		Votes: []RecordedVote{recorded(pBook, pPage2, 20)}}
	_, err := account(t, twoPages(t, 1), facts, pBook)
	requireUnevaluable(t, err)
}

func TestVotes_AVoteTheNetworkNeverRecordedStopsTheVote(t *testing.T) {
	facts := Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10)}}
	_, err := account(t, twoPages(t, 1), facts, pBook)
	requireUnevaluable(t, err)
}

// No record and no page that decided: the authority did not vote. That is a verdict, not a disagreement.
func TestVotes_NoRecordAndNoDecisionIsNotAVote(t *testing.T) {
	facts := Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10)}}
	av, err := account(t, twoPages(t, 2), facts, pBook)
	requireSatisfied(t, av, err, false)
}

func TestVotes_ADelegatedVoteMustComeFromThePageItsRecordNames(t *testing.T) {
	const dPage2 = "acc://d.acme/book/2"
	tls := memTimelines{
		normalizeAccURL(pPage):  timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 1, delegates: []string{dBook}}),
		normalizeAccURL(dPage):  timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"d"}}),
		normalizeAccURL(dPage2): timeline(t, dPage2, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"e"}}),
	}
	arr := arrival(pPage, dBook, 11)
	arr.Origin = normalizeAccURL(dPage2) // the network names page 2 of the delegate; only page 1 signed
	facts := Facts{Sigs: []SigFact{sig(dPage, "d", 1, 10, pPage)}, Arrivals: []ArrivalFact{arr},
		Votes: []RecordedVote{recorded(pBook, pPage, 12)}}
	_, err := account(t, tls, facts, pBook)
	requireUnevaluable(t, err)
}
