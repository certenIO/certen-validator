// Copyright 2026 Certen Protocol

package govvote

import "testing"

// A transaction held by HoldUntil (RB9-C1b-1-F2, settled in C1b-2 against sig_common.go:84-172). Core computes the authority signature
// when the signature that completes a page's vote arrives (maybeSendAuthoritySignature asks AuthorityWillVote then), stores it while the
// transaction is held - ONE per authority, replaced by a signature whose origin page is equal or lower in the book (recordOnHoldAuthSig,
// comparePriority) - and at the release produces the stored signature unchanged (releaseHeldAuthSigs): Origin and Vote are never asked
// again at the release.

// A higher page decides first and is held; a lower page decides later and replaces it. The release at block 30 produces the lower
// page's vote: the earlier decision of the higher page is not a disagreement with the record.
func TestVotes_AHeldVoteIsTheLowestPageThatDecidedBeforeTheRelease(t *testing.T) {
	r := recorded(pBook, pPage, 30)
	r.ReleasedAt = 30
	facts := Facts{Sigs: []SigFact{sig(pPage2, "b", 1, 10), sig(pPage, "a", 1, 20)}, Votes: []RecordedVote{r}, HoldUntil: 1000}
	av, err := account(t, twoPages(t, 1), facts, pBook)
	requireSatisfied(t, av, err, true)
	if by := av.Authorities[0].Vote.By; by != normalizeAccURL(pPage) {
		t.Fatalf("the held vote is attributed to %s; page 1 replaced page 2's stored signature", by)
	}
}

// The same facts without a hold: page 2's decision at block 10 produced its vote at once, so a record naming page 1 contradicts it.
func TestVotes_TheSameFactsWithoutAHoldContradictTheRecord(t *testing.T) {
	facts := Facts{Sigs: []SigFact{sig(pPage2, "b", 1, 10), sig(pPage, "a", 1, 20)}, Votes: []RecordedVote{recorded(pBook, pPage, 30)}}
	_, err := account(t, twoPages(t, 1), facts, pBook)
	requireUnevaluable(t, err)
}

// A hold whose release is not established does not weaken the check either.
func TestVotes_AHeldVoteWithoutAnEstablishedReleaseIsJudgedAsBefore(t *testing.T) {
	facts := Facts{Sigs: []SigFact{sig(pPage2, "b", 1, 10), sig(pPage, "a", 1, 20)}, Votes: []RecordedVote{recorded(pBook, pPage, 30)}, HoldUntil: 1000}
	_, err := account(t, twoPages(t, 1), facts, pBook)
	requireUnevaluable(t, err)
}

// A lower page that decided before the release would have won the stored slot: a record naming the higher page is impossible.
func TestVotes_AHeldVoteCannotBeAHigherPageWhenALowerOneDecidedBeforeTheRelease(t *testing.T) {
	r := recorded(pBook, pPage2, 30)
	r.ReleasedAt = 30
	facts := Facts{Sigs: []SigFact{sig(pPage, "a", 1, 10), sig(pPage2, "b", 1, 20)}, Votes: []RecordedVote{r}, HoldUntil: 1000}
	_, err := account(t, twoPages(t, 1), facts, pBook)
	requireUnevaluable(t, err)
	// A lower page that decided only after the release did not take part in it.
	r2 := recorded(pBook, pPage2, 30)
	r2.ReleasedAt = 30
	facts2 := Facts{Sigs: []SigFact{sig(pPage2, "b", 1, 20), sig(pPage, "a", 1, 40)}, Votes: []RecordedVote{r2}, HoldUntil: 1000}
	av, err := account(t, twoPages(t, 1), facts2, pBook)
	requireSatisfied(t, av, err, true)
}
