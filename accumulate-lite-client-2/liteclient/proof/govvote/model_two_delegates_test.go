// Copyright 2026 Certen Protocol

package govvote

import "testing"

// A page of threshold 2 whose two entries are delegate books, each casting a delegated vote (AGT A-03: two officers through the principal's
// officers' page). The page's vote is reproduced only from BOTH delegates' own signatures: with the first delegate's arrival recorded but its
// own signature absent from the facts the vote is unevaluable - the refusal the validators gave before the collector carried that chain.
func TestVotes_TwoDelegatesEachCastOneVoteOfAThresholdTwoPage(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1}, vPage{version: 1, accept: 2, delegates: []string{dBook, eBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"d1"}}),
		normalizeAccURL(ePage): timeline(t, ePage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"e1"}}),
	}
	facts := Facts{
		Sigs: []SigFact{sig(dPage, "d1", 1, 10, pPage), sig(ePage, "e1", 1, 12, pPage)},
		Arrivals: []ArrivalFact{
			from(arrival(pPage, dBook, 11), dPage),
			from(arrival(pPage, eBook, 13), ePage),
		},
		Votes: []RecordedVote{recorded(pBook, pPage, 13)},
	}
	av, err := account(t, tls, facts, pBook)
	requireSatisfied(t, av, err, true)

	facts.Sigs = facts.Sigs[1:] // the first delegate's own signature is missing, as in the capture of intent 0c720b71
	_, err = account(t, tls, facts, pBook)
	requireUnevaluable(t, err)
}
