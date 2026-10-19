package main

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The vote-by-vote half of the comparison must be able to fail on its own: each way the 2.1 document's votes can differ from the votes v1
// recorded is a disagreement, and agreement is silent. (The live fixtures cannot reach these branches: an edit that removes a vote is
// caught earlier, as a role mismatch.)
func TestVoteByVoteComparisonReportsEachWayTheDocumentDiffersFromV1(t *testing.T) {
	authority := func(book, vote, by string) govvote.AuthorityVote {
		return govvote.AuthorityVote{Authority: book, Vote: govvote.BookVote{Book: book, Voted: true, Vote: vote, By: by}}
	}
	bank, cust := "acc://bank.acme/book", "acc://cust.acme/book"
	av := &govvote.AccountVote{Authorities: []govvote.AuthorityVote{
		authority(bank, "accept", "acc://bank.acme/book/1"),
		authority(cust, "accept", "acc://cust.acme/book/1"),
		{Authority: "acc://idle.acme/book", Vote: govvote.BookVote{Book: "acc://idle.acme/book"}}, // did not vote: not compared
	}}
	same := []proofv2.Vote{
		{Authority: bank, Origin: "acc://bank.acme/book/1", Vote: "accept"},
		{Authority: cust, Origin: "acc://cust.acme/book/1", Vote: "ACCEPT"}, // case is not a difference
	}
	if got := compareVotes(av, same); len(got) != 0 {
		t.Fatalf("matching votes reported as differing: %v", got)
	}
	cases := []struct {
		name  string
		votes []proofv2.Vote
		av    *govvote.AccountVote
		want  string
	}{
		{"a vote v1 recorded is missing from the document", same[:1], av, "the document carries no vote for it"},
		{"the document's vote differs", []proofv2.Vote{same[0], {Authority: cust, Origin: "acc://cust.acme/book/1", Vote: "reject"}}, av, "v1 accept, document reject"},
		{"the vote was decided by another page", []proofv2.Vote{same[0], {Authority: cust, Origin: "acc://cust.acme/book/2", Vote: "accept"}}, av, "v1 decided by page acc://cust.acme/book/1, the document by acc://cust.acme/book/2"},
		{"the document carries a vote v1 did not record", append(append([]proofv2.Vote{}, same...), proofv2.Vote{Authority: "acc://idle.acme/book", Origin: "acc://idle.acme/book/1", Vote: "accept"}), av, "the document carries a vote that v1 did not record"},
		{"v1 recorded nothing at all", same, nil, "the document carries a vote that v1 did not record"},
	}
	for _, c := range cases {
		got := compareVotes(c.av, c.votes)
		if len(got) == 0 {
			t.Errorf("%s: no disagreement reported", c.name)
			continue
		}
		if !strings.Contains(strings.Join(got, "\n"), c.want) {
			t.Errorf("%s: reported %v, want one containing %q", c.name, got, c.want)
		}
	}
}
