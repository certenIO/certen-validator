// Copyright 2026 Certen Protocol

package main

import (
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB4-F67: the model checks each book's vote against the network's own record of it, so G1 must read that record -
// the authority signatures core produced, with the page each names as its origin and the vote it cast - from the
// transaction's signature sets. It read the delegated ones without their origin and skipped the principal's own.

func recordedSets(t *testing.T) map[string]interface{} {
	t.Helper()
	resp := loadRecordedResponse(t, "g0_inclusion.json")
	return resp["result"].(map[string]interface{})["value"].(map[string]interface{})
}

// Kermit, certen-kermit-12: the principal's signature set carries its book's vote, cast by page 1.
func TestRecordedVotes_ThePrincipalsVoteIsRead(t *testing.T) {
	arrivals, votes, err := recordedVotesOf(recordedSets(t), "acc://certen-kermit-12.acme/data")
	if err != nil {
		t.Fatal(err)
	}
	if len(arrivals) != 0 {
		t.Fatalf("read %d delegated votes from a transaction with none", len(arrivals))
	}
	if len(votes) != 1 {
		t.Fatalf("read %d recorded votes, want the principal's one: %+v", len(votes), votes)
	}
	v := votes[0]
	if v.Authority != "acc://certen-kermit-12.acme/book" || v.Origin != "acc://certen-kermit-12.acme/book/1" ||
		v.Vote != protocol.VoteTypeAccept || v.ID == "" {
		t.Fatalf("recorded vote %+v", v)
	}
}

// A delegated vote is read with its origin and its vote; the vote is not assumed to be an acceptance.
func TestRecordedVotes_ADelegatedVoteCarriesItsOriginAndVote(t *testing.T) {
	sets := map[string]interface{}{"signatures": map[string]interface{}{"records": []interface{}{
		map[string]interface{}{
			"account": map[string]interface{}{"url": "acc://p.acme/book/1"},
			"signatures": map[string]interface{}{"records": []interface{}{map[string]interface{}{
				"id": "acc://" + "ab" + "000000000000000000000000000000000000000000000000000000000000cd" + "@p.acme/book/1",
				"message": map[string]interface{}{"type": "signature", "signature": map[string]interface{}{
					"type": "authority", "origin": "acc://d.acme/book/2", "authority": "acc://d.acme/book",
					"vote": "reject", "delegator": []interface{}{"acc://p.acme/book/1"},
				}},
			}}},
		},
	}}}
	arrivals, votes, err := recordedVotesOf(sets, "acc://p.acme/data")
	if err != nil {
		t.Fatal(err)
	}
	if len(votes) != 0 || len(arrivals) != 1 {
		t.Fatalf("arrivals %+v, votes %+v", arrivals, votes)
	}
	a := arrivals[0]
	if a.Origin != "acc://d.acme/book/2" || a.Vote != protocol.VoteTypeReject || a.Authority != "acc://d.acme/book" {
		t.Fatalf("delegated vote %+v", a)
	}
}

// A recorded authority signature that names no origin is not a record of which page voted.
func TestRecordedVotes_AVoteWithoutAnOriginIsRefused(t *testing.T) {
	sets := map[string]interface{}{"signatures": map[string]interface{}{"records": []interface{}{
		map[string]interface{}{
			"account": map[string]interface{}{"url": "acc://p.acme/data"},
			"signatures": map[string]interface{}{"records": []interface{}{map[string]interface{}{
				"id": "acc://" + "ab" + "000000000000000000000000000000000000000000000000000000000000ef" + "@p.acme/data",
				"message": map[string]interface{}{"type": "signature", "signature": map[string]interface{}{
					"type": "authority", "authority": "acc://p.acme/book",
				}},
			}}},
		},
	}}}
	if _, _, err := recordedVotesOf(sets, "acc://p.acme/data"); err == nil {
		t.Fatal("an authority signature with no origin was accepted as a record of a vote")
	}
}
