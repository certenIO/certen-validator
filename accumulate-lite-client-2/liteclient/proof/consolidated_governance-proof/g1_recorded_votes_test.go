// Copyright 2026 Certen Protocol

package main

import (
	"encoding/hex"
	"strings"
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

// RB4-F66: each recorded vote is kept as the chain holds it - Accumulate's binary encoding of the authority signature,
// decoding back to the vote the fact records - so the vote's evidence can bind the fact to its bytes.
func TestRecordedVotes_BytesAreKeptPerVote(t *testing.T) {
	_, votes, binaries, err := recordedVotesWithBytes(recordedSets(t), "acc://certen-kermit-12.acme/data")
	if err != nil {
		t.Fatal(err)
	}
	if len(votes) != 1 || len(binaries) != 1 {
		t.Fatalf("votes %d, bytes %d", len(votes), len(binaries))
	}
	b, err := hex.DecodeString(binaries[strings.ToLower(votes[0].ID)])
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.UnmarshalSignature(b)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := sig.(*protocol.AuthoritySignature)
	if !ok || a.Origin.String() != "acc://certen-kermit-12.acme/book/1" || a.Authority.String() != "acc://certen-kermit-12.acme/book" {
		t.Fatalf("the kept bytes decode to %+v", sig)
	}
}

// A recorded vote whose signature does not decode with Accumulate's types cannot be carried as evidence, and is
// refused rather than counted without it.
func TestRecordedVotes_UndecodableBytesAreRefused(t *testing.T) {
	sets := map[string]interface{}{"signatures": map[string]interface{}{"records": []interface{}{
		map[string]interface{}{
			"account": map[string]interface{}{"url": "acc://p.acme/data"},
			"signatures": map[string]interface{}{"records": []interface{}{map[string]interface{}{
				"id": "acc://" + strings.Repeat("ab", 32) + "@p.acme/data",
				"message": map[string]interface{}{"type": "signature", "signature": map[string]interface{}{
					"type": "authority", "origin": "acc://p.acme/book/1", "authority": "acc://p.acme/book",
					"vote": "accept", "txID": "not a txid",
				}},
			}}},
		},
	}}}
	if _, _, _, err := recordedVotesWithBytes(sets, "acc://p.acme/data"); err == nil {
		t.Fatal("a recorded vote whose signature does not decode was read without its bytes")
	}
}
