// Copyright 2026 Certen Protocol

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB4-F67. Accumulate does not refuse a signature on a transaction that has already executed (msg_signature.go and
// sig_user.go never ask whether the transaction is pending), so a page's signature records can grow after the page
// voted - on another partition, where G1 cannot compare blocks with the execution, nothing filters them. The model
// tallied every recorded contribution at the NEWEST version it saw. A page therefore:
//   - could be judged on a signature set it only reached after it had voted, after a later rotation, and reported
//     as not having voted (a false rejection), and
//   - reported a different vote record depending on when it was read.
// Accumulate's page votes at the first moment its active set - replaced whenever an entry at a newer version
// arrives - reaches a decision (SignerWillVote, addSignature), and its set is cleared when it does. The model now
// walks the page's records in block order the same way, and what was recorded after the deciding block is excluded
// by name.

func TestVotes_ARotationAfterThePageVotedDoesNotReopenIt(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1, 60},
		vPage{version: 1, accept: 1, keys: []string{"a"}},
		vPage{version: 2, accept: 2, keys: []string{"a", "b"}})}
	// a decides at v1, block 10. The page is rotated at 60 and b signs the executed transaction at v2, block 70.
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "a", 1, 10), sig(pPage, "b", 2, 70)},
		Votes: []recordedVote{recorded(pBook, pPage, 10)}}, pBook)
	requireSatisfied(t, av, err, true)
	pv := av.Authorities[0].Vote.Pages[0]
	if pv.Version != 1 || pv.DecidedAt != 10 {
		t.Fatalf("the page decided at version %d, block %d; want version 1 at block 10", pv.Version, pv.DecidedAt)
	}
	requireExcludedAfterDecision(t, pv, "sig-b-")
}

func TestVotes_ASignatureAfterThePageVotedIsNotCounted(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 1, keys: []string{"a", "b"}})}
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "b", 1, 70), sig(pPage, "a", 1, 10)},
		Votes: []recordedVote{recorded(pBook, pPage, 10)}}, pBook)
	requireSatisfied(t, av, err, true)
	pv := av.Authorities[0].Vote.Pages[0]
	if len(pv.Counted) != 1 || pv.Counted[0].Entry != "key:"+kh("a") || pv.Counted[0].Block != 10 {
		t.Fatalf("counted %+v; want only a, at block 10", pv.Counted)
	}
	if pv.DecidedAt != 10 {
		t.Fatalf("decided at %d; want 10", pv.DecidedAt)
	}
	requireExcludedAfterDecision(t, pv, "sig-b-")
}

// A delegated vote that arrives after the page already voted on its own keys is not part of the decision, and the
// delegate is not evaluated for it.
func TestVotes_AnArrivalAfterThePageVotedIsNotCounted(t *testing.T) {
	tls := memTimelines{
		normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
			vPage{version: 1, accept: 1, keys: []string{"a"}, delegates: []string{dBook}}),
		normalizeAccURL(dPage): timeline(t, dPage, []int64{1}, vPage{version: 1, accept: 1, keys: []string{"d"}}),
	}
	facts := voteFacts{
		Sigs:     []sigFact{sig(pPage, "a", 1, 10), sig(dPage, "d", 1, 500, pPage)},
		Arrivals: []arrivalFact{from(arrival(pPage, dBook, 80), dPage)},
		Votes:    []recordedVote{recorded(pBook, pPage, 10)},
	}
	av, err := account(t, tls, facts, pBook)
	requireSatisfied(t, av, err, true)
	pv := av.Authorities[0].Vote.Pages[0]
	if len(pv.Counted) != 1 || len(pv.Delegates) != 0 {
		t.Fatalf("counted %+v, delegates %d; want only a, no delegate", pv.Counted, len(pv.Delegates))
	}
	requireExcludedAfterDecision(t, pv, "arr-")
}

// The record is a function of the chain, not of the order it was read in.
func TestVotes_TheRecordDoesNotDependOnReadOrder(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, keys: []string{"a", "b", "c"}})}
	one := []sigFact{sig(pPage, "a", 1, 10), sig(pPage, "b", 1, 12), sig(pPage, "c", 1, 90)}
	two := []sigFact{one[2], one[0], one[1]}
	rec := []recordedVote{recorded(pBook, pPage, 12)}
	a1, err1 := account(t, tls, voteFacts{Sigs: one, Votes: rec}, pBook)
	a2, err2 := account(t, tls, voteFacts{Sigs: two, Votes: rec}, pBook)
	requireSatisfied(t, a1, err1, true)
	requireSatisfied(t, a2, err2, true)
	j1, _ := json.Marshal(a1)
	j2, _ := json.Marshal(a2)
	if string(j1) != string(j2) {
		t.Fatalf("read in another order the record differs:\n%s\n%s", j2, j1)
	}
	if pv := a1.Authorities[0].Vote.Pages[0]; pv.DecidedAt != 12 || len(pv.Counted) != 2 {
		t.Fatalf("decided at %d counting %d; want block 12 counting a and b", pv.DecidedAt, len(pv.Counted))
	}
}

// Every threshold that decided the vote is recorded, not only the accept threshold.
func TestVotes_ThePageRecordsEveryThreshold(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 2, reject: 3, response: 2, keys: []string{"a", "b", "c"}})}
	av, err := account(t, tls, voteFacts{Sigs: []sigFact{sig(pPage, "a", 1, 10), sig(pPage, "b", 1, 11)},
		Votes: []recordedVote{recorded(pBook, pPage, 11)}}, pBook)
	requireSatisfied(t, av, err, true)
	pv := av.Authorities[0].Vote.Pages[0]
	if pv.Threshold != 2 || pv.RejectThreshold != 3 || pv.ResponseThreshold != 2 {
		t.Fatalf("thresholds accept=%d reject=%d response=%d; want 2/3/2", pv.Threshold, pv.RejectThreshold, pv.ResponseThreshold)
	}
	_ = protocol.VoteTypeAccept
}

func requireExcludedAfterDecision(t *testing.T, pv PageVote, byPrefix string) {
	t.Helper()
	for _, e := range pv.Excluded {
		if strings.HasPrefix(e.By, byPrefix) && strings.Contains(e.Reason, "after the page's vote was decided") {
			return
		}
	}
	t.Fatalf("no exclusion of %s* as recorded after the decision: %+v", byPrefix, pv.Excluded)
}

// The same key recorded twice in one block: which message core processed last is not in the block number. The same
// vote credits one message deterministically; different votes make the vote itself unknown.
func TestVotes_OneKeyTwiceInOneBlockIsCreditedDeterministically(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 1, keys: []string{"a"}})}
	s1, s2 := sig(pPage, "a", 1, 10), sig(pPage, "a", 1, 10)
	s1.ID, s2.ID = "sig-a-first", "sig-a-second"
	rec := []recordedVote{recorded(pBook, pPage, 10)}
	a1, err1 := account(t, tls, voteFacts{Sigs: []sigFact{s1, s2}, Votes: rec}, pBook)
	a2, err2 := account(t, tls, voteFacts{Sigs: []sigFact{s2, s1}, Votes: rec}, pBook)
	requireSatisfied(t, a1, err1, true)
	requireSatisfied(t, a2, err2, true)
	j1, _ := json.Marshal(a1)
	j2, _ := json.Marshal(a2)
	if string(j1) != string(j2) {
		t.Fatalf("read in another order the record differs:\n%s\n%s", j2, j1)
	}
}

func TestVotes_OneKeyVotingBothWaysInOneBlockIsUnevaluable(t *testing.T) {
	tls := memTimelines{normalizeAccURL(pPage): timeline(t, pPage, []int64{1},
		vPage{version: 1, accept: 1, keys: []string{"a"}})}
	s1, s2 := sig(pPage, "a", 1, 10), vote(sig(pPage, "a", 1, 10), protocol.VoteTypeReject)
	s1.ID, s2.ID = "sig-a-accept", "sig-a-reject"
	_, err := account(t, tls, voteFacts{Sigs: []sigFact{s1, s2}, Votes: []recordedVote{recorded(pBook, pPage, 10)}}, pBook)
	requireUnevaluable(t, err)
	if !strings.Contains(err.Error(), "in the same block") {
		t.Fatalf("unevaluable for another reason: %v", err)
	}
}
