// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The Phase 7 corpus, through the authority vote.
//
// Every page state and signature here came off Kermit. Each signature goes
// through the real extractor (messageResultFor renders it the way Kermit
// returns it), and the vote model decides. What the corpus did not capture is
// the delegated votes the network recorded at each delegator page; for a
// transaction the network DELIVERED those exist, and they are supplied here as
// core records them (sig_authority.go: at delegator[0], path = the rest). For
// a transaction that was never delivered none is supplied - the network did
// not record a vote it rejected.
//
// Ported from phase7_resolution_test.go, whose resolver this model replaces.

const corpusBlock = 10

func corpusTimelines(t *testing.T, cf corpusFile) memTimelines {
	t.Helper()
	if len(cf.Pages) == 0 {
		t.Fatal("corpus carries no page states - re-run `go run ./cmd/p7corpus -stage capture`")
	}
	tls := memTimelines{}
	for url, p := range cf.Pages {
		page, err := pageFromState(normalizeAccURL(url), p.state())
		if err != nil {
			t.Fatalf("corpus page %s: %v", url, err)
		}
		tls[normalizeAccURL(url)] = &pageTimeline{Page: normalizeAccURL(url),
			States: []timedState{{Block: 1, Page: page}}}
	}
	return tls
}

// corpusFacts extracts a case's signatures through the real extractor and, if
// the network delivered it, the delegated votes it recorded.
func corpusFacts(t *testing.T, cf corpusFile, caseName string) (voteFacts, string, bool) {
	t.Helper()
	facts := voteFacts{TxType: protocol.TransactionTypeWriteData}
	var principal string
	delivered := false
	sv := SignatureVerifier{}
	for i, tr := range cf.Traces {
		if tr.Case != caseName {
			continue
		}
		principal = normalizeAccURL(strings.TrimSuffix(tr.Principal, "/") + "/book/1")
		delivered = delivered || tr.ExecStatus == "delivered"
		sig, err := sv.ExtractSignatureFromMessageResult(messageResultFor(tr))
		if err != nil {
			t.Fatalf("%s: extract: %v", tr.Label, err)
		}
		f, isVote, err := sigFactOf(ValidatedSignature{MessageID: tr.Label + "#" + string(rune('a'+i)),
			Signature: sig, Receipt: ReceiptData{LocalBlock: corpusBlock}})
		if err != nil || !isVote {
			t.Fatalf("%s: fact: %v", tr.Label, err)
		}
		facts.Sigs = append(facts.Sigs, f)
	}
	if principal == "" {
		t.Fatalf("case %s is not in the corpus", caseName)
	}
	if delivered {
		for _, s := range facts.Sigs {
			// The vote travels inward-out: from the signer's book to its
			// innermost delegator, and from each delegator's book outward.
			hops := append(append([]string{}, s.Path...), s.Signer)
			for i := len(hops) - 1; i > 0; i-- {
				facts.Arrivals = append(facts.Arrivals, arrivalFact{
					ID: "arrival:" + hops[i] + "->" + hops[i-1], Page: hops[i-1],
					Authority: bookOfPage(hops[i]), Path: hops[:i-1], Block: corpusBlock + 1,
				})
			}
		}
	}
	return facts, principal, delivered
}

func corpusVote(t *testing.T, cf corpusFile, caseName string) (*AccountVote, error) {
	t.Helper()
	facts, principal, _ := corpusFacts(t, cf, caseName)
	return newVoteModel(facts, corpusTimelines(t, cf)).accountVote(context.Background(),
		"acc://corpus.acme/data", []AccountAuthority{{URL: bookOfPage(principal)}}, nil, false)
}

// B, C, D, E, F, H and H-repeat: delivered by Kermit, and satisfied here.
func TestCorpusVotes_DeliveredCasesAreSatisfied(t *testing.T) {
	cf := loadCorpus(t)
	for _, name := range []string{"B", "C", "C-merkle", "D", "E", "F", "H", "H-repeat"} {
		t.Run(name, func(t *testing.T) {
			av, err := corpusVote(t, cf, name)
			if err != nil {
				t.Fatalf("vote: %v", err)
			}
			if !av.Satisfied {
				t.Fatalf("a transaction Kermit delivered is not authorized: %s", av.Describe())
			}
			t.Logf("%s: %s, %d accepting key(s)", name, av.Describe(), av.acceptingKeys())
		})
	}
}

// D and F are the cases whose signing key is NOT on the outer page, so they
// cannot be satisfied without walking delegation.
func TestCorpusVotes_DelegationIsActuallyExercised(t *testing.T) {
	cf := loadCorpus(t)
	var discriminating []string
	for _, tr := range cf.Traces {
		if len(tr.Delegators) > 0 && tr.KeyIsDirectOnOuterPage != nil && !*tr.KeyIsDirectOnOuterPage {
			discriminating = append(discriminating, tr.Case)
		}
	}
	if len(discriminating) == 0 {
		t.Fatal("no corpus case has a signing key absent from its outer page")
	}
	for _, name := range discriminating {
		t.Run(name, func(t *testing.T) {
			av, err := corpusVote(t, cf, name)
			if err != nil || !av.Satisfied {
				t.Fatalf("not satisfied: %v %+v", err, av)
			}
			delegated := false
			for _, a := range av.Authorities {
				for _, pv := range a.Vote.Pages {
					if len(pv.Delegates) > 0 {
						delegated = true
					}
				}
			}
			if !delegated {
				t.Fatal("satisfied without any delegate's vote - this case cannot be")
			}
		})
	}
}

// Case I: a 2-of-3 page signed twice by the SAME key. One key is one entry,
// and Kermit agrees: the transaction is still pending.
func TestCorpusVotes_DuplicateKeyCountsOnce(t *testing.T) {
	cf := loadCorpus(t)
	av, err := corpusVote(t, cf, "I")
	if err != nil {
		t.Fatalf("vote: %v", err)
	}
	if av.Satisfied {
		t.Fatalf("one key signing twice satisfied a 2-of-3 page: %s", av.Describe())
	}
	if n := av.Authorities[0].Vote.Pages[0].Counted; len(n) != 1 {
		t.Fatalf("two signatures from one key counted as %d entries", len(n))
	}
}

// H and H-repeat traverse the same cycle once and twice; both satisfy the SAME
// single entry of the principal page, once.
func TestCorpusVotes_LongerPathGrantsNoMoreAuthority(t *testing.T) {
	cf := loadCorpus(t)
	short, err := corpusVote(t, cf, "H")
	if err != nil {
		t.Fatal(err)
	}
	long, err := corpusVote(t, cf, "H-repeat")
	if err != nil {
		t.Fatal(err)
	}
	sp, lp := short.Authorities[0].Vote.Pages[0], long.Authorities[0].Vote.Pages[0]
	if len(sp.Counted) != 1 || len(lp.Counted) != 1 || sp.Counted[0].Entry != lp.Counted[0].Entry {
		t.Fatalf("the two paths do not satisfy the same single entry: %+v vs %+v", sp.Counted, lp.Counted)
	}
}

// Case J: correct inner key, wrong delegator chain. It reaches no authority
// the account is governed by; it is reported, and nothing is satisfied.
func TestCorpusVotes_WrongDelegatorChainReachesNothing(t *testing.T) {
	cf := loadCorpus(t)
	av, err := corpusVote(t, cf, "J")
	if err != nil {
		t.Fatalf("vote: %v", err)
	}
	if av.Satisfied {
		t.Fatal("a signature whose path the authority does not grant satisfied it")
	}
	if len(av.Unused) == 0 {
		t.Fatal("the wrong-chain signature was not reported as reaching no authority")
	}
	t.Logf("reported: %s", av.Unused[0].Reason)
}

// Case G: a 21-deep chain is refused by the extractor, for its depth - never
// as a threshold shortfall.
func TestCorpusVotes_DepthIsRefusedAtExtraction(t *testing.T) {
	cf := loadCorpus(t)
	for _, tr := range cf.Traces {
		if tr.Case != "G" {
			continue
		}
		_, err := (&SignatureVerifier{}).ExtractSignatureFromMessageResult(messageResultFor(tr))
		var depth DelegationDepthExceeded
		if !errors.As(err, &depth) {
			t.Fatalf("a %d-deep chain was not refused for its depth: %v", len(tr.Delegators), err)
		}
		return
	}
	t.Fatal("case G is not in the corpus")
}

// Case K: a btc signature Kermit delivered is refused as unsupported, never as
// a threshold reason.
func TestCorpusVotes_UnsupportedTypeIsRefusedAtExtraction(t *testing.T) {
	cf := loadCorpus(t)
	for _, tr := range cf.Traces {
		if tr.Case != "K" {
			continue
		}
		_, err := (&SignatureVerifier{}).ExtractSignatureFromMessageResult(messageResultFor(tr))
		if _, ok := IsUnsupportedSignatureType(err); !ok {
			t.Fatalf("a btc signature was not refused as unsupported: %v", err)
		}
		return
	}
	t.Fatal("case K is not in the corpus")
}

// Every direct ed25519 signature in the corpus satisfies its own page alone,
// and the same signature at a version its page never held is not believed.
func TestCorpusVotes_DirectSignaturesAndVersionBinding(t *testing.T) {
	cf := loadCorpus(t)
	tls := corpusTimelines(t, cf)
	checked := 0
	for i, tr := range cf.Traces {
		if tr.KeyType != "ed25519" || len(tr.Delegators) > 0 {
			continue
		}
		sig, err := (&SignatureVerifier{}).ExtractSignatureFromMessageResult(messageResultFor(tr))
		if err != nil {
			t.Fatalf("%s: %v", tr.Label, err)
		}
		f, _, err := sigFactOf(ValidatedSignature{MessageID: tr.Label, Signature: sig,
			Receipt: ReceiptData{LocalBlock: corpusBlock}})
		if err != nil {
			t.Fatal(err)
		}
		page := f.Signer
		m := newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData, Sigs: []sigFact{f}}, tls)
		pv, err := m.pageVote(context.Background(), page, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", tr.Label, err)
		}
		if len(pv.Counted) != 1 {
			t.Fatalf("%s: a direct signature counted %d entries on its own page", tr.Label, len(pv.Counted))
		}

		wrong := f
		wrong.Version++
		m = newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData, Sigs: []sigFact{wrong}}, tls)
		if _, err := m.pageVote(context.Background(), page, nil, 0); err == nil {
			t.Fatalf("%s: a signature at a version the page never held was believed", tr.Label)
		}
		checked++
		_ = i
	}
	if checked == 0 {
		t.Fatal("no direct signature in the corpus")
	}
}

// Case D is satisfied by signatures on two different pages, and the evidence
// names both - every signer account a multi-partition proof needs a leg for.
func TestCorpusVotes_EvidenceNamesEverySignerPage(t *testing.T) {
	cf := loadCorpus(t)
	av, err := corpusVote(t, cf, "D")
	if err != nil || !av.Satisfied {
		t.Fatalf("case D: %v %+v", err, av)
	}
	if got := av.SignerPages(); len(got) < 2 {
		t.Fatalf("case D is satisfied from two pages, the evidence names %v", got)
	}
	dup, err := corpusVote(t, cf, "I")
	if err != nil {
		t.Fatal(err)
	}
	if got := dup.SignerPages(); len(got) > 1 {
		t.Fatalf("case I has one signing page, the evidence names %v", got)
	}
}
