// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"errors"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The authority-set rules and the verdict's refusal to be computed from what
// could not be established, through the vote model.
//
// Ported from phase7_authority_set_test.go, phase8_version_comparability_test.go
// and phase8_extra_authorities_test.go's TestP8_DerivedExtrasReachTheResolver,
// whose resolver this model replaces.

const (
	alphaData  = "acc://alpha.acme/data"
	alphaBook  = "acc://alpha.acme/book"
	alphaPage  = "acc://alpha.acme/book/1"
	betaBook   = "acc://beta.acme/book"
	betaPage   = "acc://beta.acme/book/1"
	multiBook  = "acc://multi.acme/book"
	multiPage1 = "acc://multi.acme/book/1"
	multiPage2 = "acc://multi.acme/book/2"
	extraBook  = "acc://extra.acme/book"
	extraPage  = "acc://extra.acme/book/1"
)

func oneKeyPages(t *testing.T, pages map[string]string) memTimelines {
	t.Helper()
	tls := memTimelines{}
	for page, key := range pages {
		tls[normalizeAccURL(page)] = timeline(t, page, []int64{1}, vPage{version: 1, accept: 1, keys: []string{key}})
	}
	return tls
}

func authVote(t *testing.T, tls memTimelines, sigs []sigFact, auths []AccountAuthority, extra []string, ignoreDisabled bool) (*AccountVote, error) {
	t.Helper()
	m := newVoteModel(voteFacts{TxType: protocol.TransactionTypeWriteData, Sigs: sigs}, tls)
	return m.accountVote(context.Background(), alphaData, auths, extra, ignoreDisabled)
}

// userTransactionIsReady: ALL enabled authorities must vote.
func TestAuthVotes_AllAuthoritiesMustVote(t *testing.T) {
	tls := oneKeyPages(t, map[string]string{alphaPage: "a1", betaPage: "b1"})
	auths := []AccountAuthority{{URL: alphaBook}, {URL: betaBook}}

	one, err := authVote(t, tls, []sigFact{sig(alphaPage, "a1", 1, 10)}, auths, nil, false)
	requireSatisfied(t, one, err, false)

	both, err := authVote(t, tls, []sigFact{sig(alphaPage, "a1", 1, 10), sig(betaPage, "b1", 1, 10)}, auths, nil, false)
	requireSatisfied(t, both, err, true)
	if len(both.Authorities) != 2 {
		t.Fatalf("evidence records %d authorities, expected 2", len(both.Authorities))
	}
}

// AuthorityWillVote: any one page of a book satisfies it, and the evidence
// says which.
func TestAuthVotes_AnyPageSatisfiesTheBook(t *testing.T) {
	tls := oneKeyPages(t, map[string]string{multiPage1: "m1", multiPage2: "m2"})
	av, err := authVote(t, tls, []sigFact{sig(multiPage2, "m2", 1, 10)},
		[]AccountAuthority{{URL: multiBook}}, nil, false)
	requireSatisfied(t, av, err, true)
	if by := av.Authorities[0].Vote.By; by != normalizeAccURL(multiPage2) {
		t.Fatalf("the book voted by %q, expected page 2", by)
	}
}

// A disabled authority is skipped - unless the transaction type requires
// authorization.
func TestAuthVotes_DisabledAuthorityIsSkipped(t *testing.T) {
	tls := oneKeyPages(t, map[string]string{alphaPage: "a1", betaPage: "b1"})
	auths := []AccountAuthority{{URL: alphaBook}, {URL: betaBook, Disabled: true}}
	sigs := []sigFact{sig(alphaPage, "a1", 1, 10)}

	av, err := authVote(t, tls, sigs, auths, nil, false)
	requireSatisfied(t, av, err, true)
	strict, err := authVote(t, tls, sigs, auths, nil, true)
	requireSatisfied(t, strict, err, false)
}

// An authority whose page history cannot be read is unevaluable - never a
// failure, and never skipped.
func TestAuthVotes_UnreadableAuthorityIsNotAFailure(t *testing.T) {
	tls := oneKeyPages(t, map[string]string{alphaPage: "a1"})
	gone := "acc://gone.acme/book/1"
	_, err := authVote(t, tls, []sigFact{sig(alphaPage, "a1", 1, 10), sig(gone, "g1", 1, 10)},
		[]AccountAuthority{{URL: alphaBook}, {URL: "acc://gone.acme/book"}}, nil, false)
	requireUnevaluable(t, err)
}

// The authorities a transaction's own body requires - derived from the body,
// not handed in - must vote too.
func TestAuthVotes_DerivedExtrasAreRequired(t *testing.T) {
	derived, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateKeyPage",
		"operation":[{"type":"add","entry":{"delegate":"acc://extra.acme/book"}}]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	tls := oneKeyPages(t, map[string]string{alphaPage: "a1", extraPage: "e1"})
	auths := []AccountAuthority{{URL: alphaBook}}

	only, err := authVote(t, tls, []sigFact{sig(alphaPage, "a1", 1, 10)}, auths, derived.URLs, derived.IgnoreDisabled)
	requireSatisfied(t, only, err, false)
	both, err := authVote(t, tls, []sigFact{sig(alphaPage, "a1", 1, 10), sig(extraPage, "e1", 1, 10)},
		auths, derived.URLs, derived.IgnoreDisabled)
	requireSatisfied(t, both, err, true)
}

// ---- the verdict ----------------------------------------------------------

type fixedEvaluator struct {
	vote *AccountVote
	err  error
}

func (f fixedEvaluator) Evaluate(context.Context, []ValidatedSignature, ExtraAuthorities) (*AccountVote, error) {
	return f.vote, f.err
}

func verdict(t *testing.T, eval authorizationEvaluator) (*AuthorizationResult, error) {
	t.Helper()
	sv := NewSignatureVerifier("")
	snap := AuthoritySnapshot{Page: alphaPage, StateExec: KeyPageState{Version: 1, Threshold: 1}}
	return sv.ValidateSignatureSet(context.Background(), nil, snap, "00", true, alphaData, eval, ExtraAuthorities{})
}

// A vote that could not be established stops the verdict: it is evidence
// missing, never a governance rejection.
func TestAuthVotes_UnevaluableStopsTheVerdict(t *testing.T) {
	_, err := verdict(t, fixedEvaluator{err: &VoteUnevaluable{Page: alphaPage, Reason: "test"}})
	if _, ok := IsEvidenceIncomplete(err); !ok {
		t.Fatalf("an unevaluable vote produced %v, not incomplete evidence", err)
	}
	var ve ValidationError
	if errors.As(err, &ve) {
		t.Fatal("an unevaluable vote was reported as a validation failure")
	}
}

// There is no fallback: with no evaluator nothing is evaluated.
func TestAuthVotes_NoEvaluatorNoVerdict(t *testing.T) {
	_, err := verdict(t, nil)
	if _, ok := IsEvidenceIncomplete(err); !ok {
		t.Fatalf("no evaluator produced %v, not incomplete evidence", err)
	}
}

// An authority set that did not vote to accept is a verdict - a rejection that
// names who did not vote.
func TestAuthVotes_UnsatisfiedIsARejection(t *testing.T) {
	_, err := verdict(t, fixedEvaluator{vote: &AccountVote{Account: alphaData, Satisfied: false,
		Authorities: []AuthorityVote{{Authority: alphaBook}}}})
	var ve ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("an unsatisfied authority set produced %v, not a rejection", err)
	}
}
