// Copyright 2026 Certen Protocol
//
// Phase 8 — a signer version names an AUTHORITY STATE, and states are only
// comparable to themselves.
//
// A key page's version is not a freshness stamp. It is the identity of the
// page's authority: version 1 and version 2 are two different sets of entries,
// with two different thresholds, admitting two different sets of keys. So a
// signature made against version 1 says nothing whatever about version 2, in
// either direction. It is not "stale" and it is not "invalid" — it is a
// statement about a different authority.
//
// Three outcomes follow, and this file pins all three, because collapsing any
// two of them is a live failure mode:
//
//	same version, state at execution        -> COUNTED
//	different version, state at execution   -> REFUSED (a real finding: the
//	                                           signature names a state the page
//	                                           was not in when it executed)
//	different version, state as of NOW      -> UNEVALUABLE (no comparison was
//	                                           made; the page has merely changed
//	                                           since, which every page does)
//
// The third is the one that was wrong, and it is the one that matters most.
// Reporting it as a refusal turns "this page changed after the transaction" into
// "the institution did not authorize this" — a false governance rejection, which
// runbook rule 8 places above every other failure because an error looks like a
// problem and a false rejection looks like a finding.
//
// Measured on Kermit 2026-08-26: after acc://certen-kermit-12.acme/book/1 moved
// to version 2, G1 refused transaction 1f25bb6ae4cad401 — signed and executed at
// version 1 — as a version mismatch, against a page it had queried live.
package main

import (
	"context"
	"testing"
)

// p8Page builds a one-key page at a given version.
func p8Page(version uint64, keyHash string) KeyPageState {
	return KeyPageState{
		Version:   version,
		Threshold: 1,
		Keys:      []string{keyHash},
		Entries:   []KeyPageEntry{{KeyHash: keyHash}},
	}
}

// p8ExecSource serves page states "as of execution" from memory, and can be
// told that a page cannot be reconstructed.
type p8ExecSource struct {
	pages map[string]KeyPageState
}

func (s p8ExecSource) PageStateAtExec(_ context.Context, page string) (KeyPageState, error) {
	st, ok := s.pages[normalizeAccURL(page)]
	if !ok {
		return KeyPageState{}, errNotFound(page)
	}
	return st, nil
}

const p8Principal = "acc://p8ver.acme/book/1"

// TestP8_SameVersionAtExecutionCounts is the baseline: the ordinary case must
// keep working, or the other two prove nothing.
func TestP8_SameVersionAtExecutionCounts(t *testing.T) {
	kh, sig := keyFor("p8-v-ok")
	sig.Signer = p8Principal
	sig.SignerVersion = 1

	r := &AuthorityResolver{}
	res, err := r.Resolve(context.Background(), p8Principal, p8Page(1, kh), true,
		[]SignatureData{sig})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.ThresholdMet() {
		t.Fatalf("a version-1 signature against the page at version 1 did not count: %+v", res)
	}
}

// TestP8_DifferentVersionAtExecutionIsRefused: against the page AS IT WAS, a
// version mismatch is a real finding. Accumulate would have refused it too.
func TestP8_DifferentVersionAtExecutionIsRefused(t *testing.T) {
	kh, sig := keyFor("p8-v-bad")
	sig.Signer = p8Principal
	sig.SignerVersion = 1

	r := &AuthorityResolver{}
	res, err := r.Resolve(context.Background(), p8Principal, p8Page(2, kh), true,
		[]SignatureData{sig})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.ThresholdMet() {
		t.Fatal("a signature naming a version the page was NOT at when it executed was counted")
	}
	if len(res.Refused) != 1 {
		t.Fatalf("expected exactly one refusal, got %d", len(res.Refused))
	}
	if got := res.Refused[0].Reason; got != ReasonWrongVersion {
		t.Errorf("reason = %q, want %q — against the state at execution this IS a finding",
			got, ReasonWrongVersion)
	}
}

// TestP8_DifferentVersionOnCurrentStateIsUnevaluable is the rule this phase
// added, and the one that prevents a false governance rejection.
//
// The only state available is the page as it stands today. It disagrees with the
// signature's version, which tells us the page has changed since the transaction
// executed — and nothing at all about whether the signature was good.
func TestP8_DifferentVersionOnCurrentStateIsUnevaluable(t *testing.T) {
	kh, sig := keyFor("p8-v-live")
	sig.Signer = p8Principal
	sig.SignerVersion = 1

	r := &AuthorityResolver{}
	res, err := r.Resolve(context.Background(), p8Principal, p8Page(2, kh), false,
		[]SignatureData{sig})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.ThresholdMet() {
		t.Fatal("a signature that could not be evaluated was counted toward the threshold")
	}
	if len(res.Refused) != 1 {
		t.Fatalf("expected exactly one refusal record, got %d", len(res.Refused))
	}
	got := res.Refused[0]
	if got.Reason == ReasonWrongVersion {
		t.Fatal("a version difference measured against the page's CURRENT state was reported " +
			"as a governance refusal. The page has changed since execution; that is not a " +
			"finding about the signature, and reporting it as one is a false rejection")
	}
	if got.Reason != ReasonPageUnavailable {
		t.Errorf("reason = %q, want %q", got.Reason, ReasonPageUnavailable)
	}
	if !isPageUnavailable(got) {
		t.Error("the refusal is not classified as unevaluable, so no caller will fail closed on it")
	}
}

// TestP8_UnevaluableStopsTheVerdict: an unevaluable signature must not be
// counted OUT and the threshold computed over the remainder. That is a silent
// skip, and it surfaces as a shortfall that reads as a rejection.
func TestP8_UnevaluableStopsTheVerdict(t *testing.T) {
	kh, sig := keyFor("p8-v-stop")
	sig.Signer = p8Principal
	sig.SignerVersion = 1

	book := "acc://p8ver.acme/book"
	src := fakeAuthoritySource{
		auth:  map[string][]AccountAuthority{"acc://p8ver.acme/data": {{URL: book}}},
		books: map[string][]string{book: {p8Principal}},
		// The page as it stands NOW: version 2, so not comparable.
		pages: map[string]KeyPageState{p8Principal: p8Page(2, kh)},
	}

	// No Exec source, so resolution can only see the current state.
	r := &AuthorityResolver{Source: src}
	authz, err := r.ResolveAccount(context.Background(), "acc://p8ver.acme/data", nil, false,
		[]SignatureData{sig}, nil)
	if err != nil {
		t.Fatalf("resolve account: %v", err)
	}
	if authz.Satisfied {
		t.Fatal("the authority set was reported satisfied on a signature that was never evaluated")
	}
	un := authz.UnevaluableSignatures()
	if len(un) != 1 {
		t.Fatalf("expected 1 unevaluable signature, got %d — without this the caller computes a "+
			"threshold over an incomplete set", len(un))
	}
}

// TestP8_ReplayBeatsTheLivePage: given both, resolution uses the page AS OF
// EXECUTION. This is what makes case A verifiable again after its page moved to
// version 2.
func TestP8_ReplayBeatsTheLivePage(t *testing.T) {
	kh, sig := keyFor("p8-v-replay")
	sig.Signer = p8Principal
	sig.SignerVersion = 1

	book := "acc://p8ver.acme/book"
	src := fakeAuthoritySource{
		auth:  map[string][]AccountAuthority{"acc://p8ver.acme/data": {{URL: book}}},
		books: map[string][]string{book: {p8Principal}},
		pages: map[string]KeyPageState{p8Principal: p8Page(2, kh)}, // today
	}
	exec := p8ExecSource{pages: map[string]KeyPageState{p8Principal: p8Page(1, kh)}} // at execution

	r := &AuthorityResolver{Source: src, Exec: exec}
	authz, err := r.ResolveAccount(context.Background(), "acc://p8ver.acme/data", nil, false,
		[]SignatureData{sig}, nil)
	if err != nil {
		t.Fatalf("resolve account: %v", err)
	}
	if !authz.Satisfied {
		t.Fatalf("a version-1 signature was not counted against the page replayed to version 1, "+
			"even though the replay was available: %s", authz.Describe())
	}
	if len(authz.Authorities) != 1 || len(authz.Authorities[0].Pages) != 1 {
		t.Fatalf("unexpected shape: %+v", authz.Authorities)
	}
	if !authz.Authorities[0].Pages[0].Replayed {
		t.Error("the page was resolved from the live state, not the replay — a reader of this " +
			"evidence could not tell which state the verdict rests on")
	}
}
