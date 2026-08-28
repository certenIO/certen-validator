// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The authority-set rules, pinned.
//
// These are the rules Accumulate enforces in
// internal/core/execute/v2/block/transaction.go:
//
//	userTransactionIsReady  ALL enabled authorities must vote
//	AuthorityWillVote       ANY ONE page of a book satisfies it
//	                        a disabled authority is skipped
//
// The Phase 7 corpus cannot exercise them: every account in it has exactly one
// authority - the inherited default book - with exactly one page. That is also
// true of every account in production, which is why evaluating a single page
// happened to give the right answer for years.
//
// So the rules are pinned against a source built for the purpose. These are
// tests of the RULES; the live cases (D, F, A) prove the same resolver reads a
// real account's authority set off Kermit and agrees.

// fakeAuthoritySource serves an authority graph from memory.
type fakeAuthoritySource struct {
	auth  map[string][]AccountAuthority
	books map[string][]string
	pages map[string]KeyPageState
}

func (f fakeAuthoritySource) AccountAuthorities(_ context.Context, account string) ([]AccountAuthority, error) {
	a, ok := f.auth[normalizeAccURL(account)]
	if !ok {
		return nil, errNotFound(account)
	}
	return a, nil
}

func (f fakeAuthoritySource) BookPages(_ context.Context, book string) ([]string, error) {
	p, ok := f.books[normalizeAccURL(book)]
	if !ok {
		return nil, errNotFound(book)
	}
	return p, nil
}

func (f fakeAuthoritySource) PageState(_ context.Context, page string) (KeyPageState, error) {
	s, ok := f.pages[normalizeAccURL(page)]
	if !ok {
		return KeyPageState{}, errNotFound(page)
	}
	return s, nil
}

type notFoundErr string

func (e notFoundErr) Error() string { return string(e) + " not found" }
func errNotFound(s string) error    { return notFoundErr(s) }

// keyFor makes a deterministic key hash and a matching signature for it.
func keyFor(seed string) (hash string, sig SignatureData) {
	h := sha256.Sum256([]byte(seed))
	pub := hex.EncodeToString(h[:])
	kh := sha256.Sum256(h[:])
	return hex.EncodeToString(kh[:]), SignatureData{
		Type: "ed25519", PublicKey: pub, SignerVersion: 1,
	}
}

func pageWith(version, threshold uint64, keyHashes ...string) KeyPageState {
	entries := make([]KeyPageEntry, 0, len(keyHashes))
	for _, k := range keyHashes {
		entries = append(entries, KeyPageEntry{KeyHash: k})
	}
	return KeyPageState{
		Version: version, Threshold: threshold,
		Entries: entries, Keys: deriveKeyHashes(entries),
	}
}

// TestP7_Auth_AllAuthoritiesMustVote is the rule that a single-page evaluation
// cannot express.
//
// An account with two authorities requires BOTH. A verifier that accepted one
// would be answering an easier question than the one it claims to answer, and
// the answer would look identical.
func TestP7_Auth_AllAuthoritiesMustVote(t *testing.T) {
	kh1, sig1 := keyFor("authority-one")
	kh2, sig2 := keyFor("authority-two")
	sig1.Signer = "acc://alpha.acme/book/1"
	sig2.Signer = "acc://beta.acme/book/1"

	src := fakeAuthoritySource{
		auth: map[string][]AccountAuthority{
			"acc://alpha.acme/data": {
				{URL: "acc://alpha.acme/book"},
				{URL: "acc://beta.acme/book"},
			},
		},
		books: map[string][]string{
			"acc://alpha.acme/book": {"acc://alpha.acme/book/1"},
			"acc://beta.acme/book":  {"acc://beta.acme/book/1"},
		},
		pages: map[string]KeyPageState{
			"acc://alpha.acme/book/1": pageWith(1, 1, kh1),
			"acc://beta.acme/book/1":  pageWith(1, 1, kh2),
		},
	}
	r := &AuthorityResolver{Source: src}

	// Only the first authority signed.
	one, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data", nil, false,
		[]SignatureData{sig1}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if one.Satisfied {
		t.Fatalf("one of two authorities signed and the account read as approved: %s", one.Describe())
	}

	// Both signed.
	both, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data", nil, false,
		[]SignatureData{sig1, sig2}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !both.Satisfied {
		t.Fatalf("both authorities signed and the account did not read as approved: %s",
			both.Describe())
	}
	if len(both.Authorities) != 2 {
		t.Fatalf("evidence records %d authorities, expected 2", len(both.Authorities))
	}
}

// TestP7_Auth_AnyPageSatisfiesTheBook is AuthorityWillVote's behaviour: it
// iterates the book's signers and returns on the FIRST that would vote.
//
// A verifier that only ever looked at page 1 would report a book unsatisfied
// when page 2 signed - a false governance rejection, and one that reads as an
// unmet threshold.
func TestP7_Auth_AnyPageSatisfiesTheBook(t *testing.T) {
	kh1, _ := keyFor("page-one-key")
	kh2, sig2 := keyFor("page-two-key")
	sig2.Signer = "acc://multi.acme/book/2"

	src := fakeAuthoritySource{
		auth: map[string][]AccountAuthority{
			"acc://multi.acme/data": {{URL: "acc://multi.acme/book"}},
		},
		books: map[string][]string{
			"acc://multi.acme/book": {"acc://multi.acme/book/1", "acc://multi.acme/book/2"},
		},
		pages: map[string]KeyPageState{
			"acc://multi.acme/book/1": pageWith(1, 1, kh1),
			"acc://multi.acme/book/2": pageWith(1, 1, kh2),
		},
	}
	r := &AuthorityResolver{Source: src}

	res, err := r.ResolveAccount(context.Background(), "acc://multi.acme/data", nil, false,
		[]SignatureData{sig2}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.Satisfied {
		t.Fatalf("page 2 signed and the book read as unsatisfied: %s", res.Describe())
	}
	if got := res.Authorities[0].SatisfiedBy; !strings.HasSuffix(got, "/2") {
		t.Fatalf("the book was satisfied by %q, expected page 2 - the evidence must say WHICH "+
			"page voted, because any one of them is enough", got)
	}
}

// TestP7_Auth_DisabledAuthorityIsSkipped mirrors the executor: a disabled
// authority is not required to vote, unless the transaction type requires
// authorization.
func TestP7_Auth_DisabledAuthorityIsSkipped(t *testing.T) {
	kh1, sig1 := keyFor("enabled-key")
	kh2, _ := keyFor("disabled-key")
	sig1.Signer = "acc://alpha.acme/book/1"

	src := fakeAuthoritySource{
		auth: map[string][]AccountAuthority{
			"acc://alpha.acme/data": {
				{URL: "acc://alpha.acme/book"},
				{URL: "acc://beta.acme/book", Disabled: true},
			},
		},
		books: map[string][]string{
			"acc://alpha.acme/book": {"acc://alpha.acme/book/1"},
			"acc://beta.acme/book":  {"acc://beta.acme/book/1"},
		},
		pages: map[string]KeyPageState{
			"acc://alpha.acme/book/1": pageWith(1, 1, kh1),
			"acc://beta.acme/book/1":  pageWith(1, 1, kh2),
		},
	}
	r := &AuthorityResolver{Source: src}

	// Disabled skipped: the one enabled authority is enough.
	res, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data", nil, false,
		[]SignatureData{sig1}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !res.Satisfied {
		t.Fatalf("a disabled authority blocked approval: %s", res.Describe())
	}

	// ignoreDisabled (RequireAuthorization): now it must vote too.
	strict, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data", nil, true,
		[]SignatureData{sig1}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if strict.Satisfied {
		t.Fatalf("a transaction type that requires authorization accepted a disabled authority "+
			"that did not vote: %s", strict.Describe())
	}
}

// TestP7_Auth_UnreadableAuthorityIsNotAFailure keeps the distinction this whole
// package exists to keep: an authority we could not load is NOT an authority
// that refused.
func TestP7_Auth_UnreadableAuthorityIsNotAFailure(t *testing.T) {
	kh1, sig1 := keyFor("enabled-key")
	sig1.Signer = "acc://alpha.acme/book/1"

	src := fakeAuthoritySource{
		auth: map[string][]AccountAuthority{
			"acc://alpha.acme/data": {
				{URL: "acc://alpha.acme/book"},
				{URL: "acc://gone.acme/book"}, // no pages registered
			},
		},
		books: map[string][]string{
			"acc://alpha.acme/book": {"acc://alpha.acme/book/1"},
		},
		pages: map[string]KeyPageState{
			"acc://alpha.acme/book/1": pageWith(1, 1, kh1),
		},
	}
	r := &AuthorityResolver{Source: src}

	res, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data", nil, false,
		[]SignatureData{sig1}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Satisfied {
		t.Fatal("an account with an unreadable authority read as approved")
	}
	if len(res.Unevaluated) != 1 {
		t.Fatalf("the unreadable authority was not recorded as unevaluated: %s", res.Describe())
	}
	if !strings.Contains(res.Describe(), "could not be evaluated") {
		t.Fatalf("the verdict does not distinguish unreadable from refused: %s", res.Describe())
	}
}

// TestP7_Auth_ExtraAuthoritiesAreRequired covers the authorities a transaction
// names itself.
//
// Accumulate adds Header.Authorities to the required set from V2Baikonur, and
// the explorer additionally derives them from the body - an UpdateKeyPage that
// ADDS a delegate requires that delegate's approval, which is the two-sided
// delegation the corpus had to learn the hard way.
func TestP7_Auth_ExtraAuthoritiesAreRequired(t *testing.T) {
	kh1, sig1 := keyFor("account-key")
	kh2, sig2 := keyFor("extra-key")
	sig1.Signer = "acc://alpha.acme/book/1"
	sig2.Signer = "acc://extra.acme/book/1"

	src := fakeAuthoritySource{
		auth: map[string][]AccountAuthority{
			"acc://alpha.acme/data": {{URL: "acc://alpha.acme/book"}},
		},
		books: map[string][]string{
			"acc://alpha.acme/book": {"acc://alpha.acme/book/1"},
			"acc://extra.acme/book": {"acc://extra.acme/book/1"},
		},
		pages: map[string]KeyPageState{
			"acc://alpha.acme/book/1": pageWith(1, 1, kh1),
			"acc://extra.acme/book/1": pageWith(1, 1, kh2),
		},
	}
	r := &AuthorityResolver{Source: src}
	extra := []string{"acc://extra.acme/book"}

	// The account's own authority signed, the named extra did not.
	res, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data", extra, false,
		[]SignatureData{sig1}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.Satisfied {
		t.Fatalf("an authority the transaction names was not required: %s", res.Describe())
	}

	// Both signed.
	both, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data", extra, false,
		[]SignatureData{sig1, sig2}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !both.Satisfied {
		t.Fatalf("both authorities signed and it did not read as approved: %s", both.Describe())
	}
}
