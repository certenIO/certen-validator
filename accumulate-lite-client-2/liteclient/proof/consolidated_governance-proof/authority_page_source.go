// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// The live source of key page states for authority resolution.
//
// WHAT THIS IS, AND WHAT IT IS NOT.
//
// The PRINCIPAL's page comes from the KPSW-EXEC snapshot: genesis located,
// every mutation up to the execution block replayed, each step receipt-bound.
// That is a strong claim - the page's state is derived from the chain's own
// history rather than from what an endpoint says today.
//
// Pages reached THROUGH delegation do not get that treatment here. They are
// queried, once, and their current state is used. That is a weaker claim, and
// it is recorded as such on every resolution link (ResolutionLink.FromReplayed)
// rather than being quietly presented as the same thing. A reader of a proof
// can therefore tell which pages were replayed and which were asked about.
//
// Building a full KPSW snapshot for every page in a delegation chain is the
// stronger form and it is not done here: case G's chain alone is twenty-two
// pages, each needing its own genesis search and mutation replay. Saying so is
// the point - an unstated approximation is the thing this codebase keeps
// finding and removing.
type livePageSource struct {
	builder *AuthorityBuilder
	client  RPCClientInterface

	mu    sync.Mutex
	cache map[string]KeyPageState
}

func newLivePageSource(client RPCClientInterface, builder *AuthorityBuilder) *livePageSource {
	return &livePageSource{
		builder: builder,
		client:  client,
		cache:   map[string]KeyPageState{},
	}
}

// PageState returns a key page's current state, entries included.
//
// Failures are errors, never empty states. An empty authority is satisfied by
// nothing, so returning one on a failed query would turn an outage into a
// governance rejection - the defect this package exists to keep closed.
func (s *livePageSource) PageState(ctx context.Context, page string) (KeyPageState, error) {
	key := normalizeAccURL(page)

	s.mu.Lock()
	if st, ok := s.cache[key]; ok {
		s.mu.Unlock()
		return st, nil
	}
	s.mu.Unlock()

	resp, err := s.client.Query(ctx, key, map[string]interface{}{})
	if err != nil {
		return KeyPageState{}, fmt.Errorf("query key page %s: %w", key, err)
	}

	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return KeyPageState{}, fmt.Errorf("key page %s: %w", key, err)
	}

	// The account record nests the page under "account"; some paths return it
	// flat. Accept both rather than depending on which one an endpoint chose.
	def := result
	if acct, ok := pu.CaseInsensitiveGet(result, "account").(map[string]interface{}); ok {
		def = acct
	}

	// A key page reports its accept threshold as "acceptThreshold"; the snapshot
	// parser reads "threshold". Normalise before parsing.
	//
	// And when NEITHER is present, supply zero rather than letting the parse
	// fail. Accumulate omits an accept threshold of zero, and a freshly created
	// book's first page has exactly that - every delegate book in the Phase 7
	// corpus reports no threshold field at all. Failing the parse there made
	// PageState error, which made delegation enumeration skip the page, which
	// made the delegated signature invisible and the threshold come up short.
	// Zero is not "no rule": the resolver reads it as one, which is what
	// Accumulate means by it.
	if pu.CaseInsensitiveGet(def, "threshold") == nil {
		copied := make(map[string]interface{}, len(def)+1)
		for k, v := range def {
			copied[k] = v
		}
		if at := pu.CaseInsensitiveGet(def, "acceptThreshold"); at != nil {
			copied["threshold"] = at
		} else {
			copied["threshold"] = float64(0)
		}
		def = copied
	}

	state, err := s.builder.parseKeyPageStateFromDef(def)
	if err != nil {
		return KeyPageState{}, fmt.Errorf("parse key page %s: %w", key, err)
	}

	s.mu.Lock()
	s.cache[key] = state
	s.mu.Unlock()
	return state, nil
}

// AccountAuthorities returns the authority set that governs an account.
//
// It follows the same derivation the Accumulate explorer uses, which in turn
// mirrors the executor:
//
//	key page      -> its BOOK (strip the trailing page index) and ask again
//	lite identity -> the identity itself is its own authority
//	otherwise     -> the account's own `authorities` array
//
// The walk matters. An account whose authority is inherited reports it in
// `authorities` like any other, but a KEY PAGE does not carry an authority set
// of its own - its authority is the book it belongs to - so asking a page
// directly returns nothing and the account reads as ungoverned.
func (s *livePageSource) AccountAuthorities(ctx context.Context, account string) ([]AccountAuthority, error) {
	pu := ProofUtilities{}
	scope := normalizeAccURL(account)

	// Bounded: the walk only ever climbs from a page to its book, so one step is
	// enough. The bound is here so a surprising account type cannot loop.
	for hop := 0; hop < 4; hop++ {
		resp, err := s.client.Query(ctx, scope, map[string]interface{}{})
		if err != nil {
			return nil, fmt.Errorf("query %s: %w", scope, err)
		}
		result, err := pu.ExpectResult(resp)
		if err != nil {
			return nil, fmt.Errorf("account %s: %w", scope, err)
		}
		def := result
		if acct, ok := pu.CaseInsensitiveGet(result, "account").(map[string]interface{}); ok {
			def = acct
		}

		typ, _ := pu.CaseInsensitiveGet(def, "type").(string)
		switch strings.ToLower(typ) {
		case "keypage":
			// The page's authority is its book.
			book := bookOfPage(scope)
			if book == "" {
				return nil, fmt.Errorf("cannot derive the book of key page %s", scope)
			}
			scope = book
			continue

		case "liteidentity", "litetokenaccount":
			// A lite account is its own authority.
			return []AccountAuthority{{URL: identityURLOf(scope)}}, nil
		}

		raw, _ := pu.CaseInsensitiveGet(def, "authorities").([]interface{})

		// AN EMPTY AUTHORITY SET IS INHERITED, NOT ABSENT.
		//
		// Measured on Kermit 2026-08-26: acc://certen-kermit-12.acme/data — the
		// account every production intent writes to — reports
		// "authorities": null, and so does the freshly provisioned corpus case
		// M. That is not a malformed account. accumulate-core's
		// setInitialAuthorities (chain/create_utils.go) creates an account with
		// NO authority list of its own and verifies only that some parent has a
		// non-empty one:
		//
		//	// Otherwise leave the authority set empty - but verify that there is
		//	// a parent with a non-empty authority set
		//
		// The governing authority is then the parent identity's. Before this,
		// asking this source about such an account returned "reports no
		// authority set" — an error, which ResolveAccount's caller correctly
		// refuses to turn into a verdict, and which would have taken down every
		// production account the moment the authority set was actually consulted.
		//
		// So climb, exactly as the executor does. Only a ROOT identity with no
		// authorities is genuinely ungoverned, and that is still an error.
		if len(raw) == 0 {
			parent := identityURLOf(scope)
			if parent != "" && parent != scope {
				scope = parent
				continue
			}
			return nil, fmt.Errorf("account %s (%s) reports no authority set and is a root "+
				"identity with no parent to inherit from; an account with no authority cannot "+
				"be shown to have approved anything", scope, typ)
		}

		out := make([]AccountAuthority, 0, len(raw))
		for _, item := range raw {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			u, _ := pu.CaseInsensitiveGet(m, "url").(string)
			if u == "" {
				continue
			}
			disabled, _ := pu.CaseInsensitiveGet(m, "disabled").(bool)
			out = append(out, AccountAuthority{URL: normalizeAccURL(u), Disabled: disabled})
		}
		return out, nil
	}
	return nil, fmt.Errorf("authority derivation for %s did not terminate", account)
}

// BookPages returns a key book's signer pages in priority order.
//
// Accumulate's KeyBook.GetSigners() is pages 1..PageCount, and ANY ONE of them
// satisfying its threshold satisfies the book. Reading pageCount rather than
// assuming page 1 is the difference between evaluating the authority and
// evaluating a guess about it.
func (s *livePageSource) BookPages(ctx context.Context, book string) ([]string, error) {
	pu := ProofUtilities{}
	scope := normalizeAccURL(book)

	resp, err := s.client.Query(ctx, scope, map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("query book %s: %w", scope, err)
	}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return nil, fmt.Errorf("book %s: %w", scope, err)
	}
	def := result
	if acct, ok := pu.CaseInsensitiveGet(result, "account").(map[string]interface{}); ok {
		def = acct
	}

	count := uint64(0)
	switch v := pu.CaseInsensitiveGet(def, "pageCount").(type) {
	case float64:
		count = uint64(v)
	case int:
		count = uint64(v)
	case uint64:
		count = v
	}
	if count == 0 {
		// A book with no pages cannot be satisfied by anything. Refusing beats
		// returning an empty list, which a caller could read as "checked, and
		// nothing was wrong".
		return nil, fmt.Errorf("book %s reports no pages", scope)
	}

	out := make([]string, 0, count)
	for i := uint64(1); i <= count; i++ {
		out = append(out, fmt.Sprintf("%s/%d", scope, i))
	}
	return out, nil
}

// identityURLOf returns the acc:// identity an account belongs to.
func identityURLOf(account string) string {
	s := normalizeAccURL(account)
	body := strings.TrimPrefix(s, "acc://")
	if i := strings.Index(body, "/"); i >= 0 {
		body = body[:i]
	}
	return "acc://" + body
}
