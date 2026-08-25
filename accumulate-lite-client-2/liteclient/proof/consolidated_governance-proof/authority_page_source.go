// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
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

	// A key page reports its accept threshold as "acceptThreshold"; the
	// snapshot parser reads "threshold". Normalise before parsing so a page
	// whose threshold is only spelled one way does not silently read as zero.
	if pu.CaseInsensitiveGet(def, "threshold") == nil {
		if at := pu.CaseInsensitiveGet(def, "acceptThreshold"); at != nil {
			copied := make(map[string]interface{}, len(def)+1)
			for k, v := range def {
				copied[k] = v
			}
			copied["threshold"] = at
			def = copied
		}
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
