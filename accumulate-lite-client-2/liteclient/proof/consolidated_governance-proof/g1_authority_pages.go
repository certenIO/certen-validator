// Copyright 2026 Certen Protocol
//
// WHICH PAGES CAN CARRY A VOTE — every authority's, not just the one G1 was
// handed.
//
// # THE DEFECT, MEASURED
//
// Both signature-collection routes walk outward from a single key page:
//
//	route 1  enumerateAcrossSigners starts at the principal's page and follows
//	         AUTHORITY SIGNATURES, hop by hop, through delegation.
//	route 2  enumerateDelegatePages starts at the same page and follows its
//	         DELEGATE ENTRIES.
//
// Two independent discoveries of the same ground, which is the point of having
// two — and both cover only what is reachable BY DELEGATION from one page.
//
// A second authority is not reachable by delegation from the first. It is a
// sibling: the account names both books, and neither delegates to the other.
// So a vote cast by the second authority's page is never collected, and the
// threshold is computed over a set that is missing it.
//
// Measured on Kermit 2026-08-26, corpus case L
// (acc://certen-p8l.acme/data, transaction 27498a8f018585b7), a transaction the
// network DELIVERED after both books signed:
//
//	[SIGNATURE]   Valid signatures: 1
//	[SIGNATURE]   Authority set (2 authority/ies):
//	                acc://certen-p8l.acme/book:  satisfied by .../book/1
//	                acc://certen-p8l.acme/book2: NOT satisfied (.../book2/1: 0/1 entries)
//	Error: authorization evaluation failed: Threshold not satisfied
//
// That is a FALSE GOVERNANCE REJECTION — the failure runbook rule 8 calls worse
// than an error, because an error is obviously a problem and a false rejection
// looks like a finding. l2's signature exists, is valid, and is on the
// transaction; nothing ever looked at the page holding it.
//
// # WHY THE SEEDS AND NOT THE WALK
//
// The walks are right. What was wrong is where they were told to start: one
// page, when the account has an authority SET. So the seed becomes every page
// of every authority, and each route then walks outward from all of them by its
// own method. Neither route's logic changes, and the two still discover
// signatures independently.
//
// # OVER-COLLECTING IS SAFE; UNDER-COLLECTING IS NOT
//
// Disabled authorities are seeded too. A disabled authority is not required to
// vote, but it MAY have voted, and whether its vote counts is resolution's
// decision, not collection's. Collecting a signature that turns out not to be
// needed costs one evaluation; missing one that was needed produces the
// shortfall above. The asymmetry is the whole reason this file exists.

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// accountSignerPages returns every key page that could carry a vote for a
// transaction against `account`: all pages of all its authorities.
//
// principalPage is always included and always first — it is the authority being
// evaluated, and it must stay first so the enumeration order the previous
// implementation produced is unchanged for every account with a single
// authority. That is every account on record, and their evidence must read
// exactly as it did.
//
// Failure to read the authority set is returned as an error, never as an empty
// list. An empty list would silently reduce collection to the principal's page —
// which is the pre-Phase-8 behaviour, arrived at by accident instead of by
// design, and indistinguishable from it in the output.
func (g1 *G1Layer) accountSignerPages(ctx context.Context, account, principalPage string) ([]string, error) {
	principalPage = normalizeAccURL(principalPage)
	if account == "" {
		// No principal to resolve against. The caller keeps the single-page
		// behaviour, which is correct for every caller that has no account.
		return []string{principalPage}, nil
	}

	src := newLivePageSource(g1.client, g1.authorityBuilder)
	auths, err := src.AccountAuthorities(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("read the authority set of %s, which decides which pages may "+
			"carry a vote: %w", account, err)
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("%s reports no authorities; an account with no authority cannot "+
			"be shown to have approved anything", account)
	}

	out := []string{principalPage}
	seen := map[string]bool{principalPage: true}
	var extra []string

	for _, a := range auths {
		pages, err := src.BookPages(ctx, a.URL)
		if err != nil {
			// NOT skipped. An authority whose pages cannot be listed is an
			// authority whose vote cannot be found, and proceeding would compute
			// a threshold over a set that is missing it.
			return nil, fmt.Errorf("list the pages of authority %s: %w", a.URL, err)
		}
		for _, p := range pages {
			p = normalizeAccURL(p)
			if !seen[p] {
				seen[p] = true
				extra = append(extra, p)
			}
		}
	}

	// Canonical order for everything after the principal, so two validators
	// reading the same account produce the same candidate list in the same
	// order. Discovery order is not stable.
	sort.Strings(extra)
	out = append(out, extra...)

	if len(out) > 1 {
		fmt.Printf("[G1] [AUTHORITY-PAGES] %s is governed by %d authority/ies; %d page(s) may "+
			"carry a vote: %v\n", account, len(auths), len(out), out)
	}
	return out, nil
}

// mergePages appends `extra` to `roots`, preserving the first element and
// dropping duplicates.
func mergePages(roots []string, extra []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(roots)+len(extra))
	for _, p := range append(append([]string{}, roots...), extra...) {
		p = normalizeAccURL(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
