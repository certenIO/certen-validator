// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Enumeration ACROSS signer accounts, which is what delegation requires.
//
// THE DEFECT THIS CLOSES, AND HOW IT WAS FOUND.
//
// Signature collection enumerated the PRINCIPAL's key page and nothing else.
// For a 1-of-1 or a plain M-of-N that is complete, because every signature is
// on that page - which is why 400 production proofs never noticed. Under
// delegation it is not: the delegated signer's user signature lives on the
// INNERMOST page, and what sits on the principal's page is an `authority`
// signature recording that the delegate approved.
//
// So the principal's page yields one countable signature and one entry the
// extractor correctly calls "not a key signature". Resolution then sees a single
// signature for a 2-of-3 page and reports 1/2 - a threshold shortfall, which
// reads as "the institution did not authorize this", about a transaction Kermit
// executed.
//
// Found by running the real G1 prover against corpus case D on live Kermit,
// after Gate 3 had passed offline. Gate 3 hands resolution the signatures; this
// is the step that FINDS them, and no offline test of the resolver could have
// caught it.
//
// THE WALK.
//
// An authority signature names `origin` - the page one hop inward - and the
// `delegator` path it travelled. Following origin recursively reaches the page
// holding the real delegated user signature. Every set is already in the single
// transaction query's response, so the walk costs no extra round trips.
//
// This is governance spec section 4.1 item 5, recorded as half-satisfied in
// L4_DESIGN.md section 1.3 Defect C: "Enumeration of P#signature entries and
// single-entry resolution for each counted candidate", where enumeration must
// cover EVERY signer account.

// signatureSetIndex is every account's signature set from one transaction
// query, keyed by normalised account URL.
type signatureSetIndex struct {
	sets map[string]map[string]interface{}
}

// indexSignatureSets collects every signatureSet record in a transaction query
// response.
//
// pickKeypageSignatureSet finds ONE set and stops. Delegation needs all of them,
// because the signature that actually carries the key is on a page the principal
// never names directly.
func indexSignatureSets(txResult map[string]interface{}) (*signatureSetIndex, error) {
	pu := ProofUtilities{}
	uu := URLUtils{}

	var data interface{}
	if data = pu.CaseInsensitiveGet(txResult, "result"); data == nil {
		data = pu.CaseInsensitiveGet(txResult, "data")
		if data == nil {
			return nil, ValidationError{Msg: "Transaction result missing result{} or data{}"}
		}
	}
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Transaction data is not an object"}
	}

	sigsMap, ok := pu.CaseInsensitiveGet(dataMap, "signatures").(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Tx result missing signatures{}"}
	}
	recordsArray, ok := pu.CaseInsensitiveGet(sigsMap, "records").([]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Transaction signatures.records[] is not an array"}
	}

	idx := &signatureSetIndex{sets: map[string]map[string]interface{}{}}
	for _, item := range recordsArray {
		rec, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if rt, _ := pu.CaseInsensitiveGet(rec, "recordType").(string); rt != "signatureSet" {
			continue
		}
		acct, ok := pu.CaseInsensitiveGet(rec, "account").(map[string]interface{})
		if !ok {
			continue
		}
		// Key books also carry signature sets (signature requests live there).
		// Only key PAGES hold user signatures, so only they are indexed - a book
		// in the walk would be a hop that can never yield a key.
		if at, _ := pu.CaseInsensitiveGet(acct, "type").(string); !strings.EqualFold(at, "keyPage") {
			continue
		}
		if url, _ := pu.CaseInsensitiveGet(acct, "url").(string); url != "" {
			idx.sets[uu.NormalizeURL(url)] = rec
		}
	}
	if len(idx.sets) == 0 {
		return nil, ValidationError{Msg: "transaction carries no key page signature sets"}
	}
	return idx, nil
}

// delegatedOrigins returns the pages an authority signature on this set points
// inward to.
//
// An authority signature is the record that a delegate approved: its `origin` is
// the page that actually signed, one hop in. Collecting those is how the walk
// finds the page holding the user signature.
func delegatedOrigins(set map[string]interface{}) []string {
	pu := ProofUtilities{}
	uu := URLUtils{}

	sigs, ok := pu.CaseInsensitiveGet(set, "signatures").(map[string]interface{})
	if !ok {
		return nil
	}
	records, ok := pu.CaseInsensitiveGet(sigs, "records").([]interface{})
	if !ok {
		return nil
	}

	var out []string
	for _, item := range records {
		rec, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		msg, ok := pu.CaseInsensitiveGet(rec, "message").(map[string]interface{})
		if !ok {
			continue
		}
		sig, ok := pu.CaseInsensitiveGet(msg, "signature").(map[string]interface{})
		if !ok {
			continue
		}
		if st, _ := pu.CaseInsensitiveGet(sig, "type").(string); !strings.EqualFold(st, "authority") {
			continue
		}
		if origin, _ := pu.CaseInsensitiveGet(sig, "origin").(string); origin != "" {
			out = append(out, uu.NormalizeURL(origin))
		}
	}
	return out
}

// enumerateAcrossSigners walks from the principal's page through every
// delegation hop and returns each page reached, in canonical order.
//
// The visited set is what makes this terminate. A delegation graph may cycle -
// corpus case H is book -> book2 -> book, and Kermit executes transactions over
// it - so a walk that did not track where it had been would not stop. Note the
// difference from resolution: THERE a cycle is legitimate and refusing it would
// be a false rejection, because the signature names a finite path. HERE we are
// discovering the graph rather than following a stated path, so a visited set is
// exactly the right guard.
//
// Bounded by DelegationDepthLimit hops as well, for the same reason the parser
// is: an untrusted response must not be able to make this walk forever.
func enumerateAcrossSigners(idx *signatureSetIndex, principalPage string, maxHops int) []string {
	uu := URLUtils{}
	start := uu.NormalizeURL(principalPage)

	visited := map[string]bool{}
	order := []string{}
	queue := []string{start}

	for hop := 0; len(queue) > 0 && hop <= maxHops; hop++ {
		next := []string{}
		for _, page := range queue {
			if visited[page] {
				continue
			}
			set, ok := idx.sets[page]
			if !ok {
				// A page named by an authority signature but carrying no
				// signature set of its own. Not an error: the set may belong to
				// a book, or the hop may end here.
				continue
			}
			visited[page] = true
			order = append(order, page)
			next = append(next, delegatedOrigins(set)...)
		}
		queue = next
	}

	// Canonical order, so two validators enumerating the same transaction
	// produce the same candidate list. The principal stays first because it is
	// the authority being evaluated; the rest are sorted.
	if len(order) > 1 {
		rest := order[1:]
		sort.Strings(rest)
	}
	return order
}

// collectDelegatedMessageIDs returns every user-signature message ID on the
// principal's page AND on every page reachable through delegation.
//
// Returned in the order the pages were walked, so the principal's own
// signatures come first and the evidence reads outermost-inward.
func (g1 *G1Layer) collectDelegatedMessageIDs(txResult map[string]interface{}, principalPage string) ([]string, []string, error) {
	idx, err := indexSignatureSets(txResult)
	if err != nil {
		return nil, nil, err
	}

	pages := enumerateAcrossSigners(idx, principalPage, delegationEnumerationMaxHops)
	if len(pages) == 0 {
		return nil, nil, ValidationError{Msg: fmt.Sprintf(
			"no signature set for the principal's page %s on this transaction", principalPage)}
	}

	var ids []string
	seen := map[string]bool{}
	for _, page := range pages {
		set, ok := idx.sets[page]
		if !ok {
			continue
		}
		pageIDs, err := g1.extractSignatureMessageIDs(set)
		if err != nil {
			// One page's set being unreadable is not a reason to drop it
			// silently: the caller would then compute a threshold over fewer
			// candidates than exist, which is the shortfall-looks-like-refusal
			// defect this file exists to close.
			return nil, nil, fmt.Errorf("signature set for %s: %w", page, err)
		}
		for _, id := range pageIDs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, pages, nil
}

// delegationEnumerationMaxHops bounds the discovery walk. It is Accumulate's own
// delegation depth limit: a chain deeper than the protocol allows cannot have
// produced a valid signature, so there is nothing past it worth finding.
const delegationEnumerationMaxHops = 20

// pageOfMessageID pulls the account out of acc://<hash>@<account>.
//
// A signature message's ID already states which chain carries it, so the page a
// candidate belongs to never has to be assumed. Returns empty for anything not
// in that form, and the caller then falls back to the route's own page.
func pageOfMessageID(messageID string) string {
	at := strings.LastIndex(messageID, "@")
	if at < 0 || at+1 >= len(messageID) {
		return ""
	}
	uu := URLUtils{}
	return uu.NormalizeURL(messageID[at+1:])
}
