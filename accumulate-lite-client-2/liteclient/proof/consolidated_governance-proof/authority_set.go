// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// The account's AUTHORITY SET, which is what actually governs a transaction.
//
// WHAT ACCUMULATE REQUIRES, from internal/core/execute/v2/block/transaction.go:
//
//	userTransactionIsReady loads the principal's AccountAuth, walks EVERY
//	authority entry - skipping disabled ones unless the transaction type
//	RequireAuthorization() - adds any additional authorities named on the
//	transaction header, and is ready only when notReady is empty. So ALL
//	enabled authorities must vote.
//
//	AuthorityWillVote loads the authority and iterates authority.GetSigners(),
//	which for a key book is pages 1..PageCount, returning on the FIRST signer
//	that would vote. So ANY ONE satisfied page satisfies the whole book.
//
//	A page is satisfied by distinct entries reaching its AcceptThreshold, where
//	an entry is a public key hash or a delegate book.
//
// WHAT THIS FILE FIXES.
//
// Resolution previously evaluated ONE key page, and the caller chose it by
// assuming the principal's ADI plus "/book/1". That is right for an account
// whose authority is the inherited default book, whose book has one page, and
// which has no second authority - which is every account in the corpus and
// every account in production so far, and is why the answer kept coming out
// correct.
//
// It is not what G1 claims. G1 claims a verifier can independently establish
// that Accumulate's governance rules were satisfied; "one key page reached its
// threshold" is a strictly narrower statement than "the account's authority set
// approved". An account with two authorities, or with an explicit authority that
// is not the default book, or whose signing page is page 2, would produce a
// confident G1 answer about the wrong question.
//
// So the authority set is READ, every enabled authority must be satisfied, and
// a book is satisfied by any one of its pages.

// AuthoritySource supplies the account and book state authority resolution needs.
//
// Separate from PageSource because these are different questions - "who governs
// this account" and "what is on this page" - and a source that can answer one
// and not the other is a real state a caller should be able to hold.
type AuthoritySource interface {
	PageSource

	// AccountAuthorities returns the authority set of an account: the
	// authorities that govern it and whether each is disabled.
	AccountAuthorities(ctx context.Context, account string) ([]AccountAuthority, error)

	// BookPages returns a key book's signer pages, in priority order.
	BookPages(ctx context.Context, book string) ([]string, error)
}

// AccountAuthority is one entry of an account's authority set.
type AccountAuthority struct {
	URL string `json:"url"`

	// Disabled means auth checks are skipped for this authority - anyone may
	// sign for it. It is carried rather than filtered at read time because
	// whether a disabled authority is ignored depends on the TRANSACTION type
	// (RequireAuthorization), which is not this layer's to decide.
	Disabled bool `json:"disabled,omitempty"`
}

// PageOutcome is one signer page's resolution within a book.
type PageOutcome struct {
	Page      string            `json:"page"`
	Satisfied bool              `json:"satisfied"`
	Result    *ResolutionResult `json:"result,omitempty"`
	Err       string            `json:"error,omitempty"`
}

// AuthorityOutcome is one authority's verdict, and the evidence for it.
type AuthorityOutcome struct {
	Authority string `json:"authority"`
	Disabled  bool   `json:"disabled,omitempty"`
	Satisfied bool   `json:"satisfied"`

	// SatisfiedBy names the page that satisfied this authority. Any one page of
	// the book is enough, so which one is evidence a reader needs.
	SatisfiedBy string `json:"satisfiedBy,omitempty"`

	Pages []PageOutcome `json:"pages"`
}

// AccountAuthorization is the answer to the question G1 actually asks: did the
// account's authority set approve this transaction?
type AccountAuthorization struct {
	Account     string             `json:"account"`
	Authorities []AuthorityOutcome `json:"authorities"`

	// Satisfied is true only when EVERY authority that had to vote did. It is
	// not "some authority approved": Accumulate requires all of them, and a
	// verifier that accepted one out of two would be answering a different and
	// easier question than the one it claims to answer.
	Satisfied bool `json:"satisfied"`

	// Unevaluated records authorities that could not be read at all. A
	// governance verdict must never be computed while one is outstanding: an
	// authority we could not load is not an authority that failed.
	Unevaluated []string `json:"unevaluated,omitempty"`
}

// ResolveAccount evaluates a transaction's whole authority set.
//
// extraAuthorities are the authorities named on the transaction header, which
// Accumulate requires in addition to the account's own from V2Baikonur onward.
//
// ignoreDisabled mirrors Body.Type().RequireAuthorization(): when the
// transaction type requires authorization, a disabled authority is NOT skipped.
func (r *AuthorityResolver) ResolveAccount(ctx context.Context, account string,
	extraAuthorities []string, ignoreDisabled bool, sigs []SignatureData) (*AccountAuthorization, error) {

	src, ok := r.Source.(AuthoritySource)
	if !ok {
		return nil, fmt.Errorf("authority resolution: the configured source cannot read account " +
			"authority sets, so it can only answer about a single key page - which is a narrower " +
			"question than whether the account's authorities approved")
	}

	auths, err := src.AccountAuthorities(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("authority resolution: read %s authority set: %w", account, err)
	}
	for _, extra := range extraAuthorities {
		auths = append(auths, AccountAuthority{URL: normalizeAccURL(extra)})
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("authority resolution: %s has no authorities; an account with no "+
			"authority cannot be shown to have approved anything", account)
	}

	// Canonical order, so the evidence reads the same for two validators.
	sort.SliceStable(auths, func(i, j int) bool {
		return normalizeAccURL(auths[i].URL) < normalizeAccURL(auths[j].URL)
	})

	out := &AccountAuthorization{Account: normalizeAccURL(account)}
	seen := map[string]bool{}
	allSatisfied := true

	for _, a := range auths {
		key := normalizeAccURL(a.URL)
		if seen[key] {
			continue
		}
		seen[key] = true

		if a.Disabled && !ignoreDisabled {
			// Accumulate skips it, so it is not required to vote. Recorded, not
			// dropped: "this authority was disabled" is a fact a reader of the
			// proof should see rather than infer from an absence.
			out.Authorities = append(out.Authorities, AuthorityOutcome{
				Authority: key, Disabled: true, Satisfied: true,
				SatisfiedBy: "(disabled - not required to vote)",
			})
			continue
		}

		outcome, err := r.resolveAuthority(ctx, src, key, sigs)
		if err != nil {
			out.Unevaluated = append(out.Unevaluated, key)
			allSatisfied = false
			continue
		}
		outcome.Disabled = a.Disabled
		out.Authorities = append(out.Authorities, *outcome)
		if !outcome.Satisfied {
			allSatisfied = false
		}
	}

	// An authority we could not read is not an authority that failed, and the
	// caller must be able to tell those apart - so Satisfied is false either
	// way, and Unevaluated says which case it is.
	out.Satisfied = allSatisfied && len(out.Unevaluated) == 0
	return out, nil
}

// resolveAuthority decides whether one key book approved, by trying each of its
// pages.
//
// ANY ONE satisfied page satisfies the book - that is AuthorityWillVote's
// behaviour, returning on the first signer that would vote. Every page is still
// evaluated and recorded, because "page 2 satisfied it" and "page 1 satisfied
// it" are different facts about who signed.
func (r *AuthorityResolver) resolveAuthority(ctx context.Context, src AuthoritySource,
	book string, sigs []SignatureData) (*AuthorityOutcome, error) {

	pages, err := src.BookPages(ctx, book)
	if err != nil {
		return nil, fmt.Errorf("read pages of %s: %w", book, err)
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("%s has no signer pages", book)
	}

	out := &AuthorityOutcome{Authority: normalizeAccURL(book)}
	for _, page := range pages {
		state, err := src.PageState(ctx, page)
		if err != nil {
			out.Pages = append(out.Pages, PageOutcome{Page: page, Err: err.Error()})
			continue
		}
		res, err := r.Resolve(ctx, page, state, sigs)
		if err != nil {
			out.Pages = append(out.Pages, PageOutcome{Page: page, Err: err.Error()})
			continue
		}
		po := PageOutcome{Page: page, Satisfied: res.ThresholdMet(), Result: res}
		out.Pages = append(out.Pages, po)
		if po.Satisfied && !out.Satisfied {
			out.Satisfied = true
			out.SatisfiedBy = page
		}
	}
	return out, nil
}

// CountedSignerAccounts returns every signer account that contributed to a
// satisfied page, across every authority.
//
// This is what Phase 4's per-partition legs are built from: only signatures that
// actually satisfied something need their inclusion proven.
func (a *AccountAuthorization) CountedSignerAccounts() []string {
	seen := map[string]bool{}
	var out []string
	for _, auth := range a.Authorities {
		for _, p := range auth.Pages {
			if !p.Satisfied || p.Result == nil {
				continue
			}
			for _, acct := range p.Result.SignerAccounts() {
				k := normalizeAccURL(acct)
				if !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Describe renders the verdict for a failure message, so an unmet authority set
// says WHICH authority was unmet rather than only that one was.
func (a *AccountAuthorization) Describe() string {
	parts := make([]string, 0, len(a.Authorities))
	for _, auth := range a.Authorities {
		switch {
		case auth.Disabled && auth.Satisfied:
			parts = append(parts, auth.Authority+": disabled")
		case auth.Satisfied:
			parts = append(parts, auth.Authority+": satisfied by "+auth.SatisfiedBy)
		default:
			detail := ""
			for _, p := range auth.Pages {
				if p.Result != nil {
					detail = fmt.Sprintf(" (%s: %d/%d entries)", p.Page,
						p.Result.Satisfied, p.Result.Threshold)
					break
				}
			}
			parts = append(parts, auth.Authority+": NOT satisfied"+detail)
		}
	}
	for _, u := range a.Unevaluated {
		parts = append(parts, u+": could not be evaluated")
	}
	return strings.Join(parts, "; ")
}
