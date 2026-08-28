// Copyright 2026 Certen Protocol
//
// A PAGE'S STATE AS OF EXECUTION — because a signer version is not a detail,
// it is the statement that the page's authority changed.
//
// # WHY VERSIONS ARE NOT COMPARABLE ACROSS TIME
//
// Every user signature names the version of the page it was made against, and
// Accumulate refuses one made against any other (KPSW-EXEC). The version is
// therefore not a freshness stamp to be tolerated or waived — it IS the
// identity of an authority state. Version 1 and version 2 of a page are two
// different authorities that happen to share a URL: different entries,
// different threshold, different set of keys that may sign.
//
// It follows that there is exactly ONE state a signature may be evaluated
// against — the page as it stood when the transaction executed — and that
// comparing a signature to any other state is not a strict check or a lenient
// one. It is a meaningless one that returns a confident answer.
//
// # WHAT WAS ACTUALLY HAPPENING
//
// Authority resolution queried pages LIVE. For the principal's page the layer
// above had already built the KPSW-EXEC snapshot — genesis located, every
// mutation up to the execution block replayed, each step receipt-bound — and
// resolution threw it away and asked the network what the page looks like now.
//
// Measured on Kermit 2026-08-26. After acc://certen-kermit-12.acme/book/1 moved
// from version 1 to version 2, G1 could no longer prove transaction
// 1f25bb6ae4cad401, which was signed AND executed at version 1:
//
//	acc://certen-kermit-12.acme/book: NOT satisfied (book/1: 0/1 entries)
//
// The signature was refused as a version mismatch — a GOVERNANCE REJECTION of a
// transaction the network executed, produced by comparing a version-1 signature
// against a version-2 page. Confirmed against the pre-Phase-8 build, which
// fails identically: a defect that could not fire until a page actually
// changed, on an account whose page had never changed in 400 proofs.
//
// # THE TWO RULES THIS FILE ENFORCES
//
//  1. A signature is compared ONLY against the page state at execution. Every
//     page reached during resolution — the principal's, each authority's, and
//     each delegation hop's — is replayed to the execution block.
//
//  2. When that state cannot be obtained, NOTHING IS COMPARED. The signature is
//     reported as UNEVALUABLE, never as refused. A page we could not reconstruct
//     is not a page that withheld its approval, and reporting it as one is the
//     false-rejection failure runbook rule 8 puts above every other.
//
// Rule 2 is what makes rule 1 safe to enforce. Without it, tightening the
// comparison would convert every replay failure into a governance rejection —
// trading a wrong "yes" for a wrong "no", which is the worse of the two.

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// PageStateAt is a page's state together with WHEN it is true of.
//
// AtExec distinguishes a state derived by replay to the execution block from
// one merely queried as it stands today. Only the first may be compared against
// a signature's version; the second is carried so the caller can say why it
// could not decide, rather than deciding wrongly.
type PageStateAt struct {
	State  KeyPageState
	AtExec bool
}

// ExecPageSource returns a page's state as of the execution block.
type ExecPageSource interface {
	PageStateAtExec(ctx context.Context, page string) (KeyPageState, error)
}

// execPageSource replays any page to the execution block, with a cache.
//
// Seeded with the principal's snapshot, which the G1 layer has already built —
// rebuilding it would be a second replay of the same chain producing the same
// answer, and a second thing that can drift.
type execPageSource struct {
	builder     *AuthorityBuilder
	execMBI     int64
	execWitness string

	mu    sync.Mutex
	cache map[string]KeyPageState
	// failed remembers pages whose replay did not succeed, so a page that
	// cannot be reconstructed is not re-replayed once per signature.
	failed map[string]error
}

func newExecPageSource(builder *AuthorityBuilder, execMBI int64, execWitness string,
	seed map[string]KeyPageState) *execPageSource {

	s := &execPageSource{
		builder:     builder,
		execMBI:     execMBI,
		execWitness: execWitness,
		cache:       map[string]KeyPageState{},
		failed:      map[string]error{},
	}
	for page, st := range seed {
		s.cache[normalizeAccURL(page)] = st
	}
	return s
}

// PageStateAtExec returns the page as it stood at the execution block.
//
// Failure is an error and never an empty state. An empty authority is satisfied
// by nothing, so returning one here would turn a replay failure into a
// threshold shortfall — the shape this whole package exists to keep closed.
func (s *execPageSource) PageStateAtExec(ctx context.Context, page string) (KeyPageState, error) {
	key := normalizeAccURL(page)

	s.mu.Lock()
	if st, ok := s.cache[key]; ok {
		s.mu.Unlock()
		return st, nil
	}
	if err, ok := s.failed[key]; ok {
		s.mu.Unlock()
		return KeyPageState{}, err
	}
	s.mu.Unlock()

	snap, err := s.builder.BuildAuthoritySnapshot(ctx, key, s.execMBI, s.execWitness)
	if err != nil || snap == nil {
		if err == nil {
			err = fmt.Errorf("no snapshot was produced")
		}
		wrapped := fmt.Errorf("replay %s to the execution block (MBI %d): %w", key, s.execMBI, err)
		s.mu.Lock()
		s.failed[key] = wrapped
		s.mu.Unlock()
		return KeyPageState{}, wrapped
	}

	s.mu.Lock()
	s.cache[key] = snap.StateExec
	s.mu.Unlock()
	return snap.StateExec, nil
}

// stateFor returns the state a signature may be compared against, and says
// whether it is execution-accurate.
//
// Prefers the replay. Falls back to the live page ONLY so the caller has
// something to report about — a live state is returned with AtExec false, and
// the comparison rules refuse to draw a verdict from it when the versions
// differ.
func (r *AuthorityResolver) stateFor(ctx context.Context, page string) (PageStateAt, error) {
	if r.Exec != nil {
		if st, err := r.Exec.PageStateAtExec(ctx, page); err == nil {
			return PageStateAt{State: st, AtExec: true}, nil
		} else if r.Source == nil {
			return PageStateAt{}, err
		} else {
			fmt.Printf("[RESOLUTION] [WARN] %s could not be replayed to the execution block "+
				"(%v); falling back to its CURRENT state, which may not be comparable\n", page, err)
		}
	}
	if r.Source == nil {
		return PageStateAt{}, fmt.Errorf("no page source is configured")
	}
	st, err := r.Source.PageState(ctx, page)
	if err != nil {
		return PageStateAt{}, err
	}
	return PageStateAt{State: st, AtExec: false}, nil
}

// versionRefusal returns the refusal for a signature whose version does not
// match the state it was compared against — or, when that state is not
// execution-accurate, the UNEVALUABLE outcome instead.
//
// This is the whole point of PageStateAt. Against the page at execution, a
// version mismatch is a real finding: the signature names an authority state
// the page was not in, and Accumulate would have refused it too. Against the
// page as it is today it is not a finding at all — it says only that the page
// has changed since, which every page eventually does.
func versionRefusal(atExec bool, page string, sigVersion, stateVersion uint64) (reason, detail string) {
	if atExec {
		return ReasonWrongVersion, fmt.Sprintf(
			"signature was made against version %d of %s, which was at version %d when the "+
				"transaction executed", sigVersion, page, stateVersion)
	}
	return ReasonPageUnavailable, fmt.Sprintf(
		"signature was made against version %d of %s and the only state available is its "+
			"CURRENT one, version %d. Those are two different authorities, so no comparison "+
			"was made: this signature could not be evaluated, and it has NOT been refused",
		sigVersion, page, stateVersion)
}

// bookPagesOfAuthorities lists every page of every authority, for seeding.
func bookPagesOfAuthorities(ctx context.Context, src AuthoritySource, auths []AccountAuthority) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, a := range auths {
		pages, err := src.BookPages(ctx, a.URL)
		if err != nil {
			return nil, fmt.Errorf("list the pages of %s: %w", a.URL, err)
		}
		for _, p := range pages {
			p = normalizeAccURL(p)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// isPageUnavailable reports whether a refusal means "could not evaluate".
func isPageUnavailable(r RefusedSignature) bool {
	return r.Reason == ReasonPageUnavailable
}

// describeUnavailable renders the unevaluable refusals for an error message.
func describeUnavailable(rs []RefusedSignature) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("%s on %s: %s", SafeTruncate(r.PublicKeyHash, 16),
			r.SignerPage, r.Detail))
	}
	return strings.Join(parts, "; ")
}
