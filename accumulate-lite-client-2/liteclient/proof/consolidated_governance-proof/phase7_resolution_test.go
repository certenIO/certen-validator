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
	"testing"
)

// Phase 7, Gate 3 - authority resolution.
//
// Every page state here came off Kermit and is stored in the corpus, so these
// run offline against what the chain actually says rather than against a
// fixture written to match the implementation.
//
// The claims, from PHASE7_RUNBOOK.md Gate 3:
//
//	B, C, D, E, F resolve and satisfy their thresholds
//	G (depth), I (duplicate), J (wrong chain) refused, each with its own reason
//	K refused with an unsupported-type reason, never a threshold reason
//	A unchanged - the 1-of-1 path must not regress

// corpusPageSource serves the key page states captured with the corpus.
type corpusPageSource struct {
	pages map[string]corpusPage
}

func (s corpusPageSource) PageState(_ context.Context, page string) (KeyPageState, error) {
	p, ok := s.pages[normalizeAccURL(page)]
	if !ok {
		// Never a zero state. A page we cannot read is a page we cannot resolve
		// against, and returning an empty authority would make it satisfied by
		// nothing at all.
		return KeyPageState{}, fmt.Errorf("no captured state for key page %s", page)
	}
	return p.state(), nil
}

func newCorpusPageSource(t *testing.T, cf corpusFile) corpusPageSource {
	t.Helper()
	if len(cf.Pages) == 0 {
		t.Skip("corpus carries no page states - re-run `go run ./cmd/p7corpus -stage capture`")
	}
	pages := make(map[string]corpusPage, len(cf.Pages))
	for url, p := range cf.Pages {
		pages[normalizeAccURL(url)] = p
	}
	return corpusPageSource{pages: pages}
}

// principalPageOf returns the key page whose authority a case is evaluated
// against: the first page of the principal ADI's default book.
func principalPageOf(tr corpusTrace) string {
	return normalizeAccURL(strings.TrimSuffix(tr.Principal, "/") + "/book/1")
}

// resolveCase runs every signature of one corpus case against its principal.
func resolveCase(t *testing.T, cf corpusFile, caseName string) *ResolutionResult {
	t.Helper()

	src := newCorpusPageSource(t, cf)
	var sigs []SignatureData
	var principal string
	for _, tr := range cf.Traces {
		if tr.Case != caseName {
			continue
		}
		principal = principalPageOf(tr)
		sigs = append(sigs, corpusSignatureData(tr))
	}
	if principal == "" {
		t.Fatalf("case %s is not in the corpus", caseName)
	}

	state, err := src.PageState(context.Background(), principal)
	if err != nil {
		t.Fatalf("principal page %s: %v", principal, err)
	}

	r := &AuthorityResolver{Source: src}
	res, err := r.Resolve(context.Background(), principal, state, sigs)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return res
}

// TestP7_3_ThresholdsAreSatisfied is Gate 3's first condition.
func TestP7_3_ThresholdsAreSatisfied(t *testing.T) {
	cf := loadCorpus(t)

	for _, name := range []string{"B", "C", "C-merkle", "D", "E", "F", "H", "H-repeat"} {
		t.Run(name, func(t *testing.T) {
			res := resolveCase(t, cf, name)
			if !res.ThresholdMet() {
				t.Fatalf("threshold NOT met: %d of %d entries satisfied on %s (v%d)\nrefused: %v",
					res.Satisfied, res.Threshold, res.Page, res.Version, describeRefusals(res))
			}
			t.Logf("%s: %d/%d entries satisfied on %s, %d delegated, max depth %d",
				name, res.Satisfied, res.Threshold, shortAcc(res.Page), res.DelegatedCount, res.MaxDepth)
		})
	}
}

// TestP7_3_DelegationIsActuallyExercised is the control on the test above.
//
// A resolver that ignored delegation entirely would still satisfy cases C, E, G
// and H, because provision.py built those chains by creating every book with
// the SAME key - so the signing key is also a direct entry on the outer page.
// D and F are the cases where it is not, and they are the ones that prove
// delegation was resolved rather than sidestepped. The corpus measures that
// property against the chain; this insists at least one such case is used.
func TestP7_3_DelegationIsActuallyExercised(t *testing.T) {
	cf := loadCorpus(t)

	var discriminating []string
	for _, tr := range cf.Traces {
		if len(tr.Delegators) > 0 && tr.KeyIsDirectOnOuterPage != nil && !*tr.KeyIsDirectOnOuterPage {
			discriminating = append(discriminating, tr.Case)
		}
	}
	if len(discriminating) == 0 {
		t.Fatal("no corpus case has a signing key that is absent from its outer page, " +
			"so nothing here distinguishes resolving delegation from ignoring it")
	}

	for _, name := range discriminating {
		t.Run(name, func(t *testing.T) {
			res := resolveCase(t, cf, name)
			if !res.ThresholdMet() {
				t.Fatalf("threshold not met: %v", describeRefusals(res))
			}
			if res.DelegatedCount == 0 {
				t.Fatal("resolved, but no signature was delegated - this case cannot have " +
					"been satisfied without walking a delegation path")
			}
			// And the path must be real: every link names a delegate entry that
			// exists on the page it leaves.
			for _, s := range res.Resolved {
				for _, l := range s.Path {
					if l.Via == "" {
						t.Fatalf("path link %s -> %s names no delegate entry", l.From, l.To)
					}
					if bookOfPage(l.To) != normalizeAccURL(l.Via) {
						t.Fatalf("link claims %s delegates to %s, but %s is not a page of it",
							l.From, l.Via, l.To)
					}
				}
			}
			t.Logf("%s satisfied through %d delegated signature(s), depth %d",
				name, res.DelegatedCount, res.MaxDepth)
		})
	}
}

// TestP7_3_DuplicateKeyCountsOnce is corpus case I.
//
// A 2-of-3 page signed twice by the SAME key must not reach its threshold. One
// key satisfies at most one entry, so unique acceptances is 1 and 1 < 2. Kermit
// agrees: case I's transaction is still pending, never delivered.
func TestP7_3_DuplicateKeyCountsOnce(t *testing.T) {
	cf := loadCorpus(t)
	res := resolveCase(t, cf, "I")

	if res.Satisfied != 1 {
		t.Fatalf("two signatures from one key satisfied %d entries; one key is one acceptance",
			res.Satisfied)
	}
	if res.ThresholdMet() {
		t.Fatalf("threshold of %d reported met by one key signing twice - OVER-COUNTING",
			res.Threshold)
	}
	if !hasRefusal(res, ReasonDuplicateEntry) {
		t.Fatalf("the second signature was not refused with the duplicate-entry reason: %v",
			describeRefusals(res))
	}
	t.Logf("2-of-3 signed twice by one key: %d/%d satisfied, threshold not met",
		res.Satisfied, res.Threshold)
}

// TestP7_3_LongerPathGrantsNoMoreAuthority is corpus case H-repeat, and it is
// the over-counting test the cycle cases turned into.
//
// H traverses a delegation cycle once; H-repeat traverses it twice. Kermit
// delivers both. Both satisfy the SAME single entry on the principal page, so
// both must contribute exactly one acceptance. An implementation that credited
// an acceptance per HOP would pass H and fail here.
func TestP7_3_LongerPathGrantsNoMoreAuthority(t *testing.T) {
	cf := loadCorpus(t)

	short := resolveCase(t, cf, "H")
	long := resolveCase(t, cf, "H-repeat")

	if long.MaxDepth <= short.MaxDepth {
		t.Fatalf("H-repeat is not longer than H (%d vs %d hops) - it cannot test what it exists for",
			long.MaxDepth, short.MaxDepth)
	}
	if long.Satisfied != short.Satisfied {
		t.Fatalf("a path of %d hops satisfied %d entries where a path of %d satisfied %d. "+
			"A longer path through the same cycle grants no more authority; this is an "+
			"acceptance credited per hop",
			long.MaxDepth, long.Satisfied, short.MaxDepth, short.Satisfied)
	}
	if len(long.Resolved) != 1 || len(short.Resolved) != 1 {
		t.Fatalf("expected one resolved signature each, got %d and %d",
			len(long.Resolved), len(short.Resolved))
	}
	if long.Resolved[0].SatisfiedEntry != short.Resolved[0].SatisfiedEntry {
		t.Fatalf("the two paths satisfy different entries (%s vs %s) - they start at the "+
			"same page and must satisfy the same entry of it",
			long.Resolved[0].SatisfiedEntry, short.Resolved[0].SatisfiedEntry)
	}
	t.Logf("%d hops and %d hops both satisfy entry %s, once",
		short.MaxDepth, long.MaxDepth, short.Resolved[0].SatisfiedEntry)
}

// TestP7_3_WrongDelegatorChainIsRefused is corpus case J.
//
// The inner key is correct and every URL in the chain is real; only the PATH is
// wrong. The digest commits to the whole chain, so a signature naming a
// different path is not evidence for the path actually walked. Kermit agrees:
// case J's transaction is pending, never delivered.
func TestP7_3_WrongDelegatorChainIsRefused(t *testing.T) {
	cf := loadCorpus(t)
	res := resolveCase(t, cf, "J")

	if res.Satisfied != 0 {
		t.Fatalf("a signature with a wrong delegator chain satisfied %d entries", res.Satisfied)
	}
	if res.ThresholdMet() {
		t.Fatal("threshold met by a signature whose path this authority does not grant")
	}
	if !hasRefusal(res, ReasonPathBroken) {
		t.Fatalf("refused, but not for path binding: %v", describeRefusals(res))
	}
	t.Logf("refused: %s", refusalDetail(res, ReasonPathBroken))
}

// TestP7_3_DepthLimitIsRefusedWithItsOwnReason is corpus case G.
func TestP7_3_DepthLimitIsRefusedWithItsOwnReason(t *testing.T) {
	cf := loadCorpus(t)
	res := resolveCase(t, cf, "G")

	if res.ThresholdMet() {
		t.Fatal("a 21-deep delegation chain satisfied the threshold")
	}
	if !hasRefusal(res, ReasonDepthExceeded) {
		t.Fatalf("refused, but not for depth: %v", describeRefusals(res))
	}
	// The distinction Gate 3 is really asking about: the reason must be about
	// DEPTH, not about a threshold that came up short.
	if hasRefusal(res, ReasonKeyNotOnPage) || hasRefusal(res, ReasonPathBroken) {
		t.Fatalf("the depth case also produced a membership or path reason, which would "+
			"make an over-deep chain indistinguishable from a bad one: %v", describeRefusals(res))
	}
	t.Logf("refused: %s", refusalDetail(res, ReasonDepthExceeded))
}

// TestP7_3_UnsupportedTypeIsNeverAThresholdReason is corpus case K, and runbook
// rule 7.
//
// Case K is a btc signature Kermit DELIVERED. It must be refused - we cannot
// verify it - but the refusal must say so. If it came back as a threshold
// shortfall it would read as "the institution did not authorize this", about a
// transaction the institution demonstrably did authorize.
func TestP7_3_UnsupportedTypeIsNeverAThresholdReason(t *testing.T) {
	cf := loadCorpus(t)
	res := resolveCase(t, cf, "K")

	if !hasRefusal(res, ReasonUnsupportedType) {
		t.Fatalf("a btc signature was not refused with the unsupported-type reason: %v",
			describeRefusals(res))
	}
	for _, r := range res.Refused {
		if r.Reason == ReasonKeyNotOnPage {
			t.Fatal("the btc signature was refused for key membership. Its key IS on the " +
				"page - the corpus registers it there precisely so that its TYPE is the " +
				"only thing wrong with it")
		}
	}
	t.Logf("refused: %s", refusalDetail(res, ReasonUnsupportedType))
}

// TestP7_3_OneOfOneDoesNotRegress is case A's shape.
//
// Every one of the 400 production proofs is a single ed25519 key satisfying a
// page directly. Nothing in this phase may change that, and a delegation-aware
// resolver that broke it would have cost more than it bought.
func TestP7_3_OneOfOneDoesNotRegress(t *testing.T) {
	cf := loadCorpus(t)
	src := newCorpusPageSource(t, cf)

	var checked int
	for _, tr := range cf.Traces {
		if tr.KeyType != "ed25519" || len(tr.Delegators) > 0 {
			continue
		}
		// One signature, alone, against its own page.
		page := normalizeAccURL(tr.Signer)
		state, err := src.PageState(context.Background(), page)
		if err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		checked++

		t.Run(tr.Label, func(t *testing.T) {
			r := &AuthorityResolver{Source: src}
			res, err := r.Resolve(context.Background(), page, state, []SignatureData{corpusSignatureData(tr)})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if res.Satisfied != 1 {
				t.Fatalf("a direct ed25519 signature on its own page satisfied %d entries: %v",
					res.Satisfied, describeRefusals(res))
			}
			if len(res.Resolved) != 1 || len(res.Resolved[0].Path) != 0 {
				t.Fatal("a non-delegated signature resolved with a delegation path")
			}
		})
	}
	if checked == 0 {
		t.Fatal("no direct ed25519 signature in the corpus - case A's shape is untested")
	}
	t.Logf("%d direct signatures resolve against their own page", checked)
}

// TestP7_3_VersionBindingIsEnforced is the KPSW-EXEC rule.
//
// A signature carries the page version it was made against. A signature valid
// under an older page is not valid now, and accepting one would let a key
// removed from a page keep authorizing with a signature made before it left.
func TestP7_3_VersionBindingIsEnforced(t *testing.T) {
	cf := loadCorpus(t)
	src := newCorpusPageSource(t, cf)

	var checked int
	for _, tr := range cf.Traces {
		if tr.KeyType != "ed25519" || len(tr.Delegators) > 0 {
			continue
		}
		checked++
		t.Run(tr.Label, func(t *testing.T) {
			page := normalizeAccURL(tr.Signer)
			state, _ := src.PageState(context.Background(), page)

			sig := corpusSignatureData(tr)
			sig.SignerVersion++ // a version the page is not at

			r := &AuthorityResolver{Source: src}
			res, err := r.Resolve(context.Background(), page, state, []SignatureData{sig})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if res.Satisfied != 0 {
				t.Fatal("a signature made against a different page version was counted")
			}
			if !hasRefusal(res, ReasonWrongVersion) {
				t.Fatalf("refused, but not for the version: %v", describeRefusals(res))
			}
		})
		break // one is enough; the rule is not per-case
	}
	if checked == 0 {
		t.Fatal("no direct signature to mutate - version binding is untested")
	}
}

// TestP7_3_SignerEnumerationCoversEveryCountedAccount finishes governance spec
// section 4.1 item 5, recorded as half-satisfied in L4_DESIGN.md section 1.3
// Defect C.
//
// Enumeration must cover EVERY signer account. Under delegation that means
// several, and under case F it means several on DIFFERENT PARTITIONS - which is
// what Phase 4 builds one proof leg per.
func TestP7_3_SignerEnumerationCoversEveryCountedAccount(t *testing.T) {
	cf := loadCorpus(t)

	// Case D is satisfied by two signatures on two different pages.
	res := resolveCase(t, cf, "D")
	accounts := res.SignerAccounts()
	if len(accounts) < 2 {
		t.Fatalf("case D is satisfied by two signatures on two pages, but enumeration "+
			"found %d signer account(s): %v", len(accounts), accounts)
	}

	// Only COUNTED signatures contribute. A signature that did not help meet the
	// threshold needs no inclusion proof, and proving it inflates the proof
	// without adding evidence.
	dup := resolveCase(t, cf, "I")
	if len(dup.SignerAccounts()) != 1 {
		t.Fatalf("case I has two signatures from one key on one page; enumeration found "+
			"%d accounts", len(dup.SignerAccounts()))
	}
	t.Logf("case D signer accounts: %v", accounts)
}

// ---------------------------------------------------------------------------

func hasRefusal(res *ResolutionResult, reason string) bool {
	for _, r := range res.Refused {
		if r.Reason == reason {
			return true
		}
	}
	return false
}

func refusalDetail(res *ResolutionResult, reason string) string {
	for _, r := range res.Refused {
		if r.Reason == reason {
			return r.Detail
		}
	}
	return ""
}

func describeRefusals(res *ResolutionResult) string {
	if len(res.Refused) == 0 {
		return "(nothing refused)"
	}
	parts := make([]string, 0, len(res.Refused))
	for _, r := range res.Refused {
		parts = append(parts, r.Reason+": "+r.Detail)
	}
	return strings.Join(parts, "; ")
}

func shortAcc(s string) string { return strings.TrimPrefix(s, "acc://") }
