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

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Authority resolution: does this set of signatures satisfy this key page?
//
// The rule, from PHASE7_DELEGATION_PLAN section 3.3:
//
//	satisfied(page P) := |{ e in P.Entries : satisfied_entry(e) }| >= P.AcceptThreshold
//
// where an entry is satisfied by a direct ed25519 signature whose key hash
// matches, or - when the entry names a delegate - by that delegate's book being
// satisfied in turn.
//
// RESOLUTION IS SIGNATURE-DRIVEN, NOT GRAPH-DRIVEN, and that choice decides
// most of what follows. A signature already names the exact path its digest
// commits to, so resolution WALKS THAT PATH and checks each link exists. It
// never searches the delegation graph for a path that would work. Two
// consequences:
//
//   - Path binding is structural rather than a separate check. There is no way
//     to resolve a signature along a path other than the one inside its digest,
//     because the path is the only thing being walked.
//   - The walk cannot loop. It is bounded by the chain's own length, which is
//     bounded by protocol.DelegationDepthLimit.
//
// ON CYCLES, WHERE THE PLAN AND THE NETWORK DISAGREE.
//
// The plan says to track visited pages and fail closed on revisit. The corpus
// says otherwise, and the corpus is made of transactions Kermit executed.
// Case H's delegation graph cycles (book -> book2 -> book) and a signature
// traversing it once is DELIVERED; case H-repeat traverses it twice and is also
// DELIVERED. A visited-page rule would refuse both - a false governance
// rejection of a transaction the network accepted, which is the precise failure
// this phase exists to remove.
//
// So the loop guard is the depth bound, which is Accumulate's own number, and
// the over-counting guard is the distinct-entry rule below. What H-repeat
// actually tests is that a longer path grants no more authority than a short
// one: both satisfy the SAME single entry on the principal page, so both
// contribute exactly one acceptance. An implementation that credited an
// acceptance per HOP would pass case H and fail here.

// PageSource supplies the key page states resolution needs.
//
// The principal's page comes from the KPSW-EXEC snapshot, which is reconstructed
// from genesis and replayed mutations. Pages reached THROUGH delegation are
// fetched directly, and the difference is recorded on every link rather than
// smoothed over: a page whose state was queried is a weaker claim than one
// replayed from genesis, and a proof that cannot tell them apart is claiming
// more than it established.
type PageSource interface {
	// PageState returns a key page's current state.
	PageState(ctx context.Context, page string) (KeyPageState, error)
}

// ResolutionLink is one hop of a resolved delegation path, and the evidence for
// it.
type ResolutionLink struct {
	// From is the page that delegated; To is the page that was delegated to.
	From string `json:"from"`
	To   string `json:"to"`

	// Via is the key BOOK named by the delegate entry on From. It is recorded
	// separately because the entry names a book while the signature names a
	// page, and the check is that To is a page OF Via.
	Via string `json:"via"`

	// FromVersion is the version of From that carried the delegate entry.
	FromVersion uint64 `json:"fromVersion"`

	// FromReplayed is true when From's state came from the KPSW-EXEC snapshot
	// rather than a direct query. Only the principal's page is replayed.
	FromReplayed bool `json:"fromReplayed"`
}

// ResolvedSignature is one signature that resolved, and what it satisfied.
type ResolvedSignature struct {
	PublicKeyHash string           `json:"publicKeyHash"`
	SignerPage    string           `json:"signerPage"`
	SignerVersion uint64           `json:"signerVersion"`
	DigestForm    string           `json:"digestForm"`
	Path          []ResolutionLink `json:"path,omitempty"`

	// SatisfiedEntry is the identity of the entry on the PRINCIPAL page that
	// this signature satisfies. One signature satisfies at most one, however
	// long its path.
	SatisfiedEntry string `json:"satisfiedEntry"`
}

// ResolutionResult is the answer, with the evidence for it.
type ResolutionResult struct {
	Page      string `json:"page"`
	Version   uint64 `json:"version"`
	Threshold uint64 `json:"threshold"`
	Entries   int    `json:"entries"`

	// Satisfied is the number of DISTINCT entries satisfied. This is what the
	// threshold is compared against - not the number of signatures, which is
	// the same number only when every signature satisfies a different entry.
	Satisfied int `json:"satisfied"`

	Resolved []ResolvedSignature `json:"resolved"`
	Refused  []RefusedSignature  `json:"refused,omitempty"`

	// MaxDepth is the deepest path walked, and DelegatedCount how many of the
	// resolved signatures were delegated at all. Both are recorded because
	// "delegation was exercised" is a claim a reader should be able to check
	// without re-deriving it.
	MaxDepth       int `json:"maxDepth"`
	DelegatedCount int `json:"delegatedCount"`
}

// ThresholdMet reports the answer resolution exists to give.
func (r *ResolutionResult) ThresholdMet() bool {
	return uint64(r.Satisfied) >= r.Threshold
}

// RefusedSignature records a signature that did not resolve, and why, with a
// reason code that can be compared rather than read.
type RefusedSignature struct {
	PublicKeyHash string `json:"publicKeyHash"`
	SignerPage    string `json:"signerPage"`
	Reason        string `json:"reason"`
	Detail        string `json:"detail"`
}

// Refusal reason codes. Each names a DIFFERENT thing being wrong, which is the
// whole point: a threshold shortfall and a signature we could not evaluate look
// identical in a count and must never look identical in a reason.
const (
	ReasonPathBroken      = "path-binding"
	ReasonWrongVersion    = "signer-version-mismatch"
	ReasonKeyNotOnPage    = "key-not-on-signer-page"
	ReasonDepthExceeded   = "delegation-depth-exceeded"
	ReasonUnsupportedType = "unsupported-signature-type"
	ReasonDuplicateEntry  = "duplicate-entry"
	ReasonPageUnavailable = "page-unavailable"
	ReasonWrongPrincipal  = "wrong-principal-page"
)

// AuthorityResolver answers whether a page is satisfied.
type AuthorityResolver struct {
	Source PageSource
}

// Resolve evaluates every candidate signature against the principal's page.
//
// It returns a result rather than a boolean because the evidence is the point:
// a caller that only learns "false" cannot tell an unmet threshold from a
// signature it could not read, and those must never be reported the same way.
//
// An error - as opposed to a refused signature - means resolution could not be
// completed at all. It is never a governance verdict.
func (r *AuthorityResolver) Resolve(ctx context.Context, principalPage string,
	principal KeyPageState, sigs []SignatureData) (*ResolutionResult, error) {

	principalPage = normalizeAccURL(principalPage)
	entries := principal.EntrySet()

	out := &ResolutionResult{
		Page:      principalPage,
		Version:   principal.Version,
		Threshold: principal.Threshold,
		Entries:   len(entries),
	}

	// An AcceptThreshold of zero is how Accumulate spells "one" on a page that
	// has never set one - the corpus's freshly created books report 0. Treating
	// it literally would make every such page satisfied by nothing at all.
	if out.Threshold == 0 {
		out.Threshold = 1
	}

	// satisfied tracks which PRINCIPAL entries have been satisfied. It is the
	// distinct-entry rule, and it is the reason two signatures from one key
	// count once: they satisfy the same entry, and an entry already in this set
	// is not counted again.
	satisfied := map[string]bool{}

	for _, sig := range sigs {
		res, entry, err := r.resolveOne(ctx, principalPage, principal, entries, sig)
		if err != nil {
			out.Refused = append(out.Refused, *err)
			continue
		}

		if satisfied[entry] {
			// Not an error and not evidence of wrongdoing - a second signature
			// for an entry that is already satisfied simply adds nothing. It is
			// recorded so the count and the signature list can be reconciled by
			// a reader who wonders why three signatures produced two.
			out.Refused = append(out.Refused, RefusedSignature{
				PublicKeyHash: res.PublicKeyHash,
				SignerPage:    res.SignerPage,
				Reason:        ReasonDuplicateEntry,
				Detail: fmt.Sprintf("entry %s is already satisfied; one entry is one "+
					"acceptance however many signatures reach it", entry),
			})
			continue
		}

		satisfied[entry] = true
		res.SatisfiedEntry = entry
		out.Resolved = append(out.Resolved, *res)
		if len(res.Path) > out.MaxDepth {
			out.MaxDepth = len(res.Path)
		}
		if len(res.Path) > 0 {
			out.DelegatedCount++
		}
	}

	out.Satisfied = len(satisfied)
	return out, nil
}

// resolveOne walks the path a single signature declares and reports which
// principal entry it satisfies.
func (r *AuthorityResolver) resolveOne(ctx context.Context, principalPage string,
	principal KeyPageState, entries []KeyPageEntry, sig SignatureData) (
	*ResolvedSignature, string, *RefusedSignature) {

	refuse := func(reason, detail string) *RefusedSignature {
		return &RefusedSignature{
			PublicKeyHash: keyHashOf(sig.PublicKey),
			SignerPage:    normalizeAccURL(sig.Signer),
			Reason:        reason,
			Detail:        detail,
		}
	}

	if err := requireSupportedType(sig); err != nil {
		if u, ok := IsUnsupportedSignatureType(err); ok {
			return nil, "", refuse(ReasonUnsupportedType, u.Error())
		}
		return nil, "", refuse(ReasonUnsupportedType, err.Error())
	}
	if len(sig.Chain) > protocol.DelegationDepthLimit {
		return nil, "", refuse(ReasonDepthExceeded, fmt.Sprintf(
			"chain is %d deep against Accumulate's limit of %d",
			len(sig.Chain), protocol.DelegationDepthLimit))
	}

	chain := sig.DelegatorChain()
	signerPage := normalizeAccURL(sig.Signer)

	res := &ResolvedSignature{
		PublicKeyHash: keyHashOf(sig.PublicKey),
		SignerPage:    signerPage,
		SignerVersion: uint64(sig.SignerVersion),
		DigestForm:    sig.DigestForm,
	}

	// ---- the direct case -------------------------------------------------
	//
	// No delegation: the signer must BE the principal's page, and the key must
	// be one of its entries.
	if len(chain) == 0 {
		if signerPage != principalPage {
			return nil, "", refuse(ReasonWrongPrincipal, fmt.Sprintf(
				"signer is %s but the authority being evaluated is %s", signerPage, principalPage))
		}
		if uint64(sig.SignerVersion) != principal.Version {
			return nil, "", refuse(ReasonWrongVersion, fmt.Sprintf(
				"signature was made against version %d, the page is at version %d",
				sig.SignerVersion, principal.Version))
		}
		entry, ok := entryForKey(entries, res.PublicKeyHash)
		if !ok {
			return nil, "", refuse(ReasonKeyNotOnPage, fmt.Sprintf(
				"key %s is not an entry of %s", SafeTruncate(res.PublicKeyHash, 16), principalPage))
		}
		return res, entry.Identity(), nil
	}

	// ---- the delegated case ----------------------------------------------
	//
	// The chain is stated outermost first, so chain[0] must be the principal's
	// own page: the delegation starts at the authority being evaluated. A chain
	// that starts anywhere else is not evidence about this authority at all.
	if normalizeAccURL(chain[0]) != principalPage {
		return nil, "", refuse(ReasonWrongPrincipal, fmt.Sprintf(
			"the chain starts at %s, but the authority being evaluated is %s",
			chain[0], principalPage))
	}

	// Walk the path: chain[0] -> chain[1] -> ... -> chain[n-1] -> signerPage.
	// Each step must be a real delegate entry on the page it leaves.
	hops := append(append([]string{}, chain...), signerPage)

	fromState := principal
	fromReplayed := true
	var firstEntry KeyPageEntry
	for i := 0; i < len(hops)-1; i++ {
		from, to := normalizeAccURL(hops[i]), normalizeAccURL(hops[i+1])

		entry, ok := delegateEntryTo(fromState.EntrySet(), to)
		if !ok {
			return nil, "", refuse(ReasonPathBroken, fmt.Sprintf(
				"%s has no entry delegating to the book of %s - the chain inside the "+
					"signature's digest names a path this authority does not grant",
				from, to))
		}
		if i == 0 {
			// The entry on the PRINCIPAL page is the one this signature
			// satisfies, no matter how far the path continues. This is what
			// makes a longer path grant no more authority than a short one.
			firstEntry = entry
		}

		res.Path = append(res.Path, ResolutionLink{
			From: from, To: to, Via: entry.Delegate,
			FromVersion: fromState.Version, FromReplayed: fromReplayed,
		})

		next, err := r.Source.PageState(ctx, to)
		if err != nil {
			// Not a refusal of the signature - we could not read the page. A
			// caller must not turn this into a threshold verdict.
			return nil, "", refuse(ReasonPageUnavailable, fmt.Sprintf(
				"could not read %s: %v", to, err))
		}
		fromState = next
		fromReplayed = false
	}

	// The innermost page must carry the signing key, at the version the
	// signature was made against (KPSW-EXEC).
	if uint64(sig.SignerVersion) != fromState.Version {
		return nil, "", refuse(ReasonWrongVersion, fmt.Sprintf(
			"signature was made against version %d of %s, which is at version %d",
			sig.SignerVersion, signerPage, fromState.Version))
	}
	if _, ok := entryForKey(fromState.EntrySet(), res.PublicKeyHash); !ok {
		return nil, "", refuse(ReasonKeyNotOnPage, fmt.Sprintf(
			"key %s is not an entry of %s", SafeTruncate(res.PublicKeyHash, 16), signerPage))
	}

	return res, firstEntry.Identity(), nil
}

// entryForKey finds the entry a key hash satisfies.
func entryForKey(entries []KeyPageEntry, keyHash string) (KeyPageEntry, bool) {
	keyHash = strings.ToLower(keyHash)
	for _, e := range entries {
		if e.KeyHash != "" && strings.EqualFold(e.KeyHash, keyHash) {
			return e, true
		}
	}
	return KeyPageEntry{}, false
}

// delegateEntryTo finds the entry on a page that delegates to the book
// containing the given page.
//
// The entry names a BOOK and the signature names a PAGE, so the comparison is
// "is this page one of that book's pages" - which, for Accumulate's naming, is
// the page URL's parent. Comparing the two directly is the mistake that makes a
// correctly built chain look broken.
func delegateEntryTo(entries []KeyPageEntry, page string) (KeyPageEntry, bool) {
	book := bookOfPage(page)
	if book == "" {
		return KeyPageEntry{}, false
	}
	for _, e := range entries {
		if e.Delegate != "" && normalizeAccURL(e.Delegate) == book {
			return e, true
		}
	}
	return KeyPageEntry{}, false
}

// bookOfPage returns the key book a page belongs to: acc://foo.acme/book/1 ->
// acc://foo.acme/book.
func bookOfPage(page string) string {
	p := normalizeAccURL(page)
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i]
}

func keyHashOf(publicKey string) string {
	sv := SignatureVerifier{}
	h, err := sv.ComputeKeyHash(publicKey)
	if err != nil {
		return ""
	}
	return strings.ToLower(h)
}

// SignerAccounts returns every account that signed, sorted and de-duplicated.
//
// This finishes governance spec section 4.1 item 5, recorded as half-satisfied
// in L4_DESIGN.md section 1.3 Defect C: enumeration must cover EVERY signer
// account, which under delegation means several, on possibly several
// partitions. It is also what Phase 4 builds one proof leg per.
//
// Only signatures that were COUNTED contribute. A signature that did not help
// meet the threshold needs no inclusion proof, and proving it would inflate the
// proof without adding evidence.
func (r *ResolutionResult) SignerAccounts() []string {
	seen := map[string]bool{}
	for _, s := range r.Resolved {
		seen[s.SignerPage] = true
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// describeResolutionRefusals renders why each signature did not count, for a
// threshold failure message.
//
// A bare "1/2" cannot distinguish an institution that did not authorize
// something from a signature we could not read, and those must never look the
// same to whoever reads the failure.
func describeResolutionRefusals(res *ResolutionResult) string {
	if len(res.Refused) == 0 {
		return "no signature was refused, so the set was simply too small"
	}
	parts := make([]string, 0, len(res.Refused))
	for _, r := range res.Refused {
		parts = append(parts, fmt.Sprintf("[%s] %s", r.Reason, r.Detail))
	}
	return strings.Join(parts, "; ")
}
