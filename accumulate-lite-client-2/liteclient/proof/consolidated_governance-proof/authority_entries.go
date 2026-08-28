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

// What a key page entry actually is.
//
// KeyPageState carried `Keys []string` - a list of key hashes - and nothing
// else. An Accumulate key page entry is a KeySpec, and a KeySpec holds a key
// hash OR a delegate, or both:
//
//	{"publicKeyHash": "44d3e6..."}          a key
//	{"delegate": "acc://foo.acme/book2"}    an authority
//
// Parsing only the first kind did not lose a detail, it lost the entry. A page
// whose only entry is a delegate parsed as "No valid keys found in key page
// definition" and the whole authority snapshot failed - which is why every one
// of the 400 production proofs is 1-of-1 with no delegation: nothing else could
// be represented, let alone counted.
//
// The threshold counts ENTRIES, not keys, so an entry model is not a nicety.
// A 2-of-3 page with one delegated entry has three entries and two of them must
// be satisfied; a model that can only see two of the three cannot reach the
// right answer even by accident.

// KeyPageEntry is one entry of a key page: a key, a delegated authority, or
// both.
//
// Both is legal in Accumulate and means either route satisfies THIS ONE entry -
// never two. That is the distinct-entry rule, and it is the first way to
// over-count.
type KeyPageEntry struct {
	// KeyHash is the SHA-256 of a public key, lowercase hex. Empty for a
	// delegate-only entry.
	KeyHash string `json:"keyHash,omitempty"`

	// Delegate is the acc:// URL of a key BOOK whose satisfaction satisfies
	// this entry. Empty for a plain key entry.
	//
	// A book, not a page: a page delegates to a book, and Accumulate resolves
	// the book's pages. The Delegator named INSIDE a signature is the page that
	// did the delegating, which is the other end of the same edge. Confusing
	// the two produces a chain that looks plausible and never resolves.
	Delegate string `json:"delegate,omitempty"`
}

// Identity is the entry's stable name, used to hold a page's entries in a set
// and to say "this entry has already been satisfied".
//
// It is derived from the entry's content rather than its index, because an
// index is a property of the response ordering and two queries need not agree
// on it.
func (e KeyPageEntry) Identity() string {
	switch {
	case e.KeyHash != "" && e.Delegate != "":
		return "both:" + strings.ToLower(e.KeyHash) + "|" + normalizeAccURL(e.Delegate)
	case e.Delegate != "":
		return "delegate:" + normalizeAccURL(e.Delegate)
	default:
		return "key:" + strings.ToLower(e.KeyHash)
	}
}

func (e KeyPageEntry) String() string {
	switch {
	case e.KeyHash != "" && e.Delegate != "":
		return fmt.Sprintf("key %s / delegate %s", SafeTruncate(e.KeyHash, 16), e.Delegate)
	case e.Delegate != "":
		return "delegate " + e.Delegate
	default:
		return "key " + SafeTruncate(e.KeyHash, 16)
	}
}

// IsEmpty reports an entry that names neither a key nor a delegate. Such a
// thing cannot be satisfied by anything and must never be counted toward a
// threshold - an entry that can never be satisfied makes a threshold
// unreachable, which is a governance failure, and one that is silently dropped
// makes the threshold LOWER than the page says, which is worse.
func (e KeyPageEntry) IsEmpty() bool { return e.KeyHash == "" && e.Delegate == "" }

// normalizeAccURL lowercases and strips a trailing slash so two spellings of
// the same account compare equal. Accumulate URLs are case-insensitive in their
// authority part and the API is not consistent about case.
func normalizeAccURL(u string) string {
	// One definition of the canonical spelling, shared with
	// URLUtils.NormalizeURL. These two had drifted - NormalizeURL returned
	// acc:// URLs untouched, so it did not lower-case and did not strip a
	// trailing slash - and a normalisation that behaves two ways is how one
	// spelling of a page fails to match another.
	return canonicalAccSpelling(u)
}

// deriveKeyHashes returns the key-hash subset of a page's entries.
//
// KeyPageState.Keys is kept in this derived form so that everything which
// already reads it - membership checks, counts, logging - keeps working and
// keeps meaning what it meant. It is NOT the authority: Entries is. A page
// whose entries are all delegates has an empty Keys and is still a perfectly
// good authority.
func deriveKeyHashes(entries []KeyPageEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.KeyHash != "" {
			out = append(out, strings.ToLower(e.KeyHash))
		}
	}
	return out
}

// entriesEqual reports whether two entry sets are the same set, ignoring order.
// Used when comparing a parsed state against a reconstructed one.
func entriesEqual(a, b []KeyPageEntry) bool {
	if len(a) != len(b) {
		return false
	}
	ia, ib := entryIdentities(a), entryIdentities(b)
	for i := range ia {
		if ia[i] != ib[i] {
			return false
		}
	}
	return true
}

func entryIdentities(entries []KeyPageEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Identity())
	}
	sort.Strings(out)
	return out
}

// parseKeyPageEntry reads one KeySpec out of a v3 response object.
//
// It accepts every spelling the API and the transaction bodies use:
// publicKeyHash on an account, keyHash in an updateKeyPage operation, and
// publicKey when only the key itself is present.
func parseKeyPageEntry(pu ProofUtilities, m map[string]interface{}) (KeyPageEntry, error) {
	var e KeyPageEntry

	for _, field := range []string{"publicKeyHash", "keyHash"} {
		if v, ok := pu.CaseInsensitiveGet(m, field).(string); ok && v != "" {
			e.KeyHash = strings.ToLower(v)
			break
		}
	}
	if e.KeyHash == "" {
		// Only the raw key is present, so hash it the way a page stores it.
		if v, ok := pu.CaseInsensitiveGet(m, "publicKey").(string); ok && v != "" {
			sv := SignatureVerifier{}
			h, err := sv.ComputeKeyHash(v)
			if err != nil {
				return KeyPageEntry{}, fmt.Errorf("compute key hash: %w", err)
			}
			e.KeyHash = strings.ToLower(h)
		}
	}

	if v, ok := pu.CaseInsensitiveGet(m, "delegate").(string); ok && v != "" {
		e.Delegate = normalizeAccURL(v)
	}

	return e, nil
}
