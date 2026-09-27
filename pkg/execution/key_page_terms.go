// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/json"
	"strconv"
	"strings"

	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// KeyPageTerms is what a governance level row states about the key page that authorised the intent:
// M (the page's accept threshold), N (the keys on the page), the signatures that verified against it,
// and its key book. Every value comes from the proven G1 result - the page state replayed to the
// execution block - and is nil when that proof does not establish it.
//
// It replaces three sources that disagreed and were none of them proven (RB3-F69): a 1-of-1 default
// for fields no producer ever wrote, an unproven transaction query whose "M" was the signatures
// collected and whose "N" was the threshold (the reverse of what every reader takes "M of N" to
// mean), and, on the batch path, the achieved weight standing in for N. The signature count was the
// number of VALIDATOR attestations, not key page signatures.
type KeyPageTerms struct {
	Threshold  *int
	Keys       *int
	Signatures *int
	Authority  *string
}

// keyPageTermsFromG1 reads the key page terms out of a proven G1 result. Anything short of a complete
// G1 proof with a coherent page state (at least one key, a threshold between 1 and the key count)
// establishes nothing.
func keyPageTermsFromG1(raw json.RawMessage) KeyPageTerms {
	if len(raw) == 0 {
		return KeyPageTerms{}
	}
	var g1 certenproof.G1Result
	if err := json.Unmarshal(raw, &g1); err != nil || !g1.G1ProofComplete {
		return KeyPageTerms{}
	}
	state := g1.AuthoritySnapshot.StateExec
	keys := len(state.Keys)
	if keys == 0 || state.Threshold == 0 || state.Threshold > uint64(keys) {
		return KeyPageTerms{}
	}
	m, n, sigs := int(state.Threshold), keys, g1.UniqueValidKeys
	terms := KeyPageTerms{Threshold: &m, Keys: &n, Signatures: &sigs}
	if book, ok := keyBookOf(g1.AuthoritySnapshot.Page); ok {
		terms.Authority = &book
	}
	return terms
}

// keyBookOf is the key book a key page belongs to: an Accumulate key page is <book>/<index>.
func keyBookOf(page string) (string, bool) {
	i := strings.LastIndex(page, "/")
	if i <= len("acc://") || !strings.HasPrefix(page, "acc://") {
		return "", false
	}
	if _, err := strconv.ParseUint(page[i+1:], 10, 64); err != nil {
		return "", false
	}
	return page[:i], true
}
