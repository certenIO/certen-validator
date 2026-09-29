// Copyright 2026 Certen Protocol
//
// THE GOVERNANCE AN INTENT DECLARES, CHECKED AGAINST THE GOVERNANCE THAT EXECUTED IT (RB4-F64d).
//
// An intent's governance blob (the third of the four data entries of its CERTEN_INTENT WriteData) states, in
// `authorization.authorities`, the principal's authority set as the bridge read it at prepare time - every authority
// whose vote Accumulate requires, with its disabled flag - and, in `authorization.additional_authorities`, the
// authorities its transaction header adds. That is a claim about who governs the transaction, signed by the user as
// part of the transaction.
//
// The vote record says who actually governed it: the principal's authority set at execution, replayed from the
// chain, and the extra authorities the transaction required, each of which voted. The declaration is honoured only if
// the two sets are the same. When they are not - the account's authorities changed between prepare and execution, or
// the declaration was never true - the intent did not execute under the governance it declared, and that is a
// governance verdict on the intent, not an outage.
//
// The declaration is read from the governed transaction itself - the bytes the vote's evidence carries, bound to the
// hash G0 proved executed - so the validator at proof time and a verifier offline read the same claim.
//
// An intent whose governance blob carries no `authorities` declares no authority set: there is no claim to check, and
// that is reported by name wherever the decision is.
package proof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ErrDeclaredGovernanceMismatch: the intent executed under governance other than the governance it declares.
var ErrDeclaredGovernanceMismatch = errors.New("the intent did not execute under the governance it declares")

// DeclaredAuthority is one authority the intent declares, as Accumulate records it on an account.
type DeclaredAuthority struct {
	URL      string `json:"url"`
	Disabled bool   `json:"disabled"`
}

// DeclaredGovernance is the authority set an intent declares.
type DeclaredGovernance struct {
	Authorities []DeclaredAuthority
	Additional  []string
}

// governanceBlobIndex is the governance blob's position among the intent's data entries.
const governanceBlobIndex = 2

// DeclaredGovernanceOfEvidence reads the declaration from the governed transaction the vote's evidence carries.
func DeclaredGovernanceOfEvidence(ev *govvote.Evidence) (*DeclaredGovernance, error) {
	if ev == nil {
		return nil, fmt.Errorf("no vote evidence to read the declared governance from")
	}
	b, err := hex.DecodeString(ev.Transaction)
	if err != nil {
		return nil, fmt.Errorf("the governed transaction is not hex")
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("the governed transaction does not decode: %w", err)
	}
	return DeclaredGovernanceOf(txn)
}

// DeclaredGovernanceOf reads the authority set an intent transaction declares. Nil with no error when its governance
// blob declares none; an error when the declaration is present and malformed - a claim that cannot be read is not
// an absent one.
func DeclaredGovernanceOf(txn *protocol.Transaction) (*DeclaredGovernance, error) {
	wd, ok := txn.Body.(*protocol.WriteData)
	if !ok {
		return nil, fmt.Errorf("the governed transaction is a %v, not an intent's writeData", txn.Body.Type())
	}
	if wd.Entry == nil {
		return nil, fmt.Errorf("the intent's writeData carries no entry")
	}
	data := wd.Entry.GetData()
	if len(data) <= governanceBlobIndex {
		return nil, fmt.Errorf("the intent carries %d data entries, and no governance blob", len(data))
	}
	var blob struct {
		Authorization map[string]json.RawMessage `json:"authorization"`
	}
	if err := json.Unmarshal(data[governanceBlobIndex], &blob); err != nil {
		return nil, fmt.Errorf("the intent's governance blob is not JSON: %w", err)
	}
	raw, declared := blob.Authorization["authorities"]
	if !declared {
		return nil, nil
	}

	out := &DeclaredGovernance{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out.Authorities); err != nil {
		return nil, fmt.Errorf("the declared authorities are malformed: %w", err)
	}
	if len(out.Authorities) == 0 {
		return nil, fmt.Errorf("the intent declares an empty authority set; no account is governed by none")
	}
	seen := map[string]bool{}
	for i, a := range out.Authorities {
		u, err := canonicalAuthority(a.URL)
		if err != nil {
			return nil, fmt.Errorf("declared authority %d: %w", i, err)
		}
		if seen[u] {
			return nil, fmt.Errorf("the intent declares %s twice", u)
		}
		seen[u] = true
		out.Authorities[i].URL = u
	}
	if rawAdd, ok := blob.Authorization["additional_authorities"]; ok {
		if err := json.Unmarshal(rawAdd, &out.Additional); err != nil {
			return nil, fmt.Errorf("the declared additional authorities are malformed: %w", err)
		}
		for i, a := range out.Additional {
			u, err := canonicalAuthority(a)
			if err != nil {
				return nil, fmt.Errorf("declared additional authority %d: %w", i, err)
			}
			out.Additional[i] = u
		}
	}
	return out, nil
}

func canonicalAuthority(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || s == "" {
		return "", fmt.Errorf("%q is not an account url", s)
	}
	return govvote.CanonicalAccSpelling(u.String()), nil
}

// CheckDeclaredGovernance requires the vote record's governance to be the declared one: the principal's authorities
// at execution are exactly the declared authorities, disabled flags included, and the extra authorities the
// transaction required are exactly the declared additional ones. That every one of them voted accept is the vote
// record's own requirement (GovernanceDecisionRecord).
func CheckDeclaredGovernance(d *DeclaredGovernance, rec *AuthorizationRecord) error {
	if d == nil || rec == nil {
		return fmt.Errorf("a declaration and a vote record are both required")
	}
	var actual, extra []string
	for _, a := range rec.Authorities {
		u, err := canonicalAuthority(a.Authority)
		if err != nil {
			return fmt.Errorf("vote record authority: %w", err)
		}
		if a.Extra {
			extra = append(extra, u)
		} else {
			actual = append(actual, describeDeclared(u, a.Disabled))
		}
	}
	var declared []string
	for _, a := range d.Authorities {
		declared = append(declared, describeDeclared(a.URL, a.Disabled))
	}
	additional := append([]string(nil), d.Additional...)
	if !sameSet(declared, actual) {
		return fmt.Errorf("%w: it declares the authorities %v, and the account was governed at execution by %v",
			ErrDeclaredGovernanceMismatch, sorted(declared), sorted(actual))
	}
	if !sameSet(additional, extra) {
		return fmt.Errorf("%w: it declares the additional authorities %v, and the transaction required %v",
			ErrDeclaredGovernanceMismatch, sorted(additional), sorted(extra))
	}
	return nil
}

func describeDeclared(u string, disabled bool) string {
	if disabled {
		return u + " (disabled)"
	}
	return u
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa, sb := sorted(a), sorted(b)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func sorted(a []string) []string {
	out := append([]string(nil), a...)
	sort.Strings(out)
	return out
}

// DescribeDeclaredGovernance names a declaration for a reader.
func DescribeDeclaredGovernance(d *DeclaredGovernance) string {
	if d == nil {
		return "no declared authority set"
	}
	parts := make([]string, 0, len(d.Authorities))
	for _, a := range d.Authorities {
		parts = append(parts, describeDeclared(a.URL, a.Disabled))
	}
	s := "[" + strings.Join(parts, ", ") + "]"
	if len(d.Additional) > 0 {
		s += " + additional [" + strings.Join(d.Additional, ", ") + "]"
	}
	return s
}
