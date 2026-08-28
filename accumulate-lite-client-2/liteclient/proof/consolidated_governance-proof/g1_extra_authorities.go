// Copyright 2026 Certen Protocol
//
// THE AUTHORITIES A TRANSACTION REQUIRES BEYOND ITS PRINCIPAL'S.
//
// # THE DEFECT
//
// ResolveAccount has always taken an extraAuthorities argument, and the one
// live caller passed nil. So the resolver asked "did the PRINCIPAL's authority
// set approve this?" and reported the answer as though it were the whole
// question.
//
// For an ordinary writeData it is the whole question. For two kinds of
// transaction it is not, and both are exactly the kind a governance proof
// exists to check:
//
//	an UpdateKeyPage that ADDS A DELEGATE requires that delegate book's approval
//	an UpdateAccountAuth that ADDS AN AUTHORITY requires that authority's
//
// A proof that skipped them would report "authorized" on a transaction that
// added a co-signer without the co-signer's consent - a claim strictly stronger
// than the evidence, and in the direction that matters.
//
// PHASE7_CORPUS_MANIFEST.md §6 learned the first of these the hard way: two-
// sided delegation is a rule of the protocol, and all three of its failure
// modes return code:ok while nothing executes.
//
// # THE RULE, QUOTED FROM accumulate-core
//
// protocol/transaction.go, Transaction.GetAdditionalAuthorities - this file
// mirrors it case for case, and the mirror is the point. Deriving these from
// our own reading of what "ought to" require approval is how the two drift.
//
//	CreateIdentity, CreateTokenAccount, CreateDataAccount,
//	CreateToken, CreateKeyBook   -> body.Authorities
//
//	UpdateKeyPage                -> for each operation:
//	                                  AddKeyOperation    with Entry.Delegate
//	                                  UpdateKeyOperation with NewEntry.Delegate
//	                                ("The old entry can match just on the hash,
//	                                 so always assume the delegate is new")
//
//	UpdateAccountAuth            -> AddAccountAuthorityOperation -> op.Authority
//
// and internal/core/execute/v2/block/transaction.go adds Header.Authorities on
// top, gated on V2Baikonur.
//
// # AND THE ONE THAT WAS ALSO HARD-CODED
//
// The same call passed ignoreDisabled: false, always. accumulate-core computes
// it (transaction.go:207):
//
//	ignoreDisabled := delivery.Transaction.Body.Type().RequireAuthorization()
//
// which protocol/access_control.go makes true for exactly one type:
// UpdateAccountAuth. A DISABLED authority still has to vote on a transaction
// that changes the account's authority set - otherwise disabling an authority
// would be enough to stop it objecting to being removed. Hard-coding false
// skipped it.
//
// # FAIL CLOSED ON AN OPERATION WE DO NOT KNOW
//
// accumulate-core's switch ignores operations it does not name, which is
// correct there: it holds the full type set, so anything unnamed genuinely adds
// no authority. Here the set is a list of strings, and an operation type added
// to the protocol after this was written would be silently read as "adds no
// authority" - understating the authority set, which surfaces as an unmet
// threshold or, worse, as an approval that was never required.
//
// So every operation type the protocol currently defines is named below, and
// anything else is an ERROR. A capability limit stated loudly, never a
// governance verdict inferred from ignorance.
package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// ExtraAuthorities is what a transaction requires beyond its principal's
// authority set, plus the one flag that is derived from the body type.
type ExtraAuthorities struct {
	// URLs are the additional authorities, canonically ordered.
	URLs []string
	// IgnoreDisabled mirrors Body.Type().RequireAuthorization(): when true a
	// disabled authority is NOT skipped.
	IgnoreDisabled bool
	// BodyType is the transaction type the derivation was made from, so the
	// evidence can say what it read rather than only what it concluded.
	BodyType string
}

// keyPageOperationsThatAddNoAuthority are the operation types accumulate-core
// defines which cannot introduce an authority.
//
// Named explicitly so that an operation type NOT in this list and not handled
// above is an error rather than a silent no-op. Source: protocol/enums_gen.go,
// KeyPageOperationType.String().
var keyPageOperationsThatAddNoAuthority = map[string]bool{
	"remove":                 true,
	"setthreshold":           true,
	"updateallowed":          true,
	"setrejectthreshold":     true,
	"setresponsethreshold":   true,
	"setallowedtransactions": true,
}

// accountAuthOperationsThatAddNoAuthority is the same for UpdateAccountAuth.
// Source: protocol/enums_gen.go, AccountAuthOperationType.String().
var accountAuthOperationsThatAddNoAuthority = map[string]bool{
	"enable":          true,
	"disable":         true,
	"removeauthority": true,
}

// bodyTypesCarryingAuthorities are the creation transactions whose body carries
// an explicit authorities array.
var bodyTypesCarryingAuthorities = map[string]bool{
	"createidentity":     true,
	"createtokenaccount": true,
	"createdataaccount":  true,
	"createtoken":        true,
	"createkeybook":      true,
}

// DeriveExtraAuthorities reads the transaction and returns the authorities its
// body and header require beyond the principal's.
//
// Errors are errors: an undecidable body must never be reported as a body that
// requires nothing.
func DeriveExtraAuthorities(ctx context.Context, client RPCClientInterface,
	account, txHash string) (ExtraAuthorities, error) {

	out := ExtraAuthorities{}
	if client == nil {
		return out, fmt.Errorf("extra authorities: no client to read the transaction with")
	}

	scope := fmt.Sprintf("acc://%s@%s", txHash, strings.TrimPrefix(normalizeAccURL(account), "acc://"))
	resp, err := client.Query(ctx, scope, map[string]interface{}{"queryType": "default"})
	if err != nil {
		return out, fmt.Errorf("extra authorities: query %s: %w", scope, err)
	}

	pu := ProofUtilities{}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return out, fmt.Errorf("extra authorities: %s: %w", scope, err)
	}

	message, _ := pu.CaseInsensitiveGet(result, "message").(map[string]interface{})
	if message == nil {
		return out, fmt.Errorf("extra authorities: %s carries no message to read the body from", scope)
	}
	transaction, _ := pu.CaseInsensitiveGet(message, "transaction").(map[string]interface{})
	if transaction == nil {
		return out, fmt.Errorf("extra authorities: %s carries no transaction", scope)
	}

	return extraAuthoritiesFromTransaction(transaction)
}

// extraAuthoritiesFromTransaction is the derivation itself, separated from the
// query so it can be tested against a body without a network.
func extraAuthoritiesFromTransaction(transaction map[string]interface{}) (ExtraAuthorities, error) {
	pu := ProofUtilities{}
	out := ExtraAuthorities{}

	var found []string

	// Header.Authorities, added by V2Baikonur. Present or absent; when present
	// every entry is required.
	if header, ok := pu.CaseInsensitiveGet(transaction, "header").(map[string]interface{}); ok {
		for _, a := range asStringList(pu.CaseInsensitiveGet(header, "authorities")) {
			found = append(found, a)
		}
	}

	body, _ := pu.CaseInsensitiveGet(transaction, "body").(map[string]interface{})
	if body == nil {
		return out, fmt.Errorf("extra authorities: the transaction carries no body")
	}

	bodyType, _ := pu.CaseInsensitiveGet(body, "type").(string)
	out.BodyType = bodyType
	lowerType := strings.ToLower(bodyType)

	// Exactly the one type accumulate-core's RequireAuthorization returns true
	// for. Derived, not assumed.
	out.IgnoreDisabled = lowerType == "updateaccountauth"

	switch {
	case bodyTypesCarryingAuthorities[lowerType]:
		found = append(found, asStringList(pu.CaseInsensitiveGet(body, "authorities"))...)

	case lowerType == "updatekeypage":
		ops, err := operationList(body, "operation")
		if err != nil {
			return out, err
		}
		for _, op := range ops {
			opType := strings.ToLower(stringOf(pu.CaseInsensitiveGet(op, "type")))
			switch opType {
			case "add":
				// AddKeyOperation: the delegate on the entry being added.
				if d := delegateOf(pu.CaseInsensitiveGet(op, "entry")); d != "" {
					found = append(found, d)
				}
			case "update":
				// UpdateKeyOperation: accumulate-core always treats the NEW
				// entry's delegate as new, because the old entry can match on
				// the key hash alone.
				if d := delegateOf(pu.CaseInsensitiveGet(op, "newEntry")); d != "" {
					found = append(found, d)
				}
			default:
				if !keyPageOperationsThatAddNoAuthority[opType] {
					return out, fmt.Errorf("extra authorities: unrecognised key page operation %q - "+
						"this proof cannot tell whether it introduces an authority, and assuming it "+
						"does not would understate the authority set. This is a capability limit, "+
						"NOT a governance rejection", opType)
				}
			}
		}

	case lowerType == "updateaccountauth":
		ops, err := operationList(body, "operations")
		if err != nil {
			return out, err
		}
		for _, op := range ops {
			opType := strings.ToLower(stringOf(pu.CaseInsensitiveGet(op, "type")))
			switch opType {
			case "addauthority":
				if a := stringOf(pu.CaseInsensitiveGet(op, "authority")); a != "" {
					found = append(found, a)
				}
			default:
				if !accountAuthOperationsThatAddNoAuthority[opType] {
					return out, fmt.Errorf("extra authorities: unrecognised account auth operation %q - "+
						"this proof cannot tell whether it introduces an authority. This is a "+
						"capability limit, NOT a governance rejection", opType)
				}
			}
		}
	}

	out.URLs = canonicalAuthorityList(found)
	return out, nil
}

// operationList reads an operations array, requiring it to be one.
//
// A body of one of these two types with no operations array at all is not a
// body with no operations - it is a body we failed to read, and the difference
// decides whether an authority is required.
func operationList(body map[string]interface{}, field string) ([]map[string]interface{}, error) {
	pu := ProofUtilities{}
	raw := pu.CaseInsensitiveGet(body, field)
	if raw == nil {
		return nil, fmt.Errorf("extra authorities: body carries no %q array; its operations "+
			"cannot be read, so whether it requires another authority is unknown", field)
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("extra authorities: %q is not an array", field)
	}
	out := make([]map[string]interface{}, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("extra authorities: %s[%d] is not an object", field, i)
		}
		out = append(out, m)
	}
	return out, nil
}

// delegateOf pulls the delegate URL off a key page entry, if it has one.
func delegateOf(entry interface{}) string {
	m, ok := entry.(map[string]interface{})
	if !ok {
		return ""
	}
	pu := ProofUtilities{}
	return stringOf(pu.CaseInsensitiveGet(m, "delegate"))
}

func stringOf(v interface{}) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func asStringList(v interface{}) []string {
	list, ok := v.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		if s := stringOf(item); s != "" {
			out = append(out, s)
			continue
		}
		// An authority may arrive as an object carrying a url.
		if m, ok := item.(map[string]interface{}); ok {
			pu := ProofUtilities{}
			if s := stringOf(pu.CaseInsensitiveGet(m, "url")); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// canonicalAuthorityList normalizes, de-duplicates and sorts.
//
// Rule 12: the order operations appear in a body is the submitter's choice, and
// two validators reading identical chain data must produce identical bytes.
// De-duplication matters too - a body may add the same delegate on two
// operations, and requiring one authority twice is not a stronger check, only a
// threshold that can never be met.
func canonicalAuthorityList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, a := range in {
		n := normalizeAccURL(a)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
