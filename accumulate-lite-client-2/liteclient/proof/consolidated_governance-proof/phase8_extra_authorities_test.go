// Copyright 2026 Certen Protocol
//
// Phase 8 item 6 — the authorities a transaction requires beyond its
// principal's, DERIVED from the body rather than handed in.
//
// TestP7_Auth_ExtraAuthoritiesAreRequired proved the resolver honours extras it
// is GIVEN. That is a test of the rule. Nothing supplied them: the one live
// caller passed nil, so the rule was correct and unreachable, and an
// UpdateKeyPage that added a delegate was proved "authorized" without the
// delegate's approval ever being required.
//
// These tests close the gap between the rule and the caller. The derivation
// mirrors accumulate-core's Transaction.GetAdditionalAuthorities case for case;
// where the two could drift, the test names the core behaviour it is mirroring.
package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func p8tx(bodyJSON string, headerJSON string) map[string]interface{} {
	doc := `{"header":` + headerJSON + `,"body":` + bodyJSON + `}`
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		panic(err)
	}
	return m
}

const p8NoHeader = `{"principal":"acc://alpha.acme/data"}`

// TestP8_OrdinaryWriteDataRequiresNothingExtra is the compatibility direction,
// and the one that keeps every production intent working.
//
// Every CERTEN intent is a writeData. If this derivation invented an authority
// for one, it would demand an approval that does not exist and turn all
// production traffic into a governance rejection.
func TestP8_OrdinaryWriteDataRequiresNothingExtra(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(
		`{"type":"writeData","entry":{"type":"doubleHash"}}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.URLs) != 0 {
		t.Fatalf("a writeData required extra authorities: %v", got.URLs)
	}
	if got.IgnoreDisabled {
		t.Fatal("a writeData must not force disabled authorities to vote")
	}
}

// TestP8_AddDelegateRequiresTheDelegate is the two-sided delegation rule that
// PHASE7_CORPUS_MANIFEST.md §6 learned the hard way.
func TestP8_AddDelegateRequiresTheDelegate(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateKeyPage",
		"operation":[{"type":"add","entry":{"delegate":"acc://certen-p7f-omega.acme/book"}}]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.URLs) != 1 || got.URLs[0] != "acc://certen-p7f-omega.acme/book" {
		t.Fatalf("adding a delegate did not require that delegate's approval: %v", got.URLs)
	}
}

// TestP8_UpdateKeyOperationDelegateIsAlsoRequired mirrors a case the runbook's
// summary did not mention and accumulate-core does handle.
//
// GetAdditionalAuthorities takes the NEW entry's delegate on an UpdateKeyOperation,
// with the comment: "The old entry can match just on the hash, so always assume
// the delegate is new." Skipping it would let an update introduce a delegate
// that never had to approve.
func TestP8_UpdateKeyOperationDelegateIsAlsoRequired(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateKeyPage",
		"operation":[{"type":"update","newEntry":{"delegate":"acc://new.acme/book"}}]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.URLs) != 1 || got.URLs[0] != "acc://new.acme/book" {
		t.Fatalf("an update that introduces a delegate did not require it: %v", got.URLs)
	}
}

// TestP8_KeyPageOpsThatAddNothingAddNothing keeps the derivation from inventing
// requirements: removing a key or setting a threshold introduces no authority.
func TestP8_KeyPageOpsThatAddNothingAddNothing(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateKeyPage",
		"operation":[
			{"type":"remove","entry":{"keyHash":"aa"}},
			{"type":"setThreshold","threshold":2},
			{"type":"add","entry":{"keyHash":"bb"}}
		]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.URLs) != 0 {
		t.Fatalf("operations that introduce no authority produced %v", got.URLs)
	}
}

// TestP8_AddAuthorityRequiresIt covers UpdateAccountAuth.
func TestP8_AddAuthorityRequiresIt(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateAccountAuth",
		"operations":[{"type":"addAuthority","authority":"acc://second.acme/book"}]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.URLs) != 1 || got.URLs[0] != "acc://second.acme/book" {
		t.Fatalf("adding an authority did not require it: %v", got.URLs)
	}
}

// TestP8_UpdateAccountAuthIgnoresDisabled is the flag that was hard-coded false.
//
// accumulate-core: ignoreDisabled = Body.Type().RequireAuthorization(), which is
// true for UpdateAccountAuth and nothing else. A DISABLED authority still votes
// on a transaction that changes the authority set - otherwise disabling an
// authority would be enough to stop it objecting to its own removal.
func TestP8_UpdateAccountAuthIgnoresDisabled(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateAccountAuth",
		"operations":[{"type":"removeAuthority","authority":"acc://second.acme/book"}]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !got.IgnoreDisabled {
		t.Fatal("an UpdateAccountAuth did not force disabled authorities to vote; a disabled " +
			"authority could then be removed without ever objecting")
	}

	other, err := extraAuthoritiesFromTransaction(p8tx(
		`{"type":"updateKeyPage","operation":[{"type":"setThreshold","threshold":1}]}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if other.IgnoreDisabled {
		t.Fatal("a non-UpdateAccountAuth forced disabled authorities to vote; RequireAuthorization " +
			"is true for exactly one type")
	}
}

// TestP8_HeaderAuthoritiesAreRequired covers the V2Baikonur addition.
func TestP8_HeaderAuthoritiesAreRequired(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(
		`{"type":"writeData"}`,
		`{"principal":"acc://alpha.acme/data","authorities":["acc://named.acme/book"]}`))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(got.URLs) != 1 || got.URLs[0] != "acc://named.acme/book" {
		t.Fatalf("an authority named on the header was not required: %v", got.URLs)
	}
}

// TestP8_CreationBodiesCarryAuthorities covers the five creation types.
func TestP8_CreationBodiesCarryAuthorities(t *testing.T) {
	for _, typ := range []string{
		"createIdentity", "createTokenAccount", "createDataAccount",
		"createToken", "createKeyBook",
	} {
		got, err := extraAuthoritiesFromTransaction(p8tx(
			`{"type":"`+typ+`","authorities":["acc://owner.acme/book"]}`, p8NoHeader))
		if err != nil {
			t.Fatalf("%s: derive: %v", typ, err)
		}
		if len(got.URLs) != 1 || got.URLs[0] != "acc://owner.acme/book" {
			t.Errorf("%s: authorities on the body were not required: %v", typ, got.URLs)
		}
	}
}

// TestP8_UnknownOperationFailsClosed is runbook step 3, and rule 8.
//
// accumulate-core's switch ignores operations it does not name, which is right
// there because it holds the full type set. Here the set is a list of strings,
// so an operation type added to the protocol later would be read as "adds no
// authority" - understating the authority set. That must be an error, loudly,
// and never a governance verdict inferred from ignorance.
func TestP8_UnknownOperationFailsClosed(t *testing.T) {
	_, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateKeyPage",
		"operation":[{"type":"someOperationInventedIn2027"}]
	}`, p8NoHeader))

	if err == nil {
		t.Fatal("an unrecognised key page operation was silently assumed to add no authority")
	}
	if !strings.Contains(err.Error(), "NOT a governance rejection") {
		t.Errorf("a capability limit must not read as a governance rejection, got: %v", err)
	}
}

// TestP8_MissingOperationsFailsClosed: a body of these types with no operations
// array is one we failed to READ, not one with nothing to do.
func TestP8_MissingOperationsFailsClosed(t *testing.T) {
	if _, err := extraAuthoritiesFromTransaction(p8tx(
		`{"type":"updateKeyPage"}`, p8NoHeader)); err == nil {
		t.Fatal("an unreadable updateKeyPage body was treated as requiring nothing")
	}
	if _, err := extraAuthoritiesFromTransaction(p8tx(
		`{"type":"updateAccountAuth"}`, p8NoHeader)); err == nil {
		t.Fatal("an unreadable updateAccountAuth body was treated as requiring nothing")
	}
}

// TestP8_ExtraAuthoritiesAreCanonical is rule 12 plus de-duplication.
//
// A body may add the same delegate twice. Requiring one authority twice is not
// a stronger check - it is a threshold that can never be met.
func TestP8_ExtraAuthoritiesAreCanonical(t *testing.T) {
	got, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateKeyPage",
		"operation":[
			{"type":"add","entry":{"delegate":"acc://zeta.acme/book"}},
			{"type":"add","entry":{"delegate":"acc://alpha.acme/book"}},
			{"type":"update","newEntry":{"delegate":"acc://zeta.acme/book"}}
		]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	want := []string{"acc://alpha.acme/book", "acc://zeta.acme/book"}
	if len(got.URLs) != len(want) {
		t.Fatalf("want %v, got %v", want, got.URLs)
	}
	for i := range want {
		if got.URLs[i] != want[i] {
			t.Fatalf("not canonically ordered and de-duplicated: want %v, got %v", want, got.URLs)
		}
	}
}

// TestP8_DerivedExtrasReachTheResolver is the end the whole item exists for:
// the derivation and the rule, joined.
//
// TestP7_Auth_ExtraAuthoritiesAreRequired hands the resolver its extras. This
// derives them from a body and requires the same outcome, so the rule can no
// longer be correct and unreachable at the same time.
func TestP8_DerivedExtrasReachTheResolver(t *testing.T) {
	kh1, sig1 := keyFor("account-key")
	kh2, sig2 := keyFor("delegate-key")
	sig1.Signer = "acc://alpha.acme/book/1"
	sig2.Signer = "acc://extra.acme/book/1"

	src := fakeAuthoritySource{
		auth: map[string][]AccountAuthority{
			"acc://alpha.acme/data": {{URL: "acc://alpha.acme/book"}},
		},
		books: map[string][]string{
			"acc://alpha.acme/book": {"acc://alpha.acme/book/1"},
			"acc://extra.acme/book": {"acc://extra.acme/book/1"},
		},
		pages: map[string]KeyPageState{
			"acc://alpha.acme/book/1": pageWith(1, 1, kh1),
			"acc://extra.acme/book/1": pageWith(1, 1, kh2),
		},
	}
	r := &AuthorityResolver{Source: src}

	// The body itself says the delegate is required - nothing is handed in.
	derived, err := extraAuthoritiesFromTransaction(p8tx(`{
		"type":"updateKeyPage",
		"operation":[{"type":"add","entry":{"delegate":"acc://extra.acme/book"}}]
	}`, p8NoHeader))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	only, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data",
		derived.URLs, derived.IgnoreDisabled, []SignatureData{sig1}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if only.Satisfied {
		t.Fatalf("a key page added a delegate without the delegate's approval and it read as "+
			"authorized: %s", only.Describe())
	}

	both, err := r.ResolveAccount(context.Background(), "acc://alpha.acme/data",
		derived.URLs, derived.IgnoreDisabled, []SignatureData{sig1, sig2}, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !both.Satisfied {
		t.Fatalf("both the account and the added delegate signed and it did not read as "+
			"approved: %s", both.Describe())
	}
}
