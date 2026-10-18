package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RB8-E. The first live run of a delegated ECDSA approver (Kermit, 2026-10-18) was refused by the validators at RB8-B with
//
//	resolve signing key page of acc://pv2-sig-1.acme/book-deleg ...: no page of key book acc://pv2-sig-1.acme/book-deleg
//	carries a key signature over this transaction
//
// because the network files a delegated vote under the DELEGATE's page (book-dinner/1, type "delegated", the delegating page
// in `delegator`) and files only an `authority` record under the delegating page (book-deleg/1), and the resolver looked
// for a vote filed under a page of the principal's own book. The page that decided the principal's authority is the
// delegating page: it is the one the governance proof names, and G1 verifies the delegate's key behind it.
//
// testdata/kermit_delegated_ecdsa_signing_sets.json is the unedited response of Kermit's v3 `query` for that transaction.

const (
	delegBook = "acc://pv2-sig-1.acme/book-deleg"
	delegPage = "acc://pv2-sig-1.acme/book-deleg/1"
	delegTx   = "bd3fd4a2a338d0eaa56c5be697317c3c0d657f1e5f177ac92a0dc69420ed8fb1"
)

func liveDelegatedSets(t *testing.T) []signingKeyPageSet {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "kermit_delegated_ecdsa_signing_sets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var q signingKeyPageQuery
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatalf("the live response does not decode: %v", err)
	}
	return q.Result.Signatures.Records
}

func TestSigningKeyPage_DelegatedVoteFiledUnderTheDelegateNamesTheDelegatingPage(t *testing.T) {
	sets := liveDelegatedSets(t)
	page, notes, err := selectSigningKeyPage(delegBook, delegPage, delegTx, sets)
	if err != nil || page != delegPage {
		t.Fatalf("got %q, %v; want the delegating page %s (notes %v)", page, err, delegPage, notes)
	}
	if !strings.Contains(strings.Join(notes, "|"), "delegated") {
		t.Fatalf("the delegation must be visible in the notes: %v", notes)
	}
	// With no page declared, the page that decided is still the delegating page.
	if page, _, err = selectSigningKeyPage(delegBook, "", delegTx, sets); err != nil || page != delegPage {
		t.Fatalf("undeclared: got %q, %v", page, err)
	}
	// The delegate's own book is not the principal's authority: nothing in it is a vote on the principal's data account
	// through ITS book, so asking for that book names the page the delegated vote was cast from (a key vote, delegated).
	if _, _, err = selectSigningKeyPage("acc://pv2-sig-1.acme/book-other", "", delegTx, sets); err == nil {
		t.Fatal("a book none of whose pages signed or delegated must still be refused")
	}
}

// A delegated signature on another transaction says nothing about this one.
func TestSigningKeyPage_ADelegatedVoteOnAnotherTransactionIsNotCounted(t *testing.T) {
	if _, _, err := selectSigningKeyPage(delegBook, delegPage, strings.Repeat("22", 32), liveDelegatedSets(t)); err == nil {
		t.Fatal("a delegated vote for another transaction named a signing page")
	}
}
