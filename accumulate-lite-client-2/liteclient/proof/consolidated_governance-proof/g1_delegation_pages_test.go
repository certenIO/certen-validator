// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// C5-D3: the enumeration route (route 2) discovers the signer accounts from the key pages themselves. It followed
// the delegate entries of the ONE page G1 was handed and never read the pages of the other authority books the
// transaction needs, so a delegate entry on a page of a second authority's book (a bank that delegates to a
// custodian, on another identity and partition) was not followed: route 1 found the delegated vote, route 2 did not,
// and G1 refused the proof as a route disagreement, live, for a transaction Kermit executed.
//
// These tests pin the discovery. They run offline against account records in the shape Kermit returns
// (g1_delegation_replay_test.go replays the real Kermit bytes of the five live transactions end to end).

// fakeAccounts serves the key page and key book records the discovery reads, by URL.
type fakeAccounts struct {
	mu      sync.Mutex
	pages   map[string][]string // page URL -> delegate books of its entries ("" for a plain key entry)
	books   map[string]int      // book URL -> page count
	failing map[string]bool     // URL -> every query of it fails
	queries []string
}

func newFakeAccounts() *fakeAccounts {
	return &fakeAccounts{pages: map[string][]string{}, books: map[string]int{}, failing: map[string]bool{}}
}

// book declares a key book of n pages, none of which delegates.
func (f *fakeAccounts) book(url string, n int) *fakeAccounts {
	url = normalizeAccURL(url)
	f.books[url] = n
	for i := 1; i <= n; i++ {
		f.pages[fmt.Sprintf("%s/%d", url, i)] = []string{""}
	}
	return f
}

// delegates makes the page's entries the given delegate books (a page with only delegate entries).
func (f *fakeAccounts) delegates(page string, books ...string) *fakeAccounts {
	out := make([]string, 0, len(books))
	for _, b := range books {
		out = append(out, normalizeAccURL(b))
	}
	f.pages[normalizeAccURL(page)] = out
	return f
}

func (f *fakeAccounts) pageJSON(url string, entries []string) string {
	keys := make([]string, 0, len(entries))
	for i, d := range entries {
		if d == "" {
			h := fmt.Sprintf("%064x", i+1)
			keys = append(keys, fmt.Sprintf(`{"publicKeyHash":"%s","publicKey":"%s"}`, h, h))
		} else {
			keys = append(keys, fmt.Sprintf(`{"delegate":"%s"}`, d))
		}
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","result":{"recordType":"account","account":{"type":"keyPage",`+
		`"keyBook":"%s","url":"%s","creditBalance":1,"acceptThreshold":1,"threshold":1,"version":1,"keys":[%s]},`+
		`"pending":{"recordType":"range","start":0,"total":0}},"id":1}`,
		url[:strings.LastIndex(url, "/")], url, strings.Join(keys, ","))
}

func (f *fakeAccounts) bookJSON(url string, n int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","result":{"recordType":"account","account":{"type":"keyBook","url":"%s",`+
		`"authorities":[{"url":"%s"}],"pageCount":%d},"pending":{"recordType":"range","start":0,"total":0}},"id":1}`,
		url, url, n)
}

func (f *fakeAccounts) QueryRaw(_ context.Context, scope string, _ map[string]interface{}) ([]byte, error) {
	key := normalizeAccURL(scope)
	f.mu.Lock()
	f.queries = append(f.queries, key)
	failing := f.failing[key]
	entries, isPage := f.pages[key]
	n, isBook := f.books[key]
	f.mu.Unlock()
	switch {
	case failing:
		return nil, fmt.Errorf("injected fault: connection reset by peer (%s)", key)
	case isPage:
		return []byte(f.pageJSON(key, entries)), nil
	case isBook:
		return []byte(f.bookJSON(key, n)), nil
	}
	return nil, fmt.Errorf("account %s does not exist", key)
}

func (f *fakeAccounts) Query(ctx context.Context, scope string, q map[string]interface{}) (map[string]interface{}, error) {
	raw, err := f.QueryRaw(ctx, scope, q)
	if err != nil {
		return nil, err
	}
	var out map[string]interface{}
	return out, json.Unmarshal(raw, &out)
}

func (f *fakeAccounts) GetEndpoint() string { return "fake" }

// discovery runs the enumeration route's page discovery for a declared page whose replayed state at execution has the
// given entries, and the roots (every page of every authority book the transaction needs, declared page first).
func discovery(t *testing.T, f *fakeAccounts, declared string, declaredEntries []string, roots ...string) ([]string, error) {
	t.Helper()
	am, err := NewArtifactManager(t.TempDir())
	if err != nil {
		t.Fatalf("artifact manager: %v", err)
	}
	g1 := NewG1Layer(f, am, "")
	state := KeyPageState{Version: 1, Threshold: 1}
	for i, d := range declaredEntries {
		if d == "" {
			state.Entries = append(state.Entries, KeyPageEntry{KeyHash: fmt.Sprintf("%064x", i+1)})
		} else {
			state.Entries = append(state.Entries, KeyPageEntry{Delegate: normalizeAccURL(d)})
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return g1.enumerateDelegatePages(ctx, declared, AuthoritySnapshot{Page: declared, StateExec: state}, roots...)
}

func wantPages(t *testing.T, got []string, want ...string) {
	t.Helper()
	norm := make([]string, len(want))
	for i, w := range want {
		norm[i] = normalizeAccURL(w)
	}
	if len(norm) > 1 {
		sort.Strings(norm[1:])
	}
	if fmt.Sprint(got) != fmt.Sprint(norm) {
		t.Fatalf("signer pages\n  got  %v\n  want %v", got, norm)
	}
}

const (
	custPage = "acc://cust.acme/book/1"
	bankPage = "acc://bank.acme/book/1"
)

// Depth 1, the live shape (pv2-cust-537): the account's authorities are cust/book and bank/book, the declared page
// is cust/book/1, and bank/book/1 holds ONLY a delegate entry to deleg/book-d1. The delegated page is a signer page.
func TestG1Delegation_DelegateOnANonDeclaredAuthorityPageIsEnumerated(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1).book("acc://deleg.acme/book-d1", 1).
		delegates(bankPage, "acc://deleg.acme/book-d1")
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, bankPage, "acc://deleg.acme/book-d1/1")
}

// The delegate entry may be on ANY page of ANY authority book, not only page 1.
func TestG1Delegation_DelegateOnASecondPageOfAnAuthorityBookIsEnumerated(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 3).book("acc://deleg.acme/book-d1", 1).
		delegates("acc://bank.acme/book/3", "acc://deleg.acme/book-d1")
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage, "acc://bank.acme/book/2", "acc://bank.acme/book/3")
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, bankPage, "acc://bank.acme/book/2", "acc://bank.acme/book/3", "acc://deleg.acme/book-d1/1")
}

// Depth 2 (pv2-cust-515): bank/book/1 -> deleg-a/book-d2/1 -> deleg-b/book-d1/1, three identities.
func TestG1Delegation_DepthTwoThroughANonDeclaredAuthorityPage(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1).
		book("acc://deleg-a.acme/book-d2", 1).book("acc://deleg-b.acme/book-d1", 1).
		delegates(bankPage, "acc://deleg-a.acme/book-d2").
		delegates("acc://deleg-a.acme/book-d2/1", "acc://deleg-b.acme/book-d1")
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, bankPage, "acc://deleg-a.acme/book-d2/1", "acc://deleg-b.acme/book-d1/1")
}

// A delegate entry on the DECLARED page was followed before and must still be (the replayed state at execution).
func TestG1Delegation_DelegateOnTheDeclaredPageIsStillEnumerated(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://deleg.acme/book-d1", 1)
	got, err := discovery(t, f, custPage, []string{"acc://deleg.acme/book-d1"}, custPage)
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, "acc://deleg.acme/book-d1/1")
}

// A delegate book with several pages: the delegated signer may be ANY page of it (the executor loads the signer by the
// signature's own signer URL and checks only that the delegator page lists the signer's BOOK as a delegate), and any
// of its pages may delegate further.
func TestG1Delegation_EveryPageOfADelegateBookIsASignerPage(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1).
		book("acc://deleg.acme/book-d1", 3).book("acc://deleg2.acme/book-e1", 1).
		delegates(bankPage, "acc://deleg.acme/book-d1").
		delegates("acc://deleg.acme/book-d1/3", "acc://deleg2.acme/book-e1")
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, bankPage,
		"acc://deleg.acme/book-d1/1", "acc://deleg.acme/book-d1/2", "acc://deleg.acme/book-d1/3", "acc://deleg2.acme/book-e1/1")
}

// Accumulate has no cycle detection, so a delegation graph may cycle (corpus case H). The visited set ends the walk,
// and a page is enumerated once however many edges lead to it - including edges back into the authority books.
func TestG1Delegation_ACycleBetweenBooksEndsTheWalk(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1).
		book("acc://deleg.acme/book-d1", 1).book("acc://deleg.acme/book-d2", 1).
		delegates(bankPage, "acc://deleg.acme/book-d1").
		delegates("acc://deleg.acme/book-d1/1", "acc://deleg.acme/book-d2").
		delegates("acc://deleg.acme/book-d2/1", "acc://deleg.acme/book-d1", "acc://bank.acme/book", "acc://cust.acme/book")
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, bankPage, "acc://deleg.acme/book-d1/1", "acc://deleg.acme/book-d2/1")
}

// A book that delegates to itself.
func TestG1Delegation_ABookThatDelegatesToItselfEndsTheWalk(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1).
		delegates(bankPage, "acc://bank.acme/book")
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, bankPage)
}

// Control: no delegation anywhere (pv2-cust-508 - two authorities on two partitions). The pages are the declared page
// and the other authorities' pages, in the canonical order, exactly as before.
func TestG1Delegation_ControlWithoutDelegationIsUnchanged(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 2)
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage, "acc://bank.acme/book/2")
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, custPage, bankPage, "acc://bank.acme/book/2")
}

// The depth bound is the executor's own: twenty delegators is the most it accepts, so the signer can be twenty hops
// from an authority page and no further.
func TestG1Delegation_TheDepthBoundIsTheExecutorLimit(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1)
	prev := bankPage
	var all []string
	for i := 1; i <= 22; i++ {
		book := fmt.Sprintf("acc://chain.acme/book-d%d", i)
		f.book(book, 1)
		f.delegates(prev, book)
		prev = book + "/1"
		all = append(all, prev)
	}
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err != nil {
		t.Fatal(err)
	}
	wantPages(t, got, append([]string{custPage, bankPage}, all[:20]...)...)
}

// A page that cannot be read is a signer account that cannot be enumerated: the route is unavailable (named, with the
// page), never silently narrower. This is the authority page, not a delegate page.
func TestG1Delegation_AnUnreadableAuthorityPageFailsTheRouteByName(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1)
	f.failing[normalizeAccURL(bankPage)] = true
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err == nil {
		t.Fatalf("an authority page that could not be read gave pages %v; the route must be unavailable", got)
	}
	if !strings.Contains(err.Error(), "bank.acme/book/1") {
		t.Fatalf("the failure must name the page it could not read: %v", err)
	}
}

// The same for a delegate book that cannot be listed.
func TestG1Delegation_AnUnreadableDelegateBookFailsTheRouteByName(t *testing.T) {
	f := newFakeAccounts().book("acc://cust.acme/book", 1).book("acc://bank.acme/book", 1).
		delegates(bankPage, "acc://gone.acme/book-d1")
	got, err := discovery(t, f, custPage, []string{""}, custPage, bankPage)
	if err == nil {
		t.Fatalf("a delegate book that does not exist gave pages %v; the route must be unavailable", got)
	}
	if !strings.Contains(err.Error(), "gone.acme/book-d1") {
		t.Fatalf("the failure must name the book it could not read: %v", err)
	}
}

// The walk's hop bound is the executor's own delegation depth limit; they must not drift apart.
func TestG1Delegation_TheWalkBoundIsTheProtocolsDelegationDepthLimit(t *testing.T) {
	if delegationEnumerationMaxHops != protocol.DelegationDepthLimit {
		t.Fatalf("the enumeration walk allows %d hops, the executor %d delegators", delegationEnumerationMaxHops, protocol.DelegationDepthLimit)
	}
}
