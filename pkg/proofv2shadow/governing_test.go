// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// world is a set of accounts a governing walk reads.
type world map[string]protocol.Account

func (w world) get(_ context.Context, u *url.URL) (protocol.Account, error) {
	a, ok := w[strings.ToLower(u.String())]
	if !ok {
		return nil, fmt.Errorf("%w: %v", ErrAccountMissing, u)
	}
	return a, nil
}

func (w world) add(a protocol.Account) world {
	w[strings.ToLower(a.GetUrl().String())] = a
	return w
}

func authEntries(books ...string) protocol.AccountAuth {
	var a protocol.AccountAuth
	for _, b := range books {
		a.Authorities = append(a.Authorities, protocol.AuthorityEntry{Url: url.MustParse(b)})
	}
	return a
}

// adi adds an identity with a book of n one-key pages and the identity's own authority list.
func (w world) adi(host string, pages int) world {
	w.add(&protocol.ADI{Url: url.MustParse("acc://" + host), AccountAuth: authEntries("acc://" + host + "/book")})
	w.add(&protocol.KeyBook{Url: url.MustParse("acc://" + host + "/book"), PageCount: uint64(pages), AccountAuth: authEntries("acc://" + host + "/book")})
	for i := 1; i <= pages; i++ {
		w.add(&protocol.KeyPage{Url: url.MustParse(fmt.Sprintf("acc://%s/book/%d", host, i)), AcceptThreshold: 1, Version: 1,
			Keys: []*protocol.KeySpec{{PublicKeyHash: make([]byte, 32)}}})
	}
	return w
}

// delegate makes the key entry of host's page 1 delegate to the book of another identity.
func (w world) delegate(host, toHost string) {
	p := w[strings.ToLower("acc://"+host+"/book/1")].(*protocol.KeyPage)
	p.Keys = append(p.Keys, &protocol.KeySpec{Delegate: url.MustParse("acc://" + toHost + "/book")})
}

func data(host, name string, authorities ...string) *protocol.DataAccount {
	return &protocol.DataAccount{Url: url.MustParse("acc://" + host + "/" + name), AccountAuth: authEntries(authorities...)}
}

func has(c *Closure, u string) bool {
	for _, p := range c.Pages {
		if strings.EqualFold(p.URL, u) {
			return true
		}
	}
	return false
}

func rolesOf(t *testing.T, c *Closure, u string) []proofv2.PageRole {
	t.Helper()
	for _, p := range c.Pages {
		if strings.EqualFold(p.URL, u) {
			return p.Roles
		}
	}
	t.Fatalf("%s is not in the governing set %v", u, c.URLs())
	return nil
}

func hasRole(t *testing.T, c *Closure, u string, r proofv2.PageRole) bool {
	for _, x := range rolesOf(t, c, u) {
		if x == r {
			return true
		}
	}
	return false
}

func noteCodes(c *Closure) []string {
	var out []string
	for _, n := range c.Notes {
		out = append(out, n.Code)
	}
	return out
}

func facts(principal string, authorities ...string) *TxFacts {
	f := &TxFacts{Principal: url.MustParse(principal), Type: protocol.TransactionTypeWriteData}
	for _, a := range authorities {
		f.HeaderAuthorities = append(f.HeaderAuthorities, url.MustParse(a))
	}
	return f
}

func vote(authority, origin string, delegators ...string) VoteFact {
	v := VoteFact{Authority: url.MustParse(authority), Origin: url.MustParse(origin)}
	for _, d := range delegators {
		v.Delegators = append(v.Delegators, url.MustParse(d))
	}
	id, _ := url.ParseTxID("acc://" + strings.Repeat("ab", 32) + "@" + strings.TrimPrefix(origin, "acc://"))
	v.Cause = id
	return v
}

// The tcl model: the principal's authority is a key book on another identity (and another partition).
func TestGoverningCapturesForeignAuthorityBook(t *testing.T) {
	w := world{}
	w.adi("cust.acme", 1).adi("bank.acme", 2)
	w.add(data("cust.acme", "pay", "acc://bank.acme/book", "acc://cust.acme/book"))
	got, err := governing(context.Background(), facts("acc://cust.acme/pay"), w.get)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"acc://cust.acme/pay", "acc://bank.acme/book", "acc://bank.acme/book/1", "acc://bank.acme/book/2", "acc://cust.acme/book", "acc://cust.acme/book/1"}
	if !reflect.DeepEqual(got.URLs(), want) {
		t.Fatalf("got %v want %v", got.URLs(), want)
	}
	if !hasRole(t, got, "acc://bank.acme/book", proofv2.RoleAuthorityBook) || !hasRole(t, got, "acc://bank.acme/book/2", proofv2.RoleAuthorityPage) ||
		!hasRole(t, got, "acc://cust.acme/pay", proofv2.RolePrincipalChain) {
		t.Fatalf("roles: %+v", got.Pages)
	}
}

// Delegation follows page entries to books of other identities, to the depth a signature can carry: 1, 2 and 20 delegators
// are captured; a 21st level is named and not captured (the executor refuses a 21-delegator signature, so none executed).
func TestGoverningDelegateDepths(t *testing.T) {
	for _, depth := range []int{1, 2, 20, 21} {
		t.Run(fmt.Sprintf("depth %d", depth), func(t *testing.T) {
			w := world{}
			w.adi("p.acme", 1)
			w.add(data("p.acme", "d", "acc://p.acme/book"))
			// p.acme's page 1 delegates to d1.acme, which delegates to d2.acme ... to d<depth>.acme.
			prev := "p.acme"
			for i := 1; i <= depth; i++ {
				h := fmt.Sprintf("d%d.acme", i)
				w.adi(h, 1)
				w.delegate(prev, h)
				prev = h
			}
			got, err := governing(context.Background(), facts("acc://p.acme/d"), w.get)
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= depth && i <= 20; i++ {
				page := fmt.Sprintf("acc://d%d.acme/book/1", i)
				if !has(got, page) || !hasRole(t, got, page, proofv2.RoleDelegatePage) {
					t.Fatalf("level %d (%s) of %d is not captured: %v", i, page, depth, got.URLs())
				}
			}
			beyond := fmt.Sprintf("acc://d%d.acme/book/1", 21)
			if depth >= 21 {
				if has(got, beyond) {
					t.Fatalf("level 21 was captured: no executed signature can pass through it")
				}
				if !reflect.DeepEqual(noteCodes(got), []string{proofv2.StateDelegationDepthExceeded}) {
					t.Fatalf("level 21 is not named: %v", noteCodes(got))
				}
			} else if len(noteCodes(got)) != 0 {
				t.Fatalf("depth %d was named: %v", depth, noteCodes(got))
			}
		})
	}
}

// The executor has no cycle detection: a cycle of delegations is legal. It is captured once, and the walk ends.
func TestGoverningDelegationCycleAccepted(t *testing.T) {
	w := world{}
	w.adi("a.acme", 1).adi("b.acme", 1).adi("c.acme", 1)
	w.add(data("a.acme", "d", "acc://a.acme/book"))
	w.delegate("a.acme", "b.acme")
	w.delegate("b.acme", "c.acme")
	w.delegate("c.acme", "a.acme") // back to the authority
	w.delegate("c.acme", "c.acme") // and to itself
	got, err := governing(context.Background(), facts("acc://a.acme/d"), w.get)
	if err != nil {
		t.Fatalf("a cycle was refused: %v", err)
	}
	seen := map[string]int{}
	for _, p := range got.Pages {
		seen[strings.ToLower(p.URL)]++
	}
	for _, u := range []string{"acc://a.acme/book/1", "acc://b.acme/book/1", "acc://c.acme/book/1"} {
		if seen[u] != 1 {
			t.Fatalf("%s is captured %d times in %v", u, seen[u], got.URLs())
		}
	}
	if len(noteCodes(got)) != 0 {
		t.Fatalf("a cycle was named: %v", noteCodes(got))
	}
}

// A disabled authority is not required, but its vote still counts, and it may live on another identity: its pages are
// captured whether or not it voted.
func TestGoverningDisabledForeignAuthorityNotRequiredButItsVoteCounts(t *testing.T) {
	w := world{}
	w.adi("cust.acme", 1).adi("bank.acme", 1)
	pay := data("cust.acme", "pay", "acc://bank.acme/book", "acc://cust.acme/book")
	pay.Authorities[0].Disabled = true
	w.add(pay)

	f := facts("acc://cust.acme/pay")
	got, err := governing(context.Background(), f, w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !has(got, "acc://bank.acme/book/1") {
		t.Fatalf("the disabled foreign authority was not captured: %v", got.URLs())
	}
	if len(got.Counted) != 0 {
		t.Fatalf("counted votes %v with none recorded", got.Counted)
	}

	f.Votes = []VoteFact{vote("acc://bank.acme/book", "acc://bank.acme/book/1"), vote("acc://cust.acme/book", "acc://cust.acme/book/1")}
	got, err = governing(context.Background(), f, w.get)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Counted) != 2 {
		t.Fatalf("the disabled authority's vote was not counted: %d counted", len(got.Counted))
	}
	if !hasRole(t, got, "acc://bank.acme/book/1", proofv2.RoleVoter) {
		t.Fatalf("the disabled authority's voting page has no voter role: %+v", got.Pages)
	}
}

// When every listed authority is disabled and the type is not UpdateAccountAuth, any authority's single vote suffices: the
// actual voter - from the principal's recorded votes - is captured, though the list does not name it.
func TestGoverningAllAuthoritiesDisabledCapturesTheActualVoter(t *testing.T) {
	w := world{}
	w.adi("cust.acme", 1).adi("bank.acme", 1).adi("stranger.acme", 2)
	pay := data("cust.acme", "pay", "acc://cust.acme/book")
	pay.Authorities[0].Disabled = true
	w.add(pay)

	f := facts("acc://cust.acme/pay")
	f.Votes = []VoteFact{vote("acc://stranger.acme/book", "acc://stranger.acme/book/2")}
	got, err := governing(context.Background(), f, w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !has(got, "acc://stranger.acme/book/2") || !has(got, "acc://stranger.acme/book/1") {
		t.Fatalf("the actual voter's book was not captured: %v", got.URLs())
	}
	if !hasRole(t, got, "acc://stranger.acme/book/2", proofv2.RoleVoter) || len(got.Counted) != 1 {
		t.Fatalf("the voter is not marked or counted: %+v counted %d", got.Pages, len(got.Counted))
	}
	if !reflect.DeepEqual(noteCodes(got), []string{proofv2.StateAuthorityVoterOutsideList}) {
		t.Fatalf("a voter outside the list is not named: %v", noteCodes(got))
	}
	if has(got, "acc://bank.acme/book") {
		t.Fatalf("an authority nobody named or voted for was captured")
	}

	// With a listed authority enabled the executor refuses an unlisted authority's vote before it reaches the principal's chain
	// (sig_authority.go:127-136), so a recorded one is from before the list changed: its voting page is proven and it is
	// disclosed, but its book is not (no vote of the book is judged).
	pay.Authorities[0].Disabled = false
	got, err = governing(context.Background(), f, w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !has(got, "acc://stranger.acme/book/2") || has(got, "acc://stranger.acme/book/1") || len(got.Counted) != 1 {
		t.Fatalf("an unlisted recorded vote: %v counted %d", got.URLs(), len(got.Counted))
	}
	if !reflect.DeepEqual(noteCodes(got), []string{proofv2.StateAuthorityVoterOutsideList}) {
		t.Fatalf("an unlisted recorded vote is not disclosed: %v", noteCodes(got))
	}

	// UpdateAccountAuth always requires its authorities, so the all-disabled rule does not apply.
	pay.Authorities[0].Disabled = true
	f.Type = protocol.TransactionTypeUpdateAccountAuth
	got, err = governing(context.Background(), f, w.get)
	if err != nil {
		t.Fatal(err)
	}
	if has(got, "acc://stranger.acme/book/1") {
		t.Fatalf("the all-disabled rule applied to UpdateAccountAuth: the voter's whole book was proven")
	}
}

// Header.Authorities (and the authorities the body adds) are required voters and may be on any identity.
func TestGoverningHeaderAuthoritiesForeignRequired(t *testing.T) {
	w := world{}
	w.adi("cust.acme", 1).adi("auditor.acme", 2)
	w.add(data("cust.acme", "pay", "acc://cust.acme/book"))
	got, err := governing(context.Background(), facts("acc://cust.acme/pay", "acc://auditor.acme/book"), w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !has(got, "acc://auditor.acme/book/2") || !hasRole(t, got, "acc://auditor.acme/book/1", proofv2.RoleHeaderAuthority) {
		t.Fatalf("the header authority's pages are not captured with their role: %+v", got.Pages)
	}
	_, err = governing(context.Background(), facts("acc://cust.acme/pay", "acc://ghost.acme/book"), w.get)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateHeaderAuthorityMissing {
		t.Fatalf("a header authority that does not exist gave %v", err)
	}
}

// The harbor-mfg model: the page that initiated and paid for the transaction belongs to an identity that is no authority.
// It is proven as well, because the certified key page is that page.
func TestGoverningInitiatorPageOfAnUnrelatedIdentityIsCaptured(t *testing.T) {
	w := world{}
	w.adi("harbor.acme", 2).adi("risk.acme", 2).adi("erp.acme", 1)
	w.add(data("harbor.acme", "data", "acc://risk.acme/book", "acc://harbor.acme/book"))
	f := facts("acc://harbor.acme/data")
	f.Initiators = []*url.URL{url.MustParse("acc://erp.acme/book/1")}
	got, err := governing(context.Background(), f, w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !has(got, "acc://erp.acme/book/1") || !hasRole(t, got, "acc://erp.acme/book/1", proofv2.RoleInitiatorSigner) {
		t.Fatalf("the initiator's page is not captured: %+v", got.Pages)
	}
	if has(got, "acc://erp.acme/book") {
		t.Fatalf("the initiator's book was captured with its page; only the page is proven")
	}
}

// A recorded delegation path longer than the limit cannot have executed: refused by name.
func TestGoverningRefusesARecordedPathBeyondTheLimit(t *testing.T) {
	w := world{}
	w.adi("cust.acme", 1)
	w.add(data("cust.acme", "pay", "acc://cust.acme/book"))
	f := facts("acc://cust.acme/pay")
	var ds []string
	for i := 0; i < 21; i++ {
		ds = append(ds, fmt.Sprintf("acc://x%d.acme/book/1", i))
	}
	f.Votes = []VoteFact{vote("acc://cust.acme/book", "acc://cust.acme/book/1", ds...)}
	_, err := governing(context.Background(), f, w.get)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateDelegationDepthExceeded {
		t.Fatalf("a 21-delegator path gave %v", err)
	}
	f.Votes[0].Delegators = f.Votes[0].Delegators[:20]
	for _, d := range f.Votes[0].Delegators {
		w.add(&protocol.KeyPage{Url: d})
	}
	if _, err := governing(context.Background(), f, w.get); err != nil {
		t.Fatalf("a 20-delegator path was refused: %v", err)
	}
}

// Lite accounts resolve as the executor resolves them: a lite token account is governed by its root lite identity, which is its
// own authority and its own single signer; a lite token account with a delegate is governed by it alone.
func TestGoverningLiteAccounts(t *testing.T) {
	const lid = "acc://ac1df4c4bb4d2e5d8a1b2c3d4e5f60718293a4b5c6d7e8f9"
	w := world{}
	w.add(&protocol.LiteIdentity{Url: url.MustParse(lid)})
	w.add(&protocol.LiteTokenAccount{Url: url.MustParse(lid + "/ACME"), TokenUrl: protocol.AcmeUrl()})
	w.adi("del.acme", 1)
	w.add(&protocol.LiteTokenAccount{Url: url.MustParse(lid + "/DEL"), TokenUrl: protocol.AcmeUrl(), Delegate: url.MustParse("acc://del.acme/book")})
	got, err := governing(context.Background(), facts(lid+"/ACME"), w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.URLs(), []string{lid + "/ACME", lid}) {
		t.Fatalf("lite token account: %v", got.URLs())
	}
	got, err = governing(context.Background(), facts(lid+"/DEL"), w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.URLs(), []string{lid + "/DEL", "acc://del.acme/book", "acc://del.acme/book/1"}) {
		t.Fatalf("lite token account with a delegate: %v", got.URLs())
	}
}

// The certified key page is proven whatever role it has; the pages of a vote's cause chain and of the initiating signature's
// delegator path are proven too.
func TestGoverningCertifiedKeyPageCauseChainAndInitiatorPath(t *testing.T) {
	w := world{}
	w.adi("harbor.acme", 2).adi("risk.acme", 1).adi("erp.acme", 1).adi("hop.acme", 1).adi("hub.acme", 1)
	w.add(data("harbor.acme", "data", "acc://risk.acme/book", "acc://harbor.acme/book"))
	f := facts("acc://harbor.acme/data")
	f.Certified = url.MustParse("acc://erp.acme/book/1")
	f.Initiators = []*url.URL{url.MustParse("acc://erp.acme/book/1")}
	f.InitiatorPath = []*url.URL{url.MustParse("acc://hub.acme/book/1")}
	v := vote("acc://risk.acme/book", "acc://risk.acme/book/1")
	v.Hops = []Hop{{Page: url.MustParse("acc://risk.acme/book/1"), Block: 7}, {Page: url.MustParse("acc://hop.acme/book/1"), Block: 6}}
	v.Delegators = []*url.URL{url.MustParse("acc://hub.acme/book/1")}
	f.Votes = []VoteFact{v}
	got, err := governing(context.Background(), f, w.get)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRole(t, got, "acc://erp.acme/book/1", proofv2.RoleCertifiedKeyPage) || !hasRole(t, got, "acc://erp.acme/book/1", proofv2.RoleInitiatorSigner) {
		t.Fatalf("the certified page's roles: %v", rolesOf(t, got, "acc://erp.acme/book/1"))
	}
	for _, u := range []string{"acc://hop.acme/book/1", "acc://hub.acme/book/1"} {
		if !hasRole(t, got, u, proofv2.RoleVoter) {
			t.Fatalf("%s from the cause chain is not a voter: %v", u, rolesOf(t, got, u))
		}
	}
	// A certified page that does not exist is a read error, not a silent omission.
	f.Certified = url.MustParse("acc://ghost.acme/book/1")
	if _, err := governing(context.Background(), f, w.get); err == nil {
		t.Fatal("a certified page that does not exist was accepted")
	}
}
