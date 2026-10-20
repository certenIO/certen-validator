package main

// The RB9-E scenario engine: identities, books, delegation chains, data accounts and the intents that go through them.
//
// Every name is derived from the scenario numbers, never typed twice:
//
//	acc://pv2-cust-<n>.acme   the principal's identity; its data account /data is the intent's principal
//	acc://pv2-bank-<n>.acme   the identity of the authority book that is not the customer's (the tcl "bank compliance book")
//	acc://pv2-deleg-<h>.acme  the identities that host the books of a delegation chain (one per number in -hosts)
//
// Each identity has the ONE key `adi-root` (ed25519) as the first key of /book/1; books made for the chain use the host's key too.
// Keys are generated locally and kept in the gitignored keys/<identity>/. The funding lite identity of a scenario is
// keys/pv2-g1-<kind>-<n>/lite. No owner, admin or production key is used.
//
// The topology follows the tcl model (transaction-controls ADR 0004): the customer's /data lists the customer's own book AND the
// foreign authority book; every intent needs both. The customer's own book is the one the CertenAccount on the target chain
// governs (a canonical book of the intent's identity, which the factory requires), so a settlement leg is possible after the
// cross-partition activation; a "bankonly" scenario lists the foreign book alone and cannot settle (no account can be governed by
// a book of another identity), it exists for the refusal evidence.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// g1Topo is the shape of one scenario, derived from its parameters alone.
type g1Topo struct {
	Kind    string   // same | cross | after | bankonly | deleg | cycle | header | disabled | disabled-voted | alldisabled | thresh2 | page2
	N       int      // number of pv2-cust-<n> and pv2-bank-<n>
	Hosts   []int    // numbers of the pv2-deleg-<h> identities hosting the delegation chain
	Depth   int      // delegators between the bank book's page and the key (deleg kinds); the chain has Depth books
	WantCst string   // the partition the customer identity must be routed to ("" = not asserted)
	WantBnk string   // likewise the bank identity
	WantDel []string // likewise each host, in order of Hosts
}

func (t g1Topo) cust() string { return fmt.Sprintf("pv2-cust-%d", t.N) }
func (t g1Topo) bank() string { return fmt.Sprintf("pv2-bank-%d", t.N) }
func (t g1Topo) host(i int) string {
	return fmt.Sprintf("pv2-deleg-%d", t.Hosts[i%len(t.Hosts)])
}
func adiURL(name string) string { return "acc://" + name + ".acme" }

// hopBook is the book of hop i (1-based) of the chain, hosted by host (i-1) mod len(Hosts).
func (t g1Topo) hopBook(i int) string {
	return fmt.Sprintf("%s/book-d%d", adiURL(t.host(i-1)), i)
}

func (t g1Topo) usesBank() bool { return t.Kind != "same" }
func (t g1Topo) delegated() bool {
	return t.Kind == "deleg" || t.Kind == "cycle"
}

// g1Env holds the connection, the keys directory and the funding lite identity.
type g1Env struct {
	k      *kermit
	keys   string
	funder *app
	adis   map[string]*g1ADI
	ops    []g1Op // the account-level transactions this run executed, in order (authop scenario)
}

// g1Op is a transaction a scenario executed that is not an intent: the thing to capture for the transaction types the verifier models.
type g1Op struct {
	What      string `json:"what"`
	Principal string `json:"principal"`
	TxHash    string `json:"txHash"`
	Book      string `json:"declaredBook"`
	Page      string `json:"declaredPage"`
	At        string `json:"at"`
}

type g1ADI struct {
	app  *app
	root sigfixture.Key
	name string
	url  string
}

func newG1Env(ctx context.Context, k *kermit, keys, label string) (*g1Env, error) {
	f := &app{k: k, ks: keyStore{dir: filepath.Join(keys, "pv2-g1-"+label)}}
	var err error
	if f.lite, err = f.ks.loadOrCreate("lite", protocol.SignatureTypeED25519); err != nil {
		return nil, err
	}
	pub, _, err := pubAndHash(f.lite)
	if err != nil {
		return nil, err
	}
	f.lid = protocol.LiteAuthorityForKey(pub, protocol.SignatureTypeED25519)
	if f.lta, err = protocol.LiteTokenAddress(pub, "ACME", protocol.SignatureTypeED25519); err != nil {
		return nil, err
	}
	fmt.Printf("funder lite identity %s\nfunder lite token    %s\n", f.lid, f.lta)
	if err := f.fundLite(ctx, 30, 1000); err != nil {
		return nil, err
	}
	return &g1Env{k: k, keys: keys, funder: f, adis: map[string]*g1ADI{}}, nil
}

// adi returns the identity name, creating it (root key as the first key of /book/1) and funding its root page when it does not exist.
func (e *g1Env) adi(ctx context.Context, name string) (*g1ADI, error) {
	if x, ok := e.adis[name]; ok {
		return x, nil
	}
	u := adiURL(name)
	a := &app{k: e.k, ks: keyStore{dir: filepath.Join(e.keys, name)}, adi: u, lite: e.funder.lite, lid: e.funder.lid, lta: e.funder.lta}
	root, err := a.ks.loadOrCreate("adi-root", protocol.SignatureTypeED25519)
	if err != nil {
		return nil, err
	}
	acct, err := e.k.account(ctx, mustURL(u))
	if err != nil {
		return nil, err
	}
	if acct == nil {
		if err := e.funder.fundLite(ctx, 30, 5000); err != nil {
			return nil, err
		}
		_, hash, err := pubAndHash(root)
		if err != nil {
			return nil, err
		}
		txn := new(protocol.Transaction)
		txn.Header.Principal = e.funder.lta
		txn.Body = &protocol.CreateIdentity{Url: mustURL(u), KeyBookUrl: mustURL(u + "/book"), KeyHash: hash}
		env, err := e.funder.envelope(txn, e.funder.liteSigner())
		if err != nil {
			return nil, err
		}
		if err := e.funder.run(ctx, "create "+shortURL(u), txn, env); err != nil {
			return nil, err
		}
	}
	if err := e.funder.ensureCredits(ctx, u+"/book/1", 20_000_000, 5); err != nil {
		return nil, err
	}
	x := &g1ADI{app: a, root: root, name: name, url: u}
	e.adis[name] = x
	return x, nil
}

// placement reads the routing table (both sources, which must be one table) and returns the partition of each identity.
func (e *g1Env) placement(ctx context.Context, names ...string) (map[string]string, error) {
	t, err := e.k.liveRoutingTable(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, n := range names {
		out[n] = routeOf(t, adiURL(n))
	}
	return out, nil
}

// requirePlacement refuses a scenario whose identities are not where it needs them, before anything is written.
func (e *g1Env) requirePlacement(ctx context.Context, t g1Topo) (map[string]string, error) {
	names := []string{t.cust()}
	if t.usesBank() {
		names = append(names, t.bank())
	}
	for i := range t.Hosts {
		names = append(names, fmt.Sprintf("pv2-deleg-%d", t.Hosts[i]))
	}
	pl, err := e.placement(ctx, names...)
	if err != nil {
		return nil, err
	}
	check := func(name, want string) error {
		if want != "" && !strings.EqualFold(pl[name], want) {
			return fmt.Errorf("%s is routed to %s, the scenario needs %s: choose another number", name, pl[name], want)
		}
		return nil
	}
	if err := check(t.cust(), t.WantCst); err != nil {
		return nil, err
	}
	if t.usesBank() {
		if err := check(t.bank(), t.WantBnk); err != nil {
			return nil, err
		}
	}
	for i, w := range t.WantDel {
		if i < len(t.Hosts) {
			if err := check(fmt.Sprintf("pv2-deleg-%d", t.Hosts[i]), w); err != nil {
				return nil, err
			}
		}
	}
	return pl, nil
}

// hasEntry says whether page already holds an entry delegating to book.
func hasDelegateEntry(kp *protocol.KeyPage, book string) bool {
	for _, e := range kp.Keys {
		if e.Delegate != nil && strings.EqualFold(e.Delegate.String(), book) {
			return true
		}
	}
	return false
}

// delegate makes page (in the identity owning) hold an entry delegating to book (in the identity hosting). Accumulate holds the
// transaction until the DELEGATE book accepts it, so the hosting identity's key signs in the same envelope; a transaction an
// earlier run left pending is completed, not repeated.
func (e *g1Env) delegate(ctx context.Context, owning *g1ADI, page string, hosting *g1ADI, book string) error {
	kp, err := e.k.page(ctx, page)
	if err != nil || kp == nil {
		return fmt.Errorf("%s: %v", page, err)
	}
	if hasDelegateEntry(kp, book) {
		return nil
	}
	accept, err := hosting.app.pageSigner(ctx, hosting.root, book+"/1", false)
	if err != nil {
		return err
	}
	pend, err := e.k.pendingOn(ctx, page)
	if err != nil {
		return err
	}
	var txn *protocol.Transaction
	var env *messaging.Envelope
	for _, id := range pend {
		t, err := e.k.transaction(ctx, id)
		if err != nil {
			return err
		}
		if up, ok := t.Body.(*protocol.UpdateKeyPage); ok && len(up.Operation) == 1 {
			if add, ok := up.Operation[0].(*protocol.AddKeyOperation); ok && add.Entry.Delegate != nil &&
				strings.EqualFold(add.Entry.Delegate.String(), book) {
				txn = t
				break
			}
		}
	}
	if txn != nil {
		env, err = owning.app.envelope(txn, accept)
	} else {
		txn = new(protocol.Transaction)
		txn.Header.Principal = mustURL(page)
		txn.Body = &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
			&protocol.AddKeyOperation{Entry: protocol.KeySpecParams{Delegate: mustURL(book)}},
		}}
		admin, err2 := owning.app.pageSigner(ctx, owning.root, page, true)
		if err2 != nil {
			return err2
		}
		env, err = owning.app.envelope(txn, admin, accept)
	}
	if err != nil {
		return err
	}
	return owning.app.run(ctx, "delegate "+shortURL(page)+" -> "+shortURL(book), txn, env)
}

// dropRoot removes the identity's root key from page, so only the page's other entries (the delegates) can count.
func (e *g1Env) dropRoot(ctx context.Context, owning *g1ADI, page string) error {
	kp, err := e.k.page(ctx, page)
	if err != nil || kp == nil {
		return fmt.Errorf("%s: %v", page, err)
	}
	_, h, err := pubAndHash(owning.root)
	if err != nil {
		return err
	}
	for _, en := range kp.Keys {
		if string(en.PublicKeyHash) == string(h) {
			txn := new(protocol.Transaction)
			txn.Header.Principal = mustURL(page)
			txn.Body = &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
				&protocol.RemoveKeyOperation{Entry: protocol.KeySpecParams{KeyHash: h}},
			}}
			s, err := owning.app.pageSigner(ctx, owning.root, page, true)
			if err != nil {
				return err
			}
			env, err := owning.app.envelope(txn, s)
			if err != nil {
				return err
			}
			return owning.app.run(ctx, "remove root key from "+shortURL(page), txn, env)
		}
	}
	return nil
}

// createData makes cust/data with the listed authorities. Every authority of the new account approves its creation, so each
// foreign authority's identity signs beside the customer's root.
func (e *g1Env) createData(ctx context.Context, cust *g1ADI, auths []string, cosigners ...*g1ADI) error {
	data := cust.url + "/data"
	acct, err := e.k.account(ctx, mustURL(data))
	if err != nil {
		return err
	}
	if acct != nil {
		return nil
	}
	var us []*url.URL
	for _, a := range auths {
		us = append(us, mustURL(a))
	}
	body := &protocol.CreateDataAccount{Url: mustURL(data), Authorities: us}
	if b, err := body.MarshalBinary(); err != nil {
		return err
	} else if len(b) == 32 || len(b) == 64 {
		return fmt.Errorf("creating %s is a %d-byte body, which Accumulate refuses; use another number", data, len(b))
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(cust.url)
	txn.Body = body
	rs, err := cust.app.pageSigner(ctx, cust.root, cust.url+"/book/1", true)
	if err != nil {
		return err
	}
	specs := []signerSpec{rs}
	for _, c := range cosigners {
		s, err := c.app.pageSigner(ctx, c.root, c.url+"/book/1", false)
		if err != nil {
			return err
		}
		specs = append(specs, s)
	}
	env, err := cust.app.envelope(txn, specs...)
	if err != nil {
		return err
	}
	if err := cust.app.run(ctx, "create "+shortURL(data), txn, env); err != nil {
		return err
	}
	e.ops = append(e.ops, g1Op{What: "CreateDataAccount", Principal: cust.url, TxHash: hex.EncodeToString(txn.GetHash()),
		Book: cust.url + "/book", Page: cust.url + "/book/1", At: time.Now().UTC().Format(time.RFC3339)})
	return nil
}

// g1Sig is one signature of the intent's envelope.
type g1Sig struct {
	ADI        *g1ADI
	Page       string   // the key page that signs (the innermost page of a delegated chain)
	Delegators []string // outermost first
	Initiate   bool
	Key        *sigfixture.Key // the key that signs, when it is not the identity's root key
}

// g1Plan is the intent a scenario writes and what is known about it by design.
type g1Plan struct {
	Principal  string
	Book, Page string // what the intent declares (the certified key page)
	Sigs       []g1Sig
	Header     []string // Header.Authorities
	AfterKey   *g1ADI   // when set, the intent is followed by a new key added to this identity's /book/1 (the page the vote came from)
	Cust       *g1ADI
	Placement  map[string]string
	Notes      []string
}

// setup creates the scenario's identities, books, delegation chain and data account (idempotent) and returns the plan.
func (e *g1Env) setup(ctx context.Context, t g1Topo) (*g1Plan, error) {
	pl, err := e.requirePlacement(ctx, t)
	if err != nil {
		return nil, err
	}
	cust, err := e.adi(ctx, t.cust())
	if err != nil {
		return nil, err
	}
	var bank *g1ADI
	if t.usesBank() {
		if bank, err = e.adi(ctx, t.bank()); err != nil {
			return nil, err
		}
	}
	plan := &g1Plan{Principal: cust.url + "/data", Cust: cust, Placement: pl,
		Book: cust.url + "/book", Page: cust.url + "/book/1"}

	switch t.Kind {
	case "same":
		if err := e.createData(ctx, cust, []string{cust.url + "/book"}); err != nil {
			return nil, err
		}
		plan.Sigs = []g1Sig{{ADI: cust, Page: cust.url + "/book/1", Initiate: true}}
	case "cross", "after":
		if err := e.createData(ctx, cust, []string{cust.url + "/book", bank.url + "/book"}, bank); err != nil {
			return nil, err
		}
		plan.Sigs = []g1Sig{{ADI: cust, Page: cust.url + "/book/1", Initiate: true}, {ADI: bank, Page: bank.url + "/book/1"}}
		if t.Kind == "after" {
			// the foreign page is changed right after the vote arrived: the timeline must judge the signature against the page as it
			// stood when it arrived, not against the page as it is when the evidence is captured
			plan.AfterKey = bank
			plan.Notes = append(plan.Notes, "a key is added to the foreign voting page right after the intent is delivered")
		}
	case "bankonly":
		// the foreign book is the account's only authority and the page the intent declares; no CertenAccount can be governed by a book
		// of another identity, so this intent cannot settle - it is the harbor-mfg shape (a certified page that is not the principal's).
		if err := e.createData(ctx, cust, []string{bank.url + "/book"}, bank); err != nil {
			return nil, err
		}
		plan.Book, plan.Page = bank.url+"/book", bank.url+"/book/1"
		plan.Sigs = []g1Sig{{ADI: bank, Page: bank.url + "/book/1", Initiate: true}}
		plan.Notes = append(plan.Notes, "bankonly: the declared key page is the foreign book's; no CertenAccount is governed by it, so it cannot settle")
	case "authop":
		// no intent: the account-level transactions themselves (create the data account with the foreign authority, disable it, enable it)
		// are the transactions to capture; each is voted by the customer's book and the bank's.
		if err := e.createData(ctx, cust, []string{cust.url + "/book", bank.url + "/book"}, bank); err != nil {
			return nil, err
		}
		if err := e.setDisabled(ctx, cust, bank, bank.url+"/book", true); err != nil {
			return nil, err
		}
		if err := e.setDisabled(ctx, cust, bank, bank.url+"/book", false); err != nil {
			return nil, err
		}
	case "header":
		// the tcl per-payment layer: the foreign book is not an authority of the account but is named in the transaction header, so
		// Accumulate holds the transaction until it approves.
		if err := e.createData(ctx, cust, []string{cust.url + "/book"}); err != nil {
			return nil, err
		}
		plan.Header = []string{bank.url + "/book"}
		plan.Sigs = []g1Sig{{ADI: cust, Page: cust.url + "/book/1", Initiate: true}, {ADI: bank, Page: bank.url + "/book/1"}}
		plan.Notes = append(plan.Notes, "header: the foreign book is a Header.Authorities entry, not an authority of the account")
	case "disabled", "disabled-voted", "alldisabled":
		if err := e.createData(ctx, cust, []string{cust.url + "/book", bank.url + "/book"}, bank); err != nil {
			return nil, err
		}
		if err := e.setDisabled(ctx, cust, bank, bank.url+"/book", true); err != nil {
			return nil, err
		}
		plan.Sigs = []g1Sig{{ADI: cust, Page: cust.url + "/book/1", Initiate: true}}
		plan.Notes = append(plan.Notes, "the foreign book is a DISABLED authority of the account")
		switch t.Kind {
		case "disabled-voted":
			plan.Sigs = append(plan.Sigs, g1Sig{ADI: bank, Page: bank.url + "/book/1"})
			plan.Notes = append(plan.Notes, "the disabled authority votes anyway")
		case "alldisabled":
			if err := e.setDisabled(ctx, cust, bank, cust.url+"/book", true); err != nil {
				return nil, err
			}
			plan.Notes = append(plan.Notes, "every authority of the account is disabled: any authority's vote is accepted (the customer's book votes)")
		}
	case "thresh2":
		// the customer's page needs two of its two keys: two signatures from one page are counted for the same transaction
		k2, err := cust.app.ks.loadOrCreate("key2", protocol.SignatureTypeED25519)
		if err != nil {
			return nil, err
		}
		// the data account is created first: once the page needs two signatures, so does everything the customer initiates
		if err := e.createData(ctx, cust, []string{cust.url + "/book", bank.url + "/book"}, bank); err != nil {
			return nil, err
		}
		if err := e.twoKeys(ctx, cust, cust.url+"/book/1", k2); err != nil {
			return nil, err
		}
		plan.Sigs = []g1Sig{
			{ADI: cust, Page: cust.url + "/book/1", Initiate: true},
			{ADI: cust, Page: cust.url + "/book/1", Key: &k2},
			{ADI: bank, Page: bank.url + "/book/1"},
		}
		plan.Notes = append(plan.Notes, "the customer's page has threshold 2 with two keys that both sign")
	case "page2":
		// the foreign book has two pages and its vote comes from the second one
		k2, err := bank.app.ks.loadOrCreate("key2", protocol.SignatureTypeED25519)
		if err != nil {
			return nil, err
		}
		if err := e.secondPage(ctx, bank, bank.url+"/book", k2); err != nil {
			return nil, err
		}
		if err := e.createData(ctx, cust, []string{cust.url + "/book", bank.url + "/book"}, bank); err != nil {
			return nil, err
		}
		plan.Sigs = []g1Sig{{ADI: cust, Page: cust.url + "/book/1", Initiate: true}, {ADI: bank, Page: bank.url + "/book/2", Key: &k2}}
		plan.Notes = append(plan.Notes, "the foreign book has two pages and the second one's key votes")
	case "deleg", "cycle":
		if t.Kind == "cycle" {
			t.Depth = 1
		}
		if t.Depth < 1 || len(t.Hosts) < 1 {
			return nil, fmt.Errorf("deleg needs -depth >= 1 and at least one host")
		}
		hosts := map[string]*g1ADI{}
		for i := range t.Hosts {
			h, err := e.adi(ctx, fmt.Sprintf("pv2-deleg-%d", t.Hosts[i]))
			if err != nil {
				return nil, err
			}
			hosts[h.name] = h
		}
		hostOf := func(i int) *g1ADI { return hosts[t.host(i-1)] }
		for i := 1; i <= t.Depth; i++ {
			if err := e.ensureHopBook(ctx, hostOf(i), t.hopBook(i)); err != nil {
				return nil, err
			}
		}
		// the edges, outermost first: bank/book/1 -> hop 1, hop i /1 -> hop i+1; every edge needs the admin keys still in place
		if err := e.delegate(ctx, bank, bank.url+"/book/1", hostOf(1), t.hopBook(1)); err != nil {
			return nil, err
		}
		for i := 1; i < t.Depth; i++ {
			if err := e.delegate(ctx, hostOf(i), t.hopBook(i)+"/1", hostOf(i+1), t.hopBook(i+1)); err != nil {
				return nil, err
			}
		}
		if t.Kind == "cycle" {
			// the delegate's page also delegates straight back to the bank book: Accumulate has no cycle detection, and a cycle between books
			// is legal as long as the signing path itself is not (the key signs for hop 1, which signs for the bank page once).
			if err := e.delegate(ctx, hostOf(1), t.hopBook(1)+"/1", bank, bank.url+"/book"); err != nil {
				return nil, err
			}
			plan.Notes = append(plan.Notes, "the delegate page also delegates back to the bank book (a cycle between the books)")
		}
		if err := e.createData(ctx, cust, []string{cust.url + "/book", bank.url + "/book"}, bank); err != nil {
			return nil, err
		}
		// only now are the admin keys of the delegating pages removed, so the bank's vote can only come through the chain
		if err := e.dropRoot(ctx, bank, bank.url+"/book/1"); err != nil {
			return nil, err
		}
		for i := 1; i < t.Depth; i++ {
			if err := e.dropRoot(ctx, hostOf(i), t.hopBook(i)+"/1"); err != nil {
				return nil, err
			}
		}
		delegators := []string{bank.url + "/book/1"}
		for i := 1; i < t.Depth; i++ {
			delegators = append(delegators, t.hopBook(i)+"/1")
		}
		plan.Sigs = []g1Sig{
			{ADI: cust, Page: cust.url + "/book/1", Initiate: true},
			{ADI: hostOf(t.Depth), Page: t.hopBook(t.Depth) + "/1", Delegators: delegators},
		}
		plan.Notes = append(plan.Notes, fmt.Sprintf("the bank's vote is a delegated signature through %d delegator page(s): %s", len(delegators), strings.Join(delegators, " > ")))
	default:
		return nil, fmt.Errorf("unknown scenario kind %q", t.Kind)
	}
	return plan, nil
}

// g1Capture is what one submitted intent leaves in <out>/<kind>-<n>/capture.json.
type g1Capture struct {
	Kind        string            `json:"kind"`
	N           int               `json:"n"`
	Principal   string            `json:"principal"`
	DeclaredBk  string            `json:"declaredBook"`
	DeclaredPg  string            `json:"declaredPage"`
	Signers     []string          `json:"signers"`
	Delegators  []string          `json:"delegators,omitempty"`
	Header      []string          `json:"headerAuthorities,omitempty"`
	Placement   map[string]string `json:"placement"`
	Account     string            `json:"certenAccount"`
	IntentID    string            `json:"intentId"`
	OperationID string            `json:"operationId"`
	TxHash      string            `json:"txHash"`
	TxID        string            `json:"txId"`
	Status      string            `json:"status"`
	Error       string            `json:"error,omitempty"`
	SubmittedAt string            `json:"submittedAt"`
	DeliveredAt string            `json:"deliveredAt,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
}

// submit writes the plan's intent and waits for the network to deliver it.
func (e *g1Env) submit(ctx context.Context, t g1Topo, plan *g1Plan, from string, leg legChain, wait time.Duration, out string) (*g1Capture, error) {
	blobs, err := buildIntentSpec(intentSpec{
		ADI: plan.Cust.url, By: "g1-" + t.Kind, Book: plan.Book, Page: plan.Page, From: from, Leg: leg,
		Desc: fmt.Sprintf("RB9-E live G1 case %s-%d: %s", t.Kind, t.N, strings.Join(plan.Notes, "; ")),
		Tags: []string{"rb9-e", "g1", t.Kind},
	})
	if err != nil {
		return nil, err
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(plan.Principal)
	txn.Header.Memo = "CERTEN_INTENT"
	for _, h := range plan.Header {
		txn.Header.Authorities = append(txn.Header.Authorities, mustURL(h))
	}
	txn.Body = &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{
		blobs.Blobs[0], blobs.Blobs[1], blobs.Blobs[2], blobs.Blobs[3],
	}}}
	var specs []signerSpec
	var signers, delegs []string
	for _, s := range plan.Sigs {
		key := s.ADI.root
		if s.Key != nil {
			key = *s.Key
		}
		sp, err := s.ADI.app.pageSigner(ctx, key, s.Page, s.Initiate, s.Delegators...)
		if err != nil {
			return nil, err
		}
		specs = append(specs, sp)
		signers = append(signers, s.Page)
		delegs = append(delegs, s.Delegators...)
	}
	env, err := plan.Cust.app.envelope(txn, specs...)
	if err != nil {
		return nil, err
	}
	cp := &g1Capture{
		Kind: t.Kind, N: t.N, Principal: plan.Principal, DeclaredBk: plan.Book, DeclaredPg: plan.Page, Signers: signers, Delegators: delegs,
		Header: plan.Header, Placement: plan.Placement, Account: from, IntentID: blobs.IntentID, OperationID: blobs.OperationID,
		TxHash: hex.EncodeToString(txn.GetHash()), TxID: txn.ID().String(), SubmittedAt: time.Now().UTC().Format(time.RFC3339),
		Notes: plan.Notes,
	}
	fmt.Printf("%s-%d: submit %s intent %s ...\n", t.Kind, t.N, cp.TxHash[:12], cp.IntentID)
	if err := e.k.submit(ctx, env); err != nil {
		cp.Status, cp.Error = "submission_refused", err.Error()
	} else {
		cp.Status, cp.Error = e.k.await(ctx, txn.ID(), wait)
		if cp.Status == "delivered" {
			cp.DeliveredAt = time.Now().UTC().Format(time.RFC3339)
			if plan.AfterKey != nil {
				if err := e.addKeyAfter(ctx, plan.AfterKey, plan.AfterKey.url+"/book/1"); err != nil {
					cp.Error = "the page change after the intent failed: " + err.Error()
				} else {
					cp.Notes = append(cp.Notes, "page "+plan.AfterKey.url+"/book/1"+" changed at "+time.Now().UTC().Format(time.RFC3339))
				}
			}
		}
	}
	dir := filepath.Join(out, fmt.Sprintf("%s-%d", t.Kind, t.N))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return cp, err
	}
	b, _ := json.MarshalIndent(cp, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "capture.json"), append(b, '\n'), 0o644); err != nil {
		return cp, err
	}
	fmt.Printf("%s-%d: %s tx %s intent %s op %s\n", t.Kind, t.N, cp.Status, cp.TxHash, cp.IntentID, cp.OperationID)
	return cp, nil
}

func sortedKeys(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func bigFromDec(s string) (*big.Int, bool) { return new(big.Int).SetString(s, 10) }

// ensureHopBook creates the book of a delegation hop (the host's root key as the first key of its page 1) and funds the page, once: a
// book that exists with credits is left as it is, so a re-run does not buy credits again (ensureBook tops up to its full amount).
func (e *g1Env) ensureHopBook(ctx context.Context, host *g1ADI, book string) error {
	kp, err := e.k.page(ctx, book+"/1")
	if err != nil {
		return err
	}
	if kp != nil && kp.CreditBalance >= 1_000_000 {
		return nil
	}
	return host.app.ensureBook(ctx, host.root, book, host.root)
}
