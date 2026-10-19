package main

// Provisioning: a funded Kermit identity whose key books hold one key of each accepted type, and a data account
// governed by each book.
//
// Layout of acc://pv2-sig-<n>.acme (every name below is derived from liveCases, never typed twice):
//
//	/book/1            ed25519 "adi-root"            the ADI's own authority; signs only to create the books and accounts
//	/book-<tag>/1      one key of the case's type    the ONLY authority of /data-<tag>
//	/data-<tag>        data account                  the intent for this type is written here and approved by its key
//	/book-dinner/1     ecdsaSha256 "dinner"          the inner key of the delegated case
//	/book-deleg/1      delegate entry -> /book-dinner the page /data-deleg is governed by; holds no direct key
//	/data-deleg        data account                  governed by /book-deleg only
//
// Everything is signed with Accumulate's own signing code through sigfixture.Sign (the same function that makes the
// shared test vectors), with keys generated here and kept in the gitignored keys/ directory.

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// liveCase is one signature type exercised live.
type liveCase struct {
	Name      string // the Accumulate type name, or "delegated-ecdsaSha256"
	Tag       string // url suffix
	DataTag   string // the data account's suffix when it must differ from Tag (see liveCases)
	Type      protocol.SignatureType
	Delegated bool
}

// liveCases is the R8 accepted set plus the delegated ECDSA-inner case. It is the live twin of govsig.AcceptedKeyTypes;
// TestLiveCasesCoverAcceptedSet fails the day the accepted set grows.
func liveCases() []liveCase {
	var out []liveCase
	for _, t := range []protocol.SignatureType{
		protocol.SignatureTypeLegacyED25519, protocol.SignatureTypeED25519, protocol.SignatureTypeRCD1,
		protocol.SignatureTypeBTC, protocol.SignatureTypeBTCLegacy, protocol.SignatureTypeETH,
		protocol.SignatureTypeRsaSha256, protocol.SignatureTypeEcdsaSha256, protocol.SignatureTypeTypedData,
	} {
		c := liveCase{Name: t.String(), Tag: strings.ToLower(t.String()), Type: t}
		// Accumulate refuses a transaction whose binary body is exactly 32 or 64 bytes ("body is 64 bytes long": it would
		// be indistinguishable from a transaction hash). CreateDataAccount for a 3-letter tag (/data-btc, /data-eth) is exactly 64, so those
		// accounts carry a longer name.
		if len(c.Tag) == 3 { // btc, eth
			c.DataTag = c.Tag + "-intents"
		}
		out = append(out, c)
	}
	out = append(out, liveCase{Name: "delegated-ecdsaSha256", Tag: "deleg", Type: protocol.SignatureTypeEcdsaSha256, Delegated: true})
	return out
}

func (c liveCase) book(adi string) string { return adi + "/book-" + c.Tag }
func (c liveCase) page(adi string) string { return c.book(adi) + "/1" }

// dataAtRoot puts the intent on the ADI's own `/data` account (`-data-root`). CERTEN reads an intent's ADI as its principal with the
// trailing `/data` removed (pkg/intent/discovery.go) and looks the principal up again as `<adi>/data` (outcome backfill), so only an
// intent written to `<adi>/data` binds to the ADI's CertenAccount. The per-type data accounts of the first run (`/data-<tag>`)
// made the ADI "acc://pv2-sig-1.acme/data-<tag>" and every case was refused "account is bound to a different ADI" (RB8-E).
var dataAtRoot bool

func (c liveCase) data(adi string) string {
	if dataAtRoot {
		return adi + "/data"
	}
	if c.DataTag != "" {
		return adi + "/data-" + c.DataTag
	}
	return adi + "/data-" + c.Tag
}
func (c liveCase) keyName() string { return c.Tag }
func innerBook(adi string) string  { return adi + "/book-dinner" }
func innerPage(adi string) string  { return innerBook(adi) + "/1" }
func rootPage(adi string) string   { return adi + "/book/1" }
func (c liveCase) signerPage(adi string) string {
	if c.Delegated {
		return innerPage(adi)
	}
	return c.page(adi)
}
func (c liveCase) delegators(adi string) []string {
	if c.Delegated {
		return []string{c.page(adi)}
	}
	return nil
}

type app struct {
	k     *kermit
	ks    keyStore
	adi   string // acc://pv2-sig-<n>.acme
	lite  sigfixture.Key
	lid   *url.URL
	lta   *url.URL
	nonce uint64
}

func (a *app) ts() uint64 {
	n := uint64(time.Now().UnixMicro())
	if n <= a.nonce {
		n = a.nonce + 1
	}
	a.nonce = n
	return n
}

// signerSpec says who signs and how.
type signerSpec struct {
	key        sigfixture.Key
	signer     string // signer URL (key page, or lite identity)
	version    uint64
	delegators []string
	initiate   bool
}

// envelope signs txn with the given signers (the initiator first, so the initiator is in the transaction hash every other
// signature covers).
func (a *app) envelope(txn *protocol.Transaction, ss ...signerSpec) (*messaging.Envelope, error) {
	var sigs []protocol.Signature
	for _, s := range ss {
		if !s.initiate {
			continue
		}
		sig, err := sigfixture.Sign(s.key, txn, sigfixture.Opts{
			Signer: s.signer, Version: s.version, Timestamp: a.ts(), Delegators: s.delegators, Initiate: true,
		})
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}
	for _, s := range ss {
		if s.initiate {
			continue
		}
		sig, err := sigfixture.Sign(s.key, txn, sigfixture.Opts{
			Signer: s.signer, Version: s.version, Timestamp: a.ts(), Delegators: s.delegators,
		})
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}
	env := new(messaging.Envelope)
	env.Transaction = []*protocol.Transaction{txn}
	env.Signatures = sigs
	return env, nil
}

// run submits env and waits for the executor's verdict; anything but delivered is an error.
func (a *app) run(ctx context.Context, what string, txn *protocol.Transaction, env *messaging.Envelope) error {
	if err := a.k.submit(ctx, env); err != nil {
		return fmt.Errorf("%s: submit: %w", what, err)
	}
	code, msg := a.k.await(ctx, txn.ID(), 3*time.Minute)
	if code != "delivered" {
		return fmt.Errorf("%s: executor said %q %s", what, code, msg)
	}
	fmt.Printf("  %-44s delivered %s\n", what, shortHash(txn.GetHash()))
	return nil
}

func shortHash(b []byte) string { return fmt.Sprintf("%x", b[:6]) }

func (a *app) pageSigner(ctx context.Context, key sigfixture.Key, page string, initiate bool, delegators ...string) (signerSpec, error) {
	kp, err := a.k.page(ctx, page)
	if err != nil {
		return signerSpec{}, err
	}
	if kp == nil {
		return signerSpec{}, fmt.Errorf("key page %s does not exist", page)
	}
	return signerSpec{key: key, signer: page, version: kp.Version, delegators: delegators, initiate: initiate}, nil
}

func (a *app) liteSigner() signerSpec {
	return signerSpec{key: a.lite, signer: a.lid.String(), version: 1, initiate: true}
}

// fundLite makes sure the lite token account holds at least minACME and buys credits for the lite identity.
func (a *app) fundLite(ctx context.Context, minACME int64, liteCredits uint64) error {
	want := new(big.Int).Mul(big.NewInt(minACME), big.NewInt(1e8))
	for i := 0; i < 30; i++ {
		acct, err := a.k.account(ctx, a.lta)
		if err != nil {
			return err
		}
		if lt, ok := acct.(*protocol.LiteTokenAccount); ok && lt.Balance.Cmp(want) >= 0 {
			break
		}
		if i == 29 {
			return fmt.Errorf("faucet did not bring %s to %d ACME", a.lta, minACME)
		}
		if _, err := a.k.c.Faucet(ctx, a.lta, api.FaucetOptions{}); err != nil {
			fmt.Printf("  faucet attempt %d: %v\n", i+1, err)
		}
		time.Sleep(4 * time.Second)
	}
	id, err := a.k.account(ctx, a.lid)
	if err != nil {
		return err
	}
	if li, ok := id.(*protocol.LiteIdentity); ok && li.CreditBalance >= liteCredits {
		return nil
	}
	return a.buyCredits(ctx, a.lid.String(), 20)
}

// buyCredits converts acme ACME from the lite token account into credits for recipient.
func (a *app) buyCredits(ctx context.Context, recipient string, acme int64) error {
	oracle, err := a.k.oracle(ctx)
	if err != nil {
		return err
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = a.lta
	body := &protocol.AddCredits{Recipient: mustURL(recipient), Oracle: oracle}
	body.Amount.Mul(big.NewInt(acme), big.NewInt(1e8))
	txn.Body = body
	env, err := a.envelope(txn, a.liteSigner())
	if err != nil {
		return err
	}
	return a.run(ctx, fmt.Sprintf("add credits (%d ACME) -> %s", acme, shortURL(recipient)), txn, env)
}

func shortURL(s string) string { return strings.TrimPrefix(s, "acc://") }

func pageCredits(ctx context.Context, k *kermit, page string) (uint64, error) {
	kp, err := k.page(ctx, page)
	if err != nil || kp == nil {
		return 0, err
	}
	return kp.CreditBalance, nil
}

// ensureCredits tops a page up (in whole-ACME steps) until it holds at least min credits.
func (a *app) ensureCredits(ctx context.Context, page string, min uint64, acmeStep int64) error {
	for i := 0; i < 10; i++ {
		have, err := pageCredits(ctx, a.k, page)
		if err != nil {
			return err
		}
		if have >= min {
			return nil
		}
		if err := a.buyCredits(ctx, page, acmeStep); err != nil {
			return err
		}
		// the credits arrive by a synthetic transaction on the page's partition, after the purchase is delivered
		for w := 0; w < 20; w++ {
			if now, err := pageCredits(ctx, a.k, page); err != nil {
				return err
			} else if now > have {
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	return fmt.Errorf("%s could not be brought to %d credits", page, min)
}

func (a *app) setup(ctx context.Context, l liveConfig) error {
	sel, err := l.selected()
	if err != nil {
		return err
	}
	needDeleg := false
	for _, c := range sel {
		needDeleg = needDeleg || c.Delegated
	}
	if a.lite, err = a.ks.loadOrCreate("lite", protocol.SignatureTypeED25519); err != nil {
		return err
	}
	litePub, _, err := pubAndHash(a.lite)
	if err != nil {
		return err
	}
	a.lid = protocol.LiteAuthorityForKey(litePub, protocol.SignatureTypeED25519)
	if a.lta, err = protocol.LiteTokenAddress(litePub, "ACME", protocol.SignatureTypeED25519); err != nil {
		return err
	}
	root, err := a.ks.loadOrCreate("adi-root", protocol.SignatureTypeED25519)
	if err != nil {
		return err
	}
	fmt.Printf("lite identity %s\nlite token    %s\n", a.lid, a.lta)
	if err := a.fundLite(ctx, 30, 1000); err != nil {
		return err
	}

	// 1. the ADI, with the root key as the first key of /book/1.
	if acct, err := a.k.account(ctx, mustURL(a.adi)); err != nil {
		return err
	} else if acct == nil {
		_, rootHash, err := pubAndHash(root)
		if err != nil {
			return err
		}
		txn := new(protocol.Transaction)
		txn.Header.Principal = a.lta
		txn.Body = &protocol.CreateIdentity{Url: mustURL(a.adi), KeyBookUrl: mustURL(a.adi + "/book"), KeyHash: rootHash}
		env, err := a.envelope(txn, a.liteSigner())
		if err != nil {
			return err
		}
		if err := a.run(ctx, "create "+shortURL(a.adi), txn, env); err != nil {
			return err
		}
	}
	if err := a.ensureCredits(ctx, rootPage(a.adi), 100_000_000, 5); err != nil {
		return err
	}

	// 2. the inner key of the delegated case, its book, and the delegating book (only when that case is selected).
	var dinner sigfixture.Key
	if needDeleg {
		if dinner, err = a.ks.loadOrCreate("dinner", protocol.SignatureTypeEcdsaSha256); err != nil {
			return err
		}
		if err := a.ensureBook(ctx, root, innerBook(a.adi), dinner); err != nil {
			return err
		}
		deleg, err := a.ks.loadOrCreate("deleg-admin", protocol.SignatureTypeED25519)
		if err != nil {
			return err
		}
		if err := a.ensureBook(ctx, root, liveCases()[len(liveCases())-1].book(a.adi), deleg); err != nil {
			return err
		}
		if err := a.ensureDelegate(ctx, deleg, dinner); err != nil {
			return err
		}
	}

	// 3. a book and a data account per selected type.
	for _, c := range sel {
		var key sigfixture.Key
		if c.Delegated {
			key = dinner
		} else if key, err = a.ks.loadOrCreate(c.keyName(), c.Type); err != nil {
			return err
		}
		if !c.Delegated {
			if err := a.ensureBook(ctx, root, c.book(a.adi), key); err != nil {
				return err
			}
		}
		if err := a.ensureData(ctx, root, c, key); err != nil {
			return err
		}
	}
	return nil
}

// ensureBook creates book (with key as the first key of page 1) unless it exists, and funds its page.
func (a *app) ensureBook(ctx context.Context, root sigfixture.Key, book string, key sigfixture.Key) error {
	acct, err := a.k.account(ctx, mustURL(book))
	if err != nil {
		return err
	}
	if acct == nil {
		_, hash, err := pubAndHash(key)
		if err != nil {
			return err
		}
		txn := new(protocol.Transaction)
		txn.Header.Principal = mustURL(a.adi)
		txn.Body = &protocol.CreateKeyBook{Url: mustURL(book), PublicKeyHash: hash}
		rs, err := a.pageSigner(ctx, root, rootPage(a.adi), true)
		if err != nil {
			return err
		}
		env, err := a.envelope(txn, rs)
		if err != nil {
			return err
		}
		if err := a.run(ctx, "create "+shortURL(book), txn, env); err != nil {
			return err
		}
	}
	return a.ensureCredits(ctx, book+"/1", 10_000_000, 1) // credit balances are in 0.01-credit units; Kermit prices 1 ACME at 10,000,000 of them
}

// ensureDelegate makes /book-deleg/1 a page whose only entry delegates to /book-dinner: add the delegate entry, then remove
// the bootstrap admin key, so no direct key can count for /data-deleg.
func (a *app) ensureDelegate(ctx context.Context, admin, dinner sigfixture.Key) error {
	deleg := liveCases()[len(liveCases())-1]
	page := deleg.page(a.adi)
	kp, err := a.k.page(ctx, page)
	if err != nil || kp == nil {
		return fmt.Errorf("%s: %v", page, err)
	}
	hasDelegate := false
	for _, e := range kp.Keys {
		if e.Delegate != nil && strings.EqualFold(e.Delegate.String(), innerBook(a.adi)) {
			hasDelegate = true
		}
	}
	_, adminHash, err := pubAndHash(admin)
	if err != nil {
		return err
	}
	if !hasDelegate {
		// Adding a delegate entry needs the DELEGATE book to accept it: the transaction stays pending with a signature
		// request on book-dinner until the dinner key signs it too, so both keys sign in one envelope. A transaction an
		// earlier run left pending is completed, not repeated (a repeat has a new initiator and so a new hash).
		dinnerSpec, err := a.pageSigner(ctx, dinner, innerPage(a.adi), false)
		if err != nil {
			return err
		}
		pend, err := a.k.pendingOn(ctx, page)
		if err != nil {
			return err
		}
		var txn *protocol.Transaction
		var env *messaging.Envelope
		for _, id := range pend {
			t, err := a.k.transaction(ctx, id)
			if err != nil {
				return err
			}
			if up, ok := t.Body.(*protocol.UpdateKeyPage); ok && len(up.Operation) == 1 {
				if add, ok := up.Operation[0].(*protocol.AddKeyOperation); ok && add.Entry.Delegate != nil &&
					strings.EqualFold(add.Entry.Delegate.String(), innerBook(a.adi)) {
					txn = t
					break
				}
			}
		}
		if txn != nil {
			if env, err = a.envelope(txn, dinnerSpec); err != nil {
				return err
			}
		} else {
			txn = new(protocol.Transaction)
			txn.Header.Principal = mustURL(page)
			txn.Body = &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
				&protocol.AddKeyOperation{Entry: protocol.KeySpecParams{Delegate: mustURL(innerBook(a.adi))}},
			}}
			s, err := a.pageSigner(ctx, admin, page, true)
			if err != nil {
				return err
			}
			if env, err = a.envelope(txn, s, dinnerSpec); err != nil {
				return err
			}
		}
		if err := a.run(ctx, "delegate "+shortURL(page)+" -> book-dinner", txn, env); err != nil {
			return err
		}
	}
	kp, err = a.k.page(ctx, page)
	if err != nil {
		return err
	}
	for _, e := range kp.Keys {
		if string(e.PublicKeyHash) == string(adminHash) {
			txn := new(protocol.Transaction)
			txn.Header.Principal = mustURL(page)
			txn.Body = &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
				&protocol.RemoveKeyOperation{Entry: protocol.KeySpecParams{KeyHash: adminHash}},
			}}
			s, err := a.pageSigner(ctx, admin, page, true)
			if err != nil {
				return err
			}
			env, err := a.envelope(txn, s)
			if err != nil {
				return err
			}
			return a.run(ctx, "remove bootstrap key from "+shortURL(page), txn, env)
		}
	}
	return nil
}

// ensureData creates /data-<tag> governed by the case's book only. Each listed authority must sign the creation, so the
// case's own signer (the delegated chain for the delegated case) signs beside the ADI root.
func (a *app) ensureData(ctx context.Context, root sigfixture.Key, c liveCase, signKey sigfixture.Key) error {
	acct, err := a.k.account(ctx, mustURL(c.data(a.adi)))
	if err != nil {
		return err
	}
	if acct != nil {
		return nil
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(a.adi)
	txn.Body = &protocol.CreateDataAccount{Url: mustURL(c.data(a.adi)), Authorities: []*url.URL{mustURL(c.book(a.adi))}}
	if err := createDataBodyLength(c, a.adi); err != nil {
		return err
	}
	rs, err := a.pageSigner(ctx, root, rootPage(a.adi), true)
	if err != nil {
		return err
	}
	cs, err := a.pageSigner(ctx, signKey, c.signerPage(a.adi), false, c.delegators(a.adi)...)
	if err != nil {
		return err
	}
	env, err := a.envelope(txn, rs, cs)
	if err != nil {
		return err
	}
	return a.run(ctx, "create "+shortURL(c.data(a.adi)), txn, env)
}

// createDataBodyLength refuses a data-account creation Accumulate would refuse ("body is 64 bytes long": a 32- or 64-byte
// body is indistinguishable from a transaction hash). The length follows the two URLs, so another identity number or tag
// length changes it; the error names the case so the run fails before anything is written.
func createDataBodyLength(c liveCase, adi string) error {
	b, err := (&protocol.CreateDataAccount{Url: mustURL(c.data(adi)), Authorities: []*url.URL{mustURL(c.book(adi))}}).MarshalBinary()
	if err != nil {
		return err
	}
	if len(b) == 32 || len(b) == 64 {
		return fmt.Errorf("%s: creating %s with authority %s is a %d-byte body, which Accumulate refuses; use another identity number (-n)",
			c.Name, c.data(adi), c.book(adi), len(b))
	}
	return nil
}
