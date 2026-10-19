package main

// The account- and page-level operations the RB9-E scenarios need beyond the delegation chain: enabling and disabling an authority
// of the data account, a second key with threshold 2, a second page of a book.

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govsig/sigfixture"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// authEntry reads the account's authority entry for book (nil when it is not an authority).
func (e *g1Env) authEntry(ctx context.Context, account, book string) (*protocol.AuthorityEntry, error) {
	acct, err := e.k.account(ctx, mustURL(account))
	if err != nil || acct == nil {
		return nil, fmt.Errorf("%s: %v", account, err)
	}
	fa, ok := acct.(protocol.FullAccount)
	if !ok {
		return nil, fmt.Errorf("%s (%T) has no authority set", account, acct)
	}
	for i := range fa.GetAuth().Authorities {
		en := &fa.GetAuth().Authorities[i]
		if en.Url != nil && strings.EqualFold(en.Url.String(), book) {
			return en, nil
		}
	}
	return nil, nil
}

// setDisabled disables (or enables) book as an authority of cust/data. UpdateAccountAuth requires every listed authority, the
// disabled ones too, so the customer and the bank both sign.
func (e *g1Env) setDisabled(ctx context.Context, cust, bank *g1ADI, book string, disable bool) error {
	data := cust.url + "/data"
	en, err := e.authEntry(ctx, data, book)
	if err != nil {
		return err
	}
	if en == nil {
		return fmt.Errorf("%s is not an authority of %s", book, data)
	}
	if en.Disabled == disable {
		return nil
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(data)
	var op protocol.AccountAuthOperation = &protocol.EnableAccountAuthOperation{Authority: mustURL(book)}
	what := "enable"
	if disable {
		op = &protocol.DisableAccountAuthOperation{Authority: mustURL(book)}
		what = "disable"
	}
	txn.Body = &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{op}}
	cs, err := cust.app.pageSigner(ctx, cust.root, cust.url+"/book/1", true)
	if err != nil {
		return err
	}
	bs, err := bank.app.pageSigner(ctx, bank.root, bank.url+"/book/1", false)
	if err != nil {
		return err
	}
	env, err := cust.app.envelope(txn, cs, bs)
	if err != nil {
		return err
	}
	if err := cust.app.run(ctx, what+" "+shortURL(book)+" on "+shortURL(data), txn, env); err != nil {
		return err
	}
	e.ops = append(e.ops, g1Op{What: "UpdateAccountAuth/" + what, Principal: data, TxHash: hex.EncodeToString(txn.GetHash()),
		Book: cust.url + "/book", Page: cust.url + "/book/1", At: time.Now().UTC().Format(time.RFC3339)})
	return nil
}

// twoKeys gives page a second key and threshold 2 (one transaction, signed by the page's own root key).
func (e *g1Env) twoKeys(ctx context.Context, owner *g1ADI, page string, k2 sigfixture.Key) error {
	kp, err := e.k.page(ctx, page)
	if err != nil || kp == nil {
		return fmt.Errorf("%s: %v", page, err)
	}
	if kp.AcceptThreshold == 2 && len(kp.Keys) == 2 {
		return nil
	}
	_, h2, err := pubAndHash(k2)
	if err != nil {
		return err
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(page)
	txn.Body = &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
		&protocol.AddKeyOperation{Entry: protocol.KeySpecParams{KeyHash: h2}},
		&protocol.SetThresholdKeyPageOperation{Threshold: 2},
	}}
	s, err := owner.app.pageSigner(ctx, owner.root, page, true)
	if err != nil {
		return err
	}
	env, err := owner.app.envelope(txn, s)
	if err != nil {
		return err
	}
	return owner.app.run(ctx, "second key and threshold 2 on "+shortURL(page), txn, env)
}

// secondPage creates page 2 of book with key k2 as its only key, and funds it.
func (e *g1Env) secondPage(ctx context.Context, owner *g1ADI, book string, k2 sigfixture.Key) error {
	page2 := book + "/2"
	kp, err := e.k.page(ctx, page2)
	if err != nil {
		return err
	}
	if kp == nil {
		_, h2, err := pubAndHash(k2)
		if err != nil {
			return err
		}
		txn := new(protocol.Transaction)
		txn.Header.Principal = mustURL(book)
		txn.Body = &protocol.CreateKeyPage{Keys: []*protocol.KeySpecParams{{KeyHash: h2}}}
		s, err := owner.app.pageSigner(ctx, owner.root, book+"/1", true)
		if err != nil {
			return err
		}
		env, err := owner.app.envelope(txn, s)
		if err != nil {
			return err
		}
		if err := owner.app.run(ctx, "create "+shortURL(page2), txn, env); err != nil {
			return err
		}
	}
	return e.funder.ensureCredits(ctx, page2, 10_000_000, 1)
}

// addKeyAfter adds a second key to page, signed by the identity's root key: a change of the page after a vote of it has arrived.
func (e *g1Env) addKeyAfter(ctx context.Context, owner *g1ADI, page string) error {
	k2, err := owner.app.ks.loadOrCreate("key-after", protocol.SignatureTypeED25519)
	if err != nil {
		return err
	}
	_, h2, err := pubAndHash(k2)
	if err != nil {
		return err
	}
	txn := new(protocol.Transaction)
	txn.Header.Principal = mustURL(page)
	txn.Body = &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{
		&protocol.AddKeyOperation{Entry: protocol.KeySpecParams{KeyHash: h2}},
	}}
	s, err := owner.app.pageSigner(ctx, owner.root, page, true)
	if err != nil {
		return err
	}
	env, err := owner.app.envelope(txn, s)
	if err != nil {
		return err
	}
	return owner.app.run(ctx, "add a key to "+shortURL(page)+" after the intent", txn, env)
}
