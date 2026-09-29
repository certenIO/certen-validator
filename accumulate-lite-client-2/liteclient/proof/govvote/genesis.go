// Copyright 2026 Certen Protocol

package govvote

import (
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// GenesisPage is the key page a genesis transaction created, as accumulate-core's executor creates it - the four ways
// a page is born (consolidated_governance-proof/authority_genesis.go names the executor code for each):
//
//	syntheticCreateIdentity  the page travels inline in body.accounts[]
//	createIdentity           page 1 of body.keyBookUrl: Version 1, AcceptThreshold 1, one key body.keyHash
//	createKeyBook            page 1 of body.url: Version 1, AcceptThreshold unset (0), one key body.publicKeyHash
//	createKeyPage            a page of the principal book: Version 1, AcceptThreshold 1, one entry per body.keys[]
//
// page is the page whose main chain the transaction was found on; a genesis that did not create THAT page is refused.
func GenesisPage(page string, txn *protocol.Transaction) (*protocol.KeyPage, error) {
	if txn == nil || txn.Body == nil {
		return nil, fmt.Errorf("no genesis transaction")
	}
	want := normalizeAccURL(page)
	book := BookOfPage(want)
	pageURL, err := url.Parse(want)
	if err != nil {
		return nil, fmt.Errorf("key page url %q: %w", page, err)
	}

	switch body := txn.Body.(type) {
	case *protocol.SyntheticCreateIdentity:
		for _, a := range body.Accounts {
			kp, ok := a.(*protocol.KeyPage)
			if ok && normalizeAccURL(kp.Url.String()) == want {
				return kp.Copy(), nil
			}
		}
		return nil, fmt.Errorf("the syntheticCreateIdentity creates no key page %s", want)

	case *protocol.CreateIdentity:
		if body.KeyBookUrl == nil {
			return nil, fmt.Errorf("createIdentity carries no keyBookUrl, so it created no key page")
		}
		if normalizeAccURL(body.KeyBookUrl.String()) != book || !strings.HasSuffix(want, "/1") {
			return nil, fmt.Errorf("createIdentity creates %s/1, not %s", normalizeAccURL(body.KeyBookUrl.String()), want)
		}
		if len(body.KeyHash) == 0 {
			return nil, fmt.Errorf("createIdentity carries no keyHash")
		}
		kp := &protocol.KeyPage{Url: pageURL, Version: 1, AcceptThreshold: 1}
		kp.AddKeySpec(&protocol.KeySpec{PublicKeyHash: body.KeyHash})
		return kp, nil

	case *protocol.CreateKeyBook:
		if body.Url == nil || normalizeAccURL(body.Url.String()) != book {
			return nil, fmt.Errorf("createKeyBook creates %v, which is not the book of %s", body.Url, want)
		}
		if !strings.HasSuffix(want, "/1") {
			return nil, fmt.Errorf("createKeyBook creates only page 1, but the target is %s", want)
		}
		if len(body.PublicKeyHash) == 0 {
			return nil, fmt.Errorf("createKeyBook carries no publicKeyHash")
		}
		kp := &protocol.KeyPage{Url: pageURL, Version: 1}
		kp.AddKeySpec(&protocol.KeySpec{PublicKeyHash: body.PublicKeyHash})
		return kp, nil

	case *protocol.CreateKeyPage:
		if txn.Header.Principal == nil || normalizeAccURL(txn.Header.Principal.String()) != book {
			return nil, fmt.Errorf("createKeyPage acted on %v, not on %s, the book of %s", txn.Header.Principal, book, want)
		}
		if len(body.Keys) == 0 {
			return nil, fmt.Errorf("createKeyPage carries no keys")
		}
		kp := &protocol.KeyPage{Url: pageURL, Version: 1, AcceptThreshold: 1}
		for _, k := range body.Keys {
			if k == nil || (len(k.KeyHash) == 0 && k.Delegate == nil) {
				return nil, fmt.Errorf("createKeyPage key spec carries neither keyHash nor delegate")
			}
			kp.AddKeySpec(&protocol.KeySpec{PublicKeyHash: k.KeyHash, Delegate: k.Delegate})
		}
		return kp, nil
	}
	return nil, fmt.Errorf("a %v transaction does not create a key page", txn.Body.Type())
}
