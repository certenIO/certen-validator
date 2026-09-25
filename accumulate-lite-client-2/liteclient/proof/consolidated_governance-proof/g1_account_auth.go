// Copyright 2026 Certen Protocol
//
// AN ACCOUNT'S AUTHORITY SET AT A BLOCK, REPLAYED FROM ITS OWN MAIN CHAIN.
//
// An account's own authority set is written in exactly two ways, both on its
// main chain: by the transaction that created it, and by UpdateAccountAuth.
// So it can be replayed like a key page: from the creation entry through every
// UpdateAccountAuth, taking the set as of the last entry at or before the
// block, and continuing to the head, where the replay must equal the set the
// network holds. A replay that disagrees with the present cannot be trusted
// about the past.
//
// Creation, from accumulate-core chain/*.go:
//
//	createDataAccount, createTokenAccount, createToken
//	                          the authorities the body names (setInitialAuthorities)
//	createKeyBook             the book itself, then those the body names
//	createIdentity            the new key book, then those the body names
//	syntheticCreateIdentity   the created accounts travel inline, with their sets
//
// An account created naming no authority starts empty and is governed by its
// nearest ancestor with a set (V2Baikonur); before Baikonur the parent's set
// was COPIED in at creation (StateManager.SetAuth -> InheritAuth). Which rule
// created an account is not recorded on it, so both are replayed, and the one
// whose replay reaches the live set is the one that happened. If both do and
// they disagree at the block, the set at the block is not established.
package main

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// accountAuthAt returns an account's own authority set as of a block.
func (g1 *G1Layer) accountAuthAt(ctx context.Context, u *url.URL, block int64) (*protocol.AccountAuth, error) {
	scope := u.String()
	count, err := g1.authorityBuilder.getMainChainCount(ctx, scope)
	if err != nil {
		return nil, err
	}
	last, err := g1.lastMainIndexAtOrBefore(ctx, scope, block)
	if err != nil {
		return nil, err
	}
	if last < 0 {
		return nil, ValidationError{Msg: fmt.Sprintf("%s did not exist at block %d", scope, block)}
	}
	txns, err := g1.readMainChain(ctx, scope, count)
	if err != nil {
		return nil, err
	}
	live, err := g1.liveAccountAuth(ctx, u)
	if err != nil {
		return nil, err
	}

	type outcome struct {
		atBlock *protocol.AccountAuth
		err     error
	}
	var reached []outcome
	for _, inherit := range []bool{false, true} {
		initial, err := g1.createdAuth(ctx, u, txns[0], inherit)
		if err != nil {
			reached = append(reached, outcome{err: err})
			continue
		}
		atBlock, head, err := replayAccountAuth(u, initial, txns, last)
		if err != nil {
			reached = append(reached, outcome{err: err})
			continue
		}
		if !authEqual(head, live) {
			reached = append(reached, outcome{err: fmt.Errorf("replayed to the head it is %s, not %s",
				describeAuth(head), describeAuth(live))})
			continue
		}
		reached = append(reached, outcome{atBlock: atBlock})
	}

	var ok []*protocol.AccountAuth
	var why []string
	for _, r := range reached {
		if r.err != nil {
			why = append(why, r.err.Error())
		} else {
			ok = append(ok, r.atBlock)
		}
	}
	switch {
	case len(ok) == 0:
		return nil, ValidationError{Msg: fmt.Sprintf("the authority set of %s could not be replayed to the set "+
			"the network holds: %s", scope, strings.Join(why, "; "))}
	case len(ok) == 2 && !authEqual(ok[0], ok[1]):
		return nil, ValidationError{Msg: fmt.Sprintf("the authority set of %s at block %d depends on which "+
			"creation rule applied, and both reach the present", scope, block)}
	}
	return ok[0], nil
}

// readMainChain reads every entry of an account's main chain with its
// transaction, each bound to its entry.
func (g1 *G1Layer) readMainChain(ctx context.Context, scope string, count int) ([]*protocol.Transaction, error) {
	out := make([]*protocol.Transaction, 0, count)
	pu := ProofUtilities{}
	for start := 0; start < count; start += 50 {
		n := 50
		if start+n > count {
			n = count - start
		}
		resp, err := g1.artifactManager.SaveRPCArtifact(ctx, fmt.Sprintf("g1_account_main_%s_%d", sanitizeLabel(scope), start),
			g1.client, scope, map[string]interface{}{
				"queryType": "chain", "name": "main",
				"range": map[string]interface{}{"start": start, "count": n, "expand": true},
			})
		if err != nil {
			return nil, fmt.Errorf("read %s's main chain: %w", scope, err)
		}
		result, err := pu.ExpectResult(resp)
		if err != nil {
			return nil, err
		}
		records, _ := pu.CaseInsensitiveGet(result, "records").([]interface{})
		if len(records) != n {
			return nil, fmt.Errorf("%s's main chain returned %d of %d entries from %d", scope, len(records), n, start)
		}
		for i, r := range records {
			rec, _ := r.(map[string]interface{})
			if idx, ok := chainIndexOf(rec); !ok || idx != start+i {
				return nil, fmt.Errorf("%s's main chain entry %d reports index %d", scope, start+i, idx)
			}
			entry, _ := pu.CaseInsensitiveGet(rec, "entry").(string)
			txn, err := decodeEntryTransaction(rec, strings.ToLower(entry))
			if err != nil {
				return nil, err
			}
			out = append(out, txn)
		}
	}
	return out, nil
}

// createdAuth is the authority set the creating transaction gave the account.
func (g1 *G1Layer) createdAuth(ctx context.Context, u *url.URL, txn *protocol.Transaction, inherit bool) (*protocol.AccountAuth, error) {
	auth := new(protocol.AccountAuth)
	var named []*url.URL
	switch body := txn.Body.(type) {
	case *protocol.CreateDataAccount:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		named = body.Authorities
	case *protocol.CreateTokenAccount:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		named = body.Authorities
	case *protocol.CreateToken:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		named = body.Authorities
	case *protocol.CreateKeyBook:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		auth.AddAuthority(body.Url)
		named = body.Authorities
	case *protocol.CreateIdentity:
		if !body.Url.Equal(u) {
			return nil, fmt.Errorf("the first entry of %v creates %v", u, body.Url)
		}
		if body.KeyBookUrl != nil {
			auth.AddAuthority(body.KeyBookUrl)
		}
		named = body.Authorities
	case *protocol.SyntheticCreateIdentity:
		for _, a := range body.Accounts {
			if !a.GetUrl().Equal(u) {
				continue
			}
			full, ok := a.(protocol.FullAccount)
			if !ok {
				return nil, fmt.Errorf("%v was created as a %v, which has no authority set", u, a.Type())
			}
			// Created on another partition with its set already decided.
			return full.GetAuth().Copy(), nil
		}
		return nil, fmt.Errorf("the synthetic creation on %v's chain does not create it", u)
	default:
		return nil, fmt.Errorf("%v was created by a %v, which this replay has not been taught", u, txn.Body.Type())
	}

	for _, a := range named {
		auth.AddAuthority(a)
	}
	if len(auth.Authorities) > 0 || !inherit {
		return auth, nil
	}

	// Before Baikonur an account naming no authority had its parent's set
	// copied in at creation. The parent's set at the block that created it.
	if u.IsRootIdentity() {
		return auth, nil
	}
	createdAt, err := g1.firstMainBlock(ctx, u.String())
	if err != nil {
		return nil, err
	}
	parent, err := g1.accountAuthAt(ctx, u.Identity(), createdAt)
	if err != nil {
		return nil, fmt.Errorf("the set %v would have copied from %v at creation: %w", u, u.Identity(), err)
	}
	return parent.Copy(), nil
}

// replayAccountAuth applies every UpdateAccountAuth on the account's chain, and
// returns the set after entry `last` and after the final entry.
func replayAccountAuth(u *url.URL, initial *protocol.AccountAuth, txns []*protocol.Transaction, last int) (*protocol.AccountAuth, *protocol.AccountAuth, error) {
	auth := initial.Copy()
	var atBlock *protocol.AccountAuth
	if last == 0 {
		atBlock = auth.Copy()
	}
	for i := 1; i < len(txns); i++ {
		if body, ok := txns[i].Body.(*protocol.UpdateAccountAuth); ok {
			if !txns[i].Header.Principal.Equal(u) {
				return nil, nil, fmt.Errorf("an updateAccountAuth on %v's chain names %v", u, txns[i].Header.Principal)
			}
			next := auth.Copy()
			if err := applyAccountAuthOps(u, next, body.Operations); err != nil {
				return nil, nil, fmt.Errorf("replay diverges from execution at entry %d of %v: %w - the executor "+
					"applied it without error", i, u, err)
			}
			auth = next
		}
		if i == last {
			atBlock = auth.Copy()
		}
	}
	return atBlock, auth, nil
}

// applyAccountAuthOps mirrors UpdateAccountAuth.Execute, less the checks that
// can only make it fail (authority existence, not-a-page, inheritance).
func applyAccountAuthOps(u *url.URL, auth *protocol.AccountAuth, ops []protocol.AccountAuthOperation) error {
	for _, op := range ops {
		switch op := op.(type) {
		case *protocol.EnableAccountAuthOperation:
			e, ok := auth.GetAuthority(op.Authority)
			if !ok {
				return fmt.Errorf("%v is not an authority of %v", op.Authority, u)
			}
			e.Disabled = false
		case *protocol.DisableAccountAuthOperation:
			e, ok := auth.GetAuthority(op.Authority)
			if !ok {
				return fmt.Errorf("%v is not an authority of %v", op.Authority, u)
			}
			e.Disabled = true
		case *protocol.AddAccountAuthorityOperation:
			if _, isNew := auth.AddAuthority(op.Authority); !isNew {
				return fmt.Errorf("duplicate authority %v", op.Authority)
			}
		case *protocol.RemoveAccountAuthorityOperation:
			if !auth.RemoveAuthority(op.Authority) {
				return fmt.Errorf("no such authority %v", op.Authority)
			}
			if len(auth.Authorities) == 0 && u.IsRootIdentity() {
				return fmt.Errorf("removing the last authority from a root account is not allowed")
			}
		default:
			return fmt.Errorf("invalid operation %v", op.Type())
		}
	}
	return nil
}

// firstMainBlock is the block an account's first main chain entry was recorded.
func (g1 *G1Layer) firstMainBlock(ctx context.Context, scope string) (int64, error) {
	pu := ProofUtilities{}
	resp, err := g1.artifactManager.SaveRPCArtifact(ctx, "g1_main_index_first_"+sanitizeLabel(scope), g1.client, scope,
		map[string]interface{}{"queryType": "chain", "name": "main-index",
			"range": map[string]interface{}{"start": 0, "count": 1, "expand": true}})
	if err != nil {
		return 0, err
	}
	result, err := pu.ExpectResult(resp)
	if err != nil {
		return 0, err
	}
	records, _ := pu.CaseInsensitiveGet(result, "records").([]interface{})
	if len(records) != 1 {
		return 0, fmt.Errorf("%s has no main-index entry", scope)
	}
	rec, _ := records[0].(map[string]interface{})
	value, _ := pu.CaseInsensitiveGet(rec, "value").(map[string]interface{})
	inner, _ := pu.CaseInsensitiveGet(value, "value").(map[string]interface{})
	b, ok := pu.CaseInsensitiveGet(inner, "blockIndex").(float64)
	if !ok {
		return 0, fmt.Errorf("%s's first main-index entry names no block", scope)
	}
	return int64(b), nil
}

func authEqual(a, b *protocol.AccountAuth) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(b)
}

func describeAuth(a *protocol.AccountAuth) string {
	if a == nil || len(a.Authorities) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(a.Authorities))
	for _, e := range a.Authorities {
		s := e.Url.String()
		if e.Disabled {
			s += " (disabled)"
		}
		parts = append(parts, s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
