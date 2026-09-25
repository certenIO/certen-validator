// Copyright 2026 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

// THE VALIDATOR SET AN ANCHOR WAS ACCEPTED UNDER.
//
// A partition checks an anchor's signatures against ITS OWN active globals
// when it executes the anchor (accumulate-core msg_block_anchor.go:
// core.AnchorSigner(&ctx.Executor.globals.Active, partition)), and those
// globals are its own acc://<partition>/network and /globals data accounts
// (pkg/types/network/globals.go Load). A write to either lands in Pending and
// becomes Active only once its block ends (block_end.go), so the set in force
// for an anchor executed at block B is the one written by the latest entry
// recorded BEFORE B.
//
// Reading `network-status` at build time instead gives the Directory's
// CURRENT view: the wrong time once the set changes, and the wrong partition
// for an anchor delivered to a BVN, which applies updates only as they reach
// it.
//
// Using the set at B cannot accept a signature the network would not have.
// Every signature on the record was accepted by the network when it arrived,
// and the quorum that let the anchor execute was counted at B, against the
// threshold in force at B.

import (
	"context"
	"encoding/hex"
	"fmt"

	v3 "gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	acc_url "gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// maxSystemEntries bounds how many writes to one system account are read. The
// validator set of a live network changes rarely; a chain longer than this is
// not one this builder should walk entry by entry.
const maxSystemEntries = 4096

// systemEntry is one entry on a system data account's main chain, with the
// block its partition recorded it in.
type systemEntry struct {
	Block uint64
	Body  protocol.TransactionBody
}

// networkInfoAt reads the validator set and accept threshold that partition
// `dest` held in force while executing block `block`.
func (b *Layer4Builder) networkInfoAt(ctx context.Context, dest *acc_url.URL, block uint64, prefix string) (*networkInfo, error) {
	netData, err := b.systemDataAt(ctx, dest.JoinPath(protocol.Network), block, prefix+"_network")
	if err != nil {
		return nil, err
	}
	globData, err := b.systemDataAt(ctx, dest.JoinPath(protocol.Globals), block, prefix+"_globals")
	if err != nil {
		return nil, err
	}
	nd := new(protocol.NetworkDefinition)
	if err := nd.UnmarshalBinary(netData); err != nil {
		return nil, fmt.Errorf("%v/network at block %d: %w", dest, block, err)
	}
	g := new(protocol.NetworkGlobals)
	if err := g.UnmarshalBinary(globData); err != nil {
		return nil, fmt.Errorf("%v/globals at block %d: %w", dest, block, err)
	}
	return networkInfoFrom(nd, g)
}

// systemDataAt returns the record a system data account held in force at
// `block`: the entry of the latest write recorded before it.
func (b *Layer4Builder) systemDataAt(ctx context.Context, account *acc_url.URL, block uint64, prefix string) ([]byte, error) {
	entries, err := b.systemEntries(ctx, account, prefix)
	if err != nil {
		return nil, err
	}
	data, current, err := recordInForce(account, entries, block)
	if err != nil {
		return nil, err
	}
	if !current {
		return data, nil
	}

	resp, err := b.Client.Query(ctx, account, &v3.DefaultQuery{})
	if err != nil {
		return nil, fmt.Errorf("query %v: %w", account, err)
	}
	b.saveArtifact(prefix+"_state.json", resp)
	ar, ok := resp.(*v3.AccountRecord)
	if !ok {
		return nil, fmt.Errorf("%v: expected an account record, got %T", account, resp)
	}
	da, ok := ar.Account.(*protocol.DataAccount)
	if !ok {
		return nil, fmt.Errorf("%v is a %T, not a data account", account, ar.Account)
	}
	return singleRecord(account, da.Entry)
}

// recordInForce picks the record in force at `block` from an account's
// entries. When nothing was written since, the account's present state is
// its state at the block, whatever wrote it - including genesis, whose
// transaction does not carry the record as a data entry - and `current` is
// true. Otherwise the record is the one the latest earlier write carried.
func recordInForce(account *acc_url.URL, entries []systemEntry, block uint64) (data []byte, current bool, err error) {
	idx, err := entryInForceAt(entries, block)
	if err != nil {
		return nil, false, fmt.Errorf("%v: %w", account, err)
	}
	if idx == len(entries)-1 {
		return nil, true, nil
	}
	wd, ok := entries[idx].Body.(*protocol.WriteData)
	if !ok {
		return nil, false, fmt.Errorf("%v changed after block %d, and the entry in force at that block is a %v "+
			"at block %d, which does not carry the record; the validator set at the anchor is not established",
			account, block, entries[idx].Body.Type(), entries[idx].Block)
	}
	data, err = singleRecord(account, wd.Entry)
	return data, false, err
}

// entryInForceAt returns the index of the latest entry recorded before block
// `at`. A write in block `at` itself is not yet active during it.
func entryInForceAt(entries []systemEntry, at uint64) (int, error) {
	idx := -1
	for i, e := range entries {
		if i > 0 && e.Block < entries[i-1].Block {
			return 0, fmt.Errorf("main chain entry %d is at block %d, before entry %d at block %d",
				i, e.Block, i-1, entries[i-1].Block)
		}
		if e.Block < at {
			idx = i
		}
	}
	if idx < 0 {
		return 0, fmt.Errorf("has no entry before block %d", at)
	}
	return idx, nil
}

func singleRecord(account *acc_url.URL, entry protocol.DataEntry) ([]byte, error) {
	if entry == nil || len(entry.GetData()) != 1 {
		return nil, fmt.Errorf("%v: the data entry must hold exactly one record", account)
	}
	return entry.GetData()[0], nil
}

// systemEntries reads every entry of a system account's main chain with the
// block it was recorded in. Range queries do not return receipts, so each
// entry is fetched by index with one.
func (b *Layer4Builder) systemEntries(ctx context.Context, account *acc_url.URL, prefix string) ([]systemEntry, error) {
	resp, err := b.Client.Query(ctx, account, &v3.ChainQuery{Name: "main"})
	if err != nil {
		return nil, fmt.Errorf("query %v main chain: %w", account, err)
	}
	cr, ok := resp.(*v3.ChainRecord)
	if !ok {
		return nil, fmt.Errorf("%v main chain: expected a chain record, got %T", account, resp)
	}
	if cr.Count == 0 {
		return nil, fmt.Errorf("%v has an empty main chain", account)
	}
	if cr.Count > maxSystemEntries {
		return nil, fmt.Errorf("%v has %d main chain entries, more than %d", account, cr.Count, maxSystemEntries)
	}

	entries := make([]systemEntry, 0, cr.Count)
	for i := uint64(0); i < cr.Count; i++ {
		idx := i
		resp, err := b.Client.Query(ctx, account, &v3.ChainQuery{Name: "main", Index: &idx,
			IncludeReceipt: &v3.ReceiptOptions{ForAny: true}})
		if err != nil {
			return nil, fmt.Errorf("query %v main[%d]: %w", account, i, err)
		}
		b.saveArtifact(fmt.Sprintf("%s_main_%d.json", prefix, i), resp)
		ce, ok := resp.(*v3.ChainEntryRecord[v3.Record])
		if !ok {
			return nil, fmt.Errorf("%v main[%d]: expected a chain entry, got %T", account, i, resp)
		}
		if ce.Index != i {
			return nil, fmt.Errorf("%v main[%d]: returned index %d", account, i, ce.Index)
		}
		if ce.Receipt == nil || ce.Receipt.LocalBlock == 0 {
			return nil, fmt.Errorf("%v main[%d]: no receipt naming its block", account, i)
		}
		mr, ok := ce.Value.(*v3.MessageRecord[messaging.Message])
		if !ok {
			return nil, fmt.Errorf("%v main[%d]: expected a message record, got %T", account, i, ce.Value)
		}
		tm, ok := mr.Message.(*messaging.TransactionMessage)
		if !ok || tm.Transaction == nil {
			return nil, fmt.Errorf("%v main[%d]: expected a transaction, got %T", account, i, mr.Message)
		}
		if h := tm.Transaction.GetHash(); hex.EncodeToString(h) != hex.EncodeToString(ce.Entry[:]) {
			return nil, fmt.Errorf("%v main[%d]: the transaction hashes to %x, not the entry %x", account, i, h, ce.Entry)
		}
		entries = append(entries, systemEntry{Block: ce.Receipt.LocalBlock, Body: tm.Transaction.Body})
	}
	return entries, nil
}

// networkInfoFrom converts a network definition and globals into the L4 form.
// Nothing here is trusted by the verifier: it re-derives key hashes and the
// threshold and checks every signature against the set.
func networkInfoFrom(nd *protocol.NetworkDefinition, g *protocol.NetworkGlobals) (*networkInfo, error) {
	accept := Rational{Numerator: g.ValidatorAcceptThreshold.Numerator, Denominator: g.ValidatorAcceptThreshold.Denominator}
	if _, err := accept.Threshold(1); err != nil {
		return nil, fmt.Errorf("globals validatorAcceptThreshold: %w", err)
	}
	vals := make([]ValidatorKey, 0, len(nd.Validators))
	for i, v := range nd.Validators {
		pk, err := MustHex32Lower(hex.EncodeToString(v.PublicKey), fmt.Sprintf("network validator[%d].publicKey", i))
		if err != nil {
			return nil, err
		}
		var activeOn []string
		for _, p := range v.Partitions {
			if p.Active {
				activeOn = append(activeOn, p.ID)
			}
		}
		vals = append(vals, ValidatorKey{PublicKey: pk, PublicKeyHash: lowerHex(hex.EncodeToString(v.PublicKeyHash[:])), ActiveOn: activeOn})
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("the network definition has an empty validator set")
	}
	return &networkInfo{Validators: vals, Accept: accept, Version: nd.Version}, nil
}
