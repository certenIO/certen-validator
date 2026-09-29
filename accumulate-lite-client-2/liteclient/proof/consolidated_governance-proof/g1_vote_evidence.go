// Copyright 2026 Certen Protocol
//
// THE VOTE'S EVIDENCE (RB4-F66).
//
// The authority vote record says who decided the transaction. On its own it is the CLI's word for it. This is what
// the vote READ - the governed transaction, every signature, delegated vote and recorded vote with the bytes the
// chain holds and the receipt that names its block, and every page's main chain from its genesis - so the validator
// can run the same evaluation again, offline, from nothing but what the proof stores (govvote.VerifyEvidence), and
// require it to reach the same record.
//
// Before the evidence leaves this process it is verified by exactly that function, and the vote it reaches must be
// the vote this proof computed. Evidence that does not reproduce the vote is not emitted: the proof fails as
// incomplete evidence, never as a governance verdict.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govreceipt"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func receiptOf(r ReceiptData) govreceipt.Receipt {
	return govreceipt.Receipt{Start: strings.ToLower(r.Start), Anchor: strings.ToLower(r.Anchor), LocalBlock: r.LocalBlock,
		Entries: r.Entries}
}

// signatureBytes is the signature a signature message carries, in Accumulate's binary encoding (hex), decoded by
// Accumulate's own types.
func signatureBytes(message interface{}) (string, error) {
	pu := ProofUtilities{}
	m, ok := message.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("the message is not an object")
	}
	raw := pu.CaseInsensitiveGet(m, "signature")
	if raw == nil {
		return "", fmt.Errorf("the message carries no signature")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	sig, err := protocol.UnmarshalSignatureJSON(b)
	if err != nil {
		return "", fmt.Errorf("the signature does not decode with Accumulate's types: %w", err)
	}
	bin, err := sig.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("the signature does not encode: %w", err)
	}
	return hex.EncodeToString(bin), nil
}

func transactionBytes(txn *protocol.Transaction) (string, error) {
	if txn == nil {
		return "", fmt.Errorf("no transaction")
	}
	b, err := txn.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("the transaction does not encode: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// governedTransaction is the transaction G0 carried forward, decoded with Accumulate's types and bound to the hash
// G0 proved executed.
func (a *g1Authorization) governedTransaction() (*protocol.Transaction, error) {
	raw := a.g1.g0Layer.Transaction()
	if raw == nil {
		return nil, fmt.Errorf("G0 did not carry the transaction forward")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("the transaction does not decode with Accumulate's types: %w", err)
	}
	if !strings.EqualFold(hex.EncodeToString(txn.GetHash()), a.txHash) {
		return nil, fmt.Errorf("the transaction G0 carried hashes to %x, not to the executed %s", txn.GetHash(),
			SafeTruncate(a.txHash, 16))
	}
	return txn, nil
}

// buildVoteEvidence assembles what the vote read, verifies it by the offline evaluation, and requires that
// evaluation to reach the vote this proof computed.
func (a *g1Authorization) buildVoteEvidence(ctx context.Context, facts voteFacts, sigs []ValidatedSignature,
	recorded map[string]recordedMessage, authorities []AccountAuthority, extra ExtraAuthorities,
	vote *AccountVote) (*govvote.Evidence, error) {

	txn, err := a.governedTransaction()
	if err != nil {
		return nil, fmt.Errorf("the vote's evidence: the governed transaction: %w", err)
	}
	txBytes, err := transactionBytes(txn)
	if err != nil {
		return nil, fmt.Errorf("the vote's evidence: the governed transaction: %w", err)
	}
	ev := &govvote.Evidence{Version: govvote.EvidenceVersion, Account: normalizeAccURL(a.principal),
		Transaction: txBytes, Authorities: authorities, Extra: extra.URLs, IgnoreDisabled: extra.IgnoreDisabled}

	byID := map[string]ValidatedSignature{}
	for _, v := range sigs {
		byID[strings.ToLower(v.MessageID)] = v
	}
	for _, f := range facts.Sigs {
		v, ok := byID[strings.ToLower(f.ID)]
		if !ok || v.Binary == "" {
			return nil, fmt.Errorf("the vote's evidence: signature %s: its bytes were not kept", SafeTruncate(f.ID, 24))
		}
		ev.Signatures = append(ev.Signatures, govvote.SignatureEvidence{Fact: f, Signature: v.Binary,
			Receipt: receiptOf(v.Receipt)})
	}
	for _, f := range facts.Arrivals {
		r, ok := recorded[strings.ToLower(f.ID)]
		if !ok || r.Binary == "" {
			return nil, fmt.Errorf("the vote's evidence: delegated vote %s: its bytes were not kept", SafeTruncate(f.ID, 24))
		}
		ev.Arrivals = append(ev.Arrivals, govvote.ArrivalEvidence{Fact: f, Signature: r.Binary, Receipt: receiptOf(r.Receipt)})
	}
	for _, f := range facts.Votes {
		r, ok := recorded[strings.ToLower(f.ID)]
		if !ok || r.Binary == "" {
			return nil, fmt.Errorf("the vote's evidence: recorded vote %s: its bytes were not kept", SafeTruncate(f.ID, 24))
		}
		ev.Votes = append(ev.Votes, govvote.VoteEvidence{Fact: f, Signature: r.Binary, Receipt: receiptOf(r.Receipt)})
	}
	for _, tl := range a.timelines.replayed() {
		ph, err := pageHistoryOf(tl)
		if err != nil {
			return nil, fmt.Errorf("the vote's evidence: page %s: %w", tl.Page, err)
		}
		ev.Pages = append(ev.Pages, ph)
	}

	// The evidence must reproduce the vote, through the verifier's own evaluation.
	again, err := govvote.VerifyEvidence(ctx, ev)
	if err != nil {
		return nil, fmt.Errorf("the vote's evidence does not verify: %w", err)
	}
	want, err := json.Marshal(vote)
	if err != nil {
		return nil, err
	}
	got, err := json.Marshal(again)
	if err != nil {
		return nil, err
	}
	if string(want) != string(got) {
		return nil, fmt.Errorf("the vote's evidence reaches a different vote than this proof computed")
	}
	return ev, nil
}

// replayed is every page timeline this proof replayed, in page order.
func (c *timelineCache) replayed() []*pageTimeline {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*pageTimeline, 0, len(c.pages))
	for _, tl := range c.pages {
		out = append(out, tl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Page < out[j].Page })
	return out
}

// pageHistoryOf is a replayed page's history as evidence.
func pageHistoryOf(tl *pageTimeline) (govvote.PageHistory, error) {
	if tl.Genesis == nil || tl.Genesis.Txn == nil {
		return govvote.PageHistory{}, fmt.Errorf("its genesis transaction was not kept")
	}
	gtx, err := transactionBytes(tl.Genesis.Txn)
	if err != nil {
		return govvote.PageHistory{}, fmt.Errorf("genesis: %w", err)
	}
	ph := govvote.PageHistory{Page: tl.Page, Entries: tl.Entries, Genesis: govvote.HistoryEntry{Index: 0,
		EntryHash: strings.ToLower(tl.Genesis.EntryHash), LocalBlock: tl.Genesis.LocalBlock,
		Receipt: receiptOf(tl.Genesis.Receipt), Transaction: gtx}}
	for _, e := range tl.Events {
		tx, err := transactionBytes(e.Txn)
		if err != nil {
			return govvote.PageHistory{}, fmt.Errorf("entry %d: %w", e.Index, err)
		}
		he := govvote.HistoryEntry{Index: e.Index, EntryHash: strings.ToLower(e.EntryHash), LocalBlock: e.LocalBlock,
			Receipt: receiptOf(e.Receipt), Transaction: tx}
		if e.InitiatorSig != nil {
			b, err := e.InitiatorSig.MarshalBinary()
			if err != nil {
				return govvote.PageHistory{}, fmt.Errorf("entry %d: its initiating signature does not encode: %w", e.Index, err)
			}
			he.Initiator = hex.EncodeToString(b)
		}
		ph.Events = append(ph.Events, he)
	}
	return ph, nil
}
