// Copyright 2026 Certen Protocol

// Package govvote is G1's authority vote: the replay of a key page's history and the vote model that decides, as
// Accumulate's executor does, which authorities voted on a transaction, through which page, on which keys.
//
// # WHY THIS PACKAGE EXISTS
//
// This logic lived in consolidated_governance-proof, a `package main`, where the only consumer it could have was the
// govproof CLI that runs it. The validator must run the SAME evaluation offline, from a proof's stored evidence, to
// check who decided the transaction without trusting the record the CLI emitted (RB4-F66). A package main is not
// importable, so the model moved here, as govreceipt did for the receipt walk; the CLI keeps its names as aliases
// and wrappers. There is one replay and one vote model, not a CLI copy and a verifier copy.
package govvote

import (
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// CanonicalAccSpelling is the one place the canonical spelling of an account URL is defined: trimmed, lower case, no
// trailing slash. Accumulate URLs are case-insensitive in their authority part and the API is not consistent about
// case.
func CanonicalAccSpelling(u string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u)), "/")
}

func normalizeAccURL(u string) string { return CanonicalAccSpelling(u) }

// Initiator identifies what initiated a transaction, as core's transactionIsInitiated reports it: the credit payment
// flagged Initiator, its payer, and - when the payer is the page itself - the public key hash of the key signature
// that caused it.
type Initiator struct {
	Payer   *url.URL
	KeyHash []byte
}

// Event is one transaction on a key page's main chain, as the replay reads it.
type Event struct {
	EntryHash  string
	LocalBlock int64
	Txn        *protocol.Transaction
	// Initiator is required for UpdateKey and unused otherwise.
	Initiator *Initiator
}

// Effect says what a transaction did to the page's authority.
type Effect int

const (
	// EffectNone: the transaction changes nothing the authority depends on (credits only).
	EffectNone Effect = iota
	// EffectAuthority: keys, delegates, thresholds, blacklist or version.
	EffectAuthority
)

// ReplayError is the replay refusing an event: a transaction it cannot apply as the executor did, or cannot show
// leaves the page's authority unchanged. It is never a fact about the page; it is the replay declining to guess.
type ReplayError struct {
	Msg string
}

func (e *ReplayError) Error() string { return e.Msg }

// Apply applies one main chain transaction to the page, as the executor applied it.
func Apply(page *protocol.KeyPage, ev Event) (Effect, error) {
	txn := ev.Txn
	if txn == nil || txn.Header.Principal == nil {
		return EffectNone, fmt.Errorf("event %s has no transaction", short(ev.EntryHash))
	}
	if !txn.Header.Principal.Equal(page.Url) {
		return EffectNone, &ReplayError{Msg: fmt.Sprintf("a %v on %s's main chain names %v as its principal",
			txn.Body.Type(), page.Url, txn.Header.Principal)}
	}

	switch body := txn.Body.(type) {
	case *protocol.UpdateKeyPage:
		// Applied to a copy and committed only if every operation succeeds,
		// as the executor's state manager does.
		next := page.Copy()
		for i, op := range body.Operation {
			if err := applyKeyPageOperation(next, txn.Header.Principal, op); err != nil {
				return EffectNone, divergence(ev, fmt.Sprintf("operation %d (%v): %v", i, op.Type(), err))
			}
		}
		// didUpdateKeyPage
		next.Version++
		for _, k := range next.Keys {
			k.LastUsedOn = 0
		}
		*page = *next
		return EffectAuthority, nil

	case *protocol.UpdateKey:
		if ev.Initiator == nil || ev.Initiator.Payer == nil {
			return EffectNone, &ReplayError{Msg: fmt.Sprintf("updateKey %s: its initiator is unknown, and the "+
				"entry it rotates is the initiator's, so it cannot be replayed", short(ev.EntryHash))}
		}
		if err := requireKeyHash(body.NewKeyHash); err != nil {
			return EffectNone, divergence(ev, err.Error())
		}
		next := page.Copy()

		// update_key.go Execute: the delegate entry naming the payer, else
		// the key that signed, when the payer is the page itself.
		old := new(protocol.KeySpecParams)
		i, _, ok := next.EntryByDelegate(ev.Initiator.Payer)
		switch {
		case ok:
			old.Delegate = next.Keys[i].Delegate
		case ev.Initiator.Payer.Equal(next.Url):
			if len(ev.Initiator.KeyHash) == 0 {
				return EffectNone, &ReplayError{Msg: fmt.Sprintf("updateKey %s was initiated by %s's own key, "+
					"but the initiating key is unknown", short(ev.EntryHash), next.Url)}
			}
			old.KeyHash = ev.Initiator.KeyHash
		default:
			return EffectNone, divergence(ev, fmt.Sprintf("initiator %v is neither the principal nor a delegate",
				ev.Initiator.Payer))
		}

		// "Do not update the key page version, do not reset LastUsedOn"
		if err := replayUpdateKey(next, old, &protocol.KeySpecParams{KeyHash: body.NewKeyHash}, true); err != nil {
			return EffectNone, divergence(ev, err.Error())
		}
		*page = *next
		return EffectAuthority, nil

	case *protocol.SyntheticDepositCredits, *protocol.BurnCredits:
		// Credit balance only.
		return EffectNone, nil
	}

	// Anything else on a page's main chain is a transaction this replay has
	// not been taught, and cannot claim leaves the authority unchanged.
	return EffectNone, &ReplayError{Msg: fmt.Sprintf("a %v transaction (%s) is on %s's main chain; the replay "+
		"cannot show it leaves the page's authority unchanged", txn.Body.Type(), short(ev.EntryHash), page.Url)}
}

// applyKeyPageOperation mirrors checkOperation followed by executeOperation.
func applyKeyPageOperation(page *protocol.KeyPage, principal *url.URL, op protocol.KeyPageOperation) error {
	switch op := op.(type) {
	case *protocol.AddKeyOperation:
		if op.Entry.IsEmpty() {
			return fmt.Errorf("cannot add an empty entry")
		}
		if op.Entry.Delegate != nil && op.Entry.Delegate.ParentOf(principal) {
			return fmt.Errorf("self-delegation is not allowed")
		}
		if _, _, found := findKeyPageEntry(page, &op.Entry); found {
			return fmt.Errorf("cannot have duplicate entries on key page")
		}
		page.AddKeySpec(&protocol.KeySpec{PublicKeyHash: op.Entry.KeyHash, Delegate: op.Entry.Delegate})
		return nil

	case *protocol.RemoveKeyOperation:
		if op.Entry.IsEmpty() {
			return fmt.Errorf("cannot remove an empty entry")
		}
		index, _, found := findKeyPageEntry(page, &op.Entry)
		if !found {
			return fmt.Errorf("entry to be removed not found on the key page")
		}
		_, pageIndex, ok := protocol.ParseKeyPageUrl(page.Url)
		if !ok {
			return fmt.Errorf("principal is not a key page")
		}
		if len(page.Keys) == 1 && pageIndex == 1 {
			return fmt.Errorf("cannot delete last key of the highest priority page of a key book")
		}
		page.RemoveKeySpecAt(index)

		// The thresholds follow the key count down.
		n := uint64(len(page.Keys))
		if page.AcceptThreshold > n {
			page.AcceptThreshold = n
		}
		if page.RejectThreshold > n {
			page.RejectThreshold = n
		}
		if page.ResponseThreshold > n {
			page.ResponseThreshold = n
		}
		return nil

	case *protocol.UpdateKeyOperation:
		if op.OldEntry.IsEmpty() {
			return fmt.Errorf("cannot update: old entry is empty")
		}
		if op.NewEntry.IsEmpty() {
			return fmt.Errorf("cannot update: new entry is empty")
		}
		if op.NewEntry.Delegate != nil && op.NewEntry.Delegate.ParentOf(principal) {
			return fmt.Errorf("self-delegation is not allowed")
		}
		return replayUpdateKey(page, &op.OldEntry, &op.NewEntry, false)

	case *protocol.SetThresholdKeyPageOperation:
		if op.Threshold == 0 {
			return fmt.Errorf("cannot require 0 signatures on a key page")
		}
		return page.SetThreshold(op.Threshold)

	case *protocol.SetRejectThresholdKeyPageOperation:
		if op.Threshold >= uint64(len(page.Keys)) {
			return fmt.Errorf("cannot require %d rejections on a key page with %d keys", op.Threshold, len(page.Keys))
		}
		page.RejectThreshold = op.Threshold
		return nil

	case *protocol.SetResponseThresholdKeyPageOperation:
		if op.Threshold >= uint64(len(page.Keys)) {
			return fmt.Errorf("cannot require %d responses on a key page with %d keys", op.Threshold, len(page.Keys))
		}
		page.ResponseThreshold = op.Threshold
		return nil

	case *protocol.UpdateAllowedKeyPageOperation:
		for _, txn := range op.Allow {
			if _, ok := txn.AllowedTransactionBit(); !ok {
				return fmt.Errorf("transaction type %v cannot be (dis)allowed", txn)
			}
		}
		for _, txn := range op.Deny {
			if _, ok := txn.AllowedTransactionBit(); !ok {
				return fmt.Errorf("transaction type %v cannot be (dis)allowed", txn)
			}
		}
		if page.TransactionBlacklist == nil {
			page.TransactionBlacklist = new(protocol.AllowedTransactions)
		}
		for _, txn := range op.Allow {
			bit, _ := txn.AllowedTransactionBit()
			page.TransactionBlacklist.Clear(bit)
		}
		for _, txn := range op.Deny {
			bit, _ := txn.AllowedTransactionBit()
			page.TransactionBlacklist.Set(bit)
		}
		if *page.TransactionBlacklist == 0 {
			page.TransactionBlacklist = nil
		}
		return nil
	}

	return fmt.Errorf("invalid operation: %v", op.Type())
}

// replayUpdateKey mirrors update_key.go updateKey, less its book check.
func replayUpdateKey(page *protocol.KeyPage, old, new *protocol.KeySpecParams, preserveDelegate bool) error {
	oldPos, entry, found := findKeyPageEntry(page, old)
	if !found {
		return fmt.Errorf("entry to be updated not found on the key page")
	}
	newPos, _, found := findKeyPageEntry(page, new)
	if found && oldPos != newPos {
		return fmt.Errorf("cannot have duplicate entries on key page")
	}

	entry.PublicKeyHash = new.KeyHash
	if new.Delegate != nil || !preserveDelegate {
		entry.Delegate = new.Delegate
	}

	// Relocate the entry, keeping the page sorted.
	page.RemoveKeySpecAt(oldPos)
	page.AddKeySpec(entry)
	return nil
}

// findKeyPageEntry mirrors update_key_page.go findKeyPageEntry.
func findKeyPageEntry(page *protocol.KeyPage, search *protocol.KeySpecParams) (int, *protocol.KeySpec, bool) {
	var i int
	var entry protocol.KeyEntry
	var ok bool
	if len(search.KeyHash) > 0 {
		i, entry, ok = page.EntryByKeyHash(search.KeyHash)
	}
	if !ok && search.Delegate != nil {
		i, entry, ok = page.EntryByDelegate(search.Delegate)
	}
	if !ok {
		return -1, nil, false
	}
	spec, isSpec := entry.(*protocol.KeySpec)
	if !isSpec {
		return -1, nil, false
	}
	return i, spec, true
}

// requireKeyHash mirrors update_key.go requireKeyHash.
func requireKeyHash(h []byte) error {
	if len(h) == 0 {
		return fmt.Errorf("public key hash is missing")
	}
	if len(h) > 32 {
		return fmt.Errorf("public key hash is too long to be a hash")
	}
	return nil
}

func divergence(ev Event, detail string) error {
	return &ReplayError{Msg: fmt.Sprintf("replay diverges from execution at %v %s (block %d): %s - the "+
		"executor applied this transaction without error, so a replay that cannot is not the page's history",
		ev.Txn.Body.Type(), short(ev.EntryHash), ev.LocalBlock, detail)}
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// State is one state of a page and the block it began at.
type State struct {
	Block int64
	Page  *protocol.KeyPage
}

// States is every state a key page has been in, in chain order: States[0] the page as its genesis created it, each
// later state the page after one main chain transaction that changed its authority.
type States []State

// Replayed is one state Replay produced: the state, the index of the event that produced it (-1 for genesis) and
// the state it replaced (nil for genesis).
type Replayed struct {
	State
	EventIndex int
	Prev       *protocol.KeyPage
}

// Replay replays a page from its genesis state through its main chain events, in chain order, as the executor
// applied them. It returns every state the page's authority passed through, and the page as the last event left it
// (the head, which the caller compares with the page the network holds, when it can ask).
func Replay(genesis *protocol.KeyPage, genesisBlock int64, events []Event) ([]Replayed, *protocol.KeyPage, error) {
	if genesis == nil {
		return nil, nil, fmt.Errorf("no genesis page to replay from")
	}
	page := genesis.Copy()
	out := []Replayed{{State: State{Block: genesisBlock, Page: page.Copy()}, EventIndex: -1}}
	for i := range events {
		before := page.Copy()
		effect, err := Apply(page, events[i])
		if err != nil {
			return nil, nil, err
		}
		if effect == EffectAuthority {
			out = append(out, Replayed{State: State{Block: events[i].LocalBlock, Page: page.Copy()}, EventIndex: i, Prev: before})
		}
	}
	return out, page, nil
}

// CandidatesDuring returns every state the page may have been in during a block: the state it entered the block in,
// and each state a change within the block produced. Which of them a message processed in that block saw is decided
// by the message itself - a signature names its signer version.
func (s States) CandidatesDuring(block int64) []*protocol.KeyPage {
	var out []*protocol.KeyPage
	var entering *protocol.KeyPage
	for _, st := range s {
		switch {
		case st.Block < block:
			entering = st.Page
		case st.Block == block:
			out = append(out, st.Page)
		}
	}
	if entering != nil {
		out = append([]*protocol.KeyPage{entering}, out...)
	}
	return out
}

// OfVersion returns a state the page held at a version. Every state of one version has the same thresholds and
// delegates: only UpdateKey changes a page without changing its version, and it changes only a key hash.
func (s States) OfVersion(v uint64) (*protocol.KeyPage, bool) {
	for _, st := range s {
		if st.Page.Version == v {
			return st.Page, true
		}
	}
	return nil, false
}
