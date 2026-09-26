// Copyright 2026 Certen Protocol
//
// REPLAYING A KEY PAGE'S HISTORY UNDER ACCUMULATE-CORE'S OWN RULES.
//
// # WHAT WAS WRONG
//
// The replay reduced every updateKeyPage to two unordered sets - "entries
// removed" and "entries added" - plus a threshold that defaulted to 1. That
// shape cannot express what the executor does, and it was wrong in ways that
// accept signatures the network refused:
//
//   - A mutation that did not set the threshold replayed as setting it to 1,
//     so a 2-of-3 page became 1-of-3 at the first key it added.
//   - UpdateKey was not recognised at all. It rotates a key WITHOUT bumping the
//     page version, so the replayed page kept accepting the retired key and no
//     version comparison could notice.
//   - A removal did not clamp the thresholds to the new key count.
//   - Operations were not applied in order and nothing was validated, although
//     in the executor one invalid operation fails the whole transaction.
//
// # WHAT THIS DOES INSTEAD
//
// The page is a protocol.KeyPage, the transactions are protocol.Transaction,
// and each operation is applied the way accumulate-core applies it:
//
//	internal/core/execute/v2/chain/update_key_page.go   checkOperation,
//	                                                    executeOperation,
//	                                                    didUpdateKeyPage,
//	                                                    findKeyPageEntry
//	internal/core/execute/v2/chain/update_key.go        Execute, updateKey
//
// Those functions live in core's internal packages, so the few lines of rule
// logic they hold are mirrored here; everything they call on the page itself
// (AddKeySpec, RemoveKeySpecAt, SetThreshold, EntryByKeyHash, EntryByDelegate)
// is core's own public method, not a re-implementation.
//
// # WHY AN ERROR HERE IS A DIVERGENCE, NOT A SKIP
//
// A transaction reaches a page's main chain only when it executed
// successfully: the entry is written by the state manager's Commit
// (chain/state_cache.go), which the failure path never reaches - a failed
// transaction's changes are discarded and only its status is recorded
// (block/transaction.go recordFailedTransaction). So every event replayed here
// is one the executor applied without error. If applying it here errors, the
// replay has diverged from the executor, and the only honest answer is to stop.
//
// The checks core makes against the page's BOOK (verifyIsNotPage for a new
// delegate, the validator-book refusal) and the global page-entry limit are
// not repeated: they can only make a transaction fail, and these did not.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// pageInitiator identifies what initiated a transaction, as core's
// transactionIsInitiated reports it: the credit payment flagged Initiator,
// its payer, and - when the payer is the page itself - the public key hash of
// the key signature that caused it.
type pageInitiator struct {
	Payer   *url.URL
	KeyHash []byte
}

// pageEvent is one transaction on a key page's main chain, in chain order.
type pageEvent struct {
	Index      int
	EntryHash  string
	LocalBlock int64
	Receipt    ReceiptData
	Txn        *protocol.Transaction

	// Initiator is required for UpdateKey and unused otherwise.
	Initiator *pageInitiator
}

// replayEffect says what a transaction did to the page's authority.
type replayEffect int

const (
	// effectNone: the transaction changes nothing the authority depends on
	// (credits only).
	effectNone replayEffect = iota
	// effectAuthority: keys, delegates, thresholds, blacklist or version.
	effectAuthority
)

// decodeEntryTransaction reads the transaction an expanded main chain entry
// carries, with core's own types, and binds it to the entry: the body is only
// accepted if it hashes to the entry the receipt proves. Without that the
// replay would apply whatever body the endpoint returned for that entry.
func decodeEntryTransaction(expanded map[string]interface{}, entryHash string) (*protocol.Transaction, error) {
	pu := ProofUtilities{}
	value, ok := pu.CaseInsensitiveGet(expanded, "value").(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: fmt.Sprintf("main chain entry %s carries no value", short(entryHash))}
	}
	raw := pu.CaseInsensitiveGet(value, "message")
	if raw == nil {
		return nil, ValidationError{Msg: fmt.Sprintf("main chain entry %s carries no message", short(entryHash))}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("main chain entry %s: re-encode message: %w", short(entryHash), err)
	}
	msg, err := messaging.UnmarshalMessageJSON(b)
	if err != nil {
		return nil, ValidationError{Msg: fmt.Sprintf("main chain entry %s: decode message: %v", short(entryHash), err)}
	}
	tm, ok := msg.(*messaging.TransactionMessage)
	if !ok || tm.Transaction == nil {
		// A main chain holds transactions. Anything else here is not something
		// the replay can reason about.
		return nil, ValidationError{Msg: fmt.Sprintf("main chain entry %s is a %v message, not a transaction",
			short(entryHash), msg.Type())}
	}
	got := hex.EncodeToString(tm.Transaction.GetHash())
	if !strings.EqualFold(got, entryHash) {
		return nil, ValidationError{Msg: fmt.Sprintf("main chain entry %s: the transaction returned for it hashes to %s; "+
			"refusing to replay a body that is not the entry the receipt proves", short(entryHash), short(got))}
	}
	return tm.Transaction, nil
}

// applyPageEvent applies one main chain transaction to the page, in place.
func applyPageEvent(page *protocol.KeyPage, ev pageEvent) (replayEffect, error) {
	txn := ev.Txn
	if txn == nil || txn.Header.Principal == nil {
		return effectNone, fmt.Errorf("event %s has no transaction", short(ev.EntryHash))
	}
	if !txn.Header.Principal.Equal(page.Url) {
		return effectNone, ValidationError{Msg: fmt.Sprintf("a %v on %s's main chain names %v as its principal",
			txn.Body.Type(), page.Url, txn.Header.Principal)}
	}

	switch body := txn.Body.(type) {
	case *protocol.UpdateKeyPage:
		// Applied to a copy and committed only if every operation succeeds,
		// as the executor's state manager does.
		next := page.Copy()
		for i, op := range body.Operation {
			if err := applyKeyPageOperation(next, txn.Header.Principal, op); err != nil {
				return effectNone, divergence(ev, fmt.Sprintf("operation %d (%v): %v", i, op.Type(), err))
			}
		}
		// didUpdateKeyPage
		next.Version++
		for _, k := range next.Keys {
			k.LastUsedOn = 0
		}
		*page = *next
		return effectAuthority, nil

	case *protocol.UpdateKey:
		if ev.Initiator == nil || ev.Initiator.Payer == nil {
			return effectNone, ValidationError{Msg: fmt.Sprintf("updateKey %s: its initiator is unknown, and the "+
				"entry it rotates is the initiator's, so it cannot be replayed", short(ev.EntryHash))}
		}
		if err := requireKeyHash(body.NewKeyHash); err != nil {
			return effectNone, divergence(ev, err.Error())
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
				return effectNone, ValidationError{Msg: fmt.Sprintf("updateKey %s was initiated by %s's own key, "+
					"but the initiating key is unknown", short(ev.EntryHash), next.Url)}
			}
			old.KeyHash = ev.Initiator.KeyHash
		default:
			return effectNone, divergence(ev, fmt.Sprintf("initiator %v is neither the principal nor a delegate",
				ev.Initiator.Payer))
		}

		// "Do not update the key page version, do not reset LastUsedOn"
		if err := replayUpdateKey(next, old, &protocol.KeySpecParams{KeyHash: body.NewKeyHash}, true); err != nil {
			return effectNone, divergence(ev, err.Error())
		}
		*page = *next
		return effectAuthority, nil

	case *protocol.SyntheticDepositCredits, *protocol.BurnCredits:
		// Credit balance only.
		return effectNone, nil
	}

	// Anything else on a page's main chain is a transaction this replay has
	// not been taught, and cannot claim leaves the authority unchanged.
	return effectNone, ValidationError{Msg: fmt.Sprintf("a %v transaction (%s) is on %s's main chain; the replay "+
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

func divergence(ev pageEvent, detail string) error {
	return ValidationError{Msg: fmt.Sprintf("replay diverges from execution at %v %s (block %d): %s - the "+
		"executor applied this transaction without error, so a replay that cannot is not the page's history",
		ev.Txn.Body.Type(), short(ev.EntryHash), ev.LocalBlock, detail)}
}

// pageFromState builds the protocol page a KeyPageState describes. Entries
// are inserted with AddKeySpec so the page is ordered the way core orders it,
// which EntryByKeyHash's binary search depends on.
func pageFromState(pageURL string, s KeyPageState) (*protocol.KeyPage, error) {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("key page url %q: %w", pageURL, err)
	}
	page := &protocol.KeyPage{Url: u, Version: s.Version, AcceptThreshold: s.Threshold}
	for _, e := range s.EntrySet() {
		spec := new(protocol.KeySpec)
		if e.KeyHash != "" {
			h, err := hex.DecodeString(e.KeyHash)
			if err != nil {
				return nil, fmt.Errorf("key page entry %s: key hash: %w", e, err)
			}
			spec.PublicKeyHash = h
		}
		if e.Delegate != "" {
			d, err := url.Parse(e.Delegate)
			if err != nil {
				return nil, fmt.Errorf("key page entry %s: delegate: %w", e, err)
			}
			spec.Delegate = d
		}
		page.AddKeySpec(spec)
	}
	return page, nil
}

// stateFromPage is the KeyPageState a protocol page carries. Threshold is the
// accept threshold as the chain holds it; the resolver's normalisation of an
// unset (zero) threshold to one stays the single place that decides.
func stateFromPage(p *protocol.KeyPage) KeyPageState {
	s := KeyPageState{Version: p.Version, Threshold: p.AcceptThreshold, Keys: []string{}}
	for _, k := range p.Keys {
		e := KeyPageEntry{}
		if len(k.PublicKeyHash) > 0 {
			e.KeyHash = strings.ToLower(hex.EncodeToString(k.PublicKeyHash))
		}
		if k.Delegate != nil {
			e.Delegate = normalizeAccURL(k.Delegate.String())
		}
		s.Entries = append(s.Entries, e)
	}
	s.Keys = deriveKeyHashes(s.Entries)
	if s.Keys == nil {
		s.Keys = []string{}
	}
	return s
}

// authorityEqual compares two pages on everything that decides who may sign
// and how many must: every field except the credit balance and the per-key
// nonces, which change with every signature and decide nothing about
// authority.
func authorityEqual(a, b *protocol.KeyPage) bool {
	return authorityView(a).Equal(authorityView(b))
}

func authorityView(p *protocol.KeyPage) *protocol.KeyPage {
	c := p.Copy()
	c.CreditBalance = 0
	for _, k := range c.Keys {
		k.LastUsedOn = 0
	}
	return c
}

// describeAuthorityDifference names the fields on which two pages' authority
// differs, for an error a reader can act on.
func describeAuthorityDifference(replayed, live *protocol.KeyPage) string {
	var d []string
	if replayed.Version != live.Version {
		d = append(d, fmt.Sprintf("version %d != %d", replayed.Version, live.Version))
	}
	if replayed.AcceptThreshold != live.AcceptThreshold {
		d = append(d, fmt.Sprintf("acceptThreshold %d != %d", replayed.AcceptThreshold, live.AcceptThreshold))
	}
	if replayed.RejectThreshold != live.RejectThreshold {
		d = append(d, fmt.Sprintf("rejectThreshold %d != %d", replayed.RejectThreshold, live.RejectThreshold))
	}
	if replayed.ResponseThreshold != live.ResponseThreshold {
		d = append(d, fmt.Sprintf("responseThreshold %d != %d", replayed.ResponseThreshold, live.ResponseThreshold))
	}
	if replayed.BlockThreshold != live.BlockThreshold {
		d = append(d, fmt.Sprintf("blockThreshold %d != %d", replayed.BlockThreshold, live.BlockThreshold))
	}
	if !blacklistEqual(replayed.TransactionBlacklist, live.TransactionBlacklist) {
		d = append(d, "transactionBlacklist differs")
	}
	if !sameEntries(replayed.Keys, live.Keys) {
		d = append(d, fmt.Sprintf("entries %s != %s", entryList(replayed.Keys), entryList(live.Keys)))
	}
	if len(d) == 0 {
		d = append(d, "a field outside the named authority fields")
	}
	return strings.Join(d, "; ")
}

func blacklistEqual(a, b *protocol.AllowedTransactions) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}
	return *a == *b
}

func sameEntries(a, b []*protocol.KeySpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].PublicKeyHash, b[i].PublicKeyHash) {
			return false
		}
		switch {
		case a[i].Delegate == nil && b[i].Delegate == nil:
		case a[i].Delegate == nil || b[i].Delegate == nil:
			return false
		case !a[i].Delegate.Equal(b[i].Delegate):
			return false
		}
	}
	return true
}

func entryList(keys []*protocol.KeySpec) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		s := short(hex.EncodeToString(k.PublicKeyHash))
		if k.Delegate != nil {
			s += "->" + k.Delegate.String()
		}
		parts = append(parts, s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// keyPageFromAccountJSON decodes an account object, as the API renders it,
// into a key page with core's own types.
func keyPageFromAccountJSON(account interface{}) (*protocol.KeyPage, error) {
	b, err := json.Marshal(account)
	if err != nil {
		return nil, err
	}
	acct, err := protocol.UnmarshalAccountJSON(b)
	if err != nil {
		return nil, fmt.Errorf("decode account: %w", err)
	}
	page, ok := acct.(*protocol.KeyPage)
	if !ok {
		return nil, fmt.Errorf("account is a %v, not a key page", acct.Type())
	}
	return page, nil
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
