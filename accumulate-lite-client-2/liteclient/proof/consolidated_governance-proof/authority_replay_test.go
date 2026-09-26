// Copyright 2026 Certen Protocol

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Each case here is one rule of accumulate-core's key page executor, applied
// through applyPageEvent exactly as a replayed main chain entry is.

func keyHash(name string) []byte {
	h := sha256.Sum256([]byte(name))
	return h[:]
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// testPage is a page of the given keys, sorted the way core keeps it.
func testPage(t *testing.T, threshold uint64, names ...string) *protocol.KeyPage {
	t.Helper()
	p := &protocol.KeyPage{Url: mustURL(t, "acc://replay.acme/book/1"), Version: 1, AcceptThreshold: threshold}
	for _, n := range names {
		p.AddKeySpec(&protocol.KeySpec{PublicKeyHash: keyHash(n)})
	}
	return p
}

func updateKeyPageEvent(t *testing.T, page *protocol.KeyPage, ops ...protocol.KeyPageOperation) pageEvent {
	t.Helper()
	txn := &protocol.Transaction{Body: &protocol.UpdateKeyPage{Operation: ops}}
	txn.Header.Principal = page.Url
	return pageEvent{EntryHash: strings.Repeat("ab", 32), LocalBlock: 10, Txn: txn}
}

func updateKeyEvent(t *testing.T, page *protocol.KeyPage, newHash []byte, init *pageInitiator) pageEvent {
	t.Helper()
	txn := &protocol.Transaction{Body: &protocol.UpdateKey{NewKeyHash: newHash}}
	txn.Header.Principal = page.Url
	return pageEvent{EntryHash: strings.Repeat("cd", 32), LocalBlock: 11, Txn: txn, Initiator: init}
}

func addKey(name string) *protocol.AddKeyOperation {
	return &protocol.AddKeyOperation{Entry: protocol.KeySpecParams{KeyHash: keyHash(name)}}
}

func removeKey(name string) *protocol.RemoveKeyOperation {
	return &protocol.RemoveKeyOperation{Entry: protocol.KeySpecParams{KeyHash: keyHash(name)}}
}

func hasKey(p *protocol.KeyPage, name string) bool {
	_, _, ok := p.EntryByKeyHash(keyHash(name))
	return ok
}

// Defect 2: an update that does not set the threshold leaves it alone. The old
// replay turned this 2-of-3 page into 1-of-3.
func TestReplay_UpdateWithoutSetThresholdKeepsThreshold(t *testing.T) {
	p := testPage(t, 2, "a", "b", "c")
	if _, err := applyPageEvent(p, updateKeyPageEvent(t, p, addKey("d"))); err != nil {
		t.Fatal(err)
	}
	if p.AcceptThreshold != 2 {
		t.Fatalf("CRITICAL DEFECT: threshold after adding a key is %d, want 2 (the update did not set it)", p.AcceptThreshold)
	}
	if p.Version != 2 || len(p.Keys) != 4 {
		t.Fatalf("got v%d with %d keys, want v2 with 4", p.Version, len(p.Keys))
	}
}

// Defect 3: UpdateKey rotates the initiator's key, and does not move the
// version. The old replay ignored it, so the retired key kept signing.
func TestReplay_UpdateKeyRotatesTheInitiatorsKey(t *testing.T) {
	p := testPage(t, 2, "a", "b", "c")
	init := &pageInitiator{Payer: p.Url, KeyHash: keyHash("b")}
	eff, err := applyPageEvent(p, updateKeyEvent(t, p, keyHash("n"), init))
	if err != nil {
		t.Fatal(err)
	}
	if eff != effectAuthority {
		t.Fatal("an UpdateKey changes the page's authority")
	}
	if hasKey(p, "b") {
		t.Fatal("CRITICAL DEFECT: the rotated-out key is still on the page")
	}
	if !hasKey(p, "n") || !hasKey(p, "a") || !hasKey(p, "c") {
		t.Fatalf("keys after rotation are wrong: %s", entryList(p.Keys))
	}
	if p.Version != 1 {
		t.Fatalf("UpdateKey moved the version to %d; core leaves it unchanged", p.Version)
	}
}

// UpdateKey initiated through a delegate rewrites the delegate entry's key and
// keeps the delegate (preserveDelegate).
func TestReplay_UpdateKeyThroughDelegate(t *testing.T) {
	p := testPage(t, 1, "a")
	book := mustURL(t, "acc://other.acme/book")
	p.AddKeySpec(&protocol.KeySpec{Delegate: book})
	init := &pageInitiator{Payer: book}
	if _, err := applyPageEvent(p, updateKeyEvent(t, p, keyHash("n"), init)); err != nil {
		t.Fatal(err)
	}
	i, e, ok := p.EntryByKeyHash(keyHash("n"))
	if !ok {
		t.Fatalf("no entry carries the new key: %s", entryList(p.Keys))
	}
	if d := e.(*protocol.KeySpec).Delegate; d == nil || !d.Equal(book) {
		t.Fatalf("entry %d lost its delegate", i)
	}
}

// An UpdateKey whose initiator is unknown cannot be replayed at all.
func TestReplay_UpdateKeyWithoutInitiatorRefuses(t *testing.T) {
	p := testPage(t, 1, "a")
	if _, err := applyPageEvent(p, updateKeyEvent(t, p, keyHash("n"), nil)); err == nil {
		t.Fatal("an UpdateKey with no initiator was replayed")
	}
}

// A removal clamps the thresholds to the new key count.
func TestReplay_RemoveClampsThresholds(t *testing.T) {
	p := testPage(t, 3, "a", "b", "c")
	p.RejectThreshold, p.ResponseThreshold = 3, 3
	if _, err := applyPageEvent(p, updateKeyPageEvent(t, p, removeKey("c"))); err != nil {
		t.Fatal(err)
	}
	if p.AcceptThreshold != 2 || p.RejectThreshold != 2 || p.ResponseThreshold != 2 {
		t.Fatalf("thresholds after removal = %d/%d/%d, want 2/2/2",
			p.AcceptThreshold, p.RejectThreshold, p.ResponseThreshold)
	}
}

// Operations apply in order, and one invalid operation is a divergence: the
// executor would have failed the transaction, which would then never have
// reached the main chain.
func TestReplay_OperationsApplyInOrder(t *testing.T) {
	ok := testPage(t, 1, "a", "b")
	if _, err := applyPageEvent(ok, updateKeyPageEvent(t, ok, addKey("c"),
		&protocol.SetThresholdKeyPageOperation{Threshold: 3})); err != nil {
		t.Fatalf("add then raise to 3 of 3 must apply: %v", err)
	}
	if ok.AcceptThreshold != 3 {
		t.Fatalf("threshold = %d, want 3", ok.AcceptThreshold)
	}

	bad := testPage(t, 1, "a", "b")
	before := bad.Copy()
	_, err := applyPageEvent(bad, updateKeyPageEvent(t, bad,
		&protocol.SetThresholdKeyPageOperation{Threshold: 3}, addKey("c")))
	if err == nil || !strings.Contains(err.Error(), "replay diverges from execution") {
		t.Fatalf("raising to 3 before the third key exists must diverge, got %v", err)
	}
	if !bad.Equal(before) {
		t.Fatal("a diverging transaction changed the page; it must be applied all-or-nothing")
	}
}

func TestReplay_InvalidOperationsDiverge(t *testing.T) {
	cases := map[string]protocol.KeyPageOperation{
		"duplicate add":           addKey("a"),
		"remove of absent key":    removeKey("z"),
		"threshold zero":          &protocol.SetThresholdKeyPageOperation{Threshold: 0},
		"reject threshold >= key": &protocol.SetRejectThresholdKeyPageOperation{Threshold: 2},
		"update of absent key": &protocol.UpdateKeyOperation{
			OldEntry: protocol.KeySpecParams{KeyHash: keyHash("z")},
			NewEntry: protocol.KeySpecParams{KeyHash: keyHash("y")},
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			p := testPage(t, 1, "a", "b")
			if _, err := applyPageEvent(p, updateKeyPageEvent(t, p, op)); err == nil {
				t.Fatalf("%s was replayed; the executor refuses it", name)
			}
		})
	}
}

// The last key of page 1 cannot be removed.
func TestReplay_CannotRemoveLastKeyOfPageOne(t *testing.T) {
	p := testPage(t, 1, "a")
	if _, err := applyPageEvent(p, updateKeyPageEvent(t, p, removeKey("a"))); err == nil {
		t.Fatal("removed the last key of the highest priority page")
	}
}

// updateAllowed maintains the blacklist, and a blacklist that returns to empty
// is nil, as core stores it.
func TestReplay_UpdateAllowedMaintainsBlacklist(t *testing.T) {
	p := testPage(t, 1, "a", "b")
	deny := &protocol.UpdateAllowedKeyPageOperation{Deny: []protocol.TransactionType{protocol.TransactionTypeUpdateKeyPage}}
	if _, err := applyPageEvent(p, updateKeyPageEvent(t, p, deny)); err != nil {
		t.Fatal(err)
	}
	bit, _ := protocol.TransactionTypeUpdateKeyPage.AllowedTransactionBit()
	if p.TransactionBlacklist == nil || !p.TransactionBlacklist.IsSet(bit) {
		t.Fatal("updateKeyPage was not denied")
	}
	allow := &protocol.UpdateAllowedKeyPageOperation{Allow: []protocol.TransactionType{protocol.TransactionTypeUpdateKeyPage}}
	if _, err := applyPageEvent(p, updateKeyPageEvent(t, p, allow)); err != nil {
		t.Fatal(err)
	}
	if p.TransactionBlacklist != nil {
		t.Fatal("an emptied blacklist must be nil")
	}
	bogus := &protocol.UpdateAllowedKeyPageOperation{Deny: []protocol.TransactionType{protocol.TransactionTypeSendTokens}}
	if _, err := applyPageEvent(p, updateKeyPageEvent(t, p, bogus)); err == nil {
		t.Fatal("denied a transaction type that has no blacklist bit")
	}
}

// A transaction the replay has not been taught is refused, not skipped, and
// credit movements are recognised as leaving authority alone.
func TestReplay_UnknownTransactionOnMainChainRefuses(t *testing.T) {
	p := testPage(t, 1, "a")
	txn := &protocol.Transaction{Body: &protocol.WriteData{}}
	txn.Header.Principal = p.Url
	if _, err := applyPageEvent(p, pageEvent{EntryHash: strings.Repeat("ef", 32), Txn: txn}); err == nil {
		t.Fatal("an unrecognised transaction on the main chain was treated as harmless")
	}
	credits := &protocol.Transaction{Body: &protocol.SyntheticDepositCredits{Amount: 5}}
	credits.Header.Principal = p.Url
	eff, err := applyPageEvent(p, pageEvent{EntryHash: strings.Repeat("ef", 32), Txn: credits})
	if err != nil || eff != effectNone {
		t.Fatalf("a credit deposit must leave authority alone: %v", err)
	}
}

func TestReplay_PrincipalMustBeThePage(t *testing.T) {
	p := testPage(t, 1, "a", "b")
	ev := updateKeyPageEvent(t, p, addKey("c"))
	ev.Txn.Header.Principal = mustURL(t, "acc://elsewhere.acme/book/1")
	if _, err := applyPageEvent(p, ev); err == nil {
		t.Fatal("replayed an update addressed to a different page")
	}
}

// The body replayed must be the one the chain entry commits to.
func TestReplay_DecodedBodyMustHashToTheEntry(t *testing.T) {
	p := testPage(t, 1, "a")
	txn := &protocol.Transaction{Body: &protocol.UpdateKeyPage{Operation: []protocol.KeyPageOperation{addKey("b")}}}
	txn.Header.Principal = p.Url
	msgJSON := map[string]interface{}{
		"type":        "transaction",
		"transaction": mustJSONMap(t, txn),
	}
	expanded := map[string]interface{}{"value": map[string]interface{}{"message": msgJSON}}

	entry := hex.EncodeToString(txn.GetHash())
	got, err := decodeEntryTransaction(expanded, entry)
	if err != nil {
		t.Fatalf("the genuine body must decode: %v", err)
	}
	if hex.EncodeToString(got.GetHash()) != entry {
		t.Fatal("decoded body does not hash to its entry")
	}
	if _, err := decodeEntryTransaction(expanded, strings.Repeat("00", 32)); err == nil {
		t.Fatal("a body was accepted for an entry it does not hash to")
	}
}

// authorityEqual ignores what changes with every signature and nothing else.
func TestReplay_AuthorityEqualIgnoresOnlyCreditsAndNonces(t *testing.T) {
	a := testPage(t, 2, "a", "b")
	b := a.Copy()
	b.CreditBalance = 999
	b.Keys[0].LastUsedOn = 12345
	if !authorityEqual(a, b) {
		t.Fatal("credits and nonces must not count as an authority difference")
	}
	b.AcceptThreshold = 1
	if authorityEqual(a, b) {
		t.Fatal("a threshold difference must count")
	}
	c := a.Copy()
	c.Keys[1].PublicKeyHash = keyHash("x")
	if authorityEqual(a, c) {
		t.Fatal("a key difference must count")
	}
}

// pageFromState and stateFromPage round-trip, in core's order.
func TestReplay_StateRoundTrip(t *testing.T) {
	st := KeyPageState{Version: 3, Threshold: 2, Entries: []KeyPageEntry{
		{KeyHash: hex.EncodeToString(keyHash("b"))},
		{Delegate: "acc://d.acme/book"},
		{KeyHash: hex.EncodeToString(keyHash("a"))},
	}}
	p, err := pageFromState("acc://replay.acme/book/1", st)
	if err != nil {
		t.Fatal(err)
	}
	back := stateFromPage(p)
	if back.Version != 3 || back.Threshold != 2 || !entriesEqual(back.EntrySet(), st.EntrySet()) {
		t.Fatalf("round trip lost information: %+v", back)
	}
	// Ordered as core orders: the delegate-only entry (empty key hash) first.
	if back.Entries[0].Delegate == "" {
		t.Fatalf("entries are not in core's order: %v", back.Entries)
	}
}

func mustJSONMap(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
