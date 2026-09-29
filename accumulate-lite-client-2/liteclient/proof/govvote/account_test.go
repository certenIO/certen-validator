// Copyright 2026 Certen Protocol

package govvote

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govreceipt"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

type urlT = url.URL

// RB4-F66 E2b: the principal's authority set at execution is replayed from account histories alone - each entry
// bound to its hash, the creation and every UpdateAccountAuth bound to their blocks by receipts.

const (
	acctADI  = "acc://p.acme"
	acctData = "acc://p.acme/data"
	acctBook = "acc://p.acme/book"
	acctX    = "acc://x.acme/book"
)

// chainEntry is one transaction on an account's main chain, at a block.
type chainEntry struct {
	block int64
	body  protocol.TransactionBody
}

func history(t *testing.T, account string, live []string, entries ...chainEntry) AccountHistory {
	t.Helper()
	h := AccountHistory{Account: account, Entries: len(entries)}
	for i, e := range entries {
		principal := account
		if i == 0 {
			principal = acctADI
			if account == acctADI {
				principal = "acc://acme"
			}
		}
		txn := &protocol.Transaction{Body: e.body}
		txn.Header.Principal = mustURL(t, principal)
		ce, err := CompactEntry(i, txn)
		if err != nil {
			t.Fatal(err)
		}
		if NeedsBlock(i, txn) {
			// A single-leaf receipt: the entry is its own anchor.
			ce.Receipt = &govreceipt.Receipt{Start: ce.EntryHash, Anchor: ce.EntryHash, LocalBlock: e.block}
			ce.LocalBlock = e.block
		}
		h.Events = append(h.Events, ce)
	}
	for _, l := range live {
		h.Live = append(h.Live, AccountAuthority{URL: l})
	}
	return h
}

func adiHistory(t *testing.T) AccountHistory {
	return history(t, acctADI, []string{acctBook},
		chainEntry{10, &protocol.CreateIdentity{Url: mustURL(t, acctADI), KeyBookUrl: mustURL(t, acctBook)}})
}

func addAuthority(t *testing.T, book string) *protocol.UpdateAccountAuth {
	return &protocol.UpdateAccountAuth{Operations: []protocol.AccountAuthOperation{
		&protocol.AddAccountAuthorityOperation{Authority: mustURL(t, book)}}}
}

func requireSet(t *testing.T, got []AccountAuthority, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("set %v, want %v", got, want)
	}
	for i := range want {
		if got[i].URL != want[i] {
			t.Fatalf("set %v, want %v", got, want)
		}
	}
}

// The common case: a data account created naming no authority is governed by its identity's book. Both creation
// rules land there, so nothing rests on the network's present set.
func TestAuthoritySet_ADataAccountClimbsToItsIdentity(t *testing.T) {
	ev := &AuthorityEvidence{Block: 100, Accounts: []AccountHistory{adiHistory(t),
		history(t, acctData, nil,
			chainEntry{20, &protocol.CreateDataAccount{Url: mustURL(t, acctData)}},
			chainEntry{0, &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("x")}}}})}}
	set, decided, err := AuthoritySetAt(ev, acctData)
	if err != nil {
		t.Fatal(err)
	}
	requireSet(t, set, acctBook)
	if len(decided) != 0 {
		t.Fatalf("decided by live state: %v", decided)
	}

	// Without the identity's history the climb has nowhere to land.
	ev.Accounts = ev.Accounts[1:]
	if set, _, err := AuthoritySetAt(ev, acctData); err == nil {
		t.Fatalf("the climb landed on %v without the identity's history", set)
	}
}

// An authority added AFTER execution did not govern the transaction.
func TestAuthoritySet_AnAuthorityAddedAfterExecutionIsNotRequired(t *testing.T) {
	ev := &AuthorityEvidence{Block: 100, Accounts: []AccountHistory{adiHistory(t),
		history(t, acctData, []string{acctBook, acctX},
			chainEntry{20, &protocol.CreateDataAccount{Url: mustURL(t, acctData), Authorities: []*urlT{mustURL(t, acctBook)}}},
			chainEntry{150, addAuthority(t, acctX)})}}
	set, _, err := AuthoritySetAt(ev, acctData)
	if err != nil {
		t.Fatal(err)
	}
	requireSet(t, set, acctBook)

	ev.Block = 150
	set, _, err = AuthoritySetAt(ev, acctData)
	if err != nil {
		t.Fatal(err)
	}
	requireSet(t, set, acctBook, acctX)
}

// When the network's present set is what chose the creation rule, and the other rule would have landed the climb
// elsewhere, the account is named: that part of the set is not the chain's alone.
func TestAuthoritySet_ARuleChosenByTheLiveSetIsNamed(t *testing.T) {
	// Created naming none, then given x.acme/book before execution. Post-Baikonur: [x]. Pre-Baikonur it would have
	// copied p.acme/book in first: [book, x] - which is not the live set, so that rule is eliminated, and it would
	// have required p.acme/book's vote too.
	ev := &AuthorityEvidence{Block: 100, Accounts: []AccountHistory{adiHistory(t),
		history(t, acctData, []string{acctX},
			chainEntry{20, &protocol.CreateDataAccount{Url: mustURL(t, acctData)}},
			chainEntry{30, addAuthority(t, acctX)})}}
	set, decided, err := AuthoritySetAt(ev, acctData)
	if err != nil {
		t.Fatal(err)
	}
	requireSet(t, set, acctX)
	if len(decided) != 1 || decided[0] != CanonicalAccSpelling(acctData) {
		t.Fatalf("decided by live state: %v, want %s", decided, acctData)
	}
}

func TestAuthoritySet_WhatCannotBeEstablishedIsRefused(t *testing.T) {
	good := func() *AuthorityEvidence {
		return &AuthorityEvidence{Block: 100, Accounts: []AccountHistory{adiHistory(t),
			history(t, acctData, []string{acctBook, acctX},
				chainEntry{20, &protocol.CreateDataAccount{Url: mustURL(t, acctData), Authorities: []*urlT{mustURL(t, acctBook)}}},
				chainEntry{0, &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{[]byte("x")}}}},
				chainEntry{90, addAuthority(t, acctX)})}}
	}
	if _, _, err := AuthoritySetAt(good(), acctData); err != nil {
		t.Fatalf("the untampered evidence: %v", err)
	}
	for _, c := range []struct {
		name   string
		tamper func(ev *AuthorityEvidence)
	}{
		{"not yet created", func(ev *AuthorityEvidence) { ev.Block = 15 }},
		{"the account's history twice", func(ev *AuthorityEvidence) { ev.Accounts = append(ev.Accounts, ev.Accounts[1]) }},
		{"an entry dropped", func(ev *AuthorityEvidence) {
			a := &ev.Accounts[1]
			a.Events = a.Events[:2]
		}},
		{"an UpdateAccountAuth dropped with the count", func(ev *AuthorityEvidence) {
			// The history then reaches [book], which is not the live set: omitting it is caught by the present.
			a := &ev.Accounts[1]
			a.Events, a.Entries = a.Events[:2], 2
		}},
		{"an entry's header", func(ev *AuthorityEvidence) {
			e := &ev.Accounts[1].Events[1]
			e.Header = ev.Accounts[1].Events[0].Header
		}},
		{"a write-data entry's hash", func(ev *AuthorityEvidence) {
			e := &ev.Accounts[1].Events[1]
			e.DataEntryHash = strings.Repeat("11", 32)
		}},
		{"a write-data entry's hash removed", func(ev *AuthorityEvidence) { ev.Accounts[1].Events[1].DataEntryHash = "" }},
		{"the UpdateAccountAuth's receipt", func(ev *AuthorityEvidence) { ev.Accounts[1].Events[2].Receipt = nil }},
		{"the UpdateAccountAuth's block", func(ev *AuthorityEvidence) { ev.Accounts[1].Events[2].LocalBlock = 150 }},
		{"a block on an entry whose block decides nothing", func(ev *AuthorityEvidence) {
			ev.Accounts[1].Events[1].LocalBlock = 50
		}},
		{"the creation's receipt anchor", func(ev *AuthorityEvidence) {
			ev.Accounts[1].Events[0].Receipt.Anchor = strings.Repeat("00", 32)
		}},
		{"the live set", func(ev *AuthorityEvidence) { ev.Accounts[1].Live = ev.Accounts[1].Live[:1] }},
		{"an entry index", func(ev *AuthorityEvidence) { ev.Accounts[1].Events[1].Index = 5 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev := good()
			c.tamper(ev)
			set, _, err := AuthoritySetAt(ev, acctData)
			if err == nil {
				t.Fatalf("tampered evidence replayed to %v", set)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// A compact write-data entry hashes to exactly the transaction core hashed: the body without its entry, and the
// entry's hash.
func TestCompactEntry_WriteDataHashesAsCore(t *testing.T) {
	txn := &protocol.Transaction{Body: &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{
		Data: [][]byte{[]byte("certen"), make([]byte, 4096)}}}}
	txn.Header.Principal = mustURL(t, acctData)
	e, err := CompactEntry(3, txn)
	if err != nil {
		t.Fatal(err)
	}
	if e.EntryHash != hex.EncodeToString(txn.GetHash()) || e.DataEntryHash == "" || len(e.Body) > 64 {
		t.Fatalf("compact entry %+v", e)
	}
	got, err := decodeEntry(e)
	if err != nil {
		t.Fatalf("the compact entry does not bind to its hash: %v", err)
	}
	if _, ok := got.Body.(*protocol.WriteData); !ok {
		t.Fatalf("decoded %v", got.Body.Type())
	}
}

// The live evidence carries the authority set's histories, and a vote evidence whose stated set is not the one they
// replay to is refused.
func TestEvidenceAuthoritySetIsReplayed(t *testing.T) {
	for _, name := range evidenceFixtures {
		f := loadFixture(t, name)
		if f.Evidence.AuthoritySet == nil || len(f.Evidence.AuthoritySet.Accounts) != 2 {
			t.Fatalf("%s: the authority set's histories: %+v", name, f.Evidence.AuthoritySet)
		}
		if len(f.Evidence.AuthoritySet.DecidedByLiveState) != 0 {
			t.Fatalf("%s: the live set decided %v", name, f.Evidence.AuthoritySet.DecidedByLiveState)
		}
		for _, c := range []struct {
			what   string
			tamper func(ev *Evidence)
		}{
			{"stated set", func(ev *Evidence) { ev.Authorities[0].URL = "acc://other.acme/book" }},
			{"no histories", func(ev *Evidence) { ev.AuthoritySet = nil }},
			{"execution block before creation", func(ev *Evidence) { ev.AuthoritySet.Block = 1 }},
			{"a live-state claim", func(ev *Evidence) { ev.AuthoritySet.DecidedByLiveState = []string{ev.Account} }},
		} {
			f := loadFixture(t, name)
			c.tamper(f.Evidence)
			if _, err := VerifyEvidence(context.Background(), f.Evidence); err == nil {
				t.Fatalf("%s: tampered %s verified", name, c.what)
			}
		}
	}
}
