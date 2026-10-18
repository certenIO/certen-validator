// Copyright 2026 Certen Protocol

package govvote

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// RB9-L: Accumulate's union decoders (protocol.UnmarshalSignature, protocol.UnmarshalTransactionBody) return (nil, nil) for bytes that
// hold no type - a run of zeros. Evidence is chosen by whoever builds the block that carries it, so a member of it that is a run of
// zeros must be refused by name, never handed on as a nil signature or body to be dereferenced (a panic in FinalizeBlock stops every
// validator that judges the block).

func zeroHex(n int) string { return strings.Repeat("00", n) }

func refusedNotPanicked(t *testing.T, what string, run func() error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: PANIC %v", what, r)
		}
	}()
	if err := run(); err == nil {
		t.Errorf("%s: accepted", what)
	}
}

func TestDecodeSignatureRefusesBytesThatHoldNoSignature(t *testing.T) {
	for _, n := range []int{1, 2, 8, 64} {
		h := zeroHex(n)
		refusedNotPanicked(t, fmt.Sprintf("decodeSignature(%d zero bytes)", n), func() error {
			sig, err := decodeSignature(h)
			if err == nil && sig == nil {
				return nil // (nil signature, no error): the caller would dereference it
			}
			return err
		})
	}
}

func TestDecodeTransactionRefusesBytesThatHoldNoTransaction(t *testing.T) {
	for _, n := range []int{1, 2, 8, 64} {
		h := zeroHex(n)
		refusedNotPanicked(t, fmt.Sprintf("decodeTransaction(%d zero bytes)", n), func() error {
			txn, err := decodeTransaction(h)
			if err == nil && (txn == nil || txn.Body == nil) {
				return nil
			}
			return err
		})
	}
}

func TestDecodeEntryRefusesABodyThatHoldsNoTransactionBody(t *testing.T) {
	for _, n := range []int{1, 2, 8, 64} {
		e := AccountEntry{Header: "", Body: zeroHex(n), EntryHash: zeroHex(32)}
		refusedNotPanicked(t, fmt.Sprintf("decodeEntry(body of %d zero bytes)", n), func() error {
			txn, err := decodeEntry(e)
			if err == nil && (txn == nil || txn.Body == nil) {
				return nil
			}
			return err
		})
	}
}

// Every member of the evidence that is the binary encoding of a signature, a transaction or a transaction body is replaced by a run of
// zeros: the evidence is refused, never dereferenced.
func TestEvidenceWhoseBinaryMemberHoldsNothingIsRefused(t *testing.T) {
	type setter struct {
		name string
		set  func(ev *Evidence, z string) bool // false: the fixture has no such member
	}
	setters := []setter{
		{"transaction", func(ev *Evidence, z string) bool { ev.Transaction = z; return true }},
		{"signatures[0].signature", func(ev *Evidence, z string) bool {
			if len(ev.Signatures) == 0 {
				return false
			}
			ev.Signatures[0].Signature = z
			return true
		}},
		{"arrivals[0].signature", func(ev *Evidence, z string) bool {
			if len(ev.Arrivals) == 0 {
				return false
			}
			ev.Arrivals[0].Signature = z
			return true
		}},
		{"votes[0].signature", func(ev *Evidence, z string) bool {
			if len(ev.Votes) == 0 {
				return false
			}
			ev.Votes[0].Signature = z
			return true
		}},
		{"pages[0].genesis.transaction", func(ev *Evidence, z string) bool { ev.Pages[0].Genesis.Transaction = z; return true }},
		{"pages[0].events[0].transaction", func(ev *Evidence, z string) bool {
			if len(ev.Pages[0].Events) == 0 {
				return false
			}
			ev.Pages[0].Events[0].Transaction = z
			return true
		}},
		{"pages[0].events[*].initiator", func(ev *Evidence, z string) bool {
			any := false
			for i := range ev.Pages[0].Events {
				if ev.Pages[0].Events[i].Initiator != "" {
					ev.Pages[0].Events[i].Initiator = z
					any = true
				}
			}
			return any
		}},
		{"authoritySet.accounts[0].events[0].body", func(ev *Evidence, z string) bool {
			if ev.AuthoritySet == nil || len(ev.AuthoritySet.Accounts) == 0 || len(ev.AuthoritySet.Accounts[0].Events) == 0 {
				return false
			}
			ev.AuthoritySet.Accounts[0].Events[0].Body = z
			return true
		}},
		{"authoritySet.accounts[0].events[0].header", func(ev *Evidence, z string) bool {
			if ev.AuthoritySet == nil || len(ev.AuthoritySet.Accounts) == 0 || len(ev.AuthoritySet.Accounts[0].Events) == 0 {
				return false
			}
			ev.AuthoritySet.Accounts[0].Events[0].Header = z
			return true
		}},
	}
	exercised := 0
	for _, name := range evidenceFixtures {
		for _, s := range setters {
			for _, n := range []int{1, 2, 8, 64} {
				f := loadFixture(t, name)
				if !s.set(f.Evidence, zeroHex(n)) {
					continue
				}
				exercised++
				refusedNotPanicked(t, fmt.Sprintf("%s: %s as %d zero bytes", name, s.name, n), func() error {
					_, err := VerifyEvidence(context.Background(), f.Evidence)
					return err
				})
			}
		}
	}
	if exercised < 40 {
		t.Fatalf("only %d zero-filled members were exercised", exercised)
	}
}
