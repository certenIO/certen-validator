// Copyright 2026 Certen Protocol

package proofv2

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// mapSource serves chains from memory, the way a node serves them: the first n entries of a chain.
type mapSource struct {
	chains map[string][][]byte // "<lower url>|<chain>"
	hist   map[string][]HistoryEntry
	reads  int
}

func (m *mapSource) Entries(_ context.Context, a *url.URL, chain string, n uint64) ([][]byte, error) {
	m.reads++
	es, ok := m.chains[strings.ToLower(a.String())+"|"+chain]
	if !ok || uint64(len(es)) < n {
		return nil, fmt.Errorf("%v %s: %d entries asked, %d held", a, chain, n, len(es))
	}
	return es[:n], nil
}

func (m *mapSource) History(_ context.Context, a *url.URL, n uint64) ([]HistoryEntry, error) {
	h := m.hist[strings.ToLower(a.String())]
	if uint64(len(h)) < n {
		return nil, fmt.Errorf("%v: %d history entries asked, %d held", a, n, len(h))
	}
	return h[:n], nil
}

func seedN(label string, i int) []byte {
	s := sha256.Sum256(binary.BigEndian.AppendUint64([]byte(label), uint64(i)))
	return s[:]
}

// chainRootFor is the root a page proves for a chain of these entries.
func chainRootFor(name string, entries [][]byte) proof.ChainRoot {
	st := new(merkle.State)
	for _, e := range entries {
		st.AddEntry(e)
	}
	c := proof.ChainRoot{Name: name, Count: uint64(len(entries)), Anchor: hex.EncodeToString(st.Anchor())}
	for _, p := range st.Pending {
		if p == nil {
			c.Pending = append(c.Pending, nil)
			continue
		}
		h := hex.EncodeToString(p)
		c.Pending = append(c.Pending, &h)
	}
	return c
}

func indexOf(source, block uint64) []byte {
	e := &protocol.IndexEntry{Source: source, BlockIndex: block}
	raw, _ := e.MarshalBinary()
	return append(raw, make([]byte, 32-len(raw))...)
}

// A signature chain of 37 entries written in blocks of 1..5 entries; the index chain records, per block, the last position written.
func signatureWorld(t *testing.T) (*mapSource, *PageState, []uint64) {
	t.Helper()
	const n = 37
	var sig, idx [][]byte
	blocks := make([]uint64, n)
	blk, in := uint64(100), 0
	for i := 0; i < n; i++ {
		sig = append(sig, seedN("signature", i))
		blocks[i] = blk
		in++
		if in == 1+int(blk%5) || i == n-1 {
			idx = append(idx, indexOf(uint64(i), blk))
			blk += 3
			in = 0
		}
	}
	u := "acc://assemble.acme/book/1"
	src := &mapSource{chains: map[string][][]byte{strings.ToLower(u) + "|signature": sig, strings.ToLower(u) + "|signature-index": idx}}
	p := &PageState{URL: u, Chains: []proof.ChainRoot{chainRootFor("signature", sig), chainRootFor("signature-index", idx)}}
	return src, p, blocks
}

// ChainReceipt is the receipt the chain itself would give, at every height and position.
func TestChainReceiptIsTheChainsOwnReceipt(t *testing.T) {
	for n := 1; n <= 40; n++ {
		entries := make([][]byte, n)
		for i := range entries {
			entries[i] = seedN("e", i)
		}
		st := new(merkle.State)
		for _, e := range entries {
			st.AddEntry(e)
		}
		for p := 0; p < n; p++ {
			r, err := ChainReceipt(entries, p)
			if err != nil {
				t.Fatal(err)
			}
			if string(r.Anchor) != string(st.Anchor()) || !r.Validate(nil) || string(r.Start) != string(entries[p]) {
				t.Fatalf("n=%d p=%d: the receipt does not validate to the chain's anchor", n, p)
			}
			if got := receiptPositions(r, uint64(n)); len(got) != 1 || got[0] != uint64(p) {
				t.Fatalf("n=%d p=%d: the receipt decodes to %v", n, p, got)
			}
		}
	}
	if _, err := ChainReceipt([][]byte{seedN("e", 0)}, 1); err == nil {
		t.Fatal("a position past the chain was given a receipt")
	}
}

// ProveEntry's receipt and index entries are accepted by the verifier's own arrival derivation, and give the block the script wrote the
// entry in, for every position of the chain.
func TestProveEntryIsAcceptedByTheArrivalDerivation(t *testing.T) {
	src, p, blocks := signatureWorld(t)
	pa := &provenAcct{anchor: &xAnchor{id: "BVN2", block: 400}, chain: PageChain{Bound: true}}
	for i := range blocks {
		ep, err := ProveEntry(context.Background(), src, p, "signature", seedN("signature", i))
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if ep.Position != uint64(i) || ep.Block != blocks[i] {
			t.Fatalf("entry %d: position %d block %d, the script wrote it at %d in block %d", i, ep.Position, ep.Block, i, blocks[i])
		}
		a := ep.Arrival
		got, err := deriveArrival(pa, p, "signature", hex.EncodeToString(seedN("signature", i)), ep.Receipt, &a)
		if err != nil || got != blocks[i] {
			t.Fatalf("entry %d: the verifier derives (%d, %v), the script wrote block %d", i, got, err, blocks[i])
		}
	}
}

// What a node serves that does not fold to the root the page proves is refused at assembly, by name of the chain; an entry the chain does
// not hold has no proof.
func TestProveEntryRefusesEntriesThatDoNotFoldToTheProvenRoot(t *testing.T) {
	src, p, _ := signatureWorld(t)
	key := strings.ToLower(p.URL) + "|signature"
	good := src.chains[key]

	swapped := append([][]byte(nil), good...)
	swapped[5], swapped[6] = swapped[6], swapped[5]
	src.chains[key] = swapped
	if _, err := ProveEntry(context.Background(), src, p, "signature", seedN("signature", 3)); err == nil || !strings.Contains(err.Error(), "do not fold") {
		t.Fatalf("reordered entries: %v", err)
	}
	src.chains[key] = good

	if _, err := ProveEntry(context.Background(), src, p, "signature", seedN("absent", 1)); err == nil || !strings.Contains(err.Error(), "does not hold the entry") {
		t.Fatalf("an entry the chain does not hold: %v", err)
	}

	dup := append([][]byte(nil), good...)
	dup[10] = dup[2]
	src.chains[key] = dup
	p.Chains[0] = chainRootFor("signature", dup)
	if _, err := ProveEntry(context.Background(), src, p, "signature", dup[2]); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("an entry held twice has no single position: %v", err)
	}
}

// A page with no history source cannot be given a history; one whose main-index chain does not fold is refused.
func TestAttachHistoryRefusesWhatDoesNotFold(t *testing.T) {
	u := "acc://assemble.acme/book/1"
	main := [][]byte{seedN("m", 0), seedN("m", 1)}
	idx := [][]byte{indexOf(0, 10), indexOf(1, 20)}
	p := &PageState{URL: u, Chains: []proof.ChainRoot{chainRootFor("main", main), chainRootFor("main-index", idx)}}
	src := &mapSource{chains: map[string][][]byte{strings.ToLower(u) + "|main-index": {indexOf(0, 10), indexOf(1, 21)}},
		hist: map[string][]HistoryEntry{strings.ToLower(u): {{Transaction: "00"}, {Transaction: "01"}}}}
	if err := AttachHistory(context.Background(), src, p); err == nil || !strings.Contains(err.Error(), "do not fold") {
		t.Fatalf("a main-index chain that does not fold: %v", err)
	}
	p.Chains = []proof.ChainRoot{chainRootFor("signature", main)}
	if err := AttachHistory(context.Background(), src, p); err == nil || !strings.Contains(err.Error(), "no bound main") {
		t.Fatalf("a page without a bound main chain: %v", err)
	}
}

// ProveInitiating (DAX-1G) proves a captured initiating signature exactly as ProveMembers proves a hop: the receipt and the two adjacent
// index entries are accepted by the verifier's own arrival derivation and give the block the script wrote the entry in; an assembly with none
// gives none; a signature whose page was not captured, or that the chain does not hold, is an error, never a member.
func TestProveInitiatingIsAcceptedByTheArrivalDerivation(t *testing.T) {
	src, p, blocks := signatureWorld(t)
	pa := &provenAcct{anchor: &xAnchor{id: "BVN2", block: 400}, chain: PageChain{Bound: true}}
	if h, err := (&Assembly{Source: src}).ProveInitiating(context.Background()); h != nil || err != nil {
		t.Fatalf("an assembly with no initiating signature gave %v, %v", h, err)
	}
	for _, i := range []int{0, 11, 36} {
		msg := hex.EncodeToString(seedN("signature", i))
		a := &Assembly{Pages: []*PageState{p}, Source: src, Initiating: &VoteHop{Page: strings.ToUpper(p.URL[:6]) + p.URL[6:], Message: msg, Signature: "00"}}
		h, err := a.ProveInitiating(context.Background())
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if h.Block != blocks[i] || h.Arrival == nil || h.Message != msg || h.Signature != "00" {
			t.Fatalf("entry %d: hop %+v, want block %d", i, h, blocks[i])
		}
		got, err := deriveArrival(pa, p, "signature", h.Message, h.Receipt, h.Arrival)
		if err != nil || got != blocks[i] {
			t.Fatalf("entry %d: the arrival derivation gives %d, %v; the script wrote it in %d", i, got, err, blocks[i])
		}
	}
	bad := func(h VoteHop, pages []*PageState, want string) {
		t.Helper()
		if _, err := (&Assembly{Pages: pages, Source: src, Initiating: &h}).ProveInitiating(context.Background()); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want an error containing %q, got %v", want, err)
		}
	}
	bad(VoteHop{Page: "acc://other.acme/book/1", Message: hex.EncodeToString(seedN("signature", 1))}, []*PageState{p}, "not among the captured pages")
	bad(VoteHop{Page: p.URL, Message: "zz"}, []*PageState{p}, "not 32 bytes of hex")
	bad(VoteHop{Page: p.URL, Message: hex.EncodeToString(seedN("absent", 1))}, []*PageState{p}, "does not hold the entry")
}

// DAX-1G-R2 (DAX-F79): a page whose chains the capture could not bind says why in ChainError (capturePageWith: an account with a pending transaction
// has a pending component in its state hash that no API serves, so the chain roots cannot be checked against it). The assembler hit that page
// first and answered with an unnamed "<account> has no signature chain bound at the block", which is what the lab's four multi-authority
// intents on acc://harbor-mfg-tcl97.acme/data ended with on 2026-11-13: the named state g1_chain_unbound_pending was lost between the capture and
// the operator. The refusal must be the capture's own named state, with the account and the reason.
func TestProveEntryNamesTheStateTheCaptureGaveForAnUnboundChain(t *testing.T) {
	for _, c := range []struct{ note, code string }{
		{"g1_chain_unbound_pending: 1 transactions pending on the account", StateChainUnboundPending},
		{"g1_chain_unbound: neither the current roots nor the roots at block 400 bind: x", "g1_chain_unbound"},
		{"g1_chain_unread: no chain", "g1_chain_unread"},
		{"g1_chain_unread_at_block: x", "g1_chain_unread_at_block"},
		{"unnamed reason with no code", StateChainUnboundPending},
	} {
		src, p, _ := signatureWorld(t)
		p.Chains, p.PendingHash, p.ChainError = nil, "", c.note
		_, err := ProveEntry(context.Background(), src, p, "signature", seedN("signature", 3))
		var ns *NamedState
		if !errors.As(err, &ns) {
			t.Fatalf("%q: the refusal is not a named state: %v", c.note, err)
		}
		if ns.Code != c.code || !strings.Contains(ns.Detail, p.URL) || !strings.Contains(ns.Detail, c.note) {
			t.Fatalf("%q: named %q with detail %q, want code %q naming the account %s and the capture's reason", c.note, ns.Code, ns.Detail, c.code, p.URL)
		}
	}

	// A page whose chains ARE bound but which holds no signature chain keeps the plain refusal: there is nothing to name.
	src, p, _ := signatureWorld(t)
	p.Chains = nil
	if _, err := ProveEntry(context.Background(), src, p, "signature", seedN("signature", 3)); err == nil ||
		!strings.Contains(err.Error(), "has no signature chain bound at the block") {
		t.Fatalf("a page with no chain and no capture reason: %v", err)
	}
}

// DAX-1G-R2 (DAX-F79): the reason a capture gives for a page whose chains do not bind names a pending transaction when the account has one now, with
// the code the verifier and the assembler name it by; without one it is the plain g1_chain_unbound.
func TestUnboundReasonNamesAPendingTransaction(t *testing.T) {
	berr := errors.New("H(chains||pending) is not the receipt's second sibling")
	with := unboundReason(16988238, 1, berr)
	if got := chainUnboundCode(with); got != StateChainUnboundPending {
		t.Fatalf("with a pending transaction the code is %q: %s", got, with)
	}
	for _, want := range []string{"1 transactions are pending on the account now", "no API serves", "block 16988238", berr.Error()} {
		if !strings.Contains(with, want) {
			t.Fatalf("the reason %q does not say %q", with, want)
		}
	}
	without := unboundReason(16988238, 0, berr)
	if got := chainUnboundCode(without); got != "g1_chain_unbound" || strings.Contains(without, "pending on the account now") {
		t.Fatalf("with nothing pending the reason is the plain g1_chain_unbound: %q (code %q)", without, got)
	}
}
