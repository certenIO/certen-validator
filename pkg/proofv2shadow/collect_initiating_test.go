// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DAX-1G (G-83): the capture of a separate, non-voting initiator. The erp identity (acc://erp.acme, BVN3) signs first and pays; its signature is
// not in any vote's cause chain. The collector carries the signature (Capture.Initiating) with the arrival block, and captures the page with its
// certified history, which the verifier judges the key against; without the history it carries no member and ends with the named state; a VOTING
// initiator (the signature is in a vote's cause chain) carries none.

const erpPage = "acc://erp.acme/book/1"

// erpChains is the scripted ErpPage1: a main chain holding its genesis (CreateKeyPage with the world's one key), a main-index chain, a signature
// chain of three messages with the initiating one at position 1 (written in block 3010) and its index chain.
type erpChains struct {
	chains map[string][][]byte // "<chain>" -> entries
	msg    [32]byte
	sig    protocol.Signature
	hist   []proofv2.HistoryEntry
}

func indexEntryBytes(source, anchor, block uint64) []byte {
	raw, err := (&protocol.IndexEntry{Source: source, Anchor: anchor, BlockIndex: block}).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return append(raw, make([]byte, 32-len(raw))...)
}

func newErpChains() *erpChains {
	genesis := &protocol.Transaction{Header: protocol.TransactionHeader{Principal: url.MustParse("acc://erp.acme/book")},
		Body: &protocol.CreateKeyPage{Keys: []*protocol.KeySpecParams{{KeyHash: make([]byte, 32)}}}}
	raw, err := genesis.MarshalBinary()
	if err != nil {
		panic(err)
	}
	sig := &protocol.ED25519Signature{PublicKey: make([]byte, 32), Signature: make([]byte, 64), Signer: url.MustParse(erpPage), SignerVersion: 1, Timestamp: 1}
	msg := (&messaging.SignatureMessage{Signature: sig}).Hash()
	return &erpChains{
		chains: map[string][][]byte{
			"main":            {genesis.GetHash()},
			"main-index":      {indexEntryBytes(0, 1, 10)},
			"signature":       {make([]byte, 32), msg[:], append(make([]byte, 31), 1)},
			"signature-index": {indexEntryBytes(0, 1, 3000), indexEntryBytes(1, 2, 3010), indexEntryBytes(2, 3, 3012)},
		},
		msg: msg, sig: sig, hist: []proofv2.HistoryEntry{{Transaction: hex.EncodeToString(raw)}},
	}
}

// root is the chain root a page proves for the chain.
func (e *erpChains) root(name string) proof.ChainRoot {
	st := new(merkle.State)
	for _, x := range e.chains[name] {
		st.AddEntry(x)
	}
	c := proof.ChainRoot{Name: name, Count: uint64(len(e.chains[name])), Anchor: hex.EncodeToString(st.Anchor())}
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

func (e *erpChains) Entries(_ context.Context, a *url.URL, chain string, n uint64) ([][]byte, error) {
	es, ok := e.chains[chain]
	if !ok || !strings.EqualFold(a.String(), erpPage) || uint64(len(es)) < n {
		return nil, fmt.Errorf("%v %s: %d entries asked", a, chain, n)
	}
	return es[:n], nil
}

func (e *erpChains) History(_ context.Context, a *url.URL, n uint64) ([]proofv2.HistoryEntry, error) {
	if !strings.EqualFold(a.String(), erpPage) || uint64(len(e.hist)) < n {
		return nil, fmt.Errorf("%v: %d history entries asked", a, n)
	}
	return e.hist[:n], nil
}

// initiatorNet is the tcl world with an erp page whose chains the network serves, an initiating signature recorded on it, and its arrival.
func initiatorNet(t *testing.T) (*fakeNet, *erpChains, *url.TxID) {
	t.Helper()
	f := newFakeNet(t, tclWorld())
	e := newErpChains()
	id, err := url.ParseTxID("acc://" + hex.EncodeToString(e.msg[:]) + "@erp.acme/book/1")
	if err != nil {
		t.Fatal(err)
	}
	f.arrivals[id.String()] = fakeArrival{"BVN3", 3010}
	f.facts = facts("acc://cust.acme/pay")
	f.facts.Initiators = []*url.URL{url.MustParse(erpPage)}
	f.facts.Initiating = &SigRecord{ID: id, Sig: e.sig}
	f.facts.KeySigs = map[string][]*url.TxID{key(url.MustParse(erpPage)): {id}}
	return f, e, id
}

// collectorWithChains is the fake network's collector whose page reads of the erp page carry the chain roots the scripted chains hold, and whose
// chain source serves them.
func collectorWithChains(f *fakeNet, e *erpChains) *Collector {
	c := f.collector()
	base := c.Page
	c.Page = func(ctx context.Context, account, partition string, block uint64) (*proofv2.PageState, error) {
		ps, err := base(ctx, account, partition, block)
		if err == nil && strings.EqualFold(account, erpPage) {
			ps.Chains = []proof.ChainRoot{e.root("main"), e.root("main-index"), e.root("signature"), e.root("signature-index")}
			ps.PendingHash, ps.ChainError = hex.EncodeToString(make([]byte, 32)), ""
		}
		return ps, err
	}
	c.Chains = e
	return c
}

func collectInitiator(f *fakeNet, c *Collector) (*Capture, error) {
	return c.Collect(context.Background(), f.facts.Principal.String(), strings.Repeat("ab", 32))
}

// The non-voting initiator's signature is carried: page, message, signature, the block it arrived in (3010 on BVN3, from the chain), and the page is
// captured with its certified history. The assembler then proves the receipt and the arrival of the very message in the page's signature chain.
func TestCollectCarriesTheInitiatingSignatureOfANonVotingInitiator(t *testing.T) {
	f, e, id := initiatorNet(t)
	c, err := collectInitiator(f, collectorWithChains(f, e))
	if err != nil {
		t.Fatal(err)
	}
	h := c.Initiating
	if h == nil {
		t.Fatal("the capture carries no initiating signature")
	}
	if !strings.EqualFold(h.Page, erpPage) || h.Message != hex.EncodeToString(e.msg[:]) || h.Block != 3010 || h.Receipt != "" || h.Arrival != nil {
		t.Fatalf("the captured hop is %+v: page, message and arrival block, and no proof yet", h)
	}
	wantSig, _ := e.sig.MarshalBinary()
	if h.Signature != hex.EncodeToString(wantSig) {
		t.Fatalf("the captured signature %s is not the one the page recorded", h.Signature)
	}
	erp := pageByURL(t, *c, erpPage)
	if erp.History == nil || len(erp.History.Entries) != 1 || len(erp.History.Index) != 1 || !hasRoleOf(c, erpPage, proofv2.RoleInitiatorSigner) {
		t.Fatalf("the initiator's page: history %+v roles %v", erp.History, erp.Roles)
	}
	// Capture.Assembly passes it on to the assembler.
	passed, aerr := c.Assembly(context.Background(), fakeLog{f}, e)
	if aerr != nil {
		t.Fatalf("Capture.Assembly: %v", aerr)
	}
	if passed.Initiating == nil || passed.Initiating.Message != h.Message || passed.Initiating.Page != h.Page {
		t.Fatalf("the assembly carries %+v, the capture %+v", passed.Initiating, h)
	}
	// The assembler proves it in the page's own chains.
	asm := &proofv2.Assembly{Source: e, Initiating: c.Initiating}
	for i := range c.Pages {
		p := c.Pages[i].PageState
		asm.Pages = append(asm.Pages, &p)
	}
	proved, err := asm.ProveInitiating(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := new(merkle.Receipt)
	raw, _ := hex.DecodeString(proved.Receipt)
	if err := r.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if !r.Validate(nil) || hex.EncodeToString(r.Start) != h.Message || hex.EncodeToString(r.Anchor) != e.root("signature").Anchor {
		t.Fatalf("the member's receipt does not place the message in the page's signature chain root")
	}
	if proved.Block != 3010 || proved.Arrival == nil || proved.Arrival.At.Position != 1 || proved.Arrival.Before == nil || proved.Arrival.Before.Position != 0 {
		t.Fatalf("the member's arrival proof: block %d %+v", proved.Block, proved.Arrival)
	}
	_ = id
}

// Without the chains the page's history cannot be read: the capture ends with the named state, after capturing the rest, and carries NO member
// (never a member without the proof of its key).
func TestCollectNonVotingInitiatorWithoutHistoryCarriesNoMember(t *testing.T) {
	f, _, _ := initiatorNet(t)
	c, err := f.collect() // the fake network's own collector: no chain source
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateHistoryUnavailable {
		t.Fatalf("want the named state %s, got %v", proofv2.StateHistoryUnavailable, err)
	}
	if c == nil || c.Initiating != nil {
		t.Fatalf("a capture without the initiator's history carries the member: %+v", c)
	}
	if !hasRoleOf(c, erpPage, proofv2.RoleInitiatorSigner) {
		t.Fatalf("the rest of the capture was not kept: %+v", c.Pages)
	}
}

// A VOTING initiator needs no member: its signature is in the cause chain of a recorded vote, where the verifier already proves it. The capture
// is exactly the one it was before the member (no member, no history demanded for a page that is not a hop page).
func TestCollectVotingInitiatorCarriesNoMember(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	v := vote("acc://bank.acme/book", "acc://bank.acme/book/1")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2010}
	f.facts.Initiators = []*url.URL{url.MustParse("acc://bank.acme/book/1")}
	// the initiating signature IS the vote's cause: the message the vote's key signature is recorded as
	sig := &protocol.ED25519Signature{PublicKey: make([]byte, 32), Signature: make([]byte, 64), Signer: url.MustParse("acc://bank.acme/book/1"), SignerVersion: 1, Timestamp: 1}
	f.facts.Initiating = &SigRecord{ID: v.Cause, Sig: sig}
	c, err := f.collect()
	var ns *proofv2.NamedState
	if errors.As(err, &ns) && ns.Code == proofv2.StateHistoryUnavailable {
		t.Fatalf("a voting initiator's capture demanded the initiator's history: %v", err)
	}
	if c == nil || c.Initiating != nil {
		t.Fatalf("a voting initiator's capture carries the member: %+v", c)
	}
}

// A signature recorded on an account that is not its payer is a refusal by name, never a member.
func TestCollectInitiatingSignatureOnAnotherAccountThanItsPayerIsRefused(t *testing.T) {
	f, e, _ := initiatorNet(t)
	other, err := url.ParseTxID("acc://" + hex.EncodeToString(e.msg[:]) + "@cust.acme/book/1")
	if err != nil {
		t.Fatal(err)
	}
	f.arrivals[other.String()] = fakeArrival{"BVN1", 990}
	f.facts.Initiating = &SigRecord{ID: other, Sig: e.sig} // the signature's signer is the erp page, the record is on cust.acme/book/1
	_, cerr := collectInitiator(f, collectorWithChains(f, e))
	var ns *proofv2.NamedState
	if !errors.As(cerr, &ns) || ns.Code != proofv2.StateCompletenessUnproven {
		t.Fatalf("want the named state %s, got %v", proofv2.StateCompletenessUnproven, cerr)
	}
}
