// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// fakeNet is a network of partitions: accounts by identity, a state root per (partition, block) that every page read at that
// block really passes through, and the Directory's record of each partition's anchors.
type fakeNet struct {
	t        *testing.T
	acct     world
	part     map[string]string // host -> partition ID
	anchors  map[string][]fakeAnchor
	x        string
	block    uint64
	dnBlock  uint64
	facts    *TxFacts
	arrivals map[string]fakeArrival
	dels     map[string][]*url.URL // cause -> the key signature's delegator pages
	certify  *url.URL
	certErr  error

	liar     map[string]uint64 // partition -> the block it actually serves, whatever block is asked
	noAnchor map[string]bool
	noPos    bool
	reads    []string
}

type fakeAnchor struct {
	dn    uint64
	block uint64
}

type fakeArrival struct {
	partition string
	block     uint64
}

func newFakeNet(t *testing.T, w world) *fakeNet {
	return &fakeNet{t: t, acct: w, x: "BVN1", block: 1000, dnBlock: 500, arrivals: map[string]fakeArrival{},
		liar: map[string]uint64{}, noAnchor: map[string]bool{}, dels: map[string][]*url.URL{},
		part: map[string]string{"cust.acme": "BVN1", "harbor.acme": "BVN1", "bank.acme": "BVN2", "risk.acme": "BVN2", "deleg.acme": "BVN3", "erp.acme": "BVN3"},
		anchors: map[string][]fakeAnchor{
			"BVN2": {{480, 2000}, {490, 2010}, {499, 2019}, {510, 2030}},
			"BVN3": {{300, 3000}, {495, 3015}, {520, 3030}},
		}}
}

func (f *fakeNet) route(_ context.Context, account string) (string, error) {
	u := url.MustParse(account)
	p, ok := f.part[strings.ToLower(u.Hostname())]
	if !ok {
		return "", fmt.Errorf("no route for %s", account)
	}
	return p, nil
}

func leafOf(a protocol.Account) []byte {
	b, err := a.MarshalBinary()
	if err != nil {
		panic(err)
	}
	s := sha256.Sum256(b)
	return s[:]
}

// tree is the partition's accounts folded in URL order: acc_0 = 0, acc_j = H(acc_{j-1} || leaf_j). A page's path to the
// fold is the previous accumulator on the left and every later leaf on the right.
func (f *fakeNet) tree(partition string) (urls []string, leaves, accs [][]byte) {
	for k, a := range f.acct {
		if f.part[strings.ToLower(a.GetUrl().Hostname())] == partition {
			urls = append(urls, k)
		}
	}
	sort.Strings(urls)
	acc := make([]byte, 32)
	accs = append(accs, acc)
	for _, k := range urls {
		l := leafOf(f.acct[k])
		leaves = append(leaves, l)
		s := sha256.Sum256(append(append([]byte(nil), acc...), l...))
		acc = s[:]
		accs = append(accs, acc)
	}
	return
}

func salt(partition string, block uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], block)
	s := sha256.Sum256(append([]byte("block:"+partition+":"), b[:]...))
	return s[:]
}

// rootAt is the partition's state tree root at a block.
func (f *fakeNet) rootAt(partition string, block uint64) [32]byte {
	_, _, accs := f.tree(partition)
	s := sha256.Sum256(append(append([]byte(nil), accs[len(accs)-1]...), salt(partition, block)...))
	return s
}

// receiptFor is the account's path through the partition's tree to its root at block, and on to a later root.
func (f *fakeNet) receiptFor(partition string, a protocol.Account, block uint64) *merkle.Receipt {
	urls, leaves, accs := f.tree(partition)
	idx := -1
	for i, k := range urls {
		if k == strings.ToLower(a.GetUrl().String()) {
			idx = i
		}
	}
	if idx < 0 {
		f.t.Fatalf("%v is not on %s", a.GetUrl(), partition)
	}
	r := &merkle.Receipt{Start: leaves[idx]}
	r.Entries = append(r.Entries, &merkle.ReceiptEntry{Hash: accs[idx], Right: false})
	for j := idx + 1; j < len(leaves); j++ {
		r.Entries = append(r.Entries, &merkle.ReceiptEntry{Hash: leaves[j], Right: true})
	}
	r.Entries = append(r.Entries, &merkle.ReceiptEntry{Hash: salt(partition, block), Right: true})
	// And on to a later root, as a page read for a past block is served.
	r.Entries = append(r.Entries, &merkle.ReceiptEntry{Hash: salt(partition, 0xffffffff), Right: true})
	h := r.Start
	for _, e := range r.Entries {
		h = applyStep(h, e)
	}
	r.Anchor = h
	if !r.Validate(nil) {
		f.t.Fatal("the fake produced a receipt that does not validate")
	}
	return r
}

func (f *fakeNet) page(_ context.Context, account, partition string, block uint64) (*proofv2.PageState, error) {
	f.reads = append(f.reads, fmt.Sprintf("%s@%s:%d", account, partition, block))
	a, ok := f.acct[strings.ToLower(account)]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAccountMissing, account)
	}
	served := block
	if lb, ok := f.liar[partition]; ok {
		served = lb
	}
	st, err := a.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rb, err := f.receiptFor(partition, a, served).MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &proofv2.PageState{URL: account, State: hex.EncodeToString(st), Receipt: hex.EncodeToString(rb), ChainError: "g1_chain_unread: fake"}, nil
}

// log implements proofv2.AnchorLog over the fake's anchors.
type fakeLog struct{ f *fakeNet }

func (l fakeLog) Len(_ context.Context, p string) (uint64, error) {
	return uint64(len(l.f.anchors[p])), nil
}
func (l fakeLog) DNBlock(_ context.Context, p string, i uint64) (uint64, error) {
	return l.f.anchors[p][i].dn, nil
}
func (l fakeLog) Block(_ context.Context, p string, i uint64) (uint64, error) {
	return l.f.anchors[p][i].block, nil
}
func (l fakeLog) Produced(_ context.Context, p string, i uint64) (*protocol.Transaction, error) {
	a := l.f.anchors[p][i]
	pa := protocol.PartitionAnchor{
		Source: protocol.PartitionUrl(p), MinorBlockIndex: a.block, RootChainIndex: i,
		RootChainAnchor: sha256.Sum256([]byte(fmt.Sprintf("root:%s:%d", p, a.block))), StateTreeAnchor: l.f.rootAt(p, a.block)}
	if p == protocol.Directory { // the Directory is proven by the DirectoryAnchor it executes for itself
		return &protocol.Transaction{Body: &protocol.DirectoryAnchor{PartitionAnchor: pa}}, nil
	}
	return &protocol.Transaction{Body: &protocol.BlockValidatorAnchor{PartitionAnchor: pa}}, nil
}

func (f *fakeNet) collector() *Collector {
	return &Collector{
		Route: f.route,
		Block: func(context.Context, string, string) (uint64, error) { return f.block, nil },
		Position: func(context.Context, string, string, string) (*proofv2.TxPosition, error) {
			if f.noPos {
				return nil, errors.New("layer2: anchor not recorded yet")
			}
			return &proofv2.TxPosition{Block: f.block, DNBlock: f.dnBlock, StateRoot: f.rootAt(f.x, f.block)}, nil
		},
		Facts: func(context.Context, string, string) (*TxFacts, error) { return f.facts, nil },
		Log:   fakeLog{f},
		Page:  f.page,
		Anchor: func(_ context.Context, pb *proofv2.PartitionBlock) ([32]byte, error) {
			if f.noAnchor[pb.Partition] {
				return [32]byte{}, &proofv2.NamedState{Code: proofv2.StatePartitionAnchorUnavailable, Partition: pb.Partition, Block: pb.Block, Detail: "not executed by the Directory yet"}
			}
			return sha256.Sum256([]byte(fmt.Sprintf("anchortx:%s:%d", pb.Partition, pb.Block))), nil
		},
		Arrival: func(_ context.Context, id *url.TxID) (string, uint64, error) {
			a, ok := f.arrivals[id.String()]
			if !ok {
				return "", 0, fmt.Errorf("no arrival for %v", id)
			}
			return a.partition, a.block, nil
		},
		Trace: func(_ context.Context, cause *url.TxID) ([]Hop, []*url.URL, error) {
			a, ok := f.arrivals[cause.String()]
			if !ok {
				return nil, nil, fmt.Errorf("no arrival for %v", cause)
			}
			return []Hop{{Page: cause.Account(), ID: cause, Block: a.block}}, f.dels[cause.String()], nil
		},
		Certified: func(context.Context, string, string) (*url.URL, error) {
			if f.certErr != nil {
				return nil, f.certErr
			}
			return f.certify, nil
		},
		PositionWait: 20 * time.Millisecond, Poll: time.Millisecond,
	}
}

func (f *fakeNet) collect() (*Capture, error) {
	return f.collector().Collect(context.Background(), f.facts.Principal.String(), strings.Repeat("ab", 32))
}

// tclWorld: a customer's payment account on BVN1 whose authorities are its own book and a bank's book on BVN2; the bank's
// page 1 delegates to a book on BVN3.
func tclWorld() world {
	w := world{}
	w.adi("cust.acme", 1).adi("bank.acme", 2).adi("deleg.acme", 1).adi("erp.acme", 1)
	w.add(data("cust.acme", "pay", "acc://bank.acme/book", "acc://cust.acme/book"))
	w.delegate("bank.acme", "deleg.acme")
	return w
}

func pageByURL(t *testing.T, c Capture, u string) CapturedPage {
	t.Helper()
	for _, p := range c.Pages {
		if strings.EqualFold(p.URL, u) {
			return p
		}
	}
	t.Fatalf("%s was not captured: %d pages", u, len(c.Pages))
	return CapturedPage{}
}

// A page on another partition is captured at THAT partition's block - the latest anchor the Directory executed at or before
// the Directory block that executed the transaction's partition's anchor - and its receipt passes through that partition's
// anchor, not the transaction partition's.
func TestCollectForeignPageIsCapturedAtItsOwnBlock(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	// BVN2's anchors were executed at DN 480, 490, 499, 510; the transaction's anchor at DN 500: block 2019 (DN 499).
	bank := pageByURL(t, *c, "acc://bank.acme/book/2")
	if bank.Block != 2019 || bank.Partition != "acc://bvn-BVN2.acme" {
		t.Fatalf("bank page captured at block %d on %s", bank.Block, bank.Partition)
	}
	// BVN3's: DN 300, 495, 520: block 3015 (DN 495) - the delegate book.
	del := pageByURL(t, *c, "acc://deleg.acme/book/1")
	if del.Block != 3015 || del.Partition != "acc://bvn-BVN3.acme" {
		t.Fatalf("delegate page captured at block %d on %s", del.Block, del.Partition)
	}
	own := pageByURL(t, *c, "acc://cust.acme/book/1")
	if own.Block != 1000 || own.Partition != "acc://bvn-BVN1.acme" {
		t.Fatalf("own page captured at block %d on %s", own.Block, own.Partition)
	}
	for _, p := range []string{"BVN1", "BVN2", "BVN3"} {
		if _, ok := c.Partitions[p]; !ok {
			t.Fatalf("no capture record for %s: %+v", p, c.Partitions)
		}
	}
	if c.Partitions["BVN2"].Block != 2019 || c.Partitions["BVN2"].Index != 2 || c.Partitions["BVN2"].DNBlock != 499 || c.Partitions["BVN3"].Index != 1 {
		t.Fatalf("partition records: %+v", c.Partitions)
	}
	// Each page's receipt ends at its own partition's state root for its own block, and at no other.
	for _, pg := range c.Pages {
		var blockP string
		switch {
		case strings.Contains(pg.Partition, "BVN2"):
			blockP = "BVN2"
		case strings.Contains(pg.Partition, "BVN3"):
			blockP = "BVN3"
		default:
			blockP = "BVN1"
		}
		root := f.rootAt(blockP, pg.Block)
		var r merkle.Receipt
		raw, _ := hex.DecodeString(pg.Receipt)
		if err := r.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(r.Anchor, root[:]) || !r.Validate(nil) {
			t.Fatalf("%s: the stored receipt does not end at %s's root for block %d", pg.URL, blockP, pg.Block)
		}
	}
	// The roles are recorded.
	if !hasRoleOf(c, "acc://bank.acme/book/2", proofv2.RoleAuthorityPage) || !hasRoleOf(c, "acc://deleg.acme/book/1", proofv2.RoleDelegatePage) {
		t.Fatalf("roles not recorded: %+v", c.Pages)
	}
}

func hasRoleOf(c *Capture, u string, r proofv2.PageRole) bool {
	for _, p := range c.Pages {
		if strings.EqualFold(p.URL, u) {
			for _, x := range p.Roles {
				if x == r {
					return true
				}
			}
		}
	}
	return false
}

// Every read of a foreign page is made at the foreign partition's block, never the transaction's.
func TestCollectNeverReadsAForeignPartitionAtTheTransactionsBlock(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	if _, err := f.collect(); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.reads {
		if strings.Contains(r, "@BVN2:") && !strings.HasSuffix(r, ":2019") || strings.Contains(r, "@BVN3:") && !strings.HasSuffix(r, ":3015") ||
			strings.Contains(r, "@BVN1:") && !strings.HasSuffix(r, ":1000") {
			t.Fatalf("a page was read at the wrong block: %s (reads %v)", r, f.reads)
		}
	}
}

// The harbor-mfg model: the initiator and payer is a page of an unrelated identity on a third partition. It is captured at
// that partition's block.
func TestCollectInitiatorPageOfAnUnrelatedIdentityOnItsOwnPartition(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.facts.Initiators = []*url.URL{url.MustParse("acc://erp.acme/book/1")}
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	erp := pageByURL(t, *c, "acc://erp.acme/book/1")
	if erp.Block != 3015 || erp.Partition != "acc://bvn-BVN3.acme" || !hasRoleOf(c, erp.URL, proofv2.RoleInitiatorSigner) {
		t.Fatalf("initiator page: block %d on %s roles %v", erp.Block, erp.Partition, erp.Roles)
	}
}

// A node that serves a page for a block other than B_Y cannot pass it off as B_Y's: the receipt does not pass through the
// anchor's state root and the capture is refused, naming the partition and the block.
func TestCollectRefusesAPageServedForAnotherBlock(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.liar["BVN2"] = 2030 // asked for 2019, serves 2030
	c, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StatePageBlockMismatch || ns.Partition != "BVN2" || ns.Block != 2019 {
		t.Fatalf("a page served for another block gave %v", err)
	}
	// What was read before the refusal is kept, with no roles claimed.
	if c == nil || len(c.Pages) == 0 {
		t.Fatalf("the pages read before the refusal were not kept: %+v", c)
	}
}

// B_Y earlier than the arrival of a counted signature is refused: the page would predate the signature it judges.
func TestCollectRefusesABlockBeforeACountedSignaturesArrival(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	v := vote("acc://bank.acme/book", "acc://bank.acme/book/2")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2020} // after the latest admissible block, 2019
	_, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateBlockBeforeArrival || ns.Partition != "BVN2" || ns.Block != 2019 {
		t.Fatalf("B_Y before the signature's arrival gave %v", err)
	}
	// Arrival at the latest admissible block itself is fine.
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2019}
	if _, err := f.collect(); err != nil {
		t.Fatalf("arrival at B_Y was refused: %v", err)
	}
	// A signature of the transaction's own partition that arrived after the transaction's block is refused as well.
	own := vote("acc://cust.acme/book", "acc://cust.acme/book/1")
	f.facts.Votes = []VoteFact{own}
	f.arrivals[own.Cause.String()] = fakeArrival{"BVN1", 1001}
	_, err = f.collect()
	if !errors.As(err, &ns) || ns.Code != proofv2.StateBlockBeforeArrival || ns.Partition != "BVN1" || ns.Block != 1000 {
		t.Fatalf("a signature after the transaction's block gave %v", err)
	}
}

// A partition whose anchor the Directory has not executed is a named state, not a read of current state.
func TestCollectNamesAPartitionAnchorTheDirectoryHasNotExecuted(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.noAnchor["BVN2"] = true
	_, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StatePartitionAnchorUnavailable || ns.Partition != "BVN2" || ns.Block != 2019 {
		t.Fatalf("an unexecuted anchor gave %v", err)
	}
	for _, r := range f.reads {
		if strings.Contains(r, "@BVN2:") {
			t.Fatalf("BVN2 was read although its anchor is unavailable: %v", f.reads)
		}
	}
}

// If the Directory executed no anchor of the partition at or before the transaction's anchor, there is no block to read.
func TestCollectNamesAPartitionWithNoAnchorBeforeTheTransactions(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.anchors["BVN2"] = []fakeAnchor{{600, 2040}, {610, 2050}} // all after DN 500
	_, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StatePartitionAnchorUnavailable || ns.Partition != "BVN2" {
		t.Fatalf("no anchor before the transaction's gave %v", err)
	}
}

// The transaction partition's own anchor is awaited, then named when the Directory never records it.
func TestCollectNamesTheTransactionPartitionAnchorNeverRecorded(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.noPos = true
	c, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StatePartitionAnchorUnavailable || ns.Partition != "BVN1" || ns.Block != 1000 {
		t.Fatalf("a missing transaction anchor gave %v", err)
	}
	if c == nil || len(c.Pages) == 0 {
		t.Fatalf("the pages read at B were not kept")
	}
}

// A book whose page the partition cannot serve stops the capture with the page named; nothing is invented.
func TestCollectRefusesAnAuthorityBookWhosePageIsMissing(t *testing.T) {
	w := tclWorld()
	delete(w, "acc://bank.acme/book/2") // PageCount says 2
	f := newFakeNet(t, w)
	f.facts = facts("acc://cust.acme/pay")
	_, err := f.collect()
	if err == nil || !strings.Contains(err.Error(), "bank.acme/book/2") {
		t.Fatalf("a missing page gave %v", err)
	}
}

// A 2.0 evidence document carries only the transaction's partition's pages; a capture with pages elsewhere is built as evidence 2.1, and
// a proof for an intent's certificate is the named state g1_evidence_21_not_in_force until the rules that accept 2.1 are in force.
func TestPlanBuildForeignPagesNeedEvidence21(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasForeignPages() {
		t.Fatal("the cross-partition capture reports no foreign page")
	}
	_, err = planBuild(c, true, false)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateEvidence21NotInForce || ns.Block != c.Block {
		t.Fatalf("a certificate proof with foreign pages gave %v", err)
	}
	if strings.Contains(err.Error(), "g1_evidence_21_required") {
		t.Fatalf("the interim name is still emitted: %v", err)
	}
	pl, err := planBuild(c, false, false)
	if err != nil || !pl.is21 {
		t.Fatalf("the shadow builds evidence 2.1 for a foreign capture: %+v, %v", pl, err)
	}
	pl, err = planBuild(c, true, true)
	if err != nil || !pl.is21 {
		t.Fatalf("with the rules in force a certificate proof is 2.1: %+v, %v", pl, err)
	}
	if _, err := evidencePages(c); err == nil || !strings.Contains(err.Error(), "bank.acme/book") {
		t.Fatalf("2.0 pages of a foreign capture gave %v", err)
	}
	// Own-partition pages only: a 2.0 document, without 2.1 members.
	w := world{}
	w.adi("cust.acme", 1)
	w.add(data("cust.acme", "pay", "acc://cust.acme/book"))
	g := newFakeNet(t, w)
	g.facts = facts("acc://cust.acme/pay")
	c, err = g.collect()
	if err != nil {
		t.Fatal(err)
	}
	pl, err = planBuild(c, true, false)
	if err != nil || pl.is21 || len(pl.pages) != 3 {
		t.Fatalf("own-partition pages: %+v, %v", pl, err)
	}
	for _, p := range pl.pages {
		if p.Partition != "" || p.Roles != nil {
			t.Fatalf("a 2.0 page carries 2.1 members: %+v", p)
		}
	}
}

// A capture is stored as JSON; a row stored before this layout (a bare array of pages) still decodes.
func TestDecodeCaptureReadsTheLegacyArrayAndTheObject(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeCapture(raw)
	if err != nil || len(back.Pages) != len(c.Pages) || back.Partitions["BVN2"].Block != 2019 {
		t.Fatalf("object: %v %+v", err, back)
	}
	legacy, _ := json.Marshal([]*proofv2.PageState{{URL: "acc://a.acme/book/1", State: "00", Receipt: "00"}})
	old, err := DecodeCapture(legacy)
	if err != nil || len(old.Pages) != 1 || old.Version != "capture/1" || old.Pages[0].Partition != "" {
		t.Fatalf("legacy array: %v %+v", err, old)
	}
	if _, err := DecodeCapture([]byte(`{"version":"capture/9"}`)); err == nil {
		t.Fatal("an unknown capture version decoded")
	}
}

func applyStep(h []byte, e *merkle.ReceiptEntry) []byte {
	var s [32]byte
	if e.Right {
		s = sha256.Sum256(append(append([]byte(nil), h...), e.Hash...))
	} else {
		s = sha256.Sum256(append(append([]byte(nil), e.Hash...), h...))
	}
	return s[:]
}

// B_Y is the smallest admissible block at or after the latest arrival of a counted signature on the partition, never before
// it and never after the latest block the Directory had anchored when it executed the transaction's own anchor.
func TestCollectChoosesTheSmallestBlockAtOrAfterTheArrival(t *testing.T) {
	for _, tc := range []struct {
		arrival uint64
		want    uint64
	}{{0, 2019}, {1, 2000}, {2000, 2000}, {2005, 2010}, {2010, 2010}, {2011, 2019}, {2019, 2019}} {
		t.Run(fmt.Sprintf("arrival %d", tc.arrival), func(t *testing.T) {
			f := newFakeNet(t, tclWorld())
			f.facts = facts("acc://cust.acme/pay")
			if tc.arrival > 0 {
				v := vote("acc://bank.acme/book", "acc://bank.acme/book/2")
				f.facts.Votes = []VoteFact{v}
				f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", tc.arrival}
			}
			c, err := f.collect()
			if err != nil {
				t.Fatal(err)
			}
			if got := pageByURL(t, *c, "acc://bank.acme/book/2").Block; got != tc.want {
				t.Fatalf("arrival %d: pages read at %d, want %d", tc.arrival, got, tc.want)
			}
			if c.Partitions["BVN2"].Block != tc.want {
				t.Fatalf("partition record %+v", c.Partitions["BVN2"])
			}
		})
	}
}

// A block that has left the partition's retention before any page was read at it is passed over for the next admissible one.
func TestCollectAdvancesPastABlockThatLeftRetention(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	v := vote("acc://bank.acme/book", "acc://bank.acme/book/2")
	f.facts.Votes = []VoteFact{v}
	f.arrivals[v.Cause.String()] = fakeArrival{"BVN2", 2005} // smallest admissible: 2010
	col := f.collector()
	inner := col.Page
	col.Page = func(ctx context.Context, account, p string, block uint64) (*proofv2.PageState, error) {
		if p == "BVN2" && block == 2010 {
			return nil, &proofv2.NamedState{Code: proofv2.StateHistoricalUnavailable, Partition: p, Block: block, Detail: "below the retained range"}
		}
		return inner(ctx, account, p, block)
	}
	c, err := col.Collect(context.Background(), f.facts.Principal.String(), strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if got := pageByURL(t, *c, "acc://bank.acme/book/2").Block; got != 2019 {
		t.Fatalf("pages read at %d, want 2019 (2010 left retention)", got)
	}
	// With no later admissible block the named state stands.
	f.anchors["BVN2"] = []fakeAnchor{{480, 2000}, {490, 2010}, {510, 2030}}
	_, err = col.Collect(context.Background(), f.facts.Principal.String(), strings.Repeat("ab", 32))
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateHistoricalUnavailable || ns.Partition != "BVN2" || ns.Block != 2010 {
		t.Fatalf("no servable admissible block gave %v", err)
	}
}

// The certified key page is proven at its own partition, whatever role it has, and its signature's arrival bounds the block.
func TestCollectCapturesTheCertifiedKeyPageOfAnUnrelatedIdentity(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.certify = url.MustParse("acc://erp.acme/book/1")
	sig, _ := url.ParseTxID("acc://" + strings.Repeat("cd", 32) + "@erp.acme/book/1")
	f.facts.KeySigs = map[string][]*url.TxID{"acc://erp.acme/book/1": {sig}}
	f.arrivals[sig.String()] = fakeArrival{"BVN3", 3010}
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	erp := pageByURL(t, *c, "acc://erp.acme/book/1")
	if erp.Block != 3015 || !hasRoleOf(c, erp.URL, proofv2.RoleCertifiedKeyPage) {
		t.Fatalf("certified page: block %d roles %v", erp.Block, erp.Roles)
	}
	// Its signature arrived after the latest block the Directory had anchored: refused, not read at an earlier block.
	f.arrivals[sig.String()] = fakeArrival{"BVN3", 3016}
	_, err = f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateBlockBeforeArrival || ns.Partition != "BVN3" {
		t.Fatalf("a certified page's signature after B_Y gave %v", err)
	}
	// A certified page that cannot be resolved ends the capture with the named state, with every page already captured kept.
	f.arrivals[sig.String()] = fakeArrival{"BVN3", 3010}
	f.certErr = errors.New("no page of the declared book signed")
	c, err = f.collect()
	if !errors.As(err, &ns) || ns.Code != proofv2.StateCertifiedPageUnproven {
		t.Fatalf("an unresolvable certified page gave %v", err)
	}
	if c == nil || len(c.Pages) == 0 {
		t.Fatal("the captured pages were dropped with the unresolved certified page")
	}
}

// A page on the Directory is captured like any partition's (RB9 C1b-2 supersedes the g1_directory_partition_unsupported refusal this test
// pinned): with no anchor of the Directory's own recorded, it is the named state g1_partition_anchor_unavailable with the partition,
// never a read of current state. The captures that succeed are in collect_directory_test.go.
func TestCollectNamesAGoverningPageOnTheDirectory(t *testing.T) {
	w := tclWorld()
	f := newFakeNet(t, w)
	f.part["dn.acme"] = "Directory"
	w.adi("dn.acme", 1)
	w.add(data("cust.acme", "dirpay", "acc://dn.acme/book"))
	f.facts = facts("acc://cust.acme/dirpay")
	_, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StatePartitionAnchorUnavailable || ns.Partition != "Directory" {
		t.Fatalf("a Directory page with no Directory anchor gave %v", err)
	}
}

// A body type whose executor overrides who may sign is never judged by the default rule: the pages are captured and the
// capture ends with the named state.
func TestCollectNamesAnExecutorOverride(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.facts.Type = protocol.TransactionTypeUpdateKeyPage
	c, err := f.collect()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateExecutorOverrideUnsupported {
		t.Fatalf("an UpdateKeyPage gave %v", err)
	}
	if c == nil || len(c.Pages) == 0 {
		t.Fatal("the captured pages were dropped with the named state")
	}
	f.facts.Type = protocol.TransactionTypeWriteData
	if _, err := f.collect(); err != nil {
		t.Fatalf("a WriteData was refused: %v", err)
	}
}

// RB9 verifier round VA, DEF-1: the capture and the verifier read ONE table of executor-override body types. Every type of the table is
// named by the capture; the types the verifier models (UpdateAccountAuth: the default rule plus the authorities the body adds and
// RequireAuthorization) are captured.
func TestCollectRefusesEveryTypeOfTheSharedOverrideTable(t *testing.T) {
	for _, typ := range proofv2.ExecutorOverrideTypes() {
		f := newFakeNet(t, tclWorld())
		f.facts = facts("acc://cust.acme/pay")
		f.facts.Type = typ
		_, err := f.collect()
		var ns *proofv2.NamedState
		if !errors.As(err, &ns) || ns.Code != proofv2.StateExecutorOverrideUnsupported {
			t.Fatalf("%v gave %v", typ, err)
		}
	}
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	f.facts.Type = protocol.TransactionTypeUpdateAccountAuth
	if _, err := f.collect(); err != nil {
		t.Fatalf("UpdateAccountAuth, which the verifier models, was refused: %v", err)
	}
}

// RB9 verifier round VA, DEF-4: the fact of a sequenced vote carries the SequencedMessage itself, and it is the message whose hash the
// source partition's synthetic ledger holds (SeqHash), so the production of the vote can carry what the verifier binds.
func TestVoteFactCarriesTheSequencedMessageTheLedgerHolds(t *testing.T) {
	var cause [32]byte
	cause[0] = 7
	as := &protocol.AuthoritySignature{Origin: url.MustParse("acc://bank.acme/book/1"), Authority: url.MustParse("acc://bank.acme/book"), Vote: protocol.VoteTypeAccept,
		Cause: url.MustParse("acc://bank.acme/book/1").WithTxID(cause), TxID: url.MustParse("acc://cust.acme/pay").WithTxID(cause)}
	rec := &api.MessageRecord[messaging.Message]{
		ID:       url.MustParse("acc://cust.acme/pay").WithTxID(cause),
		Message:  &messaging.SignatureMessage{Signature: as, TxID: url.MustParse("acc://cust.acme/pay").WithTxID(cause)},
		Sequence: &messaging.SequencedMessage{Source: url.MustParse("acc://bvn-BVN2.acme"), Destination: url.MustParse("acc://bvn-BVN1.acme"), Number: 9},
	}
	v := voteFact(as, rec)
	if !v.Sequenced || len(v.SeqRaw) == 0 {
		t.Fatalf("sequenced %v, %d bytes", v.Sequenced, len(v.SeqRaw))
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(v.SeqRaw); err != nil {
		t.Fatal(err)
	}
	h := seq.Hash()
	if h != v.SeqHash || seq.Number != 9 || seq.Source.String() != "acc://bvn-BVN2.acme" {
		t.Fatalf("the carried message hashes to %x (SeqHash %x), number %d", h[:6], v.SeqHash[:6], seq.Number)
	}
	if mh := seq.Message.Hash(); mh != [32]byte(rec.Message.Hash()) {
		t.Fatalf("the carried message wraps %x, not the recorded %x", mh[:6], rec.Message.Hash())
	}
}
