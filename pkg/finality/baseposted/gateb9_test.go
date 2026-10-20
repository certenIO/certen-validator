// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// The builder is driven by a capture store reconstructed from the live evidence: every row the Capturer would have stored for the
// L1 blocks of a published piece of evidence (header, inbox list, transactions, the transaction-trie proof nodes root first as the
// trie walk reads them, blobs with commitment and proof, the SystemConfig nodes), and sources that serve the evidence's own
// headers, light-client chain and L2 deposits. The addendum it builds must be the published evidence.

// recDB records the nodes a proof walk reads, in order.
type recDB struct {
	db  *memorydb.Database
	got [][]byte
}

func (r *recDB) Has(k []byte) (bool, error) { return r.db.Has(k) }
func (r *recDB) Get(k []byte) ([]byte, error) {
	v, err := r.db.Get(k)
	if err == nil {
		r.got = append(r.got, common.CopyBytes(v))
	}
	return v, err
}

type hdrRec struct {
	raw    []byte
	parent [32]byte
	number uint64
}

type mapHeaders struct {
	by      map[[32]byte]hdrRec
	fail    map[[32]byte]bool
	numbers map[[32]byte]uint64 // overrides the reported number
}

func (m *mapHeaders) HeaderByHash(_ context.Context, h [32]byte) ([]byte, [32]byte, uint64, error) {
	if m.fail[h] {
		return nil, [32]byte{}, 0, errors.New("header source down")
	}
	r, ok := m.by[h]
	if !ok {
		return nil, [32]byte{}, 0, errors.New("unknown header")
	}
	n := r.number
	if o, ok := m.numbers[h]; ok {
		n = o
	}
	return r.raw, r.parent, n, nil
}

type fixedLC struct {
	lc  ethl1.LC
	err error
}

func (f fixedLC) Finalized(context.Context) (ethl1.LC, error) { return f.lc, f.err }

type fixedL2 struct {
	txs [][]byte
	err error
}

func (f fixedL2) Block(_ context.Context, n uint64) (L2BlockData, error) {
	return L2BlockData{Number: n, Txs: f.txs}, f.err
}

type headL1 struct {
	scriptL1
	headErr error
	blkErr  error
	ts      uint64
}

func (h *headL1) Head(context.Context) (uint64, error) { return 5, h.headErr }
func (h *headL1) Block(context.Context, uint64) (L1BlockData, error) {
	return L1BlockData{Timestamp: h.ts}, h.blkErr
}

type buildWorld struct {
	pins    *finality.Pins
	body    Body
	ev      []byte
	leg     Leg
	ref     finality.BlockRef
	hdrs    *mapHeaders
	store   *editStore
	l2txs   [][]byte
	blocks  map[uint64][32]byte // L1 block number -> hash, for the frame blocks
	top     uint64
	headHsh [32]byte
}

func newBuildWorld(t *testing.T, evFile, legFile string) *buildWorld {
	t.Helper()
	set := filepath.Join("testdata", SetName)
	pinsRaw, _ := readPublishedPins(set, "pins/main.json")
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	legRaw, _ := ReadFile(set, legFile)
	var leg Leg
	if err := json.Unmarshal(legRaw, &leg); err != nil {
		t.Fatal(err)
	}
	num, _ := strconv.ParseUint(leg.Number, 10, 64)
	hdr, _ := hex.DecodeString(strings.TrimPrefix(leg.Header, "0x"))
	hb, _ := hex.DecodeString(strings.TrimPrefix(leg.Hash, "0x"))
	var hash [32]byte
	copy(hash[:], hb)
	ev, err := ReadFile(set, evFile)
	if err != nil {
		t.Fatal(err)
	}
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, err := DecodeBody(c.Body, finality.DefaultLimits(), EthL1Pins(pins), 32)
	if err != nil {
		t.Fatal(err)
	}
	w := &buildWorld{pins: pins, body: body, ev: ev, leg: leg, ref: finality.BlockRef{Chain: uint64(Chain), Number: num, Hash: hash, HeaderRLP: hdr},
		hdrs: &mapHeaders{by: map[[32]byte]hdrRec{}, fail: map[[32]byte]bool{}, numbers: map[[32]byte]uint64{}}, store: newEditStore(), blocks: map[uint64][32]byte{}}
	byNum := map[uint64]finality.HeaderFields{}
	rawByNum := map[uint64][]byte{}
	for _, raw := range body.L1Spine {
		h, err := finality.ReadHeader(raw)
		if err != nil {
			t.Fatal(err)
		}
		w.hdrs.by[h.Hash] = hdrRec{raw: raw, parent: h.ParentHash, number: h.Number}
		byNum[h.Number] = h
		rawByNum[h.Number] = raw
		if h.Number > w.top {
			w.top, w.headHsh = h.Number, h.Hash
		}
	}
	// the node database of the evidence, walked the way the verifier walks it
	db := memorydb.New()
	for _, n := range body.Nodes {
		_ = db.Put(crypto.Keccak256(n), n)
	}
	txProof := map[string]bool{}
	perBlock := map[uint64][]uint32{}
	ctx := context.Background()
	for _, f := range body.Frames {
		h := byNum[f.L1Block]
		w.blocks[f.L1Block] = h.Hash
		key := CaptureKey{Chain: uint64(Chain), L1Block: f.L1Block, L1Hash: h.Hash}
		put := func(item string, data []byte) {
			k := key
			k.Item = item
			if err := w.store.Put(ctx, k, data); err != nil {
				t.Fatal(err)
			}
		}
		put(ItemHeader, rawByNum[f.L1Block])
		perBlock[f.L1Block] = append(perBlock[f.L1Block], f.TxIndex)
		put(ItemTx(f.TxIndex), f.TxRaw)
		rec := &recDB{db: db}
		idxKey, _ := rlp.EncodeToBytes(uint64(f.TxIndex))
		if _, err := trie.VerifyProof(common.Hash(h.TransactionRoot), idxKey, rec); err != nil {
			t.Fatal(err)
		}
		var pw finality.Writer
		pw.LPList(rec.got)
		put(ItemTxNodes(f.TxIndex), pw.Bytes())
		for _, n := range rec.got {
			txProof[string(n)] = true
		}
		for j, bl := range f.Blobs {
			var bw finality.Writer
			bw.LP(bl.Raw)
			bw.Fixed(bl.Commitment[:])
			bw.Fixed(bl.Proof[:])
			put(ItemBlob(f.TxIndex, j), bw.Bytes())
		}
	}
	var sys [][]byte
	for _, n := range body.Nodes {
		if !txProof[string(n)] {
			sys = append(sys, n)
		}
	}
	for blk, idx := range perBlock {
		key := CaptureKey{Chain: uint64(Chain), L1Block: blk, L1Hash: byNum[blk].Hash}
		var iw finality.Writer
		iw.Count(len(idx))
		for _, i := range idx {
			iw.U32(i)
		}
		var sw finality.Writer
		sw.LPList(sys)
		for item, data := range map[string][]byte{ItemInbox: iw.Bytes(), ItemSysCfg: sw.Bytes()} {
			k := key
			k.Item = item
			if err := w.store.Put(ctx, k, data); err != nil {
				t.Fatal(err)
			}
		}
	}
	w.l2txs = append(append([][]byte(nil), body.Deposits...), []byte{0x02, 0xc0})
	return w
}

func (w *buildWorld) builder() *Builder {
	return &Builder{Pins: w.pins, Store: w.store, L1: &headL1{ts: 1655733600 + 12*11395880}, Headers: w.hdrs, L2: fixedL2{txs: w.l2txs}, LC: fixedLC{lc: w.body.LC},
		Now: func() time.Time { return time.Unix(0, 0) }}
}

func (w *buildWorld) build(t *testing.T, b *Builder) (*finality.Addendum, *finality.PendingState, error) {
	t.Helper()
	return b.Build(context.Background(), &ethproof.Settlement{Header: w.ref.HeaderRLP}, 0, finality.LevelL1Posted)
}

func TestTheBuilderRebuildsThePublishedEvidenceFromTheCapturedRows(t *testing.T) {
	for _, c := range []struct{ ev, leg string }{{"evidence/valid_a.bin", "legs/a.json"}, {"evidence/valid_b.bin", "legs/b.json"}} {
		w := newBuildWorld(t, c.ev, c.leg)
		ad, pend, err := w.build(t, w.builder())
		if err != nil || pend != nil || ad == nil {
			t.Fatalf("%s: %v %v %v", c.ev, ad, pend, err)
		}
		if ad.Level != finality.LevelL1Posted || ad.Chain != uint64(Chain) || ad.Kind != KindName {
			t.Fatalf("%+v", ad)
		}
		if !bytes.Equal(ad.Evidence, w.ev) {
			// the same facts in another byte order would still be the same container: compare the decoded bodies
			c1, _ := finality.DecodeContainer(ad.Evidence, finality.DefaultLimits())
			got, err := DecodeBody(c1.Body, finality.DefaultLimits(), EthL1Pins(w.pins), 32)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Frames) != len(w.body.Frames) || len(got.Nodes) != len(w.body.Nodes) || got.ChannelID != w.body.ChannelID || len(got.L1Spine) != len(w.body.L1Spine) {
				t.Fatalf("%s: rebuilt %d frames %d nodes, published %d frames %d nodes", c.ev, len(got.Frames), len(got.Nodes), len(w.body.Frames), len(w.body.Nodes))
			}
			t.Fatalf("%s: the rebuilt evidence differs from the published one although the facts agree", c.ev)
		}
	}
}

func TestTheBuilderListsTheCompleteChannelsOfTheCapturedRows(t *testing.T) {
	w := newBuildWorld(t, "evidence/valid_a.bin", "legs/a.json")
	chs, err := w.builder().Channels(context.Background())
	if err != nil || len(chs) != 1 {
		t.Fatalf("%d channels, %v", len(chs), err)
	}
	ci := chs[0]
	if ci.ID != w.body.ChannelID || len(ci.Timestamps) != 68 || len(ci.L1Blocks) != len(w.body.Frames) {
		t.Fatalf("%+v", ci)
	}
	for _, b := range ci.L1Blocks {
		if b != 11954001 {
			t.Fatalf("l1 blocks %v", ci.L1Blocks)
		}
	}
	for i := 1; i < len(ci.Timestamps); i++ {
		if ci.Timestamps[i]-ci.Timestamps[i-1] != 2 {
			t.Fatalf("timestamps %v", ci.Timestamps)
		}
	}
	l2, _ := finality.ReadHeader(w.ref.HeaderRLP)
	found := false
	for _, ts := range ci.Timestamps {
		found = found || ts == l2.Timestamp
	}
	if !found {
		t.Fatal("the leg block's timestamp is not among the channel's batches")
	}
	// an incomplete channel (its first frame missing) and an empty store list nothing
	empty := &Builder{Pins: w.pins, Store: NewMemStore()}
	if chs, err = empty.Channels(context.Background()); err != nil || len(chs) != 0 {
		t.Fatalf("%v %v", chs, err)
	}
	// two channels of one capture are listed in capture order: add the second evidence's rows
	wb := newBuildWorld(t, "evidence/valid_b.bin", "legs/b.json")
	both := NewMemStore()
	for _, src := range []*editStore{w.store, wb.store} {
		for k, v := range src.rows {
			if err := both.Put(context.Background(), k, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	chs, err = (&Builder{Pins: w.pins, Store: both}).Channels(context.Background())
	if err != nil || len(chs) != 2 || chs[0].ID == chs[1].ID {
		t.Fatalf("%d channels, %v", len(chs), err)
	}
	ids := []string{fmt.Sprintf("%x", chs[0].ID), fmt.Sprintf("%x", chs[1].ID)}
	sort.Strings(ids)
	if ids[0] != "ad691fdbeabedfc7f4a1c37935fac007" || ids[1] != "d93d2e4441cfd303952a39563bc67e61" {
		t.Fatalf("channel ids %v", ids)
	}
	// the first of them (capture order is by L1 block, then hash) is the one captured at the lower L1 block
	if chs[0].L1Blocks[0] != 11954001 || chs[1].L1Blocks[0] != 11954013 {
		t.Fatalf("capture order %v %v", chs[0].L1Blocks, chs[1].L1Blocks)
	}
}

func wantPending(t *testing.T, pend *finality.PendingState, err error, reason string) *finality.PendingState {
	t.Helper()
	if err != nil || pend == nil || pend.Reason != reason || pend.Chain != uint64(Chain) || pend.LevelReached != finality.LevelIncluded || pend.NextLevel != finality.LevelL1Posted {
		t.Fatalf("want pending %s, got %+v %v", reason, pend, err)
	}
	return pend
}

func TestTheBuilderNamesWhyEvidenceCannotBeBuiltYetOrAtAll(t *testing.T) {
	w := newBuildWorld(t, "evidence/valid_a.bin", "legs/a.json")
	l2, _ := finality.ReadHeader(w.ref.HeaderRLP)
	// no channel covers the timestamp: pending, with the highest captured block
	pend := func(b *Builder, hdr []byte) (*finality.Addendum, *finality.PendingState, error) {
		return b.Build(context.Background(), &ethproof.Settlement{Header: hdr}, 0, finality.LevelL1Posted)
	}
	other := newBuildWorld(t, "evidence/valid_a_timestamp_outside.bin", "legs/a_timestamp_outside.json")
	_, p, err := pend(w.builder(), other.ref.HeaderRLP)
	p = wantPending(t, p, err, "l1_posted_unproven")
	if fmt.Sprint(p.Judged["last_scanned_l1"]) != "11954001" || p.Judged["l2_timestamp"] == nil {
		t.Fatalf("%+v", p.Judged)
	}
	// the finalized head's spine does not reach the frame block yet: the head is reported with the slot of the observed L1 head
	low := w.builder()
	lowH := &mapHeaders{by: w.hdrs.by, fail: w.hdrs.fail, numbers: map[[32]byte]uint64{w.headHsh: 11954000}}
	low.Headers = lowH
	_, p, err = w.build(t, low)
	p = wantPending(t, p, err, "block_not_yet_covered")
	es, _ := w.pins.Sepolia()
	wantSlot := (uint64(1655733600+12*11395880) - es.GenesisTime) / 12
	head, herr := ethl1.VerifyFinalizedHead(EthL1Pins(w.pins), w.body.LC)
	if herr != nil {
		t.Fatal(herr)
	}
	if fmt.Sprint(p.Judged["latest_finalized_exec_number"]) != "11954000" || fmt.Sprint(p.Judged["latest_finalized_slot"]) != fmt.Sprint(head.Slot) || fmt.Sprint(p.Judged["observed_head_slot"]) != fmt.Sprint(wantSlot) {
		t.Fatalf("%+v want slot %d", p.Judged, wantSlot)
	}
	// an observed head that cannot be read is slot 0, never a guess
	for name, l1 := range map[string]*headL1{
		"head unreadable":  {headErr: errors.New("down"), ts: 1655733600 + 12*11395880},
		"block unreadable": {blkErr: errors.New("down"), ts: 1655733600 + 12*11395880},
		"before genesis":   {ts: es.GenesisTime - 1},
	} {
		b := w.builder()
		b.Headers = lowH
		b.L1 = l1
		_, p, err = w.build(t, b)
		p = wantPending(t, p, err, "block_not_yet_covered")
		if fmt.Sprint(p.Judged["observed_head_slot"]) != "0" {
			t.Fatalf("%s: %+v", name, p.Judged)
		}
	}

	// refusals, each a named state and none a weaker answer
	fail := func(name string, mod func(b *Builder, store *editStore), code string, fields map[string]string) {
		t.Helper()
		ww := newBuildWorld(t, "evidence/valid_a.bin", "legs/a.json")
		b := ww.builder()
		mod(b, ww.store)
		ad, p, err := ww.build(t, b)
		if ad != nil || p != nil {
			t.Fatalf("%s: %v %v", name, ad, p)
		}
		wantCode(t, err, code, fields)
	}
	fail("lc source down", func(b *Builder, _ *editStore) { b.LC = fixedLC{err: errors.New("lodestar down")} }, "finality_source_unavailable", map[string]string{"reason": "lc"})
	bad := w.body.LC
	bad.FinalUpdate.SSZ = append([]byte(nil), bad.FinalUpdate.SSZ...)
	bad.FinalUpdate.SSZ[40] ^= 1
	_, innerErr := ethl1.VerifyFinalizedHead(EthL1Pins(w.pins), bad)
	var innerCode string
	if f, ok := innerErr.(*ethl1.Fault); ok {
		innerCode = f.Code
	}
	if innerCode == "" {
		t.Fatalf("test assumption: a flipped final update is a fault, got %v", innerErr)
	}
	fail("lc refused", func(b *Builder, _ *editStore) { b.LC = fixedLC{lc: bad} }, CodeL1FinalityUnproven, map[string]string{"reason": LCRefused, "inner": innerCode})
	fail("head header unreadable", func(b *Builder, _ *editStore) {
		b.Headers = &mapHeaders{by: w.hdrs.by, fail: map[[32]byte]bool{w.headHsh: true}}
	}, "finality_source_unavailable", map[string]string{"reason": "l1_header"})
	var below [32]byte
	for h, r := range w.hdrs.by {
		if r.number == 11954001 {
			below = h
		}
	}
	fail("a spine header unreadable", func(b *Builder, _ *editStore) {
		b.Headers = &mapHeaders{by: w.hdrs.by, fail: map[[32]byte]bool{below: true}}
	}, "finality_source_unavailable", map[string]string{"reason": "l1_header"})
	fail("a spine header of another number", func(b *Builder, _ *editStore) {
		b.Headers = &mapHeaders{by: w.hdrs.by, fail: w.hdrs.fail, numbers: map[[32]byte]uint64{below: 7}}
	}, "finality_source_unavailable", map[string]string{"reason": "l1_header"})
	fail("a captured block that is not on the finalized chain", func(b *Builder, store *editStore) {
		// a snapshot first: a map changed while it is ranged over may show the new keys again
		old := make(map[CaptureKey][]byte, len(store.rows))
		for k, v := range store.rows {
			old[k] = v
		}
		store.rows = map[CaptureKey][]byte{}
		for k, v := range old {
			k.L1Hash[0] ^= 1
			store.rows[k] = v
		}
	}, "l1_proof_window_unavailable", map[string]string{"l1_block": "11954001"})
	fail("l2 block unreadable", func(b *Builder, _ *editStore) { b.L2 = fixedL2{err: errors.New("down")} }, "l2_header_unavailable", map[string]string{"block": strconv.FormatUint(l2.Number, 10)})
	// a first L2 transaction that is no deposit gives a body with no deposits, which the verifier refuses on its own terms
	fail("no deposit first", func(b *Builder, _ *editStore) { b.L2 = fixedL2{txs: [][]byte{{0x02, 0xc0}}} }, CodeBatchBindingMismatch, map[string]string{"field": "l1_info_deposit"})
	fail("an empty first transaction", func(b *Builder, _ *editStore) { b.L2 = fixedL2{txs: [][]byte{{}}} }, CodeBatchBindingMismatch, map[string]string{"field": "l1_info_deposit"})
	// deposits are the leading 0x7e transactions only: a deposit after a user transaction is not one of the block's
	if len(w.body.Deposits) != 1 {
		t.Fatalf("test assumption: the live block has one deposit, got %d", len(w.body.Deposits))
	}
	trail := w.builder()
	trail.L2 = fixedL2{txs: [][]byte{w.body.Deposits[0], {0x02, 0xc0}, w.body.Deposits[0]}}
	if ad, p, err := w.build(t, trail); err != nil || p != nil || ad == nil || !bytes.Equal(ad.Evidence, w.ev) {
		t.Fatalf("%v %v %v", ad, p, err)
	}
	// rows the builder reads at the end of the build
	rowOf := func(store *editStore, item string) CaptureKey {
		for k := range store.rows {
			if k.Item == item {
				return k
			}
		}
		t.Fatalf("no row %s", item)
		return CaptureKey{}
	}
	failText := func(name string, mod func(store *editStore), want string) {
		t.Helper()
		ww := newBuildWorld(t, "evidence/valid_a.bin", "legs/a.json")
		mod(ww.store)
		ad, p, err := ww.build(t, ww.builder())
		if ad != nil || p != nil || err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v %v %v, want an error with %q", name, ad, p, err, want)
		}
	}
	failText("transaction nodes row missing", func(store *editStore) { delete(store.rows, rowOf(store, ItemTxNodes(w.body.Frames[0].TxIndex))) }, "txnodes/")
	failText("inbox row vanished", func(store *editStore) { delete(store.rows, rowOf(store, ItemTx(w.body.Frames[0].TxIndex))) }, "tx/")
	_ = binary.BigEndian
}
