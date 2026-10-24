// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// ---- determinism across validators (class 11) ----

// equalRows compares the index rows of two stores. The cursor rows are the progress of the steps (one row per cursor value, so a slower
// indexer writes more of them): they are compared by their highest block only.
func equalRows(t *testing.T, a, b map[finality.CaptureKey][]byte) {
	t.Helper()
	top := func(m map[finality.CaptureKey][]byte) (hi uint64, rest map[finality.CaptureKey][]byte) {
		rest = map[finality.CaptureKey][]byte{}
		for k, v := range m {
			if strings.HasSuffix(k.Item, "/cursor") {
				if k.L1Block > hi {
					hi = k.L1Block
				}
				continue
			}
			rest[k] = v
		}
		return hi, rest
	}
	ha, a := top(a)
	hb, b := top(b)
	if ha != hb {
		t.Fatalf("the cursors end at %d and %d", ha, hb)
	}
	if len(a) != len(b) {
		t.Fatalf("%d rows against %d", len(a), len(b))
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || !bytes.Equal(v, w) {
			t.Fatalf("row %s differs (%d B against %d B, present %v)", k, len(v), len(w), ok)
		}
	}
}

// Two indexers with different step sizes, over rows that arrive in different orders and at different times, write the same bytes.
func TestRB12ArbIndexBytesAreAFunctionOfTheCapturedRowsOnly(t *testing.T) {
	eager, _ := ixPopulation(t)
	eager.index(IndexConfig{BlocksPerStep: 1 << 20})
	// one block per step
	slow := newIxWorld(t)
	slowSrc, _ := ixPopulation(t)
	for _, k := range sortedKeys(slowSrc.allCaptureKeys()) {
		b, _, _ := slowSrc.store.Get(context.Background(), k)
		slow.put(k, b)
	}
	slow.top, slow.low = slowSrc.top, slowSrc.low
	slow.index(IndexConfig{BlocksPerStep: 1, ReconcileEvery: 1})
	equalRows(t, eager.indexRows(), slow.indexRows())

	// the rows arrive in a random order, with a step after every few of them, and the data rows (blobs) last
	late := newIxWorld(t)
	src, _ := ixPopulation(t)
	// the capturer stores the header, the batch record and the calldata of a block as ONE unit and the blob rows afterwards, one by one
	groupOf := map[finality.CaptureKey][]finality.CaptureKey{}
	var order []finality.CaptureKey
	var blobRows []finality.CaptureKey
	for _, k := range src.allCaptureKeys() {
		if strings.HasPrefix(k.Item, "blob/") {
			blobRows = append(blobRows, k)
			continue
		}
		bk := withItem(k, "")
		if _, seen := groupOf[bk]; !seen {
			order = append(order, bk)
		}
		groupOf[bk] = append(groupOf[bk], k)
	}
	rng := rand.New(rand.NewSource(7))
	rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	// the arrival order: the units shuffled, every blob row at a random place after its unit; a step after some of the chunks, never inside one
	var chunks [][]finality.CaptureKey
	pos := map[finality.CaptureKey]int{}
	for _, bk := range order {
		chunks = append(chunks, groupOf[bk])
		pos[bk] = len(chunks) - 1
	}
	rng.Shuffle(len(blobRows), func(i, j int) { blobRows[i], blobRows[j] = blobRows[j], blobRows[i] })
	for _, k := range blobRows {
		u := pos[withItem(k, "")]
		at := u + 1 + rng.Intn(len(chunks)-u)
		chunks = append(chunks, nil)
		copy(chunks[at+1:], chunks[at:])
		chunks[at] = []finality.CaptureKey{k}
		for bk, p := range pos {
			if p >= at {
				pos[bk] = p + 1
			}
		}
	}
	late.top, late.low = src.top, src.low
	late.cursor(late.low - 1)
	late.cursor(late.top + 1)
	ix := late.indexer(IndexConfig{BlocksPerStep: 3, ReconcileEvery: 1, RecentSpan: 1 << 20})
	for i, chunk := range chunks {
		for _, k := range chunk {
			b, _, _ := src.store.Get(context.Background(), k)
			late.put(k, b)
		}
		if i%3 == 0 {
			if _, err := ix.Step(context.Background(), late.top+1); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < 400; i++ {
		if _, err := ix.Step(context.Background(), late.top+1); err != nil {
			t.Fatal(err)
		}
	}
	// a row set that arrived out of order is indexed to the same bytes, except where a block was seen while incomplete and is still waiting for the
	// recent window: compare after the indexer has had every chance
	equalRows(t, eager.indexRows(), late.indexRows())
}

func (w *ixWorld) allCaptureKeys() []finality.CaptureKey {
	ks, err := w.store.ListByRange(context.Background(), ixChain, 0, finality.MaxCaptureBlock, "")
	if err != nil {
		w.t.Fatal(err)
	}
	var out []finality.CaptureKey
	for _, k := range ks {
		if !strings.HasPrefix(k.Item, "idx/") {
			out = append(out, k)
		}
	}
	return out
}

// A different row under an index key is the named conflict, never an overwrite and never ignored.
func TestRB12ArbIndexConflictingRowIsTheNamedError(t *testing.T) {
	w, _ := ixPopulation(t)
	w.index(IndexConfig{})
	ek := w.entryKey(203)
	if err := finality.IndexPut(context.Background(), w.store, FamilyArb, ek, []byte("another row")); !errors.Is(err, finality.ErrIndexConflict) {
		t.Fatalf("a different row under an entry key: %v", err)
	}
	// the same bytes are a no-op
	good, _, _ := w.store.Get(context.Background(), ek)
	if err := finality.IndexPut(context.Background(), w.store, FamilyArb, ek, good); err != nil {
		t.Fatal(err)
	}
	// an indexer that finds a conflicting row where it must write stops with the named error
	v, _ := ixPopulation(t)
	v.cursor(v.low - 1)
	v.cursor(v.top + 1)
	v.put(v.entryKeyOf(203, 1), []byte("planted"))
	ix := v.indexer(IndexConfig{})
	var err error
	for i := 0; i < 50 && err == nil; i++ {
		_, err = ix.Step(context.Background(), v.top)
	}
	if !errors.Is(err, finality.ErrIndexConflict) {
		t.Fatalf("the planted row did not stop the indexer by name: %v", err)
	}
}

// entryKeyOf is the key an entry of batch n would have at generation gen, from the world's own batch (no index needed).
func (w *ixWorld) entryKeyOf(n uint64, gen uint32) finality.CaptureKey {
	k := w.keys[n][0]
	rec := w.recs[k]
	return withItem(k, entryItem(gen, rec.Header40[0], rec.Header40[1], n))
}

// ---- the authorization: ONE rule, every reader (the F19 analog) ----

// proof stores the near-head proof of batch n at proof block p showing acc at Bridge.sequencerInboxAccs[n], with the header row of p.
func (w *ixWorld) proof(n uint64, acc common.Hash, p uint64) {
	w.t.Helper()
	st := newSynthState(w.t, map[uint64]common.Hash{n: acc}, nil)
	hdr, hash := ixHeader(p, 1_790_100_000+p, st.root)
	key := finality.CaptureKey{Chain: ixChain, L1Block: p, L1Hash: hash}
	w.put(withItem(key, capture.ItemHeader), hdr)
	pr := capture.ProofRecord{Kind: capture.ProofBatchAcc, Index: n, ProofBlock: p, ProofBlockHash: hash, Bridge: common.Address(w.arb.bridge), Nodes: st.nodes}
	w.put(withItem(key, capture.ItemProof(n)), pr.Encode())
	if p > w.top {
		w.top = p
	}
}

type authCase struct {
	n       uint64
	setup   func(w *ixWorld, rec capture.BatchRecord)
	verdict capture.Authorization
}

// The capture's rule (AuthorizeBatch), the reference reader and the indexed reader serve exactly the same records; the writer indexes all of them.
func TestRB12ArbAuthorizationIsOneRuleForEveryReader(t *testing.T) {
	w := newIxWorld(t)
	cases := []authCase{
		{300, func(w *ixWorld, r capture.BatchRecord) { w.proof(300, r.AfterAcc, r.L1Block+3) }, capture.AuthProven},
		{301, func(w *ixWorld, r capture.BatchRecord) { w.proof(301, common.Hash{9, 9}, r.L1Block+3) }, capture.AuthForeign},
		{302, func(w *ixWorld, r capture.BatchRecord) {}, capture.AuthUnproven},
		{303, func(w *ixWorld, r capture.BatchRecord) { w.proof(303, common.Hash{}, r.L1Block+3) }, capture.AuthForeign},   // the chain holds no batch 303
		{304, func(w *ixWorld, r capture.BatchRecord) { w.proof(304, common.Hash{7}, r.L1Block-1) }, capture.AuthUnproven}, // a proof BELOW the batch's block says nothing
		{305, func(w *ixWorld, r capture.BatchRecord) {
			w.proof(305, common.Hash{7}, r.L1Block+3)
			w.proof(305, r.AfterAcc, r.L1Block+9)
		}, capture.AuthProven}, // one proof confirms it
	}
	var legs [][][]byte
	for i, c := range cases {
		w.add(ixBatch{N: c.n, Block: 1000 + uint64(8*i), T: ixT0 + uint64(96*i), Msgs: [][][]byte{ixMsg(ixTx(30000 + i))}})
		legs = append(legs, [][]byte{ixTx(30000 + i)})
	}
	for _, c := range cases {
		k := w.keys[c.n][0]
		c.setup(w, w.recs[k])
	}
	w.index(IndexConfig{})
	r := w.reader()
	entries := map[uint64]bool{}
	for k := range w.indexRows() {
		if nm, ok := parseEntryName(1, k); ok {
			entries[nm.N] = true
		}
	}
	for i, c := range cases {
		rec := w.recs[w.keys[c.n][0]]
		views, err := capture.LoadProofViews(context.Background(), w.store, ixChain, c.n, rec.L1Block)
		if err != nil {
			t.Fatal(err)
		}
		got := capture.AuthorizeBatch(rec, w.arb.bridge, w.arb.Layout.AccArraySlot, views)
		if got != c.verdict {
			t.Errorf("batch %d: AuthorizeBatch says %s, want %s", c.n, got, c.verdict)
		}
		keep := c.verdict != capture.AuthForeign
		ts := ixT0 + uint64(96*i) + 10
		ref, idx := w.ref(ts, legs[i]), w.idx(r, ts, legs[i])
		if (ref.N == c.n) != keep || ref != idx {
			t.Errorf("batch %d: the reference serves %s, the index %s, the rule keeps %v", c.n, ref, idx, keep)
		}
		if !entries[c.n] {
			t.Errorf("batch %d: the index writer made no entry: the writer indexes every record the block holds (whether a proof has arrived is not a fact of the rows), the readers authorize", c.n)
		}
	}
}

// A reorg twin that the Bridge does not hold must not shadow the one it holds, whichever sorts first.
func TestRB12ArbForeignTwinNeverShadowsTheBatchTheBridgeHolds(t *testing.T) {
	for _, provenTag := range []byte{0, 1} {
		w := newIxWorld(t)
		msgs := [][][]byte{ixMsg(ixTx(31000))}
		w.add(ixBatch{N: 400, Block: 1000, T: ixT0, Msgs: msgs, AccTag: 0})
		w.add(ixBatch{N: 400, Block: 1000, T: ixT0, Tag: 1, Msgs: msgs, AccTag: 1})
		var proven finality.CaptureKey
		for _, k := range w.keys[400] {
			if (provenTag == 0) == (k.L1Hash == w.keys[400][0].L1Hash) {
				proven = k
			}
		}
		w.proof(400, w.recs[proven].AfterAcc, 1005)
		w.index(IndexConfig{})
		leg := [][]byte{ixTx(31000)}
		ref, idx := w.ref(ixT0+10, leg), w.idx(w.reader(), ixT0+10, leg)
		if ref != idx || ref.N != 400 || ref.Block != 1000 {
			t.Fatalf("tag %d: reference %s, index %s", provenTag, ref, idx)
		}
		b := &Builder{Store: w.store, Pins: w.pins, Index: w.reader()}
		loc, _, err := b.Index.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 10}, standardTxs(leg), w.arb)
		if err != nil || loc == nil || loc.rec.L1Hash != proven.L1Hash {
			t.Fatalf("tag %d: the index serves %x, the Bridge holds %x (%v)", provenTag, loc.rec.L1Hash[:4], proven.L1Hash[:4], err)
		}
		bb := &Builder{Store: w.store, Pins: w.pins}
		batches, _ := capture.LoadBatches(context.Background(), w.store, ixChain)
		rl, err := bb.locate(context.Background(), batches, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 10}, leg, w.arb)
		if err != nil || rl == nil || rl.rec.L1Hash != proven.L1Hash {
			t.Fatalf("tag %d: the reference serves %v, the Bridge holds %x (%v)", provenTag, rl, proven.L1Hash[:4], err)
		}
	}
}

// ---- late data: a batch whose data rows arrive after the cursor passed its block ----

func TestRB12ArbIndexFindsABatchWhoseBlobsArriveAfterTheCursorPassedIt(t *testing.T) {
	w, legs := ixPopulation(t)
	// batch 220 has three... blobs: only the first is stored when the cursor passes
	big := make([][][]byte, 0)
	for j := 0; j < 500; j++ {
		big = append(big, ixMsg(ixBigTx(40000+j, 700)))
	}
	full := newIxWorld(t) // the same batch stored whole from the start, for the bytes
	full.add(ixBatch{N: 220, Block: 1200, T: ixT0 + 2000, Msgs: big})
	rows := len(encodeBlobs(ixPayload(big)))
	if rows < 2 {
		t.Fatalf("the test batch needs several blobs, it has %d", rows)
	}
	key := w.add(ixBatch{N: 220, Block: 1200, T: ixT0 + 2000, Msgs: big, Blobs: 1, Partial: true})
	w.index(IndexConfig{})
	leg := [][]byte{ixBigTx(40010, 700)}
	ts := uint64(ixT0 + 2010)
	ref, idx := w.ref(ts, leg), w.idx(w.reader(), ts, leg)
	if ref != idx || !strings.Contains(ref.State, `"code":"l1_blob_unavailable"`) {
		t.Fatalf("while a blob is missing: reference %s, index %s", ref, idx)
	}
	for k := range w.indexRows() {
		if nm, ok := parseEntryName(1, k); ok && nm.N == 220 {
			t.Fatalf("an entry exists for a batch with a blob row missing: %s", k)
		}
	}
	// the other blob rows arrive; the cursor is long past; the next steps (the recent window) index the block
	ix := w.indexer(IndexConfig{RecentSpan: 1 << 20})
	for j := 1; j < rows; j++ {
		blobs := encodeBlobs(ixPayload(big))
		w.put(withItem(key, capture.ItemBlob(220, j)), capture.BlobRecord{Raw: blobs[j]}.Encode())
	}
	if _, err := ix.Step(context.Background(), w.top); err != nil {
		t.Fatal(err)
	}
	ref, idx = w.ref(ts, leg), w.idx(w.reader(), ts, leg)
	if ref != idx || ref.N != 220 {
		t.Fatalf("after the blobs arrived: reference %s, index %s", ref, idx)
	}
	// the entry and digest are the bytes an indexer writes for a batch that was whole from the start
	full.index(IndexConfig{})
	var a, b []byte
	for k, v := range w.indexRows() {
		if nm, ok := parseEntryName(1, k); ok && nm.N == 220 {
			a = v
		}
	}
	for k, v := range full.indexRows() {
		if nm, ok := parseEntryName(1, k); ok && nm.N == 220 {
			b = v
		}
	}
	if len(a) == 0 || !bytes.Equal(a, b) {
		t.Fatalf("the entry of the late batch differs from the eager one (%d B against %d B)", len(a), len(b))
	}
	_ = legs
}

// The note of the capture loop (blobs stored) indexes the block at the next step without waiting for the recent window to come round.
func TestRB12ArbIndexNoteLateIndexesTheBlockAtTheNextStep(t *testing.T) {
	w, _ := ixPopulation(t)
	big := make([][][]byte, 0)
	for j := 0; j < 500; j++ {
		big = append(big, ixMsg(ixBigTx(41000+j, 700)))
	}
	key := w.add(ixBatch{N: 221, Block: 1210, T: ixT0 + 2100, Msgs: big, Blobs: 1, Partial: true})
	ix := w.index(IndexConfig{RecentSpan: 1}) // the recent window is one block: only the note can find it
	blobs := encodeBlobs(ixPayload(big))
	for j := 1; j < len(blobs); j++ {
		w.put(withItem(key, capture.ItemBlob(221, j)), capture.BlobRecord{Raw: blobs[j]}.Encode())
	}
	if _, err := ix.Step(context.Background(), w.top); err != nil {
		t.Fatal(err)
	}
	if o := w.idx(w.reader(), ixT0+2110, [][]byte{ixBigTx(41010, 700)}); o.N != 0 {
		t.Fatalf("found before the note, with a one-block recent window: %s", o)
	}
	ix.NoteLate(1210)
	if _, err := ix.Step(context.Background(), w.top); err != nil {
		t.Fatal(err)
	}
	if o := w.idx(w.reader(), ixT0+2110, [][]byte{ixBigTx(41010, 700)}); o.N != 221 {
		t.Fatalf("not found after the note: %s", o)
	}
}

// ---- unreadable rows and holes ----

// A batch row that does not decode does not stall the index: it is recorded as unindexable, the cursor passes it, later batches are indexed, and a
// leg that is not found and whose window holds the block is told by name.
func TestRB12ArbIndexUnreadableBatchRowIsRecordedAndDoesNotStall(t *testing.T) {
	w, legs := ixPopulation(t)
	hdr, hash := ixHeader(1090, ixT0+800, common.Hash{0xee})
	bad := finality.CaptureKey{Chain: ixChain, L1Block: 1090, L1Hash: hash}
	w.put(withItem(bad, capture.ItemHeader), hdr)
	w.put(withItem(bad, capture.ItemBatch(250)), []byte("not a batch record"))
	w.index(IndexConfig{})
	if _, hi, ok, _ := finality.ReadIndexCursor(context.Background(), w.store, ixChain, 1, FamilyArb); !ok || hi != w.top+1 {
		t.Fatalf("the cursor stopped at %d (ok %v), the capture is at %d", hi, ok, w.top)
	}
	rec, _, _ := w.store.Get(context.Background(), withItem(bad, unindexedItem(1)))
	if string(rec) != finality.UnindexableBatchRowMalformed {
		t.Fatalf("the record of the unreadable block is %q", rec)
	}
	// the batches after it are served
	r := w.reader()
	b := &Builder{Store: w.store, Pins: w.pins, Index: r}
	if _, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 1100}, standardTxs(legs["cd0"]), w.arb); err != nil || pend != nil {
		t.Fatalf("a batch after the unreadable one: %v %v", pend, err)
	}
	// a leg that is not found is told that a block of its window could not be read
	_, _, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 800}, standardTxs(legs["absent"]), w.arb)
	st, named := finality.AsNamed(err)
	if !named || st.Code != finality.CodeIndexBlockUnindexable || st.Fields["reason"] != finality.UnindexableBatchRowMalformed {
		t.Fatalf("the leg is not told: %v", err)
	}
}

// A batch that was never captured leaves a hole in the dense batch numbers: a leg that is not found is told it is a capture gap - when the Bridge
// holds the batches on both sides of it.
func TestRB12ArbIndexMissingBatchNumberIsANamedCaptureGap(t *testing.T) {
	w := newIxWorld(t)
	for _, n := range []uint64{500, 501, 503, 504} {
		w.add(ixBatch{N: n, Block: 1000 + 8*(n-500), T: ixT0 + 96*(n-500), Msgs: [][][]byte{ixMsg(ixTx(int(50000 + n)))}})
	}
	for _, n := range []uint64{500, 501, 503, 504} {
		w.proof(n, w.recs[w.keys[n][0]].AfterAcc, w.recs[w.keys[n][0]].L1Block+2)
	}
	w.index(IndexConfig{})
	r := w.reader()
	b := &Builder{Store: w.store, Pins: w.pins, Index: r}
	_, _, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 200}, standardTxs([][]byte{ixTx(777777)}), w.arb)
	st, named := finality.AsNamed(err)
	if !named || st.Code != finality.CodeCaptureGap || st.Fields["gap_state"] != finality.GapStateUnrecorded || st.Fields["from_l1"] != uint64(1008) || st.Fields["to_l1"] != uint64(1024) {
		t.Fatalf("the hole is not named: %v", err)
	}
	// a leg that IS in a captured batch is served as ever
	if o := w.idx(r, ixT0+200, [][]byte{ixTx(50504)}); o.N != 504 {
		t.Fatalf("a leg in a captured batch: %s", o)
	}
}

// The authorization comes BEFORE the hole: a forged record (an invented event with a huge batch number, a record a proof contradicts) bounds no
// hole, so a leg that is simply not posted yet is never called a capture gap because of it; and neighbours with no captured proof claim nothing.
func TestRB12ArbIndexForgedBatchNumberCannotMakeAFalseCaptureGap(t *testing.T) {
	build := func(prove bool) *ixWorld {
		w := newIxWorld(t)
		for _, n := range []uint64{500, 501, 502} {
			w.add(ixBatch{N: n, Block: 1000 + 8*(n-500), T: ixT0 + 96*(n-500), Msgs: [][][]byte{ixMsg(ixTx(int(50000 + n)))}})
			if prove {
				w.proof(n, w.recs[w.keys[n][0]].AfterAcc, w.recs[w.keys[n][0]].L1Block+2)
			}
		}
		// an event a provider invented: a huge batch number, a plausible block; and one contradicted by a proof
		w.add(ixBatch{N: 1_000_000_000_000, Block: 1030, T: ixT0 + 300, Msgs: [][][]byte{ixMsg(ixTx(1))}})
		w.add(ixBatch{N: 505, Block: 1040, T: ixT0 + 400, Msgs: [][][]byte{ixMsg(ixTx(2))}})
		w.proof(505, common.Hash{9, 9, 9}, 1042)
		w.index(IndexConfig{})
		return w
	}
	for _, prove := range []bool{true, false} {
		w := build(prove)
		r := w.reader()
		b := &Builder{Store: w.store, Pins: w.pins, Index: r}
		loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ixT0 + 200}, standardTxs([][]byte{ixTx(777777)}), w.arb)
		if err != nil || loc != nil || pend == nil || pend.Reason != PendingAwaitingBatchPost {
			t.Fatalf("proved %v: a leg that is not posted yet is %v %v %v, not a capture gap", prove, loc, pend, err)
		}
	}
}

// A batch stored far below the capture's first cursor row (the archive backfill's prefix scan fills the batches posted before the capture started)
// is outside the time search unless the integrator gives the reader the floor of what it filled; the indexer finds it either way (its first step
// scans from block 0), and a note (finality.LateBlockNoter) is how a filler tells it later.
func TestRB12ArbIndexFloorHookCoversBatchesBelowTheCaptureStart(t *testing.T) {
	w := newIxWorld(t)
	w.add(ixBatch{N: 90, Block: 1000, T: ixT0, Msgs: [][][]byte{ixMsg(ixTx(91000))}})
	w.add(ixBatch{N: 600, Block: 6000, T: ixT0 + 5000, Msgs: [][][]byte{ixMsg(ixTx(91001))}})
	w.cursor(5900)
	w.cursor(6100)
	ix := w.indexer(IndexConfig{})
	stepAll(t, ix, 6100)
	leg := [][]byte{ixTx(91000)}
	r := w.reader()
	if o := w.idx(r, ixT0+10, leg); o.N != 0 {
		t.Fatalf("without the floor the batch below the capture start is outside the search window: %s", o)
	}
	r.Floor = func(context.Context) (uint64, bool, error) { return 1000, true, nil }
	if o := w.idx(r, ixT0+10, leg); o.N != 90 {
		t.Fatalf("with the floor of the prefix scan the batch is found: %s", o)
	}
	// a filler that stores a batch below the cursor tells the indexer, which indexes it at the next step
	late := w.add(ixBatch{N: 89, Block: 900, T: ixT0 - 96, Msgs: [][][]byte{ixMsg(ixTx(91002))}})
	_ = late
	var _ finality.LateBlockNoter = ix
	ix.NoteLate(900)
	if _, err := ix.Step(context.Background(), 6100); err != nil {
		t.Fatal(err)
	}
	r.Floor = func(context.Context) (uint64, bool, error) { return 900, true, nil }
	if o := w.idx(r, ixT0-86, [][]byte{ixTx(91002)}); o.N != 89 {
		t.Fatalf("a batch stored below the cursor and noted is found: %s", o)
	}
}
