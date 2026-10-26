// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-FIX (Train 3): the regression tests of the independent review V-RB12-INDEX (its probes, shipped as tests) and of the fixes.
// Everything here runs on the public API of the package, so the same file fails at the base commit by assertion, not by compilation.

// ---- helpers ----

func vPutBlock(t *testing.T, st finality.CaptureStore, bp *Pins, n uint64, txs ...[]Frame) {
	t.Helper()
	var sts []shapeTx
	for _, fr := range txs {
		sts = append(sts, shapeTx{blob: false, datas: [][]byte{payloadOf(fr...)}})
	}
	shapeBlock{number: n, hash: shapeHash(n, 0), txs: sts}.put(t, st, bp)
}

// vRef is the window reader's choice over [origin, end] for ts.
func vRef(t *testing.T, st finality.CaptureStore, bp *Pins, origin, end, ts uint64) *channelRef {
	t.Helper()
	b := &Builder{Store: st}
	all, err := b.loadRange(context.Background(), bp, origin, end, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch, _, _, _ := findChannel(all, bp, finality.HeaderFields{Timestamp: ts})
	return ch
}

func vGather(t testing.TB, name string) (float64, bool) {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var sum float64
	var found bool
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.Metric {
			found = true
			sum += vVal(mf.GetType(), m)
		}
	}
	return sum, found
}

func vVal(ty dto.MetricType, m *dto.Metric) float64 {
	switch ty {
	case dto.MetricType_GAUGE:
		return m.GetGauge().GetValue()
	case dto.MetricType_COUNTER:
		return m.GetCounter().GetValue()
	case dto.MetricType_HISTOGRAM:
		return float64(m.GetHistogram().GetSampleCount())
	}
	return 0
}

// hideStore answers "absent" for the listed keys (a row lost from the table).
type hideStore struct {
	finality.CaptureStore
	mu     sync.Mutex
	hidden map[finality.CaptureKey]bool
	reads  map[string]int
}

func (h *hideStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	h.mu.Lock()
	hidden := h.hidden[k]
	if h.reads == nil {
		h.reads = map[string]int{}
	}
	h.reads[strings.SplitN(k.Item, "/", 2)[0]]++
	h.mu.Unlock()
	if hidden {
		return nil, false, nil
	}
	return h.CaptureStore.Get(ctx, k)
}

// ---- D1: one junk channel cannot hide the honest leg ----

// A junk channel (anyone can post to the batch inbox; the capture keeps what goes there) whose coverage overflows the entry.
func junkOverflowFrames(t *testing.T) []Frame {
	t.Helper()
	var stream []byte
	for i := 0; i < maxRuns+1; i++ {
		enc, err := rlp.EncodeToBytes(singularRLP{ParentHash: [32]byte{1}, EpochNum: 5, EpochHash: [32]byte{2}, Timestamp: 1 + uint64(i)*100_000})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := rlp.EncodeToBytes(append([]byte{0}, enc...))
		stream = append(stream, b...)
	}
	data := compress("zlib", stream)
	var junk []Frame
	id := chanLabelID("junk")
	per := 900_000
	for i := 0; i*per < len(data); i++ {
		hi := (i + 1) * per
		if hi > len(data) {
			hi = len(data)
		}
		junk = append(junk, Frame{ID: id, Number: uint16(i), Data: data[i*per : hi]})
	}
	junk[len(junk)-1].IsLast = true
	return junk
}

func TestVIndexOverflowJunkChannelBlocksTheHonestLeg(t *testing.T) {
	_, bp := idxPins(t)
	W := bp.SeqWindowSize
	E := uint64(1000)
	st := NewMemStore()
	H := channelFrames("honest", 1_790_100_000, 30, E, 1)
	vPutBlock(t, st, bp, 1020, []Frame{H[0]})
	vPutBlock(t, st, bp, 1030, junkOverflowFrames(t))
	stepAll(t, newIdx(st, bp, IndexConfig{}), 1200)
	T := uint64(1_790_100_030)
	r := NewIndexReader(st, bp, 0)
	hit, _, err := r.Find(context.Background(), T, E, E+W, &ioCount{})
	if err != nil || hit == nil || hit.entry.ID != chanLabelID("honest") {
		t.Fatalf("DENIAL OF SERVICE: the honest channel exists and the window reader finds it, the index answers hit=%v err=%v", hit != nil, err)
	}
	if ref := vRef(t, st, bp, E, E+W, T); ref == nil || ref.ID != hit.entry.ID {
		t.Fatalf("the window reader and the index disagree: %v vs %x", ref, hit.entry.ID)
	}
	// with no honest channel the overflow is the named answer: nothing can be said about the junk channel's coverage, never a guess
	st2 := NewMemStore()
	vPutBlock(t, st2, bp, 1030, junkOverflowFrames(t))
	stepAll(t, newIdx(st2, bp, IndexConfig{}), 1200)
	_, _, err = NewIndexReader(st2, bp, 0).Find(context.Background(), T, E, E+W, &ioCount{})
	if se, ok := finality.AsNamed(err); !ok || se.Code != "index_inconsistent" || se.Fields["reason"] != finality.IndexCoverageOverflow {
		t.Fatalf("an overflowing channel alone must stay the named coverage_overflow, got %v", err)
	}
}

// ---- D4: an entry without transactions or frames is corruption ----

func TestVIndexEntryWithNoTransactions(t *testing.T) {
	pins, bp := idxPins(t)
	for _, c := range []struct {
		name string
		edit func(e *chanEntry)
	}{
		{"no transactions", func(e *chanEntry) { e.Txs = nil }},
		{"no frames", func(e *chanEntry) { e.NFrames = 0 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := smallWorld(t, bp, 12)
			upTo := w.numberOf(11) + 200
			stepAll(t, newIdx(w, bp, IndexConfig{}), upTo)
			var victim finality.CaptureKey
			var good []byte
			for k, v := range indexRows(t, w) {
				if strings.HasPrefix(k.Item, "idx/g1/bi/c/") && k.L1Block == w.numberOf(5) {
					victim, good = k, v
				}
			}
			e, err := decodeEntry(good)
			if err != nil {
				t.Fatal(err)
			}
			c.edit(e)
			w.mu.Lock()
			w.extra[victim] = e.encode()
			w.mu.Unlock()
			b := &Builder{Pins: pins, Store: w, L2: fixedL2{txs: [][]byte{l1InfoDeposit(w.Epoch(5), [32]byte{9})}}, Index: NewIndexReader(w, bp, 0)}
			ts, _ := w.legAt(5, 3)
			var sr searched
			var serr error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("an entry with %s panics instead of being refused by name: %v", c.name, r)
					}
				}()
				sr, serr = b.search(context.Background(), bp, finality.HeaderFields{Number: 5, Timestamp: ts}, nil)
				if sr.ch != nil {
					frameBlockRange(sr.frameTxs, sr.bt)
				}
			}()
			se, ok := finality.AsNamed(serr)
			if sr.ch != nil || !ok || se.Code != "index_inconsistent" || se.Fields["reason"] != finality.IndexEntryCorrupt {
				t.Fatalf("an entry with %s must be index_inconsistent{entry_corrupt}: ch=%v err=%v", c.name, sr.ch != nil, serr)
			}
		})
	}
}

// ---- D5 and D6: tie-break, boundary pins, digit width ----

func TestVIndexTieBreakAndDigitWidth(t *testing.T) {
	_, bp := idxPins(t)
	bp.DenimTime = 1 << 40 // the digit-width worlds below use timestamps of 10 and 11 digits to test the index names, not Denim blocks (a Denim block is keyed by its parent hash too)
	W := bp.SeqWindowSize
	E := uint64(1000)
	// two channels that both hold T, first frames in ONE transaction, B before A in the transaction
	st := NewMemStore()
	A := channelFrames("A", 1_790_100_000, 30, E, 1)
	B := channelFrames("B", 1_790_100_020, 30, E, 1)
	vPutBlock(t, st, bp, 1010, []Frame{B[0], A[0]})
	stepAll(t, newIdx(st, bp, IndexConfig{}), 1200)
	T := uint64(1_790_100_030)
	hit, _, err := NewIndexReader(st, bp, 0).Find(context.Background(), T, E, E+W, &ioCount{})
	ref := vRef(t, st, bp, E, E+W, T)
	if err != nil || hit == nil || ref == nil {
		t.Fatalf("hit=%v err=%v ref=%v", hit, err, ref)
	}
	if hit.entry.ID != ref.ID {
		t.Errorf("TIE-BREAK DIVERGENCE: index %x vs window reader %x", hit.entry.ID[:4], ref.ID[:4])
	}
	// different transactions: the first frame position decides
	st2 := NewMemStore()
	vPutBlock(t, st2, bp, 1010, []Frame{B[0]}, []Frame{A[0]})
	stepAll(t, newIdx(st2, bp, IndexConfig{}), 1200)
	hit2, _, _ := NewIndexReader(st2, bp, 0).Find(context.Background(), T, E, E+W, &ioCount{})
	ref2 := vRef(t, st2, bp, E, E+W, T)
	if hit2 == nil || ref2 == nil || hit2.entry.ID != ref2.ID {
		t.Errorf("different tx: index %v window %v", hit2, ref2)
	}
	// timestamps across the 10 -> 11 digit boundary: lexical order of the names is not numeric order
	st3 := NewMemStore()
	P := channelFrames("P", 9_999_999_990, 10, E, 1)  // 9999999990 .. 10000000008
	Q := channelFrames("Q", 10_000_000_100, 10, E, 1) // 11 digits
	R := channelFrames("R", 9_999_999_000, 10, E, 1)  // 10 digits, later in position
	vPutBlock(t, st3, bp, 1010, []Frame{P[0]})
	vPutBlock(t, st3, bp, 1011, []Frame{Q[0]})
	vPutBlock(t, st3, bp, 1012, []Frame{R[0]})
	stepAll(t, newIdx(st3, bp, IndexConfig{}), 1200)
	for _, ts := range []uint64{9_999_999_990, 9_999_999_998, 10_000_000_000, 10_000_000_008, 10_000_000_100, 10_000_000_118, 9_999_999_018} {
		h, _, err := NewIndexReader(st3, bp, 0).Find(context.Background(), ts, E, E+W, &ioCount{})
		ref := vRef(t, st3, bp, E, E+W, ts)
		if err != nil || (h != nil) != (ref != nil) || (h != nil && h.entry.ID != ref.ID) {
			t.Errorf("ts %d: index %v window %v err %v", ts, h, ref, err)
		}
	}
}

func TestVIndexWindowEdges(t *testing.T) {
	_, bp := idxPins(t)
	W := bp.SeqWindowSize
	E := uint64(100_000)
	st := NewMemStore()
	X := channelFrames("X", 1_790_000_000, 10, E, 1) // closes exactly at E+W
	Y := channelFrames("Y", 1_790_001_000, 10, E, 1) // closes at E+W+1
	Z := channelFrames("Z", 1_790_002_000, 10, E, 2) // frames at E and E+W
	V := channelFrames("V", 1_790_003_000, 10, E, 2) // frame 0 at E-1 (before origin), closes at E+5
	S := channelFrames("S", 1_790_004_000, 10, E, 2) // frames at E+10 and E+10+W (span exactly W): closes outside the window, the entry must exist
	U := channelFrames("U", 1_790_005_000, 10, E, 2) // frames at E+20 and E+20+W+1 (span W+1): the indexer must NOT make an entry
	vPutBlock(t, st, bp, E+W, []Frame{X[0]}, []Frame{Z[1]})
	vPutBlock(t, st, bp, E+W+1, []Frame{Y[0]})
	vPutBlock(t, st, bp, E, []Frame{Z[0]})
	vPutBlock(t, st, bp, E-1, []Frame{V[0]})
	vPutBlock(t, st, bp, E+5, []Frame{V[1]})
	vPutBlock(t, st, bp, E+10, []Frame{S[0]})
	vPutBlock(t, st, bp, E+10+W, []Frame{S[1]})
	vPutBlock(t, st, bp, E+20, []Frame{U[0]})
	vPutBlock(t, st, bp, E+20+W+1, []Frame{U[1]})
	stepAll(t, newIdx(st, bp, IndexConfig{BlocksPerStep: 3}), E+W+500)
	rows := indexRows(t, st)
	r := NewIndexReader(st, bp, 0)
	for _, c := range []struct {
		name  string
		t0    uint64
		wantI bool // index finds
		wantW bool // window reader finds
	}{
		{"X closes at E+W", 1_790_000_000, true, true},
		{"Y closes at E+W+1", 1_790_001_000, false, false},
		{"Z frames at E and E+W", 1_790_002_000, true, true},
		{"V frame before origin (E-1)", 1_790_003_000, true, false},
	} {
		hit, _, err := r.Find(context.Background(), c.t0+4, E, E+W, &ioCount{})
		ref := vRef(t, st, bp, E, E+W, c.t0+4)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (hit != nil) != c.wantI || (ref != nil) != c.wantW {
			t.Errorf("%s: index %v (want %v) window %v (want %v)", c.name, hit != nil, c.wantI, ref != nil, c.wantW)
		}
	}
	hasEntry := func(label string) bool {
		id := chanLabelID(label)
		for k := range rows {
			if strings.HasPrefix(k.Item, "idx/g1/bi/c/") && strings.HasSuffix(k.Item, fmt.Sprintf("%x", id)) {
				return true
			}
		}
		return false
	}
	if !hasEntry("S") {
		t.Errorf("a channel spanning exactly SeqWindowSize blocks must have an entry")
	}
	if hasEntry("U") {
		t.Errorf("a channel spanning SeqWindowSize+1 blocks must not have an entry")
	}
}

// ---- D3: the self-check recomputes an entry from its own blocks, and a skipped check is counted ----

func TestVIndexSelfCheckReferenceIsBoundedByTheEntryAndASkipIsCounted(t *testing.T) {
	metrics.RegisterMetrics()
	_, bp := idxPins(t)
	w := newShapeWorld(t, bp, 400, 10) // production density: one channel per 10 L1 blocks
	meter := &meterStore{CaptureStore: w}
	upTo := w.numberOf(399) + 200
	ix := NewIndexer(meter, bp, 0, IndexConfig{BlocksPerStep: 1 << 30, StepBudget: time.Hour, SelfCheckSample: 1, ReconcileSpan: 1 << 20})
	for i := 0; i < 5; i++ {
		rep, err := ix.Step(context.Background(), upTo)
		if err != nil {
			t.Fatal(err)
		}
		if rep.StoppedByCap == "" {
			break
		}
	}
	keys, err := w.ListByRange(context.Background(), uint64(Chain), w.numberOf(399), w.numberOf(399), "idx/g1/bi/c/")
	if err != nil || len(keys) != 1 {
		t.Fatalf("entry of channel 399: %v %v", keys, err)
	}
	n, ok := parseEntryName(1, keys[0])
	if !ok {
		t.Fatal("name")
	}
	meter.reset()
	want, err := ix.referenceEntry(context.Background(), n)
	stored, _, _ := w.Get(context.Background(), keys[0])
	if err != nil || !bytes.Equal(want, stored) {
		t.Fatalf("the reference of the entry differs from the stored entry: err=%v equal=%v", err, bytes.Equal(want, stored))
	}
	// the channel is 7 blob rows (about 0.92 MB) in one L1 block: the check reads that and the rows around it, not the sequencing window (316 MB measured)
	if got := meter.bytes.Load(); got > 4<<20 {
		t.Fatalf("PR claim 'one channel at a time' is false: recomputing ONE entry read %d MB in %d rows", got>>20, meter.gets.Load())
	}
	// a refused reservation skips the check: counted, never silent
	before, _ := vGather(t, "certen_finality_index_selfcheck_skipped_total")
	ctx := finality.WithMemoryBudget(context.Background(), finality.NewMemoryBudget(64<<10))
	if err := ix.SelfCheck(ctx, 4); err != nil {
		t.Fatalf("a skipped check is not an error: %v", err)
	}
	after, _ := vGather(t, "certen_finality_index_selfcheck_skipped_total")
	if after <= before {
		t.Fatalf("a self-check skipped for lack of memory must be counted (certen_finality_index_selfcheck_skipped_total %v -> %v)", before, after)
	}
}

// A self-check mismatch quarantines the channel by name for every build that uses it (and for every validator: the row is shared).
func TestVIndexSelfCheckMismatchRefusesTheChannelByName(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 12)
	upTo := w.numberOf(11) + 200
	ix := newIdx(w, bp, IndexConfig{SelfCheckSample: 64})
	stepAll(t, ix, upTo)
	var victim finality.CaptureKey
	var good []byte
	for k, v := range indexRows(t, w) {
		if strings.HasPrefix(k.Item, "idx/g1/bi/c/") && k.L1Block == w.numberOf(5) {
			victim, good = k, v
		}
	}
	e, err := decodeEntry(good)
	if err != nil {
		t.Fatal(err)
	}
	e.NFrames++ // a checksum-valid entry that is not what the captured rows say
	w.mu.Lock()
	w.extra[victim] = e.encode()
	w.mu.Unlock()
	ts, _ := w.legAt(5, 3)
	r := NewIndexReader(w, bp, 0)
	if h, _, err := r.Find(context.Background(), ts, w.Epoch(5), w.Epoch(5)+bp.SeqWindowSize, &ioCount{}); err != nil || h == nil {
		t.Fatalf("before the self-check the (wrong) entry is served: %v %v", h, err)
	}
	err = ix.SelfCheck(context.Background(), 64)
	if se, ok := finality.AsNamed(err); !ok || se.Fields["reason"] != finality.IndexSelfCheckMismatch {
		t.Fatalf("the self-check must name the mismatch: %v", err)
	}
	_, _, err = r.Find(context.Background(), ts, w.Epoch(5), w.Epoch(5)+bp.SeqWindowSize, &ioCount{})
	if se, ok := finality.AsNamed(err); !ok || se.Code != "index_inconsistent" || se.Fields["reason"] != finality.IndexSelfCheckMismatch {
		t.Fatalf("builds that use a channel whose entry failed the self-check must refuse by the same name, got %v", err)
	}
	// another channel is untouched
	ts2, _ := w.legAt(7, 3)
	if h, _, err := r.Find(context.Background(), ts2, w.Epoch(7), w.Epoch(7)+bp.SeqWindowSize, &ioCount{}); err != nil || h == nil {
		t.Fatalf("a channel that passed is still served: %v %v", h, err)
	}
}

// ---- D6: the metrics are set where they should be ----

func TestVIndexMetricsAreSetWhereTheyShouldBe(t *testing.T) {
	metrics.RegisterMetrics()
	pins, bp := idxPins(t)
	delta := func(name string, do func()) float64 {
		before, _ := vGather(t, name)
		do()
		after, ok := vGather(t, name)
		if !ok {
			t.Errorf("%s is not exported", name)
		}
		return after - before
	}
	w := smallWorld(t, bp, 40)
	ix := newIdx(w, bp, IndexConfig{BlocksPerStep: 10})
	upTo := w.numberOf(39) + 200
	var rebuild, digests float64
	rebuild = delta("certen_finality_index_rebuilds_total", func() {
		digests = delta("certen_finality_index_digests_total", func() {
			if _, err := ix.Step(context.Background(), upTo); err != nil {
				t.Fatal(err)
			}
		})
	})
	if rebuild < 1 || digests != 10 {
		t.Errorf("a first step of a new generation counts a rebuild and its 10 digests: rebuilds %v digests %v", rebuild, digests)
	}
	for _, n := range []string{"certen_finality_index_through_block", "certen_finality_index_lag_blocks", "certen_finality_index_entries_total", "certen_finality_index_step_seconds"} {
		if v, ok := vGather(t, n); !ok || v == 0 {
			t.Errorf("%s should be non-zero after a partial backfill step (value %v present %v)", n, v, ok)
		}
	}
	if v, _ := vGather(t, "certen_finality_index_lag_blocks"); v < 100 {
		t.Errorf("a partial backfill leaves a lag the alert can see: lag %v", v)
	}
	stepAll(t, ix, upTo)
	// lookups and the lookup bytes
	b := &Builder{Pins: pins, Store: w, L2: fixedL2{txs: [][]byte{l1InfoDeposit(w.Epoch(7), [32]byte{9})}}, Index: NewIndexReader(w, bp, 0)}
	ts, _ := w.legAt(7, 3)
	if d := delta("certen_finality_index_lookups_total", func() {
		if _, err := b.search(context.Background(), bp, finality.HeaderFields{Number: 5, Timestamp: ts}, nil); err != nil {
			t.Fatal(err)
		}
	}); d != 1 {
		t.Errorf("one lookup counts once: %v", d)
	}
	if v, ok := vGather(t, "certen_finality_index_lookup_bytes"); !ok || v == 0 {
		t.Errorf("lookup_bytes must have observed the lookup: %v %v", v, ok)
	}
	// a channel with a missing frame -> open channels
	st := NewMemStore()
	A := channelFrames("A", 1_790_100_000, 30, 1000, 4)
	vPutBlock(t, st, bp, 1010, []Frame{A[0]})
	vPutBlock(t, st, bp, 1016, []Frame{A[3]})
	stepAll(t, newIdx(st, bp, IndexConfig{}), 1200)
	if v, ok := vGather(t, "certen_finality_index_open_channels"); !ok || v == 0 {
		t.Errorf("open_channels should be non-zero while a channel is open: %v %v", v, ok)
	}
	// a block that arrives after the cursor passed it -> late blocks
	st2 := NewMemStore()
	C := channelFrames("C", 1_790_200_000, 30, 2000, 2)
	vPutBlock(t, st2, bp, 2010, []Frame{C[0]})
	ix2 := newIdx(st2, bp, IndexConfig{ReconcileEvery: 1})
	stepAll(t, ix2, 2300)
	if d := delta("certen_finality_index_late_blocks_total", func() {
		vPutBlock(t, st2, bp, 2012, []Frame{C[1]})
		stepAll(t, ix2, 2300)
	}); d < 1 {
		t.Errorf("a block filled below the cursor counts as a late block: %v", d)
	}
	// a damaged digest found by the self-check -> mismatches
	w2 := smallWorld(t, bp, 12)
	ix3 := newIdx(w2, bp, IndexConfig{SelfCheckSample: 64})
	stepAll(t, ix3, w2.numberOf(11)+200)
	for k, v := range indexRows(t, w2) {
		if strings.HasSuffix(k.Item, "/f") && k.L1Block == w2.numberOf(4) {
			dg, err := decodeDigest(k, v)
			if err != nil {
				t.Fatal(err)
			}
			dg.Txs[0].Frames[0].Len++
			w2.mu.Lock()
			w2.extra[k] = dg.encode()
			w2.mu.Unlock()
		}
	}
	if d := delta("certen_finality_index_mismatches_total", func() { _ = ix3.SelfCheck(context.Background(), 64) }); d < 1 {
		t.Errorf("a self-check mismatch is counted: %v", d)
	}
	// a conflicting write -> conflicts
	ck := finality.CaptureKey{Chain: uint64(Chain), L1Block: 7, L1Hash: [32]byte{7}, Item: "idx/g1/bi/f"}
	st4 := NewMemStore()
	if err := finality.IndexPut(context.Background(), st4, FamilyBaseInbox, ck, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if d := delta("certen_finality_index_conflicts_total", func() {
		if err := finality.IndexPut(context.Background(), st4, FamilyBaseInbox, ck, []byte("two")); !IsIndexConflict(err) {
			t.Fatalf("want the named conflict, got %v", err)
		}
	}); d != 1 {
		t.Errorf("a conflicting write is counted once: %v", d)
	}
}
