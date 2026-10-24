// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// RB12-INDEX-B cost and equivalence at the scale of the production table. The production table holds 3,276 batches (about 1.27 GB: three 131,168-byte
// blob rows each) in 2.7 days; this test generates the same SHAPE lazily - a batch row, a header row and three real blob rows (real encodings: a
// brotli payload of 400 messages of 900 bytes in three blobs) per batch, produced when a row is read and never kept - at 0.5x, 1.5x, 5x and 10x
// the batches of the table (CERTEN_RB12_ARB_SCALES; the default is two small scales so that the package suite stays fast).

const (
	scaleBase     = 11_958_041 // the first batch block of the production table
	scaleSpacing  = 8          // L1 blocks per batch
	scaleStepSecs = 96         // seconds per batch
	scaleMsgs     = 400
	scaleTxBytes  = 900
	scaleBatch0   = 884_511
	scaleT0       = 1_792_000_000
)

type genBatch struct {
	blobs [][]byte
	rec   capture.BatchRecord
	row   []byte
}

// lazyArb is a CaptureStore whose capture rows are functions of the batch index and whose index rows (idx/...) are real, kept in a store with a
// block index.
type lazyArb struct {
	nBatches uint64
	mu       sync.Mutex
	cache    map[uint64][][]byte
	inner    *blockIndexed
}

func newLazyArb(n uint64) *lazyArb {
	return &lazyArb{nBatches: n, cache: map[uint64][][]byte{}, inner: newBlockIndexed()}
}

func (l *lazyArb) blockOf(i uint64) uint64 { return scaleBase + scaleSpacing*i }
func (l *lazyArb) timeOf(i uint64) uint64  { return scaleT0 + scaleStepSecs*i }
func (l *lazyArb) top() uint64             { return l.blockOf(l.nBatches) + 4 }

func (l *lazyArb) tx(i uint64, j int) []byte { return ixRandTx(i*1000+uint64(j), scaleTxBytes) }

// ixRandTx is a transaction of size bytes of pseudo-random (incompressible) data, unique per tag, generated at memory speed.
func ixRandTx(tag uint64, size int) []byte {
	data := make([]byte, size)
	x := tag*0x9E3779B97F4A7C15 + 1
	for i := 0; i+8 <= size; i += 8 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		binary.LittleEndian.PutUint64(data[i:], x)
	}
	b, _ := rlp.EncodeToBytes([]any{tag, big.NewInt(1), uint64(21000), make([]byte, 20), big.NewInt(0), data, big.NewInt(27), big.NewInt(1), big.NewInt(2)})
	return b
}

func (l *lazyArb) header(block uint64) ([]byte, [32]byte) {
	t := scaleT0 + (block-scaleBase)*scaleStepSecs/scaleSpacing
	return ixHeader(block, t, common.Hash{0x1c})
}

// scaleBlobs is the number of blob rows of every generated batch (checked against a real encoding by the test).
const scaleBlobs = 3

// rec is the batch record of batch i: a function of i alone (it names the versioned hashes, not the blobs).
func (l *lazyArb) rec(i uint64) (capture.BatchRecord, []byte) {
	_, hash := l.header(l.blockOf(i))
	T := l.timeOf(i)
	rec := capture.BatchRecord{N: scaleBatch0 + i, BeforeAcc: common.Hash{byte(i), 1}, DelayedAcc: common.Hash{2}, Header40: [5]uint64{T - 86400, T + 768, l.blockOf(i) - 7200, l.blockOf(i) + 64, 0},
		DataLocation: capture.LocBlob, L1Block: l.blockOf(i), L1Hash: hash, TxHash: common.Hash{byte(i), 9}, TxRaw: []byte{0x03, 0xc0}}
	for k := 0; k < scaleBlobs; k++ {
		rec.VersionedHashes = append(rec.VersionedHashes, common.Hash{byte(i), byte(k), 0x77})
	}
	rec.AfterAcc = Accumulator(rec.BeforeAcc, rec.DataHash(nil), rec.DelayedAcc)
	return rec, rec.Encode()
}

// blobsOf generates the blobs of batch i: a brotli payload of scaleMsgs messages of scaleTxBytes incompressible bytes, in real blob encoding.
func (l *lazyArb) blobsOf(i uint64) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.cache[i]; ok {
		return b
	}
	if len(l.cache) > 64 {
		l.cache = map[uint64][][]byte{}
	}
	var msgs [][][]byte
	for j := 0; j < scaleMsgs; j++ {
		msgs = append(msgs, ixMsg(l.tx(i, j)))
	}
	b := encodeBlobs(ixPayloadFast(msgs))
	l.cache[i] = b
	return b
}

// ixPayloadFast is ixPayload with the fastest brotli level (the payload is incompressible data either way).
func brotliFast(b []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, 1)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func ixPayloadFast(msgs [][][]byte) []byte {
	var segs [][]byte
	for _, m := range msgs {
		segs = append(segs, seg(segL2Message, signedTxMsg(m[0])))
	}
	return append([]byte{headerBrotli}, brotliFast(bytes.Join(segs, nil))...)
}

func (l *lazyArb) indexOfBlock(block uint64) (uint64, bool) {
	if block < scaleBase || (block-scaleBase)%scaleSpacing != 0 {
		return 0, false
	}
	i := (block - scaleBase) / scaleSpacing
	return i, i < l.nBatches
}

func (l *lazyArb) cursorBlocks() (uint64, uint64) { return scaleBase + 26, l.top() }

func (l *lazyArb) Put(ctx context.Context, k finality.CaptureKey, data []byte) error {
	return l.inner.Put(ctx, k, data)
}

func (l *lazyArb) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if strings.HasPrefix(k.Item, "idx/") {
		return l.inner.Get(ctx, k)
	}
	if i, ok := l.indexOfBlock(k.L1Block); ok {
		rec, row := l.rec(i)
		if k.L1Hash != rec.L1Hash {
			return nil, false, nil
		}
		switch {
		case k.Item == capture.ItemHeader:
			raw, _ := l.header(k.L1Block)
			return raw, true, nil
		case k.Item == capture.ItemBatch(rec.N):
			return row, true, nil
		case strings.HasPrefix(k.Item, fmt.Sprintf("blob/%d/", rec.N)):
			j, err := strconv.Atoi(strings.TrimPrefix(k.Item, fmt.Sprintf("blob/%d/", rec.N)))
			if err != nil || j < 0 || j >= scaleBlobs {
				return nil, false, nil
			}
			return capture.BlobRecord{Raw: l.blobsOf(i)[j]}.Encode(), true, nil
		}
		return nil, false, nil
	}
	lo, hi := l.cursorBlocks()
	if k.L1Block == lo || k.L1Block == hi {
		raw, hash := l.header(k.L1Block)
		if k.L1Hash != hash {
			return nil, false, nil
		}
		switch k.Item {
		case capture.ItemHeader:
			return raw, true, nil
		case capture.ItemCursor:
			return append(binary.BigEndian.AppendUint64(nil, k.L1Block), hash[:]...), true, nil
		}
	}
	return l.inner.Get(ctx, k)
}

func (l *lazyArb) ListByBlock(ctx context.Context, chain, l1Block uint64) ([]finality.CaptureRow, error) {
	return nil, fmt.Errorf("lazyArb: ListByBlock is not used by the index")
}

func (l *lazyArb) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	var out []finality.CaptureKey
	add := func(block uint64, hash [32]byte, items ...string) {
		for _, it := range items {
			if strings.HasPrefix(it, prefix) {
				out = append(out, finality.CaptureKey{Chain: chain, L1Block: block, L1Hash: hash, Item: it})
			}
		}
	}
	if !strings.HasPrefix(prefix, "idx/") {
		lo, hi := l.cursorBlocks()
		for _, b := range []uint64{lo, hi} {
			if b >= from && b <= to {
				_, h := l.header(b)
				add(b, h, capture.ItemCursor, capture.ItemHeader)
			}
		}
		first := uint64(0)
		if from > scaleBase {
			first = (from - scaleBase + scaleSpacing - 1) / scaleSpacing
		}
		for i := first; i < l.nBatches && l.blockOf(i) <= to; i++ {
			b := l.blockOf(i)
			_, h := l.header(b)
			n := scaleBatch0 + i
			// the lazy key set of the batch: the same keys the capturer stores
			items := []string{capture.ItemBatch(n), capture.ItemBlob(n, 0), capture.ItemBlob(n, 1), capture.ItemBlob(n, 2), capture.ItemHeader}
			add(b, h, items...)
		}
	}
	rest, err := l.inner.ListByRange(ctx, chain, from, to, prefix)
	if err != nil {
		return nil, err
	}
	out = append(out, rest...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.L1Block != b.L1Block {
			return a.L1Block < b.L1Block
		}
		if c := bytes.Compare(a.L1Hash[:], b.L1Hash[:]); c != 0 {
			return c < 0
		}
		return a.Item < b.Item
	})
	return out, nil
}

// blockIndexed is an insert-only store with a block index, so that listing a narrow range does not scan every row.
type blockIndexed struct {
	mu     sync.Mutex
	rows   map[finality.CaptureKey][]byte
	blocks map[uint64][]finality.CaptureKey
	sorted []uint64
	dirty  bool
}

func newBlockIndexed() *blockIndexed {
	return &blockIndexed{rows: map[finality.CaptureKey][]byte{}, blocks: map[uint64][]finality.CaptureKey{}}
}

func (s *blockIndexed) Put(_ context.Context, k finality.CaptureKey, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.rows[k]; ok {
		if bytes.Equal(old, data) {
			return nil
		}
		return fmt.Errorf("%w: %s", finality.ErrCaptureConflict, k)
	}
	s.rows[k] = append([]byte(nil), data...)
	if _, ok := s.blocks[k.L1Block]; !ok {
		s.sorted = append(s.sorted, k.L1Block)
		s.dirty = true
	}
	s.blocks[k.L1Block] = append(s.blocks[k.L1Block], k)
	return nil
}

func (s *blockIndexed) Get(_ context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rows[k]
	return append([]byte(nil), b...), ok, nil
}

func (s *blockIndexed) ListByBlock(context.Context, uint64, uint64) ([]finality.CaptureRow, error) {
	return nil, nil
}

func (s *blockIndexed) ListByRange(_ context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		sort.Slice(s.sorted, func(i, j int) bool { return s.sorted[i] < s.sorted[j] })
		s.dirty = false
	}
	var out []finality.CaptureKey
	for i := sort.Search(len(s.sorted), func(i int) bool { return s.sorted[i] >= from }); i < len(s.sorted) && s.sorted[i] <= to; i++ {
		for _, k := range s.blocks[s.sorted[i]] {
			if k.Chain == chain && strings.HasPrefix(k.Item, prefix) {
				out = append(out, k)
			}
		}
	}
	return out, nil
}

// scaleMeter counts what a lookup reads of the store.
type scaleMeter struct {
	finality.CaptureStore
	bytes, gets, keys atomic.Int64
}

func (m *scaleMeter) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	b, ok, err := m.CaptureStore.Get(ctx, k)
	m.bytes.Add(int64(len(b)))
	m.gets.Add(1)
	return b, ok, err
}

func (m *scaleMeter) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	ks, err := m.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
	m.keys.Add(int64(len(ks)))
	return ks, err
}

func (m *scaleMeter) reset() { m.bytes.Store(0); m.gets.Store(0); m.keys.Store(0) }

type scaleCost struct {
	bytes, gets, keys int64
	heap              uint64
	wall              time.Duration
	out               outcome
}

func sampleHeap(f func()) (peak uint64, wall time.Duration) {
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	var p atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > p.Load() {
				p.Store(ms.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	t0 := time.Now()
	f()
	wall = time.Since(t0)
	close(stop)
	<-done
	if p.Load() > m0.HeapAlloc {
		return p.Load() - m0.HeapAlloc, wall
	}
	return 0, wall
}

func scalesFromEnv(t *testing.T) []float64 {
	raw := os.Getenv("CERTEN_RB12_ARB_SCALES")
	if raw == "" {
		raw = "0.05,0.15"
	}
	var out []float64
	for _, p := range strings.Split(raw, ",") {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || f <= 0 {
			t.Fatalf("CERTEN_RB12_ARB_SCALES: %q", p)
		}
		out = append(out, f)
	}
	return out
}

func TestRB12ArbIndexCostIsIndependentOfTheTableAndEqualsTheReference(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "finality_arb_posted1", "raw", "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatal(err)
	}
	arb, err := loadArbPins(pins)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(newLazyArb(1).blobsOf(0)); n != scaleBlobs {
		t.Fatalf("a generated batch has %d blobs, the world assumes %d", n, scaleBlobs)
	}
	var medianBytes []int64
	for _, scale := range scalesFromEnv(t) {
		n := uint64(float64(3276) * scale)
		store := newLazyArb(n)
		budget := finality.NewMemoryBudget(0)
		bctx := finality.WithMemoryBudget(context.Background(), budget)

		// the first backfill of the whole table: bounded per step, the memory reserved and released per block
		ix, err := NewIndexer(store, pins, 0, IndexConfig{BlocksPerStep: 256, StepBudget: time.Hour, ReconcileEvery: 1 << 30, SelfCheckEvery: 1 << 30})
		if err != nil {
			t.Fatal(err)
		}
		var peakUsed atomic.Int64
		stopWatch := make(chan struct{})
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			for {
				if u := budget.Used(); u > peakUsed.Load() {
					peakUsed.Store(u)
				}
				select {
				case <-stopWatch:
					return
				case <-time.After(2 * time.Millisecond):
				}
			}
		}()
		t0 := time.Now()
		steps, maxStep := 0, time.Duration(0)
		for {
			rep, err := ix.Step(bctx, store.top())
			if err != nil {
				t.Fatalf("scale %v step %d: %v", scale, steps, err)
			}
			steps++
			if rep.Elapsed > maxStep {
				maxStep = rep.Elapsed
			}
			if rep.Through >= store.top() && rep.StoppedByCap == "" {
				break
			}
		}
		backfill := time.Since(t0)
		close(stopWatch)
		<-watchDone
		if u := budget.Used(); u != 0 {
			t.Errorf("scale %v: the budget still holds %d bytes after the backfill (a reservation leaked)", scale, u)
		}
		t.Logf("scale %.2fx: %d batches (%d blob rows, %d MB of capture rows): backfill %s in %d steps, longest step %s, peak reservation %d MB", scale, n, 3*n, 3*n*131168>>20,
			backfill.Round(time.Millisecond), steps, maxStep.Round(time.Millisecond), peakUsed.Load()>>20)
		if peakUsed.Load() > 128<<20 {
			t.Errorf("scale %v: the backfill reserved %d MB at once: it must be one block (about 33 MB) at a time", scale, peakUsed.Load()>>20)
		}

		// the lookups: legs spread over the history; every one found
		meter := &scaleMeter{CaptureStore: store}
		r, err := NewIndexReader(meter, pins, 0)
		if err != nil {
			t.Fatal(err)
		}
		b := &Builder{Store: meter, Pins: pins, Index: r}
		var costs []scaleCost
		for k := 0; k < 40; k++ {
			i := uint64(k) * (n - 1) / 39
			txs := [][]byte{store.tx(i, int(i)%scaleMsgs)}
			ts := store.timeOf(i) + 30
			var c scaleCost
			meter.reset()
			c.heap, c.wall = sampleHeap(func() {
				loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ts}, standardTxs(txs), arb)
				switch {
				case err != nil:
					c.out = outcome{State: stateOf(err)}
				case pend != nil:
					c.out = outcome{State: pend.Reason}
				default:
					c.out = outcome{N: loc.rec.N, Block: loc.rec.L1Block}
				}
			})
			c.bytes, c.gets, c.keys = meter.bytes.Load(), meter.gets.Load(), meter.keys.Load()
			if c.out.N != scaleBatch0+i {
				t.Fatalf("scale %v leg %d: found %s, want batch %d", scale, i, c.out, scaleBatch0+i)
			}
			costs = append(costs, c)
		}
		sort.Slice(costs, func(i, j int) bool { return costs[i].bytes < costs[j].bytes })
		med := costs[len(costs)/2]
		maxC := costs[len(costs)-1]
		var maxHeap uint64
		var maxKeys int64
		for _, c := range costs {
			if c.heap > maxHeap {
				maxHeap = c.heap
			}
			if c.keys > maxKeys {
				maxKeys = c.keys
			}
		}
		sort.Slice(costs, func(i, j int) bool { return costs[i].wall < costs[j].wall })
		t.Logf("scale %.2fx FOUND leg: median %d KB read in %d rows, max %d KB, max %d key names listed, median wall %s, max heap above start +%d KB", scale, med.bytes>>10, med.gets, maxC.bytes>>10, maxKeys,
			costs[len(costs)/2].wall.Round(time.Millisecond), maxHeap>>10)
		if med.bytes > 50<<20 || costs[len(costs)/2].wall > 30*time.Second {
			t.Errorf("scale %v: the median found leg read %d MB in %s: the bounds are 50 MB and 30 s", scale, med.bytes>>20, costs[len(costs)/2].wall)
		}
		if maxHeap > 64<<20 {
			t.Errorf("scale %v: a lookup's heap rose by %d MB", scale, maxHeap>>20)
		}
		medianBytes = append(medianBytes, med.bytes)

		// a leg no batch holds: no blob row at all
		var absent scaleCost
		meter.reset()
		absent.heap, absent.wall = sampleHeap(func() {
			absent.out = w0(r, b, arb, store.timeOf(n/2)+30, [][]byte{ixTx(7_777_777)})
		})
		absent.bytes, absent.keys = meter.bytes.Load(), meter.keys.Load()
		t.Logf("scale %.2fx ABSENT leg: %s, %d KB read, %d key names, wall %s, heap +%d KB", scale, absent.out, absent.bytes>>10, absent.keys, absent.wall.Round(time.Millisecond), absent.heap>>10)
		if absent.out.State != PendingAwaitingBatchPost || absent.bytes > 1<<20 {
			t.Errorf("scale %v: an unmatched leg is %s and read %d KB", scale, absent.out, absent.bytes>>10)
		}

		// equivalence with the reference reader on the same lazily generated table
		ref := &Builder{Store: store, Pins: pins}
		for _, i := range []uint64{0, n / 3, n - 1} {
			txs := [][]byte{store.tx(i, 17)}
			ts := store.timeOf(i) + 30
			var batches []capture.BatchRecord
			var rc scaleCost
			rc.heap, rc.wall = sampleHeap(func() {
				var err error
				if batches, err = capture.LoadBatches(context.Background(), store, ixChain); err != nil {
					t.Fatal(err)
				}
			})
			loc, err := ref.locate(context.Background(), batches, finality.HeaderFields{Number: 5, Timestamp: ts}, txs, arb)
			if err != nil || loc == nil {
				t.Fatalf("scale %v: the reference did not find batch %d: %v", scale, scaleBatch0+i, err)
			}
			got := w0(r, b, arb, ts, txs)
			if got.N != loc.rec.N || got.Block != loc.rec.L1Block {
				t.Errorf("scale %v leg %d: reference N=%d block=%d, index %s", scale, i, loc.rec.N, loc.rec.L1Block, got)
			}
		}
		refAbsent := ref.locateOutcome(t, store, arb, store.timeOf(n/2)+30, [][]byte{ixTx(7_777_777)})
		if refAbsent != PendingAwaitingBatchPost {
			t.Errorf("scale %v: the reference says %s for the unmatched leg", scale, refAbsent)
		}
	}
	// flat in the table: the median found leg reads (about) the same bytes at every scale
	if len(medianBytes) > 1 {
		lo, hi := medianBytes[0], medianBytes[0]
		for _, m := range medianBytes {
			if m < lo {
				lo = m
			}
			if m > hi {
				hi = m
			}
		}
		if hi > lo+lo/10 {
			t.Errorf("the bytes read by a found leg are not flat in the table: %v", medianBytes)
		}
	}
}

func w0(r *IndexReader, b *Builder, arb *arbPins, ts uint64, txs [][]byte) outcome {
	loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ts}, standardTxs(txs), arb)
	switch {
	case err != nil:
		return outcome{State: stateOf(err)}
	case pend != nil:
		return outcome{State: pend.Reason}
	}
	return outcome{N: loc.rec.N, Block: loc.rec.L1Block}
}

// locateOutcome is the reference reader's answer as a pending reason / state / "found".
func (b *Builder) locateOutcome(t *testing.T, store finality.CaptureStore, arb *arbPins, ts uint64, txs [][]byte) string {
	t.Helper()
	batches, err := capture.LoadBatches(context.Background(), store, ixChain)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := b.locate(context.Background(), batches, finality.HeaderFields{Number: 5, Timestamp: ts}, txs, arb)
	switch {
	case err != nil:
		return stateOf(err)
	case loc == nil:
		return PendingAwaitingBatchPost
	}
	return "found"
}
