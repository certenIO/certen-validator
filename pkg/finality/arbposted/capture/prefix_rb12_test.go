// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL, Arbitrum prefix scan.

func prefixCapturer(sc *scenario, store CaptureStore, blocks uint64, lease *finality.Lease) *Capturer {
	c := newCapturer(sc, store)
	c.Prefix = &PrefixScan{Lease: lease, Blocks: blocks, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	return c
}

func requestPrefix(t *testing.T, st CaptureStore, from, to uint64) {
	t.Helper()
	if v, err := finality.RequestPrefix(context.Background(), st, ChainArbitrumSepolia, from, to, finality.PrefixPolicy{MaxBlocks: 1000}); err != nil || v != finality.PrefixRecorded {
		t.Fatalf("%v %v", v, err)
	}
}

func TestRB12ArbPrefixScanCapturesTheBatchRowsOfTheLiveCaptureAndClosesTheRange(t *testing.T) {
	ctx := context.Background()
	sc := newScenario(t, LocTxInput, 0)
	// the live capture of the batch (the reference)
	live := NewMemStore()
	lc := newCapturer(sc, live)
	if _, err := lc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	// the prefix scan of a window that contains it, in a store the live loop never saw
	st := NewMemStore()
	requestPrefix(t, st, 990, 999)
	c := prefixCapturer(sc, st, 400, nil)
	var rep Report
	if err := c.scanPrefix(ctx, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.PrefixScanned != 10 || rep.PrefixBatches != 1 {
		t.Fatalf("%+v", rep)
	}
	want, got := allRows(t, live, 995, 995), allRows(t, st, 995, 995)
	if len(got) == 0 || len(got) > len(want) {
		t.Fatalf("rows: got %d want %d", len(got), len(want))
	}
	index := map[string][]byte{}
	for _, r := range want {
		index[r.String()] = r.Bytes
	}
	for _, r := range got {
		if b, ok := index[r.String()]; !ok || !bytes.Equal(b, r.Bytes) {
			t.Fatalf("row %s differs from the live capture's", r.CaptureKey)
		}
	}
	if open, _ := finality.GapsIn(ctx, st, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock); len(open) != 0 {
		t.Fatalf("the range is closed by its scan row: %v", open)
	}
	if ks, _ := st.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapScanPrefix); len(ks) != 1 || ks[0].L1Block != 990 || ks[0].Item != "gapscan/999" {
		t.Fatalf("%v", ks)
	}
	// the batch is registered with the retry machinery as a prefix batch (bounded per tick), its proof still to come
	if p := c.needProof[77]; p == nil || !p.prefix {
		t.Fatalf("%+v", c.needProof)
	}
}

func TestRB12ArbPrefixScanTakesTheOldestOpenRangeFirstAndOneRangePerTick(t *testing.T) {
	ctx := context.Background()
	sc := newScenario(t, LocTxInput, 0)
	st := NewMemStore()
	requestPrefix(t, st, 980, 999) // chunks of 10: 980-989, 990-999
	c := prefixCapturer(sc, st, 10, nil)
	var seen []string
	for i := 0; i < 3; i++ {
		var rep Report
		if err := c.scanPrefix(ctx, &rep); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, fmt.Sprint(rep.PrefixScanned, "/", rep.PrefixBatches))
	}
	if fmt.Sprint(seen) != "[10/0 10/1 0/0]" {
		t.Fatalf("the empty chunk below first, then the one with the event, then nothing: %v", seen)
	}
	ks, _ := st.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapScanPrefix)
	if len(ks) != 2 || ks[0].L1Block != 980 || ks[1].L1Block != 990 {
		t.Fatalf("%v", ks)
	}
}

func TestRB12ArbPrefixScanMarksNothingWhenAnEventCannotBeCaptured(t *testing.T) {
	ctx := context.Background()
	sc := newScenario(t, LocTxInput, 0)
	sc.l1.logs[0].Topics[3][0] ^= 0xff // an afterAcc the capture cannot reproduce
	st := NewMemStore()
	requestPrefix(t, st, 990, 999)
	c := prefixCapturer(sc, st, 400, nil)
	var rep Report
	if err := c.scanPrefix(ctx, &rep); err == nil {
		t.Fatal("the range with an event that does not capture is an error")
	}
	if ks, _ := st.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapScanPrefix); len(ks) != 0 {
		t.Fatalf("an unmarked range is read again: %v", ks)
	}
	if open, _ := finality.GapsIn(ctx, st, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock); len(open) != 1 {
		t.Fatalf("%v", open)
	}
	// a provider that answers a log outside the range it was asked about is refused too
	sc2 := newScenario(t, LocTxInput, 0)
	st2 := NewMemStore()
	requestPrefix(t, st2, 990, 999)
	c2 := prefixCapturer(sc2, st2, 400, nil)
	c2.L1 = outOfRange{c2.L1}
	if err := c2.scanPrefix(ctx, &Report{}); err == nil {
		t.Fatal("a log outside the asked range is refused")
	}
	if ks, _ := st2.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapScanPrefix); len(ks) != 0 {
		t.Fatalf("%v", ks)
	}
}

type outOfRange struct{ L1Source }

func (o outOfRange) Logs(ctx context.Context, a [20]byte, t0 [32]byte, t1 *[32]byte, from, to uint64) ([]Log, error) {
	ls, err := o.L1Source.Logs(ctx, a, t0, t1, 0, 1<<40)
	for i := range ls {
		ls[i].BlockNumber = to + 5
	}
	return ls, err
}

func TestRB12ArbPrefixScanClaimsEachChunkSoTwoValidatorsNeverReadTheSameRange(t *testing.T) {
	ctx := context.Background()
	sc := newScenario(t, LocTxInput, 0)
	st := NewMemStore()
	requestPrefix(t, st, 980, 999)
	mk := func(h byte) *finality.Lease {
		l := &finality.Lease{Store: st, Chain: ChainArbitrumSepolia, Span: 10 * time.Minute, Chunk: 10}
		l.Holder[0] = h
		return l
	}
	a, b := prefixCapturer(sc, st, 10, mk(1)), prefixCapturer(sc, st, 10, mk(2))
	// both see both chunks open (a scan failure leaves a range open: simulate by scanning with a failing log source on the first)
	var ra, rb Report
	pieces, _ := finality.GapsIn(ctx, st, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock)
	if _, _, ok := nextPrefixRange(pieces, 10, map[uint64]bool{}); !ok {
		t.Fatal("open")
	}
	won, err := a.Prefix.Lease.Claim(ctx, a.Prefix.now(), 980)
	if !won || err != nil {
		t.Fatal("a claims 980")
	}
	if err := b.scanPrefix(ctx, &rb); err != nil || rb.PrefixLeaseLost != 1 || rb.PrefixScanned != 10 {
		t.Fatalf("b skips a's chunk and scans the next: %+v %v", rb, err)
	}
	ks, _ := st.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapScanPrefix)
	if len(ks) != 1 || ks[0].L1Block != 990 {
		t.Fatalf("%v", ks)
	}
	if err := a.scanPrefix(ctx, &ra); err != nil || ra.PrefixScanned != 10 {
		t.Fatalf("a scans its own chunk: %+v %v", ra, err)
	}
}

func TestRB12ArbPrefixBatchesAreRetriedAtABoundedRateAndNotOnTheOldCadence(t *testing.T) {
	ctx := context.Background()
	sc := newScenario(t, LocBlob, 1)
	st := NewMemStore()
	c := newCapturer(sc, st)
	for i := uint64(0); i < 20; i++ {
		rec := sc.rec
		rec.N = 1000 + i
		c.needBlobs[rec.N] = &pendBlob{rec: rec, ts: 1700000000, prefix: true}
	}
	counting := &countingBeacon{inner: sc.beacon}
	c.Beacon = counting
	var rep Report
	c.fetchBlobs(ctx, &rep)
	if counting.calls != PrefixBlobsPerTick {
		t.Fatalf("a tick asks the beacon about at most %d prefix batches, got %d", PrefixBlobsPerTick, counting.calls)
	}
	// the live (non-prefix) old batches keep their cadence: not asked on a tick that is not due
	c2 := newCapturer(sc, NewMemStore())
	c2.ticks = 2
	c2.needBlobs[5] = &pendBlob{rec: sc.rec, ts: 1700000000, old: true}
	cb := &countingBeacon{inner: sc.beacon}
	c2.Beacon = cb
	c2.fetchBlobs(ctx, &rep)
	if cb.calls != 0 {
		t.Fatalf("an old batch waits for its cadence: %d", cb.calls)
	}
}

type countingBeacon struct {
	inner BeaconSource
	calls int
}

func (c *countingBeacon) Sidecars(ctx context.Context, slot uint64, wanted [][32]byte) (map[[32]byte]Sidecar, error) {
	c.calls++
	return c.inner.Sidecars(ctx, slot, wanted)
}

// V-ARCHIVE-2 V2-3(b): an eth_getLogs answer that omits an event is caught by the accumulator chain where a neighbour is known.
func TestRB12ArbPrefixScanRefusesALogAnswerThatBreaksTheAccumulatorChain(t *testing.T) {
	ctx := context.Background()
	// 1. inside the range: batches 77 and 79 are not consecutive (78 was omitted)
	sc := newScenario(t, LocTxInput, 0)
	second := sc.l1.logs[0]
	second.Topics = append([][32]byte(nil), second.Topics...)
	second.Topics[1] = u256(79)
	second.BlockNumber = 996
	sc.l1.logs = append(sc.l1.logs, second)
	st := NewMemStore()
	requestPrefix(t, st, 990, 999)
	if err := prefixCapturer(sc, st, 400, nil).scanPrefix(ctx, &Report{}); err == nil {
		t.Fatal("a missing batch inside the range is refused")
	}
	if ks, _ := st.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "batch/"); len(ks) != 0 {
		t.Fatalf("nothing of a refused answer is stored: %v", ks)
	}
	if ks, _ := st.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapScanPrefix); len(ks) != 0 {
		t.Fatalf("and the range is not marked: %v", ks)
	}
	// 2. at the edges: the stored neighbours must join the first and the last event
	for _, edge := range []string{"previous", "next"} {
		sc2 := newScenario(t, LocTxInput, 0)
		st2 := NewMemStore()
		requestPrefix(t, st2, 990, 999)
		n := sc2.rec.N - 1
		nb := BatchRecord{N: n, L1Block: 900, L1Hash: [32]byte{9}, BeforeAcc: [32]byte{1}, AfterAcc: [32]byte{2}, DelayedAcc: [32]byte{3}}
		if edge == "next" {
			n, nb.N = sc2.rec.N+1, sc2.rec.N+1
			nb.BeforeAcc = [32]byte{0xee} // not the afterAcc of batch 77
		}
		if err := st2.Put(ctx, Key{Chain: ChainArbitrumSepolia, L1Block: 900, L1Hash: nb.L1Hash, Item: ItemBatch(n)}, nb.Encode()); err != nil {
			t.Fatal(err)
		}
		if err := prefixCapturer(sc2, st2, 400, nil).scanPrefix(ctx, &Report{}); err == nil {
			t.Fatalf("the %s stored batch does not join: the range is refused", edge)
		}
		if ks, _ := st2.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapScanPrefix); len(ks) != 0 {
			t.Fatalf("%s: %v", edge, ks)
		}
	}
	// 3. a consistent neighbour passes
	sc3 := newScenario(t, LocTxInput, 0)
	st3 := NewMemStore()
	requestPrefix(t, st3, 990, 999)
	prev := BatchRecord{N: 76, L1Block: 900, L1Hash: [32]byte{9}, BeforeAcc: [32]byte{1}, AfterAcc: sc3.rec.BeforeAcc, DelayedAcc: [32]byte{3}}
	if err := st3.Put(ctx, Key{Chain: ChainArbitrumSepolia, L1Block: 900, L1Hash: prev.L1Hash, Item: ItemBatch(76)}, prev.Encode()); err != nil {
		t.Fatal(err)
	}
	if err := prefixCapturer(sc3, st3, 400, nil).scanPrefix(ctx, &Report{}); err != nil {
		t.Fatalf("batch 77 follows the stored batch 76: %v", err)
	}
}
