// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/metrics"
)

// ixMetric is the sum of a metric over its series with family="arb" (counters and gauges by value, histograms by sample count).
func ixMetric(t *testing.T, name string) (float64, bool) {
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
			arb := false
			for _, l := range m.Label {
				if l.GetName() == "family" && l.GetValue() == FamilyArb {
					arb = true
				}
			}
			if !arb {
				continue
			}
			found = true
			switch mf.GetType() {
			case dto.MetricType_GAUGE:
				sum += m.GetGauge().GetValue()
			case dto.MetricType_COUNTER:
				sum += m.GetCounter().GetValue()
			case dto.MetricType_HISTOGRAM:
				sum += float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return sum, found
}

// The twelve series of the index (lag, entries, digests, open, rebuilds, mismatches, conflicts, lookups, lookup bytes, step seconds, plus
// through, late, skipped self-checks, unindexable blocks and dropped notes) are labelled family="arb" and are NON-ZERO at the moment each is meant
// to move; the lag alert can fire.
func TestRB12ArbIndexMetricsAreSetWhereTheyShouldBe(t *testing.T) {
	metrics.RegisterMetrics()
	delta := func(name string, f func()) float64 {
		before, _ := ixMetric(t, name)
		f()
		after, ok := ixMetric(t, name)
		if !ok {
			t.Fatalf("%s has no family=arb series", name)
		}
		return after - before
	}
	w, legs := ixPopulation(t)
	big := make([][][]byte, 0)
	for j := 0; j < 500; j++ {
		big = append(big, ixMsg(ixBigTx(42000+j, 700)))
	}
	w.add(ixBatch{N: 230, Block: 1300, T: ixT0 + 3000, Msgs: big, Blobs: 1, Partial: true}) // a batch whose blobs have not all arrived: open
	w.cursor(w.low - 1)
	w.cursor(w.top + 1)
	ix := w.indexer(IndexConfig{BlocksPerStep: 4})

	// a partial step: through and lag are set, the lag is large, rebuilds counts the generation, digests and entries move, the step is timed
	var rep finality.StepReport
	if d := delta("certen_finality_index_rebuilds_total", func() {
		if d := delta("certen_finality_index_digests_total", func() {
			var err error
			if rep, err = ix.Step(context.Background(), w.top+1); err != nil {
				t.Fatal(err)
			}
		}); d < 1 {
			t.Fatalf("a step that digested %d blocks moved digests_total by %v", rep.Blocks, d)
		}
	}); d != 1 {
		t.Fatalf("rebuilds_total moved by %v on the first step of a generation", d)
	}
	for _, n := range []string{"certen_finality_index_through_block", "certen_finality_index_lag_blocks", "certen_finality_index_entries_total", "certen_finality_index_step_seconds"} {
		if v, ok := ixMetric(t, n); !ok || v == 0 {
			t.Errorf("%s = %v (present %v) after a partial backfill step", n, v, ok)
		}
	}
	if v, _ := ixMetric(t, "certen_finality_index_lag_blocks"); v < 100 {
		t.Errorf("the lag after a 4-block step is %v blocks: the lag alert could not fire", v)
	}
	stepAll(t, ix, w.top+1)
	if v, _ := ixMetric(t, "certen_finality_index_open_channels"); v != 1 {
		t.Errorf("open (batches whose data rows are not all stored) = %v, want 1", v)
	}
	if v, _ := ixMetric(t, "certen_finality_index_lag_blocks"); v != 0 {
		t.Errorf("the lag of a caught-up index is %v", v)
	}
	// lookups and lookup bytes
	r := w.reader()
	if d := delta("certen_finality_index_lookups_total", func() { w.idx(r, ixT0+300, legs["d1"]) }); d < 1 {
		t.Errorf("lookups_total moved by %v", d)
	}
	if v, ok := ixMetric(t, "certen_finality_index_lookup_bytes"); !ok || v == 0 {
		t.Errorf("lookup_bytes = %v (present %v)", v, ok)
	}
	// late blocks: the open batch's blobs arrive and the next step digests the block
	key := w.keys[230][0]
	blobs := encodeBlobs(ixPayload(big))
	if d := delta("certen_finality_index_late_blocks_total", func() {
		for j := 1; j < len(blobs); j++ {
			w.put(withItem(key, capture.ItemBlob(230, j)), capture.BlobRecord{Raw: blobs[j]}.Encode())
		}
		if _, err := ix.Step(context.Background(), w.top+1); err != nil {
			t.Fatal(err)
		}
	}); d != 1 {
		t.Errorf("late_blocks_total moved by %v for one late block", d)
	}
	// a self-check that finds a lying entry; a self-check the memory budget refuses (counted, never silent)
	ek := w.entryKey(203)
	good, _, _ := w.store.Get(context.Background(), ek)
	e, _ := decodeEntry(good)
	e.Fps = nil
	o := newOverlay(w.store)
	o.over[ek] = e.encode()
	ix2, err := NewIndexer(o, w.pins, 0, IndexConfig{SelfCheckSample: 100, ReconcileSpan: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if d := delta("certen_finality_index_mismatches_total", func() { _ = ix2.SelfCheck(context.Background(), 100) }); d != 1 {
		t.Errorf("mismatches_total moved by %v for one lying entry", d)
	}
	tiny := finality.WithMemoryBudget(context.Background(), finality.NewMemoryBudget(1).WithWait(1))
	ix3, _ := NewIndexer(w.store, w.pins, 0, IndexConfig{SelfCheckSample: 100, ReconcileSpan: 1 << 20})
	if d := delta("certen_finality_index_selfcheck_skipped_total", func() { _ = ix3.SelfCheck(tiny, 100) }); d < 1 {
		t.Errorf("selfcheck_skipped_total moved by %v with a budget too small for any batch", d)
	}
	// a conflicting write
	if d := delta("certen_finality_index_conflicts_total", func() {
		_ = finality.IndexPut(context.Background(), w.store, FamilyArb, ek, []byte("another writer"))
	}); d != 1 {
		t.Errorf("conflicts_total moved by %v", d)
	}
	// an unreadable block
	hdr, hash := ixHeader(1400, ixT0+4000, common.Hash{0xee})
	bad := finality.CaptureKey{Chain: ixChain, L1Block: 1400, L1Hash: hash}
	w.put(withItem(bad, capture.ItemHeader), hdr)
	w.put(withItem(bad, capture.ItemBatch(260)), []byte("not a batch"))
	w.cursor(1500)
	if d := delta("certen_finality_index_unindexable_blocks_total", func() { stepAll(t, ix, 1500) }); d != 1 {
		t.Errorf("unindexable_blocks_total moved by %v", d)
	}
	// dropped notes: more than the pending set holds
	if d := delta("certen_finality_index_notes_dropped_total", func() {
		for b := uint64(0); b < maxHints+10; b++ {
			ix.NoteLate(b)
		}
	}); d != 10 {
		t.Errorf("notes_dropped_total moved by %v for 10 notes past the cap", d)
	}
}
