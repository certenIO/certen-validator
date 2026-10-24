// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-FIX L4 (V-INDEX-4): a channel whose first and closing frames are more than SeqWindowSize L1 blocks apart cannot be served (the
// verifier refuses a frame further than the window from the batch's origin), and the in-order indexer never saw it complete (its table forgets
// blocks older than the window) while the late path (a table loaded around the late block) did and wrote an entry: validators with different
// arrival orders then held different entry sets and the self-check flagged the difference. ensureEntry now writes NO entry for such a channel on
// either path, and counts the skip.

func entryRowsOf(t testing.TB, st interface {
	ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]CaptureKey, error)
}) int {
	t.Helper()
	ks, err := st.ListByRange(context.Background(), uint64(Chain), 0, 1<<62, "idx/g1/bi/c/")
	if err != nil {
		t.Fatal(err)
	}
	return len(ks)
}

func TestRB12AChannelSpanningMoreThanTheWindowGetsNoEntryByAnyArrivalOrder(t *testing.T) {
	metrics.RegisterMetrics()
	_, bp := idxPins(t)
	W := bp.SeqWindowSize
	first, closing := uint64(1010), 1010+W+1 // one block further apart than the window
	A := channelFrames("wide", 1_790_300_000, 30, 1000, 2)
	ok := channelFrames("ok", 1_790_400_000, 30, 1000, 1)

	// validator 1: every block present when the indexer reaches it (in order)
	st1 := NewMemStore()
	vPutBlock(t, st1, bp, first, []Frame{A[0]})
	vPutBlock(t, st1, bp, closing, []Frame{A[1]})
	vPutBlock(t, st1, bp, first+20, []Frame{ok[0]})
	ix1 := newIdx(st1, bp, IndexConfig{ReconcileEvery: 1})
	before, _ := vGather(t, "certen_finality_index_entries_skipped_total")
	stepAll(t, ix1, closing+500)

	// validator 2: the first block arrives late, after the cursor passed the closing block (the late path)
	st2 := NewMemStore()
	vPutBlock(t, st2, bp, closing, []Frame{A[1]})
	vPutBlock(t, st2, bp, first+20, []Frame{ok[0]})
	ix2 := newIdx(st2, bp, IndexConfig{ReconcileEvery: 1})
	stepAll(t, ix2, closing+500)
	vPutBlock(t, st2, bp, first, []Frame{A[0]})
	ix2.NoteLate(first)
	stepAll(t, ix2, closing+500)

	for name, st := range map[string]*MemStore{"in order": st1, "late": st2} {
		for k := range indexRows(t, st) {
			if n, isEntry := parseEntryName(1, k); isEntry && n.ID == chanLabelID("wide") {
				t.Fatalf("%s: a channel spanning %d blocks (window %d) has an entry %s", name, closing-first, W, k.Item)
			}
		}
		if got := entryRowsOf(t, st); got != 1 {
			t.Fatalf("%s: only the channel inside the window has an entry, got %d entries", name, got)
		}
	}
	// two validators with different arrival orders hold identical sets, and the self-check has nothing to flag
	if d := sameRows(indexRows(t, st1), indexRows(t, st2)); d != "" {
		t.Fatalf("different arrival orders must give the same index rows: %s", d)
	}
	for name, ix := range map[string]*Indexer{"in order": ix1, "late": ix2} {
		res, err := ix.SelfCheckReport(context.Background(), 64)
		if err != nil || res.Mismatches != 0 {
			t.Fatalf("%s: the self-check is quiet: %+v %v", name, res, err)
		}
	}
	// the late path counted the skip (once per channel per process)
	after, present := vGather(t, "certen_finality_index_entries_skipped_total")
	if !present || after-before < 1 {
		t.Fatalf("a skipped entry is counted: %v -> %v (present %v)", before, after, present)
	}
}
