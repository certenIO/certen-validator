// Copyright 2026 Certen Protocol

package baseposted

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-FIX Note (b): the HOLE INTERLOCK WITH BACKFILL. A block that the capture adds BELOW the index cursor (the CAPTURE-GAP backfill
// filling a hole, a retried capture, a block another validator captured) must get its digest and the entries of the channels it completes
// within one reconcile interval, not after the rotation of the whole table (about 51 minutes at 18 days of table).

func hasDigest(t testing.TB, st finality.CaptureStore, block uint64) bool {
	t.Helper()
	for k := range indexRows(t, st) {
		if k.L1Block == block && strings.HasSuffix(k.Item, "/f") {
			return true
		}
	}
	return false
}

func entryClosingAt(t testing.TB, st finality.CaptureStore, block uint64, id [16]byte) bool {
	t.Helper()
	for k := range indexRows(t, st) {
		if n, ok := parseEntryName(1, k); ok && n.ID == id && k.L1Block == block {
			return true
		}
	}
	return false
}

// A block filled near the head is found by the recent window of the next scheduled reconcile, though the rotating walk (16 blocks per round
// here) is nowhere near it.
func TestRB12LateBlockNearTheHeadIsIndexedWithinOneReconcileInterval(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	A := channelFrames("A", 1_790_300_000, 30, 1000, 2)
	vPutBlock(t, st, bp, 1010, []Frame{A[0]})
	filler := channelFrames("F", 1_790_400_000, 10, 1000, 1)
	vPutBlock(t, st, bp, 1020, []Frame{filler[0]})
	ix := newIdx(st, bp, IndexConfig{ReconcileEvery: 1, ReconcileSpan: 16})
	stepAll(t, ix, 1500)
	if entryClosingAt(t, st, 1480, chanLabelID("A")) {
		t.Fatal("the channel is not complete yet")
	}
	vPutBlock(t, st, bp, 1480, []Frame{A[1]}) // captured late, 20 blocks below the cursor
	stepAll(t, ix, 1500)
	if !hasDigest(t, st, 1480) || !entryClosingAt(t, st, 1480, chanLabelID("A")) {
		t.Fatalf("a block filled below the cursor must get its digest and complete its channel within one reconcile interval (digest %v)", hasDigest(t, st, 1480))
	}
}
