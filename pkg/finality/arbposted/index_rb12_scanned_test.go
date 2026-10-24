// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// RB12-TRAIN3-INT duty (3): a number missing between two captured batches is a hole in the capture only where the capture scanned. Ground that
// was never scanned (between a prefix window and the live region) is the coverage judgement's, and a range the prefix scan CLOSED (a gapscan
// row) is ground that was scanned.
func TestRB12ArbScannedBetweenKnowsLiveGroundClosedScansAndUnscannedGround(t *testing.T) {
	ctx := context.Background()
	st := capture.NewMemStore()
	chain := finality.ChainArbitrumSepolia
	cursor := func(block uint64) {
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], block)
		if err := st.Put(ctx, capture.Key{Chain: chain, L1Block: block, Item: capture.ItemCursor}, v[:]); err != nil {
			t.Fatal(err)
		}
	}
	cursor(100_000) // the live loop started here: scanned ground begins at 100,000 less the first-scan slack
	cursor(100_500)
	r := &IndexReader{Store: st}
	live := uint64(100_000) - firstScanSlack
	ok := func(lo, hi uint64) bool {
		got, err := r.scannedBetween(ctx, lo, hi)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if !ok(live+10, 100_400) {
		t.Fatal("two batches in the live region bound a capture hole")
	}
	if ok(50_000, 60_000) {
		t.Fatal("ground below the live region that no scan covers is not scanned ground")
	}
	if err := finality.RecordGapScan(ctx, st, chain, 50_000, 54_999); err != nil {
		t.Fatal(err)
	}
	if !ok(50_100, 54_900) {
		t.Fatal("a range the prefix scan closed is scanned ground")
	}
	if ok(50_100, 55_100) {
		t.Fatal("a stretch beyond the closed range is not")
	}
	if err := finality.RecordGapScan(ctx, st, chain, 55_000, 59_999); err != nil {
		t.Fatal(err)
	}
	if !ok(50_100, 59_000) {
		t.Fatal("adjacent closed ranges are one stretch of scanned ground")
	}
	if ok(40_000, 100_400) {
		t.Fatal("a stretch from unscanned ground into the live region is not scanned ground")
	}
}
