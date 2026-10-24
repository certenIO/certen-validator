// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-FIX D3: SelfCheckReport says what the check did, so the on-demand caller can name it: what it compared, what it skipped for lack
// of memory (never counted as passed) and what it found different.
func TestRB12SelfCheckReportCountsComparedSkippedAndMismatched(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 12)
	ix := newIdx(w, bp, IndexConfig{})
	stepAll(t, ix, w.numberOf(11)+200)
	res, err := ix.SelfCheckReport(context.Background(), 64)
	if err != nil || res.Generation != 1 || res.Entries == 0 || res.Digests == 0 || res.Skipped != 0 || res.Mismatches != 0 {
		t.Fatalf("a clean index compares entries and digests and skips nothing: %+v %v", res, err)
	}
	// a refused reservation: the check is skipped and the result says so
	ctx := finality.WithMemoryBudget(context.Background(), finality.NewMemoryBudget(64<<10))
	res, err = ix.SelfCheckReport(ctx, 64)
	if err != nil || res.Skipped == 0 {
		t.Fatalf("skipped checks are reported: %+v %v", res, err)
	}
	// a damaged digest is a mismatch, counted and named
	for k, v := range indexRows(t, w) {
		if strings.HasSuffix(k.Item, "/f") && k.L1Block == w.numberOf(3) {
			d, err := decodeDigest(k, v)
			if err != nil {
				t.Fatal(err)
			}
			d.Txs[0].Frames[0].Len++
			w.mu.Lock()
			w.extra[k] = d.encode()
			w.mu.Unlock()
		}
	}
	res, err = ix.SelfCheckReport(context.Background(), 64)
	if res.Mismatches == 0 {
		t.Fatalf("the damaged digest is counted: %+v %v", res, err)
	}
	if se, ok := finality.AsNamed(err); !ok || se.Fields["reason"] != finality.IndexSelfCheckMismatch {
		t.Fatalf("and named: %v", err)
	}
}
