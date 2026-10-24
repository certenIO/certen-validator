// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-B against the real table: the Arbitrum batch index rows (family arb) are ordinary rows of proof_finality_capture. The LONGEST
// item name each row kind can have (generation 2^32-1, timestamps and batch number 2^64-1, spelled exactly as pkg/finality/arbposted spells them:
// TestRB12ArbIndexLongestNamesFitTheProductionTable pins the same strings to the code) must satisfy the table's name constraint and the capture's
// own bound, and the key listings the lookup runs must find them across digit widths.
func TestFinalityCaptureIndexArbRowsFitTheProductionTable(t *testing.T) {
	ctx := context.Background()
	st := NewFinalityCaptureStore(NewClientFromDB(testDB))
	const chain = 840098
	const fam = "arb"
	max := "18446744073709551615"
	longest := []string{
		"idx/g4294967295/arb/f/" + max,
		"idx/g4294967295/arb/e/" + max + "/" + max + "/" + max,
		"idx/g4294967295/arb/q/" + max,
		"idx/g4294967295/arb/w/" + max + "/" + max + "/" + max,
		"idx/g4294967295/arb/u",
		"idx/g4294967295/arb/cursor",
	}
	h := func(b byte) [32]byte { return [32]byte{b} }
	for i, it := range longest {
		if len(it) > finality.MaxCaptureItem {
			t.Fatalf("%s is %d bytes, the capture's own bound is %d", it, len(it), finality.MaxCaptureItem)
		}
		k := finality.CaptureKey{Chain: chain, L1Block: uint64(500 + i), L1Hash: h(byte(i + 1)), Item: it}
		if err := finality.IndexPut(ctx, st, fam, k, []byte{byte(i), 7}); err != nil {
			t.Fatalf("%s (%d bytes): the production table must accept the longest name: %v", it, len(it), err)
		}
		if err := finality.IndexPut(ctx, st, fam, k, []byte{byte(i), 7}); err != nil {
			t.Fatalf("%s: identical bytes: %v", it, err)
		}
	}
	// the listings of the lookup: entries and digests of one generation, across digit widths of the timestamps and batch numbers in the name
	for i, it := range []string{
		"idx/g1/arb/f/9", "idx/g1/arb/f/10", "idx/g1/arb/f/1790000000", "idx/g1/arb/f/9999999999", "idx/g1/arb/f/10000000000",
		"idx/g1/arb/e/9/10/9", "idx/g1/arb/e/1790000000/1790087168/884511", "idx/g1/arb/e/1790000000/1790087168/1000000",
	} {
		k := finality.CaptureKey{Chain: chain, L1Block: uint64(600 + i), L1Hash: h(byte(40 + i)), Item: it}
		if err := finality.IndexPut(ctx, st, fam, k, []byte{1}); err != nil {
			t.Fatalf("%s: %v", it, err)
		}
	}
	fs, err := st.ListByRange(ctx, chain, 0, 1000, "idx/g1/arb/f/")
	if err != nil || len(fs) != 5 {
		t.Fatalf("digest listing: %v %v", fs, err)
	}
	es, err := st.ListByRange(ctx, chain, 0, 1000, "idx/g1/arb/e/")
	if err != nil || len(es) != 3 {
		t.Fatalf("entry listing: %v %v", es, err)
	}
	// a narrow L1 range (the window of a lookup) returns only its own keys, in key order
	es, err = st.ListByRange(ctx, chain, 605, 606, "idx/g1/arb/e/")
	if err != nil || len(es) != 2 || es[0].L1Block != 605 || es[1].L1Block != 606 {
		t.Fatalf("a range listing: %v %v", es, err)
	}
	// the pointers of wide batches live at block 0 under the hash of the batch's block: two records of one slot with the same name keep their own
	// rows, and a point range lists them all and nothing else
	pointers := []finality.CaptureKey{
		{Chain: chain, L1Block: 0, L1Hash: h(1), Item: "idx/g1/arb/w/5/10/7"},
		{Chain: chain, L1Block: 0, L1Hash: h(2), Item: "idx/g1/arb/w/5/10/7"},
		{Chain: chain, L1Block: 0, L1Hash: h(3), Item: "idx/g1/arb/w/5/12/8"},
	}
	for i, wk := range pointers {
		if err := finality.IndexPut(ctx, st, fam, wk, []byte{byte(i)}); err != nil {
			t.Fatalf("%s: %v", wk.Item, err)
		}
	}
	ws, err := st.ListByRange(ctx, chain, 0, 0, "idx/g1/arb/w/") // (rows are insert-only: a database that ran this test before may hold more)
	if err != nil {
		t.Fatalf("the point listing of the wide pointers: %v", err)
	}
	listed := map[finality.CaptureKey]bool{}
	for _, k := range ws {
		listed[k] = true
	}
	for _, wk := range pointers {
		if !listed[wk] {
			t.Fatalf("the point listing of the wide pointers misses %v: %v", wk, ws)
		}
	}
	// different bytes under an index key are the named conflict
	k := finality.CaptureKey{Chain: chain, L1Block: 501, L1Hash: h(2), Item: longest[1]}
	if err := finality.IndexPut(ctx, st, fam, k, []byte("another writer")); err == nil {
		t.Fatal("a different row under an index key must conflict")
	}
	if got, ok, err := st.Get(ctx, k); err != nil || !ok || !bytes.Equal(got, []byte{1, 7}) {
		t.Fatalf("the stored row changed: %v %v %v", got, ok, err)
	}
	// the digest listing the time map runs: the first digests at or after a block, bounded to a narrow range
	narrow, err := st.ListByRange(ctx, chain, 600, 603, "idx/g1/arb/f/")
	if err != nil || len(narrow) != 4 {
		t.Fatalf("a narrow digest listing: %v %v", narrow, err)
	}
}
