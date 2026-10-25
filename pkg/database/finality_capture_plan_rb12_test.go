// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 OPS-A2 item 5 (ledger CG-5): a listing of the capture table by item prefix, from block 0 as a gap lookup must, costs the rows of that
// item family and not the rows of the table. Migration 00030's index (chain, item text_pattern_ops, l1_block) serves it; this test fills a chain
// with a large table of other rows around a handful of gap rows, asks the planner for the listing ListByRange sends, and requires the index.

const planChain = 12 // a chain id no other test uses; the table is insert-only, so the rows of a run stay and the blocks are unique to the run

func TestListByRangeUsesTheItemIndexAndItsCostDoesNotGrowWithTheTable(t *testing.T) {
	ctx := context.Background()
	base := int(time.Now().Unix()) * 1_000_000 // unique to the run (a run spans 150k blocks): the table refuses DELETE
	fill := func(rows int) {
		if _, err := testDB.Exec(`INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes)
			SELECT $1, g, decode(lpad(to_hex(g), 64, '0'), 'hex'), 'blob/' || (g % 7)::text || '/0', 'x'::bytea FROM generate_series($2::bigint + 1000, $2::bigint + 1000 + $3::bigint) g`,
			int64(planChain), int64(base), int64(rows)); err != nil {
			t.Fatal(err)
		}
	}
	gap := func(block int) {
		if _, err := testDB.Exec(`INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes)
			VALUES ($1, $2::bigint, decode(repeat('00', 32), 'hex'), 'gap/' || ($2::bigint + 9)::text || '/outage_unscanned', 'g'::bytea)`, int64(planChain), int64(block)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 20; i++ {
		gap(base + 10 + i*3)
	}
	cost := func() (nodeRows float64, usesIndex bool, plan string) {
		t.Helper()
		if _, err := testDB.Exec(`ANALYZE proof_finality_capture`); err != nil {
			t.Fatal(err)
		}
		var raw []byte
		q := "EXPLAIN (FORMAT JSON) " + listByRangeSQL
		if err := testDB.QueryRow(q, int64(planChain), int64(0), int64(finality.MaxCaptureBlock), likePrefix("gap/")).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var p []struct {
			Plan struct {
				Rows float64 `json:"Plan Rows"`
			} `json:"Plan"`
		}
		if err := json.Unmarshal(raw, &p); err != nil || len(p) != 1 {
			t.Fatalf("plan %s: %v", raw, err)
		}
		return p[0].Plan.Rows, strings.Contains(string(raw), "proof_finality_capture_item_idx"), string(raw)
	}
	fill(20_000)
	smallRows, usesSmall, planSmall := cost()
	if _, err := testDB.Exec(`INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes)
		SELECT $1, g, decode(lpad(to_hex(g), 64, '0'), 'hex'), 'blob/' || (g % 7)::text || '/1', 'x'::bytea FROM generate_series($2::bigint + 30000, $2::bigint + 150000) g`, int64(planChain), int64(base)); err != nil {
		t.Fatal(err)
	}
	bigRows, usesBig, planBig := cost()
	if !usesSmall || !usesBig {
		t.Fatalf("the listing does not use proof_finality_capture_item_idx:\nsmall table: %s\nbig table: %s", planSmall, planBig)
	}
	if bigRows > 2*smallRows+50 {
		t.Fatalf("the estimated rows grew with the table: %.0f at 20k rows, %.0f at 140k rows", smallRows, bigRows)
	}
	// the listing itself: exactly the 20 gap rows, in block order, from block 0
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	ks, err := store.ListByRange(ctx, planChain, 0, finality.MaxCaptureBlock, "gap/") // from block 0, as a gap lookup does
	if err != nil || len(ks) < 20 {
		t.Fatalf("%d gap rows: %v", len(ks), err)
	}
	mine, err := store.ListByRange(ctx, planChain, uint64(base), uint64(base+200_000), "gap/")
	if err != nil || len(mine) != 20 {
		t.Fatalf("%d gap rows of this run: %v", len(mine), err)
	}
	ks = mine
	for i := 1; i < len(ks); i++ {
		if ks[i-1].L1Block >= ks[i].L1Block {
			t.Fatalf("not in block order at %d", i)
		}
	}
	// the prefix is escaped: LIKE metacharacters in it match themselves only
	for _, item := range []string{"a_b/1", "azb/2", "100abc/4"} {
		if _, err := testDB.Exec(`INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes) VALUES ($1, $3::bigint, decode(repeat('01', 32), 'hex'), $2, 'x'::bytea)`, int64(planChain), item, int64(base+5)); err != nil {
			t.Fatal(err)
		}
	}
	for prefix, want := range map[string]int{"a_b/": 1, "100%": 0, "a": 2, "100": 1, "": -1} {
		got, err := store.ListByRange(ctx, planChain, uint64(base+5), uint64(base+5), prefix)
		if err != nil {
			t.Fatal(err)
		}
		if want >= 0 && len(got) != want {
			t.Errorf("prefix %q: %d keys, want %d (%v)", prefix, len(got), want, got)
		}
		if want < 0 && len(got) < 3 {
			t.Errorf("the empty prefix lists everything in the range: %d", len(got))
		}
	}
}
