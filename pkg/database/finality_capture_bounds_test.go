// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-DBFIX D3: the column l1_block is a signed 64-bit integer, a CaptureKey's block is a uint64. A block number above MaxInt64
// used to wrap to a negative bigint in ListByRange (so (0, MaxInt64+1) and (0, MaxUint64) returned NO keys) and to reach the
// table's CHECK as a raw pq error in Put. Every method of the store now judges the range first.

func TestFinalityCaptureRangeAboveMaxInt64IsClampedNotWrapped(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	low, high := key(chain, 100, 0x11, "a/low"), key(chain, math.MaxInt64, 0x22, "a/high")
	for _, k := range []finality.CaptureKey{low, high} {
		if err := store.Put(ctx, k, []byte(k.Item)); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}
	both := func(keys []finality.CaptureKey) bool { return len(keys) == 2 && keys[0] == low && keys[1] == high }

	for name, to := range map[string]uint64{"MaxInt64": math.MaxInt64, "MaxInt64+1": uint64(math.MaxInt64) + 1, "MaxUint64": math.MaxUint64} {
		keys, err := store.ListByRange(ctx, chain, 0, to, "")
		if err != nil || !both(keys) {
			t.Fatalf("ListByRange(0, %s): %v %v: want both rows (the upper bound is clamped to MaxInt64, never wrapped)", name, keys, err)
		}
		keys, err = store.ListByRange(ctx, chain, 100, to, "a/h")
		if err != nil || len(keys) != 1 || keys[0] != high {
			t.Fatalf("ListByRange(100, %s, a/h): %v %v", name, keys, err)
		}
	}
	// a range that starts above the largest block the table can hold is empty, not an error and not a wrapped scan
	for name, from := range map[string]uint64{"MaxInt64+1": uint64(math.MaxInt64) + 1, "MaxUint64": math.MaxUint64} {
		keys, err := store.ListByRange(ctx, chain, from, math.MaxUint64, "")
		if err != nil || len(keys) != 0 {
			t.Fatalf("ListByRange(%s, MaxUint64): %v %v: want empty", name, keys, err)
		}
	}
	if keys, err := store.ListByRange(ctx, chain, 200, 100, ""); err != nil || len(keys) != 0 {
		t.Fatalf("an inverted range: %v %v", keys, err)
	}
}

func TestFinalityCaptureKeysAboveMaxInt64AreANamedStateNotARawDatabaseError(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	for name, blk := range map[string]uint64{"MaxInt64+1": uint64(math.MaxInt64) + 1, "MaxUint64": math.MaxUint64} {
		k := key(chain, blk, 0x33, "a/x")
		err := store.Put(ctx, k, []byte("x"))
		st, ok := finality.AsNamed(err)
		if !ok || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "capture.l1_block" || st.Fields["count"] != blk || st.Fields["limit"] != uint64(math.MaxInt64) {
			t.Fatalf("Put at %s: %v: want finality_evidence_too_large{part:capture.l1_block, count:%d, limit:MaxInt64}", name, err, blk)
		}
		if _, found, err := store.Get(ctx, k); err != nil || found {
			t.Fatalf("Get at %s: found=%v err=%v: no row can exist there, so it is simply absent", name, found, err)
		}
		rows, err := store.ListByBlock(ctx, chain, blk)
		if err != nil || len(rows) != 0 {
			t.Fatalf("ListByBlock at %s: %v %v", name, rows, err)
		}
	}
	// the largest block the table holds still works end to end
	k := key(chain, math.MaxInt64, 0x44, "a/edge")
	if err := store.Put(ctx, k, []byte("edge")); err != nil {
		t.Fatalf("Put at MaxInt64: %v", err)
	}
	if b, ok, err := store.Get(ctx, k); err != nil || !ok || string(b) != "edge" {
		t.Fatalf("Get at MaxInt64: %q %v %v", b, ok, err)
	}
	if rows, err := store.ListByBlock(ctx, chain, math.MaxInt64); err != nil || len(rows) != 1 {
		t.Fatalf("ListByBlock at MaxInt64: %v %v", rows, err)
	}
}
