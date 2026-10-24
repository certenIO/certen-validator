// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// Mutation-gate killers for FinalityCaptureStore (RB12-DBFIX): every method returns the database's error, a key the table cannot
// hold is judged before any query, the order PutBlock inserts in, and the exact edges of the signed 64-bit bound.

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestCaptureStoreReturnsTheDatabasesErrorFromEveryMethod(t *testing.T) {
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	k := key(7, 1, 0x11, "hdr")
	if err := store.Put(canceled(), k, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Errorf("Put: %v", err)
	}
	if b, ok, err := store.Get(canceled(), k); !errors.Is(err, context.Canceled) || ok || b != nil {
		t.Errorf("Get: %v %v %v", b, ok, err)
	}
	if rows, err := store.ListByBlock(canceled(), 7, 1); !errors.Is(err, context.Canceled) || rows != nil {
		t.Errorf("ListByBlock: %v %v", rows, err)
	}
	if keys, err := store.ListByRange(canceled(), 7, 0, 10, ""); !errors.Is(err, context.Canceled) || keys != nil {
		t.Errorf("ListByRange: %v %v", keys, err)
	}
	if sz, err := store.BlockSizes(canceled(), 7, 1, k.L1Hash); !errors.Is(err, context.Canceled) || sz != nil {
		t.Errorf("BlockSizes: %v %v", sz, err)
	}
	if err := store.PutBlock(canceled(), []finality.CaptureRow{{CaptureKey: k, Bytes: []byte("x")}}); !errors.Is(err, context.Canceled) {
		t.Errorf("PutBlock: %v", err)
	}
}

// A key the table cannot hold is judged before any query: with a context that is already done, the answer is still the empty one.
func TestCaptureStoreAnswersForAKeyTheTableCannotHoldWithoutAskingTheDatabase(t *testing.T) {
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	big := uint64(math.MaxInt64) + 1
	k := key(7, big, 0x11, "hdr")
	if b, ok, err := store.Get(canceled(), k); err != nil || ok || b != nil {
		t.Errorf("Get above MaxInt64: %v %v %v", b, ok, err)
	}
	if rows, err := store.ListByBlock(canceled(), 7, big); err != nil || len(rows) != 0 {
		t.Errorf("ListByBlock above MaxInt64: %v %v", rows, err)
	}
	if sz, err := store.BlockSizes(canceled(), 7, big, k.L1Hash); err != nil || len(sz) != 0 {
		t.Errorf("BlockSizes above MaxInt64: %v %v", sz, err)
	}
	if keys, err := store.ListByRange(canceled(), 7, big, math.MaxUint64, ""); err != nil || len(keys) != 0 {
		t.Errorf("ListByRange from above MaxInt64: %v %v", keys, err)
	}
	if keys, err := store.ListByRange(canceled(), big, 0, 10, ""); err != nil || len(keys) != 0 {
		t.Errorf("ListByRange of a chain above MaxInt64: %v %v", keys, err)
	}
	if keys, err := store.ListByRange(canceled(), 7, 10, 5, ""); err != nil || len(keys) != 0 {
		t.Errorf("an inverted range asks nobody: %v %v", keys, err)
	}
}

func TestCaptureStoreChainEdges(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	// chain 0 is refused by name; chain 1 is a chain
	if err := store.Put(ctx, key(0, 5, 0x21, "hdr"), nil); err == nil || !strings.Contains(err.Error(), "chain 0") {
		t.Errorf("Put chain 0: %v", err)
	}
	if err := store.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: key(0, 5, 0x21, "hdr")}}); err == nil || !strings.Contains(err.Error(), "chain 0") {
		t.Errorf("PutBlock chain 0: %v", err)
	}
	// a block no other test uses
	blk := uint64(2_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	if err := store.Put(ctx, key(1, blk, 0x21, "hdr"), []byte("one")); err != nil {
		t.Errorf("Put chain 1: %v", err)
	}
	if err := store.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: key(1, blk, 0x21, "tx/1"), Bytes: []byte("one")}}); err != nil {
		t.Errorf("PutBlock chain 1: %v", err)
	}
	// the largest chain the signed column holds is stored and read back; one more is the named state, from Put and from PutBlock
	maxChain := uint64(math.MaxInt64)
	k := key(maxChain, blk, 0x22, "hdr")
	if err := store.Put(ctx, k, []byte("max")); err != nil {
		t.Fatalf("Put at the largest chain: %v", err)
	}
	if b, ok, err := store.Get(ctx, k); err != nil || !ok || string(b) != "max" {
		t.Errorf("Get at the largest chain: %q %v %v", b, ok, err)
	}
	if rows, err := store.ListByBlock(ctx, maxChain, blk); err != nil || len(rows) != 1 {
		t.Errorf("ListByBlock at the largest chain: %v %v", rows, err)
	}
	if sz, err := store.BlockSizes(ctx, maxChain, blk, k.L1Hash); err != nil || sz["hdr"] != 3 {
		t.Errorf("BlockSizes at the largest chain: %v %v", sz, err)
	}
	over := key(maxChain+1, blk, 0x22, "hdr")
	for name, err := range map[string]error{"Put": store.Put(ctx, over, nil), "PutBlock": store.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: over}})} {
		if st, ok := finality.AsNamed(err); !ok || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "capture.chain" {
			t.Errorf("%s of a chain above MaxInt64: %v", name, err)
		}
	}
	// a range whose two ends are the same block is that block
	if keys, err := store.ListByRange(ctx, maxChain, blk, blk, ""); err != nil || len(keys) != 1 {
		t.Errorf("ListByRange(blk, blk): %v %v", keys, err)
	}
}

func TestCaptureStoreNamesAnItemOutsideTheAlphabetBeforeTheDatabaseDoes(t *testing.T) {
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	want := finality.CheckCaptureItem("Bad Item")
	if want == nil {
		t.Fatal("the item alphabet accepts a name with a space and capitals")
	}
	if err := store.Put(canceled(), key(7, 1, 0x31, "Bad Item"), nil); err == nil || err.Error() != want.Error() {
		t.Errorf("Put: %v, want %v", err, want)
	}
	if err := store.PutBlock(canceled(), []finality.CaptureRow{{CaptureKey: key(7, 1, 0x31, "Bad Item")}}); err == nil || err.Error() != want.Error() {
		t.Errorf("PutBlock: %v, want %v", err, want)
	}
}

// A PutBlock whose insert is held up by a row lock another transaction holds fails with the database's error and stores nothing.
func TestPutBlockReturnsTheErrorOfAnInsertTheDatabaseCannotComplete(t *testing.T) {
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	blk := uint64(2_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	k := key(9, blk, 0x41, "hdr")
	holder, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.Exec(`INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes) VALUES ($1, $2, $3, $4, $5)`, int64(k.Chain), int64(k.L1Block), k.L1Hash[:], k.Item, []byte("held")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	other := key(9, blk, 0x41, "tx/1")
	if err := store.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: other, Bytes: []byte("a")}, {CaptureKey: k, Bytes: []byte("b")}}); err == nil {
		t.Fatal("a PutBlock that waited for a lock past its deadline reported success")
	}
	holder.Rollback()
	if rows, err := store.ListByBlock(context.Background(), 9, blk); err != nil || len(rows) != 0 {
		t.Fatalf("the failed call left rows: %v %v", rows, err)
	}
}

func TestCaptureKeyLessIsTheInsertOrderChainBlockHashItem(t *testing.T) {
	ordered := []finality.CaptureKey{
		key(1, 9, 9, "z"), key(2, 1, 1, "a"), key(2, 2, 1, "a"), key(2, 2, 2, "a"), key(2, 2, 2, "b"), key(3, 0, 0, "a"),
	}
	for i := range ordered {
		for j := range ordered {
			if got, want := captureKeyLess(ordered[i], ordered[j]), i < j; got != want {
				t.Errorf("less(%s, %s) = %v, want %v", ordered[i], ordered[j], got, want)
			}
		}
	}
	// a hash that differs only at its first byte decides before the item does, in both directions
	a, b := key(1, 1, 5, "zz"), key(1, 1, 6, "aa")
	if !captureKeyLess(a, b) || captureKeyLess(b, a) {
		t.Errorf("the hash decides before the item: %v %v", captureKeyLess(a, b), captureKeyLess(b, a))
	}
}
