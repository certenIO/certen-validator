// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-DBFIX D7: FinalityCaptureStore.PutBlock stores the rows of one captured block in ONE transaction. It is still insert-only:
// it can add rows and find identical ones, never change one.

func blockRows(chain, block uint64, hash byte, items ...string) []finality.CaptureRow {
	var out []finality.CaptureRow
	for _, it := range items {
		out = append(out, finality.CaptureRow{CaptureKey: key(chain, block, hash, it), Bytes: []byte(it + "/" + string(rune('a'+hash%26)))})
	}
	return out
}

func heldItems(t *testing.T, s *FinalityCaptureStore, chain, block uint64) map[string]string {
	t.Helper()
	rows, err := s.ListByBlock(context.Background(), chain, block)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.Item] = string(r.Bytes)
	}
	return out
}

func TestPutBlockStoresEveryRowOfTheBlockAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	rows := blockRows(chain, 300, 0x31, "hdr", "tx/1", "txnodes/1", "inbox")
	if err := store.PutBlock(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if got := heldItems(t, store, chain, 300); len(got) != 4 {
		t.Fatalf("%v", got)
	}
	if err := store.PutBlock(ctx, rows); err != nil {
		t.Fatalf("the identical block again must be a no-op: %v", err)
	}
	// a row of the block already stored (identical) plus new rows: the new rows are added
	more := append(blockRows(chain, 300, 0x31, "hdr"), blockRows(chain, 300, 0x31, "syscfg")...)
	if err := store.PutBlock(ctx, more); err != nil {
		t.Fatal(err)
	}
	if got := heldItems(t, store, chain, 300); len(got) != 5 {
		t.Fatalf("%v", got)
	}
	if err := store.PutBlock(ctx, nil); err != nil {
		t.Fatalf("an empty block: %v", err)
	}
}

func TestPutBlockWithOneConflictingRowStoresNoRowOfTheCall(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	if err := store.Put(ctx, key(chain, 310, 0x41, "tx/2"), []byte("original")); err != nil {
		t.Fatal(err)
	}
	// the conflicting row sorts in the MIDDLE of the call: rows inserted before it must be rolled back, rows after it never run
	rows := []finality.CaptureRow{
		{CaptureKey: key(chain, 310, 0x41, "hdr"), Bytes: []byte("h")},
		{CaptureKey: key(chain, 310, 0x41, "tx/2"), Bytes: []byte("DIFFERENT")},
		{CaptureKey: key(chain, 310, 0x41, "txnodes/2"), Bytes: []byte("n")},
	}
	err := store.PutBlock(ctx, rows)
	if !errors.Is(err, finality.ErrCaptureConflict) {
		t.Fatalf("want ErrCaptureConflict, got %v", err)
	}
	got := heldItems(t, store, chain, 310)
	if len(got) != 1 || got["tx/2"] != "original" {
		t.Fatalf("the refused block left rows or changed one: %v", got)
	}
}

func TestPutBlockRefusesAKeyTheStoreCannotHoldBeforeWritingAnyRow(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	good := blockRows(chain, 320, 0x51, "hdr", "inbox")
	for name, bad := range map[string]finality.CaptureRow{
		"item outside the alphabet": {CaptureKey: key(chain, 320, 0x51, "Bad Item"), Bytes: []byte("x")},
		"chain 0":                   {CaptureKey: key(0, 320, 0x51, "tx/1"), Bytes: []byte("x")},
		"block above MaxInt64":      {CaptureKey: key(chain, uint64(math.MaxInt64)+1, 0x51, "tx/1"), Bytes: []byte("x")},
		"chain above MaxInt64":      {CaptureKey: key(uint64(math.MaxInt64)+1, 320, 0x51, "tx/1"), Bytes: []byte("x")},
	} {
		if err := store.PutBlock(ctx, append(append([]finality.CaptureRow(nil), good...), bad)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if got := heldItems(t, store, chain, 320); len(got) != 0 {
			t.Fatalf("%s: a refused block left rows: %v", name, got)
		}
	}
	err := store.PutBlock(ctx, append(append([]finality.CaptureRow(nil), good...), finality.CaptureRow{CaptureKey: key(chain, uint64(math.MaxInt64)+1, 0x51, "tx/1")}))
	if st, ok := finality.AsNamed(err); !ok || st.Code != finality.CodeEvidenceTooLarge {
		t.Fatalf("a block number the table cannot hold is the named state finality_evidence_too_large: %v", err)
	}
}

// Every validator captures the same blocks into this one database. Two writers of the same block with rows overlapping in other
// orders must queue on the first key and both succeed, never deadlock.
func TestPutBlockOfTheSameBlockFromManyWritersConvergesWithoutDeadlock(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	items := []string{"hdr", "inbox", "syscfg", "tx/1", "tx/2", "txnodes/1", "txnodes/2"}
	const writers = 12
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			order := append([]string(nil), items...)
			for i := range order { // each writer lists the rows in its own rotation
				order[i] = items[(i+w)%len(items)]
			}
			errs[w] = store.PutBlock(ctx, blockRows(chain, 330, 0x61, order...))
		}(w)
	}
	wg.Wait()
	for w, err := range errs {
		if err != nil {
			t.Fatalf("writer %d: %v", w, err)
		}
	}
	if got := heldItems(t, store, chain, 330); len(got) != len(items) {
		t.Fatalf("%d rows: %v", len(got), got)
	}
}

func TestBlockSizesReportsTheStoredSizeOfEveryRowOfTheBlockAndNothingOfAnotherBlock(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := uint64(1_000_000_000 + time.Now().UnixNano()%1_000_000_000)
	if err := store.PutBlock(ctx, []finality.CaptureRow{
		{CaptureKey: key(chain, 340, 0x71, "hdr"), Bytes: make([]byte, 5)},
		{CaptureKey: key(chain, 340, 0x71, "tx/1"), Bytes: make([]byte, 700)},
		{CaptureKey: key(chain, 340, 0x72, "hdr"), Bytes: make([]byte, 9)}, // the same height under another hash
		{CaptureKey: key(chain, 341, 0x71, "hdr"), Bytes: make([]byte, 11)},
		{CaptureKey: key(chain, 340, 0x71, "empty"), Bytes: nil},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.BlockSizes(ctx, chain, 340, key(chain, 340, 0x71, "").L1Hash)
	if err != nil || len(got) != 3 || got["hdr"] != 5 || got["tx/1"] != 700 || got["empty"] != 0 {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := store.BlockSizes(ctx, chain, 342, [32]byte{}); err != nil || len(got) != 0 {
		t.Fatalf("an absent block: %v %v", got, err)
	}
	for name, c := range map[string]struct{ chain, block uint64 }{"block above MaxInt64": {chain, uint64(math.MaxInt64) + 1}, "chain above MaxInt64": {uint64(math.MaxInt64) + 1, 340}} {
		if got, err := store.BlockSizes(ctx, c.chain, c.block, [32]byte{}); err != nil || len(got) != 0 {
			t.Fatalf("%s: %v %v", name, got, err)
		}
	}
}
