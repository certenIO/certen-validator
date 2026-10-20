// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func storesUnderTest(t *testing.T) map[string]CaptureStore {
	t.Helper()
	d, err := NewDirCaptureStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]CaptureStore{"mem": NewMemCaptureStore(), "dir": d, "dir-literal": DirCaptureStore{Dir: t.TempDir()}}
}

func ckey(chain, block uint64, hash byte, item string) CaptureKey {
	return CaptureKey{Chain: chain, L1Block: block, L1Hash: [32]byte{hash}, Item: item}
}

func TestEveryCaptureStoreIsInsertOnlyAndRefusesBadItemNames(t *testing.T) {
	ctx := context.Background()
	for name, s := range storesUnderTest(t) {
		k := ckey(84532, 10, 1, "tx/3")
		if err := s.Put(ctx, k, []byte("one")); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := s.Put(ctx, k, []byte("one")); err != nil {
			t.Fatalf("%s: identical bytes must be a no-op: %v", name, err)
		}
		if err := s.Put(ctx, k, []byte("two")); !errors.Is(err, ErrCaptureConflict) {
			t.Fatalf("%s: different bytes under an existing key: %v", name, err)
		}
		if b, ok, err := s.Get(ctx, k); err != nil || !ok || string(b) != "one" {
			t.Fatalf("%s: the stored row was changed: %q %v %v", name, b, ok, err)
		}
		if _, ok, err := s.Get(ctx, ckey(84532, 10, 2, "tx/3")); err != nil || ok {
			t.Fatalf("%s: a second hash at the same height is another row: %v %v", name, ok, err)
		}
		if err := s.Put(ctx, ckey(84532, 10, 1, "Bad Item"), []byte("x")); err == nil {
			t.Fatalf("%s: a bad item name was stored", name)
		}
	}
}

func TestEveryCaptureStoreListsByBlockAndRangeInTheDocumentedOrder(t *testing.T) {
	ctx := context.Background()
	for name, s := range storesUnderTest(t) {
		puts := []CaptureKey{
			ckey(5, 20, 9, "b"), ckey(5, 20, 1, "z"), ckey(5, 20, 1, "a"), ckey(5, 10, 3, "tx/0"), ckey(5, 10, 3, "tx/1"),
			ckey(5, 30, 2, "txnodes/0"), ckey(6, 20, 1, "other-chain"),
		}
		for _, k := range puts {
			if err := s.Put(ctx, k, append([]byte(k.Item), k.L1Hash[0])); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		rows, err := s.ListByBlock(ctx, 5, 20)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rows {
			if !bytes.Equal(r.Bytes, append([]byte(r.Item), r.L1Hash[0])) {
				t.Fatalf("%s: row %s carries the wrong bytes %q", name, r.CaptureKey, r.Bytes)
			}
			got = append(got, r.Item)
		}
		if want := []string{"a", "z", "b"}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Fatalf("%s: ListByBlock order (l1Hash, item) %v, want %v", name, got, want)
		}
		ks, err := s.ListByRange(ctx, 5, 10, 20, "tx")
		if err != nil {
			t.Fatal(err)
		}
		if len(ks) != 2 || ks[0].Item != "tx/0" || ks[1].Item != "tx/1" || ks[0].L1Block != 10 {
			t.Fatalf("%s: ListByRange [10,20] prefix tx: %v", name, ks)
		}
		all, _ := s.ListByRange(ctx, 5, 0, MaxCaptureBlock, "")
		if len(all) != 6 || all[0].L1Block != 10 || all[len(all)-1].L1Block != 30 {
			t.Fatalf("%s: an unbounded scan of chain 5 returned %d keys: %v", name, len(all), all)
		}
		if none, _ := s.ListByRange(ctx, 5, 31, 40, ""); len(none) != 0 {
			t.Fatalf("%s: rows outside the range: %v", name, none)
		}
		if none, _ := s.ListByBlock(ctx, 99, 20); len(none) != 0 {
			t.Fatalf("%s: rows of an unknown chain: %v", name, none)
		}
	}
}

func TestCaptureKeysAndRowsOfItemMatchTheExactNameNotThePrefix(t *testing.T) {
	ctx := context.Background()
	for name, s := range storesUnderTest(t) {
		for _, k := range []CaptureKey{ckey(1, 7, 2, "inbox"), ckey(1, 5, 4, "inbox"), ckey(1, 5, 3, "inbox"), ckey(1, 5, 3, "inbox2"), ckey(1, 6, 1, "inbo")} {
			if err := s.Put(ctx, k, []byte(k.Item)); err != nil {
				t.Fatal(err)
			}
		}
		ks, err := CaptureKeysOfItem(ctx, s, 1, "inbox")
		if err != nil {
			t.Fatal(err)
		}
		if len(ks) != 3 || ks[0].L1Block != 5 || ks[0].L1Hash[0] != 3 || ks[1].L1Hash[0] != 4 || ks[2].L1Block != 7 {
			t.Fatalf("%s: keys of item inbox: %v", name, ks)
		}
		rows, err := CaptureRowsOfItem(ctx, s, 1, "inbox")
		if err != nil || len(rows) != 3 || string(rows[0].Bytes) != "inbox" || rows[2].L1Block != 7 {
			t.Fatalf("%s: rows of item inbox: %v %v", name, rows, err)
		}
	}
}

func TestADirCaptureStoreSurvivesReopeningAndIgnoresLeftoverTemporaryFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a, err := NewDirCaptureStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	k := ckey(3, 44, 7, "blob/1/2")
	if err := a.Put(ctx, k, []byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(a.path(k)), ".put-crashed"), []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := DirCaptureStore{Dir: dir}
	if got, ok, err := b.Get(ctx, k); err != nil || !ok || string(got) != "y" {
		t.Fatalf("a reopened store lost the row: %q %v %v", got, ok, err)
	}
	if err := b.Put(ctx, k, []byte("z")); !errors.Is(err, ErrCaptureConflict) {
		t.Fatalf("a reopened store lost insert-only: %v", err)
	}
	ks, err := b.ListByRange(ctx, 3, 0, MaxCaptureBlock, "")
	if err != nil || len(ks) != 1 || ks[0] != k {
		t.Fatalf("a leftover temporary file became a row: %v %v", ks, err)
	}
}

func TestTwoWritersRacingOnOneKeyCannotBothWinWithDifferentBytes(t *testing.T) {
	ctx := context.Background()
	for name, s := range storesUnderTest(t) {
		k := ckey(9, 1, 1, "hdr")
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = s.Put(ctx, k, []byte{byte(i % 2)})
			}(i)
		}
		wg.Wait()
		won := map[byte]bool{}
		for i, err := range errs {
			if err == nil {
				won[byte(i%2)] = true
			} else if !errors.Is(err, ErrCaptureConflict) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if len(won) != 1 {
			t.Fatalf("%s: writers with different bytes both succeeded: %v", name, won)
		}
	}
}
