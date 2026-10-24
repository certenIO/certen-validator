// Copyright 2026 Certen Protocol

// Package storetest is the conformance suite of capture.Store. Every implementation (the in-memory store here, the Postgres store of
// WP-S8-5) runs Run against a fresh store per sub-test; a store that passes keeps the insert-only, byte-identical-idempotent, atomic and
// ordered semantics the seven validators sharing one database depend on.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
)

// Factory returns a fresh, empty store for one sub-test.
type Factory func(t *testing.T) capture.Store

func hash(b byte) (h [32]byte) {
	for i := range h {
		h[i] = b
	}
	return h
}

func key(chain uint64, anchor, block byte, item string) capture.Key {
	return capture.Key{Chain: chain, AnchorID: hash(anchor), BlockHash: hash(block), Item: item}
}

func mustPut(t *testing.T, s capture.Store, k capture.Key, b []byte) {
	t.Helper()
	if err := s.Put(context.Background(), k, b); err != nil {
		t.Fatalf("Put %s: %v", k, err)
	}
}

func mustGet(t *testing.T, s capture.Store, k capture.Key) ([]byte, bool) {
	t.Helper()
	b, ok, err := s.Get(context.Background(), k)
	if err != nil {
		t.Fatalf("Get %s: %v", k, err)
	}
	return b, ok
}

// Run executes the whole suite.
func Run(t *testing.T, factory Factory) {
	ctx := context.Background()
	t.Run("RoundTripAndAbsent", func(t *testing.T) {
		s := factory(t)
		k := key(11155111, 1, 2, "settle")
		if _, ok := mustGet(t, s, k); ok {
			t.Fatal("an empty store holds a row")
		}
		mustPut(t, s, k, []byte("alpha"))
		if b, ok := mustGet(t, s, k); !ok || string(b) != "alpha" {
			t.Fatalf("Get = %q, %v", b, ok)
		}
		mustPut(t, s, key(11155111, 1, 2, "empty"), nil)
		if b, ok := mustGet(t, s, key(11155111, 1, 2, "empty")); !ok || len(b) != 0 {
			t.Fatalf("an empty item is a row: %q, %v", b, ok)
		}
	})
	t.Run("IdempotentSameBytes", func(t *testing.T) {
		s := factory(t)
		k := key(84532, 3, 4, "settle")
		for i := 0; i < 3; i++ {
			mustPut(t, s, k, []byte("same"))
		}
		keys, err := s.ListByAnchor(ctx, 84532, hash(3))
		if err != nil || len(keys) != 1 {
			t.Fatalf("ListByAnchor = %v, %v; want one row", keys, err)
		}
	})
	t.Run("ConflictKeepsTheFirstRow", func(t *testing.T) {
		s := factory(t)
		k := key(84532, 3, 4, "settle")
		mustPut(t, s, k, []byte("first"))
		if err := s.Put(ctx, k, []byte("second")); !errors.Is(err, capture.ErrCaptureConflict) {
			t.Fatalf("different bytes: err = %v, want ErrCaptureConflict", err)
		}
		if err := s.Put(ctx, k, []byte("firs")); !errors.Is(err, capture.ErrCaptureConflict) {
			t.Fatalf("a prefix of the stored bytes: err = %v, want ErrCaptureConflict", err)
		}
		if err := s.Put(ctx, k, nil); !errors.Is(err, capture.ErrCaptureConflict) {
			t.Fatalf("empty bytes over a row: err = %v, want ErrCaptureConflict", err)
		}
		if b, _ := mustGet(t, s, k); string(b) != "first" {
			t.Fatalf("the stored row changed: %q", b)
		}
	})
	t.Run("KeyFieldsAreAllPartOfTheKey", func(t *testing.T) {
		s := factory(t)
		base := key(1, 1, 1, "a")
		variants := []capture.Key{key(2, 1, 1, "a"), key(1, 2, 1, "a"), key(1, 1, 2, "a"), key(1, 1, 1, "b")}
		mustPut(t, s, base, []byte("base"))
		for i, v := range variants {
			mustPut(t, s, v, []byte(fmt.Sprintf("v%d", i)))
		}
		if b, _ := mustGet(t, s, base); string(b) != "base" {
			t.Fatalf("base row = %q", b)
		}
		for i, v := range variants {
			if b, ok := mustGet(t, s, v); !ok || string(b) != fmt.Sprintf("v%d", i) {
				t.Fatalf("variant %d = %q, %v", i, b, ok)
			}
		}
	})
	t.Run("CopiesAreIsolated", func(t *testing.T) {
		s := factory(t)
		k := key(1, 1, 1, "a")
		in := []byte("abcdef")
		mustPut(t, s, k, in)
		in[0] = 'X'
		b, _ := mustGet(t, s, k)
		if string(b) != "abcdef" {
			t.Fatalf("Put kept the caller's slice: %q", b)
		}
		b[1] = 'Y'
		if b2, _ := mustGet(t, s, k); string(b2) != "abcdef" {
			t.Fatalf("Get returned the store's slice: %q", b2)
		}
		rows, _ := s.ListByBlock(ctx, 1, hash(1), hash(1))
		rows[0].Bytes[0] = 'Z'
		if b3, _ := mustGet(t, s, k); string(b3) != "abcdef" {
			t.Fatalf("ListByBlock returned the store's slice: %q", b3)
		}
	})
	t.Run("ConcurrentIdenticalPutsFromSevenWriters", func(t *testing.T) {
		s := factory(t)
		k := key(421614, 9, 8, "settle")
		payload := bytes.Repeat([]byte{0xAB}, 4096)
		var wg sync.WaitGroup
		errs := make([]error, 7)
		start := make(chan struct{})
		for i := 0; i < 7; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = s.Put(ctx, k, append([]byte(nil), payload...))
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("writer %d: %v (identical bytes are a no-op for all seven)", i, err)
			}
		}
		if b, ok := mustGet(t, s, k); !ok || !bytes.Equal(b, payload) {
			t.Fatal("the stored row is not the payload")
		}
		if keys, _ := s.ListByAnchor(ctx, 421614, hash(9)); len(keys) != 1 {
			t.Fatalf("%d rows after seven identical puts", len(keys))
		}
	})
	t.Run("ConcurrentConflictingPutsHaveExactlyOneWinner", func(t *testing.T) {
		s := factory(t)
		k := key(421614, 9, 8, "stated")
		var wg sync.WaitGroup
		errs := make([]error, 7)
		start := make(chan struct{})
		for i := 0; i < 7; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = s.Put(ctx, k, []byte(fmt.Sprintf("writer-%d", i)))
			}(i)
		}
		close(start)
		wg.Wait()
		winner, wins := -1, 0
		for i, err := range errs {
			switch {
			case err == nil:
				winner, wins = i, wins+1
			case !errors.Is(err, capture.ErrCaptureConflict):
				t.Fatalf("writer %d: %v, want nil or ErrCaptureConflict", i, err)
			}
		}
		if wins != 1 {
			t.Fatalf("%d winners among seven conflicting writers", wins)
		}
		if b, _ := mustGet(t, s, k); string(b) != fmt.Sprintf("writer-%d", winner) {
			t.Fatalf("stored %q, the winner wrote writer-%d", b, winner)
		}
	})
	t.Run("ListOrdering", func(t *testing.T) {
		s := factory(t)
		// inserted in a shuffled order; rows of other anchors and chains are never listed
		order := []capture.Key{key(5, 1, 9, "b"), key(5, 1, 2, "z"), key(5, 1, 9, "a"), key(5, 1, 2, "a/b"), key(5, 1, 2, "a"), key(5, 1, 0x30, "a"),
			key(5, 2, 1, "a"), key(6, 1, 1, "a")}
		for _, k := range order {
			mustPut(t, s, k, []byte(k.Item))
		}
		keys, err := s.ListByAnchor(ctx, 5, hash(1))
		if err != nil {
			t.Fatal(err)
		}
		want := []capture.Key{key(5, 1, 2, "a"), key(5, 1, 2, "a/b"), key(5, 1, 2, "z"), key(5, 1, 9, "a"), key(5, 1, 9, "b"), key(5, 1, 0x30, "a")}
		if len(keys) != len(want) {
			t.Fatalf("ListByAnchor = %d keys, want %d", len(keys), len(want))
		}
		for i := range want {
			if keys[i] != want[i] {
				t.Fatalf("ListByAnchor[%d] = %s, want %s", i, keys[i], want[i])
			}
		}
		rows, err := s.ListByBlock(ctx, 5, hash(1), hash(2))
		if err != nil || len(rows) != 3 || rows[0].Item != "a" || rows[1].Item != "a/b" || rows[2].Item != "z" || string(rows[2].Bytes) != "z" {
			t.Fatalf("ListByBlock = %v, %v", rows, err)
		}
		if k, _ := s.ListByAnchor(ctx, 5, hash(77)); len(k) != 0 {
			t.Fatal("an unknown anchor lists rows")
		}
	})
	t.Run("SizeGuard", func(t *testing.T) {
		s := factory(t)
		k := key(1, 1, 1, "big")
		mustPut(t, s, k, make([]byte, capture.MaxItemBytes()))
		k2 := key(1, 1, 1, "bigger")
		if err := s.Put(ctx, k2, make([]byte, capture.MaxItemBytes()+1)); !errors.Is(err, capture.ErrItemTooLarge) {
			t.Fatalf("MaxItemBytes+1: err = %v, want ErrItemTooLarge", err)
		}
		if _, ok := mustGet(t, s, k2); ok {
			t.Fatal("a refused item was stored")
		}
	})
	t.Run("BadKeysAreRefused", func(t *testing.T) {
		s := factory(t)
		for _, item := range []string{"", "Settle", "settle ", "a//b", "/a", "a/", "a.b", "a:b", string(bytes.Repeat([]byte("a"), 121))} {
			if err := s.Put(ctx, key(1, 1, 1, item), []byte("x")); !errors.Is(err, capture.ErrBadKey) {
				t.Fatalf("item %q: err = %v, want ErrBadKey", item, err)
			}
		}
		if err := s.Put(ctx, capture.Key{Chain: 1, BlockHash: hash(1), Item: "a"}, []byte("x")); !errors.Is(err, capture.ErrBadKey) {
			t.Fatalf("zero anchor id: err = %v, want ErrBadKey", err)
		}
		if err := s.Put(ctx, capture.Key{Chain: 1, AnchorID: hash(1), Item: "a"}, []byte("x")); !errors.Is(err, capture.ErrBadKey) {
			t.Fatalf("zero block hash: err = %v, want ErrBadKey", err)
		}
		if keys, _ := s.ListByAnchor(ctx, 1, hash(1)); len(keys) != 0 {
			t.Fatalf("a refused key was stored: %v", keys)
		}
		mustPut(t, s, key(1, 1, 1, string(bytes.Repeat([]byte("a"), 120))), []byte("x")) // the longest item is accepted
		mustPut(t, s, key(1, 1, 1, "a-b_c/d0"), []byte("x"))
	})
	t.Run("CancelledContextStoresNothing", func(t *testing.T) {
		s := factory(t)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		k := key(1, 1, 1, "a")
		if err := s.Put(cctx, k, []byte("x")); err == nil {
			t.Fatal("Put under a cancelled context succeeded")
		}
		if _, ok := mustGet(t, s, k); ok {
			t.Fatal("a cancelled Put stored a row")
		}
	})
}
