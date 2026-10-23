// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-A against the real table: the capture index rows are ordinary rows of proof_finality_capture under item names idx/g<G>/<family>/...
// (no migration). The table's constraints, the key listing the lookup runs, the aggregate query that reads the cursor, and the conflict
// rule of seven writers sharing one database are exercised here against PostgreSQL.
func TestFinalityCaptureIndexRowsLiveInTheCaptureTableAndConflictByName(t *testing.T) {
	ctx := context.Background()
	st := NewFinalityCaptureStore(NewClientFromDB(testDB))
	const chain = 840099 // a chain id no other test uses
	const fam = "bi"
	h := func(b byte) [32]byte { return [32]byte{b} }
	id := "00112233445566778899aabbccddeeff"
	items := []string{
		finality.IndexItem(1, fam, "f"),
		finality.IndexItem(1, fam, "c", "1790000000", "1790000118", id),
		finality.IndexItem(1, fam, "x", id),
		finality.IndexCursorItem(1, fam),
		finality.IndexItem(2, fam, "f"),
	}
	for i, it := range items {
		k := finality.CaptureKey{Chain: chain, L1Block: uint64(100 + i), L1Hash: h(byte(i + 1)), Item: it}
		if err := finality.IndexPut(ctx, st, fam, k, []byte{byte(i), 1, 2, 3}); err != nil {
			t.Fatalf("%s: the table must accept an index row: %v", it, err)
		}
		// the same bytes are a no-op
		if err := finality.IndexPut(ctx, st, fam, k, []byte{byte(i), 1, 2, 3}); err != nil {
			t.Fatalf("%s: identical bytes: %v", it, err)
		}
	}
	// different bytes under an existing key are the named conflict and the stored row is untouched
	k := finality.CaptureKey{Chain: chain, L1Block: 101, L1Hash: h(2), Item: items[1]}
	err := finality.IndexPut(ctx, st, fam, k, []byte("another writer's bytes"))
	var ce *finality.IndexConflictError
	if !errors.Is(err, finality.ErrIndexConflict) || !errors.As(err, &ce) || ce.Key != k {
		t.Fatalf("want the named conflict, got %v", err)
	}
	if got, ok, err := st.Get(ctx, k); err != nil || !ok || !bytes.Equal(got, []byte{1, 1, 2, 3}) {
		t.Fatalf("the stored row changed: %v %v %v", got, ok, err)
	}
	// the lookup's key listing: the channel entries of a generation in an L1 range, nothing of another generation or family
	keys, err := st.ListByRange(ctx, chain, 0, 1000, finality.IndexItem(1, fam, "c")+"/")
	if err != nil || len(keys) != 1 || keys[0].Item != items[1] {
		t.Fatalf("entry listing: %v %v", keys, err)
	}
	keys, err = st.ListByRange(ctx, chain, 0, 1000, finality.IndexPrefix(1, fam))
	if err != nil || len(keys) != 4 {
		t.Fatalf("generation 1 holds f, c, x and cursor: %v %v", keys, err)
	}
	// the cursor is read with one aggregate query
	if err := finality.WriteIndexCursor(ctx, st, chain, 1, fam, 5000); err != nil {
		t.Fatal(err)
	}
	if err := finality.WriteIndexCursor(ctx, st, chain, 1, fam, 7000); err != nil {
		t.Fatal(err)
	}
	lo, hi, ok, err := finality.ReadIndexCursor(ctx, st, chain, 1, fam)
	if err != nil || !ok || lo != 103 || hi != 7000 {
		t.Fatalf("cursor bounds: %d %d %v %v", lo, hi, ok, err)
	}
	if _, _, ok, _ := finality.ReadIndexCursor(ctx, st, chain, 2, fam); ok {
		t.Fatal("generation 2 has no cursor")
	}
	// the table's own item constraint still refuses a name outside the alphabet
	bad := finality.CaptureKey{Chain: chain, L1Block: 1, L1Hash: h(9), Item: "idx/g1/bi/C"}
	if err := finality.IndexPut(ctx, st, fam, bad, []byte{1}); err == nil {
		t.Fatal("an upper-case item name must be refused")
	}
}
