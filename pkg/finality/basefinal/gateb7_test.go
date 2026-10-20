// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"testing"
)

// A capture row is insert-only and the same bytes again are a no-op (the CaptureStore contract): capturing the same L1 block twice
// must not fail because the row already holds exactly what is being put.
func TestTheDirStoreTakesTheSameBytesAgainAndRefusesOtherBytes(t *testing.T) {
	ctx := context.Background()
	st := DirStore{Dir: t.TempDir()}
	hash := [32]byte{1, 2, 3}
	if err := st.Put(ctx, 84532, 5, hash, "item", []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ctx, 84532, 5, hash, "item", []byte("data")); err != nil {
		t.Fatalf("the same bytes again must be a no-op: %v", err)
	}
	if err := st.Put(ctx, 84532, 5, hash, "item", []byte("other")); err == nil {
		t.Fatal("other bytes under the same key must be refused")
	}
	rows, err := st.Rows(ctx, 84532, "item")
	if err != nil || len(rows) != 1 || string(rows[0].Data) != "data" {
		t.Fatalf("%+v %v", rows, err)
	}
}
