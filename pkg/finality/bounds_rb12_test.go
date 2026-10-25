// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"os"
	"testing"
)

// RB12 OPS-A2 item 9: the directory capture store reads a row only up to the evidence bound and refuses a larger file by name.
func TestDirCaptureStoreRefusesARowAboveTheEvidenceBoundByName(t *testing.T) {
	dir := t.TempDir()
	d := DirCaptureStore{Dir: dir}
	ctx := context.Background()
	k := CaptureKey{Chain: ChainBaseSepolia, L1Block: 7, L1Hash: [32]byte{1}, Item: "hdr"}
	if err := d.Put(ctx, k, []byte("row")); err != nil {
		t.Fatal(err)
	}
	if b, ok, err := d.Get(ctx, k); err != nil || !ok || string(b) != "row" {
		t.Fatalf("an ordinary row: %q %v %v", b, ok, err)
	}
	if _, ok, err := d.Get(ctx, CaptureKey{Chain: ChainBaseSepolia, L1Block: 8, L1Hash: [32]byte{2}, Item: "hdr"}); err != nil || ok {
		t.Fatalf("a missing row is not an error: %v %v", ok, err)
	}
	lim := int64(DefaultLimits().MaxEvidenceBytes)
	for name, size := range map[string]int64{"at the bound": lim, "one above": lim + 1} {
		big := CaptureKey{Chain: ChainBaseSepolia, L1Block: 9, L1Hash: [32]byte{3, byte(len(name))}, Item: "hdr"}
		if err := d.Put(ctx, big, []byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(d.path(big), size); err != nil { // a sparse file: no disk is spent
			t.Fatal(err)
		}
		_, _, err := d.Get(ctx, big)
		st, named := AsNamed(err)
		if size > lim && (!named || st.Code != CodeEvidenceTooLarge || st.Fields["part"] != "capture_row" || st.Fields["limit"] != uint64(lim)) {
			t.Fatalf("%s: %v", name, err)
		}
		if size <= lim && err != nil {
			t.Fatalf("%s: a row at the bound is read: %v", name, err)
		}
		if size > lim {
			if _, err := d.ListByBlock(ctx, ChainBaseSepolia, 9); err == nil {
				t.Fatal("ListByBlock read a row above the bound")
			}
		}
	}
}
