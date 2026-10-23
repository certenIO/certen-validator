// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
)

// RB12-GO-INT D7 (V-T2): a fill closes a block only for the hash the capture VERIFIED (the header re-hashed to it, the transactions
// hashed to the header's root). A fill that names no hash closes nothing, and none can be recorded.
func TestRB12GOINTAFillWithoutAVerifiedHashClosesNothing(t *testing.T) {
	ctx := context.Background()
	st := NewMemCaptureStore()
	if err := RecordGap(ctx, st, 84532, 100, 102, GapBlockUnavailable); err != nil {
		t.Fatal(err)
	}
	if err := RecordGapFill(ctx, st, 84532, 101, [32]byte{}, false); err == nil {
		t.Fatal("a fill that names no hash was recorded")
	}
	// a row of that shape written by anything else (the key carries the zero hash) is not a fill either
	var w Writer
	w.Fixed([]byte(fillMagic))
	w.U64(101)
	w.B32([32]byte{})
	w.U8(0)
	if err := st.Put(ctx, CaptureKey{Chain: 84532, L1Block: 101, Item: GapFillPrefix + "101"}, w.Bytes()); err != nil {
		t.Fatal(err)
	}
	got, err := GapsIn(ctx, st, 84532, 100, 102)
	if err != nil || len(got) != 1 || got[0].From != 100 || got[0].To != 102 {
		t.Fatalf("the gap must still be open over 100-102: %v %v", got, err)
	}
	h := [32]byte{1}
	if err := RecordGapFill(ctx, st, 84532, 101, h, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := GapsIn(ctx, st, 84532, 100, 102); len(got) != 2 {
		t.Fatalf("a fill for a verified hash closes block 101: %v", got)
	}
}
