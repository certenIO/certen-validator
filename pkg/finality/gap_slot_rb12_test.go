// Copyright 2026 Certen Protocol

package finality

import (
	"errors"
	"testing"
)

// RB12-ARCHIVE-BACKFILL: the beacon-slot evidence of a block proven unavailable is a function of the block, written once.

func TestRB12GapSlotIsAFunctionOfTheBlockAndAnotherSlotIsTheNamedConflict(t *testing.T) {
	s := NewMemCaptureStore()
	if _, ok, err := GapSlotOf(pxCtx(), s, pxChain, 70); ok || err != nil {
		t.Fatalf("nothing recorded: %v %v", ok, err)
	}
	for i := 0; i < 3; i++ {
		if err := RecordGapSlot(pxCtx(), s, pxChain, 70, 12345); err != nil {
			t.Fatalf("the same slot again is a no-op: %v", err)
		}
	}
	if slot, ok, err := GapSlotOf(pxCtx(), s, pxChain, 70); !ok || err != nil || slot != 12345 {
		t.Fatalf("%d %v %v", slot, ok, err)
	}
	if err := RecordGapSlot(pxCtx(), s, pxChain, 70, 12346); !errors.Is(err, ErrCaptureConflict) {
		t.Fatalf("another slot for the block is the named conflict, got %v", err)
	}
	// the row is not gap bookkeeping: no gap reader sees it
	if tot, _ := GapTotalsOf(pxCtx(), s, pxChain); tot != (GapTotals{}) {
		t.Fatalf("%+v", tot)
	}
	// a row that is not a slot record, or names another block, is an error and never a slot
	_ = s.Put(pxCtx(), gapSlotKey(pxChain, 71), []byte("garbage"))
	if _, ok, err := GapSlotOf(pxCtx(), s, pxChain, 71); ok || err == nil {
		t.Fatalf("garbage is refused: %v %v", ok, err)
	}
	var w Writer
	w.Fixed([]byte(slotMagic))
	w.U64(99)
	w.U64(5)
	_ = s.Put(pxCtx(), gapSlotKey(pxChain, 72), w.Bytes())
	if _, ok, err := GapSlotOf(pxCtx(), s, pxChain, 72); ok || err == nil {
		t.Fatalf("a record naming another block is refused: %v %v", ok, err)
	}
}
