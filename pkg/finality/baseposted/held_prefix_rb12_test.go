// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-TRAIN3-INT duty (e) (Train 2 PR section 7): the held answer of a window (the l1_capture_gap a leg is judged at) is returned without
// reading a row only while nothing it depends on has changed. A PREFIX window is such a dependency: it is a gap row, so a window added
// inside the leg's range and a block of a window filled both change the question, and the answer is rebuilt, never served stale.
func TestRB12HeldAnswerChangesWhenAPrefixWindowIsAddedOrFilled(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	// the leg's window straddles the first block the loop scanned: 2,000 blocks of it lie below (the prefix) and the rest above, where the
	// capture holds the rows of 300 blocks (rbStore) and nothing beyond rbFirstBlock+1495
	origin := uint64(rbFirstBlock - 2033)
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	first, err := ask()
	if first == nil || first.Code != "l1_capture_gap" || first.Fields["gap_state"] != "open" {
		t.Fatalf("the first ask requests the prefix and is judged inside the open window: %v %v", first, err)
	}
	blocks, ranges := first.Fields["blocks"].(uint64), first.Fields["ranges"].(uint64)
	// the same question with nothing changed: the held answer, byte for byte
	again, _ := ask()
	if again == nil || !bytes.Equal(again.Canonical(), first.Canonical()) {
		t.Fatalf("unchanged: the held answer is returned as it was: %v vs %v", again, first)
	}
	// a block of the window is filled (by the archive backfill): the answer follows
	for n := origin; n < origin+100; n++ {
		rawFillRow(t, st, n)
	}
	filled, _ := ask()
	if filled == nil || filled.Fields["blocks"].(uint64) >= blocks {
		t.Fatalf("a filled prefix block must change the held answer: blocks %d -> %v", blocks, filled)
	}
	afterFill := filled.Fields["blocks"].(uint64)
	// a second prefix window inside the leg's range (another validator's request) is added: the answer follows again
	if err := finality.RecordGap(context.Background(), st, uint64(Chain), rbFirstBlock+1520, rbFirstBlock+1549, finality.GapCapturePrefix); err != nil {
		t.Fatal(err)
	}
	added, _ := ask()
	if added == nil || added.Fields["ranges"].(uint64) != ranges+1 || added.Fields["blocks"].(uint64) != afterFill+30 {
		t.Fatalf("an added prefix window must change the held answer: the window of 30 blocks is a second range of the judged gap (ranges %d -> %v, blocks %d -> %v)", ranges, added, afterFill, added)
	}
}
