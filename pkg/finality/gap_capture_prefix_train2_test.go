// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
)

// A later release records windows below the capture start as class capture_prefix. This release must read such a row as an ordinary gap
// (so a rollback from that release does not turn every Base l1_posted build into the unnamed "malformed gap row item" and does not stop the
// hole backfill), and it must NOT skip unknown rows (a leg inside a window would then read "not posted yet").
func TestACapturePrefixGapRowIsAnOrdinaryGapOfThisRelease(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	if !GapCapturePrefix.Valid() {
		t.Fatal("capture_prefix is a valid gap class of this release")
	}
	if err := RecordGap(ctx, st, gapChain, 11980000, 11980009, GapCapturePrefix); err != nil {
		t.Fatalf("recording a capture_prefix gap: %v", err)
	}
	if err := RecordGap(ctx, st, gapChain, 500, 509, GapStateProofUnavailable); err != nil {
		t.Fatal(err)
	}
	got, err := GapsIn(ctx, st, gapChain, 0, MaxCaptureBlock)
	if err != nil {
		t.Fatalf("GapsIn must answer with a capture_prefix row present: %v", err)
	}
	if len(got) != 2 || got[1].From != 11980000 || got[1].To != 11980009 || got[1].State != GapOpen {
		t.Fatalf("the prefix window is an open gap range next to the hole: %v", got)
	}
	if len(got[1].Classes) != 1 || got[1].Classes[0] != GapCapturePrefix {
		t.Fatalf("the class is kept: %v", got[1].Classes)
	}
	// an UNKNOWN class is still refused (fail closed), not skipped
	if GapClass("made_up").Valid() {
		t.Fatal("an unknown class stays invalid")
	}
}
