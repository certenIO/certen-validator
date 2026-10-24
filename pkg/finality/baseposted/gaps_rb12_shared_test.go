// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// The Base l1_capture_gap is the shared builder's output (finality.CaptureGapState), with Base's own chain, kind and archive field.
func TestRB12BaseGapStateIsTheSharedBuilder(t *testing.T) {
	pieces := []finality.GapRange{{From: 200, To: 205, State: finality.GapOpen}, {From: 100, To: 120, State: finality.GapUnavailableProven}}
	for _, archive := range []bool{true, false} {
		arch := "unset"
		if archive {
			arch = "set"
		}
		want := finality.CaptureGapState(uint64(Chain), KindName, pieces, 90, 3700, arch)
		if got := gapState(pieces, 90, 3700, archive); !bytes.Equal(got.Canonical(), want.Canonical()) {
			t.Fatalf("archive=%v: %v vs the shared builder %v", archive, got, want)
		}
	}
}
