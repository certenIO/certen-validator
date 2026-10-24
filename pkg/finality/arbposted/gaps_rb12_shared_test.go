// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// The Arbitrum l1_capture_gap is the shared builder's output (finality.CaptureGapState), with Arbitrum's own chain, kind and "n/a" archive.
func TestRB12ArbitrumGapStateIsTheSharedBuilder(t *testing.T) {
	pieces := []finality.GapRange{{From: 200, To: 205, State: finality.GapOpen}, {From: 100, To: 120, State: finality.GapRetentionExpired}}
	want := finality.CaptureGapState(finality.ChainArbitrumSepolia, KindName, pieces, 90, 3700, "n/a")
	if got := gapState(pieces, 90, 3700); !bytes.Equal(got.Canonical(), want.Canonical()) {
		t.Fatalf("%v vs the shared builder %v", got, want)
	}
}
