// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"testing"
)

// RB12-TRAIN3-INT duty (b), F-ab-9: ONE l1_capture_gap builder for every family. The pieces may come in any order; the state names the most
// urgent state among them, the first range of that state in block order, and conforms to the registry.
func TestRB12CaptureGapStateIsOneBuilderForEveryFamily(t *testing.T) {
	reg := loadRegistry(t)
	pieces := []GapRange{
		{From: 300, To: 310, State: GapRetentionExpired},
		{From: 200, To: 205, State: GapOpen},
		{From: 100, To: 120, State: GapOpen},
		{From: 150, To: 160, State: GapUnavailableProven},
	}
	a := CaptureGapState(84532, "base-sepolia/l1_posted/v1", pieces, 90, 3700, "set")
	b := CaptureGapState(421614, "arbitrum-sepolia/l1_posted/v1", pieces, 90, 3700, "n/a")
	for _, st := range []*StateError{a, b} {
		if msg := conforms(reg, st); msg != "" {
			t.Fatalf("%v: %s", st, msg)
		}
		if st.Fields["gap_state"] != "open" || st.Fields["from"] != uint64(100) || st.Fields["to"] != uint64(120) || st.Fields["ranges"] != uint64(2) || st.Fields["blocks"] != uint64(27) {
			t.Fatalf("an open gap outranks the terminal ones; the first open range in block order is named, with the count of open ranges and blocks: %v", st)
		}
	}
	// the same pieces in any order give the same bytes: only the family's own chain, kind and archive fields differ
	rev := []GapRange{pieces[3], pieces[2], pieces[1], pieces[0]}
	if !bytes.Equal(a.Canonical(), CaptureGapState(84532, "base-sepolia/l1_posted/v1", rev, 90, 3700, "set").Canonical()) {
		t.Fatal("the state must not depend on the order of the pieces")
	}
	if len(pieces) != 4 || pieces[0].From != 300 {
		t.Fatal("the caller\x27s pieces are not reordered")
	}
	for k := range a.Fields {
		if k == "chain" || k == "kind" || k == "archive_provider" {
			continue
		}
		if a.Fields[k] != b.Fields[k] {
			t.Fatalf("field %s differs between families: %v vs %v", k, a.Fields[k], b.Fields[k])
		}
	}
	if CaptureGapState(84532, "k", nil, 1, 2, "set") != nil {
		t.Fatal("a window with no piece has no gap state")
	}
}
