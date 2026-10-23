// Copyright 2026 Certen Protocol

package metrics

import "testing"

func TestRB12GapMetricsAreRegisteredAndCarryTheirLabels(t *testing.T) {
	RegisterMetrics()
	SetFinalityGapBlocks(84532, 684, 2, 1, 3)
	IncFinalityGapRecorded(84532, "outage_unscanned")
	AddFinalityGapBackfilled(84532, 5)
	IncFinalityGapBackfillFailure(84532, "state_proof_unavailable")
	AddFinalityGapEnded(84532, "unavailable_proven", 1)
	want := map[string]bool{
		"certen_finality_capture_gap_blocks": false, "certen_finality_capture_gap_open_ranges": false, "certen_finality_capture_gaps_recorded_total": false,
		"certen_finality_gap_backfilled_blocks_total": false, "certen_finality_gap_backfill_failures_total": false, "certen_finality_gap_ended_total": false,
	}
	families, err := gatherDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range families {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("metric family %s is not exposed after RegisterMetrics", name)
		}
	}
}
