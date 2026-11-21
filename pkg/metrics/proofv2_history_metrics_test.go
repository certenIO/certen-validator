// Copyright 2026 Certen Protocol

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// AGT-F104: the gauge is 1 only for "met"; every named failure sets it to 0 and is counted under its verdict.
func TestProofV2HistoryFloorGaugeAndCounter(t *testing.T) {
	at := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	if ProofV2HistoryHealth()["verdict"] != "not_checked" {
		t.Fatal("verdict before the first judgement")
	}
	ReportProofV2HistoryFloor("met", "", "", "BVN1=1", at)
	if testutil.ToFloat64(phMet) != 1 {
		t.Fatal("met gauge")
	}
	before := testutil.ToFloat64(phChecks.WithLabelValues("unmet"))
	ReportProofV2HistoryFloor("unmet", "BVN3", "proof_v2_history_floor_unmet{BVN3}: ...", "BVN1=1", at)
	if testutil.ToFloat64(phMet) != 0 || testutil.ToFloat64(phChecks.WithLabelValues("unmet")) != before+1 {
		t.Fatal("unmet gauge / counter")
	}
	h := ProofV2HistoryHealth()
	if h["verdict"] != "unmet" || h["partition"] != "BVN3" || h["met"] != false || h["checked_at"] != "2026-11-21T12:00:00Z" {
		t.Fatalf("health %v", h)
	}
	ReportProofV2HistoryFloor("unreadable", "", "connection refused", "", at)
	if testutil.ToFloat64(phMet) != 0 || ProofV2HistoryHealth()["floor"] != nil {
		t.Fatal("unreadable")
	}
}
