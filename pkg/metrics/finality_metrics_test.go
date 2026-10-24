// Copyright 2026 Certen Protocol

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterMetrics registers every collector of the process on the default registry with MustRegister, which panics on a
// duplicate name or a clashing label set. The finality series sit beside the lifecycle, evidence-monitor, persistence and
// anchor-quorum series, so the whole set is registered once here and the finality families are read back.
func TestRegisterMetricsHoldsTheFinalitySeriesBesideEveryOtherCollector(t *testing.T) {
	RegisterMetrics()
	SetFinalityUpgraderEnabled(true)
	IncFinalityAppended(11155111, "included")
	SetFinalityLegs(84532, "finalized", 2)
	IncFinalityBuildFailure(421614, "finality_build_timeout")
	IncFinalityPending(2017, "included")
	SetFinalityLegsWithoutSettlement(2017, 1)
	SetFinalityUnrecordedSettlements(1)
	SetFinalityLegsWithoutProver(1, 2)
	IncFinalityChainBroken(11155111)

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("the default registry does not gather: %v", err)
	}
	have := map[string]bool{}
	for _, f := range families {
		have[f.GetName()] = true
	}
	for _, name := range []string{
		"certen_finality_upgrader_enabled", "certen_finality_legs", "certen_finality_addenda_appended_total",
		"certen_finality_legs_without_settlement", "certen_finality_unrecorded_settlements", "certen_finality_legs_no_prover",
		"certen_finality_build_failures_total", "certen_finality_pending_total", "certen_finality_chain_broken_total",
	} {
		if !have[name] {
			t.Errorf("metric family %s is not exposed after RegisterMetrics", name)
		}
	}
}

// RB12-LEGACY-191: the legacy-header reconstruction is visible in /health/detailed and in the scrape: the leg counts per state, whether
// the last scan of the leg list failed (so a failing lister is not a 0/0/0/0 that looks like "no legacy legs"), and a loop that could
// not be registered.
func TestFinalityHealthCarriesTheLegacyHeaderStateOfAChain(t *testing.T) {
	RegisterMetrics()
	const chain = 777001
	if _, ok := FinalityHealth()["chains"].(map[string]any)["777001"]; ok {
		t.Fatal("the chain is known before anything was reported")
	}
	SetFinalityLegacyHeaders(chain, "reconstructed", 3)
	SetFinalityLegacyHeaders(chain, "unserved", 2)
	SetFinalityLegacyScan(chain, true)
	SetFinalityLegacyUnwired(chain, "registration_refused")
	h := FinalityHealth()["chains"].(map[string]any)["777001"].(map[string]any)["legacy_headers"].(map[string]any)
	if h["reconstructed"] != 3 || h["unserved"] != 2 || h["scan_failing"] != true || h["unwired"] != "registration_refused" {
		t.Fatalf("legacy_headers = %v", h)
	}
	SetFinalityLegacyScan(chain, false)
	SetFinalityLegacyUnwired(chain, "")
	h = FinalityHealth()["chains"].(map[string]any)["777001"].(map[string]any)["legacy_headers"].(map[string]any)
	if h["scan_failing"] != false {
		t.Fatalf("scan_failing did not clear: %v", h)
	}
	if _, ok := h["unwired"]; ok {
		t.Fatalf("unwired did not clear: %v", h)
	}
	SetFinalityLegacyScan(chain, true)
	SetFinalityLegacyUnwired(chain, "registration_refused")
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range families {
		switch f.GetName() {
		case "certen_finality_legacy_scan_failing", "certen_finality_legacy_unwired", "certen_finality_legacy_headers":
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "chain" && l.GetValue() == "777001" {
						key := f.GetName()
						for _, l2 := range m.GetLabel() {
							if l2.GetName() == "state" {
								key += "/" + l2.GetValue()
							}
						}
						got[key] = m.GetGauge().GetValue()
					}
				}
			}
		}
	}
	for k, want := range map[string]float64{"certen_finality_legacy_scan_failing": 1, "certen_finality_legacy_unwired": 1,
		"certen_finality_legacy_headers/reconstructed": 3, "certen_finality_legacy_headers/unserved": 2} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v (all: %v)", k, got[k], want, got)
		}
	}
}
