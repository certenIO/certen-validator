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
		"certen_finality_build_failures_total", "certen_finality_pending_total", "certen_finality_chain_broken_total",
	} {
		if !have[name] {
			t.Errorf("metric family %s is not exposed after RegisterMetrics", name)
		}
	}
}
