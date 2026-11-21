// Copyright 2026 Certen Protocol
//
// Proof v2 history floor metrics (AGT-F104, OQ12; pkg/proof/v2/historyfloor.go). The validator judges the Accumulate node it reads
// against PROOF_V2_HISTORY_FLOOR at start and every 10 minutes while it runs. A node that prunes below the floor does not stop the
// validator: consensus, intent processing and every intent whose governing pages are provable carry on, and each intent that cannot
// be proven is refused by name (g1_historical_unavailable{partition,block}). These series make the node's verdict visible so it is
// reported to the operator, never discovered as a stream of refusals.
//
//	certen_proof_v2_history_floor_met                    1 when the node keeps every block from the floor on, 0 otherwise
//	certen_proof_v2_history_floor_checks_total{verdict}  each judgement: met | unset | malformed | partition_missing | partition_unknown
//	                                                     | above_head | unmet | unreadable
//
// Alert: certen_proof_v2_history_floor_met == 0 for 15m (intents with a governing page on a partition quiet for longer than the
// node's retention are unprovable until the node keeps the floor). ProofV2HistoryHealth is the same verdict for /health/detailed.
package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	phOnce sync.Once

	phMet = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_proof_v2_history_floor_met",
		Help: "1 when the Accumulate node proof v2 reads keeps every block from PROOF_V2_HISTORY_FLOOR on, 0 when it does not, is unset or cannot be read.",
	})
	phChecks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_proof_v2_history_floor_checks_total",
		Help: "Judgements of the proof v2 history floor, by verdict.",
	}, []string{"verdict"})

	phHealth struct {
		mu        sync.Mutex
		known     bool
		verdict   string
		partition string
		detail    string
		floor     string
		checkedAt time.Time
	}
)

func phRegister() {
	phOnce.Do(func() {
		prometheus.MustRegister(phMet, phChecks)
	})
}

// ReportProofV2HistoryFloor records one judgement. verdict is "met" or a named failure (the FloorError code without its
// "proof_v2_history_floor_" prefix, or "unreadable"); partition is the partition it names ("" when none); detail is the
// human-readable reason; floor is the configured floor as printed (never anything else from the environment).
func ReportProofV2HistoryFloor(verdict, partition, detail, floor string, at time.Time) {
	phRegister()
	phChecks.WithLabelValues(verdict).Inc()
	if verdict == "met" {
		phMet.Set(1)
	} else {
		phMet.Set(0)
	}
	phHealth.mu.Lock()
	defer phHealth.mu.Unlock()
	phHealth.known = true
	phHealth.verdict, phHealth.partition, phHealth.detail, phHealth.floor, phHealth.checkedAt = verdict, partition, detail, floor, at
}

// ProofV2HistoryHealth is the latest judgement as a JSON-ready block ("verdict": "not_checked" before the first one).
func ProofV2HistoryHealth() map[string]any {
	phHealth.mu.Lock()
	defer phHealth.mu.Unlock()
	if !phHealth.known {
		return map[string]any{"verdict": "not_checked"}
	}
	out := map[string]any{
		"verdict":    phHealth.verdict,
		"met":        phHealth.verdict == "met",
		"checked_at": phHealth.checkedAt.UTC().Format(time.RFC3339),
	}
	if phHealth.partition != "" {
		out["partition"] = phHealth.partition
	}
	if phHealth.detail != "" {
		out["detail"] = phHealth.detail
	}
	if phHealth.floor != "" {
		out["floor"] = phHealth.floor
	}
	return out
}
