// Copyright 2026 Certen Protocol

package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// RB12-SEPOLIA-SPINE: the progress of the Ethereum Sepolia execution-header spine, which is fetched in kept chunks over several attempts.
// A leg in finality_pending{awaiting_spine} is normal; one that stops gaining kept chunks is not, and that is what the stalled gauge says
// (alert: certen_finality_spine_stalled_attempts_max, see pr/rb11-alerts.md). The gauges are per process: one Sepolia prover runs in it.
var (
	finalitySpineHeaders = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_spine_headers_total",
		Help: "Spine headers by outcome: fetched (from the provider by this process) or reused (read from the process cache or the kept rows).",
	}, []string{"outcome"})
	finalitySpineAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_spine_attempts_total",
		Help: "Spine attempts by outcome: complete, budget (the attempt's time for new fetches was spent), throttled, error (a provider or the store failed), failed (a named state stopped the build).",
	}, []string{"outcome"})
	finalitySpineRowsInvalid = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_spine_rows_invalid_total",
		Help: "Kept spine rows that were not what their key says (finality_spine_row_invalid) and were replaced from the provider in this process, by reason.",
	}, []string{"reason"})
	finalitySpineAwaiting = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "certen_finality_spine_legs_awaiting",
		Help: "Legs whose latest spine attempt ended in finality_pending{awaiting_spine} within the last hour.",
	}, func() float64 { a, _ := spineLegs(); return float64(a) })
	finalitySpineStalled = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "certen_finality_spine_stalled_attempts_max",
		Help: "The longest run of consecutive spine attempts, over the legs, that gained no spine headers in hand (a leg that is progressing is 0); a leg not attempted for an hour is forgotten.",
	}, func() float64 { _, s := spineLegs(); return float64(s) })
)

var (
	spineSourceMu sync.Mutex
	spineSource   func() (awaiting, stalledMax int)
)

func spineLegs() (awaiting, stalledMax int) {
	spineSourceMu.Lock()
	f := spineSource
	spineSourceMu.Unlock()
	if f == nil {
		return 0, 0
	}
	return f()
}

// AddFinalitySpineHeaders counts spine headers: outcome is "fetched" or "reused".
func AddFinalitySpineHeaders(outcome string, n int) {
	if n > 0 {
		finalitySpineHeaders.WithLabelValues(outcome).Add(float64(n))
	}
}

// IncFinalitySpineAttempt counts one spine attempt by how it ended.
func IncFinalitySpineAttempt(outcome string) { finalitySpineAttempts.WithLabelValues(outcome).Inc() }

// IncFinalitySpineRowInvalid counts a kept spine row that failed its check.
func IncFinalitySpineRowInvalid(reason string) {
	finalitySpineRowsInvalid.WithLabelValues(reason).Inc()
}

// SetFinalitySpineSource names where the two spine gauges are read from, at every scrape: the legs awaiting their spine and the longest
// run of attempts without gaining spine headers in hand. The function must expire what is stale itself (one Sepolia prover per process).
func SetFinalitySpineSource(f func() (awaiting, stalledMax int)) {
	spineSourceMu.Lock()
	spineSource = f
	spineSourceMu.Unlock()
}

func registerFinalitySpineMetrics() {
	prometheus.MustRegister(finalitySpineHeaders)
	prometheus.MustRegister(finalitySpineAttempts)
	prometheus.MustRegister(finalitySpineRowsInvalid)
	prometheus.MustRegister(finalitySpineAwaiting)
	prometheus.MustRegister(finalitySpineStalled)
}
