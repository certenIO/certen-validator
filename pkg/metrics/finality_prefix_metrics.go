// Copyright 2026 Certen Protocol

package metrics

import "github.com/prometheus/client_golang/prometheus"

// RB12-ARCHIVE-BACKFILL: the legs that predate the capture and what it takes to serve them.
var (
	finalityPrefixWindows = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_prefix_windows",
		Help: "Requested capture-store prefix windows (one per leg posted before the capture started, overlapping windows counted apart), by state: complete, open (being captured), unavailable_proven or retention_expired (the blobs are gone: a blob archive would close them).",
	}, []string{"chain", "state"})
	finalityPrefixBlocks = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_prefix_requested_blocks",
		Help: "Parent-chain blocks in the union of the requested prefix windows (bounded by CERTEN_FINALITY_PREFIX_MAX_BLOCKS).",
	}, []string{"chain"})
	finalityPrefixBackfilled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_prefix_backfilled_blocks_total",
		Help: "Prefix blocks this process captured by backfill.",
	}, []string{"chain"})
	finalityPrefixLease = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_prefix_lease_total",
		Help: "Claims on chunks of prefix blocks by outcome: lost (another validator holds the chunk for this period) or error (the store could not take the claim).",
	}, []string{"chain", "outcome"})
)

// SetFinalityPrefixWindows reports the requested prefix windows of the chain by state and the blocks they hold.
func SetFinalityPrefixWindows(chain uint64, complete, open, unavailableProven, retentionExpired int, blocks uint64) {
	c := chainLabel(chain)
	finalityPrefixWindows.WithLabelValues(c, "complete").Set(float64(complete))
	finalityPrefixWindows.WithLabelValues(c, "open").Set(float64(open))
	finalityPrefixWindows.WithLabelValues(c, "unavailable_proven").Set(float64(unavailableProven))
	finalityPrefixWindows.WithLabelValues(c, "retention_expired").Set(float64(retentionExpired))
	finalityPrefixBlocks.WithLabelValues(c).Set(float64(blocks))
}

// AddFinalityPrefixBackfilled counts prefix blocks the backfill closed.
func AddFinalityPrefixBackfilled(chain uint64, n int) {
	if n > 0 {
		finalityPrefixBackfilled.WithLabelValues(chainLabel(chain)).Add(float64(n))
	}
}

// AddFinalityPrefixLease counts claim outcomes ("lost", "error").
func AddFinalityPrefixLease(chain uint64, outcome string, n int) {
	if n > 0 {
		finalityPrefixLease.WithLabelValues(chainLabel(chain), outcome).Add(float64(n))
	}
}

func registerFinalityPrefixMetrics() {
	prometheus.MustRegister(finalityPrefixWindows)
	prometheus.MustRegister(finalityPrefixBlocks)
	prometheus.MustRegister(finalityPrefixBackfilled)
	prometheus.MustRegister(finalityPrefixLease)
}
