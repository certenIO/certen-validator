// Copyright 2026 Certen Protocol
//
// Consensus persistence metrics.
//
// # WHY THESE EXIST
//
// Consensus persistence (consensus_entries, batch_attestations) runs in a background writer, off the ABCI
// Commit path, so a slow or broken database can no longer stall consensus. The price is that a stalled
// writer no longer shows up as a stalled chain: blocks keep committing while nothing is persisted. These
// series make that visible.
//
//	certen_consensus_persist_lag_blocks        committed height minus persisted height
//	certen_consensus_persist_errors_total      write/read failures that will be retried, by operation
//	certen_consensus_persist_dropped_total     hand-offs refused because the queue was full (rebuilt later)
//	certen_consensus_persist_gaps_total        heights whose rows could not be rebuilt (pruned block store)
//	certen_consensus_persist_rejected_total    rows the database refused on content (skipped)
//	certen_consensus_persist_rewinds_total     watermark found ahead of the chain (a reset chain)
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	persistLag = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_consensus_persist_lag_blocks",
		Help: "Committed CometBFT height minus the height consensus persistence has written.",
	})
	persistErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_consensus_persist_errors_total",
		Help: "Consensus persistence operations that failed and will be retried.",
	}, []string{"operation"})
	persistDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_consensus_persist_dropped_total",
		Help: "Committed blocks not handed to the persister because its queue was full (rebuilt from the block store).",
	})
	persistGaps = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_consensus_persist_gaps_total",
		Help: "Committed heights whose consensus rows could not be rebuilt.",
	})
	persistRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_consensus_persist_rejected_total",
		Help: "Consensus rows the database refused on content and that were skipped.",
	})
	persistRewinds = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_consensus_persist_rewinds_total",
		Help: "Times the persisted-height watermark was found ahead of the chain and rewound.",
	})
)

// SetConsensusPersistLag records committed height minus persisted height.
func SetConsensusPersistLag(blocks int64) { persistLag.Set(float64(blocks)) }

// RecordConsensusPersistError counts a failed persistence operation that will be retried.
func RecordConsensusPersistError(operation string) { persistErrors.WithLabelValues(operation).Inc() }

// RecordConsensusPersistDropped counts a refused hand-off.
func RecordConsensusPersistDropped() { persistDropped.Inc() }

// RecordConsensusPersistGap counts a height that could not be rebuilt.
func RecordConsensusPersistGap() { persistGaps.Inc() }

// RecordConsensusPersistRejected counts a row refused on content.
func RecordConsensusPersistRejected() { persistRejected.Inc() }

// RecordConsensusPersistRewind counts a watermark rewind.
func RecordConsensusPersistRewind() { persistRewinds.Inc() }

// registerPersistenceMetrics is called from RegisterMetrics.
func registerPersistenceMetrics() {
	prometheus.MustRegister(persistLag)
	prometheus.MustRegister(persistErrors)
	prometheus.MustRegister(persistDropped)
	prometheus.MustRegister(persistGaps)
	prometheus.MustRegister(persistRejected)
	prometheus.MustRegister(persistRewinds)
}

// Recommended alert rules:
//
//   - alert: CertenConsensusPersistenceStalled
//     expr: certen_consensus_persist_lag_blocks > 50 or increase(certen_consensus_persist_errors_total[15m]) > 20
//     for: 15m
//     labels: {severity: warning}
//     annotations:
//       summary: "Consensus rows are not being written (chain unaffected); check the database and migration 017"
