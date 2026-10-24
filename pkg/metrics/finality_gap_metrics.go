// Copyright 2026 Certen Protocol

package metrics

import "github.com/prometheus/client_golang/prometheus"

// RB12-CAPTURE-GAP (F13): the capture holes a validator knows about, and the backfill that closes them.
var (
	finalityGapBlocks = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_capture_gap_blocks",
		Help: "Parent-chain blocks inside a recorded capture gap, by state (open: not captured yet; unavailable_proven; retention_expired).",
	}, []string{"chain", "state"})
	finalityGapRanges = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_capture_gap_open_ranges",
		Help: "Runs of consecutive open capture-gap blocks.",
	}, []string{"chain"})
	finalityGapRecorded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_capture_gaps_recorded_total",
		Help: "Capture gaps this process recorded (a block or a range the capture loop could not capture), by class.",
	}, []string{"chain", "class"})
	finalityGapBackfilled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_gap_backfilled_blocks_total",
		Help: "Gap blocks this process captured by backfill (including blocks scanned and found empty).",
	}, []string{"chain"})
	finalityGapBackfillFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_gap_backfill_failures_total",
		Help: "Backfill attempts that failed, by gap class; the block stays open and is retried with backoff.",
	}, []string{"chain", "class"})
	finalityGapEnded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_gap_ended_total",
		Help: "Gap blocks this process ended: unavailable_proven (every provider proved the data gone) or retention_expired.",
	}, []string{"chain", "kind"})
)

// SetFinalityGapBlocks reports how many gap blocks of the chain are in state and how many open runs there are.
func SetFinalityGapBlocks(chain uint64, open, unavailableProven, retentionExpired, openRanges uint64) {
	c := chainLabel(chain)
	finalityGapBlocks.WithLabelValues(c, "open").Set(float64(open))
	finalityGapBlocks.WithLabelValues(c, "unavailable_proven").Set(float64(unavailableProven))
	finalityGapBlocks.WithLabelValues(c, "retention_expired").Set(float64(retentionExpired))
	finalityGapRanges.WithLabelValues(c).Set(float64(openRanges))
}

// IncFinalityGapRecorded counts a gap the capture loop recorded.
func IncFinalityGapRecorded(chain uint64, class string) {
	finalityGapRecorded.WithLabelValues(chainLabel(chain), class).Inc()
}

// AddFinalityGapBackfilled counts blocks the backfill closed.
func AddFinalityGapBackfilled(chain uint64, n int) {
	if n > 0 {
		finalityGapBackfilled.WithLabelValues(chainLabel(chain)).Add(float64(n))
	}
}

// IncFinalityGapBackfillFailure counts a failed backfill attempt.
func IncFinalityGapBackfillFailure(chain uint64, class string) {
	finalityGapBackfillFailures.WithLabelValues(chainLabel(chain), class).Inc()
}

// AddFinalityGapEnded counts blocks the backfill ended.
func AddFinalityGapEnded(chain uint64, kind string, n int) {
	if n > 0 {
		finalityGapEnded.WithLabelValues(chainLabel(chain), kind).Add(float64(n))
	}
}

func registerFinalityGapMetrics() {
	prometheus.MustRegister(finalityGapBlocks)
	prometheus.MustRegister(finalityGapRanges)
	prometheus.MustRegister(finalityGapRecorded)
	prometheus.MustRegister(finalityGapBackfilled)
	prometheus.MustRegister(finalityGapBackfillFailures)
	prometheus.MustRegister(finalityGapEnded)
}
