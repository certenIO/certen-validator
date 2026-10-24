// Copyright 2026 Certen Protocol
//
// Capture-index metrics (RB12-INDEX-A, pkg/finality capindex.go and pkg/finality/baseposted index*.go). The index is built as captures
// arrive and lets a build load only the rows of its own channel; these series say how far it got, what it wrote, whether it agrees
// with the captured bytes and what a build found in it.
//
//	certen_finality_index_through_block{chain,family}     the L1 block the index has processed through (its cursor)
//	certen_finality_index_lag_blocks{chain,family}        capture cursor minus index cursor (0 = caught up; backfill shows a large value)
//	certen_finality_index_open_channels{chain,family}     channels in the index's frame table that are not complete (a missing frame is a hole)
//	certen_finality_index_digests_total{chain,family}     block digests written
//	certen_finality_index_entries_total{chain,family}     channel entries written
//	certen_finality_index_late_blocks_total{chain,family} blocks digested by the reconcile walk (arrived after the cursor passed them)
//	certen_finality_index_rebuilds_total{chain,family}    index generations started (a rebuild is a new generation)
//	certen_finality_index_mismatches_total{chain,family}  self-check recomputations that differ from the stored row (should be 0)
//	certen_finality_index_conflicts_total{chain,family}   writes refused because the row exists with different bytes (should be 0)
//	certen_finality_index_lookups_total{chain,family,result}   build lookups: hit, miss, gap, behind, inconsistent
//	certen_finality_index_lookup_bytes{chain,family}      capture bytes a build read to assemble its channel (histogram)
//	certen_finality_index_step_seconds{chain,family}      wall time of one indexer step (histogram)
//	certen_finality_index_selfcheck_skipped_total{chain,family}  self-checks not run because the memory budget refused the rows (never silent)
//	certen_finality_index_unindexable_blocks_total{chain,family,reason}  captured blocks the indexer could not read (index_block_unindexable)
//	certen_finality_index_notes_dropped_total{chain,family}  late-block notes beyond the pending set's bound (Base drops them, the rotation still reaches the block; Arbitrum folds them into range notes)
//	certen_finality_index_entries_skipped_total{chain,family,reason}  complete channels that get no entry (reason over_window: frames further apart than the sequencing window)
//	certen_finality_index_wide_pointers{chain,family}     pointer rows of batches wider than the normal lookup window, as the last lookup listed them (0 in production)
//	certen_finality_index_disabled{chain,family,key,reason}      1 while a bad setting has switched the index off (finality_index_disabled)
//	certen_finality_capture_foreign_txs_total{chain}      batch-inbox transactions skipped because the batcher of their block did not send them (F19)
//	certen_finality_capture_batcher_unestablished_total{chain}   blocks whose captured rows cannot establish the batcher (their frames are not filtered)
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	finalityIndexThrough = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_index_through_block",
		Help: "The L1 block the capture index has processed through.",
	}, []string{"chain", "family"})
	finalityIndexLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_index_lag_blocks",
		Help: "Capture cursor minus capture-index cursor, in L1 blocks.",
	}, []string{"chain", "family"})
	finalityIndexOpen = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_index_open_channels",
		Help: "Channels in the capture index's frame table that are not complete (a frame lies in a capture hole or has not arrived).",
	}, []string{"chain", "family"})
	finalityIndexDigests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_digests_total",
		Help: "Block digests written to the capture index.",
	}, []string{"chain", "family"})
	finalityIndexEntries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_entries_total",
		Help: "Channel entries written to the capture index.",
	}, []string{"chain", "family"})
	finalityIndexLate = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_late_blocks_total",
		Help: "Captured blocks the reconcile walk digested because they arrived after the index cursor passed them.",
	}, []string{"chain", "family"})
	finalityIndexRebuilds = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_rebuilds_total",
		Help: "Capture-index generations started by this process (a rebuild is a new generation).",
	}, []string{"chain", "family"})
	finalityIndexMismatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_mismatches_total",
		Help: "Self-check recomputations from the captured rows that differ from the stored index row (named state index_inconsistent).",
	}, []string{"chain", "family"})
	finalityIndexConflicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_conflicts_total",
		Help: "Index writes refused because the row exists with different bytes (rows are a pure function of the captured bytes).",
	}, []string{"chain", "family"})
	finalityIndexUnindexable = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_unindexable_blocks_total",
		Help: "Captured blocks the indexer could not read, recorded as index_block_unindexable by reason (a leg whose window holds one and whose channel is missing is told by name).",
	}, []string{"chain", "family", "reason"})
	finalityIndexEntriesSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_entries_skipped_total",
		Help: "Complete channels that get no index entry, by reason (over_window: their frames lie further apart than the sequencing window, so no leg can be served by them).",
	}, []string{"chain", "family", "reason"})
	finalityIndexNotesDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_notes_dropped_total",
		Help: "Late-block notes beyond the pending set's bound: the Base index drops them (the rotating walk reaches the block, later), the Arbitrum index folds them into range notes and still works them off.",
	}, []string{"chain", "family"})
	finalityIndexWidePointers = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_index_wide_pointers",
		Help: "Pointer rows of batches whose time bounds are wider than the normal lookup window, as the last lookup listed them (a lookup names coverage_overflow above the bound).",
	}, []string{"chain", "family"})
	finalityIndexSelfCheckSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_selfcheck_skipped_total",
		Help: "Index self-checks not run because the memory budget refused the rows they read (a skipped check is counted, never silent).",
	}, []string{"chain", "family"})
	finalityIndexDisabled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_index_disabled",
		Help: "1 while a bad index setting has switched the capture index off (finality_index_disabled); the window reader serves.",
	}, []string{"chain", "family", "key", "reason"})
	finalityPrefixDisabled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_prefix_disabled",
		Help: "1 while a bad prefix setting has switched the archive backfill of a chain off (finality_prefix_disabled); the rest of finality runs.",
	}, []string{"chain", "key", "reason"})
	finalityForeignTxs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_capture_foreign_txs_total",
		Help: "Batch-inbox transactions skipped because the SystemConfig batcher of their block did not send them.",
	}, []string{"chain"})
	finalityBatcherUnestablished = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_capture_batcher_unestablished_total",
		Help: "Captured blocks whose rows cannot establish the batcher: their frames are kept as candidates and the verifier names the fault.",
	}, []string{"chain"})
	finalityIndexLookups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_index_lookups_total",
		Help: "Build lookups in the capture index by result (hit, miss, gap, behind, inconsistent).",
	}, []string{"chain", "family", "result"})
	finalityIndexLookupBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "certen_finality_index_lookup_bytes",
		Help:    "Capture bytes a build read to assemble the evidence of its channel.",
		Buckets: prometheus.ExponentialBuckets(1<<10, 4, 10),
	}, []string{"chain", "family"})
	finalityIndexStepSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "certen_finality_index_step_seconds",
		Help:    "Wall time of one capture-index step.",
		Buckets: prometheus.ExponentialBuckets(0.01, 3, 10),
	}, []string{"chain", "family"})
)

func registerFinalityIndexMetrics() {
	prometheus.MustRegister(finalityIndexThrough)
	prometheus.MustRegister(finalityIndexLag)
	prometheus.MustRegister(finalityIndexOpen)
	prometheus.MustRegister(finalityIndexDigests)
	prometheus.MustRegister(finalityIndexEntries)
	prometheus.MustRegister(finalityIndexLate)
	prometheus.MustRegister(finalityIndexRebuilds)
	prometheus.MustRegister(finalityIndexMismatches)
	prometheus.MustRegister(finalityIndexConflicts)
	prometheus.MustRegister(finalityIndexLookups)
	prometheus.MustRegister(finalityIndexLookupBytes)
	prometheus.MustRegister(finalityIndexStepSeconds)
	prometheus.MustRegister(finalityIndexSelfCheckSkipped)
	prometheus.MustRegister(finalityIndexNotesDropped)
	prometheus.MustRegister(finalityIndexEntriesSkipped)
	prometheus.MustRegister(finalityIndexWidePointers)
	prometheus.MustRegister(finalityIndexUnindexable)
	prometheus.MustRegister(finalityIndexDisabled)
	prometheus.MustRegister(finalityPrefixDisabled)
	prometheus.MustRegister(finalityForeignTxs)
	prometheus.MustRegister(finalityBatcherUnestablished)
}

// SetFinalityIndexProgress reports the index cursor, how far behind the capture cursor it is and how many channels are open.
func SetFinalityIndexProgress(chain uint64, family string, through, target uint64, open int) {
	c := chainLabel(chain)
	finalityIndexThrough.WithLabelValues(c, family).Set(float64(through))
	lag := uint64(0)
	if target > through {
		lag = target - through
	}
	finalityIndexLag.WithLabelValues(c, family).Set(float64(lag))
	finalityIndexOpen.WithLabelValues(c, family).Set(float64(open))
}

// AddFinalityIndexWritten counts digests, entries and late blocks written by a step.
func AddFinalityIndexWritten(chain uint64, family string, digests, entries, late int) {
	c := chainLabel(chain)
	if digests > 0 {
		finalityIndexDigests.WithLabelValues(c, family).Add(float64(digests))
	}
	if entries > 0 {
		finalityIndexEntries.WithLabelValues(c, family).Add(float64(entries))
	}
	if late > 0 {
		finalityIndexLate.WithLabelValues(c, family).Add(float64(late))
	}
}

// IncFinalityIndexRebuild counts an index generation started by this process.
func IncFinalityIndexRebuild(chain uint64, family string) {
	finalityIndexRebuilds.WithLabelValues(chainLabel(chain), family).Inc()
}

// IncFinalityIndexMismatch counts a self-check mismatch.
func IncFinalityIndexMismatch(chain uint64, family string) {
	finalityIndexMismatches.WithLabelValues(chainLabel(chain), family).Inc()
}

// IncFinalityIndexConflict counts a refused conflicting write.
func IncFinalityIndexConflict(chain uint64, family string) {
	finalityIndexConflicts.WithLabelValues(chainLabel(chain), family).Inc()
}

// IncFinalityIndexLookup counts a build lookup by result.
func IncFinalityIndexLookup(chain uint64, family, result string) {
	finalityIndexLookups.WithLabelValues(chainLabel(chain), family, result).Inc()
}

// ObserveFinalityIndexLookupBytes records the capture bytes a build read for its channel.
func ObserveFinalityIndexLookupBytes(chain uint64, family string, n int64) {
	finalityIndexLookupBytes.WithLabelValues(chainLabel(chain), family).Observe(float64(n))
}

// ObserveFinalityIndexStep records the wall time of one indexer step.
func ObserveFinalityIndexStep(chain uint64, family string, seconds float64) {
	finalityIndexStepSeconds.WithLabelValues(chainLabel(chain), family).Observe(seconds)
}

// IncFinalityIndexSelfCheckSkipped counts a self-check that was not run because the memory budget refused the rows it reads.
func IncFinalityIndexSelfCheckSkipped(chain uint64, family string) {
	finalityIndexSelfCheckSkipped.WithLabelValues(chainLabel(chain), family).Inc()
}

// SetFinalityIndexDisabled marks the capture index of a chain as switched off by the bad setting key (reason: switch_invalid,
// not_an_integer, out_of_range).
func SetFinalityIndexDisabled(chain uint64, family, key, reason string) {
	finalityIndexDisabled.WithLabelValues(chainLabel(chain), family, key, reason).Set(1)
}

// SetFinalityPrefixDisabled marks the archive backfill of a chain as switched off by the bad setting key (reason: setting_invalid).
func SetFinalityPrefixDisabled(chain uint64, key, reason string) {
	finalityPrefixDisabled.WithLabelValues(chainLabel(chain), key, reason).Set(1)
}

// AddFinalityCaptureForeignTxs counts batch-inbox transactions skipped because the batcher of their block did not send them.
func AddFinalityCaptureForeignTxs(chain uint64, n int) {
	finalityForeignTxs.WithLabelValues(chainLabel(chain)).Add(float64(n))
}

// IncFinalityBatcherUnestablished counts a captured block whose rows cannot establish the batcher.
func IncFinalityBatcherUnestablished(chain uint64) {
	finalityBatcherUnestablished.WithLabelValues(chainLabel(chain)).Inc()
}

// IncFinalityIndexUnindexable counts a captured block recorded as unindexable.
func IncFinalityIndexUnindexable(chain uint64, family, reason string) {
	finalityIndexUnindexable.WithLabelValues(chainLabel(chain), family, reason).Inc()
}

// SetFinalityIndexWidePointers reports how many wide-batch pointer rows the last lookup listed.
func SetFinalityIndexWidePointers(chain uint64, family string, n int) {
	finalityIndexWidePointers.WithLabelValues(chainLabel(chain), family).Set(float64(n))
}

// IncFinalityIndexNoteDropped counts a late-block note dropped because the set of pending notes was full.
func IncFinalityIndexNoteDropped(chain uint64, family string) {
	finalityIndexNotesDropped.WithLabelValues(chainLabel(chain), family).Inc()
}

// IncFinalityIndexEntrySkipped counts a complete channel that gets no entry, by reason.
func IncFinalityIndexEntrySkipped(chain uint64, family, reason string) {
	finalityIndexEntriesSkipped.WithLabelValues(chainLabel(chain), family, reason).Inc()
}
