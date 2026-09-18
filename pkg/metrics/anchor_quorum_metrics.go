// Copyright 2026 Certen Protocol
//
// Anchor quorum evidence metrics.
//
// # WHY THESE EXIST
//
// The quorum a batch anchor carries was computed and discarded for months, and nothing noticed: no
// request failed, no log said anything was missing, and the only visible symptom was
// batch_quorum_met=false in a UI — which looks like a feature that is simply off. 70,236 anchor rows
// accumulated with quorum_reached never once true.
//
// A silent write path needs its own signal, so these exist before the writer ships:
//
//	certen_anchor_quorum_written_total     canonical rows this validator created
//	certen_anchor_quorum_conflicts_total   an existing row disagreed — never overwritten, always alerted
//	certen_anchor_quorum_dropped_total     evidence not queued (writer saturated); recover with backfill
//	certen_anchor_quorum_write_errors_total write failures being retried
//
// The alert that matters is the ABSENCE one: settled intents with no canonical row. `written` going to
// zero while the fleet is anchoring is the same outage as before, and is what an operator should page on.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	anchorQuorumWritten = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "anchor_quorum",
		Name:      "written_total",
		Help:      "Canonical anchor rows written by this validator (first writer wins; duplicates are not counted)",
	})
	anchorQuorumConflicts = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "anchor_quorum",
		Name:      "conflicts_total",
		Help:      "Anchors whose stored evidence disagreed with this validator's; the stored row was left unchanged",
	})
	anchorQuorumDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "anchor_quorum",
		Name:      "dropped_total",
		Help:      "Proven anchors whose evidence could not be queued for writing (recoverable from the chain)",
	})
	anchorQuorumWriteErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "anchor_quorum",
		Name:      "write_errors_total",
		Help:      "Failed attempts to record anchor quorum evidence (retried)",
	})
	anchorQuorumOutboxDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "anchor_quorum",
		Name:      "outbox_depth",
		Help:      "Proven anchors held on disk awaiting a database that can take them",
	})
	anchorQuorumOutboxReplayed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "anchor_quorum",
		Name:      "outbox_replayed_total",
		Help:      "Canonical rows recovered from the outbox after the database became available again",
	})
	anchorQuorumOutboxQuarantined = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "anchor_quorum",
		Name:      "outbox_quarantined_total",
		Help:      "Outbox entries set aside for a human: the stored row disagreed, or the entry did not decode",
	})
)

// RecordAnchorQuorumWritten counts a canonical row this validator created.
func RecordAnchorQuorumWritten() { anchorQuorumWritten.Inc() }

// RecordAnchorQuorumConflict counts an anchor whose stored evidence disagreed.
func RecordAnchorQuorumConflict() { anchorQuorumConflicts.Inc() }

// RecordAnchorQuorumDropped counts evidence that could not be queued.
func RecordAnchorQuorumDropped() { anchorQuorumDropped.Inc() }

// RecordAnchorQuorumWriteError counts a write failure that will be retried.
func RecordAnchorQuorumWriteError() { anchorQuorumWriteErrors.Inc() }

// SetAnchorQuorumOutboxDepth reports how much proven evidence is waiting on disk.
func SetAnchorQuorumOutboxDepth(n int) { anchorQuorumOutboxDepth.Set(float64(n)) }

// RecordAnchorQuorumOutboxReplayed counts a row recovered from the outbox.
func RecordAnchorQuorumOutboxReplayed() { anchorQuorumOutboxReplayed.Inc() }

// RecordAnchorQuorumOutboxQuarantined counts an entry set aside for investigation.
func RecordAnchorQuorumOutboxQuarantined() { anchorQuorumOutboxQuarantined.Inc() }

// registerAnchorQuorumMetrics is called from RegisterMetrics.
func registerAnchorQuorumMetrics() {
	prometheus.MustRegister(anchorQuorumWritten)
	prometheus.MustRegister(anchorQuorumConflicts)
	prometheus.MustRegister(anchorQuorumDropped)
	prometheus.MustRegister(anchorQuorumWriteErrors)
	prometheus.MustRegister(anchorQuorumOutboxDepth)
	prometheus.MustRegister(anchorQuorumOutboxReplayed)
	prometheus.MustRegister(anchorQuorumOutboxQuarantined)
}

// Recommended alert rules:
//
//   - alert: CertenAnchorQuorumNotRecorded
//     expr: increase(certen_anchor_quorum_written_total[6h]) == 0 and increase(certen_intent_settled_total[6h]) > 0
//     for: 30m
//     labels: {severity: warning}
//     annotations:
//     summary: "Intents are settling but no anchor quorum evidence is being recorded"
//
//   - alert: CertenAnchorQuorumConflict
//     expr: increase(certen_anchor_quorum_conflicts_total[15m]) > 0
//     labels: {severity: critical}
//     annotations:
//     summary: "Two validators describe the same anchor differently — investigate before trusting either"
