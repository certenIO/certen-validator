// Copyright 2026 Certen Protocol
//
// Standing evidence checks.
//
// # WHY THESE EXIST
//
// Every defect in the 2026-09-15..18 anchor-quorum work was a claim nothing checked, and every one was
// found because a person decided to look: a layer-5 row binding a root no transaction contained, a
// Transaction Center reading a per-validator shadow row, a migration that merged and deployed and did
// nothing, a fleet whose catalog had moved ahead of its database. None of them failed a request. None of
// them logged an error.
//
// The counters in anchor_quorum_metrics.go report what the writer DID. These report what is WRONG, on a
// timer, whether or not anything is happening:
//
//	certen_evidence_settled_without_canonical_row   intents that settled with no canonical anchor
//	certen_evidence_contradicted_layer5_rows        standing layer-5 rows their own anchor contradicts
//	certen_evidence_schema_behind_binary            1 when the database is older than this binary's catalog
//	certen_evidence_check_errors_total              the checks themselves failing (a zero gauge is not proof)
//
// The last one matters as much as the others. A gauge stuck at 0 because the query errored looks exactly
// like a healthy system, which is the failure mode this whole file exists to end.
//
// All three gauges should be 0. Page on any of them, and on check_errors_total climbing.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	evidenceSettledWithoutCanonical = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "evidence",
		Name:      "settled_without_canonical_row",
		Help:      "Intents settled in the last hour with no canonical anchor row (bundle_id IS NOT NULL). Should be 0.",
	})
	evidenceContradictedLayer5 = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "evidence",
		Name:      "contradicted_layer5_rows",
		Help:      "Standing layer-5 rows naming a root other than the canonical anchor their intent was published in. Should be 0.",
	})
	evidenceSchemaBehindBinary = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "evidence",
		Name:      "schema_behind_binary",
		Help:      "1 when the database schema is older than this binary's migration catalog; a restart would fail. Should be 0.",
	})
	evidenceCheckErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "certen",
		Subsystem: "evidence",
		Name:      "check_errors_total",
		Help:      "Evidence checks that could not run. A zero gauge is only meaningful while this is flat.",
	})
)

// SetSettledWithoutCanonicalRow reports intents that settled with no canonical anchor.
func SetSettledWithoutCanonicalRow(n int) { evidenceSettledWithoutCanonical.Set(float64(n)) }

// SetContradictedLayer5Rows reports standing layer-5 rows their own anchor contradicts.
func SetContradictedLayer5Rows(n int) { evidenceContradictedLayer5.Set(float64(n)) }

// SetSchemaBehindBinary reports whether the database is older than this binary's catalog.
func SetSchemaBehindBinary(behind bool) {
	if behind {
		evidenceSchemaBehindBinary.Set(1)
		return
	}
	evidenceSchemaBehindBinary.Set(0)
}

// IncEvidenceCheckError records a check that could not run.
func IncEvidenceCheckError() { evidenceCheckErrors.Inc() }

func registerEvidenceMonitorMetrics() {
	prometheus.MustRegister(evidenceSettledWithoutCanonical)
	prometheus.MustRegister(evidenceContradictedLayer5)
	prometheus.MustRegister(evidenceSchemaBehindBinary)
	prometheus.MustRegister(evidenceCheckErrors)
}
