// Copyright 2026 Certen Protocol
//
// Staged finality upgrader metrics (RB11, pkg/finality). The upgrader is off the settlement path, so a stuck or broken one
// is invisible unless it reports: these series say how many legs sit at each level per chain, what was appended, what could
// not be built (by named state code) and whether the worker runs at all.
//
//	certen_finality_upgrader_enabled              1 when the upgrader runs, 0 when CERTEN_FINALITY_UPGRADER_ENABLED turned it off
//	certen_finality_legs{chain,level}             settled legs whose chain currently stands at this level (none, included, ...)
//	certen_finality_addenda_appended_total{chain,level}   addenda this validator appended
//	certen_finality_build_failures_total{chain,code}      builds that returned a named state other than finality_pending
//	certen_finality_pending_total{chain,level_reached}    builds that returned finality_pending
//	certen_finality_chain_broken_total{chain}     stored addendum chains that failed VerifyChain (should be 0)
//	certen_finality_status_total{chain,level,state}   builder status rows written, by target level and named state code (or verified)
//	certen_finality_status_write_failures_total{chain}   status rows the database refused (the status table is never authoritative)
//	certen_finality_chain_enabled{chain}          1 when the chain's upgrader and capturers run, 0 when its per-chain switch is off
//	certen_finality_capturer_restarts_total{chain,capturer}   capture loops restarted after a named failure or panic
//	certen_finality_pass_seconds                  duration of one upgrader pass
//	certen_finality_last_pass_unixtime            when the last pass finished (alert when it stops advancing)
package metrics

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	finalityEnabled = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_finality_upgrader_enabled",
		Help: "1 when the staged finality upgrader runs on this validator, 0 when CERTEN_FINALITY_UPGRADER_ENABLED switched it off.",
	})
	finalityLegs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_legs",
		Help: "Settled legs by the finality level their addendum chain stands at, as of the last upgrader pass.",
	}, []string{"chain", "level"})
	finalityAppended = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_addenda_appended_total",
		Help: "Finality addenda this validator appended.",
	}, []string{"chain", "level"})
	finalityBuildFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_build_failures_total",
		Help: "Finality builds that ended in a named state other than finality_pending.",
	}, []string{"chain", "code"})
	finalityPending = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_pending_total",
		Help: "Finality builds that ended in finality_pending (the level reached is proven; the next one is not yet buildable).",
	}, []string{"chain", "level_reached"})
	finalityChainBroken = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_chain_broken_total",
		Help: "Stored addendum chains that failed verification against the leg binding D0 recomputed from the leg's verified Settlement (sequence, previous-hash links, own hashes, one addendum per level, table rows). Should be 0.",
	}, []string{"chain"})
	finalityStatus = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_status_total",
		Help: "Builder status rows written (V2_SPEC_S7 2.7), by chain, target level and named state code (verified when the level is stored).",
	}, []string{"chain", "level", "state"})
	finalityStatusWriteFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_status_write_failures_total",
		Help: "Builder status rows the database refused or that timed out (the status table is never authoritative; the next pass writes it again).",
	}, []string{"chain"})
	finalityChainEnabled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_chain_enabled",
		Help: "1 when the chain's finality upgrader and capturers run on this validator, 0 when its per-chain switch is off.",
	}, []string{"chain"})
	finalityCapturerRestarts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_capturer_restarts_total",
		Help: "Finality capture loops restarted after a named failure or a panic.",
	}, []string{"chain", "capturer"})
	finalityPassSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "certen_finality_pass_seconds",
		Help:    "Duration of one finality upgrader pass.",
		Buckets: prometheus.ExponentialBuckets(0.05, 3, 10),
	})
	finalityLastPass = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_finality_last_pass_unixtime",
		Help: "Unix time the last finality upgrader pass finished.",
	})
)

func chainLabel(chain uint64) string { return strconv.FormatUint(chain, 10) }

// SetFinalityUpgraderEnabled reports whether the upgrader runs.
func SetFinalityUpgraderEnabled(on bool) {
	if on {
		finalityEnabled.Set(1)
		return
	}
	finalityEnabled.Set(0)
}

// SetFinalityLegs reports how many legs stand at a level on a chain.
func SetFinalityLegs(chain uint64, level string, n int) {
	finalityLegs.WithLabelValues(chainLabel(chain), level).Set(float64(n))
}

// IncFinalityAppended counts an appended addendum.
func IncFinalityAppended(chain uint64, level string) {
	finalityAppended.WithLabelValues(chainLabel(chain), level).Inc()
}

// IncFinalityBuildFailure counts a build that ended in a named state.
func IncFinalityBuildFailure(chain uint64, code string) {
	finalityBuildFailures.WithLabelValues(chainLabel(chain), code).Inc()
}

// IncFinalityPending counts a build that ended in finality_pending.
func IncFinalityPending(chain uint64, levelReached string) {
	finalityPending.WithLabelValues(chainLabel(chain), levelReached).Inc()
}

// IncFinalityChainBroken counts a stored chain that failed verification.
func IncFinalityChainBroken(chain uint64) {
	finalityChainBroken.WithLabelValues(chainLabel(chain)).Inc()
}

// IncFinalityStatus counts a status row written for a target level in a named state (or "verified").
func IncFinalityStatus(chain uint64, level, state string) {
	finalityStatus.WithLabelValues(chainLabel(chain), level, state).Inc()
}

// IncFinalityStatusWriteFailure counts a status row that could not be written.
func IncFinalityStatusWriteFailure(chain uint64) {
	finalityStatusWriteFailures.WithLabelValues(chainLabel(chain)).Inc()
}

// SetFinalityChainEnabled reports a chain's per-chain switch.
func SetFinalityChainEnabled(chain uint64, on bool) {
	v := 0.0
	if on {
		v = 1
	}
	finalityChainEnabled.WithLabelValues(chainLabel(chain)).Set(v)
}

// IncFinalityCapturerRestart counts a restarted capture loop.
func IncFinalityCapturerRestart(chain uint64, capturer string) {
	finalityCapturerRestarts.WithLabelValues(chainLabel(chain), capturer).Inc()
}

// ObserveFinalityPass records one finished pass.
func ObserveFinalityPass(d time.Duration, finished time.Time) {
	finalityPassSeconds.Observe(d.Seconds())
	finalityLastPass.Set(float64(finished.Unix()))
}

func registerFinalityMetrics() {
	prometheus.MustRegister(finalityEnabled)
	prometheus.MustRegister(finalityLegs)
	prometheus.MustRegister(finalityAppended)
	prometheus.MustRegister(finalityBuildFailures)
	prometheus.MustRegister(finalityPending)
	prometheus.MustRegister(finalityChainBroken)
	prometheus.MustRegister(finalityStatus)
	prometheus.MustRegister(finalityStatusWriteFailures)
	prometheus.MustRegister(finalityChainEnabled)
	prometheus.MustRegister(finalityCapturerRestarts)
	prometheus.MustRegister(finalityPassSeconds)
	prometheus.MustRegister(finalityLastPass)
}
