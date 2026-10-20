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
		Help: "Stored addendum chains that failed verification against the proof's original digest. Should be 0.",
	}, []string{"chain"})
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
	prometheus.MustRegister(finalityPassSeconds)
	prometheus.MustRegister(finalityLastPass)
}
