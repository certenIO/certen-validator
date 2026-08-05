// Copyright 2026 Certen Protocol
//
// Discovery liveness metrics.
//
// # WHY THESE EXIST
//
// On 2026-08-05 every validator in the fleet stopped discovering intents and nothing reported
// it. ACCUMULATE_URL pointed at a port that had stopped serving, so GetLatestBlock failed on
// the FIRST line of every 5-second tick, no blocks were queued, and the watermark froze. The
// containers stayed "healthy", the consensus layer kept running, and the only trace was one
// log line per tick that nobody was reading. It was found by accident, hours later, while
// chasing an unrelated error.
//
// The single number that would have caught it immediately is "how long since the watermark
// last moved". Everything here exists to make that number visible.

package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	discoveryWatermark = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "discovery",
		Name:      "watermark_height",
		Help:      "Highest contiguously-processed Accumulate block",
	})

	discoveryChainHead = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "discovery",
		Name:      "chain_head",
		Help:      "Latest Accumulate height seen by the most recent successful poll (0 = no poll has ever succeeded)",
	})

	discoveryLagBlocks = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "discovery",
		Name:      "lag_blocks",
		Help:      "chain_head - watermark. Large but shrinking is a node catching up; see seconds_since_advance to tell that from a dead one",
	})

	discoverySecondsSinceAdvance = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "discovery",
		Name:      "seconds_since_advance",
		Help:      "Seconds since the watermark last moved. THE alerting signal: a stalled watermark means no intent can be discovered",
	})

	discoveryStalled = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "discovery",
		Name:      "stalled",
		Help:      "1 when the watermark has not advanced within the stall threshold, 0 otherwise",
	})

	discoveryPollFailing = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "certen",
		Subsystem: "discovery",
		Name:      "poll_failing",
		Help:      "1 when the last poll of the Accumulate head returned an error. Distinguishes an outage from a genuinely idle chain",
	})
)

// SetDiscoveryStatus publishes one sample of discovery liveness.
func SetDiscoveryStatus(watermark, chainHead, lagBlocks uint64, secondsSinceAdvance float64, stalled, pollFailing bool) {
	discoveryWatermark.Set(float64(watermark))
	discoveryChainHead.Set(float64(chainHead))
	discoveryLagBlocks.Set(float64(lagBlocks))
	discoverySecondsSinceAdvance.Set(secondsSinceAdvance)
	discoveryStalled.Set(boolGauge(stalled))
	discoveryPollFailing.Set(boolGauge(pollFailing))
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// registerDiscoveryMetrics is called from RegisterMetrics.
func registerDiscoveryMetrics() {
	prometheus.MustRegister(discoveryWatermark)
	prometheus.MustRegister(discoveryChainHead)
	prometheus.MustRegister(discoveryLagBlocks)
	prometheus.MustRegister(discoverySecondsSinceAdvance)
	prometheus.MustRegister(discoveryStalled)
	prometheus.MustRegister(discoveryPollFailing)
}

// Recommended alert rules:
//
//   - alert: CertenDiscoveryStalled
//     expr: certen_discovery_stalled == 1
//     for: 2m
//     labels: {severity: critical}
//     annotations:
//     summary: "Intent discovery stalled on {{ $labels.instance }}"
//     description: "Watermark has not advanced for {{ $value }}s — no intent can be discovered"
//
//   - alert: CertenDiscoveryPollFailing
//     expr: certen_discovery_poll_failing == 1
//     for: 1m
//     labels: {severity: critical}
//     annotations:
//     summary: "Cannot reach Accumulate from {{ $labels.instance }}"
//     description: "The head poll is erroring; check ACCUMULATE_URL"
//
//   - alert: CertenDiscoveryFallingBehind
//     expr: certen_discovery_lag_blocks > 5000
//     for: 15m
//     labels: {severity: warning}
//     annotations:
//     summary: "Discovery is behind by {{ $value }} blocks"
