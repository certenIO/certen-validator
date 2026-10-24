// Copyright 2026 Certen Protocol
//
// Staged finality upgrader metrics (RB11, pkg/finality). The upgrader is off the settlement path, so a stuck or broken one
// is invisible unless it reports: these series say how many legs sit at each level per chain, what was appended, what could
// not be built (by named state code) and whether the worker runs at all.
//
//	certen_finality_upgrader_enabled              1 when the upgrader runs, 0 when CERTEN_FINALITY_UPGRADER_ENABLED turned it off
//	certen_finality_legs{chain,level}             settled legs whose chain currently stands at this level (none, included, ...)
//	certen_finality_legs_without_settlement{chain}   legs whose newest bundle holds no execution proof (quiet; read again only when a newer bundle appears)
//	certen_finality_unrecorded_settlements        legs attempted in the last pass served before their proof row recorded the settlement
//	certen_finality_legs_no_prover{chain}         listed legs of a chain with no registered prover (not attempted)
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
//
// The capture side (V2_SPEC_S7 2.8) and the operator-facing health block add:
//
//	certen_finality_capture_lag_blocks{chain,capturer}    parent-chain blocks between the L1 head and the last block a capture loop finished
//	certen_finality_last_captured_block{chain,capturer}   the last parent-chain block a capture loop finished
//	certen_finality_last_append_unixtime{chain}   when this validator last appended an addendum on the chain
//	certen_finality_capture_bytes_total{chain}    bytes written to the insert-only capture store
//	certen_finality_upgrader_disabled_total{chain,env}    named finality_upgrader_disabled states announced (chain 0 = the global switch)
//	certen_finality_provider_throttled_total{provider_host}   provider answers that were throttled (HTTP 429) and backed off; host name only
//	certen_finality_capture_refused_total{chain,code}     captures refused by a named state (a byte budget, a window miss ...)
//
// FinalityHealth is the same state as a JSON-ready snapshot for the /health/detailed endpoint.
package metrics

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	finalityLegsWithoutSettlement = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_legs_without_settlement",
		Help: "Legs whose L6 evidence is unavailable (finality_included_unavailable): the newest bundle holds no execution proof (component 5; not read again until the proof has a newer bundle) or an execution proof without its block header (read again every HeaderRetry until its header is reconstructed), held back quietly, as of the last upgrader pass.",
	}, []string{"chain"})
	finalityLegacyHeaders = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_legacy_headers",
		Help: "Legacy legs (stored execution proof without block_header_rlp) by chain and reconstruction state as of the last reconstruction tick: pending (not yet judged), reconstructed (header stored and the leg's proofs verify), unserved (no configured provider served the block; asked again with backoff) or invalid (the header is the block's own and the stored component contradicts it, or the component cannot be read).",
	}, []string{"chain", "state"})
	finalityLegacyScanFailing = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_legacy_scan_failing",
		Help: "1 while the last scan of the legacy-leg list of a chain failed (the leg counts of certen_finality_legacy_headers are then the legs known before it, and zeros mean nothing), 0 after a scan that succeeded.",
	}, []string{"chain"})
	finalityLegacyUnwired = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_legacy_unwired",
		Help: "1 when the legacy-header reconstruction loop of a chain could not be registered at startup (the validator runs without it; its legacy legs stay finality_included_unavailable{no_block_header}), 0 when it is registered.",
	}, []string{"chain"})
	finalityLegsWithoutProver = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_legs_no_prover",
		Help: "Listed legs of a chain for which no finality prover is registered (counted as no_prover and not attempted), as of the last complete upgrader pass.",
	}, []string{"chain"})
	finalityUnrecordedSettlements = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_finality_unrecorded_settlements",
		Help: "Legs attempted in the last upgrader pass whose settlement evidence was served while the proof row has no settlement_tx_hash or settlement_block_number yet (the check against the recorded settlement could not be made).",
	})
	finalityAppended = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_addenda_appended_total",
		Help: "Finality addenda this validator appended.",
	}, []string{"chain", "level"})
	finalityBuildFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_build_failures_total",
		Help: "Finality builds that ended in a named state other than finality_pending.",
	}, []string{"chain", "code"})
	finalityBuildHeld = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_build_held_total",
		Help: "Finality asks held by the environment instead of failed (RB12-GO-INT F17): a state that is a fact about this process or its capture store, such as l1_capture_gap, by chain and state code. A held leg is asked again at the bounded poll and is not counted in certen_finality_build_failures_total.",
	}, []string{"chain", "code"})
	finalityCaptureForeignInboxTx = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_capture_foreign_inbox_tx_total",
		Help: "Transactions sent to the batch inbox by a key that is not the SystemConfig batcher at that block, skipped by the capture (RB12-GO-INT D2), by chain.",
	}, []string{"chain"})
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
	finalityCaptureLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_capture_lag_blocks",
		Help: "Parent-chain blocks between the L1 head and the last block the capture loop finished (the provider proof window is about 8 blocks on Tenderly and at most 100 elsewhere).",
	}, []string{"chain", "capturer"})
	finalityLastCaptured = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_last_captured_block",
		Help: "The last parent-chain block the capture loop finished.",
	}, []string{"chain", "capturer"})
	finalityLastAppend = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_finality_last_append_unixtime",
		Help: "Unix time this validator last appended a finality addendum on the chain.",
	}, []string{"chain"})
	finalityCaptureBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_capture_bytes_total",
		Help: "Bytes written to the insert-only finality capture store.",
	}, []string{"chain"})
	finalityUpgraderDisabled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_upgrader_disabled_total",
		Help: "Named finality_upgrader_disabled states announced, by chain (0 for the global switch) and the setting that caused them.",
	}, []string{"chain", "env"})
	finalityProviderThrottled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_provider_throttled_total",
		Help: "Provider answers throttled with HTTP 429 and backed off, by provider host name only.",
	}, []string{"provider_host"})
	finalityCaptureRefused = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_capture_refused_total",
		Help: "Captures refused by a named state (a byte budget, a missed provider window ...), by chain and state code.",
	}, []string{"chain", "code"})
	finalityHeapInUse = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_finality_heap_inuse_bytes",
		Help: "Go heap in use by this validator process, refreshed every few seconds while the upgrader runs, independent of its passes (the figure the finality memory gate compares with its budget).",
	})
	finalityMemoryBudget = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_finality_memory_budget_bytes",
		Help: "CERTEN_FINALITY_MEMORY_BUDGET_BYTES: the bytes of in-flight working set the finality builders may hold at once in this process.",
	})
	finalityMemoryReserved = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_finality_memory_reserved_bytes",
		Help: "Bytes of in-flight working set currently reserved by finality builders (never above the budget).",
	})
	finalityMemoryRefused = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_finality_memory_refused_total",
		Help: "Reservations or leg attempts refused by the finality memory budget (named state finality_memory_budget_exceeded), by chain and what was refused (a load, or an attempt held back by the heap gate).",
	}, []string{"chain", "what"})
)

func chainLabel(chain uint64) string { return strconv.FormatUint(chain, 10) }

// ---- the health snapshot ----

// finalityNow is the clock of last_append_unixtime (tests replace it).
var finalityNow = time.Now

// finalityChainHealth is what the process knows of one chain's finality wiring.
type finalityChainHealth struct {
	enabledKnown   bool
	enabled        bool
	disabledReason string
	prefixReason   string            // the named states of an archive backfill switched off by a bad setting (RB12-TRAIN3-INT)
	indexReason    string            // the named state of a capture index switched off by a bad setting (RB12-INDEX-FIX D2)
	captured       map[string]uint64 // capturer -> last captured parent-chain block
	lag            map[string]uint64 // capturer -> lag in parent-chain blocks
	legs           map[string]int    // level -> settled legs standing there
	lastAppend     int64
	restarts       int

	legacy            map[string]int // legacy legs by reconstruction state (RB12-LEGACY-191)
	legacyScanKnown   bool
	legacyScanFailing bool
	legacyUnwired     string
}

var finalityHealth = struct {
	mu              sync.Mutex
	upgraderKnown   bool
	upgraderEnabled bool
	// upgraderReason is the named state that switched the whole upgrader off (empty while it is on or not yet reported).
	upgraderReason string
	chains         map[uint64]*finalityChainHealth
}{chains: map[uint64]*finalityChainHealth{}}

// finalityChain returns the chain's record; the caller holds finalityHealth.mu.
func finalityChain(chain uint64) *finalityChainHealth {
	c := finalityHealth.chains[chain]
	if c == nil {
		c = &finalityChainHealth{captured: map[string]uint64{}, lag: map[string]uint64{}, legs: map[string]int{}, legacy: map[string]int{}}
		finalityHealth.chains[chain] = c
	}
	return c
}

// FinalityHealth is the staged-finality block of /health/detailed: JSON-ready, secret-free (chain ids, counts, block numbers and
// the name of the setting that switched something off, never a URL or a key). Layout:
//
//	{"upgrader_enabled": bool, "upgrader_disabled_reason": string (only while the whole upgrader is off: the named state, e.g. config_invalid with the variable and entry),
//	 "chains": {"<chain id>": {"enabled": bool (once known), "disabled_reason": string, "last_captured_block": n,
//	            "capture_lag_blocks": n, "pending_legs_by_level": {"<level>": n}, "last_append_unixtime": n,
//	            "capturer_restarts": n, "capturers": {"<name>": {"last_captured_block": n, "capture_lag_blocks": n}},
//	            "legacy_headers": {"<state>": n, "scan_failing": bool, "unwired": string}}}}
//
// legacy_headers (RB12-LEGACY-191) is present once the legacy-header loop of the chain has reported: its legs by state (pending,
// reconstructed, unserved, invalid), whether the last scan of the leg list failed, and why the loop is not registered (absent when it is).
//
// last_captured_block and capture_lag_blocks of a chain are the highest block and the largest lag over its capture loops (the
// loop furthest behind decides the alert); the per-loop values are under capturers. upgrader_enabled is absent until the
// launcher has reported the switch, because "not reported" is not "off".
func FinalityHealth() map[string]any {
	finalityHealth.mu.Lock()
	defer finalityHealth.mu.Unlock()
	out := map[string]any{}
	if finalityHealth.upgraderKnown {
		out["upgrader_enabled"] = finalityHealth.upgraderEnabled
	}
	if finalityHealth.upgraderReason != "" {
		out["upgrader_disabled_reason"] = finalityHealth.upgraderReason
	}
	chains := map[string]any{}
	ids := make([]uint64, 0, len(finalityHealth.chains))
	for id := range finalityHealth.chains {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		c := finalityHealth.chains[id]
		m := map[string]any{
			"disabled_reason":      c.disabledReason,
			"last_append_unixtime": c.lastAppend,
			"capturer_restarts":    c.restarts,
		}
		if c.indexReason != "" {
			m["index_disabled_reason"] = c.indexReason
		}
		if c.prefixReason != "" {
			m["prefix_disabled_reason"] = c.prefixReason
		}
		if c.enabledKnown {
			m["enabled"] = c.enabled
		}
		var top, maxLag uint64
		per := map[string]any{}
		for name, b := range c.captured {
			if b > top {
				top = b
			}
			per[name] = map[string]any{"last_captured_block": b, "capture_lag_blocks": c.lag[name]}
		}
		for name, l := range c.lag {
			if l > maxLag {
				maxLag = l
			}
			if _, ok := per[name]; !ok {
				per[name] = map[string]any{"last_captured_block": uint64(0), "capture_lag_blocks": l}
			}
		}
		m["last_captured_block"] = top
		m["capture_lag_blocks"] = maxLag
		m["capturers"] = per
		legs := make(map[string]int, len(c.legs))
		for lvl, n := range c.legs {
			legs[lvl] = n
		}
		m["pending_legs_by_level"] = legs
		if len(c.legacy) > 0 || c.legacyScanKnown || c.legacyUnwired != "" {
			lh := map[string]any{}
			for state, n := range c.legacy {
				lh[state] = n
			}
			if c.legacyScanKnown {
				lh["scan_failing"] = c.legacyScanFailing
			}
			if c.legacyUnwired != "" {
				lh["unwired"] = c.legacyUnwired
			}
			m["legacy_headers"] = lh
		}
		chains[chainLabel(id)] = m
	}
	out["chains"] = chains
	return out
}

// SetFinalityUpgraderEnabled reports whether the upgrader runs.
func SetFinalityUpgraderEnabled(on bool) {
	finalityHealth.mu.Lock()
	finalityHealth.upgraderKnown, finalityHealth.upgraderEnabled = true, on
	if on {
		finalityHealth.upgraderReason = ""
	}
	finalityHealth.mu.Unlock()
	if on {
		finalityEnabled.Set(1)
		return
	}
	finalityEnabled.Set(0)
}

// SetFinalityUpgraderDisabledReason records, for the health block, the named state that switched the whole upgrader off (the state's
// text: its code, the setting and the entry position, never a URL or a key). Reporting the upgrader on clears it.
func SetFinalityUpgraderDisabledReason(reason string) {
	finalityHealth.mu.Lock()
	finalityHealth.upgraderReason = reason
	finalityHealth.mu.Unlock()
}

// SetFinalityLegs reports how many legs stand at a level on a chain.
func SetFinalityLegs(chain uint64, level string, n int) {
	finalityLegs.WithLabelValues(chainLabel(chain), level).Set(float64(n))
	finalityHealth.mu.Lock()
	finalityChain(chain).legs[level] = n
	finalityHealth.mu.Unlock()
}

// SetFinalityLegsWithoutSettlement reports how many legs of a chain are held back because their newest bundle holds no execution proof.
func SetFinalityLegsWithoutSettlement(chain uint64, n int) {
	finalityLegsWithoutSettlement.WithLabelValues(chainLabel(chain)).Set(float64(n))
}

// SetFinalityLegacyHeaders reports how many legacy legs of a chain stand in one reconstruction state.
func SetFinalityLegacyHeaders(chain uint64, state string, n int) {
	finalityLegacyHeaders.WithLabelValues(chainLabel(chain), state).Set(float64(n))
	finalityHealth.mu.Lock()
	finalityChain(chain).legacy[state] = n
	finalityHealth.mu.Unlock()
}

// SetFinalityLegacyScan reports whether the last scan of a chain's legacy-leg list failed.
func SetFinalityLegacyScan(chain uint64, failing bool) {
	v := 0.0
	if failing {
		v = 1
	}
	finalityLegacyScanFailing.WithLabelValues(chainLabel(chain)).Set(v)
	finalityHealth.mu.Lock()
	c := finalityChain(chain)
	c.legacyScanKnown, c.legacyScanFailing = true, failing
	finalityHealth.mu.Unlock()
}

// SetFinalityLegacyUnwired reports why a chain's legacy-header loop is not registered ("" when it is).
func SetFinalityLegacyUnwired(chain uint64, reason string) {
	v := 0.0
	if reason != "" {
		v = 1
	}
	finalityLegacyUnwired.WithLabelValues(chainLabel(chain)).Set(v)
	finalityHealth.mu.Lock()
	finalityChain(chain).legacyUnwired = reason
	finalityHealth.mu.Unlock()
}

// SetFinalityUnrecordedSettlements reports how many legs of the last pass were served before their proof row recorded the settlement.
func SetFinalityUnrecordedSettlements(n int) { finalityUnrecordedSettlements.Set(float64(n)) }

// SetFinalityLegsWithoutProver reports how many listed legs of a chain have no registered prover.
func SetFinalityLegsWithoutProver(chain uint64, n int) {
	finalityLegsWithoutProver.WithLabelValues(chainLabel(chain)).Set(float64(n))
}

// IncFinalityAppended counts an appended addendum and records when it happened.
func IncFinalityAppended(chain uint64, level string) {
	finalityAppended.WithLabelValues(chainLabel(chain), level).Inc()
	now := finalityNow().Unix()
	finalityLastAppend.WithLabelValues(chainLabel(chain)).Set(float64(now))
	finalityHealth.mu.Lock()
	finalityChain(chain).lastAppend = now
	finalityHealth.mu.Unlock()
}

// IncFinalityCaptureForeignInboxTx counts a batch-inbox transaction the capture skipped because the batcher did not send it.
func IncFinalityCaptureForeignInboxTx(chain uint64) {
	finalityCaptureForeignInboxTx.WithLabelValues(chainLabel(chain)).Inc()
}

// IncFinalityBuildHeld counts an ask held by the environment (a state of the environment class, see pkg/finality/state_class.go).
func IncFinalityBuildHeld(chain uint64, code string) {
	finalityBuildHeld.WithLabelValues(chainLabel(chain), code).Inc()
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
	finalityHealth.mu.Lock()
	c := finalityChain(chain)
	c.enabledKnown, c.enabled = true, on
	finalityHealth.mu.Unlock()
}

// SetFinalityChainDisabledReason records, for the health block, why a chain's finality is off: the named state's code and the
// setting that caused it (never a URL or a key). An empty reason clears it.
func SetFinalityChainDisabledReason(chain uint64, reason string) {
	finalityHealth.mu.Lock()
	finalityChain(chain).disabledReason = reason
	finalityHealth.mu.Unlock()
}

// SetFinalityChainIndexDisabledReason records, for the health block, the named state of a capture index that a bad setting switched off
// (the chain itself keeps running with the window reader).
func SetFinalityChainIndexDisabledReason(chain uint64, reason string) {
	finalityHealth.mu.Lock()
	finalityChain(chain).indexReason = reason
	finalityHealth.mu.Unlock()
}

// SetFinalityChainPrefixDisabledReason records, for the health block, the named states of an archive backfill that a bad setting switched off
// on the chain (the chain itself keeps running).
func SetFinalityChainPrefixDisabledReason(chain uint64, reason string) {
	finalityHealth.mu.Lock()
	finalityChain(chain).prefixReason = reason
	finalityHealth.mu.Unlock()
}

// IncFinalityCapturerRestart counts a restarted capture loop.
func IncFinalityCapturerRestart(chain uint64, capturer string) {
	finalityCapturerRestarts.WithLabelValues(chainLabel(chain), capturer).Inc()
	finalityHealth.mu.Lock()
	finalityChain(chain).restarts++
	finalityHealth.mu.Unlock()
}

// SetFinalityCaptureLag reports how many parent-chain blocks a capture loop is behind the L1 head.
func SetFinalityCaptureLag(chain uint64, capturer string, lag uint64) {
	finalityCaptureLag.WithLabelValues(chainLabel(chain), capturer).Set(float64(lag))
	finalityHealth.mu.Lock()
	finalityChain(chain).lag[capturer] = lag
	finalityHealth.mu.Unlock()
}

// SetFinalityLastCapturedBlock reports the last parent-chain block a capture loop finished.
func SetFinalityLastCapturedBlock(chain uint64, capturer string, block uint64) {
	finalityLastCaptured.WithLabelValues(chainLabel(chain), capturer).Set(float64(block))
	finalityHealth.mu.Lock()
	finalityChain(chain).captured[capturer] = block
	finalityHealth.mu.Unlock()
}

// AddFinalityCaptureBytes counts bytes written to the capture store; a non-positive n adds nothing.
func AddFinalityCaptureBytes(chain uint64, n int) {
	if n <= 0 {
		return
	}
	finalityCaptureBytes.WithLabelValues(chainLabel(chain)).Add(float64(n))
}

// IncFinalityUpgraderDisabled counts one announced finality_upgrader_disabled state; chain 0 is the global switch, env the
// setting that caused it.
func IncFinalityUpgraderDisabled(chain uint64, env string) {
	finalityUpgraderDisabled.WithLabelValues(chainLabel(chain), env).Inc()
}

// providerHostLabel reduces a provider URL (or a bare host) to its host name: no scheme, credentials, port, path or query, so
// the label can never carry an API key.
func providerHostLabel(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	if !strings.Contains(raw, "://") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "unknown"
	}
	return strings.ToLower(u.Hostname())
}

// IncFinalityProviderThrottled counts a throttled (HTTP 429) provider answer. Only the host name becomes a label, whatever the
// caller passes.
func IncFinalityProviderThrottled(host string) {
	finalityProviderThrottled.WithLabelValues(providerHostLabel(host)).Inc()
}

// IncFinalityCaptureRefused counts a capture refused by a named state.
func IncFinalityCaptureRefused(chain uint64, code string) {
	finalityCaptureRefused.WithLabelValues(chainLabel(chain), code).Inc()
}

// SetFinalityHeap reports the process heap in use, the memory budget and the bytes currently reserved against it.
func SetFinalityHeap(heapInUse uint64, budget, reserved int64) {
	finalityHeapInUse.Set(float64(heapInUse))
	finalityMemoryBudget.Set(float64(budget))
	finalityMemoryReserved.Set(float64(reserved))
}

// SetFinalityMemoryReserved reports the bytes currently reserved against the memory budget; the budget calls it on every reservation and release.
func SetFinalityMemoryReserved(reserved int64) {
	finalityMemoryReserved.Set(float64(reserved))
}

// IncFinalityMemoryRefused counts a reservation (or an attempt) refused by the memory budget; chain 0 is a refusal about no chain.
func IncFinalityMemoryRefused(chain uint64, what string) {
	finalityMemoryRefused.WithLabelValues(chainLabel(chain), what).Inc()
}

// ObserveFinalityPass records one finished pass.
func ObserveFinalityPass(d time.Duration, finished time.Time) {
	finalityPassSeconds.Observe(d.Seconds())
	finalityLastPass.Set(float64(finished.Unix()))
}

func registerFinalityMetrics() {
	prometheus.MustRegister(finalityEnabled)
	prometheus.MustRegister(finalityLegs)
	prometheus.MustRegister(finalityLegsWithoutSettlement)
	prometheus.MustRegister(finalityLegsWithoutProver)
	prometheus.MustRegister(finalityLegacyHeaders)
	prometheus.MustRegister(finalityLegacyScanFailing)
	prometheus.MustRegister(finalityLegacyUnwired)
	prometheus.MustRegister(finalityUnrecordedSettlements)
	prometheus.MustRegister(finalityAppended)
	prometheus.MustRegister(finalityBuildFailures)
	prometheus.MustRegister(finalityBuildHeld)
	prometheus.MustRegister(finalityCaptureForeignInboxTx)
	prometheus.MustRegister(finalityPending)
	prometheus.MustRegister(finalityChainBroken)
	prometheus.MustRegister(finalityStatus)
	prometheus.MustRegister(finalityStatusWriteFailures)
	prometheus.MustRegister(finalityChainEnabled)
	prometheus.MustRegister(finalityCapturerRestarts)
	prometheus.MustRegister(finalityPassSeconds)
	prometheus.MustRegister(finalityLastPass)
	prometheus.MustRegister(finalityCaptureLag)
	prometheus.MustRegister(finalityLastCaptured)
	prometheus.MustRegister(finalityLastAppend)
	prometheus.MustRegister(finalityCaptureBytes)
	prometheus.MustRegister(finalityUpgraderDisabled)
	prometheus.MustRegister(finalityProviderThrottled)
	prometheus.MustRegister(finalityCaptureRefused)
	prometheus.MustRegister(finalityHeapInUse)
	prometheus.MustRegister(finalityMemoryBudget)
	prometheus.MustRegister(finalityMemoryReserved)
	prometheus.MustRegister(finalityMemoryRefused)
	registerFinalityGapMetrics()
	registerFinalitySpineMetrics()
	registerFinalityPrefixMetrics()
}
