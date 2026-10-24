// Copyright 2026 Certen Protocol
//
// Contract-identity capture metrics (RB12 WP-S8-3b, pkg/contractidentity/capture). The capture runs beside the observation and is invisible
// unless it reports; these series say whether it runs, what it holds, what it captured or stated, and what it had to drop.
//
//	certen_contract_identity_capture_enabled                       1 when the capture runs on this validator, 0 when it is off or disabled
//	certen_contract_identity_capture_disabled_total{reason}        named capture-disabled states announced (switch_invalid, setting_invalid, no_durable_store, ...)
//	certen_contract_identity_capture_memory_bytes_budget           the byte budget of the capture working sets (set at start; non-zero while enabled)
//	certen_contract_identity_capture_memory_bytes_in_use           bytes reserved by captures that are running now
//	certen_contract_identity_capture_inflight{chain,station}       captures running now (station attest | settle)
//	certen_contract_identity_capture_total{chain,station,outcome}  finished captures: captured | stated_<reason> | not_attestation | error | panic | conflict
//	certen_contract_identity_capture_dropped_total{chain,station,reason}   triggers not captured: queue_full | memory_budget
//	certen_contract_identity_capture_seconds{chain,station}        wall-clock duration of a capture (the Arbitrum window is 25 s; alert when the p95 passes 15 s)
//
// Alerts that can fire: increase(certen_contract_identity_capture_total{outcome!~"captured|not_attestation"}[1h]) > 0 (a capture ended Stated or
// failed), increase(certen_contract_identity_capture_dropped_total[15m]) > 0, and certen_contract_identity_capture_enabled == 0 on a validator
// that was configured to capture. ContractIdentityHealth is the same state as a JSON-ready snapshot for /health/detailed.
package metrics

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	ciOnce sync.Once

	ciEnabled = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_contract_identity_capture_enabled",
		Help: "1 when the S8 contract-identity capture runs on this validator, 0 when it is off or disabled by a named state.",
	})
	ciDisabled = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_contract_identity_capture_disabled_total",
		Help: "Named contract-identity capture-disabled states announced, by reason (never the value of a setting).",
	}, []string{"reason"})
	ciBudget = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_contract_identity_capture_memory_bytes_budget",
		Help: "Bytes the running contract-identity captures may reserve in all.",
	})
	ciInUse = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_contract_identity_capture_memory_bytes_in_use",
		Help: "Bytes reserved by contract-identity captures that are running now.",
	})
	ciInflight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "certen_contract_identity_capture_inflight",
		Help: "Contract-identity captures running now, by chain and station.",
	}, []string{"chain", "station"})
	ciTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_contract_identity_capture_total",
		Help: "Finished contract-identity captures by chain, station and outcome.",
	}, []string{"chain", "station", "outcome"})
	ciDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_contract_identity_capture_dropped_total",
		Help: "Contract-identity capture triggers that were not captured, by reason.",
	}, []string{"chain", "station", "reason"})
	ciSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "certen_contract_identity_capture_seconds",
		Help:    "Wall-clock duration of a contract-identity capture.",
		Buckets: []float64{0.5, 1, 2, 4, 8, 12, 15, 20, 25, 40, 60, 120},
	}, []string{"chain", "station"})

	ciHealth struct {
		mu       sync.Mutex
		known    bool
		enabled  bool
		reason   string
		setting  string
		budget   int64
		inUse    int64
		captured uint64
		stated   uint64
		dropped  uint64
	}
)

func ciRegister() {
	ciOnce.Do(func() {
		for _, c := range []prometheus.Collector{ciEnabled, ciDisabled, ciBudget, ciInUse, ciInflight, ciTotal, ciDropped, ciSeconds} {
			prometheus.MustRegister(c)
		}
	})
}

// SetContractIdentityCapture reports the switch: on with its byte budget, or off (reason "switch_off" for the operator's off).
func SetContractIdentityCapture(on bool, budgetBytes int64) {
	ciRegister()
	ciHealth.mu.Lock()
	defer ciHealth.mu.Unlock()
	ciHealth.known, ciHealth.enabled, ciHealth.budget = true, on, budgetBytes
	if on {
		ciEnabled.Set(1)
		ciBudget.Set(float64(budgetBytes))
		ciHealth.reason, ciHealth.setting = "", ""
		return
	}
	ciEnabled.Set(0)
	ciBudget.Set(0)
	ciHealth.reason, ciHealth.setting = "switch_off", ""
}

// AnnounceContractIdentityCaptureDisabled records a named disabled state: the counter, the gauge at 0 and the health block. setting is the
// NAME of the variable that caused it (never its value), "" when no setting did.
func AnnounceContractIdentityCaptureDisabled(reason, setting string) {
	ciRegister()
	ciDisabled.WithLabelValues(reason).Inc()
	ciEnabled.Set(0)
	ciBudget.Set(0)
	ciHealth.mu.Lock()
	defer ciHealth.mu.Unlock()
	ciHealth.known, ciHealth.enabled, ciHealth.reason, ciHealth.setting = true, false, reason, setting
}

func ciChainLabel(c uint64) string { return strconv.FormatUint(c, 10) }

// ContractIdentityCaptureInflight adds delta (+1 at start, -1 at end) to the captures running now.
func ContractIdentityCaptureInflight(chain uint64, station string, delta float64) {
	ciRegister()
	ciInflight.WithLabelValues(ciChainLabel(chain), station).Add(delta)
}

// ContractIdentityMemoryInUse sets the bytes reserved now.
func ContractIdentityMemoryInUse(bytes int64) {
	ciRegister()
	ciInUse.Set(float64(bytes))
	ciHealth.mu.Lock()
	ciHealth.inUse = bytes
	ciHealth.mu.Unlock()
}

// ObserveContractIdentityCapture records one finished capture.
func ObserveContractIdentityCapture(chain uint64, station, outcome string, d time.Duration) {
	ciRegister()
	ciTotal.WithLabelValues(ciChainLabel(chain), station, outcome).Inc()
	ciSeconds.WithLabelValues(ciChainLabel(chain), station).Observe(d.Seconds())
	ciHealth.mu.Lock()
	defer ciHealth.mu.Unlock()
	if outcome == "captured" {
		ciHealth.captured++
	} else {
		ciHealth.stated++
	}
}

// ContractIdentityCaptureDropped records a trigger that was not captured.
func ContractIdentityCaptureDropped(chain uint64, station, reason string) {
	ciRegister()
	ciDropped.WithLabelValues(ciChainLabel(chain), station, reason).Inc()
	ciHealth.mu.Lock()
	ciHealth.dropped++
	ciHealth.mu.Unlock()
}

// ContractIdentityHealth is the contract-identity capture block of /health/detailed: JSON-ready and secret-free. Layout:
//
//	{"capture_enabled": bool (absent until the start has reported), "capture_disabled_reason": string, "capture_disabled_setting": string (a variable NAME),
//	 "memory_bytes_budget": n, "memory_bytes_in_use": n, "captured": n, "stated_or_failed": n, "dropped": n}
func ContractIdentityHealth() map[string]any {
	ciHealth.mu.Lock()
	defer ciHealth.mu.Unlock()
	out := map[string]any{}
	if ciHealth.known {
		out["capture_enabled"] = ciHealth.enabled
	}
	if ciHealth.reason != "" {
		out["capture_disabled_reason"] = ciHealth.reason
	}
	if ciHealth.setting != "" {
		out["capture_disabled_setting"] = ciHealth.setting
	}
	out["memory_bytes_budget"] = ciHealth.budget
	out["memory_bytes_in_use"] = ciHealth.inUse
	out["captured"] = ciHealth.captured
	out["stated_or_failed"] = ciHealth.stated
	out["dropped"] = ciHealth.dropped
	return out
}
