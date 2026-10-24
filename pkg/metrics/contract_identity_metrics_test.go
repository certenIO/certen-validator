// Copyright 2026 Certen Protocol

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func ciValue(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range fams {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for k, v := range labels {
				found := false
				for _, l := range m.GetLabel() {
					found = found || (l.GetName() == k && l.GetValue() == v)
				}
				match = match && found
			}
			if !match {
				continue
			}
			switch {
			case m.GetHistogram() != nil:
				return float64(m.GetHistogram().GetSampleCount()), true
			case m.GetCounter() != nil:
				return m.GetCounter().GetValue(), true
			case m.GetGauge() != nil:
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func TestContractIdentityMetricsAreNonZeroWhenTheyShouldBe(t *testing.T) {
	SetContractIdentityCapture(true, 12345)
	if v, ok := ciValue(t, "certen_contract_identity_capture_enabled", nil); !ok || v != 1 {
		t.Fatalf("enabled = %v %v", v, ok)
	}
	if v, ok := ciValue(t, "certen_contract_identity_capture_memory_bytes_budget", nil); !ok || v != 12345 {
		t.Fatalf("budget = %v %v", v, ok)
	}
	ContractIdentityCaptureInflight(5, "attest", 1)
	ContractIdentityMemoryInUse(777)
	ObserveContractIdentityCapture(5, "attest", "captured", 3*time.Second)
	ObserveContractIdentityCapture(5, "attest", "stated_state_unavailable", time.Second)
	ContractIdentityCaptureDropped(5, "attest", "queue_full")
	for name, want := range map[string]float64{
		"certen_contract_identity_capture_inflight":            1,
		"certen_contract_identity_capture_memory_bytes_in_use": 777,
		"certen_contract_identity_capture_dropped_total":       1,
		"certen_contract_identity_capture_seconds":             2,
	} {
		if v, ok := ciValue(t, name, nil); !ok || v != want {
			t.Fatalf("%s = %v %v, want %v", name, v, ok, want)
		}
	}
	if v, _ := ciValue(t, "certen_contract_identity_capture_total", map[string]string{"outcome": "stated_state_unavailable", "chain": "5"}); v != 1 {
		t.Fatalf("stated counter = %v", v)
	}
	h := ContractIdentityHealth()
	if h["capture_enabled"] != true || h["memory_bytes_budget"] != int64(12345) || h["captured"] != uint64(1) || h["stated_or_failed"] != uint64(1) || h["dropped"] != uint64(1) {
		t.Fatalf("health = %v", h)
	}
	if _, has := h["capture_disabled_reason"]; has {
		t.Fatal("an enabled capture reports a disabled reason")
	}
	AnnounceContractIdentityCaptureDisabled("setting_invalid", "CERTEN_CONTRACT_IDENTITY_CAPTURE_PARALLEL")
	if v, _ := ciValue(t, "certen_contract_identity_capture_enabled", nil); v != 0 {
		t.Fatal("enabled stays 1 after a disabled state")
	}
	if v, _ := ciValue(t, "certen_contract_identity_capture_disabled_total", map[string]string{"reason": "setting_invalid"}); v < 1 {
		t.Fatal("the disabled counter did not move")
	}
	h = ContractIdentityHealth()
	if h["capture_enabled"] != false || h["capture_disabled_reason"] != "setting_invalid" || h["capture_disabled_setting"] != "CERTEN_CONTRACT_IDENTITY_CAPTURE_PARALLEL" {
		t.Fatalf("health = %v", h)
	}
	SetContractIdentityCapture(false, 0)
	if h = ContractIdentityHealth(); h["capture_disabled_reason"] != "switch_off" {
		t.Fatalf("health = %v", h)
	}
}
