// Copyright 2026 Certen Protocol

package metrics

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// gatherDefault names every family of the default registry.
func gatherDefault() ([]string, error) {
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, f := range fams {
		names = append(names, f.GetName())
	}
	return names, nil
}

// resetFinalityHealth empties the in-process snapshot so a test sees only what it sets.
func resetFinalityHealth() {
	finalityHealth.mu.Lock()
	finalityHealth.upgraderKnown, finalityHealth.upgraderEnabled, finalityHealth.upgraderReason = false, false, ""
	finalityHealth.chains = map[uint64]*finalityChainHealth{}
	finalityHealth.mu.Unlock()
}

// The setters feed both the Prometheus series and the health snapshot with the same numbers.
func TestFinalityHealthSnapshotFollowsTheSetters(t *testing.T) {
	resetFinalityHealth()
	oldNow := finalityNow
	finalityNow = func() time.Time { return time.Unix(1_700_000_123, 0) }
	defer func() { finalityNow = oldNow }()

	SetFinalityUpgraderEnabled(true)
	SetFinalityChainEnabled(84532, true)
	SetFinalityChainEnabled(2017, false)
	SetFinalityChainDisabledReason(2017, "finality_upgrader_disabled: CERTEN_FINALITY_CHAIN_2017_ENABLED=false")
	SetFinalityLegs(84532, "none", 1)
	SetFinalityLegs(84532, "included", 3)
	SetFinalityLegs(84532, "finalized", 7)
	IncFinalityAppended(84532, "l1_posted")
	IncFinalityCapturerRestart(84532, "base-sepolia/inbox")
	IncFinalityCapturerRestart(84532, "base-sepolia/inbox")
	SetFinalityLastCapturedBlock(84532, "base-sepolia/inbox", 9_000_100)
	SetFinalityLastCapturedBlock(84532, "base-sepolia/games", 9_000_050)
	SetFinalityCaptureLag(84532, "base-sepolia/inbox", 2)
	SetFinalityCaptureLag(84532, "base-sepolia/games", 52)

	h := FinalityHealth()
	if h["upgrader_enabled"] != true {
		t.Fatalf("upgrader_enabled = %v", h["upgrader_enabled"])
	}
	chains := h["chains"].(map[string]any)
	base := chains["84532"].(map[string]any)
	if base["enabled"] != true || base["disabled_reason"] != "" {
		t.Errorf("base: enabled=%v reason=%q", base["enabled"], base["disabled_reason"])
	}
	if base["last_captured_block"] != uint64(9_000_100) || base["capture_lag_blocks"] != uint64(52) {
		t.Errorf("base capture: block=%v lag=%v (want the highest block and the largest lag over its loops)", base["last_captured_block"], base["capture_lag_blocks"])
	}
	if base["last_append_unixtime"] != int64(1_700_000_123) || base["capturer_restarts"] != 2 {
		t.Errorf("base: last_append=%v restarts=%v", base["last_append_unixtime"], base["capturer_restarts"])
	}
	legs := base["pending_legs_by_level"].(map[string]int)
	if legs["none"] != 1 || legs["included"] != 3 || legs["finalized"] != 7 || len(legs) != 3 {
		t.Errorf("legs by level = %v", legs)
	}
	per := base["capturers"].(map[string]any)
	if g := per["base-sepolia/games"].(map[string]any); g["last_captured_block"] != uint64(9_000_050) || g["capture_lag_blocks"] != uint64(52) {
		t.Errorf("per-loop values = %v", g)
	}
	adiri := chains["2017"].(map[string]any)
	if adiri["enabled"] != false || adiri["disabled_reason"] != "finality_upgrader_disabled: CERTEN_FINALITY_CHAIN_2017_ENABLED=false" {
		t.Errorf("adiri: %v", adiri)
	}

	// the snapshot is a copy: mutating it changes nothing in the process state
	legs["finalized"] = 99
	if got := FinalityHealth()["chains"].(map[string]any)["84532"].(map[string]any)["pending_legs_by_level"].(map[string]int)["finalized"]; got != 7 {
		t.Errorf("the snapshot aliases the live state: finalized = %d", got)
	}

	// the Prometheus series carry the same numbers
	if v := testutil.ToFloat64(finalityLastCaptured.WithLabelValues("84532", "base-sepolia/inbox")); v != 9_000_100 {
		t.Errorf("certen_finality_last_captured_block = %v", v)
	}
	if v := testutil.ToFloat64(finalityCaptureLag.WithLabelValues("84532", "base-sepolia/games")); v != 52 {
		t.Errorf("certen_finality_capture_lag_blocks = %v", v)
	}
	if v := testutil.ToFloat64(finalityLastAppend.WithLabelValues("84532")); v != 1_700_000_123 {
		t.Errorf("certen_finality_last_append_unixtime = %v", v)
	}
}

// An empty process reports nothing it does not know: no upgrader_enabled until the launcher said, and a chain's enabled only
// once its switch was reported.
func TestFinalityHealthDoesNotInventWhatWasNeverReported(t *testing.T) {
	resetFinalityHealth()
	h := FinalityHealth()
	if _, ok := h["upgrader_enabled"]; ok {
		t.Errorf("upgrader_enabled is present before the launcher reported it: %v", h)
	}
	if n := len(h["chains"].(map[string]any)); n != 0 {
		t.Errorf("%d chains in an empty process", n)
	}
	SetFinalityLegs(421614, "included", 2) // a chain seen by the gauges before its switch is reported
	c := FinalityHealth()["chains"].(map[string]any)["421614"].(map[string]any)
	if _, ok := c["enabled"]; ok {
		t.Errorf("enabled is present for a chain whose switch was never reported: %v", c)
	}
	SetFinalityUpgraderEnabled(false)
	if v, ok := FinalityHealth()["upgrader_enabled"]; !ok || v != false {
		t.Errorf("a reported off switch must read false, got %v (present=%v)", v, ok)
	}
}

// The health block is JSON-ready and carries only the documented keys: no URL, key or free text sneaks in.
func TestFinalityHealthJSONCarriesOnlyTheDocumentedKeys(t *testing.T) {
	resetFinalityHealth()
	SetFinalityUpgraderEnabled(true)
	SetFinalityChainEnabled(11155111, true)
	SetFinalityLegs(11155111, "included", 1)
	SetFinalityLastCapturedBlock(11155111, "eth-sepolia/head", 5)
	SetFinalityCaptureLag(11155111, "eth-sepolia/head", 1)
	IncFinalityAppended(11155111, "finalized")
	b, err := json.Marshal(FinalityHealth())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	allowTop := map[string]bool{"upgrader_enabled": true, "chains": true}
	for k := range doc {
		if !allowTop[k] {
			t.Errorf("unexpected top-level key %q", k)
		}
	}
	allowChain := map[string]bool{"enabled": true, "disabled_reason": true, "last_captured_block": true, "capture_lag_blocks": true,
		"pending_legs_by_level": true, "last_append_unixtime": true, "capturer_restarts": true, "capturers": true}
	for id, v := range doc["chains"].(map[string]any) {
		for k := range v.(map[string]any) {
			if !allowChain[k] {
				t.Errorf("chain %s: unexpected key %q", id, k)
			}
		}
	}
	if strings.Contains(string(b), "http") {
		t.Errorf("the health block carries a URL: %s", b)
	}
}

// Concurrent use of every setter and the snapshot is safe (run by a plain go test; the mutex is the guard).
func TestFinalityHealthConcurrentUse(t *testing.T) {
	resetFinalityHealth()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			chain := uint64(100 + i%3)
			for j := 0; j < 200; j++ {
				SetFinalityLegs(chain, "included", j)
				SetFinalityLastCapturedBlock(chain, "c", uint64(j))
				SetFinalityCaptureLag(chain, "c", uint64(j%7))
				IncFinalityCapturerRestart(chain, "c")
				IncFinalityAppended(chain, "finalized")
				SetFinalityChainEnabled(chain, j%2 == 0)
				_ = FinalityHealth()
			}
		}(i)
	}
	wg.Wait()
	total := 0
	for _, v := range FinalityHealth()["chains"].(map[string]any) {
		total += v.(map[string]any)["capturer_restarts"].(int)
	}
	if total != 8*200 {
		t.Errorf("capturer_restarts total = %d, want %d", total, 8*200)
	}
}

// The new counters count what their names say, and only a host name can become the throttle label.
func TestFinalityCaptureCountersAndTheHostOnlyThrottleLabel(t *testing.T) {
	before := testutil.ToFloat64(finalityCaptureBytes.WithLabelValues("777"))
	AddFinalityCaptureBytes(777, 1024)
	AddFinalityCaptureBytes(777, 0)
	AddFinalityCaptureBytes(777, -5)
	if got := testutil.ToFloat64(finalityCaptureBytes.WithLabelValues("777")) - before; got != 1024 {
		t.Errorf("capture bytes counted %v, want 1024 (zero and negative add nothing)", got)
	}

	IncFinalityUpgraderDisabled(0, "CERTEN_FINALITY_UPGRADER_ENABLED")
	IncFinalityUpgraderDisabled(2017, "CERTEN_FINALITY_CHAIN_2017_ENABLED")
	if v := testutil.ToFloat64(finalityUpgraderDisabled.WithLabelValues("0", "CERTEN_FINALITY_UPGRADER_ENABLED")); v < 1 {
		t.Errorf("global switch not counted: %v", v)
	}
	IncFinalityCaptureRefused(84532, "finality_evidence_too_large")
	if v := testutil.ToFloat64(finalityCaptureRefused.WithLabelValues("84532", "finality_evidence_too_large")); v < 1 {
		t.Errorf("refused capture not counted: %v", v)
	}

	for raw, want := range map[string]string{
		"https://0xrpc.io/sep":                              "0xrpc.io",
		"https://user:pass@Example.COM:8545/v2/SECRETKEY?k": "example.com",
		"api.zan.top/eth-sepolia":                           "api.zan.top",
		"https://sepolia.gateway.tenderly.co":               "sepolia.gateway.tenderly.co",
		"":                                                  "unknown",
		"http://":                                           "unknown",
	} {
		if got := providerHostLabel(raw); got != want {
			t.Errorf("providerHostLabel(%q) = %q, want %q", raw, got, want)
		}
	}
	IncFinalityProviderThrottled("https://rpc.example.org/v3/abcdef0123456789abcdef0123456789?apikey=zzz")
	if v := testutil.ToFloat64(finalityProviderThrottled.WithLabelValues("rpc.example.org")); v != 1 {
		t.Errorf("throttle not counted under the bare host: %v", v)
	}
}

// RegisterMetrics exposes the new families beside the old ones.
func TestRegisterMetricsExposesTheCaptureSeries(t *testing.T) {
	RegisterMetrics()
	SetFinalityCaptureLag(84532, "base-sepolia/inbox", 1)
	SetFinalityLastCapturedBlock(84532, "base-sepolia/inbox", 1)
	IncFinalityAppended(84532, "l1_posted")
	AddFinalityCaptureBytes(84532, 1)
	IncFinalityUpgraderDisabled(0, "CERTEN_FINALITY_UPGRADER_ENABLED")
	IncFinalityProviderThrottled("https://example.org")
	IncFinalityCaptureRefused(84532, "finality_evidence_too_large")
	want := map[string]bool{
		"certen_finality_capture_lag_blocks": false, "certen_finality_last_captured_block": false, "certen_finality_last_append_unixtime": false,
		"certen_finality_capture_bytes_total": false, "certen_finality_upgrader_disabled_total": false,
		"certen_finality_provider_throttled_total": false, "certen_finality_capture_refused_total": false,
	}
	families, err := gatherDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range families {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("metric family %s is not exposed after RegisterMetrics", name)
		}
	}
}
