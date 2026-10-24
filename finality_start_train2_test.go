package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/allkinds"
	finruntime "github.com/certen/independant-validator/pkg/finality/runtime"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-GO-INT F14 (the open question of RB12-DBFIX-FIX, now the owner's rule): EVERY failure of the finality start is a named
// finality_upgrader_disabled state - in the log, in certen_finality_upgrader_disabled_total and in the health block of /health/detailed -
// and the validator keeps running. The variables come from ONE shared environment, so a start that ended the process would take all seven
// validators down at the same roll for a typo in a setting that is no input of consensus. The old test of this file asserted the
// opposite for these injections (an error that main turned into log.Fatal); it is replaced by this table, which covers the same
// injections and the others the brief names.

const secretValue = "hunter2-fake-credential"

// callStart runs startFinality the way main does and reports a panic as a failure of the test instead of ending the test binary.
func callStart(t *testing.T, logs *finLogs) (err error, panicked any) {
	t.Helper()
	defer func() { panicked = recover() }()
	return startFinality(context.Background(), nil, logs.logf), nil
}

// disabledCount reads certen_finality_upgrader_disabled_total{chain="0",env=env}.
func disabledCount(t *testing.T, env string) float64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != "certen_finality_upgrader_disabled_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			var chain, e string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "chain":
					chain = lp.GetValue()
				case "env":
					e = lp.GetValue()
				}
			}
			if chain == "0" && e == env {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestStartFinalityNamesEveryStartupFailureAndKeepsTheValidatorRunning(t *testing.T) {
	metrics.RegisterMetrics()
	for _, tc := range []struct {
		name   string
		setup  func(t *testing.T)
		reason string   // the closed reason of the state
		env    string   // the setting (or stage label) the metric and the state name
		words  []string // in the log AND in /health/detailed
	}{
		{"the upgrader switch is not a switch", func(t *testing.T) { t.Setenv(finality.EnvEnabled, "maybe-"+secretValue) },
			"switch_invalid", finality.EnvEnabled, []string{`variable="` + finality.EnvEnabled + `"`}},
		{"a per-chain switch is not a switch", func(t *testing.T) { t.Setenv(finality.ChainEnv(finality.ChainBaseSepolia), "maybe-"+secretValue) },
			"switch_invalid", finality.ChainEnv(finality.ChainBaseSepolia), []string{`variable="` + finality.ChainEnv(finality.ChainBaseSepolia) + `"`}},
		{"a malformed number", func(t *testing.T) { t.Setenv(finruntime.EnvRateRPS, "fast-"+secretValue) },
			"setting_invalid", finruntime.EnvRateRPS, []string{`variable="` + finruntime.EnvRateRPS + `"`}},
		{"two malformed numbers are both named", func(t *testing.T) {
			t.Setenv(finruntime.EnvRateRPS, "fast-"+secretValue)
			t.Setenv(finruntime.EnvConcurrency, "0")
		}, "setting_invalid", finruntime.EnvRateRPS, []string{`variable="` + finruntime.EnvRateRPS + `"`, `refused="2"`}},
		{"a batch size above what the providers accept", func(t *testing.T) { t.Setenv(finruntime.EnvMaxBatch, "101") },
			"setting_invalid", finruntime.EnvMaxBatch, []string{`variable="` + finruntime.EnvMaxBatch + `"`}},
		{"a memory budget below the minimum", func(t *testing.T) { t.Setenv(finality.EnvMemoryBudget, "1") },
			"setting_invalid", finality.EnvMemoryBudget, []string{`variable="` + finality.EnvMemoryBudget + `"`}},
		{"the archive URL list does not parse", func(t *testing.T) {
			t.Setenv(finruntime.EnvArchiveURLs, "https://ok.example/k,wss://u:"+secretValue+"@host.example/x")
		},
			"config_invalid", finruntime.EnvArchiveURLs, []string{`variable="` + finruntime.EnvArchiveURLs + `"`, `entry="1"`, `class="other_scheme"`}},
		{"the archive URL list holds no entry", func(t *testing.T) { t.Setenv(finruntime.EnvArchiveURLs, " , ;") },
			"config_invalid", finruntime.EnvArchiveURLs, []string{`variable="` + finruntime.EnvArchiveURLs + `"`, `class="no_entry"`}},
		{"a provider URL does not parse", func(t *testing.T) { t.Setenv("BASE_SEPOLIA_RPC_URL", "https://h:abc"+secretValue+"/") },
			"config_invalid", "BASE_SEPOLIA_RPC_URL", []string{`variable="BASE_SEPOLIA_RPC_URL"`, `class="bad_port"`}},
		{"the pins file cannot be read", func(t *testing.T) {
			t.Setenv(finruntime.EnvPinsFile, filepath.Join(t.TempDir(), "absent.json"))
		},
			"pins_invalid", finruntime.EnvPinsFile, []string{`stage="pins_file"`, `variable="` + finruntime.EnvPinsFile + `"`}},
		{"the pins file is not a pins file", func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "pins.json")
			if err := os.WriteFile(p, []byte(`{"not":"pins"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(finruntime.EnvPinsFile, p)
		}, "pins_invalid", finruntime.EnvPinsFile, []string{`stage="pins_file"`}},
		{"the genesis link of the pins fails", func(t *testing.T) {
			old := genesisLinkCheck
			genesisLinkCheck = func(*finality.Pins) error { return errors.New("link broken") }
			t.Cleanup(func() { genesisLinkCheck = old })
		}, "pins_invalid", "finality:genesis_link", []string{`stage="genesis_link"`}},
		{"a verifier kind is registered twice", func(t *testing.T) {
			if err := allkinds.Register(finalityRegistry); err != nil {
				t.Fatal(err)
			}
		}, "wiring_failed", "finality:kinds", []string{`stage="kinds"`}},
		{"the start panics", func(t *testing.T) {
			old := genesisLinkCheck
			genesisLinkCheck = func(*finality.Pins) error { panic("boom " + secretValue) }
			t.Cleanup(func() { genesisLinkCheck = old })
		}, "start_panicked", "finality:start", []string{`stage="start"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearProviderEnv(t)
			metrics.SetFinalityUpgraderEnabled(true) // forget the previous case: an unset reason would pass nothing vacuously
			tc.setup(t)
			before := disabledCount(t, tc.env)
			logs := &finLogs{}
			err, panicked := callStart(t, logs)
			if panicked != nil {
				t.Fatalf("the start panicked and would have ended the validator: %v", panicked)
			}
			if err != nil {
				t.Fatalf("the start returned an error, which main turns into log.Fatal for all seven validators: %v", err)
			}
			out := logs.joined()
			// every refused setting is logged by name; the state names the first and counts them
			if tc.name == "two malformed numbers are both named" {
				for _, want := range []string{finruntime.EnvRateRPS, finruntime.EnvConcurrency} {
					if !strings.Contains(out, want) {
						t.Fatalf("the log lacks the refused setting %q:\n%s", want, out)
					}
				}
			}
			for _, want := range append([]string{finality.CodeUpgraderDisabled, "DISABLED", `reason="` + tc.reason + `"`}, tc.words...) {
				if !strings.Contains(out, want) {
					t.Fatalf("the log lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, secretValue) {
				t.Fatalf("the log echoes the value of a setting:\n%s", out)
			}
			h := metrics.FinalityHealth()
			reason, _ := h["upgrader_disabled_reason"].(string)
			if h["upgrader_enabled"] != false || !strings.Contains(reason, `reason="`+tc.reason+`"`) {
				t.Fatalf("/health/detailed does not carry the named state: %v", h)
			}
			for _, want := range tc.words {
				if !strings.Contains(reason, want) {
					t.Fatalf("/health/detailed lacks %q: %s", want, reason)
				}
			}
			raw, jerr := json.Marshal(map[string]any{"finality": h})
			if jerr != nil || strings.Contains(string(raw), secretValue) {
				t.Fatalf("the health block is not secret-free JSON: %v %s", jerr, raw)
			}
			if after := disabledCount(t, tc.env); after != before+1 {
				t.Fatalf("certen_finality_upgrader_disabled_total{chain=0,env=%q} %v -> %v, want +1", tc.env, before, after)
			}
		})
	}
}
