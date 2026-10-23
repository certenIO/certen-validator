package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	finruntime "github.com/certen/independant-validator/pkg/finality/runtime"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-DBFIX-FIX (verifier V3): a provider entry the finality runtime refuses must NOT stop the validator. The variables come from one
// shared environment, so a refusal that ended the process (startValidator error -> log.Fatal, restart: unless-stopped) would take all
// seven validators down at the roll. The finality runtime stays off as the named state
// finality_upgrader_disabled{reason: config_invalid, variable, entry, class}; the validator keeps running.

type finLogs struct {
	mu    sync.Mutex
	lines []string
}

func (l *finLogs) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *finLogs) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func clearProviderEnv(t *testing.T) {
	t.Helper()
	old := finalityRegistry
	finalityRegistry = finality.NewRegistry() // a kind registers once per registry
	t.Cleanup(func() { finalityRegistry = old })
	for _, v := range finruntime.ProviderVariables() {
		t.Setenv(v.Name, "")
	}
	t.Setenv(finality.EnvEnabled, "")
}

func TestStartFinalityWithARefusedProviderEntryKeepsTheValidatorRunningAndNamesTheDisabledState(t *testing.T) {
	const secret = "hunter2-fake-credential"
	for _, v := range finruntime.ProviderVariables() {
		t.Run(v.Name, func(t *testing.T) {
			clearProviderEnv(t)
			t.Setenv(v.Name, "https://ok.example/k,wss://user:"+secret+"@host.example/x")
			logs := &finLogs{}
			if err := startFinality(context.Background(), nil, logs.logf); err != nil {
				t.Fatalf("a refused provider entry ended the start of the validator: %v", err)
			}
			out := logs.joined()
			for _, want := range []string{finality.CodeUpgraderDisabled, "DISABLED", `reason="config_invalid"`, `variable="` + v.Name + `"`, `entry="1"`, `class="other_scheme"`} {
				if !strings.Contains(out, want) {
					t.Fatalf("the log lacks %q:\n%s", want, out)
				}
			}
			for _, leak := range []string{secret, "host.example", "ok.example", "user:"} {
				if strings.Contains(out, leak) {
					t.Fatalf("the log echoes part of the value (%q):\n%s", leak, out)
				}
			}
			h := metrics.FinalityHealth()
			reason, _ := h["upgrader_disabled_reason"].(string)
			if h["upgrader_enabled"] != false || !strings.Contains(reason, "config_invalid") || !strings.Contains(reason, v.Name) {
				t.Fatalf("the health block does not carry the named state: %v", h)
			}
			for _, leak := range []string{secret, "host.example", "ok.example"} {
				if strings.Contains(reason, leak) {
					t.Fatalf("the health reason echoes part of the value (%q): %s", leak, reason)
				}
			}
		})
	}
}

// Every refusal is logged by position, not only the one the state names, so one restart can fix them all.
func TestStartFinalityLogsEveryRefusedEntryByPosition(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("ETHEREUM_SEPOLIA_URL_FALLBACKS", "https://ok.example,https://u:p%ssXX@h/")
	t.Setenv("BASE_SEPOLIA_RPC_URL", "https://h:abcYY/")
	logs := &finLogs{}
	if err := startFinality(context.Background(), nil, logs.logf); err != nil {
		t.Fatal(err)
	}
	out := logs.joined()
	for _, want := range []string{"ETHEREUM_SEPOLIA_URL_FALLBACKS entry 1 (bad_escape)", "BASE_SEPOLIA_RPC_URL entry 0 (bad_port)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the log lacks %q:\n%s", want, out)
		}
	}
	for _, leak := range []string{"XX", "YY", "ok.example"} {
		if strings.Contains(out, leak) {
			t.Fatalf("the log echoes part of the value (%q):\n%s", leak, out)
		}
	}
}

// A good configuration with the operator's switch off is still the switch's own named state, not config_invalid.
func TestStartFinalityWithAGoodConfigurationAndTheSwitchOffIsTheSwitchsState(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv(finality.EnvEnabled, "false")
	logs := &finLogs{}
	if err := startFinality(context.Background(), nil, logs.logf); err != nil {
		t.Fatal(err)
	}
	h := metrics.FinalityHealth()
	reason, _ := h["upgrader_disabled_reason"].(string)
	if h["upgrader_enabled"] != false || !strings.Contains(reason, finality.EnvEnabled) || strings.Contains(reason, "config_invalid") {
		t.Fatalf("%v", h)
	}
}

// Every other failure of the start still refuses it by name, as before (a switch that is not a switch, a malformed number, a wiring
// failure, a failed genesis link, a per-chain switch that is not a switch).
func TestStartFinalityStillRefusesEveryOtherFailureByName(t *testing.T) {
	t.Run("a switch that is not a switch", func(t *testing.T) {
		clearProviderEnv(t)
		t.Setenv(finality.EnvEnabled, "maybe")
		if err := startFinality(context.Background(), nil, (&finLogs{}).logf); err == nil || !strings.Contains(err.Error(), "finality upgrader") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a malformed number", func(t *testing.T) {
		clearProviderEnv(t)
		t.Setenv(finruntime.EnvRateRPS, "fast")
		if err := startFinality(context.Background(), nil, (&finLogs{}).logf); err == nil || !strings.Contains(err.Error(), "finality configuration") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a pins file that cannot be read", func(t *testing.T) {
		clearProviderEnv(t)
		t.Setenv(finruntime.EnvPinsFile, filepath.Join(t.TempDir(), "absent.json"))
		if err := startFinality(context.Background(), nil, (&finLogs{}).logf); err == nil || !strings.Contains(err.Error(), "finality wiring") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a failed genesis link", func(t *testing.T) {
		clearProviderEnv(t)
		old := genesisLinkCheck
		genesisLinkCheck = func(*finality.Pins) error { return errors.New("link broken") }
		defer func() { genesisLinkCheck = old }()
		if err := startFinality(context.Background(), nil, (&finLogs{}).logf); err == nil || !strings.Contains(err.Error(), "finality pins") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a per-chain switch that is not a switch (refused while wiring, before Launch)", func(t *testing.T) {
		clearProviderEnv(t)
		t.Setenv(finality.ChainEnv(finality.ChainBaseSepolia), "maybe")
		if err := startFinality(context.Background(), nil, (&finLogs{}).logf); err == nil || !strings.Contains(err.Error(), "finality wiring") {
			t.Fatalf("%v", err)
		}
	})
}
