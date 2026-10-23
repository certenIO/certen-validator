// Copyright 2026 Certen Protocol

package runtime

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-GO-INT F14: StartFailure turns every failure of the finality start into one of the closed reasons of finality_upgrader_disabled.

func rtLogs() (func(string, ...any), func() string) {
	var lines []string
	return func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }, func() string { return strings.Join(lines, "\n") }
}

func TestRTF14StartFailureClassifiesEveryFailureOfTheStart(t *testing.T) {
	const secret = "hunter2-fake-credential"
	for _, tc := range []struct {
		name   string
		err    func(t *testing.T) error
		reason string
		field  string // a field that must be present (stage, variable)
		want   string
	}{
		{"a provider entry", func(t *testing.T) error {
			rtClearEnv(t)
			t.Setenv("BASE_SEPOLIA_RPC_URL", "wss://u:"+secret+"@h/x")
			_, err := ConfigFromEnv()
			return err
		}, "config_invalid", "variable", "BASE_SEPOLIA_RPC_URL"},
		{"a number", func(t *testing.T) error {
			rtClearEnv(t)
			t.Setenv(EnvRateRPS, "fast-"+secret)
			_, err := ConfigFromEnv()
			return err
		}, "setting_invalid", "variable", EnvRateRPS},
		{"a switch", func(t *testing.T) error {
			t.Setenv(finality.EnvEnabled, "maybe-"+secret)
			_, err := finality.Enabled()
			return err
		}, "switch_invalid", "variable", finality.EnvEnabled},
		{"a switch and a number refused together: the switch is the one named", func(t *testing.T) error {
			t.Setenv(EnvRateBurst, "fast")
			_, e1 := envvar.Int(EnvRateBurst, 1, 1)
			t.Setenv(finality.EnvEnabled, "maybe")
			_, e2 := finality.Enabled()
			return errors.Join(e1, e2)
		}, "switch_invalid", "variable", finality.EnvEnabled},
		{"the pins file", func(t *testing.T) error {
			return &WireError{Stage: finality.StartStagePinsFile, Err: errors.New(EnvPinsFile + ": open x: no such file")}
		}, "pins_invalid", "variable", EnvPinsFile},
		{"the embedded pins", func(t *testing.T) error {
			return &WireError{Stage: finality.StartStagePinsEmbedded, Err: errors.New("finality_pins_corrupt")}
		}, "pins_invalid", "stage", finality.StartStagePinsEmbedded},
		{"the genesis link", func(t *testing.T) error { return GenesisLinkFailed(errors.New("link broken")) }, "pins_invalid", "stage", finality.StartStageGenesisLink},
		{"the kinds", func(t *testing.T) error {
			return &WireError{Stage: finality.StartStageKinds, Err: errors.New("already registered")}
		}, "wiring_failed", "stage", finality.StartStageKinds},
		{"the arguments", func(t *testing.T) error {
			return &WireError{Stage: finality.StartStageArguments, Err: errors.New("no registry")}
		}, "wiring_failed", "stage", finality.StartStageArguments},
		{"the launch", func(t *testing.T) error { return LaunchFailed(errors.New("refused")) }, "launch_failed", "stage", finality.StartStageLaunch},
		{"an error with no classification of its own", func(t *testing.T) error { return errors.New("something else") }, "wiring_failed", "stage", finality.StartStageStart},
		{"a wrapped refusal", func(t *testing.T) error {
			t.Setenv(EnvMaxBatch, "250")
			_, err := ConfigFromEnv()
			return fmt.Errorf("finality configuration: %w", err)
		}, "setting_invalid", "variable", EnvMaxBatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.err(t)
			logf, logs := rtLogs()
			st := StartFailure(logf, err)
			if st.Code != finality.CodeUpgraderDisabled || st.Fields["reason"] != tc.reason || fmt.Sprint(st.Fields[tc.field]) != tc.want {
				t.Fatalf("%s", st.Error())
			}
			for _, leak := range []string{secret, "maybe", "fast"} {
				if strings.Contains(st.Error(), leak) || strings.Contains(logs(), leak) {
					t.Fatalf("the state or the log holds a value (%q):\n%s\n%s", leak, st.Error(), logs())
				}
			}
		})
	}
}

// Every refused setting is logged by name, the one the state names first, with the count in the state.
func TestRTF14StartFailureLogsEveryRefusedSettingAndCountsThem(t *testing.T) {
	rtClearEnv(t)
	t.Setenv(EnvRateRPS, "fast")
	t.Setenv(EnvConcurrency, "0")
	t.Setenv("BASE_SEPOLIA_RPC_URL", "wss://h/x")
	logf, logs := rtLogs()
	_, err := ConfigFromEnv()
	st := StartFailure(logf, err) // the provider entry stops ConfigFromEnv first: config_invalid
	if st.Fields["reason"] != "config_invalid" {
		t.Fatalf("%s", st.Error())
	}
	for _, want := range []string{EnvRateRPS, EnvConcurrency, "BASE_SEPOLIA_RPC_URL entry 0 (other_scheme)"} {
		if !strings.Contains(logs(), want) {
			t.Fatalf("the log lacks %q:\n%s", want, logs())
		}
	}
	t.Setenv("BASE_SEPOLIA_RPC_URL", "")
	_, err = ConfigFromEnv()
	logf, _ = rtLogs()
	st = StartFailure(logf, err)
	if st.Fields["reason"] != "setting_invalid" || fmt.Sprint(st.Fields["refused"]) != "2" {
		t.Fatalf("%s", st.Error())
	}
}

func TestRTF14StartPanicCarriesNoValue(t *testing.T) {
	st := StartPanic("boom hunter2-fake-credential")
	if st.Fields["reason"] != "start_panicked" || st.Fields["stage"] != finality.StartStageStart || strings.Contains(st.Error(), "hunter2") {
		t.Fatalf("%s", st.Error())
	}
	var m map[string]int
	func() {
		defer func() { st = StartPanic(recover()) }()
		m["x"] = 1 // a runtime error: its message is carried
	}()
	if !strings.Contains(st.Error(), "nil map") {
		t.Fatalf("%s", st.Error())
	}
}
