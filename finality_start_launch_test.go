package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// A failure of Launch itself (not a setting) is the named state too.
func TestStartFinalityNamesAFailedLaunch(t *testing.T) {
	metrics.RegisterMetrics()
	clearProviderEnv(t)
	metrics.SetFinalityUpgraderEnabled(true)
	old := launchFinality
	launchFinality = func(context.Context, bool, finality.LegSource, finality.AddendumStore, *finality.Registry, *finality.Pins, finality.UpgraderConfig) (*finality.Upgrader, error) {
		return nil, fmt.Errorf("launch refused")
	}
	defer func() { launchFinality = old }()
	logs := &finLogs{}
	err, panicked := callStart(t, logs)
	if panicked != nil || err != nil {
		t.Fatalf("panic %v, error %v", panicked, err)
	}
	out := logs.joined()
	for _, want := range []string{finality.CodeUpgraderDisabled, `reason="launch_failed"`, `stage="launch"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("the log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, secretValue) {
		t.Fatalf("the log echoes a secret:\n%s", out)
	}
	h := metrics.FinalityHealth()
	if reason, _ := h["upgrader_disabled_reason"].(string); h["upgrader_enabled"] != false || !strings.Contains(reason, `reason="launch_failed"`) {
		t.Fatalf("%v", h)
	}
}

// A good configuration with the switch ON reaches Launch; this is the only path that is not a disabled state, and it must stay one.
func TestStartFinalityWithAGoodConfigurationLaunchesTheUpgrader(t *testing.T) {
	clearProviderEnv(t)
	metrics.SetFinalityUpgraderEnabled(false)
	var launched bool
	old := launchFinality
	launchFinality = func(_ context.Context, enabled bool, _ finality.LegSource, _ finality.AddendumStore, reg *finality.Registry, pins *finality.Pins, _ finality.UpgraderConfig) (*finality.Upgrader, error) {
		launched = enabled && reg != nil && pins != nil
		return nil, nil
	}
	defer func() { launchFinality = old }()
	logs := &finLogs{}
	if err, panicked := callStart(t, logs); err != nil || panicked != nil {
		t.Fatalf("%v %v", err, panicked)
	}
	if !launched {
		t.Fatalf("Launch was not reached with the switch on, a registry and pins:\n%s", logs.joined())
	}
	if strings.Contains(logs.joined(), "DISABLED") {
		t.Fatalf("a good configuration was announced as disabled:\n%s", logs.joined())
	}
}
