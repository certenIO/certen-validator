// Copyright 2026 Certen Protocol

package runtime

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-FIX D2 (known defect class 3): a bad finality setting is never fatal for a consensus node. The four index settings are
// parsed outside envvar.Check; a bad one is the named state finality_index_disabled{chain, key, reason} (log, metric, /health/detailed)
// and the validator runs on with the window reader.

func TestRTBadIndexSettingsAreANamedDisabledStateNotAFatalStartup(t *testing.T) {
	for _, c := range []struct {
		key, val, reason, refused string
	}{
		{EnvBaseIndex, "maybe", "switch_invalid", ""},
		{finality.EnvIndexGeneration, "0", "setting_invalid", "out_of_range"},
		{finality.EnvIndexGeneration, "-3", "setting_invalid", "out_of_range"},
		{finality.EnvIndexGeneration, "4294967296", "setting_invalid", "out_of_range"}, // uint32(2^32) is 0 (the default): must not wrap
		{finality.EnvIndexGeneration, "4294967297", "setting_invalid", "out_of_range"}, // uint32 wraps to generation 1
		{finality.EnvIndexGeneration, "one", "setting_invalid", "not_an_integer"},
		{EnvIndexBlocks, "0", "setting_invalid", "out_of_range"},
		{EnvIndexBlocks, "many", "setting_invalid", "not_an_integer"},
		{EnvIndexStepSecond, "0", "setting_invalid", "out_of_range"},
		{EnvIndexStepSecond, "soon", "setting_invalid", "not_an_integer"},
	} {
		t.Run(c.key+"="+c.val, func(t *testing.T) {
			t.Setenv(c.key, c.val)
			cfg, err := ConfigFromEnv()
			if err != nil {
				t.Fatalf("a bad index setting must not stop the validator: ConfigFromEnv returned %v", err)
			}
			if cfg.BaseIndex {
				t.Fatalf("the index must be off while a setting is bad")
			}
			d, ok := cfg.Describe()["index_disabled"].(string)
			if !ok || !strings.Contains(d, "finality_index_disabled") || !strings.Contains(d, c.key) || !strings.Contains(d, c.reason) || !strings.Contains(d, c.refused) {
				t.Fatalf("the secret-free description names the state, the key and the reason: %v", cfg.Describe()["index_disabled"])
			}
			if strings.Contains(d, c.val) && len(c.val) > 3 {
				t.Fatalf("the state must not echo the value: %s", d)
			}
		})
	}
}

func TestRTBadIndexSettingIsAnnouncedAndWiresNoIndexWhileTheBaseChainStillRuns(t *testing.T) {
	rtProviderEnv(t)
	t.Setenv(finality.EnvIndexGeneration, "4294967297")
	w, reg, logs := rtWire(t)
	if w.Disabled[finality.ChainBaseSepolia] != nil {
		t.Fatalf("the Base chain keeps running: %v", w.Disabled[finality.ChainBaseSepolia])
	}
	if !strings.Contains(logs.String(), "finality_index_disabled") {
		t.Fatalf("the disabled state is logged: %s", logs.String())
	}
	assertBaseIndexWiring(t, reg, false)
	chains, _ := metrics.FinalityHealth()["chains"].(map[string]any)
	c, _ := chains["84532"].(map[string]any)
	if r, _ := c["index_disabled_reason"].(string); !strings.Contains(r, "finality_index_disabled") {
		t.Fatalf("/health/detailed names the disabled index of the chain: %v", c)
	}
}

// D6b: CERTEN_FINALITY_BASE_INDEX=off leaves the builder without a reader and wires no indexer; the default wires both.
func TestRTBaseIndexOffLeavesNoIndexerAndNoReaderAndOnWiresBoth(t *testing.T) {
	rtProviderEnv(t)
	t.Setenv(EnvBaseIndex, "off")
	_, reg, _ := rtWire(t)
	assertBaseIndexWiring(t, reg, false)
	t.Setenv(EnvBaseIndex, "")
	_, reg, _ = rtWire(t)
	assertBaseIndexWiring(t, reg, true)
}

func assertBaseIndexWiring(t *testing.T, reg *finality.Registry, want bool) {
	t.Helper()
	var loops, builders int
	for _, c := range reg.Capturers() {
		if l, ok := c.(*BasePostedLoop); ok {
			loops++
			if (l.Index != nil) != want {
				t.Errorf("the Base capture loop has an indexer: %v, want %v", l.Index != nil, want)
			}
		}
	}
	for _, p := range reg.Provers(finality.ChainBaseSepolia) {
		if b, ok := p.(*baseposted.Builder); ok {
			builders++
			if (b.Index != nil) != want {
				t.Errorf("the Base l1_posted builder has an index reader: %v, want %v", b.Index != nil, want)
			}
		}
	}
	if loops != 1 || builders != 1 {
		t.Fatalf("expected one Base capture loop and one l1_posted builder, got %d and %d", loops, builders)
	}
}
