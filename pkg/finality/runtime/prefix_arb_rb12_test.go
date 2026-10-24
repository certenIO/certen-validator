// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-ARCHIVE-BACKFILL, Arbitrum: the setting, the wiring and the gauges.

func TestRB12ArbPrefixScanSettingBoundsAreExact(t *testing.T) {
	for _, c := range []struct {
		value string
		ok    bool
	}{{"1", true}, {"400", true}, {"2000", true}, {"0", false}, {"2001", false}, {"lots", false}} {
		rtClearEnv(t)
		t.Setenv(EnvPrefixArbScan, c.value)
		refused := RefusedSettings()
		if c.ok && len(refused) != 0 || !c.ok && (len(refused) != 1 || refused[0].Key != EnvPrefixArbScan) {
			t.Errorf("%s=%q: %v", EnvPrefixArbScan, c.value, refused)
		}
	}
	rtClearEnv(t)
	t.Setenv(EnvPrefixArbScan, "")
	if cfg, err := ConfigFromEnv(); err != nil || cfg.PrefixArbScan != 400 {
		t.Fatalf("%+v %v", cfg.PrefixArbScan, err)
	}
}

func TestRB12ArbPrefixSettingsReachTheBuilderAndTheCapturer(t *testing.T) {
	rtClearEnv(t)
	rtProviderEnv(t)
	t.Setenv(EnvPrefixMax, "7000")
	t.Setenv(EnvPrefixFloor, "11000000")
	t.Setenv(EnvPrefixArbScan, "250")
	t.Setenv(EnvPrefixLease, "120")
	_, reg, _ := rtWire(t)
	var b *arbposted.Builder
	for _, p := range reg.Provers(finality.ChainArbitrumSepolia) {
		if x, ok := p.(*arbposted.Builder); ok {
			b = x
		}
	}
	if b == nil || b.Prefix != (finality.PrefixPolicy{MaxBlocks: 7000, Floor: 11000000}) {
		t.Fatalf("the Arbitrum l1_posted builder carries the policy: %+v", b)
	}
	var loop *ArbPostedLoop
	for _, c := range reg.Capturers() {
		if x, ok := c.(*ArbPostedLoop); ok {
			loop = x
		}
	}
	if loop == nil || loop.Cap.Prefix == nil || loop.Cap.Prefix.Lease == nil || loop.Cap.Prefix.Blocks != 250 {
		t.Fatalf("the capturer scans the prefix: %+v", loop)
	}
	l := loop.Cap.Prefix.Lease
	if l.Chunk != 250 || l.Span.Seconds() != 120 || l.Chain != finality.ChainArbitrumSepolia || l.Holder == ([16]byte{}) {
		t.Fatalf("%+v", l)
	}
}

func TestRB12ArbPrefixGaugesFollowTheScanFromTheFirstTick(t *testing.T) {
	metrics.RegisterMetrics()
	ctx := context.Background()
	st := finality.NewMemCaptureStore()
	c := finality.ChainArbitrumSepolia
	_, _ = finality.RequestPrefix(ctx, st, c, 1000, 1999, finality.PrefixPolicy{MaxBlocks: 5000})
	_, _ = finality.RequestPrefix(ctx, st, c, 3000, 3499, finality.PrefixPolicy{MaxBlocks: 5000})
	_ = finality.RecordGapScan(ctx, st, c, 3000, 3499)
	l := &ArbPostedLoop{Cap: &capture.Capturer{Store: st}, Logf: func(string, ...any) {}}
	l.reportPrefix(ctx, capture.Report{PrefixScanned: 500, PrefixBatches: 12})
	for state, want := range map[string]float64{"open": 1, "complete": 1, "unavailable_proven": 0} {
		if got, ok := gauge(t, "certen_finality_prefix_windows", map[string]string{"chain": "421614", "state": state}); !ok || got != want {
			t.Errorf("windows{state=%s} = %v (%v) want %v", state, got, ok, want)
		}
	}
	if got, ok := gauge(t, "certen_finality_prefix_requested_blocks", map[string]string{"chain": "421614"}); !ok || got != 1500 {
		t.Errorf("requested %v %v", got, ok)
	}
	if got, ok := gauge(t, "certen_finality_prefix_backfilled_blocks_total", map[string]string{"chain": "421614"}); !ok || got < 500 {
		t.Errorf("scanned %v %v", got, ok)
	}
}
