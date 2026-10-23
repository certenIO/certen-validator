// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-ARCHIVE-BACKFILL: the settings, the wiring and the gauges of the prefix extension.

func TestRB12PrefixSettingsHaveSafeDefaults(t *testing.T) {
	rtClearEnv(t)
	for _, n := range []string{EnvPrefixMax, EnvPrefixFloor, EnvPrefixLease, EnvPrefixChunk, EnvPrefixReprobe} {
		t.Setenv(n, "")
	}
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.PrefixMax != 100_000 || c.PrefixFloor != 0 || c.PrefixLease != 10*time.Minute || c.PrefixChunk != 8 || c.PrefixReprobe != 24*time.Hour {
		t.Fatalf("%+v", c)
	}
	d := c.Describe()
	if d["prefix_max_blocks"] != uint64(100_000) || d["prefix_chunk_blocks"] != 8 {
		t.Fatalf("the health view carries the settings: %v", d)
	}
}

func TestRB12PrefixSettingBoundsAreExactAndEachRefusalNamesTheVariable(t *testing.T) {
	type tc struct {
		env, value string
		ok         bool
	}
	cases := []tc{
		{EnvPrefixMax, "0", true}, {EnvPrefixMax, "1", true}, {EnvPrefixMax, "-1", false}, {EnvPrefixMax, "many", false},
		{EnvPrefixFloor, "0", true}, {EnvPrefixFloor, "11842420", true}, {EnvPrefixFloor, "-5", false},
		{EnvPrefixLease, "60", true}, {EnvPrefixLease, "59", false}, {EnvPrefixLease, "ten", false},
		{EnvPrefixChunk, "1", true}, {EnvPrefixChunk, "1024", true}, {EnvPrefixChunk, "1025", false}, {EnvPrefixChunk, "0", false},
		{EnvPrefixReprobe, "3600", true}, {EnvPrefixReprobe, "3599", false},
	}
	for _, c := range cases {
		rtClearEnv(t)
		for _, n := range []string{EnvPrefixMax, EnvPrefixFloor, EnvPrefixLease, EnvPrefixChunk, EnvPrefixReprobe} {
			t.Setenv(n, "") // a Setenv of an earlier case stays until the test ends
		}
		t.Setenv(c.env, c.value)
		refused := RefusedSettings()
		if c.ok && len(refused) != 0 {
			t.Errorf("%s=%q must be accepted: %v", c.env, c.value, refused)
		}
		if !c.ok {
			if len(refused) != 1 || refused[0].Key != c.env {
				t.Errorf("%s=%q must be refused by that variable's name: %v", c.env, c.value, refused)
				continue
			}
		}
	}
}

func TestRB12PrefixSettingsReachTheBuilderTheLeaseAndThePolicy(t *testing.T) {
	rtClearEnv(t)
	rtProviderEnv(t)
	t.Setenv(EnvPrefixMax, "5000")
	t.Setenv(EnvPrefixFloor, "11842420")
	t.Setenv(EnvPrefixLease, "120")
	t.Setenv(EnvPrefixChunk, "16")
	t.Setenv(EnvPrefixReprobe, "7200")
	_, reg, _ := rtWire(t)
	var b *baseposted.Builder
	for _, p := range reg.Provers(finality.ChainBaseSepolia) {
		if x, ok := p.(*baseposted.Builder); ok {
			b = x
		}
	}
	if b == nil || b.Prefix != (finality.PrefixPolicy{MaxBlocks: 5000, Floor: 11842420}) {
		t.Fatalf("the Base l1_posted builder carries the policy: %+v", b)
	}
	var loop *GapBackfillLoop
	for _, c := range reg.Capturers() {
		if x, ok := c.(*GapBackfillLoop); ok {
			loop = x
		}
	}
	if loop == nil || loop.Backfill == nil || loop.Backfill.Lease == nil {
		t.Fatalf("the gap backfill carries a lease: %+v", loop)
	}
	l := loop.Backfill.Lease
	if l.Span != 2*time.Minute || l.Chunk != 16 || l.Chain != finality.ChainBaseSepolia || l.Holder == ([16]byte{}) || loop.Backfill.Policy.ReprobeEvery != 2*time.Hour {
		t.Fatalf("%+v %v", l, loop.Backfill.Policy)
	}
}

func TestRB12PrefixOffSettingMakesTheBuilderPolicyOff(t *testing.T) {
	rtClearEnv(t)
	rtProviderEnv(t)
	t.Setenv(EnvPrefixMax, "0")
	_, reg, _ := rtWire(t)
	for _, p := range reg.Provers(finality.ChainBaseSepolia) {
		if x, ok := p.(*baseposted.Builder); ok && x.Prefix.Enabled() {
			t.Fatalf("CERTEN_FINALITY_PREFIX_MAX_BLOCKS=0 is off: %+v", x.Prefix)
		}
	}
}

// gauge reads one sample of the default registry.
func gauge(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
	next:
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					continue next
				}
			}
			if m.GetGauge() != nil {
				return m.GetGauge().GetValue(), true
			}
			if m.GetCounter() != nil {
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

func TestRB12PrefixGaugesAreLiveFromTheFirstTickAndTheAlertCanFire(t *testing.T) {
	metrics.RegisterMetrics()
	ctx := context.Background()
	mem := finality.NewMemCaptureStore()
	c := finality.ChainBaseSepolia
	_ = finality.RecordGap(ctx, mem, c, 1000, 1019, finality.GapCapturePrefix) // window A: open
	_ = finality.RecordGap(ctx, mem, c, 2000, 2009, finality.GapCapturePrefix) // window B: holds a block proven unavailable
	_ = finality.RecordGap(ctx, mem, c, 3000, 3004, finality.GapCapturePrefix) // window C: complete
	_ = finality.RecordGapSlot(ctx, mem, c, 2003, 777)
	_ = finality.RecordGapEnd(ctx, mem, c, 2003, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a", "b"}})
	for n := uint64(3000); n <= 3004; n++ {
		_ = finality.RecordGapFill(ctx, mem, c, n, [32]byte{1, byte(n)}, false)
	}
	for n := uint64(2000); n <= 2009; n++ {
		if n != 2003 {
			_ = finality.RecordGapFill(ctx, mem, c, n, [32]byte{2, byte(n)}, false)
		}
	}
	fc := &bfFakeCap{}
	l, lg := newGapLoop(t, mem, fc)
	l.PerTick = 1
	if err := l.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{"open": 1, "unavailable_proven": 1, "complete": 1, "retention_expired": 0}
	for state, v := range want {
		if got, ok := gauge(t, "certen_finality_prefix_windows", map[string]string{"chain": "84532", "state": state}); !ok || got != v {
			t.Errorf("certen_finality_prefix_windows{state=%s} = %v (%v), want %v", state, got, ok, v)
		}
	}
	if got, ok := gauge(t, "certen_finality_prefix_requested_blocks", map[string]string{"chain": "84532"}); !ok || got != 20+10+5 {
		t.Errorf("requested blocks %v %v", got, ok)
	}
	if got, ok := gauge(t, "certen_finality_prefix_backfilled_blocks_total", map[string]string{"chain": "84532"}); !ok || got < 1 {
		t.Errorf("one prefix block was captured in the tick: %v %v", got, ok)
	}
	if !lg.has("prefix windows requested") || !lg.has("blob archive") {
		t.Fatalf("the windows that need an archive are named in the log: %v", lg.lines)
	}
	// with nothing requested the gauges are still set (zero), not absent: an alert on absence cannot be mistaken for 'all well'
	l2, _ := newGapLoop(t, finality.NewMemCaptureStore(), fc)
	if err := l2.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if got, ok := gauge(t, "certen_finality_prefix_windows", map[string]string{"chain": "84532", "state": "open"}); !ok || got != 0 {
		t.Errorf("after a tick over an empty store the gauge is zero: %v %v", got, ok)
	}
}
