// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/metrics"
)

// scrape reads the sum of the series of a metric family whose labels contain want (a histogram counts its observations).
func scrape(t *testing.T, name string, want map[string]string) float64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	sum := 0.0
	for _, mf := range fams {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			ok := true
			for k, v := range want {
				found := false
				for _, l := range m.GetLabel() {
					found = found || (l.GetName() == k && l.GetValue() == v)
				}
				ok = ok && found
			}
			if !ok {
				continue
			}
			switch {
			case m.GetHistogram() != nil:
				sum += float64(m.GetHistogram().GetSampleCount())
			case m.GetCounter() != nil:
				sum += m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				sum += m.GetGauge().GetValue()
			}
		}
	}
	return sum
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSettingsFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, v := range []string{"", "0", "false", "off", "no", " OFF "} {
		set, dis := capture.SettingsFromEnv(env(map[string]string{capture.EnvSwitch: v}))
		if dis != nil || set.Enabled {
			t.Fatalf("switch %q: %+v %v (off is not an error)", v, set, dis)
		}
	}
	for _, v := range []string{"1", "true", "ON", "yes"} {
		set, dis := capture.SettingsFromEnv(env(map[string]string{capture.EnvSwitch: v}))
		if dis != nil || !set.Enabled || set.Concurrency != capture.DefaultConcurrency || set.Parallel != capture.DefaultParallel || set.MemoryBytes != capture.DefaultMemoryBytes {
			t.Fatalf("switch %q: %+v %v", v, set, dis)
		}
	}
	for _, v := range []string{"maybe", "2", "tru", "enabled"} {
		_, dis := capture.SettingsFromEnv(env(map[string]string{capture.EnvSwitch: v}))
		if dis == nil || dis.Reason != "switch_invalid" || dis.Setting != capture.EnvSwitch || strings.Contains(dis.Error(), v) {
			t.Fatalf("switch %q: %v (a bad switch is a named state and its value is never printed)", v, dis)
		}
	}
	on := func(k, v string) (capture.Settings, *capture.Disabled) {
		return capture.SettingsFromEnv(env(map[string]string{capture.EnvSwitch: "1", k: v}))
	}
	for _, c := range []struct {
		name    string
		ok, bad []string
		check   func(capture.Settings) bool
	}{
		{capture.EnvConcurrency, []string{"1", "16"}, []string{"0", "17", "-1", "x", "4.5", "99999999999999999999"}, func(s capture.Settings) bool { return s.Concurrency == 1 || s.Concurrency == 16 }},
		{capture.EnvParallel, []string{"1", "8"}, []string{"0", "9", "-3", "many"}, func(s capture.Settings) bool { return s.Parallel == 1 || s.Parallel == 8 }},
		{capture.EnvMemory, []string{fmt.Sprint(capture.MinMemoryBytes), fmt.Sprint(capture.MaxMemoryBytes)}, []string{fmt.Sprint(capture.MinMemoryBytes - 1), fmt.Sprint(capture.MaxMemoryBytes + 1), "0", "1GiB"},
			func(s capture.Settings) bool {
				return s.MemoryBytes == capture.MinMemoryBytes || s.MemoryBytes == capture.MaxMemoryBytes
			}},
	} {
		for _, v := range c.ok {
			if s, dis := on(c.name, v); dis != nil || !c.check(s) {
				t.Fatalf("%s=%s (inside the bounds): %+v %v", c.name, v, s, dis)
			}
		}
		for _, v := range c.bad {
			s, dis := on(c.name, v)
			if dis == nil || dis.Reason != "setting_invalid" || dis.Setting != c.name || s.Enabled || strings.Contains(dis.Error(), v) {
				t.Fatalf("%s=%s (outside the bounds): %+v %v", c.name, v, s, dis)
			}
		}
	}
	// a bad number while the switch is off is not examined: the capture is off either way
	if _, dis := capture.SettingsFromEnv(env(map[string]string{capture.EnvConcurrency: "x"})); dis != nil {
		t.Fatal("a bad number with the switch off was reported")
	}
}

func baseDeps(fc *fakeChain, st capture.Store) capture.Deps {
	return capture.Deps{Store: st, Manifest: fc.w.Manifest, Clock: ethproof.NewVirtualClock(time.Unix(1_700_000_000, 0)),
		SourceFor: func(uint64) (capture.AttestSource, error) { s, _ := fc.source(honest, honest); return s, nil }}
}

func enabled() capture.Settings {
	return capture.Settings{Enabled: true, Concurrency: 2, Parallel: 4, MemoryBytes: capture.DefaultMemoryBytes}
}

func TestRuntimeCapturesBothStationsAndTheStoredRowsAssembleTheWorldContainer(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	// the counter is process-global (other tests of this package capture on the same chain): the test reads the rise, not the absolute value
	capturedBefore := map[string]float64{}
	for _, station := range []string{"attest", "settle"} {
		capturedBefore[station] = scrape(t, "certen_contract_identity_capture_total", map[string]string{"chain": "11155111", "station": station, "outcome": "captured"})
	}
	st := capture.NewMemStore()
	rt, dis := capture.Start(context.Background(), enabled(), baseDeps(fc, st))
	if rt == nil || dis != nil {
		t.Fatalf("Start: %v", dis)
	}
	defer rt.Stop()
	facts := fc.facts(t)
	chain := int64(fc.w.Spec.Chain)
	if scrape(t, "certen_contract_identity_capture_enabled", nil) != 1 || scrape(t, "certen_contract_identity_capture_memory_bytes_budget", nil) != float64(capture.DefaultMemoryBytes) {
		t.Fatal("a started capture reports enabled=1 and its budget")
	}
	rt.AttestationObserved(chain, facts.AnchorID, fc.attTx, 0)
	rt.AttestationObserved(chain, facts.AnchorID, fc.attTx, 0) // the same transaction twice is one capture
	waitFor(t, "the attestation row", func() bool {
		_, ok, _ := st.Get(context.Background(), capture.Key{Chain: fc.w.Spec.Chain, AnchorID: facts.AnchorID, BlockHash: fc.w.BlockHashes["attest"], Item: capture.ItemAttest})
		return ok
	})
	rt.SettlementObserved(chain, fc.tx.Hash())
	waitFor(t, "the settlement row", func() bool {
		_, ok, _ := st.Get(context.Background(), capture.Key{Chain: fc.w.Spec.Chain, AnchorID: facts.AnchorID, BlockHash: fc.w.BlockHashes["settle"], Item: capture.ItemSettle})
		return ok
	})
	rt.Stop()
	if rt.MemoryInUse() != 0 {
		t.Fatalf("%d bytes still reserved", rt.MemoryInUse())
	}
	src, _ := fc.source(honest)
	att, err := capture.LoadAttest(context.Background(), st, fc.w.Spec.Chain, facts.AnchorID, fc.w.BlockHashes["attest"])
	set, err2 := capture.LoadSettle(context.Background(), st, fc.w.Spec.Chain, facts.AnchorID, fc.w.BlockHashes["settle"])
	if err != nil || err2 != nil || att == nil || set == nil || att.Stated != nil || set.Stated != nil {
		t.Fatalf("stored rows: %v %v %+v %+v", err, err2, att, set)
	}
	plan, err := capture.ChooseLink(fc.w.Manifest, fc.w.Spec.Chain, att.Block.Number, set.Block.Number, 0)
	if err != nil {
		t.Fatal(err)
	}
	part, err := capture.BuildAttestPart(context.Background(), src, att, fc.headers[set.Block.Number], plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := capture.Assemble(capture.Parts{Chain: fc.w.Spec.Chain, Leg: set.Block, Facts: facts, Settle: set, Attest: part})
	if err != nil || !bytes.Equal(got, fc.w.ContainerBytes) {
		t.Fatalf("the container built from the stored rows differs from the world's: %v", err)
	}
	for _, station := range []string{"attest", "settle"} {
		lbl := map[string]string{"chain": "11155111", "station": station, "outcome": "captured"}
		if got := scrape(t, "certen_contract_identity_capture_total", lbl) - capturedBefore[station]; got != 1 {
			t.Fatalf("%s: captured counter rose by %v, want exactly 1 (a duplicate trigger is one capture)", station, got)
		}
		if scrape(t, "certen_contract_identity_capture_seconds", map[string]string{"chain": "11155111", "station": station}) < 1 {
			t.Fatalf("%s: no duration observed", station)
		}
		if scrape(t, "certen_contract_identity_capture_inflight", map[string]string{"chain": "11155111", "station": station}) != 0 {
			t.Fatalf("%s: inflight did not return to 0", station)
		}
	}
	if h := metrics.ContractIdentityHealth(); h["capture_enabled"] != true || h["captured"].(uint64) < 2 {
		t.Fatalf("health = %v", h)
	}
}

// blockSource blocks its receipt read until released (a provider that has hung).
type blockSource struct {
	*fakeSource
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (b *blockSource) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-b.release:
		return nil, errors.New("released")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestRuntimeNeverBlocksTheCallerAndGaugesAreNonZeroWhileItWorks(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	hung := &blockSource{fakeSource: &fakeSource{fc: fc}, release: make(chan struct{}), started: make(chan struct{})}
	d := baseDeps(fc, capture.NewMemStore())
	d.SourceFor = func(uint64) (capture.AttestSource, error) { return hung, nil }
	set := capture.Settings{Enabled: true, Concurrency: 2, Parallel: 1, MemoryBytes: 2 * capture.WorkingSetBytes}
	rt, dis := capture.Start(context.Background(), set, d)
	if rt == nil {
		t.Fatal(dis)
	}
	base := runtime.NumGoroutine()
	const chain = 31337
	lbl := map[string]string{"chain": "31337", "station": "attest"}
	t0 := time.Now()
	for i := 0; i < 200; i++ { // 200 triggers into a capture whose providers hang: the caller is never held
		rt.AttestationObserved(chain, [32]byte{1}, common.BigToHash(big.NewInt(int64(i+1))), 0)
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("200 triggers took %v", d)
	}
	<-hung.started
	waitFor(t, "two captures running", func() bool { return scrape(t, "certen_contract_identity_capture_inflight", lbl) == 2 })
	if got := scrape(t, "certen_contract_identity_capture_memory_bytes_in_use", nil); got != float64(2*capture.WorkingSetBytes) {
		t.Fatalf("memory in use = %v, want the two reservations", got)
	}
	if rt.MemoryInUse() != 2*capture.WorkingSetBytes {
		t.Fatalf("MemoryInUse = %d", rt.MemoryInUse())
	}
	if scrape(t, "certen_contract_identity_capture_dropped_total", map[string]string{"chain": "31337", "station": "attest", "reason": "queue_full"}) < 100 {
		t.Fatal("triggers beyond the queue were not counted as dropped")
	}
	// the byte budget holds exactly two working sets: a third worker would be refused by name
	d2 := capture.Settings{Enabled: true, Concurrency: 3, Parallel: 1, MemoryBytes: 2 * capture.WorkingSetBytes}
	hung2 := &blockSource{fakeSource: &fakeSource{fc: fc}, release: make(chan struct{}), started: make(chan struct{})}
	dd := baseDeps(fc, capture.NewMemStore())
	dd.SourceFor = func(uint64) (capture.AttestSource, error) { return hung2, nil }
	rt2, _ := capture.Start(context.Background(), d2, dd)
	for i := 0; i < 3; i++ {
		rt2.AttestationObserved(31338, [32]byte{2}, common.BigToHash(big.NewInt(int64(i+1))), 0)
	}
	waitFor(t, "the third capture refused for the budget", func() bool {
		return scrape(t, "certen_contract_identity_capture_dropped_total", map[string]string{"chain": "31338", "station": "attest", "reason": "memory_budget"}) >= 1
	})
	if rt2.MemoryInUse() != 2*capture.WorkingSetBytes {
		t.Fatalf("budget: %d bytes reserved", rt2.MemoryInUse())
	}
	close(hung2.release)
	rt2.Stop()
	if rt2.MemoryInUse() != 0 {
		t.Fatal("the reservations were not released")
	}
	close(hung.release)
	rt.Stop()
	if rt.MemoryInUse() != 0 || scrape(t, "certen_contract_identity_capture_inflight", lbl) != 0 {
		t.Fatalf("after Stop: %d bytes, inflight %v", rt.MemoryInUse(), scrape(t, "certen_contract_identity_capture_inflight", lbl))
	}
	time.Sleep(50 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > base+2 {
		t.Fatalf("goroutines: %d before, %d after Stop", base, n)
	}
}

func TestRuntimeSurvivesAPanicAndKeepsWorking(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	st := capture.NewMemStore()
	calls := 0
	d := baseDeps(fc, st)
	good := d.SourceFor
	d.SourceFor = func(c uint64) (capture.AttestSource, error) {
		calls++
		if calls == 1 {
			panic("hostile source factory")
		}
		return good(c)
	}
	set := capture.Settings{Enabled: true, Concurrency: 1, Parallel: 1, MemoryBytes: capture.DefaultMemoryBytes}
	rt, _ := capture.Start(context.Background(), set, d)
	defer rt.Stop()
	chain := int64(fc.w.Spec.Chain)
	rt.AttestationObserved(chain, fc.facts(t).AnchorID, common.Hash{0xbb}, 0) // the panicking one
	waitFor(t, "the panic counted", func() bool {
		return scrape(t, "certen_contract_identity_capture_total", map[string]string{"chain": "11155111", "station": "attest", "outcome": "panic"}) >= 1
	})
	if rt.MemoryInUse() != 0 {
		t.Fatal("a recovered panic leaked its reservation")
	}
	rt.AttestationObserved(chain, fc.facts(t).AnchorID, fc.attTx, 0) // the worker is alive and captures
	waitFor(t, "the next capture", func() bool {
		_, ok, _ := st.Get(context.Background(), capture.Key{Chain: fc.w.Spec.Chain, AnchorID: fc.facts(t).AnchorID, BlockHash: fc.w.BlockHashes["attest"], Item: capture.ItemAttest})
		return ok
	})
	// a nil runtime and a runtime that was stopped ignore triggers
	var none *capture.Runtime
	none.AttestationObserved(1, [32]byte{}, common.Hash{1}, 0)
	none.SettlementObserved(1, common.Hash{1})
	rt.Stop()
	rt.AttestationObserved(chain, [32]byte{9}, common.Hash{0xcc}, 0)
}

func TestStartAnnouncesEveryDisabledStateByName(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	reason := func(r string) float64 {
		return scrape(t, "certen_contract_identity_capture_disabled_total", map[string]string{"reason": r})
	}
	for _, c := range []struct {
		reason string
		mutate func(*capture.Deps)
	}{
		{"no_durable_store", func(d *capture.Deps) { d.Store = nil }},
		{"manifest_unavailable", func(d *capture.Deps) { d.Manifest = nil }},
		{"no_chain_reader", func(d *capture.Deps) { d.SourceFor = nil }},
	} {
		d := baseDeps(fc, capture.NewMemStore())
		c.mutate(&d)
		before := reason(c.reason)
		rt, dis := capture.Start(context.Background(), enabled(), d)
		if rt != nil || dis == nil || dis.Reason != c.reason {
			t.Fatalf("%s: %v %v", c.reason, rt, dis)
		}
		if reason(c.reason) != before+1 || scrape(t, "certen_contract_identity_capture_enabled", nil) != 0 {
			t.Fatalf("%s: counter %v -> %v, enabled %v", c.reason, before, reason(c.reason), scrape(t, "certen_contract_identity_capture_enabled", nil))
		}
		if h := metrics.ContractIdentityHealth(); h["capture_enabled"] != false || h["capture_disabled_reason"] != c.reason {
			t.Fatalf("%s: health %v", c.reason, h)
		}
	}
	// off: no state to name, the health block says why it is not running
	rt, dis := capture.Start(context.Background(), capture.Settings{}, baseDeps(fc, capture.NewMemStore()))
	if rt != nil || dis != nil {
		t.Fatal("an off switch started or failed")
	}
	if h := metrics.ContractIdentityHealth(); h["capture_enabled"] != false || h["capture_disabled_reason"] != "switch_off" {
		t.Fatalf("health = %v", h)
	}
	// the reasons the code announces are exactly the closed list
	known := map[string]bool{}
	for _, r := range capture.DisabledReasons() {
		known[r] = true
	}
	for _, r := range []string{"no_durable_store", "manifest_unavailable", "no_chain_reader", "start_panicked", "switch_invalid", "setting_invalid"} {
		if !known[r] {
			t.Fatalf("reason %s is announced and not in DisabledReasons", r)
		}
	}
}

func TestAPanickingLoggerDoesNotStopTheCapture(t *testing.T) {
	fc := newFakeChain(t, 11155111, "h0")
	d := baseDeps(fc, capture.NewMemStore())
	d.Logf = func(string, ...interface{}) { panic("hostile logger") }
	rt, dis := capture.Start(context.Background(), enabled(), d)
	if rt == nil || dis != nil {
		t.Fatalf("Start with a hostile logger: %v", dis)
	}
	rt.Stop()
}
