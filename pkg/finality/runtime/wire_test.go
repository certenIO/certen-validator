// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// rtProviderEnv sets every provider variable to a dummy endpoint; a test then blanks the one it is about.
func rtProviderEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"ETHEREUM_URL": "https://sepolia.example/v2/k", "BASE_SEPOLIA_RPC_URL": "https://base.example/v2/k",
		"ARBITRUM_SEPOLIA_RPC_URL": "https://arb.example/v2/k", "TELCOIN_ADIRI_RPC_URL": "https://adiri.example/v2/k",
	} {
		t.Setenv(k, v)
	}
}

func rtWire(t *testing.T) (*Wiring, *finality.Registry, *syncBuf) {
	t.Helper()
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	reg := finality.NewRegistry()
	w, err := Wire(cfg, Deps{Registry: reg, Store: finality.NewMemCaptureStore(), Logf: logs.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return w, reg, logs
}

func TestRTWireNamesTheMissingProviderSettingOfEachChain(t *testing.T) {
	rtProviderEnv(t)
	t.Setenv("BASE_SEPOLIA_RPC_URL", "")
	w, reg, logs := rtWire(t)

	st := w.Disabled[finality.ChainBaseSepolia]
	if st == nil || st.Code != finality.CodeUpgraderDisabled || st.Fields["env"] != "BASE_SEPOLIA_RPC_URL" || st.Fields["value"] != "unset" {
		t.Fatalf("Base is off for a missing provider but the state is %v", st)
	}
	if w.Upgrader.DisabledReasons[finality.ChainBaseSepolia] != st || !w.Upgrader.DisabledChains[finality.ChainBaseSepolia] {
		t.Fatalf("the upgrader config does not carry the reason: %+v", w.Upgrader)
	}
	for _, c := range []uint64{finality.ChainSepolia, finality.ChainArbitrumSepolia, finality.ChainAdiri} {
		if w.Disabled[c] != nil || w.Upgrader.DisabledChains[c] {
			t.Fatalf("chain %d is configured yet off: %v", c, w.Disabled[c])
		}
	}
	if n := len(reg.Provers(finality.ChainBaseSepolia)); n != 0 {
		t.Fatalf("%d Base provers registered although the chain is off", n)
	}
	if n := len(reg.Provers(finality.ChainArbitrumSepolia)); n != 2 {
		t.Fatalf("%d Arbitrum provers, want the l1_posted and the finalized builder", n)
	}
	for _, c := range []uint64{finality.ChainSepolia, finality.ChainAdiri} {
		if n := len(reg.Provers(c)); n != 1 {
			t.Fatalf("chain %d has %d provers, want 1", c, n)
		}
	}
	caps := reg.Capturers()
	if len(caps) != 1 || caps[0].Chain() != finality.ChainArbitrumSepolia {
		t.Fatalf("capture loops %v: only the Arbitrum loop is expected while Base is off", caps)
	}
	if !strings.Contains(logs.String(), "chains_off_by_configuration=[84532]") || !strings.Contains(logs.String(), "pins_source=embedded") {
		t.Fatalf("the startup line does not report the chains off and the pins source:\n%s", logs.String())
	}
}

func TestRTWireTakesTheEnvironmentSwitchesAndBounds(t *testing.T) {
	rtProviderEnv(t)
	t.Setenv(finality.ChainEnv(finality.ChainAdiri), "false")
	t.Setenv(EnvConcurrency, "7")
	t.Setenv(EnvInterval, "13")
	t.Setenv(EnvBuildTimeout, "321")
	w, reg, _ := rtWire(t)
	if !w.Upgrader.DisabledChains[finality.ChainAdiri] || w.Upgrader.DisabledReasons[finality.ChainAdiri] != nil {
		t.Fatalf("the Adiri switch is off but the config says %+v", w.Upgrader)
	}
	if len(w.Disabled) != 0 {
		t.Fatalf("no provider is missing yet chains are named off by configuration: %v", w.Disabled)
	}
	if w.Upgrader.Concurrency != 7 || w.Upgrader.Interval != 13*time.Second || w.Upgrader.BuildTimeout != 321*time.Second {
		t.Fatalf("bounds not taken from the environment: %+v", w.Upgrader)
	}
	var names []string
	for _, c := range reg.Capturers() {
		names = append(names, c.Name())
	}
	if fmt.Sprint(names) != "[base-sepolia/inbox base-sepolia/gapfill arbitrum-sepolia/sequencer-inbox]" {
		t.Fatalf("capture loops %v, want the Base inbox loop, the Base gap backfill loop (RB12-CAPTURE-GAP) and the Arbitrum sequencer-inbox loop", names)
	}
	// a switch that is not a switch is refused by name (an *envvar.Refusal; the process announces switch_invalid)
	t.Setenv(finality.ChainEnv(finality.ChainBaseSepolia), "sometimes")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Wire(cfg, Deps{Registry: finality.NewRegistry(), Store: finality.NewMemCaptureStore()})
	if err == nil || !strings.Contains(err.Error(), finality.ChainEnv(finality.ChainBaseSepolia)) {
		t.Fatalf("a bad switch must be refused naming the variable: %v", err)
	}
}

func TestRTLoadPinsEmbeddedOrExplicitOverrideReportingItsSource(t *testing.T) {
	p, source, sha, err := LoadPins("")
	if err != nil || p == nil || source != finality.PinsSourceEmbedded || sha != finality.PinsSHA256 {
		t.Fatalf("%v %s %s", err, source, sha)
	}
	file := filepath.Join(t.TempDir(), "pins.json")
	if err := os.WriteFile(file, finality.EmbeddedPinsBytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, source, sha, err = LoadPins(file)
	if err != nil || !strings.HasPrefix(source, "override:") || source != "override:"+sha {
		t.Fatalf("an override must report its source: %v %s %s", err, source, sha)
	}
	if _, _, _, err = LoadPins(filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), EnvPinsFile) {
		t.Fatalf("a missing override file must name the variable: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`{"format":"nope"}`), 0o600)
	if _, _, _, err = LoadPins(bad); err == nil {
		t.Fatal("a pins file that does not parse was accepted")
	}
}

type rtLC struct{ calls *atomic.Int64 }

func (r rtLC) FinalizedAt(context.Context) (ethl1.LC, uint64, error) {
	r.calls.Add(1)
	return ethl1.LC{Profile: ethl1.ProfileLC}, 42, nil
}

func TestRTLightClientIsReusedOnlyWithinItsAge(t *testing.T) {
	var calls atomic.Int64
	now := time.Unix(1_760_000_000, 0)
	c := &lcCache{inner: rtLC{&calls}, now: func() time.Time { return now }}
	for i := 0; i < 3; i++ {
		if _, slot, err := c.FinalizedAt(context.Background()); err != nil || slot != 42 {
			t.Fatalf("%v %d", err, slot)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("%d fetches inside the age, want 1", calls.Load())
	}
	now = now.Add(lcAge - time.Second)
	_, _, _ = c.FinalizedAt(context.Background())
	if calls.Load() != 1 {
		t.Fatalf("refetched %v before the age", lcAge-time.Second)
	}
	now = now.Add(2 * time.Second)
	_, _, _ = c.FinalizedAt(context.Background())
	if calls.Load() != 2 {
		t.Fatalf("not refetched after the age: %d", calls.Load())
	}
}

func TestRTCaptureStatusProofIDsAreChainScopedAndRecognisable(t *testing.T) {
	a, b := CaptureStatusProofID(finality.ChainBaseSepolia), CaptureStatusProofID(finality.ChainArbitrumSepolia)
	if a == b || len(a) != 36 || !IsCaptureStatusProofID(a) || !IsCaptureStatusProofID(b) {
		t.Fatalf("%s %s", a, b)
	}
	if _, err := finality.ParseProofID(a); err != nil {
		t.Fatalf("the status store must accept the pseudo id: %v", err)
	}
	if IsCaptureStatusProofID("3f2504e0-4f89-41d3-9a0c-0305e82c3301") {
		t.Fatal("an ordinary proof id was taken for a capture row")
	}
	if a != "ffffffff-ffff-4fff-8fff-000000014a34" {
		t.Fatalf("chain 84532 -> %s", a)
	}
}
