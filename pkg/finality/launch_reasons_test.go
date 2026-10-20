// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A chain switched off because a provider setting is missing is announced AT LAUNCH, once, as finality_upgrader_disabled with
// the reason that names the missing setting (not as its CERTEN_FINALITY_CHAIN_<id>_ENABLED switch), whether or not a leg of the
// chain exists, and the worker does not announce it a second time when a leg of the chain turns up (RB11-B2B2b).
func TestLaunchAnnouncesAMissingProviderSettingByNameOnceAtLaunch(t *testing.T) {
	logs := &logSink{}
	const missing = "BASE_SEPOLIA_RPC_URL"
	reasons := map[uint64]*StateError{ChainBaseSepolia: NewState(CodeUpgraderDisabled, "chain", ChainBaseSepolia, "env", missing, "value", "unset",
		"effect", "no finality addenda are appended for chain 84532")}
	src := &memSource{legs: []LegRef{{ProofID: "00000000-0000-4000-8000-000000000001", Chain: ChainBaseSepolia}}, settlements: map[string]Settlement{}}
	ctx, cancel := context.WithCancel(context.Background())
	u, err := Launch(ctx, true, src, newMemStore(), NewRegistry(), nil, UpgraderConfig{
		Interval: 20 * time.Millisecond, Logf: logs.Logf,
		DisabledChains:  map[uint64]bool{ChainBaseSepolia: true, ChainArbitrumSepolia: true},
		DisabledReasons: reasons,
	})
	if err != nil || u == nil {
		t.Fatalf("%v %v", err, u)
	}
	deadline := time.Now().Add(5 * time.Second)
	for src.listed.Load() < 3 && time.Now().Before(deadline) { // several passes, with the Base leg listed in each
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	out := logs.Joined()
	if n := strings.Count(out, "chain 84532 upgrader DISABLED"); n != 1 {
		t.Fatalf("chain 84532 announced %d times, want once:\n%s", n, out)
	}
	if !strings.Contains(out, "env="+missing) && !strings.Contains(out, missing) {
		t.Fatalf("the announcement does not name the missing setting %s:\n%s", missing, out)
	}
	if strings.Contains(out, "CERTEN_FINALITY_CHAIN_84532_ENABLED") {
		t.Fatalf("a missing provider setting was announced as the chain's switch:\n%s", out)
	}
	// a chain with no reason of its own is announced as its switch, also at launch although it has no leg
	if n := strings.Count(out, "chain 421614 upgrader DISABLED"); n != 1 || !strings.Contains(out, ChainEnv(ChainArbitrumSepolia)) {
		t.Fatalf("chain 421614: announced %d times, or not as its switch:\n%s", n, out)
	}
}
