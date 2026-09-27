// Copyright 2026 Certen Protocol

package strategy

import (
	"strings"
	"testing"
)

// RB3-F102: a strategy with several endpoints reads through its failover pool or is not built. The pool
// used to be dropped silently when it could not be created - here, on a cooldown that does not parse -
// leaving one connect-time endpoint that cannot observe an L2 leg.
func TestAStrategyIsNotBuiltWithoutItsFailoverPool(t *testing.T) {
	t.Setenv("ETHEREUM_RPC_COOLDOWN_SECONDS", "30s")
	_, err := NewEVMStrategy(&EVMStrategyConfig{ChainConfig: &ChainConfig{
		NetworkName: "base-sepolia",
		RPC:         "http://free.invalid",
		Endpoints:   []string{"http://free.invalid", "http://archive.invalid"},
	}})
	if err == nil || !strings.Contains(err.Error(), "ETHEREUM_RPC_COOLDOWN_SECONDS") {
		t.Fatalf("the strategy was built without its failover pool: %v", err)
	}
}
