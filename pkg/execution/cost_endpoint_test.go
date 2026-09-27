// Copyright 2026 Certen Protocol

package execution

import (
	"strings"
	"testing"
)

// RB3-F96: a chain's cost is measured on that chain's own node or not at all. A missing endpoint used
// to become ETHEREUM_URL - the Sepolia node - for a Base or Arbitrum transaction.
func TestCostIsMeasuredOnTheChainsOwnNodeOrNotAtAll(t *testing.T) {
	t.Setenv("VALIDATOR_ID", "validator-3")
	t.Setenv("ETHEREUM_URL", "http://sepolia-node.invalid")
	t.Setenv("ETHEREUM_SEPOLIA_RPC_URL", "http://sepolia-node.invalid")
	t.Setenv("BASE_SEPOLIA_RPC_URL", "")
	t.Setenv("ARBITRUM_SEPOLIA_RPC_URL", "http://arbitrum-node.invalid")

	if url, _, err := costEndpointForChain("base-sepolia"); err == nil {
		t.Fatalf("Base cost would be measured on %s, a node that never saw the transaction", url)
	}
	if url, _, err := costEndpointForChain("arbitrum-sepolia"); err != nil || url != "http://arbitrum-node.invalid" {
		t.Fatalf("Arbitrum cost endpoint (%q, %v); want its own node", url, err)
	}

	t.Setenv("REQUIRE_QUORUM", "flase")
	if _, _, err := costEndpointForChain("arbitrum-sepolia"); err == nil || !strings.Contains(err.Error(), "REQUIRE_QUORUM") {
		t.Fatalf("a configuration that does not load was ignored: %v", err)
	}
}
