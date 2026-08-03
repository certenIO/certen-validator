package ethrpc

import (
	"strings"
	"testing"
)

// Ethereum must keep working from its original variables alone.
func TestEthereumKeepsLegacyVars(t *testing.T) {
	t.Setenv(EnvPrimary, "https://eth-primary")
	t.Setenv(EnvFallbacks, "https://eth-paid")
	got := EndpointsForChain("ethereum-sepolia")
	if len(got) < 2 || got[0] != "https://eth-primary" {
		t.Fatalf("ethereum lost its legacy config: %v", got)
	}
}

// A non-Ethereum chain resolves its own primary AND its own paid fallback.
//
// Without this, Base/Arbitrum/Optimism had a pool of one publicnode endpoint, which refuses every
// archive eth_getLogs — so a leg on those chains could never finish Phase 7.
func TestOtherChainGetsItsOwnFallbacks(t *testing.T) {
	t.Setenv("BASE_SEPOLIA_RPC_URL", "https://base-free")
	t.Setenv("INFURA_BASE_SEPOLIA_URL", "https://base-sepolia.infura.io/v3/k")
	got := EndpointsForChain("base-sepolia")
	if len(got) != 2 || got[0] != "https://base-free" || !strings.Contains(got[1], "infura") {
		t.Fatalf("base did not get a fallback tier: %v", got)
	}
}

// A chain must never silently borrow Ethereum's endpoints — that would observe the wrong chain.
func TestUnconfiguredChainDoesNotBorrowEthereum(t *testing.T) {
	t.Setenv(EnvPrimary, "https://eth-primary")
	if got := EndpointsForChain("optimism-sepolia"); len(got) != 0 {
		t.Fatalf("unconfigured chain borrowed endpoints: %v", got)
	}
	if _, err := PoolForChain("optimism-sepolia", nil); err == nil {
		t.Fatal("PoolForChain should fail closed for an unconfigured chain")
	}
}

func TestChainEnvPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"base-sepolia": "BASE_SEPOLIA", "Base Sepolia": "BASE_SEPOLIA", "arbitrum-sepolia": "ARBITRUM_SEPOLIA",
	} {
		if got := ChainEnvPrefix(in); got != want {
			t.Fatalf("%q → %q, want %q", in, got, want)
		}
	}
}
