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

// A watcher on one chain must never rotate onto another chain's endpoints.
//
// The pool was built from Ethereum's fallback vars no matter which chain was being watched, so a
// Base watcher would fall over to Ethereum Sepolia on the first refusal and filter logs from the
// wrong chain — succeeding, and meaning nothing.
func TestChainIDNeverBorrowsAnotherChainsEndpoints(t *testing.T) {
	t.Setenv(EnvFallbacks, "https://eth-sepolia-paid")
	t.Setenv(EnvInfura, "https://eth-infura")
	t.Setenv("INFURA_BASE_SEPOLIA_URL", "https://base-infura")

	got := EndpointsForChainID(84532, "https://base-free") // Base Sepolia
	for _, u := range got {
		if strings.Contains(u, "eth-") {
			t.Fatalf("base pool contains an Ethereum endpoint: %v", got)
		}
	}
	if len(got) != 2 || got[0] != "https://base-free" || got[1] != "https://base-infura" {
		t.Fatalf("unexpected base pool: %v", got)
	}
}

// An unknown chain gets its own URL only — never a borrowed fallback tier.
func TestUnknownChainIDGetsOnlyItsOwnURL(t *testing.T) {
	t.Setenv(EnvFallbacks, "https://eth-paid")
	got := EndpointsForChainID(999999, "https://mystery-chain")
	if len(got) != 1 || got[0] != "https://mystery-chain" {
		t.Fatalf("unknown chain borrowed endpoints: %v", got)
	}
}

// Ethereum keeps its existing tier when resolved by ID.
func TestEthereumChainIDKeepsItsTier(t *testing.T) {
	t.Setenv(EnvFallbacks, "https://eth-paid")
	got := EndpointsForChainID(11155111, "https://eth-free")
	if len(got) < 2 || got[0] != "https://eth-free" {
		t.Fatalf("ethereum lost its tier: %v", got)
	}
}
