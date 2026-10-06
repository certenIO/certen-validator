// Copyright 2026 Certen Protocol

package ethrpc

import (
	"testing"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// Every chain id maps to the key it mapped to at origin/main 0fc818e: the catalogue is now where the settled chains' keys
// come from, and nothing it answers moved.
func TestChainKeyForIDIsUnchangedForEveryChainItKnew(t *testing.T) {
	for id, want := range map[int64]string{
		1: "ethereum", 11155111: "ethereum-sepolia", 84532: "base-sepolia", 421614: "arbitrum-sepolia",
		11155420: "optimism-sepolia", 80002: "polygon-amoy", 97: "bsc-testnet", 1287: "moonbase-alpha", 296: "hedera-testnet",
		10: "", 8453: "", 42161: "", 0: "",
	} {
		if got := ChainKeyForID(id); got != want {
			t.Fatalf("ChainKeyForID(%d) = %q, want %q", id, got, want)
		}
	}
}

// Every catalogued chain's key and variable prefix are the catalogue's, so the configuration (which reads the catalogue's
// variable names) and the providers (which read ChainKeyForID's) can never name different variables.
func TestEveryCataloguedChainsKeyIsTheCataloguesOwn(t *testing.T) {
	for _, c := range supportedchains.All {
		if ChainKeyForID(c.ID) != c.RPCKey || ChainEnvPrefix(c.RPCKey) != c.EnvPrefix() {
			t.Fatalf("chain %d: key %q prefix %q, catalogue %q / %q", c.ID, ChainKeyForID(c.ID), ChainEnvPrefix(c.RPCKey),
				c.RPCKey, c.EnvPrefix())
		}
	}
}

// RB7 Task 4 (CODE_MAP V22): Telcoin Adiri's providers resolve from its own variables. Before, 2017 was unknown, its
// fallbacks were never read, and the agreeing reader saw one host and refused the chain at boot.
func TestTelcoinAdiriResolvesItsOwnProviders(t *testing.T) {
	t.Setenv("TELCOIN_ADIRI_RPC_URL", "https://rpc.adiri.invalid")
	t.Setenv("TELCOIN_ADIRI_URL_FALLBACKS", "https://second.adiri.invalid,https://third.adiri.invalid")
	t.Setenv(EnvFallbacks, "https://eth-sepolia-paid")
	got := EndpointsForChainID(2017, "https://rpc.adiri.invalid")
	want := []string{"https://rpc.adiri.invalid", "https://second.adiri.invalid", "https://third.adiri.invalid"}
	if len(got) != len(want) {
		t.Fatalf("2017 endpoints %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("2017 endpoints %v, want %v", got, want)
		}
	}
}
