// Copyright 2026 Certen Protocol

package config

import "testing"

// RB3-F44: an unconfigured chain has no configuration - never the Ethereum one - and only the chains
// CERTEN settles on are loaded, with no contract address compiled in.
func TestEVMChainConfigIsOnlyTheSupportedChainsAndNeverDefaulted(t *testing.T) {
	for _, k := range []string{"ETHEREUM_URL", "SEPOLIA_ACCOUNTFACTORY_V6_ADDRESS", "SEPOLIA_ACCOUNTFACTORY_ADDRESS"} {
		t.Setenv(k, "")
	}
	t.Setenv("ETHEREUM_SEPOLIA_RPC_URL", "http://sepolia.invalid")
	t.Setenv("BASE_SEPOLIA_RPC_URL", "http://base.invalid")
	t.Setenv("ARBITRUM_SEPOLIA_RPC_URL", "")
	t.Setenv("OPTIMISM_SEPOLIA_RPC_URL", "http://optimism.invalid")
	t.Setenv("HEDERA_TESTNET_RPC_URL", "http://hedera.invalid")

	c := &AnchorConfig{}
	c.Network.Ethereum.ChainID = 11155111
	c.Network.Ethereum.RPCURL = "http://sepolia.invalid"
	c.Network.EVMChains = loadEVMChainsFromEnv()

	if len(c.Network.EVMChains) != 2 || c.Network.EVMChains[11155111] == nil || c.Network.EVMChains[84532] == nil {
		t.Fatalf("loaded chains %v, want Sepolia and Base (Arbitrum has no RPC; Optimism and Hedera are not supported)", keys(c.Network.EVMChains))
	}
	if got := c.GetEVMChainConfig(421614); got != nil {
		t.Fatalf("an unconfigured chain answered with %+v; it must have no configuration", got)
	}
	if got := c.GetEVMChainConfig(84532); got.RPCURL != "http://base.invalid" || got.ChainID != 84532 {
		t.Fatalf("Base: %+v", got)
	}
	if f := c.GetEVMChainConfig(11155111).AccountFactory; f != "" {
		t.Fatalf("an unset account factory defaulted to %s", f)
	}
}

func keys(m map[int64]*EVMChainConfig) []int64 {
	var out []int64
	for k := range m {
		out = append(out, k)
	}
	return out
}
