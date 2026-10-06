// Copyright 2026 Certen Protocol

package config

import (
	"reflect"
	"testing"
	"time"
)

// clearChainEnv unsets every variable a catalogued chain's row reads, so a test states the whole environment.
func clearChainEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"ETHEREUM_URL", "ETHEREUM_SEPOLIA_RPC_URL", "ETHEREUM_SEPOLIA_WS_URL", "BASE_SEPOLIA_RPC_URL", "BASE_SEPOLIA_WS_URL",
		"ARBITRUM_SEPOLIA_RPC_URL", "ARBITRUM_SEPOLIA_WS_URL", "TELCOIN_ADIRI_RPC_URL", "TELCOIN_ADIRI_WS_URL",
		"SEPOLIA_ACCOUNTFACTORY_V6_ADDRESS", "SEPOLIA_ACCOUNTFACTORY_ADDRESS", "BASE_SEPOLIA_ACCOUNTFACTORY_V6_ADDRESS",
		"BASE_SEPOLIA_ACCOUNTFACTORY_ADDRESS", "ARBITRUM_SEPOLIA_ACCOUNTFACTORY_V6_ADDRESS", "ARBITRUM_SEPOLIA_ACCOUNTFACTORY_ADDRESS",
		"TELCOIN_ADIRI_ACCOUNTFACTORY_V6_ADDRESS", "TELCOIN_ADIRI_ACCOUNTFACTORY_ADDRESS",
	} {
		t.Setenv(k, "")
	}
	for _, g := range []string{"SEPOLIA", "BASE", "ARBITRUM", "TELCOIN_ADIRI"} {
		for _, s := range []string{"_MAX_GAS_PRICE_GWEI", "_MAX_PRIORITY_FEE_GWEI", "_GAS_LIMIT_ANCHOR"} {
			t.Setenv(g+s, "")
		}
	}
}

// The three live chains load exactly the rows the compiled table held at origin/main 0fc818e, under the same variables,
// with the same defaults - the catalogue changed where the rows come from, not what they are.
func TestTheLiveChainRowsAreUnchanged(t *testing.T) {
	clearChainEnv(t)
	t.Setenv("ETHEREUM_URL", "http://sepolia-legacy.invalid") // Sepolia's legacy name, read when its own is unset
	t.Setenv("ETHEREUM_SEPOLIA_WS_URL", "ws://sepolia.invalid")
	t.Setenv("SEPOLIA_ACCOUNTFACTORY_ADDRESS", "0x00000000000000000000000000000000000000f1")
	t.Setenv("BASE_SEPOLIA_RPC_URL", "http://base.invalid")
	t.Setenv("BASE_SEPOLIA_ACCOUNTFACTORY_V6_ADDRESS", "0x00000000000000000000000000000000000000f2")
	t.Setenv("BASE_SEPOLIA_ACCOUNTFACTORY_ADDRESS", "0x00000000000000000000000000000000000000ff")
	t.Setenv("ARBITRUM_SEPOLIA_RPC_URL", "http://arb.invalid")
	t.Setenv("ARBITRUM_MAX_GAS_PRICE_GWEI", "3")

	row := func(name string, id int64, rpc, ws, factory string, gas, prio, limit int64, explorer string) *EVMChainConfig {
		return &EVMChainConfig{Name: name, ChainID: id, RPCURL: rpc, WSURL: ws, RPCTimeout: Duration(30 * time.Second),
			MaxConnections: 10, MaxIdleConnections: 5, AccountFactory: factory, MaxGasPriceGwei: gas, MaxPriorityFeeGwei: prio,
			GasLimitAnchor: limit, ExplorerURL: explorer}
	}
	want := map[int64]*EVMChainConfig{
		11155111: row("Ethereum Sepolia", 11155111, "http://sepolia-legacy.invalid", "ws://sepolia.invalid",
			"0x00000000000000000000000000000000000000f1", 100, 2, 500000, "https://sepolia.etherscan.io"),
		84532: row("Base Sepolia", 84532, "http://base.invalid", "", "0x00000000000000000000000000000000000000f2", 1, 0, 2000000,
			"https://sepolia.basescan.org"),
		421614: row("Arbitrum Sepolia", 421614, "http://arb.invalid", "", "", 3, 0, 2000000, "https://sepolia.arbiscan.io"),
	}
	got := loadEVMChainsFromEnv()
	if !reflect.DeepEqual(got, want) {
		for id := range want {
			t.Logf("%d:\n got %+v\nwant %+v", id, got[id], want[id])
		}
		t.Fatalf("loaded %v", keys(got))
	}
}

// RB7 §4.2: Telcoin Adiri loads from its own variables, with its RPC, gas ceiling and anchor gas limit from the
// environment and no compiled-in address; without them it is absent, or carries no ceiling the batch path would accept.
func TestTelcoinAdiriLoadsFromItsOwnVariables(t *testing.T) {
	clearChainEnv(t)
	if c := loadEVMChainsFromEnv()[2017]; c != nil {
		t.Fatalf("2017 loaded with no RPC: %+v", c)
	}
	t.Setenv("TELCOIN_ADIRI_RPC_URL", "http://adiri.invalid")
	c := loadEVMChainsFromEnv()[2017]
	if c == nil || c.RPCURL != "http://adiri.invalid" || c.Name != "Telcoin Adiri" || c.ExplorerURL != "https://scan.telcoin.network" {
		t.Fatalf("2017: %+v", c)
	}
	if c.MaxGasPriceGwei != 0 || c.GasLimitAnchor != 0 || c.AccountFactory != "" {
		t.Fatalf("2017 carries a compiled default: %+v", c)
	}
	t.Setenv("TELCOIN_ADIRI_MAX_GAS_PRICE_GWEI", "250")
	t.Setenv("TELCOIN_ADIRI_GAS_LIMIT_ANCHOR", "3000000")
	t.Setenv("TELCOIN_ADIRI_MAX_PRIORITY_FEE_GWEI", "1")
	c = loadEVMChainsFromEnv()[2017]
	if c.MaxGasPriceGwei != 250 || c.GasLimitAnchor != 3000000 || c.MaxPriorityFeeGwei != 1 {
		t.Fatalf("2017 gas settings not read: %+v", c)
	}
	// Configured is not enabled: whether CERTEN settles on 2017 is CERTEN_SETTLEMENT_CHAINS alone.
	if !(&AnchorConfig{Network: NetworkSettings{EVMChains: loadEVMChainsFromEnv()}}).IsChainSupported(2017) {
		t.Fatal("a configured 2017 is not a configured catalogued chain")
	}
}
