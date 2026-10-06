// Copyright 2026 Certen Protocol

package execution

import "testing"

// RB7 Task 4 (V-2): the name and slug tables read the chain catalogue. For every chain id and name they knew at origin/main
// 0fc818e they answer byte-for-byte as before - except "arb", fixed below - and Telcoin Adiri (2017) gets its own names
// instead of a placeholder.

func TestAnchorRowChainLabelsComeFromTheCatalogue(t *testing.T) {
	for id, want := range map[int64]string{
		11155111: "sepolia", 84532: "base-sepolia", 421614: "arbitrum-sepolia", // unchanged
		2017: "telcoin-adiri", // was chain-2017
		10:   "chain-10", 42161: "chain-42161", 0: "chain-0",
	} {
		if got := chainName(id); got != want {
			t.Fatalf("chainName(%d) = %q, want %q", id, got, want)
		}
	}
}

func TestNetworkNamesComeFromTheCatalogue(t *testing.T) {
	// Every entry of the map getNetworkName held at origin/main 0fc818e, unchanged, and 2017 (was unknown-2017).
	for id, want := range map[string]string{
		"1": "ethereum-mainnet", "11155111": "ethereum-sepolia", "137": "polygon-mainnet", "80001": "polygon-mumbai",
		"80002": "polygon-amoy", "42161": "arbitrum-one", "421614": "arbitrum-sepolia", "10": "optimism-mainnet",
		"11155420": "optimism-sepolia", "8453": "base-mainnet", "84532": "base-sepolia", "43114": "avalanche-mainnet",
		"43113": "avalanche-fuji", "56": "bsc-mainnet", "97": "bsc-testnet", "1284": "moonbeam", "1287": "moonbase-alpha",
		"2494104990": "tron-shasta", "728126428": "tron-mainnet", "101": "solana-mainnet", "103": "solana-devnet",
		"397": "near-mainnet", "398": "near-testnet", "2": "aptos-testnet", "sui-testnet": "sui-testnet",
		"sui-mainnet": "sui-mainnet", "-3": "ton-testnet", "-239": "ton-mainnet",
		"2017": "telcoin-adiri", "424242": "unknown-424242", "": "unknown-",
	} {
		if got := getNetworkName(id); got != want {
			t.Fatalf("getNetworkName(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestCostSlugsComeFromTheCatalogue(t *testing.T) {
	// The canonical slug of every id the table knew, unchanged, and 2017's.
	for id, want := range map[int64]string{
		1: "ethereum", 11155111: "ethereum-sepolia", 42161: "arbitrum", 421614: "arbitrum-sepolia", 10: "optimism",
		11155420: "optimism-sepolia", 8453: "base", 84532: "base-sepolia", 137: "polygon", 80002: "polygon-amoy", 56: "bsc",
		97: "bsc-testnet", 1284: "moonbeam", 1287: "moonbase-alpha", 296: "hedera-testnet", 295: "hedera-mainnet",
		2017: "telcoin-adiri",
	} {
		if got, ok := evmCanonicalSlugForChainID(id); !ok || got != want {
			t.Fatalf("slug(%d) = %q %v, want %q", id, got, ok, want)
		}
	}
	// Every name the table accepted, except "arb", resolves as before; Telcoin Adiri's names resolve to 2017.
	for name, want := range map[string]int64{
		"ethereum": 1, "eth": 1, "ethereum-sepolia": 11155111, "eth-sepolia": 11155111, "sepolia": 11155111,
		"arbitrum": 42161, "arbitrum-one": 42161, "arbitrum-sepolia": 421614, "optimism": 10, "op": 10, "op-mainnet": 10,
		"optimism-sepolia": 11155420, "op-sepolia": 11155420, "base": 8453, "base-mainnet": 8453, "base-sepolia": 84532,
		"polygon": 137, "matic": 137, "polygon-amoy": 80002, "amoy": 80002, "bsc": 56, "binance": 56, "bsc-testnet": 97,
		"moonbeam": 1284, "moonbase": 1287, "moonbase-alpha": 1287, "moonbeam-moonbase-alpha": 1287, "hedera": 296,
		"hedera-testnet": 296, "hedera-mainnet": 295,
		"telcoin-adiri": 2017, "adiri": 2017, "tel-adiri": 2017,
	} {
		if got, ok := evmChainIDForName(name); !ok || got != want {
			t.Fatalf("id(%q) = %d %v, want %d", name, got, ok, want)
		}
	}
	if slug, id := canonicalChainSlugForChainID(2017); slug != "telcoin-adiri" || id != 2017 {
		t.Fatalf("2017 cost events are attributed to (%q, %d)", slug, id)
	}
	if slug, id := canonicalChainSlug("Telcoin Adiri"); slug != "telcoin-adiri" || id != 2017 {
		t.Fatalf("canonicalChainSlug(Telcoin Adiri) = (%q, %d)", slug, id)
	}
}

// "arb" resolved to 42161, Arbitrum ONE - mainnet, never settled on by this fleet - so a cost event labelled "arb" was
// attributed to a chain it never touched. It names no chain now, and passes through unattributed rather than misattributed.
func TestArbNoLongerResolvesToArbitrumMainnet(t *testing.T) {
	if id, ok := evmChainIDForName("arb"); ok {
		t.Fatalf(`"arb" resolves to chain %d`, id)
	}
	if slug, id := canonicalChainSlug("arb"); slug != "arb" || id != 0 {
		t.Fatalf(`canonicalChainSlug("arb") = (%q, %d)`, slug, id)
	}
}

// Whether a contract's block.number is the parent chain's comes from the catalogue: Arbitrum Sepolia yes (as before),
// Telcoin Adiri no, and Arbitrum One (not catalogued) yes, as before.
func TestContractBlockIsL1ComesFromTheCatalogue(t *testing.T) {
	for id, want := range map[int64]bool{421614: true, 42161: true, 84532: false, 11155111: false, 2017: false, 10: false} {
		if got := contractBlockIsL1(id); got != want {
			t.Fatalf("contractBlockIsL1(%d) = %v", id, got)
		}
	}
}
