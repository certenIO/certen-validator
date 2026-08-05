package execution

import "testing"

// cost_events.chain is the JOIN KEY against the gateway's quotes table. If the two spellings
// diverge, every chain-keyed lookup returns zero rows and the gas estimator produces a median
// over an empty set — a zero estimate, with no error anywhere. These tests pin the spellings.

func TestCanonicalChainSlug_DisplayNameBecomesGatewaySlug(t *testing.T) {
	// The exact value that was written to all 197 production rows.
	slug, chainID := canonicalChainSlug("Ethereum Sepolia")
	if slug != "ethereum-sepolia" {
		t.Fatalf("slug = %q, want %q — this is the value that matched no quote and made the "+
			"pricing gate see zero events", slug, "ethereum-sepolia")
	}
	if chainID != 11155111 {
		t.Fatalf("chainID = %d, want 11155111", chainID)
	}
}

// Both "ethereum-sepolia" and the short "sepolia" appear in production data (419 and 234 rows).
// They must collapse to one spelling, or a GROUP BY chain reports two chains that are one.
func TestCanonicalChainSlug_AliasesCollapse(t *testing.T) {
	want := "ethereum-sepolia"
	for _, in := range []string{"sepolia", "Sepolia", "ETH-SEPOLIA", "eth-sepolia", " Ethereum Sepolia "} {
		if got, id := canonicalChainSlug(in); got != want || id != 11155111 {
			t.Errorf("canonicalChainSlug(%q) = (%q, %d), want (%q, 11155111)", in, got, id, want)
		}
	}
}

func TestCanonicalChainSlug_MatchesGatewayQuoteSpellings(t *testing.T) {
	// The chain values the gateway's quotes table actually holds.
	cases := map[string]struct {
		slug    string
		chainID int64
	}{
		"Base Sepolia":     {"base-sepolia", 84532},
		"base-sepolia":     {"base-sepolia", 84532},
		"Polygon Amoy":     {"polygon-amoy", 80002},
		"amoy":             {"polygon-amoy", 80002},
		"Arbitrum Sepolia": {"arbitrum-sepolia", 421614},
	}
	for in, want := range cases {
		gotSlug, gotID := canonicalChainSlug(in)
		if gotSlug != want.slug || gotID != want.chainID {
			t.Errorf("canonicalChainSlug(%q) = (%q, %d), want (%q, %d)",
				in, gotSlug, gotID, want.slug, want.chainID)
		}
	}
}

// Non-EVM chains have no EVM chain id. They must pass through with shape normalisation and a
// zero id rather than being dropped or mis-mapped onto an EVM chain's config.
func TestCanonicalChainSlug_NonEVMPassesThroughWithZeroID(t *testing.T) {
	for _, in := range []string{"solana-devnet", "near-testnet", "ton-testnet", "aptos-testnet", "sui-testnet"} {
		got, id := canonicalChainSlug(in)
		if got != in {
			t.Errorf("canonicalChainSlug(%q) = %q; non-EVM slugs are already canonical", in, got)
		}
		if id != 0 {
			t.Errorf("canonicalChainSlug(%q) returned chainID %d; non-EVM chains have no EVM id", in, id)
		}
	}
}

// Every name evmChainIDForName accepts must produce a canonical slug that maps BACK to the same
// id. Without this, adding an alias to one function and forgetting the other reintroduces
// exactly the split this fix closes.
func TestCanonicalChainSlug_RoundTripsForEveryKnownName(t *testing.T) {
	names := []string{
		"ethereum", "eth", "ethereum-sepolia", "eth-sepolia", "sepolia",
		"arbitrum", "arb", "arbitrum-one", "arbitrum-sepolia",
		"optimism", "op", "op-mainnet", "optimism-sepolia", "op-sepolia",
		"base", "base-mainnet", "base-sepolia",
		"polygon", "matic", "polygon-amoy", "amoy",
		"bsc", "binance", "bsc-testnet",
		"moonbeam", "moonbase", "moonbase-alpha", "moonbeam-moonbase-alpha",
		"hedera", "hedera-testnet", "hedera-mainnet",
	}
	for _, n := range names {
		slug, id := canonicalChainSlug(n)
		if id == 0 {
			t.Errorf("canonicalChainSlug(%q) returned chainID 0 for a known EVM name", n)
			continue
		}
		backID, ok := evmChainIDForName(slug)
		if !ok {
			t.Errorf("canonical slug %q (from %q) is not accepted by evmChainIDForName — the "+
				"two maps have drifted", slug, n)
			continue
		}
		if backID != id {
			t.Errorf("%q -> slug %q -> id %d, want %d", n, slug, backID, id)
		}
	}
}

func TestCanonicalChainSlug_EmptyIsEmpty(t *testing.T) {
	if slug, id := canonicalChainSlug("   "); slug != "" || id != 0 {
		t.Fatalf("blank chain produced (%q, %d), want (\"\", 0)", slug, id)
	}
}
