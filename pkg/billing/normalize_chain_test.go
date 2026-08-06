package billing

import "testing"

// Chain names arrive in three shapes depending on the caller: the slug
// ("ethereum-sepolia"), the env-var form ("ETHEREUM_SEPOLIA"), and the display
// name ("Ethereum Sepolia"). All three must resolve to the same fee model.
//
// The display form silently failed: normalizeChain lowercased it to
// "ethereum sepolia" but the suffix list is hyphenated, so nothing matched and
// NewProbe returned "no fee model implemented". Cost events were dropped at the
// validator, so the chain never accumulated measured cost data and stayed
// unpriceable forever — with no error surfaced to the gateway.
func TestNormalizeChainAcceptsEverySpelling(t *testing.T) {
	cases := map[string]string{
		"ethereum-sepolia":    "ethereum",
		"Ethereum Sepolia":    "ethereum",
		"ETHEREUM_SEPOLIA":    "ethereum",
		"ethereum  sepolia":   "ethereum",
		"  Ethereum-Sepolia ": "ethereum",
		"sepolia":             "ethereum",
		"base-sepolia":        "base",
		"Base Sepolia":        "base",
		"arbitrum-sepolia":    "arbitrum",
		"Arbitrum Sepolia":    "arbitrum",
		"optimism-sepolia":    "optimism",
		"Optimism Sepolia":    "optimism",
		// Amoy is Polygon's testnet. This previously asserted "polygon-amoy" — the suffix was
		// missing from the list, so the name never reduced to a family. That is not "stable",
		// it is broken: all three callers want the family, so NewProbe found no fee model AND
		// NativeSymbolFor returned "", failing Validate on native_symbol. Every polygon-amoy
		// cost event was dropped before it was sent.
		"polygon-amoy":    "polygon",
		"Polygon Amoy":    "polygon",
		"moonbase-alpha":  "moonbeam",
		"Solana Devnet":   "solana",
		"solana-devnet":   "solana",
		"Sui Testnet":     "sui",
		"Aptos Testnet":   "aptos",
		"NEAR Testnet":    "near",
		"TON Testnet":     "ton",
		"Cardano Preview": "cardano",
		"Hedera Testnet":  "hedera",
		"BSC Testnet":     "bsc",
	}
	for in, want := range cases {
		if got := normalizeChain(in); got != want {
			t.Errorf("normalizeChain(%q) = %q, want %q", in, got, want)
		}
	}
}

// A fee model must resolve for every spelling, or the cost event is dropped.
func TestNewProbeResolvesDisplayNames(t *testing.T) {
	for _, name := range []string{
		"ethereum-sepolia", "Ethereum Sepolia", "ETHEREUM_SEPOLIA",
		"Base Sepolia", "Arbitrum Sepolia", "Optimism Sepolia",
		"Solana Devnet", "Sui Testnet", "Aptos Testnet", "NEAR Testnet",
	} {
		p, err := NewProbe(ProbeConfig{Chain: name, RPCURL: "http://localhost:1"})
		if err != nil {
			t.Errorf("NewProbe(%q) returned %v, want a fee model", name, err)
			continue
		}
		if p == nil {
			t.Errorf("NewProbe(%q) returned a nil probe", name)
		}
	}
}

// The guard that must NOT regress: an unknown chain still fails loudly rather
// than silently defaulting to the EVM model, which would mis-price it.
func TestNewProbeStillRejectsUnknownChains(t *testing.T) {
	if _, err := NewProbe(ProbeConfig{Chain: "dogecoin", RPCURL: "http://localhost:1"}); err == nil {
		t.Fatal("NewProbe(dogecoin) succeeded; an unknown chain must not silently get the EVM fee model")
	}
}

func TestNativeSymbolForAcceptsDisplayNames(t *testing.T) {
	cases := map[string]string{
		"Ethereum Sepolia": "ETH",
		"ethereum-sepolia": "ETH",
		"Base Sepolia":     "ETH",
		"Solana Devnet":    "SOL",
		"Sui Testnet":      "SUI",
		"NEAR Testnet":     "NEAR",
		"Hedera Testnet":   "HBAR",
	}
	for in, want := range cases {
		if got := NativeSymbolFor(in); got != want {
			t.Errorf("NativeSymbolFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// Testnet suffixes must reduce to the family the probe registry keys on, or the chain is dropped
// with "no fee model implemented" — silently, for every event.
//
// polygon-amoy was exactly that: "-amoy" was missing from the suffix list, so it never reached
// the "polygon" case and every cost event for the chain was discarded.
func TestNormalizeChainReducesEveryConfiguredTestnet(t *testing.T) {
	cases := map[string]string{
		"polygon-amoy":     "polygon",
		"moonbase-alpha":   "moonbeam",
		"base-sepolia":     "base",
		"arbitrum-sepolia": "arbitrum",
		"optimism-sepolia": "optimism",
		"bsc-testnet":      "bsc",
		"hedera-testnet":   "hedera",
		"ethereum-sepolia": "ethereum",
		"solana-devnet":    "solana",
		"aptos-testnet":    "aptos",
		"sui-testnet":      "sui",
		"near-testnet":     "near",
		"ton-testnet":      "ton",
		"tron-shasta":      "tron",
	}
	for in, want := range cases {
		if got := normalizeChain(in); got != want {
			t.Errorf("normalizeChain(%q) = %q, want %q — a chain that does not reduce is dropped "+
				"with 'no fee model implemented'", in, got, want)
		}
	}
}

// Every chain the fleet has RPC configured for must actually get a probe.
func TestEveryConfiguredChainHasAFeeModel(t *testing.T) {
	for _, chain := range []string{
		"ethereum-sepolia", "base-sepolia", "arbitrum-sepolia", "optimism-sepolia",
		"polygon-amoy", "bsc-testnet", "moonbase-alpha", "hedera-testnet",
		"solana-devnet", "aptos-testnet", "sui-testnet", "near-testnet", "ton-testnet",
		"tron-shasta",
	} {
		if _, err := NewProbe(ProbeConfig{Chain: chain, RPCURL: "http://x", Leg: LegAnchor}); err != nil {
			t.Errorf("no fee model for %q: %v — every cost event on this chain is dropped", chain, err)
		}
	}
}
