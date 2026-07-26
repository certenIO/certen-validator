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
		"ethereum-sepolia":  "ethereum",
		"Ethereum Sepolia":  "ethereum",
		"ETHEREUM_SEPOLIA":  "ethereum",
		"ethereum  sepolia": "ethereum",
		"  Ethereum-Sepolia ": "ethereum",
		"sepolia":           "ethereum",
		"base-sepolia":      "base",
		"Base Sepolia":      "base",
		"arbitrum-sepolia":  "arbitrum",
		"Arbitrum Sepolia":  "arbitrum",
		"optimism-sepolia":  "optimism",
		"Optimism Sepolia":  "optimism",
		"polygon-amoy":      "polygon-amoy", // amoy is not in the suffix list; still stable
		"Solana Devnet":     "solana",
		"solana-devnet":     "solana",
		"Sui Testnet":       "sui",
		"Aptos Testnet":     "aptos",
		"NEAR Testnet":      "near",
		"TON Testnet":       "ton",
		"Cardano Preview":   "cardano",
		"Hedera Testnet":    "hedera",
		"BSC Testnet":       "bsc",
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
