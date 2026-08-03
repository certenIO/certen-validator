package ethrpc

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variables, in the order the pool will try them.
//
// The split exists so the cost ranking is explicit in configuration rather than implied by code.
// ETHEREUM_URL stays exactly what it has always been — the single primary endpoint every existing
// consumer reads — so nothing breaks for a deployment that never sets the fallback vars.
const (
	// EnvPrimary is the free/cheap endpoint tried first. Existing var; unchanged meaning.
	EnvPrimary = "ETHEREUM_URL"
	// EnvPrimaryAlt is consulted when EnvPrimary is unset, matching the existing config precedence.
	EnvPrimaryAlt = "ETHEREUM_SEPOLIA_RPC_URL"
	// EnvFallbacks is a comma-separated list of paid providers, used only when cheaper ones refuse.
	EnvFallbacks = "ETHEREUM_URL_FALLBACKS"
	// EnvInfura and EnvAlchemy are conveniences so each provider can be set on its own line.
	// Both are appended after EnvFallbacks, and duplicates are dropped.
	EnvInfura  = "INFURA_SEPOLIA_URL"
	EnvAlchemy = "ALCHEMY_SEPOLIA_URL"
	// EnvCooldownSeconds overrides how long a refusing endpoint is skipped.
	EnvCooldownSeconds = "ETHEREUM_RPC_COOLDOWN_SECONDS"
)

// EndpointsFromEnv builds the ordered endpoint list.
//
// Order is the cost ranking and is deliberate: free first, paid only as fallback. Callers that want
// a different order should set ETHEREUM_URL_FALLBACKS explicitly rather than relying on this.
func EndpointsFromEnv() []string {
	primary := os.Getenv(EnvPrimary)
	if primary == "" {
		primary = os.Getenv(EnvPrimaryAlt)
	}
	return ParseEndpoints(
		primary,
		os.Getenv(EnvFallbacks),
		os.Getenv(EnvInfura),
		os.Getenv(EnvAlchemy),
	)
}

// CooldownFromEnv reads the cooldown override, falling back to DefaultCooldown.
func CooldownFromEnv() time.Duration {
	if v := os.Getenv(EnvCooldownSeconds); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return DefaultCooldown
}

// FromEnv builds a Pool from the environment.
//
// A single-endpoint deployment gets a pool of one, which behaves exactly like the previous direct
// ethclient.Dial — so adopting this is safe before any fallback provider is configured.
func FromEnv(logger *log.Logger) (*Pool, error) {
	urls := EndpointsFromEnv()
	if len(urls) == 0 {
		return nil, fmt.Errorf("ethrpc: neither %s nor %s is set", EnvPrimary, EnvPrimaryAlt)
	}
	return NewPool(urls, CooldownFromEnv(), logger)
}

// =============================================================================
// PER-CHAIN ENDPOINTS
// =============================================================================
//
// The vars above are Ethereum-only (ETHEREUM_URL, INFURA_SEPOLIA_URL, …). Every other chain got a
// single publicnode endpoint and no fallback tier, so the moment one of them refuses an archive
// eth_getLogs — which publicnode always does — Phase 7 cannot observe a leg on that chain and the
// proof cycle stalls exactly as Ethereum's did from 2026-07-26 to 2026-08-03.
//
// That is invisible until a multi-leg intent spans networks, at which point the second leg fails
// for RPC reasons that look like an aggregation bug. Naming the vars by chain removes the trap:
// adding a chain is configuration, not code.

// ChainEnvPrefix converts a chain key to its environment-variable prefix.
//
// "base-sepolia" and "Base Sepolia" both become "BASE_SEPOLIA", so the caller can pass whatever
// spelling the intent used.
func ChainEnvPrefix(chainKey string) string {
	up := strings.ToUpper(strings.TrimSpace(chainKey))
	for _, sep := range []string{" ", "-", "."} {
		up = strings.ReplaceAll(up, sep, "_")
	}
	return up
}

// EndpointsForChain builds the ordered endpoint list for one chain, cheapest first.
//
// Reads <PREFIX>_RPC_URL as primary, then <PREFIX>_URL_FALLBACKS, INFURA_<PREFIX>_URL and
// ALCHEMY_<PREFIX>_URL as paid fallbacks. Ethereum keeps its existing variables: a deployment that
// has only ETHEREUM_URL set behaves exactly as before.
func EndpointsForChain(chainKey string) []string {
	p := ChainEnvPrefix(chainKey)
	if p == "" {
		return EndpointsFromEnv()
	}

	// Ethereum Sepolia is the chain the original vars were written for. Honour both spellings so
	// existing configuration keeps working and a per-chain override is still possible.
	if p == "ETHEREUM_SEPOLIA" || p == "SEPOLIA" || p == "ETHEREUM" {
		return ParseEndpoints(
			os.Getenv(p+"_RPC_URL"),
			os.Getenv(EnvPrimary),
			os.Getenv(EnvPrimaryAlt),
			os.Getenv(p+"_URL_FALLBACKS"),
			os.Getenv(EnvFallbacks),
			os.Getenv(EnvInfura),
			os.Getenv(EnvAlchemy),
		)
	}

	return ParseEndpoints(
		os.Getenv(p+"_RPC_URL"),
		os.Getenv(p+"_URL_FALLBACKS"),
		os.Getenv("INFURA_"+p+"_URL"),
		os.Getenv("ALCHEMY_"+p+"_URL"),
	)
}

// PoolForChain builds a Pool for one chain.
//
// Returns an error rather than falling back to Ethereum's endpoints: dialing the wrong chain would
// observe the wrong transactions and attest a result that never happened there.
func PoolForChain(chainKey string, logger *log.Logger) (*Pool, error) {
	urls := EndpointsForChain(chainKey)
	if len(urls) == 0 {
		return nil, fmt.Errorf("ethrpc: no endpoint configured for chain %q (set %s_RPC_URL)",
			chainKey, ChainEnvPrefix(chainKey))
	}
	return NewPool(urls, CooldownFromEnv(), logger)
}

// ChainKeyForID maps an EVM chain ID to the key used for its environment variables.
//
// Returns "" for a chain this build does not know, and callers must then fall back to that
// chain's own single URL rather than to Ethereum's — see EndpointsForChainID.
func ChainKeyForID(chainID int64) string {
	switch chainID {
	case 1:
		return "ethereum"
	case 11155111:
		return "ethereum-sepolia"
	case 84532:
		return "base-sepolia"
	case 421614:
		return "arbitrum-sepolia"
	case 11155420:
		return "optimism-sepolia"
	case 80002:
		return "polygon-amoy"
	case 97:
		return "bsc-testnet"
	case 1287:
		return "moonbase-alpha"
	case 296:
		return "hedera-testnet"
	}
	return ""
}

// EndpointsForChainID resolves a chain's endpoints from its numeric ID, with primary as the
// last-resort entry.
//
// NEVER mixes another chain's endpoints in. A pool built from Ethereum's fallback variables while
// watching Base would rotate onto Ethereum on the first refusal and observe an entirely different
// chain's logs — the observation would look successful and be meaningless. An unknown chain gets
// its own URL alone, which is strictly what it had before per-chain resolution existed.
func EndpointsForChainID(chainID int64, primary string) []string {
	key := ChainKeyForID(chainID)
	if key == "" {
		return ParseEndpoints(primary)
	}
	return ParseEndpoints(append([]string{primary}, EndpointsForChain(key)...)...)
}
