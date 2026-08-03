package ethrpc

import (
	"fmt"
	"log"
	"os"
	"strconv"
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
