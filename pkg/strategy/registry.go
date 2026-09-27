// Copyright 2025 Certen Protocol
//
// Strategy Registry - the proof cycle's chain observers and attestation schemes.
//
// Chains are keyed by their decimal chain id and only the chains CERTEN settles on are accepted
// (ChainKey): a lookup by a network name or an unsupported chain is refused, never resolved to some
// other chain. The only platform is EVM, attested with BLS12-381 (RB3-F44).

package strategy

import (
	"fmt"
	"sync"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// Registry manages attestation and chain execution strategies
type Registry struct {
	mu sync.RWMutex

	// Attestation strategies indexed by scheme
	attestationStrategies map[attestation.AttestationScheme]attestation.AttestationStrategy

	// Chain execution strategies and their configs, indexed by ChainKey
	chainStrategies map[string]chain.ChainExecutionStrategy
	chainConfigs    map[string]*chain.ChainConfig
}

// platformSchemes is the attestation scheme of each platform CERTEN settles on.
var platformSchemes = map[chain.ChainPlatform]attestation.AttestationScheme{
	// BLS12-381 for EVM chains - ZK-verified on-chain aggregation
	chain.ChainPlatformEVM: attestation.AttestationSchemeBLS12381,
}

// NewRegistry creates an empty strategy registry
func NewRegistry() *Registry {
	return &Registry{
		attestationStrategies: make(map[attestation.AttestationScheme]attestation.AttestationStrategy),
		chainStrategies:       make(map[string]chain.ChainExecutionStrategy),
		chainConfigs:          make(map[string]*chain.ChainConfig),
	}
}

// =============================================================================
// ATTESTATION STRATEGY MANAGEMENT
// =============================================================================

// RegisterAttestationStrategy registers an attestation strategy for a scheme
func (r *Registry) RegisterAttestationStrategy(strategy attestation.AttestationStrategy) error {
	if strategy == nil {
		return fmt.Errorf("attestation strategy cannot be nil")
	}

	scheme := strategy.Scheme()
	if !scheme.IsValid() {
		return fmt.Errorf("invalid attestation scheme: %s", scheme)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.attestationStrategies[scheme]; exists {
		return fmt.Errorf("attestation strategy already registered for scheme: %s", scheme)
	}

	r.attestationStrategies[scheme] = strategy
	return nil
}

// GetAttestationStrategy retrieves an attestation strategy by scheme
func (r *Registry) GetAttestationStrategy(scheme attestation.AttestationScheme) (attestation.AttestationStrategy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	strategy, exists := r.attestationStrategies[scheme]
	if !exists {
		return nil, fmt.Errorf("no attestation strategy registered for scheme: %s", scheme)
	}

	return strategy, nil
}

// ListAttestationSchemes returns all registered attestation schemes
func (r *Registry) ListAttestationSchemes() []attestation.AttestationScheme {
	r.mu.RLock()
	defer r.mu.RUnlock()

	schemes := make([]attestation.AttestationScheme, 0, len(r.attestationStrategies))
	for scheme := range r.attestationStrategies {
		schemes = append(schemes, scheme)
	}
	return schemes
}

// =============================================================================
// CHAIN STRATEGY MANAGEMENT
// =============================================================================

// RegisterChainStrategy registers a chain execution strategy under the chain's ChainKey.
func (r *Registry) RegisterChainStrategy(chainID string, config *chain.ChainConfig, strategy chain.ChainExecutionStrategy) error {
	if strategy == nil {
		return fmt.Errorf("chain strategy cannot be nil")
	}
	if config == nil {
		return fmt.Errorf("chain config cannot be nil")
	}
	key, err := ChainKey(chainID)
	if err != nil {
		return err
	}
	if key != chainID {
		return fmt.Errorf("chain %q must be registered under its chain id %s", chainID, key)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.chainStrategies[key]; exists {
		return fmt.Errorf("chain strategy already registered for chain: %s", key)
	}

	r.chainStrategies[key] = strategy
	r.chainConfigs[key] = config
	return nil
}

// GetChainStrategy retrieves a chain execution strategy by chain id ("11155111" or "evm-11155111")
func (r *Registry) GetChainStrategy(chainID string) (chain.ChainExecutionStrategy, error) {
	key, err := ChainKey(chainID)
	if err != nil {
		return nil, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	strategy, exists := r.chainStrategies[key]
	if !exists {
		return nil, fmt.Errorf("no chain strategy registered for chain: %s", key)
	}

	return strategy, nil
}

// GetChainConfig retrieves chain configuration by chain id
func (r *Registry) GetChainConfig(chainID string) (*chain.ChainConfig, error) {
	key, err := ChainKey(chainID)
	if err != nil {
		return nil, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.chainConfigs[key]
	if !exists {
		return nil, fmt.Errorf("no chain config registered for chain: %s", key)
	}

	return config, nil
}

// ListChainIDs returns all registered chain IDs
func (r *Registry) ListChainIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.chainStrategies))
	for id := range r.chainStrategies {
		ids = append(ids, id)
	}
	return ids
}

// =============================================================================
// COMBINED STRATEGY LOOKUP
// =============================================================================

// GetAttestationSchemeForChain returns the attestation scheme for a specific chain
func (r *Registry) GetAttestationSchemeForChain(chainID string) (attestation.AttestationScheme, error) {
	config, err := r.GetChainConfig(chainID)
	if err != nil {
		return "", err
	}

	// A chain-specific scheme, when its config names one
	if config.AttestationScheme != "" {
		return config.AttestationScheme, nil
	}

	scheme, exists := platformSchemes[config.Platform]
	if !exists {
		return "", fmt.Errorf("no attestation scheme for platform: %s", config.Platform)
	}

	return scheme, nil
}

// GetAttestationStrategyForChain returns the attestation strategy for a chain
func (r *Registry) GetAttestationStrategyForChain(chainID string) (attestation.AttestationStrategy, error) {
	scheme, err := r.GetAttestationSchemeForChain(chainID)
	if err != nil {
		return nil, err
	}

	return r.GetAttestationStrategy(scheme)
}

// GetStrategiesForChain returns both chain and attestation strategies for a chain
func (r *Registry) GetStrategiesForChain(chainID string) (chain.ChainExecutionStrategy, attestation.AttestationStrategy, error) {
	chainStrategy, err := r.GetChainStrategy(chainID)
	if err != nil {
		return nil, nil, fmt.Errorf("get chain strategy: %w", err)
	}

	attestStrategy, err := r.GetAttestationStrategyForChain(chainID)
	if err != nil {
		return nil, nil, fmt.Errorf("get attestation strategy: %w", err)
	}

	return chainStrategy, attestStrategy, nil
}
