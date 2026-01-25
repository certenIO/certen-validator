// Copyright 2025 Certen Protocol
//
// Strategy Registry - Central Registry for Attestation and Chain Strategies
// Manages pluggable strategies for multi-chain and multi-attestation support
//
// Per Unified Multi-Chain Architecture:
// - Single registry for all strategy types
// - Platform defaults for attestation schemes
// - Dynamic strategy registration and lookup

package strategy

import (
	"fmt"
	"sync"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// =============================================================================
// STRATEGY REGISTRY
// =============================================================================

// Registry manages attestation and chain execution strategies
type Registry struct {
	mu sync.RWMutex

	// Attestation strategies indexed by scheme
	attestationStrategies map[attestation.AttestationScheme]attestation.AttestationStrategy

	// Chain execution strategies indexed by chainID
	chainStrategies map[string]chain.ChainExecutionStrategy

	// Chain configs indexed by chainID
	chainConfigs map[string]*chain.ChainConfig

	// Platform defaults for attestation schemes
	platformDefaults map[chain.ChainPlatform]attestation.AttestationScheme

	// Default chain for operations
	defaultChainID string
}

// NewRegistry creates a new strategy registry with default platform mappings
func NewRegistry() *Registry {
	return &Registry{
		attestationStrategies: make(map[attestation.AttestationScheme]attestation.AttestationStrategy),
		chainStrategies:       make(map[string]chain.ChainExecutionStrategy),
		chainConfigs:          make(map[string]*chain.ChainConfig),
		platformDefaults: map[chain.ChainPlatform]attestation.AttestationScheme{
			// BLS12-381 for EVM chains - ZK-verified on-chain aggregation
			chain.ChainPlatformEVM: attestation.AttestationSchemeBLS12381,

			// Ed25519 for all other chains - native support, lower cost
			chain.ChainPlatformCosmWasm: attestation.AttestationSchemeEd25519,
			chain.ChainPlatformSolana:   attestation.AttestationSchemeEd25519,
			chain.ChainPlatformMove:     attestation.AttestationSchemeEd25519,
			chain.ChainPlatformTON:      attestation.AttestationSchemeEd25519,
			chain.ChainPlatformNEAR:     attestation.AttestationSchemeEd25519,
		},
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

// GetAttestationStrategyForPlatform gets the default attestation strategy for a platform
func (r *Registry) GetAttestationStrategyForPlatform(platform chain.ChainPlatform) (attestation.AttestationStrategy, error) {
	r.mu.RLock()
	scheme, exists := r.platformDefaults[platform]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no default attestation scheme for platform: %s", platform)
	}

	return r.GetAttestationStrategy(scheme)
}

// HasAttestationStrategy checks if a strategy is registered for a scheme
func (r *Registry) HasAttestationStrategy(scheme attestation.AttestationScheme) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.attestationStrategies[scheme]
	return exists
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

// RegisterChainStrategy registers a chain execution strategy
func (r *Registry) RegisterChainStrategy(chainID string, config *chain.ChainConfig, strategy chain.ChainExecutionStrategy) error {
	if strategy == nil {
		return fmt.Errorf("chain strategy cannot be nil")
	}
	if config == nil {
		return fmt.Errorf("chain config cannot be nil")
	}
	if chainID == "" {
		return fmt.Errorf("chain ID cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.chainStrategies[chainID]; exists {
		return fmt.Errorf("chain strategy already registered for chain: %s", chainID)
	}

	r.chainStrategies[chainID] = strategy
	r.chainConfigs[chainID] = config

	// Set as default if this is the first chain registered
	if r.defaultChainID == "" {
		r.defaultChainID = chainID
	}

	return nil
}

// GetChainStrategy retrieves a chain execution strategy by chain ID
func (r *Registry) GetChainStrategy(chainID string) (chain.ChainExecutionStrategy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	strategy, exists := r.chainStrategies[chainID]
	if !exists {
		return nil, fmt.Errorf("no chain strategy registered for chain: %s", chainID)
	}

	return strategy, nil
}

// GetChainConfig retrieves chain configuration by chain ID
func (r *Registry) GetChainConfig(chainID string) (*chain.ChainConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.chainConfigs[chainID]
	if !exists {
		return nil, fmt.Errorf("no chain config registered for chain: %s", chainID)
	}

	return config, nil
}

// HasChainStrategy checks if a strategy is registered for a chain
func (r *Registry) HasChainStrategy(chainID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.chainStrategies[chainID]
	return exists
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

// ListChainsByPlatform returns chain IDs for a specific platform
func (r *Registry) ListChainsByPlatform(platform chain.ChainPlatform) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0)
	for id, config := range r.chainConfigs {
		if config.Platform == platform {
			ids = append(ids, id)
		}
	}
	return ids
}

// =============================================================================
// COMBINED STRATEGY LOOKUP
// =============================================================================

// GetAttestationSchemeForChain returns the attestation scheme for a specific chain
func (r *Registry) GetAttestationSchemeForChain(chainID string) (attestation.AttestationScheme, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	config, exists := r.chainConfigs[chainID]
	if !exists {
		return "", fmt.Errorf("no chain config for chain: %s", chainID)
	}

	// Use chain-specific override if set
	if config.AttestationScheme != "" {
		return config.AttestationScheme, nil
	}

	// Fall back to platform default
	scheme, exists := r.platformDefaults[config.Platform]
	if !exists {
		return "", fmt.Errorf("no default attestation scheme for platform: %s", config.Platform)
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

// =============================================================================
// DEFAULT CHAIN MANAGEMENT
// =============================================================================

// SetDefaultChain sets the default chain for operations
func (r *Registry) SetDefaultChain(chainID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.chainStrategies[chainID]; !exists {
		return fmt.Errorf("chain not registered: %s", chainID)
	}

	r.defaultChainID = chainID
	return nil
}

// GetDefaultChainID returns the default chain ID
func (r *Registry) GetDefaultChainID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.defaultChainID
}

// GetDefaultChainStrategy returns the default chain execution strategy
func (r *Registry) GetDefaultChainStrategy() (chain.ChainExecutionStrategy, error) {
	r.mu.RLock()
	defaultID := r.defaultChainID
	r.mu.RUnlock()

	if defaultID == "" {
		return nil, fmt.Errorf("no default chain configured")
	}

	return r.GetChainStrategy(defaultID)
}

// =============================================================================
// PLATFORM DEFAULT MANAGEMENT
// =============================================================================

// SetPlatformDefault sets the default attestation scheme for a platform
func (r *Registry) SetPlatformDefault(platform chain.ChainPlatform, scheme attestation.AttestationScheme) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.platformDefaults[platform] = scheme
}

// GetPlatformDefault returns the default attestation scheme for a platform
func (r *Registry) GetPlatformDefault(platform chain.ChainPlatform) (attestation.AttestationScheme, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	scheme, exists := r.platformDefaults[platform]
	return scheme, exists
}

// =============================================================================
// REGISTRY STATS
// =============================================================================

// Stats returns registry statistics
type Stats struct {
	AttestationSchemes int      `json:"attestation_schemes"`
	ChainStrategies    int      `json:"chain_strategies"`
	DefaultChain       string   `json:"default_chain"`
	RegisteredChains   []string `json:"registered_chains"`
}

// GetStats returns current registry statistics
func (r *Registry) GetStats() *Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	chains := make([]string, 0, len(r.chainStrategies))
	for id := range r.chainStrategies {
		chains = append(chains, id)
	}

	return &Stats{
		AttestationSchemes: len(r.attestationStrategies),
		ChainStrategies:    len(r.chainStrategies),
		DefaultChain:       r.defaultChainID,
		RegisteredChains:   chains,
	}
}

// =============================================================================
// GLOBAL REGISTRY
// =============================================================================

var (
	globalRegistry     *Registry
	globalRegistryOnce sync.Once
)

// GetGlobalRegistry returns the global strategy registry singleton
func GetGlobalRegistry() *Registry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewRegistry()
	})
	return globalRegistry
}

// SetGlobalRegistry replaces the global registry (for testing)
func SetGlobalRegistry(r *Registry) {
	globalRegistry = r
}
