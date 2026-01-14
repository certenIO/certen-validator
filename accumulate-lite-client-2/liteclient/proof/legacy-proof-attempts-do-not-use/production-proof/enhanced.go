// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package production_proof provides the enhanced production-ready proof system
// with features ported from the original accumulate-lite-client
package production_proof

import (
	"context"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/interfaces"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/manager"
)

// EnhancedProofSystem provides the complete enhanced proof system
type EnhancedProofSystem struct {
	manager interfaces.ProofManager
	config  *interfaces.ProofConfig
}

// NewEnhancedProofSystem creates a new enhanced proof system with all features
func NewEnhancedProofSystem(config *interfaces.ProofConfig) *EnhancedProofSystem {
	if config == nil {
		config = manager.DefaultProofConfig()
	}

	proofManager := manager.NewProductionProofManager(config)

	return &EnhancedProofSystem{
		manager: proofManager,
		config:  config,
	}
}

// NewEnhancedProofSystemWithEndpoints creates an enhanced system with custom endpoints
func NewEnhancedProofSystemWithEndpoints(apiEndpoint, cometEndpoint string) *EnhancedProofSystem {
	config := manager.DefaultProofConfig()
	config.APIEndpoint = apiEndpoint
	config.CometEndpoint = cometEndpoint

	return NewEnhancedProofSystem(config)
}

// Initialize initializes the enhanced proof system
func (e *EnhancedProofSystem) Initialize(backend interfaces.DataBackend) error {
	return e.manager.Initialize(backend)
}

// GenerateProof generates a proof using the default optimized strategy
func (e *EnhancedProofSystem) GenerateProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	return e.manager.GenerateProof(ctx, accountURL, e.config.DefaultStrategy)
}

// GenerateProofWithStrategy generates a proof using a specific strategy
func (e *EnhancedProofSystem) GenerateProofWithStrategy(
	ctx context.Context,
	accountURL string,
	strategy interfaces.ProofStrategy,
) (*interfaces.CompleteProof, error) {
	return e.manager.GenerateProof(ctx, accountURL, strategy)
}

// GenerateBatchProofs generates proofs for multiple accounts efficiently
func (e *EnhancedProofSystem) GenerateBatchProofs(
	ctx context.Context,
	accountURLs []string,
) (map[string]*interfaces.CompleteProof, error) {
	return e.manager.GenerateBatchProof(ctx, accountURLs)
}

// VerifyProof verifies a complete proof
func (e *EnhancedProofSystem) VerifyProof(proof *interfaces.CompleteProof) error {
	return e.manager.VerifyProof(proof)
}

// GetMetrics returns comprehensive system metrics
func (e *EnhancedProofSystem) GetMetrics() *interfaces.ProofSystemMetrics {
	return e.manager.GetMetrics()
}

// GetCacheMetrics returns cache-specific metrics
func (e *EnhancedProofSystem) GetCacheMetrics() *interfaces.ProofCacheMetrics {
	if cache := e.manager.GetCache(); cache != nil {
		return cache.GetProofCacheMetrics()
	}
	return nil
}

// EnableDebugMode enables comprehensive debug output
func (e *EnhancedProofSystem) EnableDebugMode() {
	e.manager.SetDebugMode(true)
	e.config.DebugMode = true
}

// DisableDebugMode disables debug output
func (e *EnhancedProofSystem) DisableDebugMode() {
	e.manager.SetDebugMode(false)
	e.config.DebugMode = false
}

// GetDebugInfo returns detailed debug information for an account
func (e *EnhancedProofSystem) GetDebugInfo(accountURL string) (*interfaces.DebugInfo, error) {
	return e.manager.GetDebugInfo(accountURL)
}

// UpdateConfiguration updates the system configuration
func (e *EnhancedProofSystem) UpdateConfiguration(config *interfaces.ProofConfig) error {
	if err := e.manager.UpdateConfig(config); err != nil {
		return err
	}
	e.config = config
	return nil
}

// GetConfiguration returns the current configuration
func (e *EnhancedProofSystem) GetConfiguration() *interfaces.ProofConfig {
	return e.manager.GetConfig()
}

// ClearCache clears all cached proofs
func (e *EnhancedProofSystem) ClearCache() error {
	if cache := e.manager.GetCache(); cache != nil {
		return cache.ClearProofCache()
	}
	return nil
}

// InvalidateAccountProof removes a specific account proof from cache
func (e *EnhancedProofSystem) InvalidateAccountProof(accountURL string) error {
	if cache := e.manager.GetCache(); cache != nil {
		return cache.InvalidateAccountProof(accountURL)
	}
	return nil
}

// Convenience methods for specific strategies

// GenerateMinimalProof generates a minimal proof (Layer 1 only, cache-first)
func (e *EnhancedProofSystem) GenerateMinimalProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	return e.manager.GenerateProof(ctx, accountURL, interfaces.StrategyMinimal)
}

// GenerateCompleteProof generates a complete proof (all layers, no cache shortcuts)
func (e *EnhancedProofSystem) GenerateCompleteProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	return e.manager.GenerateProof(ctx, accountURL, interfaces.StrategyComplete)
}

// GenerateDebugProof generates a proof with full debug output
func (e *EnhancedProofSystem) GenerateDebugProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	return e.manager.GenerateProof(ctx, accountURL, interfaces.StrategyDebug)
}

// Configuration presets

// NewHighPerformanceConfig returns a configuration optimized for high performance
func NewHighPerformanceConfig(apiEndpoint, cometEndpoint string) *interfaces.ProofConfig {
	config := manager.DefaultProofConfig()
	config.APIEndpoint = apiEndpoint
	config.CometEndpoint = cometEndpoint
	config.EnableCache = true
	config.CacheSize = 10000
	config.CacheTTL = 60 * time.Minute
	config.DefaultStrategy = interfaces.StrategyOptimized
	config.BatchSize = 100
	config.ParallelWorkers = 20
	config.Timeout = 30 * time.Second
	config.DebugMode = false
	config.StrictMode = false
	return config
}

// NewDevelopmentConfig returns a configuration optimized for development
func NewDevelopmentConfig(apiEndpoint, cometEndpoint string) *interfaces.ProofConfig {
	config := manager.DefaultProofConfig()
	config.APIEndpoint = apiEndpoint
	config.CometEndpoint = cometEndpoint
	config.EnableCache = true
	config.CacheSize = 100
	config.CacheTTL = 5 * time.Minute
	config.DefaultStrategy = interfaces.StrategyDebug
	config.BatchSize = 10
	config.ParallelWorkers = 2
	config.Timeout = 60 * time.Second
	config.DebugMode = true
	config.VerboseMode = true
	config.LogLevel = "verbose"
	config.StrictMode = true
	return config
}

// NewProductionConfig returns a configuration optimized for production
func NewProductionConfig(apiEndpoint, cometEndpoint string) *interfaces.ProofConfig {
	config := manager.DefaultProofConfig()
	config.APIEndpoint = apiEndpoint
	config.CometEndpoint = cometEndpoint
	config.EnableCache = true
	config.CacheSize = 5000
	config.CacheTTL = 30 * time.Minute
	config.DefaultStrategy = interfaces.StrategyOptimized
	config.BatchSize = 50
	config.ParallelWorkers = 10
	config.Timeout = 45 * time.Second
	config.DebugMode = false
	config.VerboseMode = false
	config.LogLevel = "basic"
	config.StrictMode = false
	config.RequireConsensus = true
	config.MinValidators = 3
	config.MaxRetries = 3
	config.RetryDelay = 2 * time.Second
	return config
}

// Compatibility with existing production proof interface

// VerifyAccountWithDetails provides compatibility with existing interfaces
func (e *EnhancedProofSystem) VerifyAccountWithDetails(accountURL *url.URL) (*ProofResult, error) {
	// Convert to string for internal processing
	accountURLStr := accountURL.String()

	// Generate proof using default strategy
	proof, err := e.GenerateProof(context.Background(), accountURLStr)
	if err != nil {
		return &ProofResult{
			TrustRequired: "error",
			ErrorMessage:  err.Error(),
		}, err
	}

	// Convert CompleteProof to ProofResult for compatibility
	result := &ProofResult{
		AccountHash:     proof.AccountHash,
		BPTRoot:         proof.BPTRoot,
		BlockHeight:     proof.BlockHeight,
		BlockHash:       proof.BlockHash,
		FullyVerified:   len(proof.AccountHash) > 0 && len(proof.BPTRoot) > 0 && len(proof.BlockHash) > 0,
		TrustRequired:   proof.TrustLevel,
		Layer3Available: proof.ValidatorProof != nil,
	}

	if proof.ValidatorProof != nil {
		result.ValidatorCount = len(proof.ValidatorProof.Validators)
		result.SignatureCount = len(proof.ValidatorProof.Signatures)
		result.Layer1Verified = true
		result.Layer2Verified = true
		result.Layer3Verified = proof.ValidatorProof.SignedPower > 0
	}

	return result, nil
}

// ProofResult maintains compatibility with existing proof result structure
type ProofResult struct {
	// Layer 1: Account → BPT
	AccountHash     []byte `json:"accountHash"`
	BPTRoot         []byte `json:"bptRoot"`
	Layer1Verified  bool   `json:"layer1Verified"`

	// Layer 2: BPT → Block
	BlockHeight     uint64 `json:"blockHeight"`
	BlockHash       []byte `json:"blockHash"`
	Layer2Verified  bool   `json:"layer2Verified"`

	// Layer 3: Block → Validators (when available)
	ValidatorCount  int    `json:"validatorCount"`
	SignatureCount  int    `json:"signatureCount"`
	Layer3Available bool   `json:"layer3Available"`
	Layer3Verified  bool   `json:"layer3Verified"`

	// Overall status
	FullyVerified   bool   `json:"fullyVerified"`
	TrustRequired   string `json:"trustRequired"` // "none" | "api" | "validators"
	ErrorMessage    string `json:"errorMessage,omitempty"`
}

// ConfigurableVerifier maintains compatibility with existing interfaces
type ConfigurableVerifier struct {
	*EnhancedProofSystem
	apiEndpoint   string
	cometEndpoint string
}

// NewConfigurableVerifier creates a verifier with custom endpoints for compatibility
func NewConfigurableVerifier(apiEndpoint, cometEndpoint string) *ConfigurableVerifier {
	if apiEndpoint == "" {
		apiEndpoint = "http://localhost:26660/v3"
	}
	if cometEndpoint == "" {
		cometEndpoint = "http://127.0.0.2:26657"
	}

	enhanced := NewEnhancedProofSystemWithEndpoints(apiEndpoint, cometEndpoint)

	return &ConfigurableVerifier{
		EnhancedProofSystem: enhanced,
		apiEndpoint:         apiEndpoint,
		cometEndpoint:       cometEndpoint,
	}
}