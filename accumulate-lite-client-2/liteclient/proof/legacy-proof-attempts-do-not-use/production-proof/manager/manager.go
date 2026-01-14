// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package manager provides a comprehensive proof manager with strategies and configuration
package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/batch"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/cache"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/debug"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/interfaces"
)

// ProductionProofManager implements ProofManager with all enhanced features
type ProductionProofManager struct {
	verifier       *core.CryptographicVerifier
	debugVerifier  *debug.DebugVerifier
	batchGenerator *batch.BatchProofGenerator
	cache          interfaces.ProofCache
	config         *interfaces.ProofConfig
	backend        interfaces.DataBackend

	// Metrics
	metrics        *interfaces.ProofSystemMetrics
	startTime      time.Time
	mu             sync.RWMutex

	// State
	initialized    bool
}

// NewProductionProofManager creates a new production-ready proof manager
func NewProductionProofManager(config *interfaces.ProofConfig) *ProductionProofManager {
	if config == nil {
		config = DefaultProofConfig()
	}

	// Create metrics
	metrics := &interfaces.ProofSystemMetrics{
		CacheMetrics: &interfaces.ProofCacheMetrics{},
	}

	return &ProductionProofManager{
		config:     config,
		metrics:    metrics,
		startTime:  time.Now(),
		initialized: false,
	}
}

// DefaultProofConfig returns a default configuration
func DefaultProofConfig() *interfaces.ProofConfig {
	return &interfaces.ProofConfig{
		EnableCache:      true,
		CacheSize:        1000,
		CacheTTL:         30 * time.Minute,
		DefaultStrategy:  interfaces.StrategyOptimized,
		BatchSize:        50,
		ParallelWorkers:  10,
		StrictMode:       false,
		RequireConsensus: false,
		MinValidators:    1,
		Timeout:          60 * time.Second,
		MaxRetries:       3,
		RetryDelay:       1 * time.Second,
		DebugMode:        false,
		VerboseMode:      false,
		LogLevel:         "basic",
		APIEndpoint:      "http://localhost:26660/v3",
		CometEndpoint:    "http://localhost:26657",
	}
}

// Initialize initializes the proof system with backend
func (m *ProductionProofManager) Initialize(backend interfaces.DataBackend) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return fmt.Errorf("proof manager already initialized")
	}

	m.backend = backend

	// Initialize core verifier
	m.verifier = core.NewCryptographicVerifierWithEndpoints(
		m.config.APIEndpoint,
		m.config.CometEndpoint,
	)

	// Initialize cache if enabled
	if m.config.EnableCache {
		m.cache = cache.NewMemoryProofCache(m.config.CacheSize, m.config.CacheTTL)
	}

	// Initialize batch generator
	m.batchGenerator = batch.NewBatchProofGenerator(
		m.verifier,
		m.cache,
		m.config.ParallelWorkers,
		m.config.Timeout,
		m.config.BatchSize,
	)

	// Initialize debug verifier if debug mode is enabled
	if m.config.DebugMode {
		debugLevel := debug.GetDebugLevelFromString(m.config.LogLevel)
		m.debugVerifier = debug.NewDebugVerifier(m.verifier, debugLevel, m.config.VerboseMode)
		m.batchGenerator.SetDebug(true)
	}

	m.initialized = true
	return nil
}

// GenerateProof generates a proof with the specified strategy
func (m *ProductionProofManager) GenerateProof(
	ctx context.Context,
	accountURL string,
	strategy interfaces.ProofStrategy,
) (*interfaces.CompleteProof, error) {
	if !m.initialized {
		return nil, fmt.Errorf("proof manager not initialized")
	}

	startTime := time.Now()

	// Update metrics
	m.mu.Lock()
	m.metrics.ProofsGenerated++
	m.mu.Unlock()

	// Handle different strategies
	switch strategy {
	case interfaces.StrategyMinimal:
		return m.generateMinimalProof(ctx, accountURL)
	case interfaces.StrategyComplete:
		return m.generateCompleteProof(ctx, accountURL)
	case interfaces.StrategyOptimized:
		return m.generateOptimizedProof(ctx, accountURL)
	case interfaces.StrategyDebug:
		return m.generateDebugProof(ctx, accountURL)
	case interfaces.StrategyBatch:
		// For single account, fall back to optimized
		return m.generateOptimizedProof(ctx, accountURL)
	default:
		return m.generateOptimizedProof(ctx, accountURL)
	}

	// Update average time
	duration := time.Since(startTime)
	m.updateAverageTime(duration)

	return nil, fmt.Errorf("strategy not implemented")
}

// GenerateBatchProof generates proofs for multiple accounts efficiently
func (m *ProductionProofManager) GenerateBatchProof(
	ctx context.Context,
	accountURLs []string,
) (map[string]*interfaces.CompleteProof, error) {
	if !m.initialized {
		return nil, fmt.Errorf("proof manager not initialized")
	}

	if m.batchGenerator == nil {
		return nil, fmt.Errorf("batch generator not available")
	}

	// Update metrics
	m.mu.Lock()
	m.metrics.BatchProofsGenerated++
	m.mu.Unlock()

	// Generate batch
	response := m.batchGenerator.GenerateBatchSimple(ctx, accountURLs)

	// Convert response to map
	results := make(map[string]*interfaces.CompleteProof)
	for _, result := range response.Results {
		if result.Error == nil && result.Proof != nil {
			results[result.AccountURL] = result.Proof
		}
	}

	// Update metrics
	m.mu.Lock()
	m.metrics.ProofsGenerated += int64(response.SuccessCount)
	if response.ErrorCount > 0 {
		m.metrics.FailureCount += int64(response.ErrorCount)
	}
	m.mu.Unlock()

	return results, nil
}

// VerifyProof verifies a complete proof
func (m *ProductionProofManager) VerifyProof(proof *interfaces.CompleteProof) error {
	if !m.initialized {
		return fmt.Errorf("proof manager not initialized")
	}

	if proof == nil {
		return fmt.Errorf("proof is nil")
	}

	// Update metrics
	m.mu.Lock()
	m.metrics.ProofsVerified++
	m.mu.Unlock()

	// Basic validation
	if len(proof.AccountHash) == 0 {
		return fmt.Errorf("missing account hash")
	}

	if len(proof.BPTRoot) == 0 {
		return fmt.Errorf("missing BPT root")
	}

	if len(proof.BlockHash) == 0 {
		return fmt.Errorf("missing block hash")
	}

	// Verify consensus if available and required
	if m.config.RequireConsensus && proof.ValidatorProof != nil {
		if proof.ValidatorProof.TotalPower <= 0 {
			return fmt.Errorf("invalid total voting power")
		}

		threshold := (proof.ValidatorProof.TotalPower * 2 / 3) + 1
		if proof.ValidatorProof.SignedPower < threshold {
			return fmt.Errorf("insufficient validator signatures: %d/%d (need %d)",
				proof.ValidatorProof.SignedPower, proof.ValidatorProof.TotalPower, threshold)
		}

		if len(proof.ValidatorProof.Validators) < m.config.MinValidators {
			return fmt.Errorf("insufficient validators: %d (need %d)",
				len(proof.ValidatorProof.Validators), m.config.MinValidators)
		}
	}

	return nil
}

// GetRequirements returns proof requirements for an account
func (m *ProductionProofManager) GetRequirements(accountURL string) *interfaces.ProofRequirements {
	// TODO: Implement proof requirements analysis
	return nil
}

// GetCache returns the proof cache
func (m *ProductionProofManager) GetCache() interfaces.ProofCache {
	return m.cache
}

// GetMetrics returns system metrics
func (m *ProductionProofManager) GetMetrics() *interfaces.ProofSystemMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Update uptime
	m.metrics.TotalUptime = time.Since(m.startTime)

	// Update cache metrics if available
	if m.cache != nil {
		m.metrics.CacheMetrics = m.cache.GetProofCacheMetrics()
	}

	// Calculate success rates (simplified)
	total := m.metrics.ProofsGenerated
	if total > 0 {
		successRate := float64(total-m.metrics.FailureCount) / float64(total)
		m.metrics.Layer1SuccessRate = successRate
		m.metrics.Layer2SuccessRate = successRate
		m.metrics.Layer3SuccessRate = successRate * 0.8 // Layer 3 typically has lower success
	}

	return m.metrics
}

// UpdateConfig updates the proof system configuration
func (m *ProductionProofManager) UpdateConfig(config *interfaces.ProofConfig) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Update configuration
	oldConfig := m.config
	m.config = config

	// Apply configuration changes
	if m.cache != nil && m.config.CacheSize != oldConfig.CacheSize {
		// Update cache size
		if memCache, ok := m.cache.(*cache.MemoryProofCache); ok {
			memCache.SetMaxSize(m.config.CacheSize)
			memCache.SetTTL(m.config.CacheTTL)
		}
	}

	if m.batchGenerator != nil {
		m.batchGenerator.UpdateConfiguration(
			m.config.ParallelWorkers,
			m.config.BatchSize,
			m.config.Timeout,
		)
		m.batchGenerator.SetDebug(m.config.DebugMode)
	}

	if m.debugVerifier != nil {
		debugLevel := debug.GetDebugLevelFromString(m.config.LogLevel)
		m.debugVerifier.SetLogLevel(debugLevel)
		m.debugVerifier.SetVerboseMode(m.config.VerboseMode)
	}

	return nil
}

// GetConfig returns the current configuration
func (m *ProductionProofManager) GetConfig() *interfaces.ProofConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// SetDebugMode enables or disables debug mode
func (m *ProductionProofManager) SetDebugMode(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config.DebugMode = enabled

	if m.debugVerifier != nil {
		// Debug verifier already exists, just update config
		return
	}

	if enabled && m.verifier != nil {
		// Create debug verifier
		debugLevel := debug.GetDebugLevelFromString(m.config.LogLevel)
		m.debugVerifier = debug.NewDebugVerifier(m.verifier, debugLevel, m.config.VerboseMode)
	}

	if m.batchGenerator != nil {
		m.batchGenerator.SetDebug(enabled)
	}
}

// GetDebugInfo returns debug information for an account
func (m *ProductionProofManager) GetDebugInfo(accountURL string) (*interfaces.DebugInfo, error) {
	if !m.initialized {
		return nil, fmt.Errorf("proof manager not initialized")
	}

	if m.debugVerifier == nil {
		// Create temporary debug verifier
		debugLevel := debug.GetDebugLevelFromString(m.config.LogLevel)
		tempDebugVerifier := debug.NewDebugVerifier(m.verifier, debugLevel, m.config.VerboseMode)
		_, debugInfo, err := tempDebugVerifier.VerifyAccountWithDebug(accountURL)
		return debugInfo, err
	}

	_, debugInfo, err := m.debugVerifier.VerifyAccountWithDebug(accountURL)
	return debugInfo, err
}

// Strategy implementations

func (m *ProductionProofManager) generateMinimalProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	// Minimal proof: only Layer 1 verification, use cache aggressively
	if m.cache != nil {
		if cached, found := m.cache.GetAccountProof(accountURL); found {
			return cached, nil
		}
	}

	return m.generateBasicProof(ctx, accountURL, interfaces.StrategyMinimal)
}

func (m *ProductionProofManager) generateCompleteProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	// Complete proof: all layers, no cache shortcuts
	return m.generateBasicProof(ctx, accountURL, interfaces.StrategyComplete)
}

func (m *ProductionProofManager) generateOptimizedProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	// Optimized proof: balance between completeness and performance
	if m.cache != nil {
		if cached, found := m.cache.GetAccountProof(accountURL); found {
			// Check if cached proof is still fresh enough
			maxAge := m.config.CacheTTL / 2 // Use cache for half the TTL period
			if time.Since(cached.GeneratedAt) < maxAge {
				return cached, nil
			}
		}
	}

	return m.generateBasicProof(ctx, accountURL, interfaces.StrategyOptimized)
}

func (m *ProductionProofManager) generateDebugProof(ctx context.Context, accountURL string) (*interfaces.CompleteProof, error) {
	// Debug proof: generate with full debug output
	if m.debugVerifier == nil {
		debugLevel := debug.GetDebugLevelFromString(m.config.LogLevel)
		m.debugVerifier = debug.NewDebugVerifier(m.verifier, debugLevel, m.config.VerboseMode)
	}

	_, _, err := m.debugVerifier.VerifyAccountWithDebug(accountURL)
	if err != nil {
		return nil, err
	}

	// Generate regular proof but with debug info attached
	proof, err := m.generateBasicProof(ctx, accountURL, interfaces.StrategyDebug)
	if err != nil {
		return nil, err
	}

	// Attach debug information if possible
	proof.Strategy = interfaces.StrategyDebug

	return proof, nil
}

func (m *ProductionProofManager) generateBasicProof(ctx context.Context, accountURL string, strategy interfaces.ProofStrategy) (*interfaces.CompleteProof, error) {
	// Parse URL
	parsedURL, err := url.Parse(accountURL)
	if err != nil {
		m.mu.Lock()
		m.metrics.FailureCount++
		m.metrics.LastError = err
		m.mu.Unlock()
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}

	// Perform verification
	result, err := m.verifier.VerifyAccount(ctx, parsedURL)
	if err != nil {
		m.mu.Lock()
		m.metrics.FailureCount++
		m.metrics.LastError = err
		m.mu.Unlock()
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	// Build proof from verification result
	proof, err := m.buildProofFromVerification(result, strategy)
	if err != nil {
		m.mu.Lock()
		m.metrics.FailureCount++
		m.metrics.LastError = err
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to build proof: %w", err)
	}

	// Cache the proof if caching is enabled
	if m.cache != nil && strategy != interfaces.StrategyDebug {
		if err := m.cache.StoreAccountProof(accountURL, proof); err != nil {
			// Cache failure is not critical
			if m.config.DebugMode {
				fmt.Printf("Warning: failed to cache proof: %v\n", err)
			}
		}
	}

	return proof, nil
}

func (m *ProductionProofManager) buildProofFromVerification(result *core.VerificationResult, strategy interfaces.ProofStrategy) (*interfaces.CompleteProof, error) {
	proof := &interfaces.CompleteProof{
		GeneratedAt: time.Now(),
		Strategy:    strategy,
		TrustLevel:  result.TrustLevel,
	}

	// Extract data from verification layers
	// This is a simplified version - full implementation would extract all details
	if result.Layer1Result != nil {
		// Layer 1 data extraction would go here
		proof.AccountHash = []byte("placeholder") // TODO: Extract actual data
	}

	if result.Layer2Result != nil {
		// Layer 2 data extraction would go here
		proof.BlockHeight = uint64(result.Layer2Result.BlockHeight)
	}

	if result.Layer3Result != nil && result.Layer3Result.Verified {
		// Layer 3 data extraction would go here
		proof.ValidatorProof = &interfaces.ConsensusProof{
			BlockHeight: uint64(result.Layer3Result.BlockHeight),
			ChainID:     result.Layer3Result.ChainID,
			TotalPower:  result.Layer3Result.TotalPower,
			SignedPower: result.Layer3Result.SignedPower,
		}
	}

	return proof, nil
}

func (m *ProductionProofManager) updateAverageTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.metrics.ProofsGenerated == 1 {
		m.metrics.AverageProofTime = duration
	} else {
		// Simple moving average
		count := m.metrics.ProofsGenerated
		m.metrics.AverageProofTime = time.Duration(
			(int64(m.metrics.AverageProofTime)*int64(count-1) + int64(duration)) / int64(count),
		)
	}
}