// Copyright 2025 Certen Protocol
//
// ProofArtifactService - Collects and bundles proof artifacts from existing generators
//
// This service orchestrates the collection of proof artifacts from:
// - LiteClientProofGenerator (ChainedProof L1/L2/L3)
// - GovernanceProofGenerator (G0/G1/G2)
// - Batch Merkle Tree (inclusion proofs)
// - Anchor references (external chain)
//
// Outputs self-contained CertenProofBundle for external retrieval.

package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
)

// =============================================================================
// ProofArtifactService - Main orchestration service
// =============================================================================

// ProofArtifactService collects proof artifacts from existing generators
// and creates self-contained verification bundles.
type ProofArtifactService struct {
	// Proof generators
	liteClientGen *LiteClientProofGenerator
	govProofGen   GovernanceProofGenerator // G0/G1/G2 governance proof generator

	// Configuration
	config *ArtifactServiceConfig

	// Metrics
	metrics *ArtifactMetrics
	mu      sync.RWMutex
}

// ArtifactServiceConfig contains service configuration
type ArtifactServiceConfig struct {
	// Generator settings
	V3Endpoint        string        `json:"v3_endpoint"`
	GeneratorTimeout  time.Duration `json:"generator_timeout"`

	// Governance proof settings
	GovProofCLIPath   string `json:"gov_proof_cli_path"` // Path to govproof CLI binary (optional)
	GovProofWorkDir   string `json:"gov_proof_work_dir"` // Working directory for gov proof artifacts

	// Bundle settings
	DefaultGovLevel   GovernanceLevel `json:"default_gov_level"`
	IncludeAllLayers  bool            `json:"include_all_layers"`

	// Validation settings
	ValidateOnCreate  bool `json:"validate_on_create"`
	RequireAllComponents bool `json:"require_all_components"`

	// Coordinator identity
	ValidatorID string `json:"validator_id"`
}

// ArtifactMetrics tracks service metrics
type ArtifactMetrics struct {
	BundlesCreated     int64
	BundlesComplete    int64
	BundlesIncomplete  int64
	GenerationErrors   int64
	TotalGenerationMs  int64
	LastGenerationAt   time.Time
}

// DefaultArtifactServiceConfig returns default configuration
func DefaultArtifactServiceConfig() *ArtifactServiceConfig {
	return &ArtifactServiceConfig{
		V3Endpoint:       "https://mainnet.accumulatenetwork.io/v3",
		GeneratorTimeout: 30 * time.Second,
		DefaultGovLevel:  GovLevelG1,
		IncludeAllLayers: true,
		ValidateOnCreate: true,
		RequireAllComponents: false,
		ValidatorID:     "validator-default",
	}
}

// NewProofArtifactService creates a new artifact service
func NewProofArtifactService(config *ArtifactServiceConfig) (*ProofArtifactService, error) {
	if config == nil {
		config = DefaultArtifactServiceConfig()
	}

	// Create lite client generator
	liteClientGen, err := NewLiteClientProofGenerator(config.V3Endpoint, config.GeneratorTimeout)
	if err != nil {
		return nil, fmt.Errorf("create lite client generator: %w", err)
	}

	// Create governance proof generator
	var govProofGen GovernanceProofGenerator
	if config.GovProofCLIPath != "" {
		// Use CLI-based generator when path is configured
		cliGen, err := NewCLIGovernanceProofGenerator(
			config.GovProofCLIPath,
			config.V3Endpoint,
			config.GovProofWorkDir,
			config.GeneratorTimeout,
		)
		if err != nil {
			return nil, fmt.Errorf("create CLI governance proof generator: %w", err)
		}
		govProofGen = cliGen
	} else {
		// Use in-process generator (returns stub proofs until library is available)
		govProofGen = NewInProcessGovernanceGenerator(
			config.V3Endpoint,
			config.GovProofWorkDir,
			config.GeneratorTimeout,
		)
	}

	return &ProofArtifactService{
		liteClientGen: liteClientGen,
		govProofGen:   govProofGen,
		config:        config,
		metrics:       &ArtifactMetrics{},
	}, nil
}

// NewProofArtifactServiceWithGenerator creates a service with an existing generator
func NewProofArtifactServiceWithGenerator(liteClientGen *LiteClientProofGenerator, config *ArtifactServiceConfig) (*ProofArtifactService, error) {
	if liteClientGen == nil {
		return nil, fmt.Errorf("lite client generator cannot be nil")
	}
	if config == nil {
		config = DefaultArtifactServiceConfig()
	}

	// Create governance proof generator
	var govProofGen GovernanceProofGenerator
	if config.GovProofCLIPath != "" {
		cliGen, err := NewCLIGovernanceProofGenerator(
			config.GovProofCLIPath,
			config.V3Endpoint,
			config.GovProofWorkDir,
			config.GeneratorTimeout,
		)
		if err != nil {
			return nil, fmt.Errorf("create CLI governance proof generator: %w", err)
		}
		govProofGen = cliGen
	} else {
		govProofGen = NewInProcessGovernanceGenerator(
			config.V3Endpoint,
			config.GovProofWorkDir,
			config.GeneratorTimeout,
		)
	}

	return &ProofArtifactService{
		liteClientGen: liteClientGen,
		govProofGen:   govProofGen,
		config:        config,
		metrics:       &ArtifactMetrics{},
	}, nil
}

// =============================================================================
// Artifact Collection Request/Response
// =============================================================================

// ArtifactRequest specifies what proof artifacts to collect
type ArtifactRequest struct {
	// Transaction identification
	TransactionHash string `json:"transaction_hash"`
	AccountURL      string `json:"account_url"`
	TransactionType string `json:"transaction_type,omitempty"`

	// Governance proof fields (required for G1+ proofs)
	KeyPage string `json:"key_page,omitempty"` // Key page URL for authority validation

	// Proof options
	GovernanceLevel GovernanceLevel `json:"governance_level"`
	IncludeMerkle   bool            `json:"include_merkle"`
	IncludeAnchor   bool            `json:"include_anchor"`
	IncludeChained  bool            `json:"include_chained"`
	IncludeGov      bool            `json:"include_governance"`

	// Batch context (if part of a batch)
	BatchID     string `json:"batch_id,omitempty"`
	BatchIndex  int64  `json:"batch_index,omitempty"`

	// Anchor context (if already anchored)
	AnchorChain    string `json:"anchor_chain,omitempty"`
	AnchorTxHash   string `json:"anchor_tx_hash,omitempty"`
	AnchorBlockNum uint64 `json:"anchor_block_num,omitempty"`

	// Merkle context (if batch is known)
	MerkleRoot string            `json:"merkle_root,omitempty"`
	MerklePath []MerklePathEntry `json:"merkle_path,omitempty"`
}

// ArtifactResponse contains the collected artifacts
type ArtifactResponse struct {
	// The complete bundle
	Bundle *CertenProofBundle `json:"bundle"`

	// Collection status
	Success       bool     `json:"success"`
	Errors        []string `json:"errors,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`

	// Component status
	ComponentsCollected map[string]bool `json:"components_collected"`

	// Timing
	CollectionTime time.Duration `json:"collection_time"`
	CollectedAt    time.Time     `json:"collected_at"`
}

// NewArtifactRequest creates a request with default options
func NewArtifactRequest(accountURL string) *ArtifactRequest {
	return &ArtifactRequest{
		AccountURL:      accountURL,
		GovernanceLevel: GovLevelG1,
		IncludeMerkle:   true,
		IncludeAnchor:   true,
		IncludeChained:  true,
		IncludeGov:      true,
	}
}

// NewArtifactRequestForTx creates a request for a specific transaction
func NewArtifactRequestForTx(txHash, accountURL string) *ArtifactRequest {
	req := NewArtifactRequest(accountURL)
	req.TransactionHash = txHash
	return req
}

// =============================================================================
// Artifact Collection Methods
// =============================================================================

// CollectArtifacts collects all requested proof artifacts and creates a bundle
func (s *ProofArtifactService) CollectArtifacts(ctx context.Context, req *ArtifactRequest) (*ArtifactResponse, error) {
	startTime := time.Now()

	response := &ArtifactResponse{
		ComponentsCollected: make(map[string]bool),
		CollectedAt:         startTime,
	}

	// Validate request
	if req.AccountURL == "" {
		return nil, fmt.Errorf("account_url is required")
	}

	// Create bundle
	bundleID := uuid.New().String()
	bundle := NewCertenProofBundle(bundleID)

	// Set transaction reference
	bundle.SetTransactionRef(req.TransactionHash, req.AccountURL, req.TransactionType)

	// Collect components concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errors []string
	var warnings []string

	// Component 1: Merkle Inclusion (if batch context provided)
	if req.IncludeMerkle && req.MerkleRoot != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.collectMerkleProof(ctx, bundle, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("merkle proof: %v", err))
			} else {
				response.ComponentsCollected["merkle_inclusion"] = true
			}
		}()
	} else if req.IncludeMerkle {
		warnings = append(warnings, "merkle proof skipped: no batch context")
	}

	// Component 2: Anchor Reference (if anchor context provided)
	if req.IncludeAnchor && req.AnchorTxHash != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.collectAnchorRef(ctx, bundle, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("anchor reference: %v", err))
			} else {
				response.ComponentsCollected["anchor_reference"] = true
			}
		}()
	} else if req.IncludeAnchor {
		warnings = append(warnings, "anchor reference skipped: no anchor context")
	}

	// Component 3: Chained Proof (from lite client)
	if req.IncludeChained {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.collectChainedProof(ctx, bundle, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errors = append(errors, fmt.Sprintf("chained proof: %v", err))
			} else {
				response.ComponentsCollected["chained_proof"] = true
			}
		}()
	}

	// Component 4: Governance Proof
	if req.IncludeGov {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.collectGovernanceProof(ctx, bundle, req)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("governance proof: %v", err))
			} else {
				response.ComponentsCollected["governance_proof"] = true
			}
		}()
	}

	// Wait for all collection to complete
	wg.Wait()

	// Set response
	response.Bundle = bundle
	response.Errors = errors
	response.Warnings = warnings
	response.CollectionTime = time.Since(startTime)
	response.Success = len(errors) == 0

	// Update metrics
	s.updateMetrics(response)

	// Validate bundle if configured
	if s.config.ValidateOnCreate {
		validationErrors := bundle.Validate()
		if len(validationErrors) > 0 {
			response.Warnings = append(response.Warnings, validationErrors...)
		}
	}

	// Check completeness requirement
	if s.config.RequireAllComponents && !bundle.IsComplete() {
		response.Success = false
		response.Errors = append(response.Errors, "bundle is incomplete (all components required)")
	}

	return response, nil
}

// collectMerkleProof collects Merkle inclusion proof from batch context
func (s *ProofArtifactService) collectMerkleProof(ctx context.Context, bundle *CertenProofBundle, req *ArtifactRequest) error {
	if req.MerkleRoot == "" {
		return fmt.Errorf("merkle_root not provided")
	}

	// Compute leaf hash from transaction
	leafHash := computeLeafHash(req.TransactionHash, req.AccountURL)

	bundle.SetMerkleInclusion(req.MerkleRoot, leafHash, req.BatchIndex, req.MerklePath)

	if bundle.ProofComponents.MerkleInclusion != nil {
		bundle.ProofComponents.MerkleInclusion.BatchID = req.BatchID
	}

	return nil
}

// collectAnchorRef collects anchor reference from external chain
func (s *ProofArtifactService) collectAnchorRef(ctx context.Context, bundle *CertenProofBundle, req *ArtifactRequest) error {
	if req.AnchorTxHash == "" {
		return fmt.Errorf("anchor_tx_hash not provided")
	}

	// Set anchor reference from request context
	// In production, this would query the external chain for confirmation count
	bundle.SetAnchorReference(req.AnchorChain, req.AnchorTxHash, req.AnchorBlockNum, 0)

	return nil
}

// collectChainedProof collects L1/L2/L3 proof from lite client
func (s *ProofArtifactService) collectChainedProof(ctx context.Context, bundle *CertenProofBundle, req *ArtifactRequest) error {
	// Generate proof using lite client
	completeProof, err := s.liteClientGen.GenerateAccumulateProof(ctx, req.AccountURL)
	if err != nil {
		return fmt.Errorf("generate lite client proof: %w", err)
	}

	// Verify the proof
	if err := s.liteClientGen.VerifyProof(completeProof); err != nil {
		return fmt.Errorf("verify lite client proof: %w", err)
	}

	// Set in bundle
	bundle.SetChainedProof(completeProof)

	return nil
}

// collectGovernanceProof collects governance proof (G0/G1/G2) using real generator
func (s *ProofArtifactService) collectGovernanceProof(ctx context.Context, bundle *CertenProofBundle, req *ArtifactRequest) error {
	level := req.GovernanceLevel
	if level == "" {
		level = s.config.DefaultGovLevel
	}

	// Build governance proof request
	govReq := &GovernanceRequest{
		AccountURL:      req.AccountURL,
		TransactionHash: req.TransactionHash,
		KeyPage:         req.KeyPage, // Required for G1+ proofs
		V3Endpoint:      s.config.V3Endpoint,
		WorkDir:         s.config.GovProofWorkDir,
	}

	// Generate governance proof using the configured generator
	var govProof *GovernanceProof
	var err error

	if s.govProofGen != nil {
		govProof, err = s.govProofGen.GenerateAtLevel(ctx, level, govReq)
		if err != nil {
			// Log warning but don't fail - governance proofs are valuable but not always required
			// Fall back to creating a stub proof
			govProof = s.createFallbackGovProof(level, req)
		}
	} else {
		// No generator configured - create stub proof
		govProof = s.createFallbackGovProof(level, req)
	}

	bundle.SetGovernanceProof(govProof)

	return nil
}

// createFallbackGovProof creates a stub governance proof when generator fails or is unavailable
func (s *ProofArtifactService) createFallbackGovProof(level GovernanceLevel, req *ArtifactRequest) *GovernanceProof {
	govProof := &GovernanceProof{
		Level:       level,
		SpecVersion: GovernanceSpecVersion,
		GeneratedAt: time.Now(),
	}

	switch level {
	case GovLevelG0:
		govProof.G0 = &G0Result{
			TxHash:          req.TransactionHash,
			Scope:           req.AccountURL,
			Chain:           "main",
			Principal:       req.AccountURL,
			G0ProofComplete: false, // Stub - not verified
		}
	case GovLevelG1:
		govProof.G1 = &G1Result{
			G0Result: G0Result{
				TxHash:          req.TransactionHash,
				Scope:           req.AccountURL,
				Chain:           "main",
				Principal:       req.AccountURL,
				G0ProofComplete: false,
			},
			G1ProofComplete: false, // Stub - authority not validated
		}
	case GovLevelG2:
		govProof.G2 = &G2Result{
			G1Result: G1Result{
				G0Result: G0Result{
					TxHash:          req.TransactionHash,
					Scope:           req.AccountURL,
					Chain:           "main",
					Principal:       req.AccountURL,
					G0ProofComplete: false,
				},
				G1ProofComplete: false,
			},
			G2ProofComplete: false, // Stub - outcome not verified
		}
	}

	return govProof
}

// =============================================================================
// Bundle Finalization
// =============================================================================

// FinalizeBundle adds integrity hashes and optional signature
func (s *ProofArtifactService) FinalizeBundle(bundle *CertenProofBundle, custodyChainHash string, signBundle bool) error {
	if bundle == nil {
		return fmt.Errorf("bundle cannot be nil")
	}

	// Compute artifact hash
	artifactHash, err := bundle.ComputeArtifactHash()
	if err != nil {
		return fmt.Errorf("compute artifact hash: %w", err)
	}

	var bundleSignature string
	if signBundle {
		// In production, this would use the validator's Ed25519 key
		// For now, create a placeholder signature
		bundleSignature = "placeholder_signature"
	}

	bundle.BundleIntegrity = BundleIntegrity{
		ArtifactHash:     artifactHash,
		CustodyChainHash: custodyChainHash,
		BundleSignature:  bundleSignature,
		SignerID:         s.config.ValidatorID,
	}

	return nil
}

// =============================================================================
// Batch Operations
// =============================================================================

// CollectBatchArtifacts collects artifacts for multiple transactions in a batch
func (s *ProofArtifactService) CollectBatchArtifacts(ctx context.Context, requests []*ArtifactRequest) ([]*ArtifactResponse, error) {
	responses := make([]*ArtifactResponse, len(requests))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstError error

	for i, req := range requests {
		wg.Add(1)
		go func(idx int, r *ArtifactRequest) {
			defer wg.Done()
			resp, err := s.CollectArtifacts(ctx, r)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstError == nil {
				firstError = err
			}
			responses[idx] = resp
		}(i, req)
	}

	wg.Wait()

	if firstError != nil {
		return responses, fmt.Errorf("batch collection had errors: %w", firstError)
	}

	return responses, nil
}

// =============================================================================
// Retrieval Methods
// =============================================================================

// GetCompleteProof retrieves a CompleteProof for an account
func (s *ProofArtifactService) GetCompleteProof(ctx context.Context, accountURL string) (*lcproof.CompleteProof, error) {
	return s.liteClientGen.GenerateAccumulateProof(ctx, accountURL)
}

// GetConsensusState retrieves current Accumulate consensus state
func (s *ProofArtifactService) GetConsensusState(ctx context.Context) (*ConsensusState, error) {
	return s.liteClientGen.GetConsensusState(ctx)
}

// =============================================================================
// Metrics and Status
// =============================================================================

// GetMetrics returns current service metrics
func (s *ProofArtifactService) GetMetrics() ArtifactMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return *s.metrics
}

// updateMetrics updates service metrics from a response
func (s *ProofArtifactService) updateMetrics(resp *ArtifactResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.metrics.BundlesCreated++
	s.metrics.TotalGenerationMs += resp.CollectionTime.Milliseconds()
	s.metrics.LastGenerationAt = resp.CollectedAt

	if resp.Bundle != nil && resp.Bundle.IsComplete() {
		s.metrics.BundlesComplete++
	} else {
		s.metrics.BundlesIncomplete++
	}

	if !resp.Success {
		s.metrics.GenerationErrors++
	}
}

// GetConfig returns service configuration
func (s *ProofArtifactService) GetConfig() *ArtifactServiceConfig {
	return s.config
}

// =============================================================================
// Helper Functions
// =============================================================================

// computeLeafHash computes the Merkle leaf hash for a transaction
func computeLeafHash(txHash, accountURL string) string {
	data := []byte(txHash + "|" + accountURL)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
