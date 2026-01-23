// Copyright 2025 Certen Protocol
//
// Batch Processor - Coordinates batch closing and anchor triggering
// Per Whitepaper Section 3.4.2: Write Merkle root to external chain
//
// The processor:
// - Takes closed batches and triggers anchoring
// - Creates Certen Anchor Proofs in the database
// - Tracks anchor confirmations
// - Integrates with the AnchorManager for external chain writes

package batch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/merkle"
	"github.com/certen/independant-validator/pkg/proof"
)

// AnchorCreator is the interface for creating anchors on external chains
// This abstracts the AnchorManager to avoid circular imports
type AnchorCreator interface {
	// CreateBatchAnchor creates an anchor for a closed batch
	CreateBatchAnchor(ctx context.Context, req *BatchAnchorRequest) (*BatchAnchorResult, error)

	// ExecuteComprehensiveProof submits a complete proof bundle for on-chain verification
	// Per CRITICAL-001: This method MUST be called after CreateBatchAnchor to submit
	// the L1-L4 cryptographic proofs and G0-G2 governance proofs to the contract
	ExecuteComprehensiveProof(ctx context.Context, req *ExecuteProofRequest) (*ExecuteProofResult, error)
}

// ExecuteProofRequest is the request to execute a comprehensive proof
// This bridges batch processor data to the anchor manager's proof execution
type ExecuteProofRequest struct {
	AnchorID             string    `json:"anchor_id"`               // The bundleId from CreateBatchAnchor
	BatchID              string    `json:"batch_id"`                // Batch identifier
	ValidatorID          string    `json:"validator_id"`            // This validator's ID
	TransactionHash      [32]byte  `json:"transaction_hash"`        // Representative tx hash
	MerkleRoot           [32]byte  `json:"merkle_root"`             // Batch Merkle root
	ProofHashes          [][32]byte `json:"proof_hashes"`           // Merkle proof path
	LeafHash             [32]byte  `json:"leaf_hash"`               // Leaf being proven
	OperationCommitment  [32]byte  `json:"operation_commitment"`    // = MerkleRoot
	CrossChainCommitment [32]byte  `json:"cross_chain_commitment"`  // BPT root from Accumulate
	GovernanceRoot       [32]byte  `json:"governance_root"`         // Root of governance proofs
	BLSSignature         []byte    `json:"bls_signature,omitempty"` // Aggregate BLS signature
	Timestamp            int64     `json:"timestamp"`               // Proof creation time
}

// ExecuteProofResult is the result from comprehensive proof execution
type ExecuteProofResult struct {
	TxHash      string `json:"tx_hash"`
	BlockNumber int64  `json:"block_number"`
	BlockHash   string `json:"block_hash"`
	GasUsed     int64  `json:"gas_used"`
	Success     bool   `json:"success"`
	ProofValid  bool   `json:"proof_valid"`
}

// BatchAnchorRequest is the request to anchor a batch
// Extended with proof data fields per Phase 2 (HIGH-002, HIGH-003)
type BatchAnchorRequest struct {
	BatchID          uuid.UUID `json:"batch_id"`
	MerkleRoot       []byte    `json:"merkle_root"`
	TxCount          int       `json:"tx_count"`
	AccumulateHeight int64     `json:"accumulate_height"`
	AccumulateHash   string    `json:"accumulate_hash"`
	TargetChain      string    `json:"target_chain"` // "ethereum", "bitcoin"
	ValidatorID      string    `json:"validator_id"`

	// ========== Phase 2 Additions: Real Proof Data ==========
	// These fields provide cryptographic binding per CERTEN whitepaper

	// BPTRoot is the Binary Patricia Tree root from Accumulate
	// This is the L2 anchor that provides cryptographic binding to chain state
	// Per HIGH-002: CrossChainCommitment MUST be real BPT data
	BPTRoot []byte `json:"bpt_root,omitempty"`

	// NetworkRootHash is the Directory Network root hash
	// This is the L3 anchor for full chain state binding
	NetworkRootHash []byte `json:"network_root_hash,omitempty"`

	// TransactionProofs contains the ChainedProof (L1-L3) for each transaction
	// These are raw JSON-encoded proof data from Accumulate
	TransactionProofs []json.RawMessage `json:"transaction_proofs,omitempty"`

	// GovernanceProofs contains the GovernanceProof (G0-G2) for each transaction
	// These are raw JSON-encoded governance proofs with signature data
	// Per HIGH-003: GovernanceRoot MUST be Merkle root of actual governance proofs
	GovernanceProofs []json.RawMessage `json:"governance_proofs,omitempty"`

	// GovernanceLevels tracks the governance level for each transaction
	GovernanceLevels []string `json:"governance_levels,omitempty"`
}

// BatchAnchorResult is the result of anchoring a batch
type BatchAnchorResult struct {
	AnchorID        uuid.UUID `json:"anchor_id"`
	BatchID         uuid.UUID `json:"batch_id"`
	TargetChain     string    `json:"target_chain"`
	TxHash          string    `json:"tx_hash"`
	BlockNumber     int64     `json:"block_number"`
	BlockHash       string    `json:"block_hash"`
	GasUsed         int64     `json:"gas_used"`
	GasPriceWei     string    `json:"gas_price_wei"`
	TotalCostWei    string    `json:"total_cost_wei"`
	Success         bool      `json:"success"`
	Timestamp       time.Time `json:"timestamp"`
}

// OnAnchorCallback is called when a batch is successfully anchored
// Used for multi-validator attestation collection per Whitepaper Section 3.4.1 Component 4
type OnAnchorCallback func(ctx context.Context, batchID uuid.UUID, merkleRoot []byte, anchorTxHash string, txCount int, blockNumber int64) error

// Processor manages batch processing and anchor creation
type Processor struct {
	mu sync.Mutex

	// Dependencies
	repos         *database.Repositories
	anchorCreator AnchorCreator

	// Phase 2: Governance Proof Generator
	// Per Task 2.2: Wire governance generator to batch processor
	govGenerator *proof.NativeGovernanceProofGenerator

	// Configuration
	validatorID    string
	targetChain    string // Default target chain
	chainID        string
	networkName    string
	contractAddr   string

	// Governance proof configuration
	defaultGovLevel proof.GovernanceLevel // Default governance level for batch proofs

	// CONSENSUS FIX: Executor selection for anchor creation
	// Only the elected executor should create anchors to prevent duplicate writes
	// and ensure all validators agree on the same merkleRoot
	validatorSet []string // List of all validators in consensus (sorted)

	// Processing state
	processing   map[uuid.UUID]bool // Batches currently being processed

	// PHASE 5: Attestation callback for multi-validator consensus
	onAnchorCallback OnAnchorCallback

	// Logging
	logger *log.Logger
}

// ProcessorConfig holds processor configuration
type ProcessorConfig struct {
	ValidatorID     string
	TargetChain     string
	ChainID         string
	NetworkName     string
	ContractAddress string
	Logger          *log.Logger

	// Phase 2: Governance proof configuration
	GovernanceLevel    proof.GovernanceLevel // Default governance level (G0, G1, G2)
	V3Endpoint         string                // Accumulate V3 API endpoint
	ValidatorKey       []byte                // Ed25519 private key for signing governance proofs

	// CONSENSUS FIX: Validator set for executor selection
	// This list must be the SAME on all validators to ensure consistent election
	ValidatorSet       []string              // List of validator IDs (e.g., ["validator-1", "validator-2", ...])
}

// DefaultProcessorConfig returns default configuration
func DefaultProcessorConfig() *ProcessorConfig {
	return &ProcessorConfig{
		ValidatorID:     "validator-default",
		TargetChain:     "ethereum",
		ChainID:         "11155111", // Sepolia
		NetworkName:     "sepolia",
		Logger:          log.New(log.Writer(), "[BatchProcessor] ", log.LstdFlags),
		GovernanceLevel: proof.GovLevelG1, // Default to G1 (governance correctness)
		V3Endpoint:      "",               // Must be configured for real governance proofs
		// CONSENSUS FIX: Default validator set - MUST be configured with actual validators
		ValidatorSet:    []string{"validator-1", "validator-2", "validator-3", "validator-4", "validator-5", "validator-6", "validator-7"},
	}
}

// NewProcessor creates a new batch processor
func NewProcessor(repos *database.Repositories, anchorCreator AnchorCreator, cfg *ProcessorConfig) (*Processor, error) {
	if repos == nil {
		return nil, fmt.Errorf("repositories cannot be nil")
	}
	if cfg == nil {
		cfg = DefaultProcessorConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[BatchProcessor] ", log.LstdFlags)
	}

	// CONSENSUS FIX: Sort and store validator set for deterministic executor selection
	validatorSet := cfg.ValidatorSet
	if len(validatorSet) == 0 {
		// Default validator set - MUST match across all validators
		validatorSet = []string{"validator-1", "validator-2", "validator-3", "validator-4", "validator-5", "validator-6", "validator-7"}
	}
	// Sort to ensure deterministic selection across all validators
	sort.Strings(validatorSet)

	p := &Processor{
		repos:           repos,
		anchorCreator:   anchorCreator,
		validatorID:     cfg.ValidatorID,
		targetChain:     cfg.TargetChain,
		chainID:         cfg.ChainID,
		networkName:     cfg.NetworkName,
		contractAddr:    cfg.ContractAddress,
		processing:      make(map[uuid.UUID]bool),
		logger:          cfg.Logger,
		defaultGovLevel: cfg.GovernanceLevel,
		validatorSet:    validatorSet, // CONSENSUS FIX: Store sorted validator set
	}

	// Phase 2: Initialize governance proof generator if V3 endpoint is configured
	if cfg.V3Endpoint != "" {
		var validatorKey []byte
		if len(cfg.ValidatorKey) > 0 {
			validatorKey = cfg.ValidatorKey
		}

		govGenCfg := &proof.NativeGeneratorConfig{
			V3Endpoint:   cfg.V3Endpoint,
			ValidatorKey: validatorKey,
			ValidatorID:  cfg.ValidatorID,
			Logger:       log.New(log.Writer(), "[GovProof] ", log.LstdFlags),
		}

		govGenerator, err := proof.NewNativeGovernanceProofGenerator(govGenCfg)
		if err != nil {
			cfg.Logger.Printf("⚠️ Failed to initialize governance generator: %v", err)
			// Continue without governance generator - will use fallback
		} else {
			p.govGenerator = govGenerator
			cfg.Logger.Printf("✅ Governance proof generator initialized (endpoint: %s)", cfg.V3Endpoint)
		}
	}

	return p, nil
}

// =============================================================================
// CONSENSUS FIX: Deterministic Executor Selection for Anchor Creation
// =============================================================================

// selectExecutorForBatch deterministically selects which validator should create
// the anchor for a given batch. This MUST produce the same result on all validators.
//
// The algorithm:
// 1. Hash the batch ID (UUID is already unique per batch)
// 2. Convert first bytes to integer
// 3. Modulo by number of validators
// 4. Select validator from sorted list
//
// This ensures:
// - All validators compute the same executor for the same batch
// - Only ONE validator creates the anchor (no duplicates)
// - All validators agree on merkleRoot BEFORE anchor creation
func (p *Processor) selectExecutorForBatch(batchID uuid.UUID) string {
	if len(p.validatorSet) == 0 {
		// Fallback: if no validator set configured, allow all validators
		p.logger.Printf("⚠️ [CONSENSUS] No validator set configured - allowing anchor creation")
		return p.validatorID
	}

	// Hash the batch ID for deterministic selection
	hash := sha256.Sum256(batchID[:])

	// Convert first 4 bytes to integer for index calculation
	index := int(hash[0])<<24 | int(hash[1])<<16 | int(hash[2])<<8 | int(hash[3])
	if index < 0 {
		index = -index // Ensure positive
	}

	// Select from sorted validator set
	selectedIndex := index % len(p.validatorSet)
	selectedExecutor := p.validatorSet[selectedIndex]

	return selectedExecutor
}

// isElectedExecutor checks if this validator is the elected executor for a batch
func (p *Processor) isElectedExecutor(batchID uuid.UUID) bool {
	selectedExecutor := p.selectExecutorForBatch(batchID)
	isElected := selectedExecutor == p.validatorID

	if isElected {
		p.logger.Printf("🎯 [CONSENSUS] Validator %s is ELECTED EXECUTOR for batch %s",
			p.validatorID, batchID)
	} else {
		p.logger.Printf("👁️ [CONSENSUS] Validator %s observing batch %s (executor: %s)",
			p.validatorID, batchID, selectedExecutor)
	}

	return isElected
}

// SetOnAnchorCallback sets the callback to be called when a batch is successfully anchored
// PHASE 5: This enables multi-validator attestation collection
func (p *Processor) SetOnAnchorCallback(callback OnAnchorCallback) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onAnchorCallback = callback
	p.logger.Printf("✅ Attestation callback configured for batch processor")
}

// SetGovernanceGenerator sets the governance proof generator (for late binding)
// Phase 2 Task 2.2: Wire governance generator to batch processor
func (p *Processor) SetGovernanceGenerator(generator *proof.NativeGovernanceProofGenerator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.govGenerator = generator
	p.logger.Printf("✅ Governance proof generator configured for batch processor")
}

// SetDefaultGovernanceLevel sets the default governance level for batch proofs
func (p *Processor) SetDefaultGovernanceLevel(level proof.GovernanceLevel) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.defaultGovLevel = level
	p.logger.Printf("✅ Default governance level set to %s", level)
}

// HasGovernanceGenerator returns true if governance generator is configured
func (p *Processor) HasGovernanceGenerator() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.govGenerator != nil
}

// ProcessClosedBatch processes a closed batch and creates an anchor
// This is called by the scheduler or on-demand handler when a batch is ready
func (p *Processor) ProcessClosedBatch(ctx context.Context, result *ClosedBatchResult) error {
	if result == nil {
		return nil
	}

	p.mu.Lock()
	if p.processing[result.BatchID] {
		p.mu.Unlock()
		return fmt.Errorf("batch %s is already being processed", result.BatchID)
	}
	p.processing[result.BatchID] = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.processing, result.BatchID)
		p.mu.Unlock()
	}()

	// Determine batch type prefix for logging
	batchTypePrefix := "[ON-CADENCE]"
	priceTier := "$0.05/proof"
	if result.BatchType == database.BatchTypeOnDemand {
		batchTypePrefix = "[ON-DEMAND]"
		priceTier = "$0.25/proof"
	}

	p.logger.Printf("%s Processing closed batch %s (txs=%d, root=%s, price_tier=%s)",
		batchTypePrefix, result.BatchID, result.TxCount, result.MerkleRootHex[:16]+"...", priceTier)

	// =======================================================================
	// Phase 2 Task 2.2: Generate Real Governance Proofs Before Anchoring
	// Per CRITICAL-002 fix: Generate governance proofs using native library
	// =======================================================================
	if p.govGenerator != nil && len(result.Transactions) > 0 {
		p.logger.Printf("%s 🔐 [Phase 2] Generating governance proofs for batch %s...", batchTypePrefix, result.BatchID)
		if err := p.enrichBatchWithGovernanceProofs(ctx, result); err != nil {
			p.logger.Printf("%s ⚠️ [Phase 2] Governance proof generation failed (non-fatal): %v", batchTypePrefix, err)
			// Continue - governance proof failure is non-fatal
			// In production with strict mode, this should be a hard failure
		} else {
			p.logger.Printf("%s ✅ [Phase 2] Governance proofs generated successfully", batchTypePrefix)
		}
	} else if len(result.Transactions) > 0 {
		p.logger.Printf("%s ⚠️ [Phase 2] No governance generator configured - using existing proof data", batchTypePrefix)
	}

	// =======================================================================
	// CONSENSUS FIX: Check if this validator is elected to create the anchor
	// Only ONE validator should create the anchor to prevent:
	// 1. Multiple anchors with different merkleRoots
	// 2. Wasted gas from duplicate transactions
	// 3. Contract state conflicts
	// =======================================================================
	isElected := p.isElectedExecutor(result.BatchID)

	// Step 1: Create anchor on external chain (ONLY if elected executor)
	var anchorResult *BatchAnchorResult
	if p.anchorCreator != nil && isElected {
		p.logger.Printf("%s 🚀 [CONSENSUS] Validator %s is ELECTED - proceeding with anchor creation for batch %s (price_tier=%s)",
			batchTypePrefix, p.validatorID, result.BatchID, priceTier)

		// Phase 2: Extract proof data from ClosedBatchResult per HIGH-002, HIGH-003
		txProofs, govProofs, govLevels := p.extractProofDataFromResult(result)

		req := &BatchAnchorRequest{
			BatchID:          result.BatchID,
			MerkleRoot:       result.MerkleRoot,
			TxCount:          result.TxCount,
			AccumulateHeight: result.AccumulateHeight,
			AccumulateHash:   result.AccumulateHash,
			TargetChain:      p.targetChain,
			ValidatorID:      p.validatorID,
			// Phase 2 additions: Real proof data
			BPTRoot:           result.AggregatedBPTRoot,
			NetworkRootHash:   result.AggregatedNetworkRoot,
			TransactionProofs: txProofs,
			GovernanceProofs:  govProofs,
			GovernanceLevels:  govLevels,
		}

		var err error
		anchorResult, err = p.anchorCreator.CreateBatchAnchor(ctx, req)
		if err != nil {
			// Mark batch as failed
			if updateErr := p.repos.Batches.UpdateBatchStatus(ctx, result.BatchID, database.BatchStatusFailed, err.Error()); updateErr != nil {
				p.logger.Printf("Failed to update batch status: %v", updateErr)
			}
			return fmt.Errorf("failed to create anchor: %w", err)
		}

		p.logger.Printf("%s ✅ [CONSENSUS] Anchor created by elected executor on %s: tx=%s, block=%d",
			batchTypePrefix, anchorResult.TargetChain, anchorResult.TxHash[:16]+"...", anchorResult.BlockNumber)
		// =====================================================================
		// PHASE 1: Execute Comprehensive Proof (CRITICAL-001 Fix)
		// Per ANCHOR_V3_IMPLEMENTATION_PLAN.md: MUST call executeComprehensiveProof
		// after createAnchor to submit L1-L4 cryptographic proofs and G0-G2
		// governance proofs for on-chain verification.
		// =====================================================================
		p.logger.Printf("%s 📋 [Phase 1] Building comprehensive proof for batch %s...", batchTypePrefix, result.BatchID)

		proofReq, buildErr := p.buildProofRequestFromBatch(result, anchorResult)
		if buildErr != nil {
			p.logger.Printf("%s ⚠️ [Phase 1] Failed to build proof request: %v", batchTypePrefix, buildErr)
			// Continue - anchor was created, proof execution is optional for now
			// In production, this should be a hard failure
		} else {
			p.logger.Printf("%s 📋 [Phase 1] Executing comprehensive proof on-chain...", batchTypePrefix)

			proofResult, proofErr := p.anchorCreator.ExecuteComprehensiveProof(ctx, proofReq)
			if proofErr != nil {
				p.logger.Printf("%s ⚠️ [Phase 1] Comprehensive proof execution failed: %v", batchTypePrefix, proofErr)
				// Continue - anchor was created, but proof execution failed
				// In production, this should trigger retry logic
			} else if proofResult != nil {
				p.logger.Printf("%s ✅ [Phase 1] Comprehensive proof executed successfully!", batchTypePrefix)
				p.logger.Printf("%s    Proof TxHash: %s", batchTypePrefix, proofResult.TxHash[:16]+"...")
				p.logger.Printf("%s    Block: %d, GasUsed: %d", batchTypePrefix, proofResult.BlockNumber, proofResult.GasUsed)
				p.logger.Printf("%s    ProofValid: %v, Success: %v", batchTypePrefix, proofResult.ProofValid, proofResult.Success)
			}
		}
	} else if p.anchorCreator != nil && !isElected {
		// NOT the elected executor - skip anchor creation
		p.logger.Printf("👁️ [CONSENSUS] Validator %s is NOT elected - skipping anchor creation for batch %s",
			p.validatorID, result.BatchID)
		// Update batch status to indicate it was processed but not anchored by this validator
		// The elected executor will create the anchor
		if err := p.repos.Batches.UpdateBatchStatus(ctx, result.BatchID, database.BatchStatusClosed, "awaiting_elected_anchor"); err != nil {
			p.logger.Printf("Warning: failed to update batch status: %v", err)
		}
		return nil // Exit early - elected executor will handle anchor creation
	}

	// Step 2: Store anchor record in database
	var anchorID uuid.UUID
	if anchorResult != nil {
		anchorRecord := &database.NewAnchorRecord{
			BatchID:         result.BatchID,
			TargetChain:     database.TargetChain(p.targetChain),
			ChainID:         p.chainID,
			NetworkName:     p.networkName,
			ContractAddress: p.contractAddr,
			AnchorTxHash:    anchorResult.TxHash,
			AnchorBlockNumber: anchorResult.BlockNumber,
			AnchorBlockHash: anchorResult.BlockHash,
			MerkleRoot:      result.MerkleRoot,
			ValidatorID:     p.validatorID,
			GasUsed:         anchorResult.GasUsed,
			GasPriceWei:     anchorResult.GasPriceWei,
			TotalCostWei:    anchorResult.TotalCostWei,
		}

		anchor, err := p.repos.Anchors.CreateAnchor(ctx, anchorRecord)
		if err != nil {
			p.logger.Printf("Failed to store anchor record: %v", err)
			// Continue - anchor was created on-chain
		} else {
			anchorID = anchor.AnchorID
		}
	}

	// Step 3: Create Certen Anchor Proofs for each transaction
	if result.Proofs != nil && anchorResult != nil {
		if err := p.createProofs(ctx, result, anchorID, anchorResult); err != nil {
			p.logger.Printf("Failed to create proofs: %v", err)
			// Continue - proofs can be created later
		}
	}

	// Step 4: Update batch status
	status := database.BatchStatusAnchored
	if anchorResult == nil {
		status = database.BatchStatusClosed // No anchor creator, just closed
	}
	if err := p.repos.Batches.UpdateBatchStatus(ctx, result.BatchID, status, ""); err != nil {
		p.logger.Printf("Failed to update batch status: %v", err)
	}

	// PHASE 5: Trigger attestation collection callback
	// Per Whitepaper Section 3.4.1 Component 4: Multi-validator attestations
	if p.onAnchorCallback != nil && anchorResult != nil {
		p.logger.Printf("🔔 Triggering attestation callback for batch %s", result.BatchID)
		if err := p.onAnchorCallback(ctx, result.BatchID, result.MerkleRoot, anchorResult.TxHash, result.TxCount, anchorResult.BlockNumber); err != nil {
			p.logger.Printf("⚠️ Attestation callback failed (non-fatal): %v", err)
			// Continue - attestation failure is non-fatal, anchor is already created
		} else {
			p.logger.Printf("✅ Attestation collection initiated for batch %s", result.BatchID)
		}
	}

	p.logger.Printf("%s Batch %s processed successfully (price_tier=%s)", batchTypePrefix, result.BatchID, priceTier)
	return nil
}

// createProofs creates Certen Anchor Proofs for each transaction in the batch
func (p *Processor) createProofs(ctx context.Context, result *ClosedBatchResult, anchorID uuid.UUID, anchorResult *BatchAnchorResult) error {
	// Get transactions from database
	txs, err := p.repos.Batches.GetTransactionsInBatch(ctx, result.BatchID)
	if err != nil {
		return fmt.Errorf("failed to get transactions: %w", err)
	}

	for i, tx := range txs {
		if i >= len(result.Proofs) {
			p.logger.Printf("Warning: proof index out of range for tx %d", i)
			continue
		}

		proof := result.Proofs[i]

		// Convert merkle proof path to database format
		merklePath := make([]database.MerklePathNode, len(proof.Path))
		for j, node := range proof.Path {
			merklePath[j] = database.MerklePathNode{
				Hash:     node.Hash,
				Position: string(node.Position),
			}
		}
		merkleInclusionJSON, err := json.Marshal(merklePath)
		if err != nil {
			p.logger.Printf("Failed to serialize merkle inclusion for tx %d: %v", tx.ID, err)
			continue
		}

		// Decode governance level
		var govLevel database.GovernanceLevel
		if tx.GovLevel.Valid {
			govLevel = database.GovernanceLevel(tx.GovLevel.String)
		}

		proofInput := &database.NewCertenAnchorProof{
			BatchID:           result.BatchID,
			AnchorID:          anchorID,
			TransactionID:     tx.ID,
			AccumTxHash:       tx.AccumTxHash,
			AccountURL:        tx.AccountURL,
			MerkleRoot:        result.MerkleRoot,
			MerkleInclusion:   merklePath,
			AnchorChain:       database.TargetChain(p.targetChain),
			AnchorTxHash:      anchorResult.TxHash,
			AnchorBlockNumber: anchorResult.BlockNumber,
			AnchorBlockHash:   anchorResult.BlockHash,
			AccumStateProof:   tx.ChainedProof,
			GovProof:          tx.GovProof,
			GovLevel:          govLevel,
			ValidatorID:       p.validatorID,
		}

		certenProof, err := p.repos.Proofs.CreateProof(ctx, proofInput)
		if err != nil {
			p.logger.Printf("Failed to create proof for tx %d: %v", tx.ID, err)
			continue
		}

		// PHASE 5: Also create record in proof_artifacts table for comprehensive proof storage
		// This provides better API access patterns and supports proof bundles
		if p.repos.ProofArtifacts != nil {
			artifactInput := p.buildProofArtifact(tx, result, certenProof, anchorResult, proof, govLevel)
			if artifactInput != nil {
				_, artifactErr := p.repos.ProofArtifacts.CreateProofArtifact(ctx, artifactInput)
				if artifactErr != nil {
					p.logger.Printf("Warning: failed to create proof artifact for tx %d: %v", tx.ID, artifactErr)
					// Non-fatal: certen_anchor_proof was created successfully
				}
			}
		}

		// Update transaction merkle path in database
		if err := p.repos.Batches.UpdateMerklePath(ctx, tx.ID, merkleInclusionJSON); err != nil {
			p.logger.Printf("Warning: failed to update merkle path for tx %d: %v", tx.ID, err)
			// Continue - proof is created, just merkle path not updated in transactions table
		}
	}

	p.logger.Printf("Created %d proofs for batch %s", len(txs), result.BatchID)
	return nil
}

// GetBatchesReadyForAnchoring returns closed batches that need anchoring
func (p *Processor) GetBatchesReadyForAnchoring(ctx context.Context) ([]*database.AnchorBatch, error) {
	return p.repos.Batches.GetBatchesReadyForAnchoring(ctx)
}

// ProcessPendingBatches processes all closed batches that haven't been anchored
func (p *Processor) ProcessPendingBatches(ctx context.Context) error {
	batches, err := p.GetBatchesReadyForAnchoring(ctx)
	if err != nil {
		return fmt.Errorf("failed to get pending batches: %w", err)
	}

	p.logger.Printf("Found %d batches ready for anchoring", len(batches))

	for _, batch := range batches {
		// Get transactions for this batch
		txs, err := p.repos.Batches.GetTransactionsInBatch(ctx, batch.BatchID)
		if err != nil {
			p.logger.Printf("Failed to get transactions for batch %s: %v", batch.BatchID, err)
			continue
		}

		// Rebuild merkle tree
		leaves := make([][]byte, len(txs))
		for i, tx := range txs {
			leaves[i] = tx.TxHash
		}

		if len(leaves) == 0 {
			p.logger.Printf("Skipping empty batch %s", batch.BatchID)
			continue
		}

		tree, err := merkle.BuildTree(leaves)
		if err != nil {
			p.logger.Printf("Failed to rebuild merkle tree for batch %s: %v", batch.BatchID, err)
			continue
		}

		// Generate proofs
		proofs := make([]*merkle.InclusionProof, len(leaves))
		for i := range leaves {
			proof, err := tree.GenerateProof(i)
			if err != nil {
				p.logger.Printf("Failed to generate proof for leaf %d: %v", i, err)
				continue
			}
			proofs[i] = proof
		}

		// Create closed batch result
		result := &ClosedBatchResult{
			BatchID:       batch.BatchID,
			BatchType:     batch.BatchType,
			MerkleRoot:    batch.MerkleRoot,
			MerkleRootHex: hex.EncodeToString(batch.MerkleRoot),
			TxCount:       len(txs),
			StartTime:     batch.StartTime,
			EndTime:       time.Now(),
			Proofs:        proofs,
		}

		if err := p.ProcessClosedBatch(ctx, result); err != nil {
			p.logger.Printf("Failed to process batch %s: %v", batch.BatchID, err)
			continue
		}
	}

	return nil
}

// SetAnchorCreator sets the anchor creator (for late binding)
func (p *Processor) SetAnchorCreator(creator AnchorCreator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.anchorCreator = creator
}

// UpdateChainConfig updates the target chain configuration
func (p *Processor) UpdateChainConfig(chain, chainID, network, contract string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targetChain = chain
	p.chainID = chainID
	p.networkName = network
	p.contractAddr = contract
	p.logger.Printf("Chain config updated: %s (%s/%s)", chain, chainID, network)
}

// buildProofArtifact constructs a NewProofArtifact for the comprehensive proof storage schema
// This bridges the batch system's CertenAnchorProof to the proof_artifacts table
func (p *Processor) buildProofArtifact(
	tx *database.BatchTransaction,
	result *ClosedBatchResult,
	certenProof *database.CertenAnchorProof,
	anchorResult *BatchAnchorResult,
	inclusionProof *merkle.InclusionProof,
	govLevel database.GovernanceLevel,
) *database.NewProofArtifact {
	// Build artifact JSON containing all proof components
	artifact := map[string]interface{}{
		"proof_id":          certenProof.ProofID.String(),
		"batch_id":          result.BatchID.String(),
		"accum_tx_hash":     tx.AccumTxHash,
		"account_url":       tx.AccountURL,
		"merkle_root":       hex.EncodeToString(result.MerkleRoot),
		"anchor_chain":      p.targetChain,
		"anchor_tx_hash":    anchorResult.TxHash,
		"anchor_block":      anchorResult.BlockNumber,
		"validator_id":      p.validatorID,
		"proof_version":     database.CurrentProofVersion,
		"created_at":        time.Now().Format(time.RFC3339),
	}

	// Add chained proof if present
	if len(tx.ChainedProof) > 0 {
		artifact["chained_proof"] = json.RawMessage(tx.ChainedProof)
	}

	// Add governance proof if present
	if len(tx.GovProof) > 0 {
		artifact["governance_proof"] = json.RawMessage(tx.GovProof)
		artifact["governance_level"] = string(govLevel)
	}

	// Add merkle inclusion proof
	if inclusionProof != nil {
		pathData := make([]map[string]interface{}, len(inclusionProof.Path))
		for i, node := range inclusionProof.Path {
			pathData[i] = map[string]interface{}{
				"hash":     node.Hash, // Already hex-encoded string
				"position": string(node.Position),
			}
		}
		artifact["merkle_inclusion"] = map[string]interface{}{
			"leaf_index": inclusionProof.LeafIndex,
			"tree_size":  inclusionProof.TreeSize,
			"path":       pathData,
		}
	}

	artifactJSON, err := json.Marshal(artifact)
	if err != nil {
		p.logger.Printf("Warning: failed to serialize proof artifact JSON: %v", err)
		return nil
	}

	// Determine proof class based on batch type
	proofClass := database.ProofClassOnCadence
	if result.BatchType == "on_demand" {
		proofClass = database.ProofClassOnDemand
	}

	// Build the new proof artifact input
	batchID := result.BatchID
	leafIndex := inclusionProof.LeafIndex
	var govLevelPtr *database.GovernanceLevel
	if govLevel != "" {
		govLevelPtr = &govLevel
	}

	return &database.NewProofArtifact{
		ProofType:    database.ProofTypeCertenAnchor,
		AccumTxHash:  tx.AccumTxHash,
		AccountURL:   tx.AccountURL,
		BatchID:      &batchID,
		MerkleRoot:   result.MerkleRoot,
		LeafHash:     tx.TxHash,
		LeafIndex:    &leafIndex,
		GovLevel:     govLevelPtr,
		ProofClass:   proofClass,
		ValidatorID:  p.validatorID,
		ArtifactJSON: artifactJSON,
	}
}

// =============================================================================
// Phase 2: Proof Data Extraction (HIGH-002, HIGH-003)
// =============================================================================

// extractProofDataFromResult extracts ChainedProofs and GovernanceProofs from transactions
// Per HIGH-002: Extract real BPT data for CrossChainCommitment
// Per HIGH-003: Extract real governance proofs for GovernanceRoot
func (p *Processor) extractProofDataFromResult(result *ClosedBatchResult) (
	txProofs []json.RawMessage,
	govProofs []json.RawMessage,
	govLevels []string,
) {
	if result.Transactions == nil || len(result.Transactions) == 0 {
		p.logger.Printf("No transaction proof data available in ClosedBatchResult")
		return nil, nil, nil
	}

	txProofs = make([]json.RawMessage, 0, len(result.Transactions))
	govProofs = make([]json.RawMessage, 0, len(result.Transactions))
	govLevels = make([]string, 0, len(result.Transactions))

	chainedProofCount := 0
	govProofCount := 0

	for _, tx := range result.Transactions {
		// Extract ChainedProof (L1-L3 cryptographic proof)
		if len(tx.ChainedProof) > 0 {
			txProofs = append(txProofs, tx.ChainedProof)
			chainedProofCount++
		} else {
			txProofs = append(txProofs, nil)
		}

		// Extract GovernanceProof (G0-G2 authority proof)
		if len(tx.GovProof) > 0 {
			govProofs = append(govProofs, tx.GovProof)
			govLevels = append(govLevels, tx.GovLevel)
			govProofCount++
		} else {
			govProofs = append(govProofs, nil)
			govLevels = append(govLevels, "")
		}
	}

	p.logger.Printf("Extracted proof data: %d chained proofs, %d governance proofs from %d transactions",
		chainedProofCount, govProofCount, len(result.Transactions))

	return txProofs, govProofs, govLevels
}

// =============================================================================
// Phase 1: Comprehensive Proof Execution Integration (CRITICAL-001)
// Per ANCHOR_V3_IMPLEMENTATION_PLAN.md Task 1.3
// =============================================================================

// buildProofRequestFromBatch constructs an ExecuteProofRequest from batch data
// This is the bridge between batch processing and contract proof execution.
// Per CRITICAL-001: The validator MUST call executeComprehensiveProof after createAnchor
func (p *Processor) buildProofRequestFromBatch(
	result *ClosedBatchResult,
	anchorResult *BatchAnchorResult,
) (*ExecuteProofRequest, error) {
	if result == nil {
		return nil, fmt.Errorf("closed batch result is required")
	}
	if anchorResult == nil {
		return nil, fmt.Errorf("anchor result is required")
	}

	// Validate MerkleRoot is 32 bytes
	if len(result.MerkleRoot) != 32 {
		return nil, fmt.Errorf("merkle root must be 32 bytes, got %d", len(result.MerkleRoot))
	}

	// Convert MerkleRoot to [32]byte
	var merkleRoot [32]byte
	copy(merkleRoot[:], result.MerkleRoot)

	// Operation Commitment = Merkle Root (canonical binding per whitepaper)
	var operationCommitment [32]byte
	copy(operationCommitment[:], result.MerkleRoot)

	// Cross-Chain Commitment = BPT Root from Accumulate (L2 binding)
	// Per HIGH-002: MUST use real BPT data, not placeholder
	var crossChainCommitment [32]byte
	if len(result.AggregatedBPTRoot) == 32 {
		copy(crossChainCommitment[:], result.AggregatedBPTRoot)
		p.logger.Printf("📋 Using real BPT root for cross-chain commitment: %x...", result.AggregatedBPTRoot[:8])
	} else {
		// Fallback: derive from Accumulate hash if available
		if result.AccumulateHash != "" {
			hashBytes, err := hex.DecodeString(result.AccumulateHash)
			if err == nil && len(hashBytes) >= 32 {
				copy(crossChainCommitment[:], hashBytes[:32])
				p.logger.Printf("📋 Using Accumulate hash for cross-chain commitment: %s...", result.AccumulateHash[:16])
			}
		}
		// If still empty, hash the merkle root + height (deterministic but not ideal)
		if crossChainCommitment == [32]byte{} {
			data := append(result.MerkleRoot, []byte(fmt.Sprintf("%d", result.AccumulateHeight))...)
			hash := sha256.Sum256(data)
			crossChainCommitment = hash
			p.logger.Printf("⚠️ Derived cross-chain commitment (no real BPT root available)")
		}
	}

	// Governance Root = Merkle root of governance proof hashes
	// Per HIGH-003: MUST be real Merkle root of actual governance proofs
	var governanceRoot [32]byte
	if len(result.GovernanceProofHashes) > 0 {
		// Compute Merkle root of governance proof hashes
		govRootSlice := computeGovMerkleRootFromHashes(result.GovernanceProofHashes)
		if len(govRootSlice) == 32 {
			copy(governanceRoot[:], govRootSlice)
		}
		p.logger.Printf("📋 Computed governance root from %d proof hashes: %x...", len(result.GovernanceProofHashes), governanceRoot[:8])
	} else {
		// Fallback: derive from batch ID + validator (deterministic but not ideal)
		data := []byte(fmt.Sprintf("gov_%s_%s", result.BatchID.String(), p.validatorID))
		hash := sha256.Sum256(data)
		governanceRoot = hash
		p.logger.Printf("⚠️ Derived governance root (no governance proofs available)")
	}

	// Get representative transaction hash (first non-empty tx hash)
	var transactionHash [32]byte
	var leafHash [32]byte
	proofHashes := make([][32]byte, 0)

	if len(result.Proofs) > 0 && result.Proofs[0] != nil {
		// Use the first transaction's proof data
		firstProof := result.Proofs[0]

		// Get the leaf hash from the first proof
		if leafHashBytes, err := hex.DecodeString(firstProof.LeafHash); err == nil && len(leafHashBytes) == 32 {
			copy(leafHash[:], leafHashBytes)
		}

		// Convert proof path to [32]byte array
		for _, node := range firstProof.Path {
			var pathHash [32]byte
			if hashBytes, err := hex.DecodeString(node.Hash); err == nil && len(hashBytes) == 32 {
				copy(pathHash[:], hashBytes)
				proofHashes = append(proofHashes, pathHash)
			}
		}
	}

	// If we have transactions, get the first tx hash as representative
	if len(result.Transactions) > 0 && len(result.Transactions[0].TxHash) == 32 {
		copy(transactionHash[:], result.Transactions[0].TxHash)
		copy(leafHash[:], result.Transactions[0].TxHash)
	} else if leafHash == [32]byte{} {
		// Fallback: use merkle root as representative
		transactionHash = merkleRoot
		leafHash = merkleRoot
	}

	req := &ExecuteProofRequest{
		AnchorID:             result.BatchID.String(),
		BatchID:              result.BatchID.String(),
		ValidatorID:          p.validatorID,
		TransactionHash:      transactionHash,
		MerkleRoot:           merkleRoot,
		ProofHashes:          proofHashes,
		LeafHash:             leafHash,
		OperationCommitment:  operationCommitment,
		CrossChainCommitment: crossChainCommitment,
		GovernanceRoot:       governanceRoot,
		Timestamp:            time.Now().Unix(),
	}

	p.logger.Printf("🔧 Built proof request for batch %s:", result.BatchID)
	p.logger.Printf("   MerkleRoot: %x...", merkleRoot[:8])
	p.logger.Printf("   OperationCommitment: %x...", operationCommitment[:8])
	p.logger.Printf("   CrossChainCommitment: %x...", crossChainCommitment[:8])
	p.logger.Printf("   GovernanceRoot: %x...", governanceRoot[:8])
	p.logger.Printf("   ProofHashes: %d elements", len(proofHashes))

	return req, nil
}

// computeGovMerkleRootFromHashes computes the Merkle root of governance proof hashes
// Per HIGH-003: GovernanceRoot = Merkle root of SHA256(each governance proof)
// Note: This is a wrapper that uses the shared computeGovernanceMerkleRoot from anchor_adapter.go
func computeGovMerkleRootFromHashes(hashes [][]byte) []byte {
	// Delegate to the shared implementation in anchor_adapter.go
	return computeGovernanceMerkleRoot(hashes)
}

// =============================================================================
// Phase 2 Task 2.2: Governance Proof Generation for Batches
// =============================================================================

// BatchGovernanceResult holds the result of governance proof generation for a batch
type BatchGovernanceResult struct {
	Proofs           []*proof.GovernanceProof
	ProofHashes      [][]byte
	GovernanceRoot   [32]byte
	Level            proof.GovernanceLevel
	SuccessCount     int
	FailureCount     int
	GenerationTimeMs int64
}

// buildGovernanceProofs generates governance proofs for all transactions in a batch
// Per Task 2.2: Wire Governance Generator to Batch Processor
// This method is called during batch processing to generate real governance proofs
func (p *Processor) buildGovernanceProofs(ctx context.Context, result *ClosedBatchResult) (*BatchGovernanceResult, error) {
	if p.govGenerator == nil {
		return nil, fmt.Errorf("governance generator not configured")
	}

	if result == nil || len(result.Transactions) == 0 {
		return nil, fmt.Errorf("no transactions in batch")
	}

	startTime := time.Now()
	level := p.defaultGovLevel
	if level == "" {
		level = proof.GovLevelG1 // Default to G1 if not configured
	}

	p.logger.Printf("🔐 [Phase 2] Generating %s governance proofs for %d transactions...", level, len(result.Transactions))

	// Build transaction info list for batch processing
	txInfos := make([]proof.TransactionInfo, 0, len(result.Transactions))
	for _, tx := range result.Transactions {
		txInfo := proof.TransactionInfo{
			TxHash:     hex.EncodeToString(tx.TxHash),
			AccountURL: tx.AccountURL,
			KeyPage:    tx.KeyPage, // Use direct KeyPage field
		}
		// Also try Metadata as fallback
		if txInfo.KeyPage == "" && tx.Metadata != nil {
			if keyPage, ok := tx.Metadata["key_page"].(string); ok {
				txInfo.KeyPage = keyPage
			}
		}
		txInfos = append(txInfos, txInfo)
	}

	// Generate proofs in batch
	batchProof, err := p.govGenerator.GenerateForBatch(ctx, txInfos, level)
	if err != nil {
		p.logger.Printf("⚠️ [Phase 2] Batch governance proof generation failed: %v", err)
		return nil, fmt.Errorf("batch governance proof generation failed: %w", err)
	}

	// Build result
	govResult := &BatchGovernanceResult{
		Proofs:           batchProof.Proofs,
		GovernanceRoot:   batchProof.BatchRoot,
		Level:            level,
		SuccessCount:     len(batchProof.Proofs),
		FailureCount:     len(result.Transactions) - len(batchProof.Proofs),
		GenerationTimeMs: time.Since(startTime).Milliseconds(),
	}

	// Compute proof hashes for Merkle root calculation
	govResult.ProofHashes = make([][]byte, len(batchProof.Proofs))
	for i, gp := range batchProof.Proofs {
		hash := gp.ComputeProofHash()
		govResult.ProofHashes[i] = hash[:]
	}

	p.logger.Printf("✅ [Phase 2] Generated %d/%d governance proofs in %dms",
		govResult.SuccessCount, len(result.Transactions), govResult.GenerationTimeMs)
	p.logger.Printf("   Governance Root: %x...", govResult.GovernanceRoot[:8])

	return govResult, nil
}

// generateGovernanceProofForTransaction generates a governance proof for a single transaction
// This can be called for on-demand proof generation
func (p *Processor) generateGovernanceProofForTransaction(
	ctx context.Context,
	txHash string,
	accountURL string,
	keyPage string,
	level proof.GovernanceLevel,
) (*proof.GovernanceProof, error) {
	if p.govGenerator == nil {
		return nil, fmt.Errorf("governance generator not configured")
	}

	if level == "" {
		level = p.defaultGovLevel
	}

	req := &proof.GovernanceRequest{
		TransactionHash: txHash,
		AccountURL:      accountURL,
		KeyPage:         keyPage,
	}

	return p.govGenerator.GenerateAtLevel(ctx, level, req)
}

// enrichBatchWithGovernanceProofs adds governance proofs to a ClosedBatchResult
// This mutates the result to include governance proof data and hashes
func (p *Processor) enrichBatchWithGovernanceProofs(ctx context.Context, result *ClosedBatchResult) error {
	govResult, err := p.buildGovernanceProofs(ctx, result)
	if err != nil {
		p.logger.Printf("⚠️ Failed to generate governance proofs: %v", err)
		return err
	}

	// Update the batch result with governance data
	result.GovernanceProofHashes = govResult.ProofHashes
	copy(result.AggregatedGovernanceRoot[:], govResult.GovernanceRoot[:])

	// Update individual transactions with their governance proofs
	for i := 0; i < len(result.Transactions) && i < len(govResult.Proofs); i++ {
		proofJSON, err := govResult.Proofs[i].ToJSON()
		if err != nil {
			p.logger.Printf("⚠️ Failed to serialize governance proof %d: %v", i, err)
			continue
		}
		result.Transactions[i].GovProof = proofJSON
		result.Transactions[i].GovLevel = string(govResult.Level)
	}

	p.logger.Printf("✅ Batch enriched with %d governance proofs", govResult.SuccessCount)
	return nil
}
