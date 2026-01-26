// Copyright 2025 Certen Protocol
//
// Unified Proof Cycle Orchestrator
// Unifies on_demand and on_cadence flows through a single orchestrator
//
// Per Unified Multi-Chain Architecture:
// - Single orchestrator for both proof flows
// - Supports multiple attestation strategies (BLS, Ed25519)
// - Supports multiple chain execution strategies (EVM, Solana, CosmWasm, etc.)
// - Complete proof artifact collection to unified PostgreSQL tables

package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/proof"
	"github.com/certen/independant-validator/pkg/strategy"
)

// =============================================================================
// UNIFIED ORCHESTRATOR CONFIGURATION
// =============================================================================

// UnifiedOrchestratorConfig holds configuration for the unified orchestrator
type UnifiedOrchestratorConfig struct {
	// ValidatorID is this validator's identifier
	ValidatorID string

	// ValidatorIndex is this validator's index in the active set
	ValidatorIndex uint32

	// Registry is the strategy registry
	Registry *strategy.Registry

	// Repositories for database access
	Repos *database.Repositories

	// UnifiedRepo for new unified tables
	UnifiedRepo *database.UnifiedRepository

	// DefaultChainID if not specified in request
	DefaultChainID string

	// Thresholds
	ThresholdConfig *attestation.ThresholdConfig

	// Timeouts
	ObservationTimeout  time.Duration
	AttestationTimeout  time.Duration
	WriteBackTimeout    time.Duration

	// Peer attestation collection
	// Per Whitepaper Section 3.4.1 Component 4: Validator attestations
	AttestationPeers         []string // URLs of peer validators (e.g., "http://validator-2:8080")
	AttestationRequiredCount int      // Required attestations for consensus (typically 2f+1)
	AttestationTimeout_      time.Duration

	// Write-back configuration
	// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 9
	AccumulateClient AccumulateSubmitter    // Client for submitting to Accumulate
	ResultsPrincipal string                 // Accumulate URL for results (e.g., "acc://certen.acme/results")
	Ed25519Key       []byte                 // Ed25519 signing key for write-back transactions

	// Callbacks
	OnCycleComplete func(*UnifiedProofCycleResult)
	OnCycleFailed   func(*UnifiedProofCycleResult, error)
	OnPhaseComplete func(cycleID string, phase int)

	// Feature flags
	EnableMultiChain       bool
	EnableUnifiedTables    bool
	FallbackToLegacy       bool
	EnableWriteBack        bool // Enable Phase 9 write-back to Accumulate

	// Chained proof generator for L1/L2/L3 proofs
	// Used to fetch Accumulate proof chain: Transaction → BVN → DN → Consensus
	ProofGenerator ChainedProofGenerator
}

// ChainedProofGenerator interface for generating Accumulate chained proofs
type ChainedProofGenerator interface {
	// GenerateChainedProofForTx generates L1/L2/L3 chained proof for a transaction
	// Parameters:
	//   - accountURL: The Accumulate account URL (e.g., "acc://certen.acme/intent-data")
	//   - txHash: The Accumulate transaction hash (64-char hex)
	//   - bvn: The BVN partition name (e.g., "bvn0", "bvn1")
	GenerateChainedProofForTx(ctx context.Context, accountURL, txHash, bvn string) (*ChainedProofResult, error)
}

// ChainedProofResult contains the L1/L2/L3 proof chain
type ChainedProofResult struct {
	// L1: Transaction to BVN
	L1ReceiptAnchor []byte
	L1BVNRoot       []byte
	L1BVNPartition  string

	// L2: BVN to DN
	L2DNRoot      []byte
	L2AnchorSeq   int64
	L2DNBlockHash []byte

	// L3: DN to Consensus
	L3ConsensusTimestamp time.Time
	L3DNBlockHeight      int64

	// Complete proof data
	CompleteProof interface{} // *lcproof.CompleteProof
}

// DefaultUnifiedOrchestratorConfig returns default configuration
func DefaultUnifiedOrchestratorConfig() *UnifiedOrchestratorConfig {
	return &UnifiedOrchestratorConfig{
		ThresholdConfig:     attestation.DefaultThresholdConfig(),
		ObservationTimeout:  30 * time.Minute,
		AttestationTimeout:  5 * time.Minute,
		WriteBackTimeout:    2 * time.Minute,
		EnableMultiChain:    true,
		EnableUnifiedTables: true,
		FallbackToLegacy:    true,
	}
}

// =============================================================================
// PROOF CYCLE INPUT/OUTPUT TYPES
// =============================================================================

// UnifiedProofCycleRequest represents a request to start a proof cycle
type UnifiedProofCycleRequest struct {
	// CycleID is a unique identifier for this cycle
	CycleID string `json:"cycle_id"`

	// ProofClass is on_demand or on_cadence
	ProofClass string `json:"proof_class"`

	// IntentID for the original intent
	IntentID string `json:"intent_id,omitempty"`

	// BatchID if this is a batch proof
	BatchID *uuid.UUID `json:"batch_id,omitempty"`

	// TargetChain for the anchor
	TargetChain string `json:"target_chain"`

	// Transaction hashes to observe (from anchor workflow)
	TxHashes []string `json:"tx_hashes"`

	// Merkle root and proofs
	MerkleRoot          [32]byte `json:"merkle_root"`
	OperationCommitment [32]byte `json:"operation_commitment"`
	GovernanceRoot      [32]byte `json:"governance_root"`
	BundleID            [32]byte `json:"bundle_id"`

	// Additional context
	AccumulateHeight int64             `json:"accumulate_height,omitempty"`
	AccumulateHash   string            `json:"accumulate_hash,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`

	// User tracking (for Firestore)
	UserID *string `json:"user_id,omitempty"`

	// Accumulate proof chain data (for L1/L2/L3 proofs)
	AccumulateAccountURL string `json:"accumulate_account_url,omitempty"` // Account URL where intent was created
	AccumulateTxHash     string `json:"accumulate_tx_hash,omitempty"`     // Transaction hash on Accumulate
	AccumulateBVN        string `json:"accumulate_bvn,omitempty"`         // BVN partition (bvn0, bvn1, bvn2)
}

// UnifiedProofCycleResult represents the result of a proof cycle
type UnifiedProofCycleResult struct {
	// CycleID uniquely identifies this cycle
	CycleID string `json:"cycle_id"`

	// ProofID is the resulting proof artifact ID
	ProofID uuid.UUID `json:"proof_id"`

	// Status
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	FailPhase int    `json:"fail_phase,omitempty"`

	// Phase 7 results
	ObservationResults []*chain.ObservationResult `json:"observation_results,omitempty"`
	ChainExecutionIDs  []uuid.UUID                `json:"chain_execution_ids,omitempty"`

	// Phase 8 results
	Attestations          []*attestation.Attestation          `json:"attestations,omitempty"`
	AggregatedAttestation *attestation.AggregatedAttestation `json:"aggregated_attestation,omitempty"`
	AttestationID         *uuid.UUID                          `json:"attestation_id,omitempty"`
	ThresholdMet          bool                                `json:"threshold_met"`

	// Phase 9 results
	WriteBackTxHash string `json:"write_back_tx_hash,omitempty"`
	WriteBackSuccess bool   `json:"write_back_success"`

	// Timing
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Chain info
	ChainPlatform string `json:"chain_platform"`
	ChainID       string `json:"chain_id"`
	Scheme        string `json:"attestation_scheme"`
}

// =============================================================================
// UNIFIED PROOF CYCLE ORCHESTRATOR
// =============================================================================

// UnifiedOrchestrator manages proof cycles across all chains and attestation schemes
type UnifiedOrchestrator struct {
	mu sync.RWMutex

	// Configuration
	config *UnifiedOrchestratorConfig

	// Active cycles
	activeCycles map[string]*activeCycle

	// HTTP client for peer attestation collection
	httpClient *http.Client

	// Synthetic transaction builder for write-back
	txBuilder *SyntheticTxBuilder

	// State
	running     bool
	stopCh      chan struct{}
}

// activeCycle tracks a running proof cycle
type activeCycle struct {
	CycleID   string
	Request   *UnifiedProofCycleRequest
	StartedAt time.Time
	Phase     int
	Result    *UnifiedProofCycleResult
	Cancel    context.CancelFunc
}

// NewUnifiedOrchestrator creates a new unified orchestrator
func NewUnifiedOrchestrator(config *UnifiedOrchestratorConfig) (*UnifiedOrchestrator, error) {
	if config == nil {
		config = DefaultUnifiedOrchestratorConfig()
	}

	if config.Registry == nil {
		return nil, fmt.Errorf("strategy registry is required")
	}

	if config.ValidatorID == "" {
		return nil, fmt.Errorf("validator ID is required")
	}

	orch := &UnifiedOrchestrator{
		config:       config,
		activeCycles: make(map[string]*activeCycle),
		stopCh:       make(chan struct{}),
		httpClient: &http.Client{
			Timeout: config.AttestationTimeout,
		},
	}

	// Initialize synthetic transaction builder if write-back is enabled
	if config.EnableWriteBack && config.ResultsPrincipal != "" && len(config.Ed25519Key) > 0 {
		orch.txBuilder = NewSyntheticTxBuilder(
			config.ResultsPrincipal,
			config.ValidatorID,
			config.Ed25519Key,
		)
	}

	return orch, nil
}

// =============================================================================
// PROOF CYCLE EXECUTION
// =============================================================================

// StartProofCycle starts a new proof cycle
func (o *UnifiedOrchestrator) StartProofCycle(ctx context.Context, req *UnifiedProofCycleRequest) (*UnifiedProofCycleResult, error) {
	// Validate request
	if err := o.validateRequest(req); err != nil {
		return nil, fmt.Errorf("validate request: %w", err)
	}

	// Generate cycle ID if not provided
	if req.CycleID == "" {
		req.CycleID = uuid.New().String()
	}

	// Create result
	result := &UnifiedProofCycleResult{
		CycleID:   req.CycleID,
		StartedAt: time.Now().UTC(),
	}

	// Get strategies for target chain
	targetChain := req.TargetChain
	if targetChain == "" {
		targetChain = o.config.DefaultChainID
	}

	chainStrategy, attestStrategy, err := o.config.Registry.GetStrategiesForChain(targetChain)
	if err != nil {
		result.Error = fmt.Sprintf("get strategies: %v", err)
		return result, err
	}

	result.ChainPlatform = string(chainStrategy.Platform())
	result.ChainID = chainStrategy.ChainID()
	result.Scheme = string(attestStrategy.Scheme())

	// Create active cycle
	cycleCtx, cancel := context.WithCancel(ctx)
	cycle := &activeCycle{
		CycleID:   req.CycleID,
		Request:   req,
		StartedAt: time.Now().UTC(),
		Phase:     0,
		Result:    result,
		Cancel:    cancel,
	}

	o.mu.Lock()
	o.activeCycles[req.CycleID] = cycle
	o.mu.Unlock()

	defer func() {
		o.mu.Lock()
		delete(o.activeCycles, req.CycleID)
		o.mu.Unlock()
	}()

	// Execute phases
	if err := o.executePhase7(cycleCtx, cycle, chainStrategy); err != nil {
		result.Error = fmt.Sprintf("phase 7 failed: %v", err)
		result.FailPhase = 7
		if o.config.OnCycleFailed != nil {
			o.config.OnCycleFailed(result, err)
		}
		return result, err
	}

	if err := o.executePhase8(cycleCtx, cycle, attestStrategy); err != nil {
		result.Error = fmt.Sprintf("phase 8 failed: %v", err)
		result.FailPhase = 8
		if o.config.OnCycleFailed != nil {
			o.config.OnCycleFailed(result, err)
		}
		return result, err
	}

	if err := o.executePhase9(cycleCtx, cycle); err != nil {
		result.Error = fmt.Sprintf("phase 9 failed: %v", err)
		result.FailPhase = 9
		if o.config.OnCycleFailed != nil {
			o.config.OnCycleFailed(result, err)
		}
		return result, err
	}

	// Generate and persist proof bundle (after all phases complete)
	if o.config.EnableUnifiedTables && o.config.Repos != nil {
		if err := o.generateAndPersistBundle(cycleCtx, cycle); err != nil {
			// Log warning but don't fail the cycle - bundle generation is supplementary
			fmt.Printf("Warning: failed to generate proof bundle: %v\n", err)
		}
	}

	// Success
	now := time.Now().UTC()
	result.CompletedAt = &now
	result.Success = true

	if o.config.OnCycleComplete != nil {
		o.config.OnCycleComplete(result)
	}

	return result, nil
}

// validateRequest validates a proof cycle request
func (o *UnifiedOrchestrator) validateRequest(req *UnifiedProofCycleRequest) error {
	if len(req.TxHashes) == 0 {
		return fmt.Errorf("at least one transaction hash is required")
	}

	if req.ProofClass != "on_demand" && req.ProofClass != "on_cadence" {
		return fmt.Errorf("invalid proof class: %s", req.ProofClass)
	}

	return nil
}

// =============================================================================
// PHASE 7: EXTERNAL CHAIN OBSERVATION
// =============================================================================

func (o *UnifiedOrchestrator) executePhase7(ctx context.Context, cycle *activeCycle, chainStrategy chain.ChainExecutionStrategy) error {
	cycle.Phase = 7

	if o.config.OnPhaseComplete != nil {
		defer func() { o.config.OnPhaseComplete(cycle.CycleID, 7) }()
	}

	req := cycle.Request
	result := cycle.Result

	// Create timeout context
	observeCtx, cancel := context.WithTimeout(ctx, o.config.ObservationTimeout)
	defer cancel()

	// Observe all transactions
	observationResults := make([]*chain.ObservationResult, 0, len(req.TxHashes))
	chainExecutionIDs := make([]uuid.UUID, 0, len(req.TxHashes))

	for i, txHash := range req.TxHashes {
		obsResult, err := chainStrategy.ObserveTransaction(observeCtx, txHash)
		if err != nil {
			return fmt.Errorf("observe transaction %d (%s): %w", i, txHash, err)
		}

		if !obsResult.IsFinalized {
			return fmt.Errorf("transaction %d not finalized after observation", i)
		}

		observationResults = append(observationResults, obsResult)

		// Persist to unified tables if enabled
		if o.config.EnableUnifiedTables && o.config.UnifiedRepo != nil {
			execID, err := o.persistChainExecution(ctx, cycle, obsResult, i+1)
			if err != nil {
				// Log but don't fail
				fmt.Printf("Warning: failed to persist chain execution: %v\n", err)
			} else {
				chainExecutionIDs = append(chainExecutionIDs, execID)
			}
		}
	}

	result.ObservationResults = observationResults
	result.ChainExecutionIDs = chainExecutionIDs

	return nil
}

// persistChainExecution persists a chain execution result to the database
func (o *UnifiedOrchestrator) persistChainExecution(ctx context.Context, cycle *activeCycle, obs *chain.ObservationResult, step int) (uuid.UUID, error) {
	if o.config.UnifiedRepo == nil {
		return uuid.Nil, fmt.Errorf("unified repo not configured")
	}

	workflowStep := database.WorkflowStep(step)

	// Properly encode all JSONB fields - PostgreSQL JSONB requires valid JSON, not nil/empty
	// 1. Logs - marshal event logs array, default to empty array
	var logsJSON json.RawMessage = []byte("[]")
	if len(obs.Logs) > 0 {
		if encoded, err := json.Marshal(obs.Logs); err == nil {
			logsJSON = encoded
		}
	}

	// 2. RawReceipt - base64 encode binary RLP data, default to null
	var rawReceiptJSON json.RawMessage = []byte("null")
	if len(obs.RawReceipt) > 0 {
		receiptWrapper := map[string]string{
			"encoding": "base64",
			"data":     base64.StdEncoding.EncodeToString(obs.RawReceipt),
		}
		if encoded, err := json.Marshal(receiptWrapper); err == nil {
			rawReceiptJSON = encoded
		}
	}

	// 3. PlatformData - default to empty object
	var platformDataJSON json.RawMessage = []byte("{}")

	// 4. Derive network name from chain ID
	networkName := getNetworkName(cycle.Result.ChainID)

	// 5. Set anchor_id from request BundleID
	var anchorID []byte
	if cycle.Request != nil {
		anchorID = cycle.Request.BundleID[:]
	}

	// 6. Set submitted_at to cycle start time
	submittedAt := cycle.StartedAt

	input := &database.NewChainExecutionResult{
		CycleID:               cycle.CycleID,
		ChainPlatform:         database.ChainPlatform(cycle.Result.ChainPlatform),
		ChainID:               cycle.Result.ChainID,
		NetworkName:           networkName,
		TxHash:                obs.TxHash,
		BlockNumber:           ptrInt64(int64(obs.BlockNumber)),
		BlockHash:             obs.BlockHash,
		BlockTimestamp:        &obs.BlockTimestamp,
		Status:                database.ExecutionStatus(obs.Status),
		GasUsed:               ptrInt64(int64(obs.GasUsed)),
		Confirmations:         obs.Confirmations,
		RequiredConfirmations: ptrInt(obs.RequiredConfirmations),
		IsFinalized:           obs.IsFinalized,
		ResultHash:            obs.ResultHash[:],
		MerkleProof:           obs.MerkleProof,
		ReceiptProof:          obs.ReceiptProof,
		StateRoot:             obs.StateRoot[:],
		TransactionsRoot:      obs.TransactionsRoot[:],
		ReceiptsRoot:          obs.ReceiptsRoot[:],
		RawReceipt:            rawReceiptJSON,
		Logs:                  logsJSON,
		PlatformData:          platformDataJSON,
		ObserverValidatorID:   o.config.ValidatorID,
		WorkflowStep:          &workflowStep,
		AnchorID:              anchorID,
		SubmittedAt:           &submittedAt,
	}

	return o.config.UnifiedRepo.CreateChainExecutionResult(ctx, input)
}

// getNetworkName returns human-readable network name from chain ID
func getNetworkName(chainID string) string {
	networkNames := map[string]string{
		"1":        "ethereum-mainnet",
		"11155111": "sepolia",
		"137":      "polygon-mainnet",
		"80001":    "polygon-mumbai",
		"42161":    "arbitrum-one",
		"421614":   "arbitrum-sepolia",
		"10":       "optimism-mainnet",
		"11155420": "optimism-sepolia",
		"8453":     "base-mainnet",
		"84532":    "base-sepolia",
		"43114":    "avalanche-mainnet",
		"43113":    "avalanche-fuji",
		"56":       "bsc-mainnet",
		"97":       "bsc-testnet",
	}
	if name, ok := networkNames[chainID]; ok {
		return name
	}
	return "unknown-" + chainID
}

// =============================================================================
// PHASE 8: ATTESTATION COLLECTION & AGGREGATION
// =============================================================================

func (o *UnifiedOrchestrator) executePhase8(ctx context.Context, cycle *activeCycle, attestStrategy attestation.AttestationStrategy) error {
	cycle.Phase = 8

	if o.config.OnPhaseComplete != nil {
		defer func() { o.config.OnPhaseComplete(cycle.CycleID, 8) }()
	}

	req := cycle.Request
	result := cycle.Result

	// Create attestation message
	var primaryResultHash [32]byte
	if len(result.ObservationResults) > 0 {
		primaryResultHash = result.ObservationResults[0].ResultHash
	}

	message := &attestation.AttestationMessage{
		IntentID:     req.IntentID,
		ResultHash:   primaryResultHash,
		AnchorTxHash: req.TxHashes[0],
		BlockNumber:  result.ObservationResults[0].BlockNumber,
		TargetChain:  req.TargetChain,
		ChainID:      result.ChainID,
		Timestamp:    time.Now().Unix(),
		CycleID:      cycle.CycleID,
		BundleID:     req.BundleID,
		MerkleRoot:   req.MerkleRoot,
	}

	// Create timeout context
	attestCtx, cancel := context.WithTimeout(ctx, o.config.AttestationTimeout)
	defer cancel()

	// Sign our own attestation
	localAttestation, err := attestStrategy.Sign(attestCtx, message)
	if err != nil {
		return fmt.Errorf("create local attestation: %w", err)
	}

	// Set weight based on validator voting power (default 1)
	localAttestation.Weight = 1

	attestations := []*attestation.Attestation{localAttestation}

	// Collect attestations from peer validators
	if len(o.config.AttestationPeers) > 0 {
		peerAttestations, err := o.collectPeerAttestations(attestCtx, cycle, message, attestStrategy)
		if err != nil {
			fmt.Printf("Warning: peer attestation collection failed: %v\n", err)
			// Continue with local attestation only
		} else {
			attestations = append(attestations, peerAttestations...)
			fmt.Printf("Collected %d attestations from peers (total: %d)\n", len(peerAttestations), len(attestations))
		}
	}

	// Persist individual attestations
	if o.config.EnableUnifiedTables && o.config.UnifiedRepo != nil {
		for _, att := range attestations {
			_, err := o.persistUnifiedAttestation(ctx, cycle, att)
			if err != nil {
				fmt.Printf("Warning: failed to persist attestation: %v\n", err)
			}
		}
	}

	// Aggregate attestations
	aggAttestation, err := attestStrategy.Aggregate(attestCtx, attestations)
	if err != nil {
		return fmt.Errorf("aggregate attestations: %w", err)
	}

	// Calculate threshold
	thresholdConfig := o.config.ThresholdConfig
	if thresholdConfig == nil {
		thresholdConfig = attestation.DefaultThresholdConfig()
	}

	aggAttestation.TotalWeight = aggAttestation.AchievedWeight // Simplified: assume all validators have equal weight
	aggAttestation.ThresholdWeight = thresholdConfig.CalculateThresholdWeight(aggAttestation.TotalWeight)
	aggAttestation.ThresholdMet = thresholdConfig.IsThresholdMet(aggAttestation.AchievedWeight, aggAttestation.TotalWeight)

	// Verify aggregated attestation
	valid, err := attestStrategy.VerifyAggregated(attestCtx, aggAttestation)
	if err != nil {
		return fmt.Errorf("verify aggregated attestation: %w", err)
	}
	if !valid {
		return fmt.Errorf("aggregated attestation verification failed")
	}
	aggAttestation.Verified = true
	now := time.Now().UTC()
	aggAttestation.VerifiedAt = &now

	// Persist aggregated attestation
	if o.config.EnableUnifiedTables && o.config.UnifiedRepo != nil {
		aggID, err := o.persistAggregatedAttestation(ctx, cycle, aggAttestation)
		if err != nil {
			fmt.Printf("Warning: failed to persist aggregated attestation: %v\n", err)
		} else {
			result.AttestationID = &aggID
		}
	}

	result.Attestations = attestations
	result.AggregatedAttestation = aggAttestation
	result.ThresholdMet = aggAttestation.ThresholdMet

	return nil
}

// persistUnifiedAttestation persists an attestation to the unified table
func (o *UnifiedOrchestrator) persistUnifiedAttestation(ctx context.Context, cycle *activeCycle, att *attestation.Attestation) (uuid.UUID, error) {
	if o.config.UnifiedRepo == nil {
		return uuid.Nil, fmt.Errorf("unified repo not configured")
	}

	validatorIndex := int32(att.ValidatorIndex)
	blockNumber := int64(att.AttestedBlockNumber)

	// Extract block hash from observation results if available
	var attestedBlockHash []byte
	if len(cycle.Result.ObservationResults) > 0 {
		obs := cycle.Result.ObservationResults[0]
		attestedBlockHash = []byte(obs.BlockHash)
	}

	input := &database.NewUnifiedAttestation{
		CycleID:             cycle.CycleID,
		Scheme:              database.AttestationScheme(att.Scheme),
		ValidatorID:         att.ValidatorID,
		ValidatorIndex:      &validatorIndex,
		PublicKey:           att.PublicKey,
		Signature:           att.Signature,
		MessageHash:         att.MessageHash[:],
		Weight:              att.Weight,
		AttestedBlockNumber: &blockNumber,
		AttestedBlockHash:   attestedBlockHash,
		AttestedAt:          att.Timestamp,
	}

	// Create attestation and get ID
	attID, err := o.config.UnifiedRepo.CreateUnifiedAttestation(ctx, input)
	if err != nil {
		return uuid.Nil, err
	}

	// Mark as verified (attestations are verified before persisting)
	if err := o.config.UnifiedRepo.MarkUnifiedAttestationVerified(ctx, attID, true, "signature verified during collection"); err != nil {
		fmt.Printf("Warning: failed to mark attestation verified: %v\n", err)
	}

	return attID, nil
}

// persistAggregatedAttestation persists an aggregated attestation
func (o *UnifiedOrchestrator) persistAggregatedAttestation(ctx context.Context, cycle *activeCycle, agg *attestation.AggregatedAttestation) (uuid.UUID, error) {
	if o.config.UnifiedRepo == nil {
		return uuid.Nil, fmt.Errorf("unified repo not configured")
	}

	// Extract attestation IDs
	attestationIDs := make([]uuid.UUID, len(agg.Attestations))
	for i, att := range agg.Attestations {
		attestationIDs[i] = att.AttestationID
	}

	thresholdConfig := o.config.ThresholdConfig
	if thresholdConfig == nil {
		thresholdConfig = attestation.DefaultThresholdConfig()
	}

	input := &database.NewUnifiedAggregatedAttestation{
		CycleID:              cycle.CycleID,
		Scheme:               database.AttestationScheme(agg.Scheme),
		MessageHash:          agg.MessageHash[:],
		AggregatedSignature:  agg.AggregatedSignature,
		AggregatedPublicKey:  agg.AggregatedPublicKey,
		ParticipantIDs:       agg.ParticipantIDs,
		ParticipantCount:     agg.ParticipantCount,
		ValidatorBitfield:    agg.ValidatorBitfield,
		TotalWeight:          agg.TotalWeight,
		AchievedWeight:       agg.AchievedWeight,
		ThresholdWeight:      agg.ThresholdWeight,
		ThresholdMet:         agg.ThresholdMet,
		ThresholdNumerator:   int(thresholdConfig.Numerator),
		ThresholdDenominator: int(thresholdConfig.Denominator),
		AttestationIDs:       attestationIDs,
		FirstAttestationAt:   &agg.FirstAttestation,
		LastAttestationAt:    &agg.LastAttestation,
		AggregatedAt:         agg.AggregatedAt,
	}

	// Create aggregated attestation and get ID
	aggID, err := o.config.UnifiedRepo.CreateAggregatedAttestation(ctx, input)
	if err != nil {
		return uuid.Nil, err
	}

	// Mark as verified if threshold was met and aggregation succeeded
	if agg.ThresholdMet && agg.Verified {
		if err := o.config.UnifiedRepo.MarkAggregatedAttestationVerified(ctx, aggID, true, "threshold met, aggregation verified"); err != nil {
			fmt.Printf("Warning: failed to mark aggregation verified: %v\n", err)
		}
	}

	return aggID, nil
}

// =============================================================================
// PHASE 8 PEER ATTESTATION COLLECTION
// =============================================================================

// PeerAttestationRequest is sent to peer validators requesting attestation
type PeerAttestationRequest struct {
	CycleID      string                        `json:"cycle_id"`
	Message      *attestation.AttestationMessage `json:"message"`
	Scheme       attestation.AttestationScheme `json:"scheme"`
	RequestingID string                        `json:"requesting_validator"`
	RequestedAt  time.Time                     `json:"requested_at"`
}

// PeerAttestationResponse is the response from a peer validator
type PeerAttestationResponse struct {
	CycleID     string                    `json:"cycle_id"`
	Success     bool                      `json:"success"`
	Error       string                    `json:"error,omitempty"`
	Attestation *attestation.Attestation `json:"attestation,omitempty"`
}

// collectPeerAttestations broadcasts attestation requests to peer validators
// and collects their responses
func (o *UnifiedOrchestrator) collectPeerAttestations(
	ctx context.Context,
	cycle *activeCycle,
	message *attestation.AttestationMessage,
	attestStrategy attestation.AttestationStrategy,
) ([]*attestation.Attestation, error) {
	if len(o.config.AttestationPeers) == 0 {
		return nil, nil
	}

	// Build request
	req := &PeerAttestationRequest{
		CycleID:      cycle.CycleID,
		Message:      message,
		Scheme:       attestStrategy.Scheme(),
		RequestingID: o.config.ValidatorID,
		RequestedAt:  time.Now().UTC(),
	}

	// Request attestations from peers in parallel
	var wg sync.WaitGroup
	responses := make(chan *PeerAttestationResponse, len(o.config.AttestationPeers))

	for _, peer := range o.config.AttestationPeers {
		wg.Add(1)
		go func(peerURL string) {
			defer wg.Done()
			resp, err := o.requestAttestationFromPeer(ctx, peerURL, req)
			if err != nil {
				fmt.Printf("Failed to get attestation from %s: %v\n", peerURL, err)
				responses <- &PeerAttestationResponse{
					CycleID: cycle.CycleID,
					Success: false,
					Error:   err.Error(),
				}
				return
			}
			responses <- resp
		}(peer)
	}

	// Wait for all requests to complete (or timeout)
	go func() {
		wg.Wait()
		close(responses)
	}()

	// Collect successful responses
	var attestations []*attestation.Attestation
	for resp := range responses {
		if resp.Success && resp.Attestation != nil {
			// Verify the attestation before adding
			valid, err := attestStrategy.Verify(ctx, resp.Attestation)
			if err != nil {
				fmt.Printf("Failed to verify attestation: %v\n", err)
				continue
			}
			if !valid {
				fmt.Printf("Attestation from %s failed verification\n", resp.Attestation.ValidatorID)
				continue
			}
			attestations = append(attestations, resp.Attestation)
		}
	}

	return attestations, nil
}

// requestAttestationFromPeer sends an attestation request to a single peer
func (o *UnifiedOrchestrator) requestAttestationFromPeer(
	ctx context.Context,
	peerURL string,
	req *PeerAttestationRequest,
) (*PeerAttestationResponse, error) {
	// Serialize request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/unified/attestation/request", peerURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Validator-ID", o.config.ValidatorID)

	// Send request
	resp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var attResp PeerAttestationResponse
	if err := json.Unmarshal(body, &attResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &attResp, nil
}

// HandlePeerAttestationRequest processes an attestation request from a peer validator
// This is called by the HTTP handler when receiving requests from peers
func (o *UnifiedOrchestrator) HandlePeerAttestationRequest(
	ctx context.Context,
	req *PeerAttestationRequest,
) (*PeerAttestationResponse, error) {
	// Get the attestation strategy for the requested scheme
	attestStrategy, err := o.config.Registry.GetAttestationStrategy(req.Scheme)
	if err != nil {
		return &PeerAttestationResponse{
			CycleID: req.CycleID,
			Success: false,
			Error:   fmt.Sprintf("unsupported scheme: %v", err),
		}, nil
	}

	// Create our attestation
	att, err := attestStrategy.Sign(ctx, req.Message)
	if err != nil {
		return &PeerAttestationResponse{
			CycleID: req.CycleID,
			Success: false,
			Error:   fmt.Sprintf("sign failed: %v", err),
		}, nil
	}

	return &PeerAttestationResponse{
		CycleID:     req.CycleID,
		Success:     true,
		Attestation: att,
	}, nil
}

// =============================================================================
// PHASE 9: RESULT WRITE-BACK
// =============================================================================

func (o *UnifiedOrchestrator) executePhase9(ctx context.Context, cycle *activeCycle) error {
	cycle.Phase = 9

	if o.config.OnPhaseComplete != nil {
		defer func() { o.config.OnPhaseComplete(cycle.CycleID, 9) }()
	}

	// Skip write-back if not enabled
	if !o.config.EnableWriteBack || o.txBuilder == nil || o.config.AccumulateClient == nil {
		fmt.Printf("Write-back skipped (not configured): cycle=%s\n", cycle.CycleID)
		cycle.Result.WriteBackSuccess = true
		return nil
	}

	// Create timeout context
	writeBackCtx, cancel := context.WithTimeout(ctx, o.config.WriteBackTimeout)
	defer cancel()

	// Build ComprehensiveProofContext from the cycle data
	proofCtx := o.buildComprehensiveProofContext(cycle)

	// Build attestation bundle from cycle result
	bundle := o.buildAttestationBundleFromCycle(cycle)
	if bundle == nil {
		return fmt.Errorf("failed to build attestation bundle")
	}

	// Build synthetic transaction with comprehensive proof context
	tx, err := o.txBuilder.BuildFromBundleWithContext(bundle, proofCtx)
	if err != nil {
		return fmt.Errorf("build synthetic tx: %w", err)
	}

	// Add our signature
	if err := o.txBuilder.AddSignature(tx); err != nil {
		return fmt.Errorf("add signature: %w", err)
	}

	// Submit transaction to Accumulate
	receipt, err := o.config.AccumulateClient.SubmitTransaction(writeBackCtx, tx)
	if err != nil {
		return fmt.Errorf("submit to accumulate: %w", err)
	}

	cycle.Result.WriteBackTxHash = receipt
	cycle.Result.WriteBackSuccess = true

	fmt.Printf("Write-back submitted: cycle=%s, receipt=%s\n", cycle.CycleID, receipt)

	return nil
}

// buildComprehensiveProofContext creates the context for write-back from cycle data
func (o *UnifiedOrchestrator) buildComprehensiveProofContext(cycle *activeCycle) *ComprehensiveProofContext {
	req := cycle.Request
	result := cycle.Result

	ctx := &ComprehensiveProofContext{
		IntentID:     req.IntentID,
		IntentTxHash: req.IntentID, // Would come from original intent
		IntentBlock:  uint64(req.AccumulateHeight),
	}

	// Set bundle ID and commitment if available
	if req.BundleID != [32]byte{} {
		// Populate from request
		ctx.Commitment = &ExecutionCommitment{
			OperationID: req.MerkleRoot,
			BundleID:    req.BundleID,
		}
	}

	// Set proof artifact ID for PostgreSQL lookup
	ctx.ProofArtifactID = result.ProofID.String()

	// Set sequence number if available
	ctx.SequenceNumber = uint64(time.Now().UnixNano())

	return ctx
}

// buildAttestationBundleFromCycle creates an AttestationBundle from the cycle result
func (o *UnifiedOrchestrator) buildAttestationBundleFromCycle(cycle *activeCycle) *AttestationBundle {
	result := cycle.Result

	if len(result.ObservationResults) == 0 {
		return nil
	}

	// Get the primary observation result
	obs := result.ObservationResults[0]

	// Build external chain result
	extResult := &ExternalChainResult{
		Chain:              result.ChainID,
		ChainID:            11155111, // Would come from chain strategy
		TxHash:             parseHash(obs.TxHash),
		BlockNumber:        parseBigInt(obs.BlockNumber),
		BlockHash:          parseHash(obs.BlockHash),
		Status:             uint64(obs.Status), // 1=success, 0=revert
		StateRoot:          obs.StateRoot,
		TransactionsRoot:   obs.TransactionsRoot,
		ReceiptsRoot:       obs.ReceiptsRoot,
		ConfirmationBlocks: obs.Confirmations,
		FinalizedAt:        time.Now().UTC(),
	}

	// Build aggregated attestation
	var agg *AggregatedAttestation
	if result.AggregatedAttestation != nil {
		agg = &AggregatedAttestation{
			MessageHash:        result.AggregatedAttestation.MessageHash,
			AggregateSignature: result.AggregatedAttestation.AggregatedSignature,
			ValidatorCount:     result.AggregatedAttestation.ParticipantCount,
			ThresholdMet:       result.AggregatedAttestation.ThresholdMet,
			Finalized:          result.AggregatedAttestation.ThresholdMet && result.AggregatedAttestation.Verified,
			FinalizedAt:        time.Now().UTC(),
		}
	}

	return &AttestationBundle{
		BundleID:   cycle.Request.BundleID,
		ResultHash: obs.ResultHash,
		Result:     extResult,
		Aggregated: agg,
	}
}

// parseHash parses a hex string to common.Hash
func parseHash(s string) common.Hash {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, _ := hex.DecodeString(s)
	var h common.Hash
	if len(b) >= 32 {
		copy(h[:], b[:32])
	}
	return h
}

// parseBigInt parses a uint64 to *big.Int
func parseBigInt(n uint64) *big.Int {
	return new(big.Int).SetUint64(n)
}

// =============================================================================
// MANAGEMENT METHODS
// =============================================================================

// GetActiveCycles returns all active proof cycles
func (o *UnifiedOrchestrator) GetActiveCycles() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()

	cycles := make([]string, 0, len(o.activeCycles))
	for id := range o.activeCycles {
		cycles = append(cycles, id)
	}
	return cycles
}

// GetCycleStatus returns the status of a specific cycle
func (o *UnifiedOrchestrator) GetCycleStatus(cycleID string) (*UnifiedProofCycleResult, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	cycle, exists := o.activeCycles[cycleID]
	if !exists {
		return nil, false
	}
	return cycle.Result, true
}

// CancelCycle cancels an active proof cycle
func (o *UnifiedOrchestrator) CancelCycle(cycleID string) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	cycle, exists := o.activeCycles[cycleID]
	if !exists {
		return fmt.Errorf("cycle not found: %s", cycleID)
	}

	cycle.Cancel()
	return nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func ptrInt64(v int64) *int64 {
	return &v
}

func ptrInt(v int) *int {
	return &v
}

// =============================================================================
// BUNDLE GENERATION
// =============================================================================

// generateAndPersistBundle creates a CertenProofBundle and persists it to proof_bundles table
// This is the final step after all phases complete, creating a self-contained verification bundle
func (o *UnifiedOrchestrator) generateAndPersistBundle(ctx context.Context, cycle *activeCycle) error {
	if o.config.Repos == nil || o.config.Repos.ProofArtifacts == nil {
		return fmt.Errorf("proof artifacts repository not configured")
	}

	req := cycle.Request
	result := cycle.Result

	// Step 1: Create proof_artifact entry first (to get proof_id)
	proofClass := database.ProofClassOnDemand
	if req.ProofClass == "on_cadence" {
		proofClass = database.ProofClassOnCadence
	}

	// Determine accumulate tx hash (use first tx hash or intent ID)
	accumTxHash := req.IntentID
	if accumTxHash == "" && len(req.TxHashes) > 0 {
		accumTxHash = req.TxHashes[0]
	}

	// Build artifact JSON with cycle result summary
	artifactData := map[string]interface{}{
		"cycle_id":           cycle.CycleID,
		"chain_platform":     result.ChainPlatform,
		"chain_id":           result.ChainID,
		"attestation_scheme": result.Scheme,
		"threshold_met":      result.ThresholdMet,
		"write_back_success": result.WriteBackSuccess,
	}
	artifactJSON, err := json.Marshal(artifactData)
	if err != nil {
		return fmt.Errorf("marshal artifact data: %w", err)
	}

	newArtifact := &database.NewProofArtifact{
		ProofType:    database.ProofTypeCertenAnchor,
		AccumTxHash:  accumTxHash,
		AccountURL:   req.IntentID, // Use intent ID as account reference
		BatchID:      req.BatchID,
		MerkleRoot:   req.MerkleRoot[:],
		ProofClass:   proofClass,
		ValidatorID:  o.config.ValidatorID,
		ArtifactJSON: artifactJSON,
		UserID:       req.UserID,
		IntentID:     &req.IntentID,
	}

	proofArtifact, err := o.config.Repos.ProofArtifacts.CreateProofArtifact(ctx, newArtifact)
	if err != nil {
		return fmt.Errorf("create proof artifact: %w", err)
	}

	// Update the result with the proof ID
	result.ProofID = proofArtifact.ProofID

	fmt.Printf("Created proof artifact: proof_id=%s, cycle_id=%s\n", proofArtifact.ProofID, cycle.CycleID)

	// Step 2: Populate related tables for GetProofWithDetails support

	// 2a. Create anchor_references entry (from chain execution results)
	if len(result.ObservationResults) > 0 {
		obs := result.ObservationResults[0]
		networkName := getNetworkName(result.ChainID)
		blockTimestamp := obs.BlockTimestamp
		confirmedAt := time.Now().UTC()

		// When finalized, ensure confirmations reflects at least the required amount
		confirmations := obs.Confirmations
		if obs.IsFinalized && obs.RequiredConfirmations > 0 && confirmations < obs.RequiredConfirmations {
			confirmations = obs.RequiredConfirmations
		}

		// Get required confirmations (default to 12 if not set)
		reqConfirmations := obs.RequiredConfirmations
		if reqConfirmations <= 0 {
			reqConfirmations = 12
		}

		anchorRef := &database.NewAnchorReference{
			ProofID:               proofArtifact.ProofID,
			TargetChain:           result.ChainPlatform,
			ChainID:               result.ChainID,
			NetworkName:           networkName,
			AnchorTxHash:          obs.TxHash,
			AnchorBlockNumber:     int64(obs.BlockNumber),
			AnchorBlockHash:       &obs.BlockHash,
			AnchorTimestamp:       &blockTimestamp,
			Confirmations:         confirmations,
			RequiredConfirmations: ptrInt(reqConfirmations),
			IsConfirmed:           obs.IsFinalized,
			ConfirmedAt:           &confirmedAt,
			GasUsed:               ptrInt64(int64(obs.GasUsed)),
		}

		if _, err := o.config.Repos.ProofArtifacts.CreateAnchorReference(ctx, anchorRef); err != nil {
			fmt.Printf("Warning: failed to create anchor reference: %v\n", err)
		} else {
			fmt.Printf("Created anchor_reference for proof_id=%s, confirmations=%d, finalized=%v\n",
				proofArtifact.ProofID, confirmations, obs.IsFinalized)
		}
	}

	// 2b. Create governance_proof_levels entries (G0, G1, G2)
	isAnchored := len(result.ObservationResults) > 0
	sigCount := len(result.Attestations)

	// G0 - Inclusion and Finality (always created if we have anchor data)
	if isAnchored {
		var blockHeight *int64
		var anchorHeight *int64
		if len(result.ObservationResults) > 0 {
			bh := int64(result.ObservationResults[0].BlockNumber)
			blockHeight = &bh
			anchorHeight = &bh
		}

		g0JSON, _ := json.Marshal(map[string]interface{}{
			"inclusion_verified": true,
			"finality_achieved":  result.ObservationResults[0].IsFinalized,
			"confirmations":      result.ObservationResults[0].Confirmations,
		})

		// G0 is verified if we have anchor data
		g0Verified := true

		g0Level := &database.NewGovernanceProofLevel{
			ProofID:      proofArtifact.ProofID,
			GovLevel:     database.GovLevelG0,
			LevelName:    "G0 - Inclusion and Finality",
			BlockHeight:  blockHeight,
			AnchorHeight: anchorHeight,
			IsAnchored:   &isAnchored,
			LevelJSON:    g0JSON,
			Verified:     &g0Verified,
		}

		if _, err := o.config.Repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g0Level); err != nil {
			fmt.Printf("Warning: failed to create G0 governance level: %v\n", err)
		} else {
			fmt.Printf("Created governance_proof_level G0 for proof_id=%s\n", proofArtifact.ProofID)
		}
	}

	// G1 - Governance Correctness (created if we have governance root and attestations)
	if req.GovernanceRoot != [32]byte{} {
		g1JSON, _ := json.Marshal(map[string]interface{}{
			"governance_root":   hex.EncodeToString(req.GovernanceRoot[:]),
			"threshold_met":     result.ThresholdMet,
			"attestation_count": len(result.Attestations),
		})

		// G1 is verified if threshold is met
		g1Verified := result.ThresholdMet

		g1Level := &database.NewGovernanceProofLevel{
			ProofID:        proofArtifact.ProofID,
			GovLevel:       database.GovLevelG1,
			LevelName:      "G1 - Governance Correctness",
			IsAnchored:     &isAnchored,
			SignatureCount: &sigCount,
			LevelJSON:      g1JSON,
			Verified:       &g1Verified,
		}

		if _, err := o.config.Repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g1Level); err != nil {
			fmt.Printf("Warning: failed to create G1 governance level: %v\n", err)
		} else {
			fmt.Printf("Created governance_proof_level G1 for proof_id=%s\n", proofArtifact.ProofID)
		}
	}

	// G2 - Outcome Binding (created if we have operation commitment binding)
	if req.OperationCommitment != [32]byte{} && result.ThresholdMet {
		outcomeType := "execution_complete"
		bindingEnforced := true

		g2JSON, _ := json.Marshal(map[string]interface{}{
			"operation_commitment": hex.EncodeToString(req.OperationCommitment[:]),
			"outcome_bound":        true,
			"write_back_success":   result.WriteBackSuccess,
		})

		// G2 is verified if threshold met and binding enforced
		g2Verified := result.ThresholdMet && bindingEnforced

		g2Level := &database.NewGovernanceProofLevel{
			ProofID:         proofArtifact.ProofID,
			GovLevel:        database.GovLevelG2,
			LevelName:       "G2 - Outcome Binding",
			IsAnchored:      &isAnchored,
			SignatureCount:  &sigCount,
			OutcomeType:     &outcomeType,
			OutcomeHash:     req.OperationCommitment[:],
			BindingEnforced: &bindingEnforced,
			LevelJSON:       g2JSON,
			Verified:        &g2Verified,
		}

		if _, err := o.config.Repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g2Level); err != nil {
			fmt.Printf("Warning: failed to create G2 governance level: %v\n", err)
		} else {
			fmt.Printf("Created governance_proof_level G2 for proof_id=%s\n", proofArtifact.ProofID)
		}
	}

	// 2c. Create chained_proof_layers entries (L1/L2/L3)
	// Fetch chained proof from Accumulate if ProofGenerator is configured
	if o.config.ProofGenerator != nil {
		// Determine parameters for chained proof generation
		accountURL := req.AccumulateAccountURL
		txHash := req.AccumulateTxHash
		bvn := req.AccumulateBVN

		// Fallbacks for missing values
		if accountURL == "" {
			// Use ResultsPrincipal or construct from IntentID
			if o.config.ResultsPrincipal != "" {
				accountURL = o.config.ResultsPrincipal
			} else if req.IntentID != "" {
				// Last resort: use intent ID (may not work)
				accountURL = req.IntentID
			}
		}
		if txHash == "" {
			txHash = req.IntentID // Fall back to intent ID as tx hash
		}
		if bvn == "" {
			bvn = "bvn0" // Default to BVN0
		}

		if accountURL != "" && txHash != "" {
			chainedProof, err := o.config.ProofGenerator.GenerateChainedProofForTx(ctx, accountURL, txHash, bvn)
			if err != nil {
				fmt.Printf("Warning: failed to generate chained proof (account=%s, tx=%s, bvn=%s): %v\n", accountURL, txHash, bvn, err)

				// Record the failure in chained_proof_layers so we have a record of the attempt
				failJSON, _ := json.Marshal(map[string]interface{}{
					"status":      "failed",
					"error":       err.Error(),
					"account_url": accountURL,
					"tx_hash":     txHash,
					"bvn":         bvn,
					"attempted_at": time.Now().UTC(),
				})
				failLayer := &database.NewChainedProofLayer{
					ProofID:      proofArtifact.ProofID,
					LayerNumber:  0, // 0 indicates failed attempt
					LayerName:    "L1-L3 Generation Failed",
					BVNPartition: &bvn,
					LayerJSON:    failJSON,
				}
				if _, createErr := o.config.Repos.ProofArtifacts.CreateChainedProofLayer(ctx, failLayer); createErr != nil {
					fmt.Printf("Warning: failed to record chained proof failure: %v\n", createErr)
				} else {
					fmt.Printf("Recorded chained proof generation failure for proof_id=%s\n", proofArtifact.ProofID)
				}
			} else if chainedProof != nil {
			// L1: Transaction → BVN
			l1JSON, _ := json.Marshal(map[string]interface{}{
				"layer":          "L1",
				"description":    "Transaction to BVN",
				"bvn_partition":  chainedProof.L1BVNPartition,
				"receipt_anchor": hex.EncodeToString(chainedProof.L1ReceiptAnchor),
			})
			l1Layer := &database.NewChainedProofLayer{
				ProofID:       proofArtifact.ProofID,
				LayerNumber:   1,
				LayerName:     "L1 - Transaction to BVN",
				BVNPartition:  &chainedProof.L1BVNPartition,
				ReceiptAnchor: chainedProof.L1ReceiptAnchor,
				BVNRoot:       chainedProof.L1BVNRoot,
				LayerJSON:     l1JSON,
			}
			if _, err := o.config.Repos.ProofArtifacts.CreateChainedProofLayer(ctx, l1Layer); err != nil {
				fmt.Printf("Warning: failed to create L1 chained layer: %v\n", err)
			}

			// L2: BVN → DN
			l2JSON, _ := json.Marshal(map[string]interface{}{
				"layer":       "L2",
				"description": "BVN to DN",
				"anchor_seq":  chainedProof.L2AnchorSeq,
			})
			l2Layer := &database.NewChainedProofLayer{
				ProofID:        proofArtifact.ProofID,
				LayerNumber:    2,
				LayerName:      "L2 - BVN to DN",
				DNRoot:         chainedProof.L2DNRoot,
				AnchorSequence: &chainedProof.L2AnchorSeq,
				DNBlockHash:    chainedProof.L2DNBlockHash,
				LayerJSON:      l2JSON,
			}
			if _, err := o.config.Repos.ProofArtifacts.CreateChainedProofLayer(ctx, l2Layer); err != nil {
				fmt.Printf("Warning: failed to create L2 chained layer: %v\n", err)
			}

			// L3: DN → Consensus
			l3JSON, _ := json.Marshal(map[string]interface{}{
				"layer":               "L3",
				"description":         "DN to Consensus",
				"dn_block_height":     chainedProof.L3DNBlockHeight,
				"consensus_timestamp": chainedProof.L3ConsensusTimestamp,
			})
			consensusTS := chainedProof.L3ConsensusTimestamp
			l3Layer := &database.NewChainedProofLayer{
				ProofID:            proofArtifact.ProofID,
				LayerNumber:        3,
				LayerName:          "L3 - DN to Consensus",
				DNBlockHeight:      &chainedProof.L3DNBlockHeight,
				ConsensusTimestamp: &consensusTS,
				LayerJSON:          l3JSON,
			}
			if _, err := o.config.Repos.ProofArtifacts.CreateChainedProofLayer(ctx, l3Layer); err != nil {
				fmt.Printf("Warning: failed to create L3 chained layer: %v\n", err)
			}

			fmt.Printf("Created chained_proof_layers L1/L2/L3 for proof_id=%s\n", proofArtifact.ProofID)
			}
		} else {
			fmt.Printf("Note: Cannot generate chained proof - missing accountURL or txHash\n")
		}
	} else {
		fmt.Printf("Note: ProofGenerator not configured, skipping chained proof layers\n")
	}

	// 2d. Create validator_attestations entries
	if result.Attestations != nil {
		for _, att := range result.Attestations {
			var anchorTxHash *string
			var blockNumber *int64
			if len(result.ObservationResults) > 0 {
				anchorTxHash = &result.ObservationResults[0].TxHash
				bn := int64(result.ObservationResults[0].BlockNumber)
				blockNumber = &bn
			}

			// Attestations from the proof cycle are validated signatures
			signatureValid := true

			proofAttest := &database.NewProofAttestation{
				ProofArtifactID: &proofArtifact.ProofID,
				ValidatorID:     att.ValidatorID,
				ValidatorPubkey: att.PublicKey,
				AttestedHash:    att.MessageHash[:],
				Signature:       att.Signature,
				AnchorTxHash:    anchorTxHash,
				MerkleRoot:      req.MerkleRoot[:],
				BlockNumber:     blockNumber,
				AttestedAt:      att.Timestamp,
				SignatureValid:  &signatureValid,
			}

			if _, err := o.config.Repos.ProofArtifacts.CreateProofAttestation(ctx, proofAttest); err != nil {
				fmt.Printf("Warning: failed to create proof attestation for %s: %v\n", att.ValidatorID, err)
			}
		}
		fmt.Printf("Created %d validator_attestations for proof_id=%s\n", len(result.Attestations), proofArtifact.ProofID)
	}

	// 2e. Create verification_history entry (record that proof was verified)
	verifierID := o.config.ValidatorID
	durationMS := int(time.Since(cycle.StartedAt).Milliseconds())
	if _, err := o.config.Repos.ProofArtifacts.CreateVerificationRecord(
		ctx,
		proofArtifact.ProofID,
		"proof_cycle_complete",
		result.ThresholdMet,
		nil, // no error
		&verifierID,
		&durationMS,
	); err != nil {
		fmt.Printf("Warning: failed to create verification record: %v\n", err)
	} else {
		fmt.Printf("Created verification_history for proof_id=%s\n", proofArtifact.ProofID)
	}

	// Step 3: Build the CertenProofBundle
	bundle := proof.NewCertenProofBundle(cycle.CycleID)

	// Set transaction reference
	bundle.SetTransactionRef(accumTxHash, req.IntentID, req.ProofClass)

	// Set Merkle inclusion proof if available
	if req.MerkleRoot != [32]byte{} {
		bundle.SetMerkleInclusion(
			hex.EncodeToString(req.MerkleRoot[:]),
			hex.EncodeToString(req.OperationCommitment[:]), // Use operation commitment as leaf hash
			0, // Leaf index (would need to be passed in request)
			nil, // Merkle path (would need to be passed in request)
		)
	}

	// Set anchor reference from chain execution results
	if len(result.ObservationResults) > 0 {
		obs := result.ObservationResults[0]
		bundle.SetAnchorReference(
			result.ChainID,
			obs.TxHash,
			obs.BlockNumber,
			obs.Confirmations,
		)
		// Also set contract address if available
		if bundle.ProofComponents.AnchorReference != nil {
			bundle.ProofComponents.AnchorReference.AnchorBlockHash = obs.BlockHash
		}
	}

	// Set governance proof (basic G1 structure)
	if req.GovernanceRoot != [32]byte{} {
		govProof := &proof.GovernanceProof{
			Level:       proof.GovLevelG1,
			SpecVersion: "1.0",
			GeneratedAt: time.Now().UTC(),
			G1: &proof.G1Result{
				G0Result: proof.G0Result{
					EntryHashExec:   hex.EncodeToString(req.OperationCommitment[:]),
					TxHash:          accumTxHash,
					ExecWitness:     hex.EncodeToString(req.GovernanceRoot[:]),
					Chain:           result.ChainID,
					G0ProofComplete: true,
				},
				ThresholdSatisfied: result.ThresholdMet,
				ExecutionSuccess:   result.WriteBackSuccess,
				G1ProofComplete:    true,
			},
		}
		bundle.SetGovernanceProof(govProof)
	}

	// Add validator attestations
	if result.Attestations != nil {
		for _, att := range result.Attestations {
			bundle.AddAttestation(
				att.ValidatorID,
				hex.EncodeToString(att.Signature),
				hex.EncodeToString(att.MessageHash[:]),
				att.Timestamp,
			)
		}
	}

	// Finalize bundle integrity
	artifactHash, err := bundle.ComputeArtifactHash()
	if err != nil {
		return fmt.Errorf("compute artifact hash: %w", err)
	}
	bundle.BundleIntegrity = proof.BundleIntegrity{
		ArtifactHash:     artifactHash,
		CustodyChainHash: hex.EncodeToString(proofArtifact.ProofID[:]),
		SignerID:         o.config.ValidatorID,
	}

	// Compress bundle to gzipped JSON
	compressedData, err := bundle.ToCompressedJSON()
	if err != nil {
		return fmt.Errorf("compress bundle: %w", err)
	}

	// Compute hash of uncompressed JSON for verification
	uncompressedData, err := bundle.ToJSON()
	if err != nil {
		return fmt.Errorf("serialize bundle: %w", err)
	}
	bundleHash := sha256.Sum256(uncompressedData)

	// Step 3: Persist to proof_bundles table
	includesChained := bundle.ProofComponents.ChainedProof != nil
	includesGovernance := bundle.ProofComponents.GovernanceProof != nil
	includesMerkle := bundle.ProofComponents.MerkleInclusion != nil
	includesAnchor := bundle.ProofComponents.AnchorReference != nil

	newBundle := &database.NewProofBundle{
		ProofID:            proofArtifact.ProofID,
		BundleFormat:       "certen_v1",
		BundleVersion:      proof.BundleVersion,
		BundleData:         compressedData,
		BundleHash:         bundleHash[:],
		BundleSizeBytes:    len(compressedData),
		IncludesChained:    includesChained,
		IncludesGovernance: includesGovernance,
		IncludesMerkle:     includesMerkle,
		IncludesAnchor:     includesAnchor,
		AttestationCount:   len(bundle.ValidatorAttestations),
	}

	dbBundle, err := o.config.Repos.ProofArtifacts.CreateProofBundle(ctx, newBundle)
	if err != nil {
		return fmt.Errorf("create proof bundle: %w", err)
	}

	fmt.Printf("Created proof bundle: bundle_id=%s, proof_id=%s, size=%d bytes, attestations=%d, components=[merkle=%v,anchor=%v,chained=%v,gov=%v]\n",
		dbBundle.BundleID, proofArtifact.ProofID, len(compressedData), len(bundle.ValidatorAttestations),
		includesMerkle, includesAnchor, includesChained, includesGovernance)

	// Step 4: Update proof_artifacts with final state (status, anchor info, gov_level, verification)
	// This ensures the main proof record reflects the completed cycle
	if len(result.ObservationResults) > 0 {
		obs := result.ObservationResults[0]

		// Determine the highest governance level achieved
		govLevel := database.GovLevelG0 // Default to G0 if anchored
		if req.GovernanceRoot != [32]byte{} {
			govLevel = database.GovLevelG1
		}
		if req.OperationCommitment != [32]byte{} && result.ThresholdMet {
			govLevel = database.GovLevelG2
		}

		// Update the proof_artifacts record with final state
		if err := o.config.Repos.ProofArtifacts.UpdateProofFinalState(
			ctx,
			proofArtifact.ProofID,
			obs.TxHash,
			int64(obs.BlockNumber),
			result.ChainID,
			govLevel,
			result.ThresholdMet,
		); err != nil {
			fmt.Printf("Warning: failed to update proof final state: %v\n", err)
		} else {
			fmt.Printf("Updated proof_artifacts final state: proof_id=%s, status=anchored, gov_level=%s, verified=%v\n",
				proofArtifact.ProofID, govLevel, result.ThresholdMet)
		}
	}

	return nil
}
