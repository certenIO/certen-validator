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

	logsJSON, _ := json.Marshal(obs.Logs)
	workflowStep := database.WorkflowStep(step)

	input := &database.NewChainExecutionResult{
		CycleID:               cycle.CycleID,
		ChainPlatform:         database.ChainPlatform(cycle.Result.ChainPlatform),
		ChainID:               cycle.Result.ChainID,
		NetworkName:           "", // Would come from chain strategy
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
		RawReceipt:            obs.RawReceipt,
		Logs:                  logsJSON,
		ObserverValidatorID:   o.config.ValidatorID,
		WorkflowStep:          &workflowStep,
	}

	return o.config.UnifiedRepo.CreateChainExecutionResult(ctx, input)
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
		AttestedAt:          att.Timestamp,
	}

	return o.config.UnifiedRepo.CreateUnifiedAttestation(ctx, input)
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

	return o.config.UnifiedRepo.CreateAggregatedAttestation(ctx, input)
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
