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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	// One vocabulary for the settlement tri-state, not two. pkg/execution already
	// imports pkg/consensus (batch_proof_submitter.go, batch_quorum_attestor.go)
	// and consensus does not import this package, so there is no cycle — and
	// restating "confirmed | pending | failed" locally is exactly how two copies
	// of a classification drift apart.
	"github.com/certen/independant-validator/pkg/consensus"
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

	// Thresholds
	ThresholdConfig *attestation.ThresholdConfig

	// Timeouts
	ObservationTimeout time.Duration
	AttestationTimeout time.Duration
	WriteBackTimeout   time.Duration

	// Peer attestation collection
	// Per Whitepaper Section 3.4.1 Component 4: Validator attestations
	AttestationPeers         []string // URLs of peer validators (e.g., "http://validator-2:8080")
	AttestationRequiredCount int      // Required attestations for consensus (typically 2f+1)
	AttestationTimeout_      time.Duration

	// Write-back configuration
	// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 9
	AccumulateClient AccumulateSubmitter // Client for submitting to Accumulate
	ResultsPrincipal string              // Accumulate URL for results (e.g., "acc://certen.acme/results")
	Ed25519Key       []byte              // Ed25519 signing key for write-back transactions

	// Accumulate query client for fetching transaction governance data (M-of-N threshold)
	// This is used to query signatureBooks from transactions for accurate governance_proof_levels
	AccumulateQueryClient AccumulateQueryClient

	// Callbacks
	OnCycleComplete func(*UnifiedProofCycleResult)
	OnCycleFailed   func(*UnifiedProofCycleResult, error)
	OnPhaseComplete func(cycleID string, phase int)

	// Feature flags
	EnableMultiChain bool

	// Chained proof generator for L1/L2/L3 proofs
	// Used to fetch Accumulate proof chain: Transaction → BVN → DN → Consensus
	ProofGenerator ChainedProofGenerator

	// ResultQuorumRegistry is the on-chain validator registry Phase 8 counts its quorum against.
	// Required: without it there is no quorum to count.
	ResultQuorumRegistry ResultQuorumRegistryFn

	// Non-settlement (RB3-F49): a member that never settled is attested by quorum and written back.
	// MemberLookup finds this validator's own copy of a member; NonSettlementChain reads the chain
	// facts; NonSettlements holds failures until they are attestable. All required.
	MemberLookup       MemberLookupFn
	NonSettlementChain NonSettlementChain
	NonSettlements     *NonSettlementQueue
	// MemberOutcomes keeps member outcomes the lifecycle store refused until it takes them (RB3-F78).
	MemberOutcomes MemberOutcomeOutbox
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

// AccumulateQueryClient is the orchestrator's read-only access to Accumulate. Key page terms are not
// read through it: they come from the proven G1 result (keyPageTermsFromG1).
type AccumulateQueryClient interface {
	// GetIntentBlobs fetches the 4 signed intent blobs (intentData, crossChainData,
	// governanceData, replayData) so a peer can INDEPENDENTLY re-derive committed effects
	// from the user-signed intent (RB-SEC-1).
	GetIntentBlobs(ctx context.Context, txHash, accountURL string) ([][]byte, error)
}

// ChainedProofResult contains the L1/L2/L3 proof chain
type ChainedProofResult struct {
	// L1: Transaction to BVN
	L1ReceiptAnchor  []byte
	L1BVNRoot        []byte
	L1BVNPartition   string
	L1SourceHash     []byte                    // Receipt start hash
	L1TargetHash     []byte                    // Receipt anchor hash
	L1ReceiptEntries []database.MerklePathNode // Receipt path entries

	// L2: BVN to DN
	L2DNRoot         []byte
	L2AnchorSeq      int64
	L2DNBlockHash    []byte
	L2SourceHash     []byte                    // Receipt start hash
	L2TargetHash     []byte                    // Receipt anchor hash
	L2ReceiptEntries []database.MerklePathNode // Receipt path entries

	// L3: DN to Consensus
	L3ConsensusTimestamp time.Time
	L3DNBlockHeight      int64
	L3SourceHash         []byte                    // Receipt start hash
	L3TargetHash         []byte                    // Receipt anchor hash
	L3ReceiptEntries     []database.MerklePathNode // Receipt path entries

	// Complete proof data
	CompleteProof interface{} // *lcproof.CompleteProof
}

// DefaultUnifiedOrchestratorConfig returns default configuration
func DefaultUnifiedOrchestratorConfig() *UnifiedOrchestratorConfig {
	return &UnifiedOrchestratorConfig{
		ThresholdConfig:    attestation.DefaultThresholdConfig(),
		ObservationTimeout: 30 * time.Minute,
		AttestationTimeout: 5 * time.Minute,
		WriteBackTimeout:   2 * time.Minute,
		EnableMultiChain:   true,
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// convertMerklePathToBundle converts database MerklePathNode to bundle MerklePathEntry
func convertMerklePathToBundle(nodes []database.MerklePathNode) []proof.MerklePathEntry {
	if len(nodes) == 0 {
		return nil
	}
	result := make([]proof.MerklePathEntry, len(nodes))
	for i, node := range nodes {
		result[i] = proof.MerklePathEntry{
			Hash:  node.Hash,
			Right: node.Position == "right",
		}
	}
	return result
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

	// Merkle inclusion proof details (for MerkleTreeVisualization)
	LeafHash   []byte                    `json:"leaf_hash,omitempty"`   // The leaf (transaction) hash
	LeafIndex  int                       `json:"leaf_index,omitempty"`  // Position in the tree (0-indexed)
	MerklePath []database.MerklePathNode `json:"merkle_path,omitempty"` // Sibling hashes for proof

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

	// CommitmentData holds the full commitment map from BFT consensus
	// Contains step selectors, anchor contract, intent hash, chain info, expected events
	CommitmentData map[string]interface{} `json:"commitment_data,omitempty"`
}

// UnifiedProofCycleResult represents the result of a proof cycle
type UnifiedProofCycleResult struct {
	// CycleID uniquely identifies this cycle
	CycleID string `json:"cycle_id"`

	// anchorObservations caches anchor transactions read back by observeAnchor, keyed by lower-case hash;
	// a nil entry records a read that failed, so a batch does not retry it for every member.
	anchorObservations map[string]*chain.ObservationResult

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
	Attestations          []*attestation.Attestation         `json:"attestations,omitempty"`
	AggregatedAttestation *attestation.AggregatedAttestation `json:"aggregated_attestation,omitempty"`
	AttestationID         *uuid.UUID                         `json:"attestation_id,omitempty"`
	ThresholdMet          bool                               `json:"threshold_met"`

	// Phase 9 results. WriteBackSuccess is true only when a write-back transaction was actually
	// submitted; WriteBackState says what happened in every case.
	WriteBackTxHash  string `json:"write_back_tx_hash,omitempty"`
	WriteBackSuccess bool   `json:"write_back_success"`
	WriteBackState   string `json:"write_back_state,omitempty"`

	// Timing
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Chain info
	ChainPlatform string `json:"chain_platform"`
	ChainID       string `json:"chain_id"`
	Scheme        string `json:"attestation_scheme"`

	// Metadata propagated from the request (e.g., multi_leg, chain_key, leg_indices)
	Metadata map[string]string `json:"metadata,omitempty"`

	// CommitmentData from the original request, propagated for multi-leg aggregator write-back
	CommitmentData map[string]interface{} `json:"commitment_data,omitempty"`
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

	// Result hash chains per chain ID (for sequence_number, previous_result_hash, anchor_proof_hash)
	resultChains     map[string]*ResultHashChain
	resultChainsLock sync.RWMutex

	// Multi-leg aggregator for unified write-back across chain groups

	// Multi-leg chain groups whose proof levels complete when the unified write-back lands

	// State
	running bool
	stopCh  chan struct{}
}

// activeCycle tracks a running proof cycle
type activeCycle struct {
	CycleID   string
	Request   *UnifiedProofCycleRequest
	StartedAt time.Time
	Phase     int
	Result    *UnifiedProofCycleResult
	Cancel    context.CancelFunc

	// SnapshotID is the validator_set_snapshots row this cycle's attestations were counted against.
	SnapshotID *uuid.UUID
	// Completions are the proof_cycle_completions rows tracking this cycle's proofs through the four
	// levels: one for an on-demand cycle, one per transaction for a batch cycle.
	Completions []uuid.UUID
	// PrimaryResultHash is the result hash the write-back bundle committed to for this cycle.
	PrimaryResultHash [32]byte
	// NonSettlement is set for a cycle attesting that a member never settled (RB3-F49).
	NonSettlement *NonSettlementClaim
	// VerifiedCalls are the executed calls Phase 7's contract-call gate proved - committed events (and
	// state) from the inclusion-proven receipt - keyed by lowercase transaction hash without 0x.
	VerifiedCalls verifiedCallProofs
	// EffectsShortfall is set when the gate proved the settlement executed this intent's committed calls
	// under its leaf but a committed effect is absent (RB3-F67): the cycle attests and writes back that.
	EffectsShortfall *attestation.EffectsShortfallClaim
	// SettlementTx is the transaction Phase 7's gate proved is this member's settlement (RB3-F77); Phase 8
	// attests it and no other.
	SettlementTx string
	// SettlementProof is the gate's own observation of that settlement: included in its block (tx and
	// receipt proofs verified) and bound to the member, whatever its outcome.
	SettlementProof *ExternalChainResult
	// CommittedEffects is whether the member committed any effect (event or state) to prove.
	CommittedEffects bool
}

// provenSettlementObservation is the cycle's observation of its proven settlement transaction.
func provenSettlementObservation(observations []*chain.ObservationResult, tx string) *chain.ObservationResult {
	if tx == "" {
		return nil
	}
	for _, obs := range observations {
		if obs != nil && strings.EqualFold(strings.TrimPrefix(obs.TxHash, "0x"), strings.TrimPrefix(tx, "0x")) {
			return obs
		}
	}
	return nil
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

	if config.ResultQuorumRegistry == nil {
		return nil, fmt.Errorf("a validator registry source is required - Phase 8 counts its quorum against it")
	}

	// The evidence store is part of every proof cycle (RB3-F73): its rows are what the result is proven by.
	if config.Repos == nil || config.Repos.ProofArtifacts == nil || config.Repos.IntentLifecycle == nil || config.UnifiedRepo == nil {
		return nil, fmt.Errorf("the proof artifact, intent lifecycle and unified evidence repositories are required")
	}
	if config.MemberOutcomes == nil {
		return nil, fmt.Errorf("a member outcome outbox is required - an outcome the lifecycle store refuses would otherwise leave its intent short of a terminal status")
	}

	// Write-back is part of every proof cycle (RB3-F75): results that never reach Accumulate are not a
	// mode this validator runs in.
	if config.ResultsPrincipal == "" || len(config.Ed25519Key) == 0 || config.AccumulateClient == nil {
		return nil, fmt.Errorf("write-back requires a results principal, a signing key and an Accumulate client")
	}

	if config.MemberLookup == nil || config.NonSettlementChain == nil || config.NonSettlements == nil {
		return nil, fmt.Errorf("a member lookup, a non-settlement chain reader and a non-settlement queue are required - " +
			"without them a member that never settled is recorded nowhere")
	}

	orch := &UnifiedOrchestrator{
		config:       config,
		activeCycles: make(map[string]*activeCycle),
		resultChains: make(map[string]*ResultHashChain),
		stopCh:       make(chan struct{}),
		httpClient: &http.Client{
			Timeout: config.AttestationTimeout,
		},
	}

	orch.txBuilder = NewSyntheticTxBuilder(
		config.ResultsPrincipal,
		config.ValidatorID,
		config.Ed25519Key,
	)

	// Continue this validator's persisted result hash chains rather than restarting them at sequence 0.
	if config.UnifiedRepo != nil {
		seedCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		seeded, err := seedResultHashChains(seedCtx, config.UnifiedRepo, config.ValidatorID, orch.resultChains)
		cancel()
		if err != nil {
			// Starting the chains over would repeat sequence numbers already persisted (RB3-F73).
			return nil, fmt.Errorf("load persisted result hash chains: %w", err)
		} else if seeded > 0 {
			fmt.Printf("Continuing %d persisted result hash chain(s) for %s\n", seeded, config.ValidatorID)
		}
	}

	return orch, nil
}

// hashChainRepo is where result hash chain links are persisted.
func hashChainRepo(config *UnifiedOrchestratorConfig) *database.UnifiedRepository {
	return config.UnifiedRepo
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
		CycleID:        req.CycleID,
		StartedAt:      time.Now().UTC(),
		Metadata:       req.Metadata,
		CommitmentData: req.CommitmentData,
	}

	// Get strategies for target chain
	// The chain the member settled on. No default: a cycle observed on a guessed chain finds nothing,
	// or worse, finds something that is not this member's (RB3-F45).
	targetChain := req.TargetChain
	if targetChain == "" {
		err := fmt.Errorf("proof cycle %s names no target chain", req.CycleID)
		result.Error = err.Error()
		return result, err
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

	// Intent lifecycle: mark as in_process
	if err := o.updateLifecycleInProcess(ctx, req.IntentID, req.CycleID); err != nil {
		o.mu.Lock()
		delete(o.activeCycles, req.CycleID)
		o.mu.Unlock()
		return nil, err
	}

	defer func() {
		o.mu.Lock()
		delete(o.activeCycles, req.CycleID)
		o.mu.Unlock()
	}()

	// Execute phases
	if err := o.executePhase7(cycleCtx, cycle, chainStrategy); err != nil {
		o.recordPhaseFailure(ctx, cycle, 7, err)
		if o.config.OnCycleFailed != nil {
			o.config.OnCycleFailed(result, err)
		}
		return result, err
	}

	if err := o.executePhase8(cycleCtx, cycle, attestStrategy); err != nil {
		o.recordPhaseFailure(ctx, cycle, 8, err)
		if o.config.OnCycleFailed != nil {
			o.config.OnCycleFailed(result, err)
		}
		return result, err
	}

	// Generate and persist the proof bundle BEFORE Phase 9 so its ProofID is written back. The bundle is
	// the product: a cycle whose evidence was not stored does not write its result back as if it had
	// been (RB3-F73) - it fails, and says why.
	if o.config.Repos != nil {
		if err := o.generateAndPersistBundle(cycleCtx, cycle); err != nil {
			err = fmt.Errorf("proof bundle not stored: %w", err)
			o.recordPhaseFailure(ctx, cycle, 9, err)
			if o.config.OnCycleFailed != nil {
				o.config.OnCycleFailed(result, err)
			}
			return result, err
		}
	}

	if err := o.executePhase9(cycleCtx, cycle); err != nil {
		o.recordPhaseFailure(ctx, cycle, 9, err)
		if o.config.OnCycleFailed != nil {
			o.config.OnCycleFailed(result, err)
		}
		return result, err
	}

	// Success
	now := time.Now().UTC()
	result.CompletedAt = &now
	result.Success = true

	o.completeProofCycles(ctx, req.CycleID, cycle.Completions, result, req.MerkleRoot, result.WriteBackTxHash)

	// This member's outcome; the intent's status is derived from every member's (RB3-F50). A
	// settlement that reverted is a failed member even when its revert was written back, and a
	// write-back that did not happen is not recorded as written.
	proofCycle, reason := database.MemberProofCycleWritten, ""
	if result.WriteBackState != WriteBackWritten {
		proofCycle, reason = database.MemberProofCycleFailed, "write-back "+result.WriteBackState
	}
	if tx, reverted := revertedObservation(result.ObservationResults); reverted {
		reason = strings.TrimPrefix(reason+"; settlement transaction "+tx+" reverted on the target chain", "; ")
	}
	if err := o.recordMemberOutcome(ctx, cycle, observedSettlement(result.ObservationResults), proofCycle, reason); err != nil {
		if o.config.OnCycleFailed != nil {
			o.config.OnCycleFailed(result, err)
		}
		return result, err
	}

	if o.config.OnCycleComplete != nil {
		o.config.OnCycleComplete(result)
	}

	return result, nil
}

// =============================================================================
// INTENT LIFECYCLE HELPERS
// =============================================================================

// updateLifecycleInProcess marks an intent as in_process in the lifecycle table. A status the lifecycle
// could not record is an error: the gateway reads the intent's state from it (RB3-F73).
func (o *UnifiedOrchestrator) updateLifecycleInProcess(ctx context.Context, intentID, cycleID string) error {
	if o.config.Repos == nil || o.config.Repos.IntentLifecycle == nil || intentID == "" {
		return nil
	}
	if err := o.config.Repos.IntentLifecycle.UpdateStatus(ctx, intentID,
		database.IntentLifecycleInProcess,
		database.WithCycleID(cycleID),
	); err != nil {
		return fmt.Errorf("lifecycle: mark %s in_process: %w", intentID, err)
	}
	return nil
}

// updateLifecycleSettling marks an intent as waiting on its target-chain receipt. A status the
// lifecycle could not record is an error (RB3-F73).
//
// STAGE 1. Sits between in_process and the terminal states. Before it existed,
// 'complete' covered this interval and an intent was reported successful ~51s
// before its transaction confirmed (intent 1638327d…, 2026-08-25). Never terminal:
// executePhase7 resolves it from the observed receipt.
func (o *UnifiedOrchestrator) updateLifecycleSettling(ctx context.Context, intentID, cycleID string) error {
	if o.config.Repos == nil || o.config.Repos.IntentLifecycle == nil || intentID == "" {
		return nil
	}
	if err := o.config.Repos.IntentLifecycle.UpdateStatus(ctx, intentID,
		database.IntentLifecycleSettling,
		database.WithCycleID(cycleID),
	); err != nil {
		return fmt.Errorf("lifecycle: mark %s settling: %w", intentID, err)
	}
	return nil
}

// logTargetChainResolution prints the TERMINAL settlement line for one observed
// transaction, against the same intent ID the pending line named.
//
// STAGE 1. The defect this closes is not that the database ended up wrong — it
// ended up right — but that the LOG kept a warning forever with nothing beside
// it. Whoever read "gas may have been spent on a reverted transaction" at 07:33:41
// had no line to find at 07:34:32 saying the transaction confirmed.
//
// This is the first point in the pipeline entitled to say "failed": obsResult
// carries a receipt that was actually seen (Status 1 = success, 2 = failed), not
// an inference from a submit window that expired.
func (o *UnifiedOrchestrator) logTargetChainResolution(intentID, txHash string, obs *chain.ObservationResult) {
	if obs == nil {
		return
	}
	outcome := consensus.TargetChainOutcomeFromReceiptStatus(obs.Status)
	if observationReverted(obs) {
		outcome = consensus.TargetChainFailed
	}
	switch outcome {
	case consensus.TargetChainConfirmedOutcome:
		fmt.Printf("✅ [SETTLEMENT-RESOLVED] intent=%s tx=%s CONFIRMED status=1 block=%d chain=%s "+
			"— this is the terminal answer for this intent; any earlier pending line is now closed\n",
			intentID, txHash, obs.BlockNumber, obs.ChainName)
	case consensus.TargetChainFailed:
		fmt.Printf("❌ [SETTLEMENT-RESOLVED] intent=%s tx=%s REVERTED status=0 block=%d chain=%s gasUsed=%d "+
			"— gas was spent on a reverted transaction\n",
			intentID, txHash, obs.BlockNumber, obs.ChainName, obs.GasUsed)
	default:
		// Finalized but neither success nor revert. Not a failure — say so rather
		// than picking one, which is the whole point of the tri-state.
		fmt.Printf("⏳ [SETTLEMENT-RESOLVED] intent=%s tx=%s finalized with a NON-TERMINAL receipt "+
			"status=%d block=%d chain=%s — not treated as a failure\n",
			intentID, txHash, obs.Status, obs.BlockNumber, obs.ChainName)
	}
}

// executionOutcome is what the cycle's observed executions did: "succeeded" when every observed
// transaction is a finalized success, "reverted" when every one is a finalized revert, and "" when
// they are not all final or do not agree - a batch whose members ended differently has no single
// outcome, and each intent's own evidence has to decide it.
func executionOutcome(obs []*chain.ObservationResult) (string, []string) {
	outcome := ""
	txs := make([]string, 0, len(obs))
	for _, o := range obs {
		if o == nil || !o.IsFinalized {
			return "", nil
		}
		this := "succeeded"
		if observationReverted(o) {
			this = "reverted"
		}
		if outcome != "" && outcome != this {
			return "", nil
		}
		outcome = this
		txs = append(txs, o.TxHash)
	}
	return outcome, txs
}

// revertedObservation returns the first observed transaction that is a finalized revert.
func revertedObservation(obs []*chain.ObservationResult) (string, bool) {
	for _, o := range obs {
		if observationReverted(o) {
			return o.TxHash, true
		}
	}
	return "", false
}

// recordMemberOutcome records this cycle's member outcome; the intent's status is derived from all of
// its members' (IntentLifecycleRepository.RecordMemberOutcome). The member set and the member's leg
// count come from consensus through the commitment; without them the outcome cannot be placed and
// that is said, never guessed.
func (o *UnifiedOrchestrator) recordMemberOutcome(
	ctx context.Context,
	cycle *activeCycle,
	settlement database.MemberSettlement,
	proofCycle database.MemberProofCycle,
	reason string,
) error {
	if o.config.Repos == nil || o.config.Repos.IntentLifecycle == nil || cycle == nil || cycle.Request == nil {
		return nil
	}
	req, result := cycle.Request, cycle.Result
	chainID, chains, legs, err := memberSetOf(req)
	if err != nil {
		fmt.Printf("❌ [LIFECYCLE] intent %s cycle %s: %v; member outcome not recorded\n", req.IntentID, req.CycleID, err)
		return err
	}
	out := database.MemberOutcome{
		IntentID: req.IntentID, ChainID: chainID, MemberChains: chains, Legs: legs,
		Settlement: settlement, ProofCycle: proofCycle, CycleID: req.CycleID, Reason: reason,
		EffectsProven: cycleEffectsProven(cycle),
	}
	if result != nil {
		out.WriteBackTx = result.WriteBackTxHash
		if len(result.ObservationResults) > 0 && result.ObservationResults[0] != nil {
			out.SettlementTx = result.ObservationResults[0].TxHash
		}
	}
	derived, err := o.config.Repos.IntentLifecycle.RecordMemberOutcome(ctx, out)
	if err != nil {
		// The intent's status waits on this record (RB3-F78): the outbox keeps it until the store takes it.
		if o.config.MemberOutcomes == nil {
			fmt.Printf("❌ [LIFECYCLE] intent %s member %d: %v\n", req.IntentID, chainID, err)
			return fmt.Errorf("record member outcome: %w", err)
		}
		if qErr := o.config.MemberOutcomes.Put(out); qErr != nil {
			fmt.Printf("❌ [LIFECYCLE] intent %s member %d: the store refused the outcome (%v) and the outbox could not keep it: %v\n",
				req.IntentID, chainID, err, qErr)
			return fmt.Errorf("record member outcome: %v; queue it: %w", err, qErr)
		}
		fmt.Printf("⚠️ [LIFECYCLE] intent %s member %d: outcome queued for the lifecycle store (%v)\n", req.IntentID, chainID, err)
		return nil
	}
	if derived.Terminal {
		fmt.Printf("[LIFECYCLE] intent %s is %s: %s\n", req.IntentID, derived.Status, derived.Summary)
	}
	return nil
}

// memberSetOf is the member a cycle reports: its chain and the intent's member set. Every cycle must carry
// it - the intent's status is derived from every member's outcome (RB3-F50) - so a request without it is
// refused before anything is attested, rather than discovered after its write-back (RB3-F78).
func memberSetOf(req *UnifiedProofCycleRequest) (int64, []int64, int, error) {
	if strings.TrimSpace(req.TargetChain) == "" {
		return 0, nil, 0, fmt.Errorf("the proof cycle names no target chain")
	}
	chainID, err := strconv.ParseInt(req.TargetChain, 10, 64)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("target chain %q is not a chain id", req.TargetChain)
	}
	chains := commitmentInt64s(req.CommitmentData["memberChains"])
	legs := int(commitmentInt64(req.CommitmentData["memberLegs"]))
	if len(chains) == 0 || legs <= 0 {
		return 0, nil, 0, fmt.Errorf("the commitment carries no member set (chains=%v legs=%d)", chains, legs)
	}
	return chainID, chains, legs, nil
}

// observedSettlement is what the cycle's observation shows for the member.
func observedSettlement(obs []*chain.ObservationResult) database.MemberSettlement {
	if _, reverted := revertedObservation(obs); reverted {
		return database.MemberSettlementReverted
	}
	for _, o := range obs {
		if o != nil {
			return database.MemberSettlementSettled
		}
	}
	return database.MemberSettlementUnobserved
}

// recordPhaseFailure records the member's outcome when a phase of its proof cycle fails: its settlement
// as far as it was observed, and its proof cycle failed, with why. A settlement Phase 7 saw mined stays
// settled (or reverted) whatever failed after it - Phase 7's own contract-call gate included. It used to
// be recorded "unobserved" for every Phase 7 failure, contradicting a receipt Phase 7 had read (RB3-F65).
func (o *UnifiedOrchestrator) recordPhaseFailure(ctx context.Context, cycle *activeCycle, phase int, err error) {
	reason := fmt.Sprintf("phase %d failed: %v", phase, err)
	cycle.Result.Error = reason
	cycle.Result.FailPhase = phase
	if rErr := o.recordMemberOutcome(ctx, cycle, observedSettlement(cycle.Result.ObservationResults), database.MemberProofCycleFailed, reason); rErr != nil {
		fmt.Printf("❌ [LIFECYCLE] cycle %s failed in phase %d and its failure could not be recorded: %v\n", cycle.CycleID, phase, rErr)
	}
}

// commitmentInt64s reads a list of integers the commitment map carries ([]int64 in-process,
// []interface{} of float64 after a JSON round trip).
func commitmentInt64s(v interface{}) []int64 {
	switch t := v.(type) {
	case []int64:
		return append([]int64(nil), t...)
	case []interface{}:
		out := make([]int64, 0, len(t))
		for _, x := range t {
			n := commitmentInt64(x)
			if n == 0 {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	return nil
}

// validateRequest validates a proof cycle request
func (o *UnifiedOrchestrator) validateRequest(req *UnifiedProofCycleRequest) error {
	if len(req.TxHashes) == 0 {
		return fmt.Errorf("at least one transaction hash is required")
	}

	if req.ProofClass != "on_demand" && req.ProofClass != "on_cadence" {
		return fmt.Errorf("invalid proof class: %s", req.ProofClass)
	}

	if _, _, _, err := memberSetOf(req); err != nil {
		return err
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

	// STAGE 1 — this is where the settlement is genuinely unresolved, so this is
	// where the lifecycle says so. Between in_process (the proof cycle is running)
	// and the terminal states, an intent is waiting on a target-chain receipt, and
	// until now nothing recorded that. 'complete' absorbed it and reported success
	// ~51s early; see migration 014.
	if err := o.updateLifecycleSettling(ctx, req.IntentID, req.CycleID); err != nil {
		return err
	}

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

		// THE TERMINAL LINE, against the same intent ID as the pending one.
		//
		// The warning that opened Stage 1 was never retracted because the truth
		// arrived here, in the database, and never in the log. A receipt has now
		// been SEEN — obsResult.Status is 1 or 2, not a guess about a window — so
		// this is the first point in the pipeline entitled to say "failed".
		o.logTargetChainResolution(req.IntentID, txHash, obsResult)

		observationResults = append(observationResults, obsResult)

		// Persist to unified tables if enabled
		if o.config.UnifiedRepo != nil {
			execID, err := o.persistChainExecution(ctx, cycle, obsResult, i+1)
			if err != nil {
				return fmt.Errorf("persist chain execution %s: %w", txHash, err)
			}
			chainExecutionIDs = append(chainExecutionIDs, execID)
		}
	}

	result.ObservationResults = observationResults
	result.ChainExecutionIDs = chainExecutionIDs

	// RB-2/RB-4/RB-5: cryptographic attestation gate for proof-gated contract calls.
	// Refuses the cycle (⇒ no attestation / write-back) unless the executed call's
	// inclusion proof verifies AND every committed event/state is proven on-chain.
	verified, err := o.verifyContractCallGate(observeCtx, cycle, chainStrategy)
	if err != nil {
		return fmt.Errorf("RB contract-call verification gate failed: %w", err)
	}
	cycle.VerifiedCalls = verified
	// A shortfall is the result this cycle attests: the settlement observation's result hash is bound to
	// the claim, so Phase 8 signs it and the write-back carries it - never the settlement's plain hash,
	// which would read as a success.
	if c := cycle.EffectsShortfall; c != nil {
		bound := false
		for _, obs := range observationResults {
			if obs != nil && strings.EqualFold(strings.TrimPrefix(obs.TxHash, "0x"), strings.TrimPrefix(c.TxHash, "0x")) {
				obs.ResultHash = effectsShortfallResultHash(obs.ResultHash, c)
				bound = true
			}
		}
		if !bound {
			return fmt.Errorf("effects shortfall names settlement %s, which this cycle did not observe", c.TxHash)
		}
	}

	// Persist the proofs the gate verified onto the rows written above, so the database carries the
	// real trie proofs (tx and receipt, bound to the header roots) rather than what the strategy
	// observer could build — which on Ethereum is a hash list and on Base/Arbitrum is nothing.
	if err := o.persistVerifiedProofs(ctx, observationResults, chainExecutionIDs, verified); err != nil {
		return err
	}

	return nil
}

// verifiedCallProofs is what the gate hands back on success: the verified observation for each
// executed call, keyed by lowercase transaction hash without 0x.
type verifiedCallProofs map[string]*ExternalChainResult

// persistVerifiedProofs writes the gate's verified tx and receipt inclusion proofs onto the
// chain_execution_results rows persisted during observation, matched by transaction hash. A proof the
// gate verified and the store did not keep is an error: the stored settlement would be missing the
// proof it was attested on (RB3-F73).
func (o *UnifiedOrchestrator) persistVerifiedProofs(ctx context.Context, observations []*chain.ObservationResult, execIDs []uuid.UUID, verified verifiedCallProofs) error {
	if len(verified) == 0 || o.config.UnifiedRepo == nil {
		return nil
	}
	if len(execIDs) != len(observations) {
		return fmt.Errorf("persist verified proofs: %d chain-execution rows for %d observations", len(execIDs), len(observations))
	}
	for i, obs := range observations {
		key := strings.ToLower(strings.TrimPrefix(obs.TxHash, "0x"))
		res, ok := verified[key]
		if !ok || res.TxInclusionProof == nil || res.ReceiptInclusionProof == nil {
			continue
		}
		txJSON, err1 := json.Marshal(res.TxInclusionProof)
		rcJSON, err2 := json.Marshal(res.ReceiptInclusionProof)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("encode verified proofs for %s: %v %v", obs.TxHash, err1, err2)
		}
		// The observation object travels on into the artifact, so carry the real proofs there too.
		obs.MerkleProof = txJSON
		obs.ReceiptProof = rcJSON
		if err := o.config.UnifiedRepo.UpdateChainExecutionProofs(ctx, execIDs[i], txJSON, rcJSON); err != nil {
			return fmt.Errorf("persist verified proofs for %s: %w", obs.TxHash, err)
		}
		fmt.Printf("💾 [RB-GATE] Persisted verified tx+receipt inclusion proofs for %s (%d + %d bytes)\n", obs.TxHash, len(txJSON), len(rcJSON))
	}
	return nil
}

// verifyContractCallGate is Phase 7's settlement gate (RB-2/RB-4/RB-5, bound to the member - RB3-F77).
// Every member is held to the user-signed intent's member on this chain (signedMemberLegs): the
// settlement must be the member's own execution - its account, exactly its committed calls in order
// (native transfers included), its operationID, its leaf consumed - and then one of three proven
// outcomes: executed with every committed effect (VerifyExecutedCall), reverted (VerifyRevertedCall),
// or executed without a committed effect (VerifyEffectsNotProven, RB3-F67). A transaction that is not
// the member's settlement proves none of them, whatever it emitted. The gate records the settlement it
// proved; Phase 8 attests that transaction and no other.
func (o *UnifiedOrchestrator) verifyContractCallGate(ctx context.Context, cycle *activeCycle, chainStrategy chain.ChainExecutionStrategy) (verifiedCallProofs, error) {
	req := cycle.Request
	legs, account, opID, err := o.signedMemberLegs(ctx, req.IntentID, req.AccumulateTxHash, req.AccumulateAccountURL, chainStrategy)
	if err != nil {
		return nil, fmt.Errorf("settlement gate: %w", err)
	}
	observer, err := o.observerForChain(&attestation.AttestationMessage{TargetChain: req.TargetChain}, chainStrategy)
	if err != nil {
		return nil, fmt.Errorf("settlement gate: build observer: %w", err)
	}
	for _, l := range legs {
		if len(l.Events) > 0 || len(l.State) > 0 {
			cycle.CommittedEffects = true
		}
	}

	verified := make(verifiedCallProofs)
	seen := make(map[string]bool)
	var lastErr error
	for _, tx := range req.TxHashes {
		key := strings.ToLower(strings.TrimPrefix(tx, "0x"))
		if tx == "" || seen[key] {
			continue
		}
		seen[key] = true
		h := common.HexToHash(tx)
		fmt.Printf("🔒 [RB-GATE] Verifying member settlement (chain=%s account=%s legs=%d) tx=%s\n",
			chainStrategy.ChainID(), account.Hex(), len(legs), tx)

		result, verr := observer.VerifyExecutedCall(ctx, h, legs, opID, account)
		if verr == nil {
			fmt.Printf("✅ [RB-GATE] Member settlement proven (RB-2 inclusion, member binding, RB-4 events, RB-5 state): chain=%s tx=%s block=%s\n",
				chainStrategy.ChainID(), tx, result.BlockNumber.String())
			verified[key] = result
			cycle.SettlementTx, cycle.SettlementProof = tx, result
			return verified, nil
		}
		lastErr = verr
		if IsChainReadError(verr) {
			continue
		}
		// A REVERT of the committed calls is an outcome, not a failed verification: the status-0 receipt
		// is proven included and the transaction is bound to the member's calls and operationID.
		if rres, rerr := observer.VerifyRevertedCall(ctx, h, committedCalls(legs), opID, account); rerr == nil {
			fmt.Printf("❌ [RB-GATE] Member settlement REVERTED, proven: chain=%s tx=%s block=%s - attesting the failure\n",
				chainStrategy.ChainID(), tx, rres.BlockNumber.String())
			verified[key] = rres
			cycle.SettlementTx, cycle.SettlementProof = tx, rres
			return verified, nil
		} else if IsChainReadError(rerr) {
			lastErr = rerr
			continue
		}
		// Executed as the member's settlement, but a committed effect is absent (RB3-F67).
		if sres, claim, serr := observer.VerifyEffectsNotProven(ctx, h, legs, opID, account); serr == nil {
			fmt.Printf("❌ [RB-GATE] Member settlement EXECUTED WITHOUT its committed effects, proven (missing events %v, unset state %v): chain=%s tx=%s block=%s - attesting that\n",
				claim.MissingEvents, claim.UnsetState, chainStrategy.ChainID(), tx, sres.BlockNumber.String())
			cycle.EffectsShortfall = claim
			cycle.SettlementTx, cycle.SettlementProof = tx, sres
			return verified, nil
		} else if IsChainReadError(serr) {
			lastErr = serr
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("the cycle observed no transaction")
	}
	fmt.Printf("❌ [RB-GATE] No observed transaction is this member's settlement (chain=%s): %v\n", chainStrategy.ChainID(), lastErr)
	return nil, fmt.Errorf("no observed transaction is the member's settlement (chain=%s): %w", chainStrategy.ChainID(), lastErr)
}

// observationReverted reports whether an observed transaction is a finalized REVERT.
//
// Not TargetChainOutcomeFromReceiptStatus alone: the EVM strategy reports a reverted receipt as
// status 0 - its raw receipt status - which the strategy interface otherwise uses for "pending".
// Terminality comes from IsFinalized; once finalized, anything other than success is a revert.
// The same rule HandlePeerAttestationRequest applies.
func observationReverted(obs *chain.ObservationResult) bool {
	return obs != nil && obs.IsFinalized && obs.Status != 1
}

// commitmentInt64 reads an integer the commitment map carries: an int64 in-process, a float64 after
// a JSON round trip. Anything else reads as 0, which callers treat as absent.
func commitmentInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		if n == float64(int64(n)) {
			return int64(n)
		}
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
	}
	return 0
}

// peerVerifyCommittedEffect (RB-SEC-1, bound to the member - RB3-F77) is a peer's own proof, before it
// signs, that the named settlement is the member's and has the outcome its observation found: from the
// USER-SIGNED intent fetched from Accumulate (never the requester's copy), the member it contributes on
// the chain this peer observed, and the peer's own chain reads. reverted says the peer's own observation
// found the execution reverted; the transaction is then proven to be the member's reverted execution.
// Native value transfers are held to the same binding: the committed call is the transfer itself.
func (o *UnifiedOrchestrator) peerVerifyCommittedEffect(ctx context.Context, msg *attestation.AttestationMessage, chainStrategy chain.ChainExecutionStrategy, reverted bool) error {
	execTx, err := attestedSettlementTx(msg)
	if err != nil {
		return err
	}
	legs, account, opID, err := o.signedMemberLegs(ctx, msg.IntentID, msg.AccumulateTxHash, msg.AccumulateAccountURL, chainStrategy)
	if err != nil {
		return err
	}
	observer, err := o.observerForChain(msg, chainStrategy)
	if err != nil {
		return err // fail closed — cannot independently verify without an observer
	}
	if reverted {
		if _, verr := observer.VerifyRevertedCall(ctx, common.HexToHash(execTx), committedCalls(legs), opID, account); verr != nil {
			return fmt.Errorf("reverted execution not proven as the member's on %s: %w", execTx, verr)
		}
		fmt.Printf("❌ [RB-SEC-1] Peer independently verified the member's settlement REVERTED for intent %s (chain=%s tx=%s)\n",
			msg.IntentID, msg.TargetChain, execTx)
		return nil
	}
	if _, verr := observer.VerifyExecutedCall(ctx, common.HexToHash(execTx), legs, opID, account); verr != nil {
		return fmt.Errorf("member settlement not proven on %s: %w", execTx, verr)
	}
	fmt.Printf("✅ [RB-SEC-1] Peer independently verified the member's settlement for intent %s (chain=%s tx=%s)\n",
		msg.IntentID, msg.TargetChain, execTx)
	return nil
}

// attestedSettlementTx is the one transaction an attestation names as the member's settlement. The
// result hash a peer re-observes (AnchorTxHash) and the transaction it binds to the member
// (ExecutionTxHash) must be the same transaction; two could otherwise sign one transaction's result
// while proving another's binding.
func attestedSettlementTx(msg *attestation.AttestationMessage) (string, error) {
	tx := msg.AnchorTxHash
	if tx == "" {
		return "", fmt.Errorf("no settlement transaction named")
	}
	if msg.ExecutionTxHash != "" && !strings.EqualFold(strings.TrimPrefix(msg.ExecutionTxHash, "0x"), strings.TrimPrefix(tx, "0x")) {
		return "", fmt.Errorf("the attestation names settlement %s but binds %s", tx, msg.ExecutionTxHash)
	}
	return tx, nil
}

// observerForChain builds an independent observer on the chain this peer re-observed.
func (o *UnifiedOrchestrator) observerForChain(msg *attestation.AttestationMessage, chainStrategy chain.ChainExecutionStrategy) (*ExternalChainObserver, error) {
	if chainStrategy == nil {
		return nil, fmt.Errorf("no chain strategy for %s (cannot independently verify)", msg.TargetChain)
	}
	cfg := chainStrategy.Config()
	if cfg == nil || cfg.RPC == "" {
		return nil, fmt.Errorf("no RPC for chain %s", chainStrategy.ChainID())
	}
	chainID, _ := strconv.ParseInt(chainStrategy.ChainID(), 10, 64)
	return NewExternalChainObserver(&ExternalChainObserverConfig{
		EthereumRPC:           cfg.RPC,
		ChainID:               chainID,
		ValidatorID:           o.config.ValidatorID,
		RequiredConfirmations: 1,
		Timeout:               90 * time.Second,
	})
}

// peerDeriveEffectsShortfall is a peer's own derivation of a settlement's effects shortfall (RB3-F67):
// from the user-signed intent's member on the chain it observed and its own chain reads.
func (o *UnifiedOrchestrator) peerDeriveEffectsShortfall(ctx context.Context, msg *attestation.AttestationMessage, chainStrategy chain.ChainExecutionStrategy) (*attestation.EffectsShortfallClaim, error) {
	execTx, err := attestedSettlementTx(msg)
	if err != nil {
		return nil, err
	}
	legs, account, opID, err := o.signedMemberLegs(ctx, msg.IntentID, msg.AccumulateTxHash, msg.AccumulateAccountURL, chainStrategy)
	if err != nil {
		return nil, err
	}
	observer, err := o.observerForChain(msg, chainStrategy)
	if err != nil {
		return nil, err
	}
	_, claim, err := observer.VerifyEffectsNotProven(ctx, common.HexToHash(execTx), legs, opID, account)
	if err != nil {
		return nil, err
	}
	return claim, nil
}

// sameShortfall reports whether two shortfall claims state the same facts.
func sameShortfall(a, b *attestation.EffectsShortfallClaim) bool {
	if a == nil || b == nil {
		return false
	}
	eq := func(x, y []string) bool {
		if len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
		return true
	}
	return a.ChainID == b.ChainID && strings.EqualFold(a.TxHash, b.TxHash) && strings.EqualFold(a.Account, b.Account) &&
		strings.EqualFold(a.OperationID, b.OperationID) && strings.EqualFold(a.Leaf, b.Leaf) &&
		eq(a.MissingEvents, b.MissingEvents) && eq(a.UnsetState, b.UnsetState)
}

// intentIDFromBlob extracts intent_id from the signed intentData blob.
func intentIDFromBlob(b []byte) string {
	var m struct {
		IntentID string `json:"intent_id"`
	}
	_ = json.Unmarshal(b, &m)
	return m.IntentID
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
		"1":           "ethereum-mainnet",
		"11155111":    "ethereum-sepolia",
		"137":         "polygon-mainnet",
		"80001":       "polygon-mumbai",
		"80002":       "polygon-amoy",
		"42161":       "arbitrum-one",
		"421614":      "arbitrum-sepolia",
		"10":          "optimism-mainnet",
		"11155420":    "optimism-sepolia",
		"8453":        "base-mainnet",
		"84532":       "base-sepolia",
		"43114":       "avalanche-mainnet",
		"43113":       "avalanche-fuji",
		"56":          "bsc-mainnet",
		"97":          "bsc-testnet",
		"1284":        "moonbeam",
		"1287":        "moonbase-alpha",
		"2494104990":  "tron-shasta",
		"728126428":   "tron-mainnet",
		"101":         "solana-mainnet",
		"103":         "solana-devnet",
		"397":         "near-mainnet",
		"398":         "near-testnet",
		"2":           "aptos-testnet",
		"sui-testnet": "sui-testnet",
		"sui-mainnet": "sui-mainnet",
		"-3":          "ton-testnet",
		"-239":        "ton-mainnet",
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

	// A cycle is one chain member's, and a member has exactly one settlement transaction. The
	// attestation below binds that one observation's result; a second observation would reach the
	// write-back unattested, so it is refused rather than left out.
	if len(result.ObservationResults) != 1 {
		return fmt.Errorf("phase 8: a chain member's cycle attests exactly one observation, this cycle has %d",
			len(result.ObservationResults))
	}
	// The settlement Phase 7's gate proved is the one transaction attested (RB3-F77): its observation's
	// result hash, and its hash as both the re-observed and the member-bound transaction.
	// A non-settlement has no settlement transaction: its one observation is the non-settlement itself,
	// which peers verify on their own path (RB3-F49).
	settlementTx := cycle.SettlementTx
	settlementObs := provenSettlementObservation(result.ObservationResults, settlementTx)
	if cycle.NonSettlement != nil {
		settlementObs, settlementTx = result.ObservationResults[0], firstTx(req.TxHashes)
	} else if settlementObs == nil {
		return fmt.Errorf("phase 8: the gate proved no settlement among this cycle's observations")
	}
	primaryResultHash := settlementObs.ResultHash

	message := &attestation.AttestationMessage{
		IntentID:     req.IntentID,
		ResultHash:   primaryResultHash,
		AnchorTxHash: settlementTx,
		BlockNumber:  settlementObs.BlockNumber,
		TargetChain:  req.TargetChain,
		ChainID:      result.ChainID,
		Timestamp:    time.Now().Unix(),
		CycleID:      cycle.CycleID,
		BundleID:     req.BundleID,
		MerkleRoot:   req.MerkleRoot,
		// RB-SEC-1: bind the execution (governance) tx + Accumulate pointer so peers can
		// independently re-verify the committed effect against the signed intent.
		ExecutionTxHash:      settlementTx,
		AccumulateTxHash:     req.AccumulateTxHash,
		AccumulateAccountURL: req.AccumulateAccountURL,
		NonSettlement:        cycle.NonSettlement,
		EffectsShortfall:     cycle.EffectsShortfall,
	}

	// Create timeout context
	attestCtx, cancel := context.WithTimeout(ctx, o.config.AttestationTimeout)
	defer cancel()

	// The registry this quorum is counted against. Read before signing: without it there is no
	// quorum to form, and the cycle fails by name rather than counting self-declared weights.
	if o.config.ResultQuorumRegistry == nil {
		return fmt.Errorf("phase 8: no validator registry source configured - the result quorum cannot be counted")
	}
	registry, err := o.config.ResultQuorumRegistry(attestCtx, result.ChainID)
	if err != nil {
		return fmt.Errorf("phase 8: validator registry for chain %s: %w", result.ChainID, err)
	}

	// Sign our own attestation. Its weight, like every peer's, is set from the registry by the fold.
	localAttestation, err := attestStrategy.Sign(attestCtx, message)
	if err != nil {
		return fmt.Errorf("create local attestation: %w", err)
	}

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

	thresholdConfig := o.config.ThresholdConfig
	if thresholdConfig == nil {
		thresholdConfig = attestation.DefaultThresholdConfig()
	}

	// Record the validator set this quorum is counted against, so a reader can check the threshold
	// against the membership rather than trusting the stored weights.
	if o.config.Repos != nil && o.config.Repos.ProofArtifacts != nil {
		set, err := registryAttestationSet(registry, thresholdConfig.CalculateThresholdWeight, result.ObservationResults[0].BlockNumber)
		if err != nil {
			return fmt.Errorf("phase 8: validator set snapshot: %w", err)
		}
		snapshotID, err := persistValidatorSetSnapshot(ctx, o.config.Repos.ProofArtifacts, set, result.ChainID, getNetworkName(result.ChainID))
		if err != nil {
			return fmt.Errorf("phase 8: persist validator set snapshot: %w", err)
		}
		cycle.SnapshotID = snapshotID
	}

	// Count against the registry: registered keys at registered power, one per validator, over this
	// result's message. Anything else is excluded by name and neither helps nor blocks the quorum.
	aggAttestation, excluded, err := foldResultAttestations(attestCtx, attestStrategy, message, attestations, registry, thresholdConfig)
	for _, x := range excluded {
		fmt.Printf("[Phase 8] cycle %s: attestation from %q not counted: %s\n", cycle.CycleID, x.ValidatorID, x.Reason)
	}
	if err != nil {
		return fmt.Errorf("phase 8: %w", err)
	}
	fmt.Printf("[Phase 8] Attestation threshold: achieved=%d total=%d required=%d met=%v\n",
		aggAttestation.AchievedWeight, aggAttestation.TotalWeight, aggAttestation.ThresholdWeight, aggAttestation.ThresholdMet)

	// Persist the attestations that COUNTED - each is recorded as verified, which an excluded one is not.
	counted := aggAttestation.Attestations
	if o.config.UnifiedRepo != nil {
		for _, att := range counted {
			if _, err := o.persistUnifiedAttestation(ctx, cycle, att); err != nil {
				return fmt.Errorf("phase 8: persist attestation of %s: %w", att.ValidatorID, err)
			}
		}
	}

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
	if o.config.UnifiedRepo != nil {
		messageHashes := make([][]byte, len(counted))
		for i, att := range counted {
			messageHashes[i] = att.MessageHash[:]
		}
		aggID, err := o.persistAggregatedAttestation(ctx, cycle, aggAttestation, attestationMessagesAgree(messageHashes))
		if err != nil {
			return fmt.Errorf("phase 8: persist aggregated attestation: %w", err)
		}
		result.AttestationID = &aggID
	}

	result.Attestations = counted
	result.AggregatedAttestation = aggAttestation
	result.ThresholdMet = aggAttestation.ThresholdMet

	return nil
}

// firstTx is the first transaction hash, or "" when the cycle has none (a non-settlement).
func firstTx(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	return hashes[0]
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
		SnapshotID:          cycle.SnapshotID,
	}

	// Create attestation and get ID
	attID, err := o.config.UnifiedRepo.CreateUnifiedAttestation(ctx, input)
	if err != nil {
		return uuid.Nil, err
	}

	// Mark as verified (attestations are verified before persisting)
	if err := o.config.UnifiedRepo.MarkUnifiedAttestationVerified(ctx, attID, true, "signature verified during collection"); err != nil {
		return uuid.Nil, fmt.Errorf("mark attestation verified: %w", err)
	}

	return attID, nil
}

// persistAggregatedAttestation persists an aggregated attestation
func (o *UnifiedOrchestrator) persistAggregatedAttestation(ctx context.Context, cycle *activeCycle, agg *attestation.AggregatedAttestation, messagesAgree bool) (uuid.UUID, error) {
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

		SnapshotID:              cycle.SnapshotID,
		MessageConsistencyValid: messagesAgree,
	}

	// Create aggregated attestation and get ID
	aggID, err := o.config.UnifiedRepo.CreateAggregatedAttestation(ctx, input)
	if err != nil {
		return uuid.Nil, err
	}

	// Mark as verified if threshold was met and aggregation succeeded
	if agg.ThresholdMet && agg.Verified {
		if err := o.config.UnifiedRepo.MarkAggregatedAttestationVerified(ctx, aggID, true, "threshold met, aggregation verified"); err != nil {
			return uuid.Nil, fmt.Errorf("mark aggregation verified: %w", err)
		}
	}

	return aggID, nil
}

// =============================================================================
// PHASE 8 PEER ATTESTATION COLLECTION
// =============================================================================

// PeerAttestationRequest is sent to peer validators requesting attestation
type PeerAttestationRequest struct {
	CycleID      string                          `json:"cycle_id"`
	Message      *attestation.AttestationMessage `json:"message"`
	Scheme       attestation.AttestationScheme   `json:"scheme"`
	RequestingID string                          `json:"requesting_validator"`
	RequestedAt  time.Time                       `json:"requested_at"`
}

// PeerAttestationResponse is the response from a peer validator
type PeerAttestationResponse struct {
	CycleID     string                   `json:"cycle_id"`
	Success     bool                     `json:"success"`
	Error       string                   `json:"error,omitempty"`
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

// Phase 8 peer-attestation request bounds (replay / freshness protection).
const (
	peerAttestationMaxAgeSec  = 600 // reject messages older than 10 minutes
	peerAttestationMaxSkewSec = 120 // tolerate 2 minutes of clock skew (future-dated)
)

// HandlePeerAttestationRequest processes an attestation request from a peer
// validator and is invoked by the /api/unified/attestation/request HTTP handler.
//
// SECURITY: a validator must NEVER blind-sign whatever a caller posts. This
// validator only attests to a result it can INDEPENDENTLY confirm on the target
// chain — the core of a meaningful multi-validator quorum
// ("each validator independently observes and attests", result_attestation.go).
// Before signing it: (1) structurally validates the message, (2) enforces
// freshness (replay protection), and (3) re-observes the anchor transaction via
// the same chain strategy used in Phase 7 and requires it to be finalized,
// successful, AND to recompute to the exact ResultHash claimed. The result hash
// is a deterministic function of on-chain facts (e.g. Solana sha256(txHash||slot||
// "solana")), so an honest peer's recomputation matches while a fabricated or
// non-existent result is rejected.
func (o *UnifiedOrchestrator) HandlePeerAttestationRequest(
	ctx context.Context,
	req *PeerAttestationRequest,
) (*PeerAttestationResponse, error) {
	fail := func(msg string) (*PeerAttestationResponse, error) {
		cid := ""
		if req != nil {
			cid = req.CycleID
		}
		fmt.Printf("[Phase 8] Rejecting peer attestation request (cycle=%s): %s\n", cid, msg)
		return &PeerAttestationResponse{CycleID: cid, Success: false, Error: msg}, nil
	}

	// 1. Structural validation.
	if req == nil || req.Message == nil {
		return fail("missing attestation message")
	}
	if req.RequestingID == "" {
		return fail("missing requesting validator id")
	}
	msg := req.Message
	// A member that never settled has no transaction: it is verified from this validator's own copy of
	// the member and its own chain reads (RB3-F49).
	if msg.NonSettlement != nil {
		return o.handlePeerNonSettlement(ctx, req, fail)
	}
	if msg.TargetChain == "" || msg.AnchorTxHash == "" {
		return fail("attestation message missing target_chain/anchor_tx_hash")
	}
	if msg.ResultHash == ([32]byte{}) {
		return fail("attestation message has zero result_hash")
	}

	// 2. Freshness — reject stale (replay) or future-dated messages.
	if msg.Timestamp != 0 {
		age := time.Now().Unix() - msg.Timestamp
		if age > peerAttestationMaxAgeSec {
			return fail(fmt.Sprintf("attestation message too old (%ds)", age))
		}
		if age < -peerAttestationMaxSkewSec {
			return fail("attestation message timestamp is in the future")
		}
	}

	// 3. Independent re-observation on the target chain (the trust anchor).
	chainStrategy, _, err := o.config.Registry.GetStrategiesForChain(msg.TargetChain)
	if err != nil {
		return fail(fmt.Sprintf("unsupported target chain %q: %v", msg.TargetChain, err))
	}
	obsCtx, cancel := context.WithTimeout(ctx, o.config.ObservationTimeout)
	defer cancel()
	obs, err := chainStrategy.ObserveTransaction(obsCtx, msg.AnchorTxHash)
	if err != nil {
		return fail(fmt.Sprintf("independent observation of %s failed: %v", msg.AnchorTxHash, err))
	}
	if !obs.IsFinalized {
		return fail("anchor transaction not finalized on independent observation")
	}
	// A REVERT is an outcome, not a reason to refuse.
	//
	// This demanded status==1. A batch member that reverts on chain is a real, finalized,
	// independently verifiable result — the receipt proves it — but every peer refused to attest
	// it, so the failure never reached quorum and Phase 9 never wrote it back. The ADI could not
	// tell a reverted intent from one that was never processed, which is the exact silence the
	// failure policy exists to remove. Observed live 2026-08-03: achieved=1 of required=5 on the
	// reverted member while the settled member of the SAME batch reached 7 of 7.
	//
	// What must still hold is that peers agree on WHICH outcome occurred, and the ResultHash
	// comparison immediately below enforces that: it is derived from the peer's own observation,
	// so a success cannot be passed off as a revert or the reverse.
	//
	// Terminality comes from IsFinalized, checked immediately above — NOT from the status code.
	// The observer reports a reverted receipt as status 0, the same value the comment here called
	// "pending", so gating on the code alone cannot tell a revert from an unmined transaction and
	// rejected both. Once finalized, anything other than success IS a revert.
	if obs.Status != 1 {
		fmt.Printf("[Phase 8] attesting a REVERTED execution (%s) — outcome is failure, bound by result hash\n",
			msg.AnchorTxHash)
	}
	if msg.EffectsShortfall != nil {
		// RB3-F67: the requester attests that the settlement EXECUTED without a committed effect. This
		// peer derives the shortfall itself - from the user-signed intent and its own chain reads - and
		// signs only the identical claim, bound to the settlement it re-observed.
		own, serr := o.peerDeriveEffectsShortfall(ctx, msg, chainStrategy)
		if serr != nil {
			return fail(fmt.Sprintf("effects shortfall not reproduced: %v", serr))
		}
		if !sameShortfall(own, msg.EffectsShortfall) {
			return fail(fmt.Sprintf("effects shortfall differs: this validator finds missing events %v, unset state %v",
				own.MissingEvents, own.UnsetState))
		}
		if effectsShortfallResultHash(obs.ResultHash, own) != msg.ResultHash {
			return fail("result hash is not the re-observed settlement bound to the shortfall — refusing to attest")
		}
	} else {
		if obs.ResultHash != msg.ResultHash {
			return fail("independently-observed result hash does not match requested message — refusing to attest")
		}

		// 3b. RB-SEC-1: independently verify the committed CONTRACT-CALL effect from the
		//     USER-SIGNED intent (fetched from Accumulate), so the quorum — not just the
		//     executor — enforces RB-2/RB-4/RB-5. Fails closed on any doubt.
		if err := o.peerVerifyCommittedEffect(ctx, msg, chainStrategy, obs.Status != 1); err != nil {
			return fail(fmt.Sprintf("committed-effect verification failed: %v", err))
		}
	}

	// 4. Verified — sign with the requested scheme so the signature aggregates
	//    with the executor's self-attestation.
	attestStrategy, err := o.config.Registry.GetAttestationStrategy(req.Scheme)
	if err != nil {
		return fail(fmt.Sprintf("unsupported scheme: %v", err))
	}
	att, err := attestStrategy.Sign(obsCtx, msg)
	if err != nil {
		return fail(fmt.Sprintf("sign failed: %v", err))
	}

	fmt.Printf("[Phase 8] Independently verified + attested for cycle %s (requester=%s chain=%s tx=%s)\n",
		req.CycleID, req.RequestingID, msg.TargetChain,
		msg.AnchorTxHash[:min(12, len(msg.AnchorTxHash))])

	return &PeerAttestationResponse{
		CycleID:     req.CycleID,
		Success:     true,
		Attestation: att,
	}, nil
}

// =============================================================================
// PHASE 9: RESULT WRITE-BACK
// =============================================================================

// Phase 9 write-back states, recorded on every cycle.
const (
	WriteBackWritten             = "written"
	WriteBackRefusedQuorumNotMet = "refused_quorum_not_met"
	WriteBackFailed              = "failed"
)

func (o *UnifiedOrchestrator) executePhase9(ctx context.Context, cycle *activeCycle) (err error) {
	cycle.Phase = 9
	// Any error below is a write-back that did not happen; say so unless a more specific state
	// was already recorded.
	defer func() {
		if err != nil && cycle.Result != nil {
			cycle.Result.WriteBackSuccess = false
			if cycle.Result.WriteBackState == "" {
				cycle.Result.WriteBackState = WriteBackFailed
			}
		}
	}()

	if o.config.OnPhaseComplete != nil {
		defer func() { o.config.OnPhaseComplete(cycle.CycleID, 9) }()
	}

	// RB-SEC-1: QUORUM ENFORCEMENT (fail closed). Never write back unless the attestation aggregate met the
	// ≥2/3 threshold in Phase 8. Without this a lone/malicious executor could write back
	// with only its own attestation (peers refusing via RB-SEC-1 would then be moot).
	if cycle.Result == nil || !cycle.Result.ThresholdMet {
		fmt.Printf("🚫 [Phase 9] Attestation threshold NOT met for cycle %s — refusing write-back (quorum enforcement)\n", cycle.CycleID)
		if cycle.Result != nil {
			cycle.Result.WriteBackSuccess = false
			cycle.Result.WriteBackState = WriteBackRefusedQuorumNotMet
		}
		return fmt.Errorf("attestation threshold not met — refusing write-back")
	}

	if o.txBuilder == nil || o.config.AccumulateClient == nil {
		return fmt.Errorf("write-back has no transaction builder or Accumulate client")
	}

	// Create timeout context
	writeBackCtx, cancel := context.WithTimeout(ctx, o.config.WriteBackTimeout)
	defer cancel()

	// Build ComprehensiveProofContext from the cycle data
	if ce, _ := cycle.Request.CommitmentData["commitmentError"].(string); ce != "" {
		return fmt.Errorf("write-back refused: the member's execution commitment could not be built: %s", ce)
	}
	proofCtx := o.buildComprehensiveProofContext(cycle)
	// A record of a settlement states the calls it was settled by. One that cannot is not written: it
	// would carry blank steps as if nothing had executed (RB3-F66). A non-settlement executed nothing.
	if proofCtx.StepsError != nil && cycle.NonSettlement == nil {
		return fmt.Errorf("write-back cannot state what was executed: %w", proofCtx.StepsError)
	}

	// Build the attestation bundle and persist its hash chain link under one lock: the link takes the
	// next sequence number only if it is stored (RB3-F82).
	o.resultChainsLock.Lock()
	bundle, rollback, err := o.buildAttestationBundleFromCycle(cycle)
	if err != nil {
		o.resultChainsLock.Unlock()
		return fmt.Errorf("build attestation bundle: %w", err)
	}
	if cycle.NonSettlement != nil {
		// A non-settlement has no transaction and no chain-execution row; its link has a table of its own.
		err = persistNonSettlementChainLink(ctx, hashChainRepo(o.config), o.config.ValidatorID, cycle, bundle.Result)
	} else {
		err = persistResultHashChainLink(ctx, hashChainRepo(o.config), cycle.Result.ChainExecutionIDs,
			len(cycle.Result.ObservationResults), bundle.Result)
	}
	if err != nil {
		rollback()
		o.resultChainsLock.Unlock()
		return fmt.Errorf("persist result hash chain link: %w", err)
	}
	o.resultChainsLock.Unlock()
	cycle.PrimaryResultHash = bundle.Result.ResultHash

	// Enrich bundle with per-leg data for multi-leg intents
	if cycle.Request.CommitmentData != nil {
		o.enrichBundleWithLegData(bundle, cycle)
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
	cycle.Result.WriteBackState = WriteBackWritten

	fmt.Printf("Write-back submitted: cycle=%s, receipt=%s\n", cycle.CycleID, receipt)

	return nil
}

// buildComprehensiveProofContext creates the context for write-back from cycle data
func (o *UnifiedOrchestrator) buildComprehensiveProofContext(cycle *activeCycle) *ComprehensiveProofContext {
	req := cycle.Request
	result := cycle.Result
	cm := req.CommitmentData

	ctx := &ComprehensiveProofContext{
		IntentID:     req.IntentID,
		IntentTxHash: req.AccumulateTxHash,
		IntentBlock:  uint64(req.AccumulateHeight),
	}

	// Extract AccumulateHeight from commitment if not set on request
	if ctx.IntentBlock == 0 && cm != nil {
		if h, ok := cm["accumulateBlockHeight"].(uint64); ok {
			ctx.IntentBlock = h
		} else if h, ok := cm["accumulateBlockHeight"].(float64); ok {
			ctx.IntentBlock = uint64(h)
		}
	}
	// Same for tx hash
	if ctx.IntentTxHash == "" || ctx.IntentTxHash == req.IntentID {
		if h, ok := cm["accumulateTxHash"].(string); ok && h != "" {
			ctx.IntentTxHash = h
		}
	}

	// Compute intent hash from tx hash
	if ctx.IntentTxHash != "" && ctx.IntentTxHash != req.IntentID {
		hashBytes, _ := hex.DecodeString(strings.TrimPrefix(ctx.IntentTxHash, "0x"))
		if len(hashBytes) == 32 {
			copy(ctx.IntentHash[:], hashBytes)
		}
	}

	// Populate commitment from request + commitment map
	if req.BundleID != [32]byte{} {
		ctx.Commitment = &ExecutionCommitment{
			OperationID: req.MerkleRoot,
			BundleID:    req.BundleID,
		}
		if cm != nil {
			// Commitment hash
			if ch, ok := cm["commitmentHash"].(string); ok {
				if decoded, err := hex.DecodeString(ch); err == nil && len(decoded) == 32 {
					copy(ctx.Commitment.CommitmentHash[:], decoded)
				}
			}
			// Intent references on commitment
			if txh, ok := cm["txHash"].(string); ok {
				ctx.Commitment.IntentTxHash = txh
			}
			// Expected value (final transfer amount)
			if fv, ok := cm["finalValue"].(string); ok && fv != "" && fv != "0" {
				if val, ok := new(big.Int).SetString(fv, 10); ok {
					ctx.Commitment.ExpectedValue = val
				}
			}
		}
	}

	// The three calls, as this member actually executed them (settlementSteps): never a template.
	if steps, err := o.settlementSteps(req.TargetChain, result.ObservationResults); err == nil {
		ctx.Step1Contract, ctx.Step1Selector = steps.anchor.Hex(), steps.step1Selector
		ctx.Step2Contract, ctx.Step2Selector = steps.anchor.Hex(), steps.step2Selector
		ctx.Step3Contract, ctx.Step3Selector = steps.step3Contract, steps.step3Selector
		if ctx.Commitment != nil {
			ctx.Commitment.TargetContract = steps.anchor
			copy(ctx.Commitment.FunctionSelector[:], common.FromHex(steps.step1Selector))
		}
	} else {
		ctx.StepsError = err
	}
	if cm != nil {
		// The member's committed final target and value: its own chain's leg (consensus, member-scoped).
		if ft, ok := cm["finalTarget"].(string); ok {
			ctx.Step3FinalTarget = ft
		}
		if fv, ok := cm["finalValue"].(string); ok {
			ctx.Step3FinalValue = fv
		}
		// Step1 intent hash (bundleID hex)
		if bid, ok := cm["bundleID"].(string); ok {
			ctx.Step1IntentHash = bid
		}
		// Governance proof ref
		if gr, ok := cm["governanceRoot"].(string); ok && gr != "" {
			ctx.GovernanceProofRef = gr
		}
	}

	// Events, as observed and as proven (RB3-F66). The transfer was executed by the member's settlement
	// transaction - the observed call step 3 states - not by a V3 GovernanceExecuted event the batch path
	// never emits, and never by whichever observation happened to be third. events_verified says the
	// committed events were PROVEN (Phase 7's contract-call gate, from the inclusion-proven receipt), not
	// merely that a receipt had logs; a native transfer commits none, so it states false: nothing verified.
	for _, obs := range result.ObservationResults {
		if obs == nil {
			continue
		}
		ctx.EventCount += len(obs.Logs)
		if ctx.TransferExecutedHash == "" && common.IsHexAddress(obs.TxTo) {
			ctx.TransferExecutedHash = obs.TxHash
		}
	}
	if ctx.TransferExecutedHash != "" {
		_, ctx.EventsVerified = cycle.VerifiedCalls[strings.ToLower(strings.TrimPrefix(ctx.TransferExecutedHash, "0x"))]
	}

	// Set proof artifact ID for PostgreSQL lookup
	if result.ProofID != uuid.Nil {
		ctx.ProofArtifactID = result.ProofID.String()
	}

	return ctx
}

// buildAttestationBundleFromCycle creates an AttestationBundle from the cycle result
//
// It binds the result into its chain's result hash chain. The caller holds resultChainsLock until the
// link is persisted and calls rollback if it is not, so a link that was never stored does not consume a
// sequence number (RB3-F82).
func (o *UnifiedOrchestrator) buildAttestationBundleFromCycle(cycle *activeCycle) (*AttestationBundle, func(), error) {
	result := cycle.Result

	if len(result.ObservationResults) == 0 {
		return nil, nil, fmt.Errorf("the cycle observed nothing to attest")
	}
	if result.ChainID == "" {
		return nil, nil, fmt.Errorf("the result names no chain")
	}

	// Get the primary observation result
	obs := result.ObservationResults[0]

	// A non-settlement has no transaction: its hash is zero, stated as such beside its outcome. Every
	// other hash is the chain's own 32 bytes - never a stand-in computed from whatever string was there.
	txHash, err := hash32(obs.TxHash, cycle.NonSettlement != nil)
	if err != nil {
		return nil, nil, fmt.Errorf("settlement transaction: %w", err)
	}
	blockHash, err := hash32(obs.BlockHash, false)
	if err != nil {
		return nil, nil, fmt.Errorf("block: %w", err)
	}

	// Build external chain result
	extResult := &ExternalChainResult{
		Chain:               getNetworkName(result.ChainID),
		ChainID:             parseChainIDInt(result.ChainID),
		TxHash:              txHash,
		BlockNumber:         parseBigInt(obs.BlockNumber),
		BlockHash:           blockHash,
		Status:              uint64(obs.Status), // 1=success, 0=revert
		StateRoot:           obs.StateRoot,
		TransactionsRoot:    obs.TransactionsRoot,
		ReceiptsRoot:        obs.ReceiptsRoot,
		ConfirmationBlocks:  obs.Confirmations,
		FinalizedAt:         time.Now().UTC(),
		TxGasUsed:           obs.GasUsed,
		ObservedByValidator: obs.ObserverValidatorID,
		TxFrom:              common.HexToAddress(obs.TxFrom),
		// Native (non-EVM) identifiers - preserve original strings for chains like NEAR
		NativeTxHash:    obs.TxHash,
		NativeBlockHash: obs.BlockHash,
		NativeTxFrom:    obs.TxFrom,
	}
	// A member that never settled: the record says so, with why - not a zero transaction that reads
	// like a revert.
	if cycle.NonSettlement != nil {
		extResult.Outcome = ResultOutcomeNotSettled
		extResult.OutcomeReason = cycle.NonSettlement.Cause
	}
	// A settlement that executed without its committed effects: the record says so and names them.
	if c := cycle.EffectsShortfall; c != nil {
		extResult.Outcome = ResultOutcomeEffectsNotProven
		extResult.OutcomeReason = fmt.Sprintf("settlement %s executed the committed call(s) under leaf %s, but committed effects are absent: events %v, state %v",
			c.TxHash, c.Leaf, c.MissingEvents, c.UnsetState)
	}

	// Copy logs from all observation results (not just primary)
	for _, obsResult := range result.ObservationResults {
		for _, l := range obsResult.Logs {
			extResult.Logs = append(extResult.Logs, LogEntry{
				Address: common.HexToAddress(l.Address),
				Topics:  parseTopics(l.Topics),
				Data:    l.Data,
				Index:   l.LogIndex,
			})
		}
	}

	// Compute anchor proof hash from the MerkleRoot (L3→L4 binding)
	anchorProofHash := cycle.Request.MerkleRoot

	// Apply result hash chain tracking (sequence_number, previous_result_hash, anchor_proof_hash). The
	// caller holds resultChainsLock.
	chainKey := result.ChainID
	hashChain, exists := o.resultChains[chainKey]
	if !exists {
		hashChain = NewResultHashChain(chainKey, anchorProofHash)
		o.resultChains[chainKey] = hashChain
	}
	before := *hashChain
	if err := hashChain.AddResult(extResult); err != nil { // Sets PreviousResultHash, AnchorProofHash, SequenceNumber
		return nil, nil, fmt.Errorf("result hash chain: %w", err)
	}
	rollback := func() {
		if exists {
			*hashChain = before
		} else {
			delete(o.resultChains, chainKey)
		}
	}

	// Build aggregated attestation
	var agg *AggregatedAttestation
	if result.AggregatedAttestation != nil {
		// Counts as counts and voting power as voting power (RB3-F81): the validator count used to be the
		// total WEIGHT, and a zero achieved weight was replaced by the participant COUNT.
		agg = &AggregatedAttestation{
			MessageHash:        result.AggregatedAttestation.MessageHash,
			AggregateSignature: result.AggregatedAttestation.AggregatedSignature,
			ValidatorCount:     result.AggregatedAttestation.ParticipantCount,
			SignedVotingPower:  new(big.Int).SetUint64(uint64(result.AggregatedAttestation.AchievedWeight)),
			TotalVotingPower:   new(big.Int).SetUint64(uint64(result.AggregatedAttestation.TotalWeight)),
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
	}, rollback, nil
}

// hash32 decodes a chain's 32-byte hash from its hex form. Empty is the zero hash only where there is,
// by definition, nothing to name (a non-settlement's transaction).
func hash32(s string, emptyIsNone bool) (common.Hash, error) {
	t := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	if t == "" && emptyIsNone {
		return common.Hash{}, nil
	}
	b, err := hex.DecodeString(t)
	if err != nil || len(b) != 32 {
		return common.Hash{}, fmt.Errorf("%q is not a 32-byte hash", s)
	}
	return common.BytesToHash(b), nil
}

// enrichBundleWithLegData adds per-leg proof data to the bundle for multi-leg intents.
// Leg data is extracted from the commitment map which carries all legs from the BFT consensus.
func (o *UnifiedOrchestrator) enrichBundleWithLegData(bundle *AttestationBundle, cycle *activeCycle) {
	commitMap := cycle.Request.CommitmentData
	if commitMap == nil {
		return
	}

	// Extract leg count
	var legCount int
	switch lc := commitMap["legCount"].(type) {
	case float64:
		legCount = int(lc)
	case int:
		legCount = lc
	}
	if legCount <= 1 {
		return // Single-leg intent, no enrichment needed
	}

	// Extract legs array from commitment
	legsRaw, ok := commitMap["legs"]
	if !ok {
		fmt.Printf("[MULTI-LEG] legCount=%d but no legs array in commitment for intent %s\n",
			legCount, cycle.Request.IntentID)
		return
	}

	legsList, ok := legsRaw.([]map[string]interface{})
	if !ok {
		// Try interface{} slice (may happen with JSON deserialization)
		if rawSlice, ok2 := legsRaw.([]interface{}); ok2 {
			for _, item := range rawSlice {
				if m, ok3 := item.(map[string]interface{}); ok3 {
					legsList = append(legsList, m)
				}
			}
		}
	}

	if len(legsList) == 0 {
		fmt.Printf("[MULTI-LEG] Could not parse legs array for intent %s\n", cycle.Request.IntentID)
		return
	}

	// This member executed only the legs on ITS chain, in the one transaction it observed. The legs on
	// the intent's other chains are executed - and recorded - by their own chain's members; listing
	// them here gave them this member's transaction, block and status (RB3-F51).
	if len(cycle.Result.ObservationResults) == 0 {
		return
	}
	cycleChainID, err := strconv.ParseInt(cycle.Result.ChainID, 10, 64)
	if err != nil {
		fmt.Printf("[MULTI-LEG] cycle chain %q is not a numeric chain id; no leg results recorded for intent %s\n",
			cycle.Result.ChainID, cycle.Request.IntentID)
		return
	}
	obs := cycle.Result.ObservationResults[0]

	for _, legMap := range legsList {
		chainID := commitmentInt64(legMap["chainId"])
		if chainID != cycleChainID {
			continue
		}
		legIndex := int(commitmentInt64(legMap["legIndex"]))
		chainName, _ := legMap["chain"].(string)
		if network, _ := legMap["network"].(string); network != "" && network != chainName {
			chainName = chainName + "-" + network
		}
		legID, _ := legMap["legId"].(string)

		bundle.LegResults = append(bundle.LegResults, LegResult{
			LegIndex:    legIndex,
			LegID:       legID,
			Chain:       chainName,
			ChainID:     chainID,
			TxHash:      obs.TxHash,
			BlockNumber: obs.BlockNumber,
			BlockHash:   obs.BlockHash,
			Status:      uint64(obs.Status),
			GasUsed:     obs.GasUsed,
			IsFinalized: obs.IsFinalized,
		})
	}
	if len(bundle.LegResults) == 0 {
		fmt.Printf("[MULTI-LEG] intent %s has no leg on chain %d - the member for this chain executed none of its legs\n",
			cycle.Request.IntentID, cycleChainID)
		return
	}

	bundle.MultiLegResultHash = ComputeMultiLegResultHash(bundle.LegResults)
	fmt.Printf("[MULTI-LEG] Recorded %d leg result(s) on chain %d for intent %s (hash=%x)\n",
		len(bundle.LegResults), cycleChainID, cycle.Request.IntentID, bundle.MultiLegResultHash[:8])
}

// parseBigInt parses a uint64 to *big.Int
func parseBigInt(n uint64) *big.Int {
	return new(big.Int).SetUint64(n)
}

// parseChainIDInt parses a chain ID string to int64
func parseChainIDInt(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// parseTopics converts string topic list to common.Hash slice
func parseTopics(topics []string) []common.Hash {
	result := make([]common.Hash, len(topics))
	for i, t := range topics {
		result[i] = common.HexToHash(t)
	}
	return result
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
//
// For on-cadence batches: Creates proof artifacts for each transaction in the batch,
// with proper leaf_index and merkle_path from batch_transactions table.
//
// For on-demand proofs: Creates a single proof artifact with leaf_index=0 for single-tx,
// or multiple artifacts for multi-leg intents.
func (o *UnifiedOrchestrator) generateAndPersistBundle(ctx context.Context, cycle *activeCycle) error {
	if o.config.Repos == nil || o.config.Repos.ProofArtifacts == nil {
		return fmt.Errorf("proof artifacts repository not configured")
	}

	req := cycle.Request
	result := cycle.Result

	// Determine proof class
	proofClass := database.ProofClassOnDemand
	if req.ProofClass == "on_cadence" {
		proofClass = database.ProofClassOnCadence
	}

	// Build artifact JSON with cycle result summary
	artifactData := map[string]interface{}{
		"cycle_id":           cycle.CycleID,
		"chain_platform":     result.ChainPlatform,
		"chain_id":           result.ChainID,
		"attestation_scheme": result.Scheme,
		"threshold_met":      result.ThresholdMet,
		"write_back_success": result.WriteBackSuccess,
		"write_back_state":   result.WriteBackState,
	}
	// What the proven execution DID. An artifact exists for a reverted settlement as well as a
	// successful one - the failure is proven, attested and written back too - so the artifact must
	// say which, or a reader of it (the gateway) takes "a proof exists" to mean "it executed".
	if outcome, txs := executionOutcome(result.ObservationResults); outcome != "" {
		artifactData["execution_outcome"] = outcome
		artifactData["execution_tx_hashes"] = txs
	}
	artifactJSON, err := json.Marshal(artifactData)
	if err != nil {
		return fmt.Errorf("marshal artifact data: %w", err)
	}

	// =========================================================================
	// ON-DEMAND: Create single proof artifact (or handle multi-leg)
	// =========================================================================

	// The ACCUMULATE TRANSACTION HASH — not the intent id.
	//
	// This is the key every consumer looks the artifact up by: proof-service does
	// `WHERE pa.accum_tx_hash = $1`, and the gateway calls it with the intent's
	// `accum_tx_hash` to attach `proof_id` to a completed transaction.
	//
	// The precedence here used to be inverted — `req.IntentID` first, the real hash only if the
	// intent id happened to be empty. `IntentID` is effectively always set, so the column got a
	// UUID and every lookup by hash missed. 380 artifacts written between 2026-01-26 and
	// 2026-08-21 carry an intent id in this column; the proofs were all generated and anchored
	// correctly and simply could not be found. Downstream that surfaced as `proof_id: null` on
	// every completed intent, which is why intents had to be allowed to complete on chain
	// evidence alone (api-gateway aee0110) — a workaround for this line.
	//
	// `req.AccumulateTxHash` is the field that carries it (unified_adapter.go:428, :631).
	accumTxHash := req.AccumulateTxHash
	if accumTxHash == "" {
		// Keying it by the intent id instead left an artifact every lookup by transaction hash missed.
		return fmt.Errorf("cycle %s names no Accumulate transaction to key its proof artifact by", req.CycleID)
	}

	// The member's place in its anchored batch, from its canonical row (RB3-F85). The request's
	// LeafHash and MerkleRoot are the operation commitment - an input to the leaf - and were stored as
	// both leaf and root, with index 0 and no path, for members of multi-intent batches too.
	placementChain, _ := strconv.ParseInt(req.TargetChain, 10, 64)
	placement, err := o.batchPlacement(ctx, req.IntentID, accumTxHash, placementChain)
	if err != nil {
		return err
	}
	var leafIndexPtr *int
	var artifactRoot, artifactLeaf []byte
	if placement != nil {
		idx := placement.TreeIndex
		leafIndexPtr, artifactRoot, artifactLeaf = &idx, placement.BatchRoot, placement.LeafHash
	}

	newArtifact := &database.NewProofArtifact{
		ProofType:    database.ProofTypeCertenAnchor,
		AccumTxHash:  accumTxHash,
		AccountURL:   req.AccumulateAccountURL, // Use actual Accumulate account URL (ADI)
		BatchID:      req.BatchID,
		MerkleRoot:   artifactRoot,
		LeafHash:     artifactLeaf,
		LeafIndex:    leafIndexPtr, // Position in the tree
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

	fmt.Printf("Created proof artifact: proof_id=%s, cycle_id=%s, leaf_index=%v\n",
		proofArtifact.ProofID, cycle.CycleID, leafIndexPtr)

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
			return fmt.Errorf("create anchor reference: %w", err)
		} else {
			fmt.Printf("Created anchor_reference for proof_id=%s, confirmations=%d, finalized=%v\n",
				proofArtifact.ProofID, confirmations, obs.IsFinalized)
		}
	}

	// 2b. Create governance_proof_levels entries (G0, G1, G2)
	isAnchored := len(result.ObservationResults) > 0

	// STAGE 2 — the real governance results, recovered once for all three levels.
	//
	// req.CommitmentData is the map RunProofCycle built; it carries the marshalled
	// G0/G1/G2 results and their receipt evidence under the shared key constants.
	// This writer never looked for them at all, which is why every row it produced
	// held verdict flags and no governance proof.
	govIn := GovernanceInputsFromCommitment(req.CommitmentData)
	if govIn == nil {
		logfPrintf("🚨 [GOV-LEVEL] proof %s: the commitment carries NO governance results — every "+
			"level written below is verdict flags only and is summary-only by construction",
			proofArtifact.ProofID)
	}

	// What the proven G1 result establishes about the key page that authorised the intent (RB3-F69).
	keyPage := keyPageTermsFromG1(govIn.ResultFor("G1"))

	// The highest governance level actually written, and its evidence: the authority proof of the
	// four-component Certen proof.
	var govLevelReached database.GovernanceLevel
	var govLevelJSON json.RawMessage
	var govLevelVerified bool

	// G0 - Inclusion and Finality (always created if we have anchor data)
	if isAnchored {
		var blockHeight *int64
		var anchorHeight *int64
		var finalityTimestamp *time.Time
		if len(result.ObservationResults) > 0 {
			obs := result.ObservationResults[0]
			bh := int64(obs.BlockNumber)
			blockHeight = &bh
			anchorHeight = &bh
			// Set finality timestamp from block timestamp
			if !obs.BlockTimestamp.IsZero() {
				finalityTimestamp = &obs.BlockTimestamp
			}
		}

		// The key page's M-of-N and its book from the proven G1 result (RB3-F69).
		thresholdM, thresholdN, authorityURL := keyPage.Threshold, keyPage.Keys, keyPage.Authority

		// STAGE 2 — the flags stay, EXACTLY as they were, and the governance proof
		// is added beside them.
		//
		// These six keys are what governance_proof_levels actually contained:
		// verdict flags about an EVM settlement plus key-page thresholds. They are
		// read by the evidence report and the approval console, so they are kept
		// unchanged. What they never were is the governance proof — the real
		// G0Result lived on PendingAttestation and died at this boundary.
		// Verdicts from the proofs they name (RB3-F73): inclusion from the gate's proven settlement, each
		// level from its own proven result - never by construction, never the validator quorum.
		g0Flags := map[string]interface{}{
			"inclusion_verified": settlementInclusionProven(cycle),
			"finality_achieved":  result.ObservationResults[0].IsFinalized,
			"confirmations":      result.ObservationResults[0].Confirmations,
			"threshold_m":        thresholdM,
			"threshold_n":        thresholdN,
			"authority_url":      authorityURL,
		}
		g0Result, g0Ev := govIn.ResultFor("G0"), govIn.ReceiptFor("G0")
		g0TB := govIn.TimingBasisFor("G0")
		g0JSON := BuildGovernanceLevelJSON("G0", g0Result, g0Ev, g0TB, g0Flags)
		LogGovernanceLevelEvidence(logfPrintf, proofArtifact.ProofID, "G0", g0Result, g0Ev, g0TB)

		g0Verified := levelProven("G0", g0Result)

		g0Level := &database.NewGovernanceProofLevel{
			ProofID:           proofArtifact.ProofID,
			GovLevel:          database.GovLevelG0,
			LevelName:         "G0 - Inclusion and Finality",
			BlockHeight:       blockHeight,
			FinalityTimestamp: finalityTimestamp,
			AnchorHeight:      anchorHeight,
			IsAnchored:        &isAnchored,
			ThresholdM:        thresholdM,
			ThresholdN:        thresholdN,
			SignatureCount:    keyPage.Signatures,
			AuthorityURL:      authorityURL,
			LevelJSON:         g0JSON,
			Verified:          &g0Verified,
		}

		if _, err := o.config.Repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g0Level); err != nil {
			return fmt.Errorf("create G0 governance level: %w", err)
		} else {
			fmt.Printf("Created governance_proof_level G0 for proof_id=%s\n", proofArtifact.ProofID)
			govLevelReached, govLevelJSON, govLevelVerified = database.GovLevelG0, g0JSON, g0Verified
		}
	}

	// G1 - Governance Correctness (created if we have governance root and attestations)
	if req.GovernanceRoot != [32]byte{} {
		// The key page's M-of-N and its book from the proven G1 result (RB3-F69).
		thresholdM, thresholdN, authorityURL := keyPage.Threshold, keyPage.Keys, keyPage.Authority

		// STAGE 2. G1 is the product's central claim — "did the right key page
		// authorize this" — and until now it was persisted as threshold_met, a
		// boolean with nothing behind it. The real G1Result and its receipt path
		// go in beside the flags.
		g1Flags := map[string]interface{}{
			"governance_root":   hex.EncodeToString(req.GovernanceRoot[:]),
			"threshold_met":     result.ThresholdMet,
			"attestation_count": len(result.Attestations),
			"authority_url":     authorityURL,
			"threshold_m":       thresholdM,
			"threshold_n":       thresholdN,
		}
		g1Result, g1Ev := govIn.ResultFor("G1"), govIn.ReceiptFor("G1")
		g1TB := govIn.TimingBasisFor("G1")
		g1JSON := BuildGovernanceLevelJSON("G1", g1Result, g1Ev, g1TB, g1Flags)
		LogGovernanceLevelEvidence(logfPrintf, proofArtifact.ProofID, "G1", g1Result, g1Ev, g1TB)

		g1Verified := levelProven("G1", g1Result)

		g1Level := &database.NewGovernanceProofLevel{
			ProofID:        proofArtifact.ProofID,
			GovLevel:       database.GovLevelG1,
			LevelName:      "G1 - Governance Correctness",
			AuthorityURL:   authorityURL,
			ThresholdM:     thresholdM,
			ThresholdN:     thresholdN,
			IsAnchored:     &isAnchored,
			SignatureCount: keyPage.Signatures,
			LevelJSON:      g1JSON,
			Verified:       &g1Verified,
		}

		if _, err := o.config.Repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g1Level); err != nil {
			return fmt.Errorf("create G1 governance level: %w", err)
		} else {
			fmt.Printf("Created governance_proof_level G1 for proof_id=%s\n", proofArtifact.ProofID)
			govLevelReached, govLevelJSON, govLevelVerified = database.GovLevelG1, g1JSON, g1Verified
		}
	}

	// G2 - Outcome Binding (created if we have operation commitment binding)
	if req.OperationCommitment != [32]byte{} && result.ThresholdMet {
		outcomeType := "execution_complete"
		g2Result, g2Ev := govIn.ResultFor("G2"), govIn.ReceiptFor("G2")
		bindingEnforced := levelProven("G2", g2Result)

		// The key page's M-of-N from the proven G1 result (RB3-F69).
		thresholdM, thresholdN, authorityURL := keyPage.Threshold, keyPage.Keys, keyPage.Authority

		// STAGE 2: flags kept, real G2Result and receipt path added beside them.
		g2Flags := map[string]interface{}{
			"operation_commitment": hex.EncodeToString(req.OperationCommitment[:]),
			"outcome_bound":        bindingEnforced,
			"write_back_success":   result.WriteBackSuccess,
			"write_back_state":     result.WriteBackState,
			"threshold_m":          thresholdM,
			"threshold_n":          thresholdN,
		}
		g2TB := govIn.TimingBasisFor("G2")
		g2JSON := BuildGovernanceLevelJSON("G2", g2Result, g2Ev, g2TB, g2Flags)
		LogGovernanceLevelEvidence(logfPrintf, proofArtifact.ProofID, "G2", g2Result, g2Ev, g2TB)

		g2Verified := bindingEnforced

		g2Level := &database.NewGovernanceProofLevel{
			ProofID:         proofArtifact.ProofID,
			GovLevel:        database.GovLevelG2,
			LevelName:       "G2 - Outcome Binding",
			ThresholdM:      thresholdM,
			ThresholdN:      thresholdN,
			AuthorityURL:    authorityURL,
			IsAnchored:      &isAnchored,
			SignatureCount:  keyPage.Signatures,
			OutcomeType:     &outcomeType,
			OutcomeHash:     req.OperationCommitment[:],
			BindingEnforced: &bindingEnforced,
			LevelJSON:       g2JSON,
			Verified:        &g2Verified,
		}

		if _, err := o.config.Repos.ProofArtifacts.CreateGovernanceProofLevel(ctx, g2Level); err != nil {
			return fmt.Errorf("create G2 governance level: %w", err)
		} else {
			fmt.Printf("Created governance_proof_level G2 for proof_id=%s\n", proofArtifact.ProofID)
			govLevelReached, govLevelJSON, govLevelVerified = database.GovLevelG2, g2JSON, g2Verified
		}
	}

	// 2c. Create chained_proof_layers entries (L1/L2/L3)
	// Fetch chained proof from Accumulate if ProofGenerator is configured
	// Store the result for bundle creation later
	var storedChainedProof *ChainedProofResult
	var anchorL5 *Layer5
	var anchorBatch *database.Layer5Binding
	anchorResolved := false
	if o.config.ProofGenerator != nil {
		// Determine parameters for chained proof generation
		accountURL := req.AccumulateAccountURL
		txHash := req.AccumulateTxHash
		bvn := req.AccumulateBVN

		if accountURL == "" || txHash == "" {
			// The results principal or the intent id used to stand in for them - a proof of some other
			// transaction, or of none.
			return fmt.Errorf("cycle %s names no Accumulate account and transaction to prove", req.CycleID)
		}
		// BVN calculation is handled by the ProofGenerator adapter
		// which uses deterministic routing from account URL
		// (see proof.CalculateBVNFromAccountURL)

		if accountURL != "" && txHash != "" {
			chainedProof, err := o.config.ProofGenerator.GenerateChainedProofForTx(ctx, accountURL, txHash, bvn)
			if err != nil {
				fmt.Printf("Warning: failed to generate chained proof (account=%s, tx=%s, bvn=%s): %v\n", accountURL, txHash, bvn, err)

				// Record the failure in chained_proof_layers so we have a record of the attempt
				failJSON, _ := json.Marshal(map[string]interface{}{
					"status":       "failed",
					"error":        err.Error(),
					"account_url":  accountURL,
					"tx_hash":      txHash,
					"bvn":          bvn,
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
					return fmt.Errorf("record chained proof failure: %w", createErr)
				} else {
					fmt.Printf("Recorded chained proof generation failure for proof_id=%s\n", proofArtifact.ProofID)
				}
			} else if chainedProof != nil {
				// Store for bundle creation later
				storedChainedProof = chainedProof

				// The full ChainedProof behind the flattened result — the scalars
				// the visualisation fields drop, plus both L4 legs.
				canonicalCP := ChainedProofFromResult(chainedProof)

				// The proof stored is the one consensus signed over, or nothing is stored (RB3-F87).
				if compared, err := matchesConsensusProof(req.CommitmentData, canonicalCP); err != nil {
					return fmt.Errorf("cycle %s: chained proof is not the one consensus signed over: %w", req.CycleID, err)
				} else if !compared {
					fmt.Printf("🚨 cycle %s: consensus signed over no L1-L3 proof for tx %s; the stored proof cannot be checked against it (RB3-F88)\n", req.CycleID, txHash)
				}

				// L1: Transaction → BVN
				l1JSON, _ := json.Marshal(map[string]interface{}{
					"layer":          "L1",
					"description":    "Transaction to BVN",
					"bvn_partition":  chainedProof.L1BVNPartition,
					"receipt_anchor": hex.EncodeToString(chainedProof.L1ReceiptAnchor),
					"source_hash":    hex.EncodeToString(chainedProof.L1SourceHash),
					"target_hash":    hex.EncodeToString(chainedProof.L1TargetHash),
					"path_depth":     len(chainedProof.L1ReceiptEntries),
				})

				// The authoritative L1 object (and the proof input it binds), beside
				// the description above. Without these the row can be redrawn but not
				// re-verified: ProofVerifier checks scalars the description drops.
				l1JSON = WithCanonicalL1(l1JSON, canonicalCP)
				l1Layer := &database.NewChainedProofLayer{
					ProofID:        proofArtifact.ProofID,
					LayerNumber:    1,
					LayerName:      "L1 - Transaction to BVN",
					BVNPartition:   &chainedProof.L1BVNPartition,
					ReceiptAnchor:  chainedProof.L1ReceiptAnchor,
					BVNRoot:        chainedProof.L1BVNRoot,
					SourceHash:     chainedProof.L1SourceHash,
					TargetHash:     chainedProof.L1TargetHash,
					ReceiptEntries: chainedProof.L1ReceiptEntries,
					LayerJSON:      l1JSON,
				}
				if _, err := o.config.Repos.ProofArtifacts.CreateChainedProofLayer(ctx, l1Layer); err != nil {
					return fmt.Errorf("create L1 chained layer: %w", err)
				}

				// L2: BVN → DN
				l2JSON, _ := json.Marshal(map[string]interface{}{
					"layer":       "L2",
					"description": "BVN to DN",
					"anchor_seq":  chainedProof.L2AnchorSeq,
					"source_hash": hex.EncodeToString(chainedProof.L2SourceHash),
					"target_hash": hex.EncodeToString(chainedProof.L2TargetHash),
					"path_depth":  len(chainedProof.L2ReceiptEntries),
				})

				l2JSON = WithCanonicalL2(l2JSON, canonicalCP)
				l2Layer := &database.NewChainedProofLayer{
					ProofID:        proofArtifact.ProofID,
					LayerNumber:    2,
					LayerName:      "L2 - BVN to DN",
					DNRoot:         chainedProof.L2DNRoot,
					AnchorSequence: &chainedProof.L2AnchorSeq,
					DNBlockHash:    chainedProof.L2DNBlockHash,
					SourceHash:     chainedProof.L2SourceHash,
					TargetHash:     chainedProof.L2TargetHash,
					ReceiptEntries: chainedProof.L2ReceiptEntries,
					LayerJSON:      l2JSON,
				}
				if _, err := o.config.Repos.ProofArtifacts.CreateChainedProofLayer(ctx, l2Layer); err != nil {
					return fmt.Errorf("create L2 chained layer: %w", err)
				}

				// L3: DN → Consensus
				l3JSON, _ := json.Marshal(map[string]interface{}{
					"layer":               "L3",
					"description":         "DN to Consensus",
					"dn_block_height":     chainedProof.L3DNBlockHeight,
					"consensus_timestamp": chainedProof.L3ConsensusTimestamp,
					"source_hash":         hex.EncodeToString(chainedProof.L3SourceHash),
					"target_hash":         hex.EncodeToString(chainedProof.L3TargetHash),
					"path_depth":          len(chainedProof.L3ReceiptEntries),
				})

				l3JSON = WithCanonicalL3(l3JSON, canonicalCP)
				consensusTS := chainedProof.L3ConsensusTimestamp
				l3Layer := &database.NewChainedProofLayer{
					ProofID:            proofArtifact.ProofID,
					LayerNumber:        3,
					LayerName:          "L3 - DN to Consensus",
					DNBlockHeight:      &chainedProof.L3DNBlockHeight,
					ConsensusTimestamp: &consensusTS,
					SourceHash:         chainedProof.L3SourceHash,
					TargetHash:         chainedProof.L3TargetHash,
					ReceiptEntries:     chainedProof.L3ReceiptEntries,
					LayerJSON:          l3JSON,
				}
				if _, err := o.config.Repos.ProofArtifacts.CreateChainedProofLayer(ctx, l3Layer); err != nil {
					return fmt.Errorf("create L3 chained layer: %w", err)
				}

				// L4: the two threshold-signed partition anchors, through the
				// SAME helper proof_cycle_orchestrator uses. Two copies of this
				// logic is how L4 came to be missing from one path already.
				if err := WriteLayer4Rows(ctx, o.config.Repos.ProofArtifacts, proofArtifact.ProofID,
					ChainedProofFromResult(chainedProof), logfPrintf); errors.Is(err, errLayer4Write) {
					return err
				} else if err != nil {
					fmt.Printf("Warning: proof_id=%s stored WITHOUT L4 evidence — it is summary-only, "+
						"not offline-verifiable\n", proofArtifact.ProofID)
				}

				// L5: the external anchor binding, plus the two joins that were
				// never written. STAGE 3.
				//
				// It comes after L4 for a structural reason, not a stylistic one:
				// L5 attests to the anchoring of a govRoot that commits to L1-L4
				// and G0-G2, so what the proof CONTAINS has to be settled before
				// the layer attesting to it is built. It is deliberately NOT in
				// the govRoot — it cannot be inside what it describes.
				anchorL5, anchorBatch = o.writeLayer5(ctx, proofArtifact.ProofID, placement, result)
				anchorResolved = true

				fmt.Printf("Created chained_proof_layers L1/L2/L3/L4/L5 for proof_id=%s\n", proofArtifact.ProofID)
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
				return fmt.Errorf("create proof attestation for %s: %w", att.ValidatorID, err)
			}
		}
		fmt.Printf("Created %d validator_attestations for proof_id=%s\n", len(result.Attestations), proofArtifact.ProofID)
	}

	// 2e. Create verification_history entry (record that proof was verified)
	verifierID := o.config.ValidatorID
	if cycle.StartedAt.IsZero() {
		return fmt.Errorf("cycle %s has no start time to measure its verification by", cycle.CycleID)
	}
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
		return fmt.Errorf("create verification record: %w", err)
	} else {
		fmt.Printf("Created verification_history for proof_id=%s\n", proofArtifact.ProofID)
	}

	// 2f. The four proof levels and the four-component Certen proof.
	if !anchorResolved {
		anchorL5, anchorBatch = o.resolveAnchorBinding(ctx, proofArtifact.ProofID, placement, result)
	}
	var chainedProofJSON json.RawMessage
	if storedChainedProof != nil {
		if encoded, err := json.Marshal(ChainedProofFromResult(storedChainedProof)); err == nil {
			chainedProofJSON = encoded
		} else {
			return fmt.Errorf("encode chained proof for level 1 of proof_id=%s: %w", proofArtifact.ProofID, err)
		}
	}
	o.recordProofLevels(ctx, cycle, proofLevelInputs{
		Artifact:         proofArtifact,
		IntentID:         req.IntentID,
		AccumTxHash:      accumTxHash,
		AccountURL:       req.AccumulateAccountURL,
		MerkleRoot:       placementRoot(placement),
		LeafHash:         placementLeaf(placement),
		LeafIndex:        placementIndex(placement),
		MerklePath:       placementPath(placement),
		ChainedProof:     chainedProofJSON,
		AccumBlockHeight: req.AccumulateHeight,
		AccumBVN:         req.AccumulateBVN,
		GovCommitment:    req.GovernanceRoot[:],
		GovLevel:         govLevelReached,
		GovProof:         govLevelJSON,
		GovValid:         govLevelVerified,
	}, anchorL5, anchorBatch)

	// Step 3: Build the CertenProofBundle
	bundle := proof.NewCertenProofBundle(cycle.CycleID)

	// Set transaction reference
	// SetTransactionRef(txHash, accountURL, txType) — the SECOND argument is the ACCOUNT URL.
	// It was being passed req.IntentID, so the bundle a counterparty downloads showed a UUID in
	// `account_url` (and, before the accumTxHash fix above, the same UUID in `accum_tx_hash`).
	// A verifier could not tie the bundle to the Accumulate account or the on-chain transaction
	// it attests to — which is the entire job of the reference block. The other two call sites
	// (proof_cycle_orchestrator.go, artifact_service.go) already pass a real account URL.
	bundle.SetTransactionRef(accumTxHash, req.AccumulateAccountURL, req.ProofClass)

	// The member's inclusion in its anchored batch, as its canonical row states it - or none. It used to
	// be the operation commitment as leaf and root, and to fall back to it for the leaf (RB3-F85).
	if placement != nil {
		var merklePath []proof.MerklePathEntry
		for _, node := range placement.MerklePath {
			merklePath = append(merklePath, proof.MerklePathEntry{Hash: node.Hash, Right: node.Position == "right"})
		}
		bundle.SetMerkleInclusion(
			hex.EncodeToString(placement.BatchRoot),
			hex.EncodeToString(placement.LeafHash),
			int64(placement.TreeIndex),
			merklePath,
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
		// Component 5: the receipt and the verified inclusion proofs, so a stranger can check the
		// event off any RPC. Only present when the gate verified a receipt proof (persistVerifiedProofs
		// wrote it onto the observation); never a receipt without its proof.
		if len(obs.ReceiptProof) > 0 {
			logs := make([]proof.ExecutionLog, 0, len(obs.Logs))
			for _, l := range obs.Logs {
				logs = append(logs, proof.ExecutionLog{Address: l.Address, Topics: l.Topics, Data: "0x" + hex.EncodeToString(l.Data), LogIndex: l.LogIndex})
			}
			bundle.SetExecutionProof(&proof.ExecutionProof{
				ChainID:          result.ChainID,
				TxHash:           obs.TxHash,
				BlockNumber:      obs.BlockNumber,
				BlockHash:        obs.BlockHash,
				Status:           obs.Status,
				TransactionsRoot: "0x" + hex.EncodeToString(obs.TransactionsRoot[:]),
				ReceiptsRoot:     "0x" + hex.EncodeToString(obs.ReceiptsRoot[:]),
				RawReceipt:       "0x" + hex.EncodeToString(obs.RawReceipt),
				Logs:             logs,
				TxInclusion:      json.RawMessage(obs.MerkleProof),
				ReceiptInclusion: json.RawMessage(obs.ReceiptProof),
				VerifiedBy:       obs.ObserverValidatorID,
				VerifiedAt:       obs.ObservedAt,
			})
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

	// Set chained proof from stored result (L1/L2/L3 layers)
	if storedChainedProof != nil {
		l1Source := hex.EncodeToString(storedChainedProof.L1SourceHash)
		l1Target := hex.EncodeToString(storedChainedProof.L1TargetHash)
		l2Source := hex.EncodeToString(storedChainedProof.L2SourceHash)
		l2Target := hex.EncodeToString(storedChainedProof.L2TargetHash)
		l3Source := hex.EncodeToString(storedChainedProof.L3SourceHash)
		l3Target := hex.EncodeToString(storedChainedProof.L3TargetHash)

		bundle.ProofComponents.ChainedProof = &proof.ChainedProofData{
			Layer1: &proof.ProofLayer{
				LayerName:   "L1 - Transaction to BVN",
				SourceHash:  l1Source,
				TargetHash:  l1Target,
				PartitionID: storedChainedProof.L1BVNPartition,
				Verified:    true,
				VerifiedAt:  time.Now().UTC(),
				Receipt: &proof.ReceiptData{
					Start:   l1Source,
					Anchor:  l1Target,
					Entries: convertMerklePathToBundle(storedChainedProof.L1ReceiptEntries),
				},
			},
			Layer2: &proof.ProofLayer{
				LayerName:  "L2 - BVN to DN",
				SourceHash: l2Source,
				TargetHash: l2Target,
				Verified:   true,
				VerifiedAt: time.Now().UTC(),
				Receipt: &proof.ReceiptData{
					Start:   l2Source,
					Anchor:  l2Target,
					Entries: convertMerklePathToBundle(storedChainedProof.L2ReceiptEntries),
				},
			},
			Layer3: &proof.ProofLayer{
				LayerName:   "L3 - DN to Consensus",
				SourceHash:  l3Source,
				TargetHash:  l3Target,
				BlockHeight: uint64(storedChainedProof.L3DNBlockHeight),
				Verified:    true,
				VerifiedAt:  time.Now().UTC(),
				Receipt: &proof.ReceiptData{
					Start:   l3Source,
					Anchor:  l3Target,
					Entries: convertMerklePathToBundle(storedChainedProof.L3ReceiptEntries),
				},
			},
			Verified:      true,
			VerifiedLevel: "complete",
		}
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

	// Serialize bundle to compact JSON (same format used for compression)
	uncompressedData, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("serialize bundle: %w", err)
	}
	bundleHash := sha256.Sum256(uncompressedData)

	// Compress bundle to gzipped JSON
	compressedData, err := bundle.ToCompressedJSON()
	if err != nil {
		return fmt.Errorf("compress bundle: %w", err)
	}

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

		// The highest governance level the proofs establish (RB3-F73): each level needs its own proof and
		// every level below it. None proven is stated as none, not as G0.
		var govLevel database.GovernanceLevel
		if levelProven("G0", govIn.ResultFor("G0")) {
			govLevel = database.GovLevelG0
			if levelProven("G1", govIn.ResultFor("G1")) {
				govLevel = database.GovLevelG1
				if levelProven("G2", govIn.ResultFor("G2")) {
					govLevel = database.GovLevelG2
				}
			}
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
			return fmt.Errorf("update proof final state: %w", err)
		} else {
			fmt.Printf("Updated proof_artifacts final state: proof_id=%s, status=anchored, gov_level=%s, verified=%v\n",
				proofArtifact.ProofID, govLevel, result.ThresholdMet)
		}
	}

	return nil
}

// The member's placement as the proof levels record it; empty when it has no canonical row.
func placementRoot(p *database.Layer5Binding) []byte {
	if p == nil {
		return nil
	}
	return p.BatchRoot
}

func placementLeaf(p *database.Layer5Binding) []byte {
	if p == nil {
		return nil
	}
	return p.LeafHash
}

func placementIndex(p *database.Layer5Binding) int {
	if p == nil {
		return 0
	}
	return p.TreeIndex
}

func placementPath(p *database.Layer5Binding) []database.MerklePathNode {
	if p == nil {
		return nil
	}
	return p.MerklePath
}
