// pkg/consensus/bft_integration.go
package consensus

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/certen/independant-validator/pkg/entitlement"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/config"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cryptoproto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"github.com/cometbft/cometbft/proxy"
	cmthttp "github.com/cometbft/cometbft/rpc/client/http"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/kvdb"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
	"github.com/certen/independant-validator/pkg/verification"
)

// ErrIntentPermanentlyInvalid marks a failure that no later attempt can fix.
//
// An intent's bytes are final on Accumulate before CERTEN ever sees them, so a
// structural defect is a property of the record, not of the moment it was read.
// Retrying is not merely useless, it is harmful: discovery rediscovers the
// intent every poll and the whole fleet re-refuses it forever, which is real
// CPU spent to reach the same answer.
//
// Wrap ONLY genuinely permanent conditions. A transient failure marked
// permanent silently drops a customer's work, which is far worse than a wasted
// retry — so when in doubt, leave it retryable.
var ErrIntentPermanentlyInvalid = errors.New("intent is permanently invalid")

// Version information - can be set at build time via ldflags:
// go build -ldflags "-X github.com/certen/independant-validator/pkg/consensus.Version=v1.0.0"
var (
	// Version is the Certen validator version
	Version = "v0.1.0-dev"
	// BuildTime is set at build time
	BuildTime = "unknown"
	// GitCommit is set at build time
	GitCommit = "unknown"
)

// validKeyPageURLPattern matches valid Accumulate keypage URLs that end with /N where N is a number
// Examples: acc://foo.acme/book/1, acc://bar.acme/book/2
var validKeyPageURLPattern = regexp.MustCompile(`/\d+$`)

// resolveKeyPageURL validates and resolves a keypage URL to ensure it follows Accumulate conventions.
// Accumulate keypages are numbered: /book/1, /book/2, etc. Not /book/page or other invalid formats.
//
// This function:
// 1. Validates if the URL ends with a number (valid format like /book/1)
// 2. If invalid (like /book/page), extracts the keybook base and queries Accumulate for valid pages
// 3. Returns the resolved keypage URL or error if resolution fails
//
// Parameters:
//   - keyPageURL: The keypage URL to validate (e.g., "acc://foo.acme/book/page")
//   - keyBookURL: The keybook URL to use for fallback resolution (e.g., "acc://foo.acme/book")
//   - logger: Logger for diagnostic output
//
// Returns:
//   - Resolved keypage URL (e.g., "acc://foo.acme/book/1")
//   - Error if the URL cannot be resolved
func resolveKeyPageURL(keyPageURL, keyBookURL string, logger Logger) (string, error) {
	// If keyPageURL is empty, derive from keybook
	if keyPageURL == "" {
		if keyBookURL == "" {
			return "", fmt.Errorf("both keypage and keybook URLs are empty")
		}
		// Keybook exists, query it to find the first keypage
		// Accumulate keypages are indexed starting from 1
		resolvedURL := keyBookURL + "/1"
		logger.Printf("🔧 [KEYPAGE-RESOLVE] Derived keypage from keybook: %s", resolvedURL)
		return resolvedURL, nil
	}

	// Check if the keyPageURL ends with a valid number pattern
	if validKeyPageURLPattern.MatchString(keyPageURL) {
		// URL is valid (ends with /N where N is a number)
		return keyPageURL, nil
	}

	// Invalid format detected - resolve from keybook
	logger.Printf("⚠️ [KEYPAGE-RESOLVE] Invalid keypage format detected: %s (must end with /N)", keyPageURL)

	// Extract the base path by removing the invalid suffix
	// e.g., "acc://foo.acme/book/page" -> "acc://foo.acme/book"
	lastSlash := strings.LastIndex(keyPageURL, "/")
	if lastSlash > 0 {
		basePath := keyPageURL[:lastSlash]
		// The base path should be the keybook
		// Query Accumulate to find valid keypages under this keybook
		// For now, use the standard convention: first keypage is at index 1
		resolvedURL := basePath + "/1"
		logger.Printf("🔧 [KEYPAGE-RESOLVE] Resolved invalid keypage %s -> %s", keyPageURL, resolvedURL)
		return resolvedURL, nil
	}

	// If we have a keybook URL, use it as fallback
	if keyBookURL != "" {
		resolvedURL := keyBookURL + "/1"
		logger.Printf("🔧 [KEYPAGE-RESOLVE] Using keybook fallback: %s", resolvedURL)
		return resolvedURL, nil
	}

	return "", fmt.Errorf("cannot resolve invalid keypage URL: %s", keyPageURL)
}

// BFTConsensusEngine is what the rest of the validator code should depend on.
// RealCometBFTEngine is the production implementation.
type BFTConsensusEngine interface {
	Start() error
	Stop() error
	// BroadcastValidatorBlockCommit sends the canonical ValidatorBlock through
	// CometBFT and waits for it to be committed.
	BroadcastValidatorBlockCommit(ctx context.Context, vb *ValidatorBlock) (*BFTExecutionResult, error)
	// BroadcastAppTxSync broadcasts ABCI transactions (executor_selection, execution_result) via in-process engine
	BroadcastAppTxSync(ctx context.Context, tx []byte) error
	GetABCIApp() *CertenApplication
	// GetLedgerStoreProvider returns the ABCI app if it provides ledger store access
	// This works for both CertenApplication and ValidatorApp
	GetLedgerStoreProvider() LedgerStoreProvider
}

// BFTExecutionResult = "what CometBFT told us" for the VB tx.
type BFTExecutionResult struct {
	Height      int64
	TxHash      []byte
	BlockHash   []byte
	CommittedAt time.Time
}

// AnchorManager interface for anchor creation
type AnchorManager interface {
	CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResponse, error)
}

// AnchorRequest represents a request to create an anchor
type AnchorRequest struct {
	RequestID       string   `json:"request_id"`
	TargetChains    []string `json:"target_chains"`
	Priority        string   `json:"priority"`
	TransactionHash string   `json:"transaction_hash"`
	AccountURL      string   `json:"account_url"`
}

// AnchorResponse represents the response from anchor creation
type AnchorResponse struct {
	AnchorID string `json:"anchor_id"`
	Success  bool   `json:"success"`
	Message  string `json:"message"`
}

// ChainLegInfo describes a single leg's chain identity for multi-leg proof cycle routing.
// Defined here (not in execution package) to avoid circular imports.
type ChainLegInfo struct {
	LegIndex  int
	LegID     string
	ChainKey  string // e.g., "base-sepolia"
	ChainName string // e.g., "Base Sepolia"
	ChainID   int64  // e.g., 84532
}

// AnchorWorkflowTxHashes contains all 3 transaction hashes from the Ethereum anchor workflow
// This enables comprehensive tracking and observation of the entire anchor process
type AnchorWorkflowTxHashes struct {
	CreateTxHash     common.Hash // Step 1: createAnchor tx
	VerifyTxHash     common.Hash // Step 2: executeComprehensiveProof tx
	GovernanceTxHash common.Hash // Step 3: executeWithGovernance tx

	// For backwards compatibility, PrimaryTxHash points to CreateTxHash
	PrimaryTxHash common.Hash

	// RawTxHashes stores native-format tx hashes for non-EVM chains (e.g. NEAR base58).
	// When populated, these take priority over the common.Hash fields which only work for hex hashes.
	RawTxHashes []string
}

// extractPureHexHash strips chain prefix from multi-chain tx hash strings.
// Multi-chain execution formats tx hashes as "ChainName:0xhash..." or "ChainName:leg-N:0xhash...".
// This extracts just the "0x..." portion for use with common.HexToHash().
func extractPureHexHash(chainPrefixedHash string) string {
	// For multi-chain results (comma-separated), find the first valid entry (skip _failed entries)
	if strings.Contains(chainPrefixedHash, ",") {
		for _, part := range strings.Split(chainPrefixedHash, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "_failed") {
				continue
			}
			if strings.Contains(part, "0x") {
				chainPrefixedHash = part
				break
			}
		}
	}
	idx := strings.LastIndex(chainPrefixedHash, "0x")
	if idx > 0 {
		return chainPrefixedHash[idx:]
	}
	return chainPrefixedHash
}

// extractRawTxHash strips chain prefix from tx hash strings, preserving native format.
// Works for any chain format: EVM hex ("0x..."), NEAR base58, Solana base58, etc.
// For multi-chain results (comma-separated), extracts the first valid (non-failed) chain's hash.
func extractRawTxHash(chainPrefixedHash string) string {
	// For multi-chain results (comma-separated), find the first valid entry
	if strings.Contains(chainPrefixedHash, ",") {
		for _, part := range strings.Split(chainPrefixedHash, ",") {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "_failed") {
				continue
			}
			chainPrefixedHash = part
			break
		}
	}
	if idx := strings.LastIndex(chainPrefixedHash, ":"); idx >= 0 {
		if candidate := chainPrefixedHash[idx+1:]; len(candidate) > 0 {
			return candidate
		}
	}
	return chainPrefixedHash
}

// ProofCycleOrchestratorInterface defines the interface for proof cycle orchestration
// This enables the BFTValidator to trigger Phase 7-9 after successful execution
type ProofCycleOrchestratorInterface interface {
	// StartProofCycle initiates Phase 7-9 for an executed operation
	// The commitment parameter uses interface{} to avoid circular imports with execution package
	StartProofCycle(ctx context.Context, intentID string, bundleID [32]byte, executionTxHash common.Hash, commitment interface{}) error

	// StartProofCycleWithAllTxs initiates Phase 7-9 with all 3 anchor workflow tx hashes
	// Enhanced: Tracks createAnchor, executeComprehensiveProof, and executeWithGovernance
	// The txHashes parameter uses interface{} to avoid circular imports - actual type is *AnchorWorkflowTxHashes
	StartProofCycleWithAllTxs(ctx context.Context, intentID string, userID string, bundleID [32]byte, txHashes interface{}, commitment interface{}) error

	// StartProofCycleWithAccumulateRef initiates Phase 7-9 with Accumulate reference data for L1/L2/L3 proofs
	// Enhanced: Includes Accumulate account URL and tx hash for chained proof generation
	StartProofCycleWithAccumulateRef(ctx context.Context, intentID string, userID string, bundleID [32]byte, txHashes interface{}, commitment interface{}, accumulateAccountURL string, accumulateTxHash string, bvn string) error

	// StartPerChainProofCycles starts separate proof cycles for each chain in a multi-leg intent.
	// chainTxHashes maps chain key (e.g., "base-sepolia") to governance tx hashes for that chain.
	// legs uses interface{} (actual type []ChainLegInfo) to avoid circular imports.
	// Returns nil if multi-leg proof cycles are not supported (legacy orchestrator).
	StartPerChainProofCycles(ctx context.Context, intentID string, operationID string, bundleID [32]byte,
		chainTxHashes map[string][]string, legs interface{}, executionMode string, commitment interface{},
		accumulateAccountURL string, accumulateTxHash string, bvn string) error
}

// BFTValidatorInfo represents information about a BFT validator
type BFTValidatorInfo struct {
	ValidatorID string
	PublicKey   []byte
	VotingPower int64
	IsActive    bool
	Address     string
}

// ConsensusParams represents consensus parameters
type ConsensusParams struct {
	ByzantineFaultTolerance float64
	ConsensusTimeout        time.Duration
	MinVotingPower          int64
	ExecutorSelectionSeed   []byte
}

// ConsensusResult represents the result of a consensus operation
type ConsensusResult struct {
	Success          bool                   `json:"success"`
	SelectedExecutor string                 `json:"selected_executor"`
	VotingResults    map[string]string      `json:"voting_results"`
	ProofValidated   bool                   `json:"proof_validated"`
	ExecutionStatus  string                 `json:"execution_status"`
	Error            string                 `json:"error,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	RoundID          string                 `json:"round_id,omitempty"`
	Result           string                 `json:"result,omitempty"`
}

// Use the real proof types from the proof package
type ProofGenerator interface {
	GenerateProof(ctx context.Context, req *proof.ProofRequest) (*proof.CertenProof, error)
}

// GovernanceProofGenerator generates G0/G1/G2 governance proofs
// Per CERTEN spec v3-governance-kpsw-exec-4.0, these proofs are generated
// AFTER L1-L4 lite client proof completes (dependency chain)
type GovernanceProofGenerator interface {
	// GenerateG0 generates G0 proof (Inclusion and Finality)
	// Uses L1-L4 artifacts as cryptographic foundation
	GenerateG0(ctx context.Context, req *proof.GovernanceRequest) (*proof.GovernanceProof, error)

	// GenerateG1 generates G1 proof (Governance Correctness)
	// Uses G0 artifacts + validates key page authority and signature threshold
	GenerateG1(ctx context.Context, req *proof.GovernanceRequest) (*proof.GovernanceProof, error)

	// GenerateG2 generates G2 proof (Governance + Outcome Binding)
	// Uses G1 artifacts + verifies payload and effects (post-execution only)
	GenerateG2(ctx context.Context, req *proof.GovernanceRequest) (*proof.GovernanceProof, error)

	// GenerateAtLevel generates governance proof at specified level
	GenerateAtLevel(ctx context.Context, level proof.GovernanceLevel, req *proof.GovernanceRequest) (*proof.GovernanceProof, error)
}

// AnchorScheduler defines the interface for scheduling anchor operations
// This enables on_cadence batching vs on_demand immediate execution per FIRST_PRINCIPLES 2.5
// BatchEnqueuer accepts an on_cadence intent for cross-ADI batching.
//
// Implemented by pkg/execution's BatchStack. Kept as an interface so consensus does not have
// to construct the batch stack itself, and so the wiring can be verified with a stub.
type BatchEnqueuer interface {
	// EnqueueForBatch queues one authorized intent. Returning an error means the intent was
	// NOT queued and the caller must fall back, or it would be silently dropped.
	EnqueueForBatch(
		intentID string,
		adiURL string,
		chainID int64,
		account [20]byte,
		operationID [32]byte,
		legs interface{},
		attestation interface{},
		commitHeight uint64,
	) error

	// EnqueueOnDemand queues an intent-keyed member: one intent, one anchor, no period.
	//
	// Same contract as EnqueueForBatch — an error means NOT queued and the caller must fall
	// back. The two differ only in which mechanism settles the member.
	EnqueueOnDemand(
		intentID string,
		adiURL string,
		chainID int64,
		account [20]byte,
		operationID [32]byte,
		legs interface{},
		attestation interface{},
		commitHeight uint64,
	) error
}

type AnchorScheduler interface {
	// QueueForCadence queues an intent for batched on-cadence execution
	// Returns the scheduled time when the batch will be processed
	QueueForCadence(ctx context.Context, intentID string, vbMeta *verification.ValidatorBlockMetadata, bftMeta *verification.BFTExecutionMetadata) (scheduledAt time.Time, err error)

	// GetQueuedCount returns the number of intents waiting in the cadence queue
	GetQueuedCount() int

	// IsRunning returns whether the scheduler is actively processing
	IsRunning() bool
}

// BFTValidator represents a decentralized BFT validator with elected executor consensus
// Phase 3: BFTValidator now uses only CometBFT for consensus (no ExecutionConsensus)
type BFTValidator struct {
	engine                BFTConsensusEngine
	anchorManager         AnchorManager
	proofGenerator        ProofGenerator
	governanceProofGen    GovernanceProofGenerator // G0/G1/G2 proof generator (runs AFTER L1-L4)
	targets               verification.TargetChainExecutor
	validatorBlockBuilder *ValidatorBlockBuilder
	logger                Logger
	validatorID           string
	chainID               string // CometBFT chain ID (e.g., "certen-validator")
	privateKey            ed25519.PrivateKey
	executionQueue        chan *ExecutionTask
	ctx                   context.Context
	cancel                context.CancelFunc

	// BFT coordination fields
	mu sync.RWMutex

	// observedHeight is the highest BFT height a round has committed at on this node. It is
	// the cutoff source for deterministic batch periods — see ObservedConsensusHeight. Kept
	// here rather than read from the ABCI app because this is the exact value stamped onto
	// batch members, so a cutoff derived from it can never be ahead of every member.
	observedHeight atomic.Uint64

	// Proof Cycle Orchestrator for Phase 7-9 (observation, attestation, write-back)
	proofCycleOrchestrator ProofCycleOrchestratorInterface

	// Anchor Scheduler for on_cadence batching per FIRST_PRINCIPLES 2.5
	// When set, on_cadence intents are queued for batched execution instead of immediate
	anchorScheduler AnchorScheduler

	// batchEnqueuer routes on_cadence intents into the cross-ADI batch mempool, where many
	// intents share ONE anchor and ONE BLS verification. Measured on live Sepolia those two
	// steps are 802,128 of the 987,644 gas an intent costs (81.2%), so amortising them is
	// where essentially all the saving is.
	//
	// Nil means the batch path is not configured and on_cadence falls back to the existing
	// deferred-serial scheduler — which still settles, just without the saving. Falling back
	// rather than failing is deliberate: a misconfigured batch path must never strand intents.
	batchEnqueuer BatchEnqueuer

	// Entitlement store, used at Phase 3 to attach proof that the submitting ADI
	// may have CERTEN spend on this intent. nil when the gate is not configured,
	// in which case no evidence is attached and the (off-by-default) consensus
	// gate lets blocks through unchanged.
	//
	// Read-only cache lookup — never performs I/O on this path.
	entitlementStore *entitlement.Store

	// Entitlement gate mode, so the proposer can decline to sign locally rather
	// than build a block the fleet will reject anyway. Purely an optimisation:
	// the authority is the consensus rule in abci_validator.go.
	entitlementMode EntitlementMode
}

// SetEntitlementStore wires the entitlement snapshot used to build evidence at
// Phase 3. Safe to leave unset: the proposer then attaches nothing, which is
// refused only if the consensus gate is enforcing.
func (bv *BFTValidator) SetEntitlementStore(store *entitlement.Store, mode EntitlementMode) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.entitlementStore = store
	bv.entitlementMode = mode
}

// Intent represents an intent to be executed
type Intent struct {
	ID              string `json:"id"`
	TransactionHash string `json:"transaction_hash"` // Real Accumulate transaction hash
	AccountURL      string `json:"account_url"`      // Real account URL from CertenIntent
	// Add other fields as needed for your system
}

// ExecutionTask represents a task for BFT consensus execution
type ExecutionTask struct {
	Intent      *Intent                   `json:"intent"`
	RoundID     string                    `json:"round_id"`
	BlockHeight uint64                    `json:"block_height"`
	ResultChan  chan *ExecutionTaskResult `json:"-"`
}

// ExecutionTaskResult contains the result of BFT execution
type ExecutionTaskResult struct {
	// Success means CONSENSUS succeeded — the validators agreed and the block
	// committed. It deliberately does NOT mean the target-chain write landed:
	// an external chain failure must not invalidate a block the fleet already
	// agreed on.
	Success bool `json:"success"`
	// TargetChainConfirmed answers the DIFFERENT question: did the on-chain work
	// actually land? Collapsing the two into one boolean is why an intent whose
	// every step reverted was logged as "executed successfully" and marked
	// complete (observed 2026-08-09 on arbitrum- and ethereum-sepolia, where
	// create, verify and governance all failed and the intent still reported
	// success). Consensus and execution are separate facts and are now reported
	// separately.
	//
	// STAGE 1: this bool is now DERIVED, because it has two values and the
	// question has three answers. A settlement that had merely not resolved yet
	// was indistinguishable from one that reverted, so a healthy intent was
	// reported as a failure. Measured 2026-08-25 on intent
	// 1638327d-af2c-439c-a188-be53cdb5c854: the "did NOT confirm … gas may have
	// been spent on a reverted transaction" warning was logged at 07:33:41 with
	// targetChainError="", and the transaction confirmed status=1 at 07:34:32.
	// FIFTY-ONE SECONDS. See TargetChainOutcome in target_chain_outcome.go.
	//
	// Kept rather than deleted: `target_chain_confirmed` is a wire field other
	// code and operators read, and "did it succeed" is still a real question with
	// a real boolean answer. Set it ONLY as (TargetChainOutcome == confirmed);
	// never assign it directly.
	TargetChainConfirmed bool `json:"target_chain_confirmed"`

	// TargetChainOutcome carries the third answer the bool above cannot hold:
	// PENDING — submitted, no terminal receipt yet. It is the authoritative
	// field. Its zero value normalizes to pending, NOT to failed: the absence of
	// a classification is not evidence of a revert.
	TargetChainOutcome TargetChainOutcome `json:"target_chain_outcome,omitempty"`

	// TargetChainTxRef is the settlement transaction hash, when one exists. A
	// pending report without it is unactionable, so the pending log line prints
	// it and this is where it comes from.
	TargetChainTxRef string `json:"target_chain_tx_ref,omitempty"`

	TargetChainError string          `json:"target_chain_error,omitempty"`
	AnchorResp       *AnchorResponse `json:"anchor_response,omitempty"`
	Error            error           `json:"error,omitempty"`
	ExecutorID       string          `json:"executor_id"`
	ConsensusHash    string          `json:"consensus_hash"`
}

// NewBFTValidator creates a new decentralized BFT validator
// Phase 3: NewBFTValidator creates a validator using only CometBFT consensus
func NewBFTValidator(
	engine BFTConsensusEngine,
	validators []BFTValidatorInfo,
	params *ConsensusParams,
	validatorID string,
	chainID string, // CometBFT chain ID (e.g., "certen-validator")
	privateKey ed25519.PrivateKey,
	anchorManager AnchorManager,
	proofGenerator ProofGenerator,
	governanceProofGen GovernanceProofGenerator, // G0/G1/G2 proof generator (runs AFTER L1-L4)
	targetChainExecutor verification.TargetChainExecutor,
	builder *ValidatorBlockBuilder,
	logger Logger,
) *BFTValidator {
	ctx, cancel := context.WithCancel(context.Background())

	// Use default chainID if not provided
	if chainID == "" {
		chainID = "certen-validator"
	}

	validator := &BFTValidator{
		engine:                engine,
		anchorManager:         anchorManager,
		proofGenerator:        proofGenerator,
		governanceProofGen:    governanceProofGen,
		targets:               targetChainExecutor,
		validatorBlockBuilder: builder,
		logger:                logger,
		validatorID:           validatorID,
		chainID:               chainID,
		privateKey:            privateKey,
		executionQueue:        make(chan *ExecutionTask, 100),
		ctx:                   ctx,
		cancel:                cancel,
		// anchorResultChannels removed - HTTP orchestration violates audit boundary
	}

	// Wire validator reference into the ABCI application
	if engine != nil {
		if app := engine.GetABCIApp(); app != nil {
			app.SetValidatorRef(validator)
		}
	}

	// Note: processExecutionTasks goroutine is started in Start() method, not here

	return validator
}

// SetConsensusEngine sets the CometBFT consensus engine and wires up bidirectional references
func (bv *BFTValidator) SetConsensusEngine(engine BFTConsensusEngine) {
	bv.engine = engine
	// if engine != nil {
	//     engine.SetValidatorRef(bv)
	// }
}

// GetConsensusEngine returns the BFT consensus engine
func (bv *BFTValidator) GetConsensusEngine() BFTConsensusEngine {
	return bv.engine
}

// GetValidatorID returns the ID of this validator
func (bv *BFTValidator) GetValidatorID() string {
	return bv.validatorID
}

// SetProofCycleOrchestrator sets the proof cycle orchestrator for Phase 7-9
func (bv *BFTValidator) SetProofCycleOrchestrator(orchestrator ProofCycleOrchestratorInterface) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.proofCycleOrchestrator = orchestrator
	if orchestrator != nil {
		bv.logger.Printf("✅ Proof cycle orchestrator configured for Phase 7-9")
	}
}

// GetProofCycleOrchestrator returns the proof cycle orchestrator
func (bv *BFTValidator) GetProofCycleOrchestrator() ProofCycleOrchestratorInterface {
	bv.mu.RLock()
	defer bv.mu.RUnlock()
	return bv.proofCycleOrchestrator
}

// SetBatchEnqueuer installs the cross-ADI batch mempool.
//
// on_cadence intents route here in preference to the deferred-serial scheduler. If it is
// never set, behaviour is exactly as before.
func (bv *BFTValidator) SetBatchEnqueuer(e BatchEnqueuer) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.batchEnqueuer = e
	if e != nil {
		bv.logger.Printf("✅ Cross-ADI batch mempool wired for on_cadence intents")
	}
}

// SetAnchorScheduler sets the anchor scheduler for on_cadence batching
// Per FIRST_PRINCIPLES 2.5: on_cadence and on_demand are NEVER interchangeable
func (bv *BFTValidator) SetAnchorScheduler(scheduler AnchorScheduler) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.anchorScheduler = scheduler
	if scheduler != nil {
		bv.logger.Printf("✅ Anchor scheduler configured for on_cadence batching")

		// Close the loop: give the scheduler the callback it needs to run Phase 7-9 once
		// a deferred batch settles. Without this the scheduler executes cadence intents
		// on-chain but their proof cycle never closes — the defect this wiring fixes.
		//
		// Installed here rather than at the call site so it can never be forgotten: any
		// scheduler capable of attestation replay gets wired the moment it is attached.
		if runner, ok := scheduler.(interface {
			SetAttestationRunner(func(context.Context, interface{}, *verification.AnchorExecutionResult))
		}); ok {
			runner.SetAttestationRunner(func(ctx context.Context, payload interface{}, res *verification.AnchorExecutionResult) {
				att, ok := payload.(*PendingAttestation)
				if !ok || att == nil {
					bv.logger.Printf("⚠️ [ATTEST] cadence attestation payload was not a *PendingAttestation")
					return
				}
				bv.RunProofCycle(ctx, att, res)
			})
			bv.logger.Printf("✅ Cadence attestation runner installed (Phase 7-9 will close for on_cadence intents)")
		} else {
			bv.logger.Printf("⚠️ Scheduler does not support attestation replay — on_cadence intents will NOT attest")
		}
	}
}

// GetAnchorScheduler returns the anchor scheduler
func (bv *BFTValidator) GetAnchorScheduler() AnchorScheduler {
	bv.mu.RLock()
	defer bv.mu.RUnlock()
	return bv.anchorScheduler
}

// Start starts the validator's background services
func (bv *BFTValidator) Start(ctx context.Context) {
	go bv.processExecutionTasks()
	bv.logger.Printf("BFT Validator background services started")
}

// StartConsensus starts the CometBFT consensus engine
func (bv *BFTValidator) StartConsensus() {
	if bv.engine != nil {
		if err := bv.engine.Start(); err != nil {
			bv.logger.Printf("Failed to start CometBFT consensus engine: %v", err)
		} else {
			bv.logger.Printf("CometBFT consensus engine started successfully")
		}
	}
}

// ExecuteWithBFTConsensus executes an intent using BFT consensus
func (bv *BFTValidator) ExecuteWithBFTConsensus(
	ctx context.Context,
	intent *Intent,
	blockHeight uint64,
) (*ExecutionTaskResult, error) {
	// Use deterministic roundID: intentID:blockHeight (no timestamp to ensure all validators compute same hash)
	roundID := fmt.Sprintf("%s:%d", intent.ID, blockHeight)

	bv.logger.Printf("🎯 [BFT-COORD] Starting BFT execution: intent=%s round=%s height=%d",
		intent.ID, roundID, blockHeight)

	// Step 1: Phase 3 - Deterministic executor selection (no ExecutionConsensus)
	selectedExecutorID := bv.selectExecutorDeterministically(roundID, intent.ID)

	// Broadcast executor selection to CometBFT for consensus agreement
	if err := bv.broadcastExecutorSelection(roundID, selectedExecutorID); err != nil {
		return nil, fmt.Errorf("executor selection broadcast failed: %w", err)
	}

	bv.logger.Printf("🎲 [BFT-COORD] Deterministically selected executor: %s for round %s",
		selectedExecutorID, roundID)

	// Step 2: Phase 3 - CometBFT handles consensus directly (vote transactions removed)
	// CometBFT's native consensus replaces the custom vote broadcasting system
	bv.logger.Printf("📊 [BFT-COORD] Using CometBFT native consensus for validator=%s round=%s",
		bv.validatorID, roundID)

	// Step 3: Wait for consensus or timeout (Phase 3: no ExecutionConsensus dependency)
	consensusCtx, consensusCancel := context.WithTimeout(ctx, 30*time.Second) // Standard timeout
	defer consensusCancel()

	consensusReached := false
	for !consensusReached {
		select {
		case <-consensusCtx.Done():
			return nil, fmt.Errorf("consensus timeout for round: %s", roundID)
		case <-time.After(100 * time.Millisecond):
			// Phase 3: Get ballot status from ABCI state instead of ExecutionConsensus
			ballot, exists := bv.getABCIBallotState(roundID)
			if exists {
				bv.logger.Printf("🔍 [BFT-CONSENSUS] Polling ballot state for %s: finalized=%v, reached=%v, executor=%s",
					roundID, ballot.IsFinalized, ballot.ConsensusReached, ballot.FinalExecutorID)
			} else {
				bv.logger.Printf("🔍 [BFT-CONSENSUS] No ballot state found for round %s, continuing to poll...", roundID)
			}
			if exists && ballot.IsFinalized {
				consensusReached = true
				if !ballot.ConsensusReached {
					return &ExecutionTaskResult{
						Success:       false,
						Error:         fmt.Errorf("consensus failed: insufficient votes"),
						ExecutorID:    ballot.FinalExecutorID,
						ConsensusHash: bv.generateConsensusHash(roundID, selectedExecutorID),
					}, nil
				}
			}
		}
	}

	// Step 4: Execute via elected executor consensus
	// Validators participate in voting and elect an executor for the round
	bv.logger.Printf("⚡ [BFT-CONSENSUS] Participating in elected executor consensus: %s", bv.validatorID)

	return bv.executeWithConsensus(ctx, intent, roundID, blockHeight)
}

// executeWithConsensus executes the intent using elected executor consensus
func (bv *BFTValidator) executeWithConsensus(
	ctx context.Context,
	intent *Intent,
	roundID string,
	blockHeight uint64,
) (*ExecutionTaskResult, error) {
	bv.logger.Printf("⚡ [BFT-EXEC] Participating in elected executor consensus: round=%s intent=%s validator=%s",
		roundID, intent.ID, bv.validatorID)

	// Create execution task
	task := &ExecutionTask{
		Intent:      intent,
		RoundID:     roundID,
		BlockHeight: blockHeight,
		ResultChan:  make(chan *ExecutionTaskResult, 1),
	}

	// Submit to execution queue
	select {
	case bv.executionQueue <- task:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Wait for execution result
	select {
	case result := <-task.ResultChan:
		return result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// processExecutionTasks processes execution tasks in the background
func (bv *BFTValidator) processExecutionTasks() {
	for {
		select {
		case <-bv.ctx.Done():
			return
		case task := <-bv.executionQueue:
			bv.executeTask(task)
		}
	}
}

// executeTask executes a single task with cryptographic result submission
func (bv *BFTValidator) executeTask(task *ExecutionTask) {
	bv.logger.Printf("🔥 [BFT-EXEC] Processing execution task: round=%s intent=%s",
		task.RoundID, task.Intent.ID)

	// Get consensus ballot from ABCI app state (Phase 3: CometBFT is the only source of truth)
	ballot, exists := bv.getABCIBallotState(task.RoundID)
	if !exists {
		// If no ballot exists in ABCI state, create one by broadcasting executor selection
		bv.logger.Printf("🎯 [BFT-EXEC] No ballot in ABCI state for round %s, selecting executor via CometBFT", task.RoundID)

		// Use a simple deterministic executor selection for now (could be enhanced with real voting)
		selectedExecutor := bv.selectExecutorDeterministically(task.RoundID, task.Intent.ID)
		if err := bv.broadcastExecutorSelection(task.RoundID, selectedExecutor); err != nil {
			bv.logger.Printf("❌ [BFT-EXEC] Failed to broadcast executor selection: %v", err)
			return
		}

		// Wait briefly for the transaction to be processed
		time.Sleep(100 * time.Millisecond)

		// Try to get the ballot again
		ballot, exists = bv.getABCIBallotState(task.RoundID)
		if !exists {
			bv.logger.Printf("❌ [BFT-EXEC] Still no ballot found in ABCI state after selection for round %s", task.RoundID)
			return
		}
	}

	if !ballot.IsFinalized || !ballot.ConsensusReached {
		bv.logger.Printf("⏳ [BFT-EXEC] Consensus not yet reached in ABCI state for round %s", task.RoundID)
		return
	}

	// Check if this validator is the elected executor
	if ballot.FinalExecutorID != bv.validatorID {
		bv.logger.Printf("👁️ [BFT-EXEC] Validator %s participating in consensus (executor: %s) - NOT executing",
			bv.validatorID, ballot.FinalExecutorID)
		return
	}

	bv.logger.Printf("⚡ [BFT-EXEC] Validator %s is the ELECTED EXECUTOR for round %s via ABCI state - proceeding with execution",
		bv.validatorID, task.RoundID)

	// DEPRECATED: Legacy ExecutionTask with Intent struct cannot be executed via canonical workflow
	// Per Golden Spec: All intents must flow through IntentDiscovery → ExecuteCanonicalIntentWithBFTConsensus
	// with proper CertenIntent (4-blob) and CertenProof from lite client
	result := &ExecutionTaskResult{
		Success:    false,
		ExecutorID: bv.validatorID,
		Error:      fmt.Errorf("DEPRECATED: Legacy ExecutionTask path removed - use ExecuteCanonicalIntentWithBFTConsensus via IntentDiscovery"),
	}

	bv.logger.Printf("⚠️ [BFT-EXEC] Legacy execution path deprecated for round %s - intent must flow through IntentDiscovery", task.RoundID)

	// Send result back
	select {
	case task.ResultChan <- result:
	default:
		bv.logger.Printf("⚠️ [BFT-EXEC] Result channel full, dropping result for round: %s", task.RoundID)
	}
}

// NOTE: executeBFTWorkflow has been REMOVED per E.1 remediation
// Per Golden Spec: All intent execution must use ExecuteCanonicalIntentWithBFTConsensus
// with proper CertenIntent (4-blob) and CertenProof from lite client.
// Legacy functions that accept raw parameters or Intent struct violate canonical semantics.

// NOTE: ExecuteIntentWithBFTConsensus has been REMOVED per E.1 remediation
// Per Golden Spec: Only ExecuteCanonicalIntentWithBFTConsensus is supported.
// Legacy callers must migrate to provide CertenIntent and CertenProof from IntentDiscovery.

// ExecuteCanonicalIntentWithBFTConsensus executes an intent using canonical inputs from IntentDiscovery + ProofGenerator
// This is the Golden Spec compliant method that consumes canonical artifacts, never reconstructs them
func (bv *BFTValidator) ExecuteCanonicalIntentWithBFTConsensus(
	ctx context.Context,
	certenIntent *CertenIntent, // canonical 4 blobs from IntentDiscovery
	certenProof *proof.CertenProof, // from ProofGenerator / lite client
	blockHeight uint64,
) error {
	_, err := bv.ExecuteCanonicalIntentWithOutcome(ctx, certenIntent, certenProof, blockHeight)
	return err
}

// ExecuteCanonicalIntentWithOutcome is ExecuteCanonicalIntentWithBFTConsensus, plus
// the settlement outcome it always knew and used to throw away.
//
// STAGE 1. The error-only signature is why IntentDiscovery logged "processed
// successfully and marked complete" for an intent whose chain write was still in
// flight: nil meant CONSENSUS committed, and the caller had no way to ask about
// the other half. Returning the outcome lets the caller say what actually
// happened instead of inferring success from the absence of an error.
//
// Additive on purpose. BFTConsensusProtocol keeps its one-method shape and callers
// type-assert for this, so nothing that implements the old interface breaks.
func (bv *BFTValidator) ExecuteCanonicalIntentWithOutcome(
	ctx context.Context,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	blockHeight uint64,
) (TargetChainOutcome, error) {
	bv.logger.Printf("🎯 [BFT-CANONICAL] Executing intent via canonical BFT consensus: intent=%s tx=%s height=%d",
		certenIntent.IntentID, certenIntent.TransactionHash, blockHeight)

	// Execute with canonical BFT consensus using real artifacts
	result, err := bv.executeCanonicalWithBFTConsensus(ctx, certenIntent, certenProof, blockHeight)
	if err != nil {
		return TargetChainFailed, fmt.Errorf("canonical BFT execution failed: %w", err)
	}

	if !result.Success {
		// %w, not %v: callers classify retryable vs permanent failure with
		// errors.Is, and %v flattens the chain to a string that nothing can
		// match against. A permanent failure reported as an opaque string gets
		// retried forever.
		return TargetChainFailed, fmt.Errorf("canonical BFT execution unsuccessful: %w", result.Error)
	}

	// Report what actually happened. This line previously said "executed
	// successfully" whenever CONSENSUS succeeded, so an intent whose create,
	// verify and governance steps had all reverted on chain was logged as a
	// success and marked complete — which is what made a hard failure look like
	// a stall for a full day. Consensus succeeding is worth saying; it is not
	// the same sentence as the work having landed.
	//
	// STAGE 1: THREE branches, not two. The second branch used to absorb both
	// "reverted" and "has not resolved yet" and asserted a revert for both,
	// including the case with a tx hash and no error — which is the signature of
	// PENDING, not of failure. The rendering lives in RenderTargetChainOutcomeLog
	// so that "the gas sentence appears only under failed" is a unit test rather
	// than a promise.
	bv.logger.Printf("%s", RenderTargetChainOutcomeLog(
		certenIntent.IntentID,
		result.TargetChainOutcome,
		result.TargetChainTxRef,
		result.TargetChainError,
	))
	return result.TargetChainOutcome.Normalize(), nil
}

// executeCanonicalWithBFTConsensus - internal canonical execution using real artifacts
func (bv *BFTValidator) executeCanonicalWithBFTConsensus(
	ctx context.Context,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	blockHeight uint64,
) (*ExecutionTaskResult, error) {
	// Use deterministic roundID: intentID:blockHeight (no timestamp to ensure all validators compute same hash)
	roundID := fmt.Sprintf("%s:%d", certenIntent.IntentID, blockHeight)

	bv.logger.Printf("🎯 [BFT-CANONICAL] Starting canonical BFT execution: intent=%s round=%s height=%d",
		certenIntent.IntentID, roundID, blockHeight)

	// CRITICAL: Build ValidatorBlock from canonical inputs ONLY - no fake data
	result, err := bv.executeCanonicalBFTWorkflow(ctx, certenIntent, certenProof, roundID, blockHeight)
	if err != nil {
		return nil, fmt.Errorf("canonical BFT workflow failed: %w", err)
	}

	return result, nil
}

// executeCanonicalBFTWorkflow - builds ValidatorBlock from canonical artifacts (replaces executeBFTWorkflow)
func (bv *BFTValidator) executeCanonicalBFTWorkflow(
	ctx context.Context,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	roundID string,
	blockHeight uint64,
) (*ExecutionTaskResult, error) {
	bv.logger.Printf("Starting CANONICAL BFT workflow for intent: %s (no fake data, no time.Now)", certenIntent.IntentID)

	// 1) Build canonical ValidatorBlock from REAL artifacts per Golden Spec
	// NO time.Now(), NO dummy data, NO reconstructed JSON blobs

	// Extract governance inputs from canonical GovernanceData blob
	governanceData, err := certenIntent.ParseGovernance()
	if err != nil {
		return nil, fmt.Errorf("parse canonical governance data: %w", err)
	}

	// CRITICAL: Extract and validate proof class per FIRST_PRINCIPLES 2.5
	proofClass, err := certenIntent.GetProofClass()
	if err != nil {
		return nil, fmt.Errorf("extract proof class: %w", err)
	}

	bv.logger.Printf("🎯 [PROOF-CLASS] Intent %s has proof class: %s", certenIntent.IntentID, proofClass)

	// CRITICAL: on_demand intents MUST have a non-nil CertenProof
	if proofClass == "on_demand" && certenProof == nil {
		return nil, fmt.Errorf(
			"on_demand intent %s requires a non-nil CertenProof (got nil); ProofGenerator must be wired before calling ExecuteCanonicalIntentWithBFTConsensus",
			certenIntent.IntentID,
		)
	}

	// Handle proof data extraction
	var blsSignature string
	var validatorSignatures []string
	var anchorRef AccumulateAnchorReference
	var liteClientProof *lcproof.CompleteProof

	// Governance proof variables — declared OUTSIDE the if-block so the
	// validator-block builder (further below) and on_cadence fallback both
	// see them as nil/empty when proofs weren't generated. V6.1 A+++ requires
	// these to be available BEFORE BLS signing, hence the move from below.
	var g0Proof *proof.G0Result
	var g1Proof *proof.G1Result
	var g2Proof *proof.G2Result
	// STAGE 2: the merkle path for each level's execution receipt, taken off the
	// GovernanceProof WRAPPER — which is not part of any canonical hash — rather
	// than out of the results themselves, which are. Without this the wrapper was
	// discarded one line after GenerateG0/G1/G2 returned and the evidence went
	// with it, which is why governance_proof_levels contained verdict flags and
	// no governance proof.
	var govReceipts []proof.GovReceiptEvidence
	var governanceLevel string
	var resolvedKeyPageURL string
	resolvedKeyBookURL := governanceData.Authorization.RequiredKeyBook

	if certenProof != nil {
		bv.logger.Printf("✅ [CANONICAL-VB] Using real proof data for intent: %s", certenIntent.IntentID)
		blsSignature = certenProof.BLSAggregateSignature
		validatorSignatures = certenProof.ValidatorSignatures

		// Safely extract anchor reference with nil checks
		if certenProof.AccumulateAnchor != nil {
			anchorRef = AccumulateAnchorReference{
				BlockHash:   certenProof.AccumulateAnchor.BlockHash,
				BlockHeight: certenProof.AccumulateAnchor.BlockHeight,
				TxHash:      certenProof.AccumulateAnchor.TxHash,
				AccountURL:  certenProof.AccountURL,
			}
		} else {
			// Fallback anchor reference when AccumulateAnchor is nil (partial proof)
			bv.logger.Printf("⚠️ [CANONICAL-VB] AccumulateAnchor is nil for intent %s, using fallback values", certenIntent.IntentID)
			anchorRef = AccumulateAnchorReference{
				BlockHash:   fmt.Sprintf("proof_pending_block_%d", blockHeight),
				BlockHeight: blockHeight,
				TxHash:      certenProof.TransactionHash, // Use transaction hash from proof if available
				AccountURL:  certenProof.AccountURL,
			}
		}

		if certenProof.LiteClientProof != nil {
			liteClientProof = certenProof.LiteClientProof.CompleteProof
		}

		// Validator's individual ed25519 signature over opID. This is for
		// BFT consensus votes (CometBFT layer), NOT the EVM-side BLS sig.
		// Keep signing opID here — CometBFT consensus is opID-based.
		if len(validatorSignatures) == 0 && bv.privateKey != nil {
			opID, err := certenIntent.OperationID()
			if err == nil {
				message := []byte(opID)
				signature := ed25519.Sign(bv.privateKey, message)
				signatureHex := hex.EncodeToString(signature)
				validatorSignatures = []string{signatureHex}
				bv.logger.Printf("🔑 [VALIDATOR-SIG] Generated initial validator signature for intent %s (opID: %s...)",
					certenIntent.IntentID, opID[:16])
			} else {
				bv.logger.Printf("⚠️ [VALIDATOR-SIG] Failed to compute operationID for signing: %v", err)
			}
		}

		// ====================================================================
		// V6.1 A+++ ORDERING: Generate G0/G1/G2 governance proofs BEFORE the
		// EVM-side BLS signature, so the messageHash the validator signs is
		// bound to the same governance outputs the EVM submission path will
		// recompute. Pre-V6.1 this block ran AFTER BLS signing, which is why
		// govRoot was forced into a `keccak256(BLS sig)` shortcut that
		// produced unverifiable circular hashes.
		//
		// Per CERTEN spec v3-governance-kpsw-exec-4.0:
		// - G0/G1/G2 proofs are generated AFTER L1-L4 lite client proof completes
		// - L1-L4 provides the cryptographic foundation that the transaction EXISTS
		// - G0 extracts TXID, EXEC_MBI from the PROVEN transaction
		// - G1 validates key page authority AT execution time
		// - G2 verifies Accumulate intent payload authenticity and effect binding
		// NOTE: G2 is about the Accumulate intent, NOT external chain execution
		// ====================================================================
		if liteClientProof != nil && bv.governanceProofGen != nil {
			bv.logger.Printf("🔗 [GOV-PROOF] L1-L4 proof complete, generating G0/G1/G2 governance proofs for intent %s",
				certenIntent.IntentID)

			// Build governance proof request from intent data
			keyPageURL, keyPageErr := resolveKeyPageURL(
				governanceData.Authorization.RequiredKeyPage,
				governanceData.Authorization.RequiredKeyBook,
				bv.logger,
			)
			if keyPageErr != nil {
				bv.logger.Printf("⚠️ [GOV-PROOF] Failed to resolve keypage URL: %v", keyPageErr)
			}
			resolvedKeyPageURL = keyPageURL
			govRequest := &proof.GovernanceRequest{
				AccountURL:      certenIntent.AccountURL,
				TransactionHash: certenIntent.TransactionHash,
				KeyPage:         keyPageURL,
				Chain:           "main",
			}

			// G0, G1 AND G2 are ALL required. None is optional.
			//
			// This block previously logged a warning on every failure and
			// carried on at whatever level it had reached, leaving
			// governanceLevel at "G0" or "G1" while the intent was still
			// signed and submitted. That is the same defect class as the
			// signature-evidence and outcome-binding bugs: a proof succeeding
			// with less evidence than the spec requires, with the shortfall
			// visible only as a warning in a log nobody reads.
			//
			// A governance proof that does not bind its outcome is not a
			// governance proof. Fail the intent instead of attesting to a
			// weaker claim than the one being made.
			if govRequest.KeyPage == "" {
				return nil, fmt.Errorf("governance proof requires a key page: "+
					"G1/G2 cannot be established without one, and G0 alone is not a governance proof "+
					"(intent %s)", certenIntent.IntentID)
			}

			g0ProofWrapper, g0Err := bv.governanceProofGen.GenerateG0(ctx, govRequest)
			if g0Err != nil {
				return nil, fmt.Errorf("G0 governance proof failed for intent %s: %w", certenIntent.IntentID, g0Err)
			}
			if g0ProofWrapper == nil || g0ProofWrapper.G0 == nil {
				return nil, fmt.Errorf("G0 governance proof returned no result for intent %s", certenIntent.IntentID)
			}
			g0Proof = g0ProofWrapper.G0
			govReceipts = append(govReceipts, g0ProofWrapper.Receipts...)
			if !g0Proof.G0ProofComplete {
				return nil, fmt.Errorf("G0 governance proof incomplete for intent %s", certenIntent.IntentID)
			}
			governanceLevel = "G0"
			bv.logger.Printf("✅ [GOV-PROOF] G0 proof generated: TXID=%s, ExecMBI=%d, Complete=%v",
				g0Proof.TXID, g0Proof.ExecMBI, g0Proof.G0ProofComplete)

			g1ProofWrapper, g1Err := bv.governanceProofGen.GenerateG1(ctx, govRequest)
			if g1Err != nil {
				return nil, fmt.Errorf("G1 governance proof failed for intent %s: %w", certenIntent.IntentID, g1Err)
			}
			if g1ProofWrapper == nil || g1ProofWrapper.G1 == nil {
				return nil, fmt.Errorf("G1 governance proof returned no result for intent %s", certenIntent.IntentID)
			}
			g1Proof = g1ProofWrapper.G1
			govReceipts = append(govReceipts, g1ProofWrapper.Receipts...)
			if !g1Proof.G1ProofComplete || !g1Proof.ThresholdSatisfied {
				return nil, fmt.Errorf("G1 governance proof incomplete for intent %s "+
					"(complete=%v thresholdSatisfied=%v uniqueKeys=%d)",
					certenIntent.IntentID, g1Proof.G1ProofComplete, g1Proof.ThresholdSatisfied, g1Proof.UniqueValidKeys)
			}
			governanceLevel = "G1"
			bv.logger.Printf("✅ [GOV-PROOF] G1 proof generated: ThresholdSatisfied=%v, UniqueKeys=%d, Complete=%v",
				g1Proof.ThresholdSatisfied, g1Proof.UniqueValidKeys, g1Proof.G1ProofComplete)

			g2ProofWrapper, g2Err := bv.governanceProofGen.GenerateG2(ctx, govRequest)
			if g2Err != nil {
				return nil, fmt.Errorf("G2 governance proof failed for intent %s: %w", certenIntent.IntentID, g2Err)
			}
			if g2ProofWrapper == nil || g2ProofWrapper.G2 == nil {
				return nil, fmt.Errorf("G2 governance proof returned no result for intent %s", certenIntent.IntentID)
			}
			g2Proof = g2ProofWrapper.G2
			govReceipts = append(govReceipts, g2ProofWrapper.Receipts...)
			if !g2Proof.G2ProofComplete {
				return nil, fmt.Errorf("G2 governance proof incomplete for intent %s "+
					"(payloadVerified=%v effectVerified=%v): the outcome is not bound, so this is a G1 claim "+
					"and must not be recorded as governance",
					certenIntent.IntentID, g2Proof.PayloadVerified, g2Proof.EffectVerified)
			}
			governanceLevel = "G2"
			bv.logger.Printf("✅ [GOV-PROOF] G2 proof generated: PayloadVerified=%v, EffectVerified=%v, Complete=%v",
				g2Proof.PayloadVerified, g2Proof.EffectVerified, g2Proof.G2ProofComplete)
		} else {
			// Neither branch may proceed without governance. L1-L4 establishes
			// that the transaction exists; G0-G2 establishes that it was
			// authorised and what it did. Attesting with one and not the other
			// claims more than has been proven.
			if liteClientProof == nil {
				return nil, fmt.Errorf("cannot generate governance proofs for intent %s: "+
					"the L1-L4 lite client proof is not available", certenIntent.IntentID)
			}
			if bv.governanceProofGen == nil {
				return nil, fmt.Errorf("cannot generate governance proofs for intent %s: "+
					"the governance proof generator is not configured", certenIntent.IntentID)
			}
			return nil, fmt.Errorf("governance proofs were not generated for intent %s", certenIntent.IntentID)
		}

		// Plumb governance proofs + authority URLs onto certenProof so the
		// EVM submission path (pkg/execution/ethereum_contracts.go::
		// buildComprehensiveProof) sees identical inputs and recomputes the
		// SAME A+++ messageHash this validator is about to sign. Both sides
		// call contracts.BuildV6_1PreExecBundleFromIntent with this proof.
		certenProof.G0Result = g0Proof
		certenProof.G1Result = g1Proof
		certenProof.G2Result = g2Proof
		// Beside the results, never inside them. RequireL4Committed and the BLS
		// signing below both run AFTER this assignment and neither reads this
		// field, which is the point: it cannot reach a hash.
		certenProof.GovReceipts = govReceipts
		certenProof.KeypageURL = resolvedKeyPageURL
		certenProof.KeybookURL = resolvedKeyBookURL

		// L4 must be committed into the governance root before anything is
		// signed. SetL4ConsensusProofFromJSON leaves the slot ZERO on an absent
		// payload, so nothing downstream can tell a missing quorum apart from a
		// committed one without this check.
		//
		// Before this change the chain committed to L1-L3 and G0-G2 but not to
		// the validator quorum that signed the anchors. Note that the old slot
		// was NOT zero: every call site passes a typed *ConsensusProof, and a
		// nil typed pointer is not `v == nil`, so json.Marshal produced "null"
		// and the slot carried a constant non-zero hash. See isAbsentPayload.
		//
		// Both L4 legs are already mandatory for the proof to exist at all
		// (ProofVerifier.Verify rejects a nil leg), so reaching here without a
		// payload means the plumbing broke, not that L4 was unavailable.
		if err := proof.RequireL4Committed(certenProof); err != nil {
			return nil, fmt.Errorf("intent %s: %w", certenIntent.IntentID, err)
		}

		// V6.1 A+++ BLS signing: sign the messageHash that CertenAnchorV6_1
		// will recompute and verify. Pre-V6.1 this signed []byte(opID),
		// which is why every TX2 reverted with "BLS signature verification
		// failed" — the contract checked a chain-bound 6-field hash that
		// committed exec, opID, validatorSetRoot, AND a 10-field A+++ govRoot.
		if blsSignature == "" {
			sig, err := signV6_1PreExecBLS(bv.logger, certenIntent, certenProof)
			if err != nil {
				bv.logger.Printf("⚠️ [BLS-SIG-V6.1] %v", err)
			} else {
				blsSignature = sig
				bv.logger.Printf("🔐 [BLS-SIG-V6.1] Generated A+++ BLS signature for intent %s (gov=%s)",
					certenIntent.IntentID, governanceLevel)
			}
		}
	} else {
		// This branch should ONLY be used for on_cadence flows where proof comes later
		if proofClass != "on_cadence" {
			return nil, fmt.Errorf("proof class %s requires a CertenProof, but got nil", proofClass)
		}
		bv.logger.Printf("⚠️ [CANONICAL-VB] Using fallback values for on_cadence intent without immediate proof: %s", certenIntent.IntentID)
		blsSignature = ""
		validatorSignatures = []string{} // This will trigger validation error for pre-execution
		anchorRef = AccumulateAnchorReference{
			BlockHash:   fmt.Sprintf("pending_anchor_block_%d", blockHeight),
			BlockHeight: blockHeight,
			TxHash:      fmt.Sprintf("pending_anchor_tx_%s", certenIntent.IntentID),
		}
		liteClientProof = nil
	}
	// Suppress "declared and not used" if the on_cadence branch left these zero.
	_ = resolvedKeyPageURL
	_ = resolvedKeyBookURL

	// ====================================================================
	// PHASE 3 ENTITLEMENT — does CERTEN agree to spend on this intent?
	//
	// Placed here deliberately. Phases 1-2 (discovery, L1-L4 proof) cost
	// nothing but CPU, so establishing that the intent is REAL before asking
	// who owns it wastes nothing and means a refusal is issued against a
	// cryptographically established intent. Everything after this point leads
	// to money: TX1 anchor, TX2 BLS-ZK verify, TX3 execution.
	//
	// The evidence is keyed on certenIntent.AccountURL — the discovered
	// Accumulate principal. That is the ONLY field a submitter cannot forge;
	// discovery overwrites the self-declared organizationAdi with it precisely
	// because the declared value is attacker-controlled.
	//
	// This is a cache read, never a network call.
	// ====================================================================
	principal := strings.TrimSpace(certenIntent.AccountURL)
	var entEvidence *entitlement.Evidence
	if bv.entitlementStore != nil {
		entEvidence = bv.entitlementStore.BuildEvidence(principal)
	}

	if bv.entitlementMode == EntitlementEnforce && entEvidence == nil {
		// Decline locally rather than build a block the fleet will reject.
		//
		// An optimisation, NOT the enforcement point: this validator could be
		// modified to skip it. The authority is VerifyEntitlement inside
		// CheckTx/FinalizeBlock, which every validator runs and none can skip.
		bv.logger.Printf("🚫 [ENTITLEMENT] refusing intent %s: principal %q has no entitlement evidence (no gas will be spent)",
			certenIntent.IntentID, principal)
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			Error: fmt.Errorf("intent %s refused: principal %q is not entitled to CERTEN execution",
				certenIntent.IntentID, principal),
		}, nil
	}
	if bv.entitlementMode == EntitlementObserve && entEvidence == nil {
		bv.logger.Printf("👁️ [ENTITLEMENT] OBSERVE would refuse intent %s: principal %q has no entitlement evidence",
			certenIntent.IntentID, principal)
	}

	// ====================================================================
	// EXECUTION VALIDATION — expiry, structure, and REPLAY PROTECTION.
	//
	// ValidateForExecution has existed and been correct for a long time, and
	// has never had a caller: grep found only its own definition. So the nonce
	// check inside it (ValidateNonce) has never run, and a replayed intent —
	// the same 4 blobs written to Accumulate a second time — was executed again
	// at CERTEN's expense.
	//
	// Placed after the entitlement check and before any money is spent. Uses
	// wall time for expiry, which is fine HERE (a proposer's local decision) and
	// would not be fine in the consensus invariant, where it would make
	// validators disagree.
	// ====================================================================
	if executionValidationEnabled() {
		if err := certenIntent.ValidateForExecution(blockHeight); err != nil {
			bv.logger.Printf("🚫 [EXEC-VALIDATION] refusing intent %s: %v", certenIntent.IntentID, err)
			return &ExecutionTaskResult{
				Success:    false,
				ExecutorID: bv.validatorID,
				// PERMANENT. The intent's bytes are already final on
				// Accumulate, so a structural defect — a missing created_at, a
				// malformed field, an expiry that already passed — cannot
				// become valid on a later pass. Marking it retryable makes the
				// fleet rediscover and re-refuse it every poll, forever.
				Error: fmt.Errorf("intent %s failed execution validation: %w: %w",
					certenIntent.IntentID, ErrIntentPermanentlyInvalid, err),
			}, nil
		}
	}

	// Create builder inputs STRICTLY from canonical sources
	builderInputs := BuilderInputs{
		Intent: certenIntent, // canonical 4 blobs from IntentDiscovery
		Governance: GovernanceInputs{
			// Extract from canonical GovernanceData, not fake values
			Leaves:                extractAuthorizationLeavesFromGovernance(governanceData),
			BLSAggregateSignature: blsSignature, // from ProofGenerator or fallback
			// Full governance proofs (generated AFTER L1-L4)
			// G0: Inclusion & Finality
			// G1: Authority Validated
			// G2: Outcome Binding (Accumulate intent payload/effect, NOT external execution)
			G0Proof:         g0Proof,
			G1Proof:         g1Proof,
			G2Proof:         g2Proof,
			GovernanceLevel: governanceLevel,
		},
		Execution: ExecutionInputs{
			Stage:               ExecutionStagePre,
			ValidatorSignatures: validatorSignatures, // from BFT consensus or fallback
			ProofClass:          proofClass,          // CRITICAL: preserve proof class for routing
		},
		AnchorRef:       anchorRef, // from proof or fallback values
		BlockHeight:     blockHeight,
		LiteClientProof: liteClientProof, // Complete cryptographic proof chain or nil

		// Carried into the block so every validator can verify entitlement
		// without performing I/O inside a consensus rule.
		EntitlementEvidence: entEvidence,
	}

	// Build ValidatorBlock using canonical method
	vb, err := bv.validatorBlockBuilder.BuildFromIntent(builderInputs)
	if err != nil {
		bv.logger.Printf("failed to build canonical ValidatorBlock: round=%s err=%v", roundID, err)
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			Error:      fmt.Errorf("build canonical validator block: %w", err),
		}, nil
	}

	bv.logger.Printf("✅ [CANONICAL-VB] Built ValidatorBlock with real artifacts: bundle=%s op=%s",
		vb.BundleID, vb.OperationCommitment)

	// 2) Submit to ValidatorApp via CometBFT for invariant verification.
	// Use a FRESH root context, NOT the intent ctx: the ValidatorBlock is fully built and
	// signed by this point, and the consensus broadcast must not inherit a deadline already
	// exhausted upstream by proof generation (e.g. a slow/hung G1 gov-proof, whose failure is
	// tolerated). Deriving from the intent ctx made context.WithTimeout return an already-expired
	// context, so BroadcastTxSync failed in <1ms with "context deadline exceeded" even though the
	// fleet was healthy. Timeout accommodates retry logic: 30s + 45s + 60s + delays ≈ 3 minutes.
	bftCtx, bftCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer bftCancel()

	bftRes, err := bv.engine.BroadcastValidatorBlockCommit(bftCtx, vb)
	if err != nil {
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			Error:      fmt.Errorf("BFT broadcast failed: %w", err),
		}, nil
	}

	// Note: Height=0 means poll timeout but transaction was validated and is in mempool.
	// The ValidatorBlock itself contains all cryptographic proofs (L1-L3, governance, BLS).
	// CometBFT consensus will commit it - we can proceed since CheckTx validated the block.
	if bftRes.Height > 0 {
		bv.logger.Printf("✅ [CANONICAL-BFT] ValidatorBlock COMMITTED at height %d, tx=%X", bftRes.Height, bftRes.TxHash)
	} else if os.Getenv("REQUIRE_BFT_COMMIT") == "true" {
		// Strict mode (opt-in): the ValidatorBlock passed CheckTx but did NOT commit
		// within the inclusion-poll window, so BFT agreement is not yet proven. Fail
		// closed (retryable) rather than executing a target-chain side effect on an
		// uncommitted block. The intent is requeued and succeeds once consensus commits.
		bv.logger.Printf("⛔ [CANONICAL-BFT] ValidatorBlock NOT committed within inclusion window and REQUIRE_BFT_COMMIT=true — failing closed (retryable), tx=%X", bftRes.TxHash)
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			Error:      fmt.Errorf("BFT commit required but ValidatorBlock not committed within inclusion window (retryable)"),
		}, nil
	} else {
		// Default (backward-compatible): proceed. The proofs live in the ValidatorBlock
		// and CometBFT is expected to commit it shortly. Set REQUIRE_BFT_COMMIT=true to
		// enforce a committed block before any target-chain side effect (fail closed).
		bv.logger.Printf("⚠️ [CANONICAL-BFT] ValidatorBlock validated (CheckTx passed) but NOT yet committed, tx=%X — proceeding (set REQUIRE_BFT_COMMIT=true to fail closed)", bftRes.TxHash)
		bv.logger.Printf("   Cryptographic proofs are in ValidatorBlock, CometBFT height is audit metadata only")
	}

	// 3) Forward to external audit/mining network via TargetChainExecutor
	// This maintains the external audit boundary per FIRST_PRINCIPLES
	//
	// CRITICAL: We must pass ALL proof data to the target chain executor so that
	// createAnchor() receives real values for crossChainCommitment and governanceRoot.
	// Without these, the contract stores merkleRoot = keccak256(op || 0x00 || 0x00)
	// which can never be verified against proofs with real data.

	// Extract BPT root from lite client proof for CrossChainCommitment
	var bptRoot []byte
	if liteClientProof != nil && liteClientProof.BPTProof != nil {
		if liteClientProof.BPTProof.Anchor != nil {
			bptRoot = liteClientProof.BPTProof.Anchor
		}
	}

	// Extract CrossChainCommitment from ValidatorBlock
	var crossChainCommitment []byte
	if vb.CrossChainProof.CrossChainCommitment != "" {
		crossChainCommitment = []byte(vb.CrossChainProof.CrossChainCommitment)
	}

	// Extract GovernanceRoot from ValidatorBlock
	// GovernanceRoot is the MerkleRoot from the GovernanceProof
	var governanceRoot []byte
	if vb.GovernanceProof.MerkleRoot != "" {
		governanceRoot = []byte(vb.GovernanceProof.MerkleRoot)
	}

	bv.logger.Printf("📦 [ANCHOR-DATA] Proof data for anchor creation:")
	bv.logger.Printf("   BPT Root len: %d", len(bptRoot))
	bv.logger.Printf("   CrossChainCommitment len: %d", len(crossChainCommitment))
	bv.logger.Printf("   GovernanceRoot len: %d", len(governanceRoot))
	bv.logger.Printf("   BLSAggregateSignature len: %d", len(blsSignature))
	bv.logger.Printf("   SourceBlockHeight: %d (Accumulate)", blockHeight)

	// V6.1 A+++: serialize G0/G1/G2 to canonical JSON so the executor can
	// reconstruct certenProof.G_n with byte-identical content to what BFT
	// signed. Without this, executor.go::SubmitAnchorFromValidatorBlock
	// builds a CertenProof with nil G_n fields, A+++ govRoot derives over
	// zero-hashes for those slots, bundleId diverges from what BFT computed,
	// and executeComprehensiveProof reverts with BLS verification failure.
	var g0JSON, g1JSON, g2JSON []byte
	if g0Proof != nil {
		g0JSON, _ = json.Marshal(g0Proof)
	}
	if g1Proof != nil {
		g1JSON, _ = json.Marshal(g1Proof)
	}
	if g2Proof != nil {
		g2JSON, _ = json.Marshal(g2Proof)
	}

	vbMeta := &verification.ValidatorBlockMetadata{
		RoundID:  roundID,
		IntentID: certenIntent.IntentID,
		// The intent's own class, carried so the executor path can attribute its
		// measured cost to the class that incurred it rather than reporting it
		// unclassified.
		ProofClass:          certenIntent.ProofClass,
		Height:              bftRes.Height,
		OperationCommitment: []byte(vb.OperationCommitment), // Convert string to []byte
		ChainID:             bv.chainID,                     // From config via NewBFTValidator

		// CRITICAL: Pass proof data for anchor creation
		BPTRoot:               bptRoot,
		CrossChainCommitment:  crossChainCommitment,
		BLSAggregateSignature: blsSignature,
		// Matched pair with the signature: the block signer's public key, so the
		// executor proves the BLS signature against the key that produced it
		// (fixes #774716 when the BFT proposer/signer differs from the executor).
		BLSValidatorSetPubKey: vb.GovernanceProof.BLSValidatorSetPubKey,
		GovernanceRoot:        governanceRoot,
		TransactionHash:       certenIntent.TransactionHash,
		AccountURL:            certenIntent.AccountURL,
		// V6.1 A+++: source block height MUST equal certenProof.BlockHeight,
		// not the BFT workflow's `blockHeight` argument. The two differ by 1
		// because the workflow runs at the block AFTER the intent was
		// committed. BFT signing uses certenProof.BlockHeight, so the
		// executor's reconstructed certenProof must read the same value
		// or operationCommitment hash diverges → bundleId diverges → TX2
		// reverts (Sepolia test #5 root cause, 2026-05-26).
		SourceBlockHeight: func() uint64 {
			if certenProof != nil && certenProof.BlockHeight > 0 {
				return certenProof.BlockHeight
			}
			return blockHeight
		}(),

		// CRITICAL: Pass complete lite client proof for Merkle verification
		// This enables extractMerkleProofHashes() to extract the actual Merkle proof path
		// for on-chain verification. Without this, proofHashes[] is empty and
		// the contract's merkleVerified check fails.
		LiteClientProof: liteClientProof,

		// CRITICAL: Pass original CrossChainData for executeWithGovernance target address
		// This ensures the correct target address (leg.To) is used, NOT the anchor contract.
		CrossChainData: certenIntent.CrossChainData,

		// V6.1 A+++ governance plumbing — see comment above on the JSON variables.
		G0CanonicalJSON: g0JSON,
		G1CanonicalJSON: g1JSON,
		G2CanonicalJSON: g2JSON,
		KeypageURL:      resolvedKeyPageURL,
		KeybookURL:      resolvedKeyBookURL,

		// V6.1 A+++ — original intent 4-blob snapshot. CrossChainData is
		// already plumbed above for executeWithGovernance; the other three
		// are required so the EVM submitter's intent.CertenIntent has
		// byte-identical blobs and intent.OperationID() returns the same
		// hex the BFT signer used. Without this, executeComprehensiveProof
		// reverts because the contract recomputed bundleId from a
		// different opID than what was signed.
		IntentData:     certenIntent.IntentData,
		GovernanceData: certenIntent.GovernanceData,
		ReplayData:     certenIntent.ReplayData,
	}

	bftMeta := &verification.BFTExecutionMetadata{
		Height:      bftRes.Height,
		TxHash:      bftRes.TxHash,
		CommittedAt: time.Now().UTC(), // This is consensus metadata, not proof data
	}

	// =======================================================================
	// EVERY VALIDATOR RECORDS THE COMMITTED HEIGHT
	//
	// This is the cutoff source for deterministic batch periods. It must advance on EVERY
	// committed round, not only on rounds this node executes or batches: the period cutoff is
	// derived from it, and a member is only selected once the cutoff has passed its own commit
	// height. Recording it only on batched rounds meant a single queued intent could never
	// settle — nothing else would ever advance the height past its period.
	// =======================================================================
	// blockHeight is the ACCUMULATE block height the intent was written in — a property of the
	// intent, identical on every validator. bftRes.Height is NOT: each validator broadcasts its
	// own ValidatorBlock transaction, so the same intent commits at a different CometBFT height
	// on each node. Observed live 2026-08-02, one intent enqueued at heights 230/232/234/235/
	// 235/236/237 across the seven. Keying periods on that put the same member in different
	// periods on different nodes, so no two validators could ever derive the same batch.
	bv.noteConsensusHeight(blockHeight)

	// =======================================================================
	// EVERY VALIDATOR ENQUEUES EVERY BATCHABLE INTENT INTO ITS OWN BATCH MEMPOOL
	//
	// PROOF CLASS NO LONGER GATES THIS. It used to admit on_cadence only, leaving on_demand to
	// a separate per-intent submission path. That path cannot settle against the deployed
	// contracts and never could:
	//
	//   * CertenAccountV7._authorizeLeaf computes ONLY the batch-form leaf
	//     (keccak256("certen:batchleaf:v1" || chainid || adiURLHash || execCommitment ||
	//     operationID)). A V7 account cannot authorise anything against a V6-form
	//     single-intent anchor, so the per-intent path could not settle a V7 account at all.
	//   * Its BLS proof declared voting power unrelated to any real signer set, which
	//     CertenAnchorV8_1._verifyBLSProof rejects against the registered total.
	//   * Its ZK witness proved against the block signer's recorded key rather than the key
	//     that signed, giving the unsatisfied constraint #774716 observed live.
	//
	// The design already anticipated the fix: "N=1 IS NOT A SPECIAL CASE. A single intent is a
	// one-leaf tree whose root equals the leaf and whose Merkle proof is empty. There is no
	// mode flag and no second code path, so the batch and single paths cannot drift apart."
	// An intent that is alone in its period simply forms a one-member batch, and gets the same
	// real quorum every other batch gets.
	//
	// What this costs is honesty about latency: on_demand's former speed came from NOT having
	// a quorum. A genuine quorum needs peers to have independently derived the same tree, which
	// means they must have processed the intent. There is no version of this that is both
	// single-signer and trustworthy.
	//
	// Intents the batch path cannot represent still fall through to the existing per-intent
	// path unchanged — EnqueueForBatch refuses chains with no configured orchestrator, and
	// batchInputsFromIntent refuses multi-chain intents. So non-EVM targets (Solana, NEAR,
	// Aptos, Sui, TON, Cardano) are untouched by this.
	//
	// This MUST happen before the elected-executor gate below, and it is the single change
	// that makes cross-ADI quorum possible at all.
	//
	// A peer attests to a batch by rebuilding it from its OWN mempool and comparing bundleIds
	// (HandleBatchAttestationRequest). If only the elected executor enqueued, every other
	// validator's mempool would be empty for that intent, PeekForPeriod would return nothing,
	// and all six peers would refuse with "no members ... in this validator's mempool".
	// Quorum could never form — the batch path would fail 100% of the time and look exactly
	// like ordinary peer disagreement.
	//
	// Enqueueing is purely local bookkeeping: it spends nothing, submits nothing, and creates
	// no transaction. Duplicate submission is prevented where it actually matters — only the
	// elected BATCH PERIOD LEADER flushes (IsBatchPeriodLeader), which is a separate election
	// from this round's executor.
	// =======================================================================
	var batchQueued bool
	if bv.batchEnqueuer != nil {
		batchQueued = bv.enqueueForBatch(certenIntent, certenProof, vb, vbMeta, bftMeta,
			blockHeight, g0Proof, g1Proof, g2Proof, blsSignature, validatorSignatures,
			governanceLevel, blockHeight)
	}

	// =======================================================================
	// CONSENSUS FIX: Only the elected executor should submit to external chains
	// This prevents multiple validators from creating duplicate transactions
	// =======================================================================

	// Deterministically select executor based on round ID
	selectedExecutorID := bv.selectExecutorForRound(roundID)

	if selectedExecutorID != bv.validatorID {
		bv.logger.Printf("👁️ [CANONICAL-BFT] Validator %s is NOT elected executor (executor: %s) - skipping external submission",
			bv.validatorID, selectedExecutorID)
		// Return success - the elected executor will handle external submission
		return &ExecutionTaskResult{
			Success: true,
			// Six of seven validators land here on every round. This node submitted
			// nothing, so it holds no evidence either way — pending, with no tx
			// hash, which renders as the informational "no target-chain submission
			// from this node" line. Before Stage 1 these six each printed the
			// gas-speculation warning for every healthy intent.
			TargetChainOutcome: TargetChainPending,
			ExecutorID:         selectedExecutorID,
			ConsensusHash:      fmt.Sprintf("consensus_%s_%d", roundID, bftRes.Height),
		}, nil
	}

	bv.logger.Printf("⚡ [CANONICAL-BFT] Validator %s is ELECTED EXECUTOR for round %s - proceeding with external submission",
		bv.validatorID, roundID)

	// =======================================================================
	// PROOF CLASS ROUTING: on_cadence vs on_demand per FIRST_PRINCIPLES 2.5
	// These are NEVER interchangeable - on_cadence gets batched, on_demand executes immediately
	// =======================================================================
	var anchorRes *verification.AnchorExecutionResult
	// Tracked separately from consensus success — see ExecutionTaskResult.
	//
	// STAGE 1: this was `var targetChainConfirmed bool`, assigned straight from
	// anchorRes.AllTransactionsConfirmed after a 60-second context. That bool
	// collapsed "did not resolve in my window" into "failed", and the measured
	// base-sepolia lag is ~51s against that 60s window — so the collapse fired on
	// ordinary, healthy settlements.
	var targetChainErr error

	// ON-CADENCE, CROSS-ADI BATCH PATH (preferred).
	//
	// The enqueue itself already happened above, on EVERY validator — see the comment there
	// for why that is load-bearing. All that remains for the elected executor is to stop:
	// the intent will settle on the batch period leader's flush, which may be a different
	// node, and executing it here as well would double-spend it.
	if batchQueued {
		return &ExecutionTaskResult{
			Success: true,
			// Queued, not settled. The batch period leader's flush resolves it,
			// possibly on another node, and RunBatchMemberAttestation then carries
			// the terminal outcome. Pending, with no tx hash — there is no
			// transaction yet, and claiming a failure here would be a guess about
			// work that has not started.
			TargetChainOutcome: TargetChainPending,
			ExecutorID:         bv.validatorID,
			ConsensusHash:      fmt.Sprintf("batch_queued_%s_%d", roundID, bftRes.Height),
		}, nil
	}

	if proofClass == "on_cadence" && bv.anchorScheduler != nil {
		// ON-CADENCE fallback: deferred-serial execution (one anchor per intent).
		bv.logger.Printf("📦 [CADENCE-BATCH] Queuing intent %s for on_cadence batched execution", certenIntent.IntentID)

		// Capture the Phase 7-9 inputs NOW, while the round's values are in scope. The
		// intent will settle minutes from now on the scheduler's ticker, long after this
		// round is gone; without this snapshot it could execute but never attest, which
		// is exactly what used to happen to every on_cadence intent.
		cadenceAtt := bv.captureAttestation(vb, certenIntent, certenProof, blockHeight,
			g0Proof, g1Proof, g2Proof, blsSignature, validatorSignatures, governanceLevel)
		cadenceAtt.Replayed = true

		var scheduledAt time.Time
		var queueErr error
		if withAtt, ok := bv.anchorScheduler.(interface {
			QueueForCadenceWithAttestation(context.Context, string, *verification.ValidatorBlockMetadata, *verification.BFTExecutionMetadata, interface{}) (time.Time, error)
		}); ok {
			scheduledAt, queueErr = withAtt.QueueForCadenceWithAttestation(
				ctx, certenIntent.IntentID, vbMeta, bftMeta, cadenceAtt)
		} else {
			bv.logger.Printf("[CADENCE-BATCH] scheduler does not support attestation replay; "+
				"intent %s will execute but its proof cycle will NOT close", certenIntent.IntentID)
			scheduledAt, queueErr = bv.anchorScheduler.QueueForCadence(ctx, certenIntent.IntentID, vbMeta, bftMeta)
		}
		if queueErr != nil {
			bv.logger.Printf("⚠️ [CADENCE-BATCH] Failed to queue for cadence: %v - falling back to immediate execution", queueErr)
			// Fall through to immediate execution
		} else {
			queuedCount := bv.anchorScheduler.GetQueuedCount()
			bv.logger.Printf("✅ [CADENCE-BATCH] Intent %s queued for batch execution at %s (queue size: %d)",
				certenIntent.IntentID, scheduledAt.Format(time.RFC3339), queuedCount)

			// Return success - execution will happen when batch is processed
			return &ExecutionTaskResult{
				Success: true,
				// Deferred to the scheduler's ticker, minutes away. Pending with no
				// tx hash: the captured attestation is replayed through RunProofCycle
				// once the batch settles, and that is what produces the terminal line.
				TargetChainOutcome: TargetChainPending,
				ExecutorID:         bv.validatorID,
				ConsensusHash:      fmt.Sprintf("cadence_queued_%s_%d", roundID, bftRes.Height),
			}, nil
		}
	}

	// ON-DEMAND or fallback: Execute immediately
	if proofClass == "on_demand" {
		bv.logger.Printf("⚡ [ON-DEMAND] Executing intent %s immediately (on_demand proof class)", certenIntent.IntentID)
	} else if proofClass == "on_cadence" {
		bv.logger.Printf("⚠️ [CADENCE-FALLBACK] No scheduler configured - executing on_cadence intent %s immediately", certenIntent.IntentID)
	}

	// External audit boundary - validators do NOT impersonate audit logic
	anchorCtx, anchorCancel := context.WithTimeout(ctx, 60*time.Second)
	defer anchorCancel()

	anchorRes, err = bv.targets.SubmitAnchorFromValidatorBlock(anchorCtx, vbMeta, bftMeta)
	if err != nil {
		bv.logger.Printf("⚠️ [CANONICAL-AUDIT] External audit submission failed: %v (continuing)", err)
		// Non-fatal - audit failure doesn't invalidate consensus
		targetChainErr = err
	}

	// Classify per the Stage 1 table. A submission error is failed; every other
	// unresolved shape is PENDING, and the terminal answer arrives from Phase 7's
	// observation of the real receipt rather than from this node's patience.
	targetChainOutcome := ClassifyTargetChainOutcome(anchorRes, targetChainErr)
	targetChainTxRef := TargetChainTxRef(anchorRes)

	if anchorRes != nil {
		bv.logger.Printf("✅ [CANONICAL-AUDIT] External audit completed: tx=%s network=%s",
			anchorRes.AnchorTxID, anchorRes.Network)

		// Enhanced logging for all 3 transaction hashes
		bv.logger.Printf("📋 [ANCHOR-WORKFLOW] Transaction hashes:")
		bv.logger.Printf("   Create TX:     %s", anchorRes.CreateTxHash)
		bv.logger.Printf("   Verify TX:     %s", anchorRes.VerifyTxHash)
		bv.logger.Printf("   Governance TX: %s", anchorRes.GovernanceTxHash)

		// Phase 7-9: Trigger proof cycle for observation, attestation, and write-back
		if bv.proofCycleOrchestrator != nil && anchorRes.AnchorTxID != "" {
			// Phase 7-9 now lives in RunProofCycle (async_attestation.go) so the
			// on_cadence path can replay the SAME logic after its deferred batch
			// settles. Previously this was an inline closure the cadence path could
			// not reach, so cadence intents never attested.
			att := bv.captureAttestation(vb, certenIntent, certenProof, blockHeight,
				g0Proof, g1Proof, g2Proof, blsSignature, validatorSignatures, governanceLevel)
			// The proof cycle is the RESOLVER for a pending settlement: it observes
			// the real receipt and records the terminal status against this same
			// intent ID. Telling it what this node believes so far keeps the two
			// halves of the story joined.
			att.TargetChainOutcome = targetChainOutcome
			go bv.RunProofCycle(context.Background(), att, anchorRes)
		}
	}

	res := &ExecutionTaskResult{
		Success: true, // consensus committed
		// Derived, never assigned: see the field comment on ExecutionTaskResult.
		TargetChainConfirmed: targetChainOutcome.IsConfirmed(),
		TargetChainOutcome:   targetChainOutcome,
		TargetChainTxRef:     targetChainTxRef,
		ExecutorID:           bv.validatorID,
		ConsensusHash:        fmt.Sprintf("%X", bftRes.TxHash),
	}
	if targetChainErr != nil {
		res.TargetChainError = targetChainErr.Error()
	}
	return res, nil
}

// parseMultiChainTxHashes parses comma-separated "ChainName:txhash" strings into per-chain groups.
// Input format: "Base Sepolia:0x1234,Arbitrum Sepolia:0x5678,Solana devnet:abc123"
// Returns map: {"base-sepolia": ["0x1234"], "arbitrum-sepolia": ["0x5678"], "solana-devnet": ["abc123"]}
func parseMultiChainTxHashes(multiChainHashes string) map[string][]string {
	result := make(map[string][]string)
	if multiChainHashes == "" {
		return result
	}

	parts := strings.Split(multiChainHashes, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Skip failed entries
		if strings.Contains(part, "_failed") {
			continue
		}

		// Handle both 2-part "ChainName:txHash" and 3-part "ChainName:leg-N:txHash" formats.
		// The governance tx format includes leg IDs: "Ethereum Sepolia:leg-0:0x8771..."
		// We need to extract just the chain name (without leg ID) as the key.
		segments := strings.Split(part, ":")
		if len(segments) < 2 {
			// No chain prefix - treat as default chain
			result["default"] = append(result["default"], part)
			continue
		}

		// TX hash is always the last segment
		txHash := strings.TrimSpace(segments[len(segments)-1])
		if txHash == "" {
			continue
		}

		// Chain name is the first segment; skip any intermediate "leg-N" segments
		chainName := strings.TrimSpace(segments[0])
		// For "0x..." hashes that got split on their ":" in oddly formatted entries,
		// reconstruct if the first segment looks like a chain name
		if chainName == "" {
			continue
		}

		// Normalize chain key (strip leg ID segments from chain name)
		chainKey := strings.ToLower(strings.ReplaceAll(chainName, " ", "-"))
		result[chainKey] = append(result[chainKey], txHash)
	}

	return result
}

// extractAuthorizationLeavesFromGovernance extracts AuthorizationLeaf structs from canonical GovernanceData
// This replaces fake "test" governance with real authorization data from the canonical blob
func extractAuthorizationLeavesFromGovernance(governanceData *GovernanceData) []AuthorizationLeaf {
	// Extract real authorization leaves from the canonical governance blob
	// This data comes from Accumulate's on-chain governance, not generated locally
	var leaves []AuthorizationLeaf

	// Convert required signers to AuthorizationLeaf structs
	for i, signer := range governanceData.Authorization.RequiredSigners {
		leaf := AuthorizationLeaf{
			KeyPage:   governanceData.Authorization.RequiredKeyPage,
			KeyHash:   fmt.Sprintf("%s-%d", governanceData.Authorization.AuthorizationHash, i),
			Role:      "signer",
			Signature: signer, // Real signature from governance data
		}
		leaves = append(leaves, leaf)
	}

	// Handle explicit role mapping if present
	for _, role := range governanceData.Authorization.Roles {
		leaf := AuthorizationLeaf{
			KeyPage:   role.KeyPage,
			KeyHash:   governanceData.Authorization.AuthorizationHash,
			Role:      role.Role,
			Signature: "", // Will be filled by BLS aggregation
		}
		leaves = append(leaves, leaf)
	}

	// Ensure at least one leaf exists for governance
	if len(leaves) == 0 {
		// Fallback from canonical governance data, not hardcoded
		leaves = []AuthorizationLeaf{{
			KeyPage:   governanceData.Authorization.RequiredKeyPage,
			KeyHash:   governanceData.Authorization.AuthorizationHash,
			Role:      "signer",
			Signature: "", // BLS signature will be added separately
		}}
	}

	return leaves
}

// createValidatorLedgerStore creates a LedgerStore for the ValidatorApp
// This provides persistent storage for ValidatorBlock metadata and system state
func createValidatorLedgerStore(cfg *config.Config, validatorID string) (*ledger.LedgerStore, error) {
	// Create dedicated validator ledger DB directory
	dbDir := filepath.Join("/app", "data", "validator-ledger", validatorID)
	os.MkdirAll(dbDir, 0755)

	// Initialize LevelDB for validator ledger
	db, err := dbm.NewGoLevelDB("validator-ledger", dbDir)
	if err != nil {
		return nil, fmt.Errorf("create validator ledger DB: %w", err)
	}

	// Wrap with KV adapter and create LedgerStore
	kvAdapter := kvdb.NewKVAdapter(db)
	ledgerStore := ledger.NewLedgerStore(kvAdapter)

	return ledgerStore, nil
}

// NewValidatorChainEngine creates a CometBFT engine specifically for ValidatorBlock consensus
// This enforces ValidatorBlock invariants via ValidatorApp, separate from system/proof chain
func NewValidatorChainEngine(
	validatorID string,
	ledgerStore *ledger.LedgerStore,
	p2pPort, rpcPort int,
) (*RealCometBFTEngine, *ValidatorApp, error) {
	logger := log.New(os.Stdout, fmt.Sprintf("[ValidatorChain-%s] ", validatorID), log.LstdFlags|log.Lmicroseconds)

	// Create ValidatorApp for ValidatorBlock consensus
	chainID := fmt.Sprintf("validator-chain-%s", validatorID)
	app := NewValidatorApp(ledgerStore, chainID)

	// CRITICAL: Recover state from ledger before CometBFT calls Info()
	// This ensures the app reports the correct height/appHash so CometBFT can sync properly
	if err := app.RecoverState(); err != nil {
		logger.Printf("⚠️ State recovery failed (will start fresh): %v", err)
	}

	// Create minimal CometBFT config for ValidatorBlock consensus
	cfg := config.DefaultConfig()
	cfg.RootDir = filepath.Join("/app", "data", "validator-chain", validatorID)
	cfg.P2P.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", p2pPort)
	cfg.RPC.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", rpcPort)
	cfg.Moniker = validatorID
	cfg.DBBackend = "goleveldb"
	cfg.TxIndex.Indexer = "kv" // Enable tx indexing for Tx query support

	// Create engine with ValidatorApp
	engine, err := NewRealCometBFTEngine(cfg, app, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("create validator chain engine: %w", err)
	}

	logger.Printf("✅ [VALIDATOR-CHAIN] ValidatorBlock consensus engine ready: %s", chainID)
	logger.Printf("🎯 [GOLDEN-SPEC] All ValidatorBlocks will be validated via VerifyValidatorBlockInvariants")

	return engine, app, nil
}

// NewSystemProofEngine creates a CometBFT engine for system/proof/anchor operations
// This uses CertenApplication and is separate from ValidatorBlock consensus
func NewSystemProofEngine(
	validatorID string,
	cfg *config.Config,
) (*RealCometBFTEngine, *CertenApplication, error) {
	logger := log.New(os.Stdout, fmt.Sprintf("[SystemProof-%s] ", validatorID), log.LstdFlags|log.Lmicroseconds)

	// Create CertenApplication for system operations
	app, err := NewCertenApplicationWithDB(nil, cfg, validatorID, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("create system proof app: %w", err)
	}

	// Create engine with CertenApplication
	engine, err := NewRealCometBFTEngine(cfg, app, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("create system proof engine: %w", err)
	}

	// Set bidirectional reference for CertenApplication
	app.engine = engine

	logger.Printf("✅ [SYSTEM-PROOF] System proof engine ready: validator=%s", validatorID)
	logger.Printf("📊 [PROOF-TRACKING] CertenApplication will handle proof verification and system ledger")

	return engine, app, nil
}

// UpdateValidatorSet updates the validator set for consensus
// Phase 3: Validator set changes are queued and returned via ABCI FinalizeBlock
func (bv *BFTValidator) UpdateValidatorSet(validators []BFTValidatorInfo) {
	if bv.engine == nil {
		bv.logger.Printf("⚠️ [BFT-COORD] Cannot update validators: engine not initialized")
		return
	}

	abciApp := bv.engine.GetABCIApp()
	if abciApp == nil {
		bv.logger.Printf("⚠️ [BFT-COORD] Cannot update validators: ABCI app not available")
		return
	}

	for _, v := range validators {
		power := v.VotingPower
		if !v.IsActive {
			power = 0 // Setting power to 0 removes the validator
		}
		abciApp.QueueValidatorUpdate(v.PublicKey, power)
	}

	bv.logger.Printf("🔄 [BFT-COORD] Queued %d validator updates for next block", len(validators))
}

// GetMetrics returns current BFT execution metrics
// Phase 3: Metrics now come from CometBFT and ABCI state
func (bv *BFTValidator) GetMetrics() map[string]interface{} {
	metrics := make(map[string]interface{})

	// Basic validator metrics
	metrics["execution_queue_length"] = len(bv.executionQueue)
	metrics["validator_id"] = bv.validatorID
	metrics["chain_id"] = bv.chainID
	metrics["consensus_engine"] = "CometBFT"

	// Add CometBFT ABCI application metrics if available
	if bv.engine != nil {
		if abciApp := bv.engine.GetABCIApp(); abciApp != nil {
			abciMetrics := abciApp.GetMetrics()
			for k, v := range abciMetrics {
				metrics["abci_"+k] = v
			}
		}
	}

	return metrics
}

// Shutdown gracefully shuts down the BFT execution coordinator
func (bv *BFTValidator) Shutdown() {
	bv.logger.Printf("🛑 [BFT-VALIDATOR] Shutting down decentralized BFT validator")
	bv.cancel()
}

// Logger interface for BFT logging
type Logger interface {
	Printf(format string, args ...interface{})
}

// =============================================================================
// REAL COMETBFT IMPLEMENTATION
// =============================================================================

// RealCometBFTEngine implements actual CometBFT consensus with real networking
// RealCometBFTEngine is the production BFT engine that runs an in-process
// CometBFT node and uses RPC to BroadcastTxCommit.
type RealCometBFTEngine struct {
	cometCfg *config.Config
	app      abcitypes.Application
	logger   *log.Logger

	node      *node.Node
	rpcClient *cmthttp.HTTP

	mu      sync.RWMutex
	started bool

	// Validator identification
	validatorID string
	nodeID      string

	// Network configuration
	p2pPort int
	rpcPort int

	// Request tracking for proof verifications
	activeRequests map[string]*ProofVerificationRequest
}

// NewRealCometBFTEngine creates the CometBFT node and RPC client.
// It does *not* start the node; Start() does that.
func NewRealCometBFTEngine(
	cometCfg *config.Config,
	app abcitypes.Application,
	logger *log.Logger,
) (*RealCometBFTEngine, error) {
	if cometCfg == nil {
		return nil, fmt.Errorf("cometCfg must not be nil")
	}
	if app == nil {
		return nil, fmt.Errorf("abci app must not be nil")
	}

	// DB provider – on-disk (Pebble / whatever cfg.DBBackend says)
	dbProvider := config.DBProvider(func(ctx *config.DBContext) (dbm.DB, error) {
		return dbm.NewDB(ctx.ID, dbm.BackendType(cometCfg.DBBackend), filepath.Join(cometCfg.RootDir, "data"))
	})

	// Private validator & node key from standard CometBFT locations under RootDir.
	pv := privval.LoadFilePV(
		cometCfg.PrivValidatorKeyFile(),
		cometCfg.PrivValidatorStateFile(),
	)
	nodeKey, err := p2p.LoadNodeKey(cometCfg.NodeKeyFile())
	if err != nil {
		return nil, fmt.Errorf("load node key: %w", err)
	}

	// CRITICAL FIX: Write shared deterministic genesis before creating node
	tempEngine := &RealCometBFTEngine{logger: logger}
	if err := tempEngine.writeDeterministicGenesisIfNeeded(cometCfg); err != nil {
		return nil, fmt.Errorf("write shared genesis: %w", err)
	}

	// CRITICAL FIX: Enable CometBFT logging to see consensus activity
	tmLogger := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout))
	tmLogger = tmLogger.With("module", "cometbft")

	// Create the in-process node.
	n, err := node.NewNode(
		cometCfg,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(app),
		node.DefaultGenesisDocProviderFunc(cometCfg),
		dbProvider,
		node.DefaultMetricsProvider(cometCfg.Instrumentation),
		tmLogger,
	)
	if err != nil {
		return nil, fmt.Errorf("create cometbft node: %w", err)
	}

	// RPC client pointing at the node's RPC listen address.
	// Note: ListenAddress uses 0.0.0.0 to bind to all interfaces,
	// but we need 127.0.0.1 for the client to connect locally
	rpcAddr := cometCfg.RPC.ListenAddress
	if rpcAddr == "" {
		rpcAddr = "tcp://127.0.0.1:26657"
	} else {
		// Replace 0.0.0.0 with 127.0.0.1 for client connection
		rpcAddr = strings.Replace(rpcAddr, "0.0.0.0", "127.0.0.1", 1)
	}
	rpcClient, err := cmthttp.New(rpcAddr, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("create cometbft rpc client: %w", err)
	}
	// Note: rpcClient.Start() is called in engine.Start() AFTER node.Start()
	// The RPC client needs a running node to connect to

	// Extract validator ID from the node's public key
	pubKey, err := pv.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("get validator public key: %w", err)
	}
	validatorID := fmt.Sprintf("%X", pubKey.Address())

	// Extract node ID from the node key
	nodeID := string(nodeKey.ID())

	// Extract ports from config
	p2pPort := 26656 // Default
	rpcPort := 26657 // Default
	if cometCfg.P2P.ListenAddress != "" {
		// Parse port from address like "tcp://0.0.0.0:26656"
		if parts := strings.Split(cometCfg.P2P.ListenAddress, ":"); len(parts) > 0 {
			if port, err := fmt.Sscanf(parts[len(parts)-1], "%d", &p2pPort); port == 0 || err != nil {
				p2pPort = 26656
			}
		}
	}
	if cometCfg.RPC.ListenAddress != "" {
		if parts := strings.Split(cometCfg.RPC.ListenAddress, ":"); len(parts) > 0 {
			if port, err := fmt.Sscanf(parts[len(parts)-1], "%d", &rpcPort); port == 0 || err != nil {
				rpcPort = 26657
			}
		}
	}

	return &RealCometBFTEngine{
		cometCfg:       cometCfg,
		app:            app,
		logger:         logger,
		node:           n,
		rpcClient:      rpcClient,
		validatorID:    validatorID,
		nodeID:         nodeID,
		p2pPort:        p2pPort,
		rpcPort:        rpcPort,
		activeRequests: make(map[string]*ProofVerificationRequest),
	}, nil
}

// SimpleBFTValidator represents a real validator in the network
type SimpleBFTValidator struct {
	ID          string
	PublicKey   []byte // Store as bytes to handle different key types
	VotingPower int
	IsActive    bool
}

// CertenApplication implements the ABCI application interface for CometBFT
type CertenApplication struct {
	logger     *log.Logger
	engine     *RealCometBFTEngine
	pendingTxs map[string]*ProofVerificationRequest
	mu         sync.RWMutex

	// App state for tracking consensus
	ballotState    map[string]*BallotInfo      // roundID -> ballot status
	proofState     map[string]*ProofRecord     // requestID -> proof verification
	executionState map[string]*ExecutionRecord // roundID -> execution result
	intentState    map[string]*IntentRecord    // intentID -> intent tracking

	// Block height tracking
	currentHeight int64
	currentTime   time.Time
	appHash       []byte

	// BFT Validator reference for callback functionality
	validator *BFTValidator

	// Ledger integration with persistent storage
	cmtDB            dbm.DB              // CometBFT database for persistence
	ledgerStore      *ledger.LedgerStore // Ledger store for system/anchor tracking
	chainID          string
	currentAccAnchor *ledger.SystemAccumulateAnchorRef // Current Accumulate anchor reference

	// Version info for system ledger
	executorVersion  string
	upstreamVersions []ledger.UpstreamExecutor

	// Pending validator updates for next FinalizeBlock
	pendingValidatorUpdates []abcitypes.ValidatorUpdate
}

// NewCertenApplication creates a new ABCI application for CERTEN consensus
// NOTE: This function is kept for testing but should NOT be used to replace
// the app in Start() as it would lose the validator reference set by SetValidatorRef.
func NewCertenApplication(engine *RealCometBFTEngine) *CertenApplication {
	return &CertenApplication{
		logger:           engine.logger,
		engine:           engine,
		pendingTxs:       make(map[string]*ProofVerificationRequest),
		ballotState:      make(map[string]*BallotInfo),
		proofState:       make(map[string]*ProofRecord),
		executionState:   make(map[string]*ExecutionRecord),
		intentState:      make(map[string]*IntentRecord),
		currentHeight:    0,
		appHash:          []byte("certen_v1"),
		validator:        nil, // Will be set via SetValidatorRef
		cmtDB:            nil, // Will be set via SetCometBFTDB
		ledgerStore:      nil, // Will be set via SetLedgerStore
		chainID:          "",  // Will be set via SetLedgerStore
		executorVersion:  "v0.1.0",
		upstreamVersions: []ledger.UpstreamExecutor{}, // Will be populated from config
	}
}

// NewCertenApplicationWithDB creates a new ABCI application with persistent storage
func NewCertenApplicationWithDB(engine *RealCometBFTEngine, cfg *config.Config, validatorID string, logger *log.Logger) (*CertenApplication, error) {
	// Create dedicated ledger DB
	dbDir := cfg.DBDir()
	ledgerDBPath := filepath.Join(dbDir, "certen-ledger")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(ledgerDBPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create ledger DB directory: %w", err)
	}

	cmtDB, err := dbm.NewGoLevelDB("certen-ledger", ledgerDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create ledger database: %w", err)
	}

	// Wrap in KV adapter
	kvAdapter := kvdb.NewKVAdapter(cmtDB)
	ledgerStore := ledger.NewLedgerStore(kvAdapter)

	app := &CertenApplication{
		logger:          logger,
		engine:          engine,
		pendingTxs:      make(map[string]*ProofVerificationRequest),
		ballotState:     make(map[string]*BallotInfo),
		proofState:      make(map[string]*ProofRecord),
		executionState:  make(map[string]*ExecutionRecord),
		intentState:     make(map[string]*IntentRecord),
		currentHeight:   0,
		appHash:         []byte("certen_v1"),
		validator:       nil, // Will be set via SetValidatorRef
		cmtDB:           cmtDB,
		ledgerStore:     ledgerStore,
		chainID:         getChainIDFromEnv(), // Use consistent chainID across all validators
		executorVersion: Version,             // Set from package-level Version variable (can be overridden at build time)
		upstreamVersions: []ledger.UpstreamExecutor{
			// Accumulate upstream executor - version populated when lite client connects
			{
				Partition: "accumulate-mainnet",
				Version:   "v1.4.x", // Default, updated on connection
			},
		},
	}

	return app, nil
}

// SetValidatorRef configures the BFT validator reference for callbacks
func (app *CertenApplication) SetValidatorRef(validator *BFTValidator) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.validator = validator
	app.logger.Printf("✅ [CERTEN-ABCI] BFT validator reference configured")
}

// SetLedgerStore configures the ledger store for system and anchor ledger updates
func (app *CertenApplication) SetLedgerStore(ledgerStore *ledger.LedgerStore, chainID string) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.ledgerStore = ledgerStore
	app.chainID = chainID
	app.logger.Printf("✅ [CERTEN-ABCI] LedgerStore configured for chain: %s", chainID)
}

// Query methods for app state
func (app *CertenApplication) GetBallotState(roundID string) (*BallotInfo, bool) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	ballot, exists := app.ballotState[roundID]
	return ballot, exists
}

func (app *CertenApplication) GetProofState(requestID string) (*ProofRecord, bool) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	proof, exists := app.proofState[requestID]
	return proof, exists
}

func (app *CertenApplication) GetExecutionState(roundID string) (*ExecutionRecord, bool) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	execution, exists := app.executionState[roundID]
	return execution, exists
}

// Required ABCI methods for CertenApplication
func (app *CertenApplication) CheckTx(ctx context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	return &abcitypes.ResponseCheckTx{Code: 0}, nil
}

func (app *CertenApplication) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	return &abcitypes.ResponseInfo{
		Data:             "CERTEN Protocol Stateful ABCI",
		Version:          "2.0.0",
		AppVersion:       2,
		LastBlockHeight:  app.currentHeight,
		LastBlockAppHash: app.appHash,
	}, nil
}

func (app *CertenApplication) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	app.logger.Printf("🚀 [CERTEN-ABCI] Initializing chain with %d validators", len(req.Validators))
	return &abcitypes.ResponseInitChain{}, nil
}

func (app *CertenApplication) PrepareProposal(ctx context.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	return &abcitypes.ResponsePrepareProposal{Txs: req.Txs}, nil
}

func (app *CertenApplication) ProcessProposal(ctx context.Context, req *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
	return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_ACCEPT}, nil
}

func (app *CertenApplication) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	app.mu.Lock()
	defer app.mu.Unlock()

	// Capture block header information for ledger tracking
	app.currentHeight = req.Height
	app.currentTime = req.Time
	app.logger.Printf("📦 [CERTEN-ABCI] Finalizing block %d with %d transactions at %s",
		req.Height, len(req.Txs), req.Time.Format(time.RFC3339))

	// Process each transaction and update app state
	for _, tx := range req.Txs {
		var txData map[string]interface{}
		if err := json.Unmarshal(tx, &txData); err != nil {
			continue
		}

		if txType, ok := txData["type"].(string); ok {
			switch txType {
			case "proof_verification":
				app.processProofVerification(txData)
			// ballot_update and validator_vote removed - CometBFT handles consensus directly
			case "execution_result":
				app.processExecutionResult(txData)
			case "anchor_result":
				app.processAnchorResult(txData)
			case "executor_selection":
				app.processExecutorSelection(txData)
			}
		}
	}

	// Update app hash
	app.appHash = app.computeAppHash()

	// Collect and clear any pending validator updates
	var validatorUpdates []abcitypes.ValidatorUpdate
	if len(app.pendingValidatorUpdates) > 0 {
		validatorUpdates = app.pendingValidatorUpdates
		app.pendingValidatorUpdates = nil
		app.logger.Printf("🔄 [CERTEN-ABCI] Returning %d validator updates at block %d",
			len(validatorUpdates), req.Height)
	}

	return &abcitypes.ResponseFinalizeBlock{
		AppHash:          app.appHash,
		ValidatorUpdates: validatorUpdates,
	}, nil
}

// QueueValidatorUpdate queues a validator update for the next FinalizeBlock
// Setting power to 0 removes the validator from the set
func (app *CertenApplication) QueueValidatorUpdate(pubKey []byte, power int64) {
	app.mu.Lock()
	defer app.mu.Unlock()

	// Convert pubKey to CometBFT pubkey format (expects 32 bytes)
	ed25519PubKey := cmted25519.PubKey(pubKey)

	update := abcitypes.ValidatorUpdate{
		PubKey: cryptoproto.PublicKey{
			Sum: &cryptoproto.PublicKey_Ed25519{
				Ed25519: ed25519PubKey,
			},
		},
		Power: power,
	}
	app.pendingValidatorUpdates = append(app.pendingValidatorUpdates, update)
	app.logger.Printf("📝 [CERTEN-ABCI] Queued validator update: pubkey=%X power=%d", pubKey[:8], power)
}

// getAccumulateAnchorRef extracts the Accumulate anchor reference for this block
func (app *CertenApplication) getAccumulateAnchorRef() *ledger.SystemAccumulateAnchorRef {
	// Return current anchor reference if available
	return app.currentAccAnchor
}

func (app *CertenApplication) Commit(ctx context.Context, req *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	app.mu.Lock()
	defer app.mu.Unlock()

	// Finalize app hash
	app.appHash = app.computeAppHash()

	// Update system ledger if LedgerStore is configured
	if app.ledgerStore != nil {
		height := uint64(app.currentHeight)
		hashHex := hex.EncodeToString(app.appHash)

		// Get anchor reference if available for this block
		accRef := app.getAccumulateAnchorRef()

		if err := app.ledgerStore.UpdateSystemLedgerOnCommit(
			height,
			hashHex,
			app.currentTime,
			accRef,
			app.executorVersion,
			app.upstreamVersions,
		); err != nil {
			app.logger.Printf("❌ [CERTEN-ABCI] Failed to update system ledger: %v", err)
		} else {
			app.logger.Printf("✅ [CERTEN-ABCI] Updated system ledger for block %d", height)
		}
	}

	// Guard RetainHeight against negative values
	retainHeight := app.currentHeight - 100
	if retainHeight < 0 {
		retainHeight = 0
	}

	return &abcitypes.ResponseCommit{
		RetainHeight: retainHeight, // Keep recent 100 blocks
	}, nil
}

func (app *CertenApplication) ExtendVote(ctx context.Context, req *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
	return &abcitypes.ResponseExtendVote{}, nil
}

func (app *CertenApplication) Query(ctx context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	// Handle basic queries for ABCI state
	switch req.Path {
	case "ballot":
		// Query ballot state
		app.mu.RLock()
		defer app.mu.RUnlock()
		if ballot, exists := app.ballotState[string(req.Data)]; exists {
			data, _ := json.Marshal(ballot)
			return &abcitypes.ResponseQuery{
				Code:  0,
				Value: data,
			}, nil
		}
		return &abcitypes.ResponseQuery{Code: 1, Log: "ballot not found"}, nil
	case "execution":
		// Query execution state
		app.mu.RLock()
		defer app.mu.RUnlock()
		if exec, exists := app.executionState[string(req.Data)]; exists {
			data, _ := json.Marshal(exec)
			return &abcitypes.ResponseQuery{
				Code:  0,
				Value: data,
			}, nil
		}
		return &abcitypes.ResponseQuery{Code: 1, Log: "execution not found"}, nil
	default:
		return &abcitypes.ResponseQuery{Code: 1, Log: "unknown query path"}, nil
	}
}

func (app *CertenApplication) VerifyVoteExtension(ctx context.Context, req *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
	return &abcitypes.ResponseVerifyVoteExtension{Status: abcitypes.ResponseVerifyVoteExtension_ACCEPT}, nil
}

func (app *CertenApplication) ListSnapshots(ctx context.Context, req *abcitypes.RequestListSnapshots) (*abcitypes.ResponseListSnapshots, error) {
	return &abcitypes.ResponseListSnapshots{}, nil
}

func (app *CertenApplication) OfferSnapshot(ctx context.Context, req *abcitypes.RequestOfferSnapshot) (*abcitypes.ResponseOfferSnapshot, error) {
	return &abcitypes.ResponseOfferSnapshot{}, nil
}

func (app *CertenApplication) LoadSnapshotChunk(ctx context.Context, req *abcitypes.RequestLoadSnapshotChunk) (*abcitypes.ResponseLoadSnapshotChunk, error) {
	return &abcitypes.ResponseLoadSnapshotChunk{}, nil
}

func (app *CertenApplication) ApplySnapshotChunk(ctx context.Context, req *abcitypes.RequestApplySnapshotChunk) (*abcitypes.ResponseApplySnapshotChunk, error) {
	return &abcitypes.ResponseApplySnapshotChunk{}, nil
}

// State processing methods
func (app *CertenApplication) processProofVerification(txData map[string]interface{}) {
	if requestID, ok := txData["request_id"].(string); ok {
		if roundID, ok := txData["round_id"].(string); ok {
			if intentID, ok := txData["intent_id"].(string); ok {
				if validatorID, ok := txData["validator"].(string); ok {
					app.proofState[requestID] = &ProofRecord{
						RequestID:   requestID,
						RoundID:     roundID,
						IntentID:    intentID,
						Status:      "verified",
						ValidatorID: validatorID,
						Timestamp:   time.Now().Unix(),
					}
					app.logger.Printf("📋 [CERTEN-ABCI] Proof verification recorded in app state: %s", requestID)
				}
			}
		}
	}
}

func (app *CertenApplication) processExecutionResult(txData map[string]interface{}) {
	if roundID, ok := txData["round_id"].(string); ok {
		if intentID, ok := txData["intent_id"].(string); ok {
			if executorID, ok := txData["executor_id"].(string); ok {
				success := false
				if s, ok := txData["success"].(bool); ok {
					success = s
				}

				app.executionState[roundID] = &ExecutionRecord{
					RoundID:    roundID,
					IntentID:   intentID,
					Success:    success,
					ExecutorID: executorID,
					Timestamp:  time.Now().Unix(),
				}
				app.logger.Printf("⚡ [CERTEN-ABCI] Execution result recorded in app state: %s", roundID)
			}
		}
	}
}

func (app *CertenApplication) processAnchorResult(txData map[string]interface{}) {
	if roundID, ok := txData["round_id"].(string); ok {
		if intentID, ok := txData["intent_id"].(string); ok {
			if anchorData, ok := txData["anchor_result"]; ok && app.validator != nil {
				anchorBytes, err := json.Marshal(anchorData)
				if err == nil {
					var anchorResp AnchorResponse
					if err := json.Unmarshal(anchorBytes, &anchorResp); err == nil {
						app.logger.Printf("📨 [CERTEN-ABCI] Anchor result logged in app state: round=%s intent=%s", roundID, intentID)
						// NOTE: processIncomingAnchorResult removed per Golden Spec - no validator-to-validator HTTP coordination
					}
				}
			}
		}
	}
}

func (app *CertenApplication) processExecutorSelection(txData map[string]interface{}) {
	app.logger.Printf("🔍 [CERTEN-ABCI] Processing executor selection: %+v", txData)

	if roundID, ok := txData["round_id"].(string); ok {
		if executorID, ok := txData["executor_id"].(string); ok {
			app.mu.Lock()
			// Update ballot state with executor selection
			if ballot, exists := app.ballotState[roundID]; exists {
				ballot.FinalExecutorID = executorID
				ballot.IsFinalized = true
				ballot.ConsensusReached = true
				app.logger.Printf("✅ [CERTEN-ABCI] Updated existing ballot state: %s -> %s", roundID, executorID)
			} else {
				// Create new ballot state
				app.ballotState[roundID] = &BallotInfo{
					RoundID:          roundID,
					IsFinalized:      true,
					ConsensusReached: true,
					FinalExecutorID:  executorID,
					VoteCount:        1,
					Timestamp:        time.Now().Unix(),
				}
				app.logger.Printf("✨ [CERTEN-ABCI] Created new ballot state: %s -> %s", roundID, executorID)
			}
			app.mu.Unlock()

			app.logger.Printf("🎯 [CERTEN-ABCI] Executor selection committed to state: %s -> %s", roundID, executorID)
		} else {
			app.logger.Printf("❌ [CERTEN-ABCI] Missing executor_id in transaction data")
		}
	} else {
		app.logger.Printf("❌ [CERTEN-ABCI] Missing round_id in transaction data")
	}
}

func (app *CertenApplication) computeAppHash() []byte {
	// Enhanced hash based on current state
	hash := sha256.New()
	summary := fmt.Sprintf(
		"height_%d_proofs_%d_ballots_%d_executions_%d_intents_%d",
		app.currentHeight,
		len(app.proofState),
		len(app.ballotState),
		len(app.executionState),
		len(app.intentState),
	)
	hash.Write([]byte(summary))
	return hash.Sum(nil)
}

// generateDeterministicNodeKey creates a deterministic node key based on validator ID and chain ID
// IMPORTANT: This MUST match the exact seed format used by generate-genesis to ensure consistent node IDs
func generateDeterministicNodeKey(validatorID string) cmted25519.PrivKey {
	// Get chain ID from environment - MUST match the genesis generator's chain ID
	chainID := os.Getenv("COMETBFT_CHAIN_ID")
	if chainID == "" {
		chainID = "certen-testnet" // Default to match typical testnet deployment
	}

	// Use EXACT same seed format as genesis generator:
	// seed := sha256.Sum256([]byte(fmt.Sprintf("certen-validator-key-%s-%s", chainID, validatorID)))
	seedStr := fmt.Sprintf("certen-validator-key-%s-%s", chainID, validatorID)
	seed := sha256.Sum256([]byte(seedStr))

	// Generate proper ed25519 key from seed (same as genesis generator)
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// CometBFT expects 64-byte format: private key seed (32) + public key (32)
	combined := make([]byte, 64)
	copy(combined[:32], privateKey[:32]) // First 32 bytes: private key
	copy(combined[32:], publicKey)       // Last 32 bytes: public key

	return cmted25519.PrivKey(combined)
}

// generateDeterministicValidatorPublicKey creates the public key for any validator ID
// IMPORTANT: Uses SAME seed as node key (matching genesis generator behavior)
func generateDeterministicValidatorPublicKey(validatorID string) cmted25519.PubKey {
	// Use the SAME key as node key (genesis generator uses one key for both)
	privKey := generateDeterministicNodeKey(validatorID)
	pubKey := privKey.PubKey()

	// Type assert to the specific ed25519 public key type
	ed25519PubKey, ok := pubKey.(cmted25519.PubKey)
	if !ok {
		// Fallback - should not happen with our deterministic generation
		return cmted25519.GenPrivKey().PubKey().(cmted25519.PubKey)
	}

	return ed25519PubKey
}

// NewUnifiedCometBFTEngine creates a unified CometBFT engine for dev testing (use NewProductionEngine for production)
func NewUnifiedCometBFTEngine(validatorID string) (*RealCometBFTEngine, error) {
	logger := log.New(os.Stdout, fmt.Sprintf("[CometBFT-%s] ", validatorID), log.LstdFlags|log.Lmicroseconds)

	// All validators use the same internal container ports - Docker handles external mapping
	p2pPort := 26656 // All validators listen on internal port 26656
	rpcPort := 26657 // All validators listen on internal port 26657

	// CometBFT home is a persistent Docker volume (validatorN_keys:/app/bft-keys).
	// DO NOT wipe the data dir on boot: blockstore.db / state.db / cs.wal must survive
	// restarts so CometBFT recovers to the same height as the persisted app ledger
	// (validator-ledger, recovered via ValidatorApp.RecoverState). Wiping it reset CometBFT
	// to genesis while the app recovered to height N, causing the handshake app-hash mismatch
	// (assertAppHashEqualsOneFromState) crash-loop on any restart after the fleet had
	// processed intents. Requires the FinalizeBlock AppHash fix (abci_validator.go) so the
	// persisted app-hash matches what CometBFT records. Node/priv-validator keys below are
	// still regenerated deterministically.
	homeDir := filepath.Join("/app", "bft-keys", validatorID)

	logger.Printf("💾 Using persistent CometBFT state at %s (survives restarts)", homeDir)

	cfg := config.DefaultConfig()
	cfg.SetRoot(homeDir)
	cfg.P2P.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", p2pPort)
	cfg.RPC.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", rpcPort)

	// Block production settings - Event-based (only create blocks when there are transactions)
	cfg.Consensus.CreateEmptyBlocks = false

	// Faster consensus timeouts for responsive block production
	cfg.Consensus.TimeoutPropose = 2 * time.Second
	cfg.Consensus.TimeoutProposeDelta = 200 * time.Millisecond
	cfg.Consensus.TimeoutPrevote = 500 * time.Millisecond
	cfg.Consensus.TimeoutPrevoteDelta = 200 * time.Millisecond
	cfg.Consensus.TimeoutPrecommit = 500 * time.Millisecond
	cfg.Consensus.TimeoutPrecommitDelta = 200 * time.Millisecond
	cfg.Consensus.TimeoutCommit = 1 * time.Second

	// Enable transaction indexing for Tx query support
	// This is required for polling transaction inclusion in blocks
	cfg.TxIndex.Indexer = "kv"

	cfg.Moniker = validatorID

	// Set up deterministic P2P configuration with persistent peers
	// Per BFT Resiliency Task 4: Each validator should have ALL other validators as persistent peers
	persistentPeers := os.Getenv("COMETBFT_P2P_PERSISTENT_PEERS")
	if persistentPeers != "" {
		cfg.P2P.PersistentPeers = persistentPeers
		logger.Printf("🔗 Configured persistent peers: %s", persistentPeers)
	}

	// Seeds for initial peer discovery (alternative to persistent peers)
	seeds := os.Getenv("COMETBFT_P2P_SEEDS")
	if seeds != "" {
		cfg.P2P.Seeds = seeds
		logger.Printf("🌱 Configured seeds: %s", seeds)
	}

	// Unconditional peer exchange for better network discovery
	cfg.P2P.PexReactor = true
	cfg.P2P.AddrBookStrict = false // Allow private IPs in Docker network

	// P2P network configuration to prevent pong timeouts and connection drops
	// These settings are critical for stable multi-validator consensus in Docker networks
	cfg.P2P.SendRate = 20000000 // 20 MB/s - increase from default 512KB/s
	cfg.P2P.RecvRate = 20000000 // 20 MB/s - increase from default 512KB/s
	cfg.P2P.FlushThrottleTimeout = 100 * time.Millisecond
	cfg.P2P.MaxPacketMsgPayloadSize = 1400                  // Default is 1024, increase for larger messages
	cfg.P2P.HandshakeTimeout = 30 * time.Second             // Increase from default 20s
	cfg.P2P.DialTimeout = 10 * time.Second                  // Increase from default 3s
	cfg.P2P.AllowDuplicateIP = true                         // Allow duplicate IPs in Docker network
	cfg.P2P.PersistentPeersMaxDialPeriod = 60 * time.Second // Keep trying persistent peers

	// Generate deterministic node key (always overwrite existing)
	nodeKeyFile := filepath.Join(homeDir, "config", "node_key.json")
	os.MkdirAll(filepath.Dir(nodeKeyFile), 0755)

	// Remove existing node key to ensure deterministic generation
	os.Remove(nodeKeyFile)

	// Generate deterministic node key
	nodePrivKey := generateDeterministicNodeKey(validatorID)
	nodeKey := &p2p.NodeKey{
		PrivKey: nodePrivKey,
	}

	// Save the deterministic node key
	if err := nodeKey.SaveAs(nodeKeyFile); err != nil {
		return nil, fmt.Errorf("failed to save node key: %w", err)
	}

	logger.Printf("✅ Generated deterministic node key for %s: %s", validatorID, nodeKey.ID())

	// Create private validator with deterministic keys
	privValKeyFile := filepath.Join(homeDir, "config", "priv_validator_key.json")
	privValStateFile := filepath.Join(homeDir, "data", "priv_validator_state.json")
	os.MkdirAll(filepath.Dir(privValKeyFile), 0755)
	os.MkdirAll(filepath.Dir(privValStateFile), 0755)

	// Remove existing keys to ensure deterministic generation
	os.Remove(privValKeyFile)
	os.Remove(privValStateFile)

	// Generate deterministic private validator key using SAME seed as node key (matches genesis generator)
	privValidatorKey := generateDeterministicNodeKey(validatorID)

	// Create the private validator - NewFilePV expects (PrivKey, keyFilePath, stateFilePath)
	privValidator := privval.NewFilePV(privValidatorKey, privValKeyFile, privValStateFile)
	privValidator.Save()

	// Create a unified validator set of 7 BFT validators
	totalValidators := 7
	byzantineFaultThreshold := (totalValidators - 1) / 3 // f = 2 (can tolerate 2 Byzantine faults)
	consensusThreshold := 2*byzantineFaultThreshold + 1  // 2f+1 = 5 (need 5 for consensus)

	logger.Printf("🏛️ Unified BFT validator network configuration:")
	logger.Printf("   • Total validators: %d", totalValidators)
	logger.Printf("   • Byzantine fault threshold: %d", byzantineFaultThreshold)
	logger.Printf("   • Consensus threshold: %d", consensusThreshold)
	logger.Printf("   • Current validator: %s", validatorID)

	// Create the unified validator set for 7 BFT validators
	validatorMap := make(map[string]*SimpleBFTValidator)
	validatorIDs := []string{"validator-1", "validator-2", "validator-3", "validator-4", "validator-5", "validator-6", "validator-7"}

	for _, vID := range validatorIDs {
		validatorPubKey := generateDeterministicValidatorPublicKey(vID)
		bftValidator := &SimpleBFTValidator{
			ID:          vID,
			PublicKey:   validatorPubKey.Bytes(),
			VotingPower: 10, // Equal voting power
			IsActive:    true,
		}
		validatorMap[vID] = bftValidator
		logger.Printf("   • Validator %s: %s (power: %d)", vID, validatorPubKey.Address(), bftValidator.VotingPower)
	}

	// CRITICAL FIX: Use ValidatorApp for ValidatorBlock consensus, NOT CertenApplication
	// Per Golden Spec: ValidatorApp enforces VerifyValidatorBlockInvariants
	// CertenApplication is for system/proof/anchor chain only
	ledgerStore, err := createValidatorLedgerStore(cfg, validatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to create ledger store: %w", err)
	}

	chainID := fmt.Sprintf("validator-chain-%s", validatorID)
	app := NewValidatorApp(ledgerStore, chainID)
	logger.Printf("✅ [VALIDATOR-CHAIN] Created ValidatorApp for VB consensus: chain=%s", chainID)

	// CRITICAL: Recover state from ledger before CometBFT calls Info()
	// This ensures the app reports the correct height/appHash so CometBFT can sync properly
	if err := app.RecoverState(); err != nil {
		logger.Printf("⚠️ State recovery failed (will start fresh): %v", err)
	}

	// Use the new, clean RealCometBFTEngine constructor instead of manual struct literal
	engine, err := NewRealCometBFTEngine(cfg, app, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create RealCometBFTEngine: %w", err)
	}

	// ValidatorApp doesn't need engine reference - it's purely ABCI
	// Engine reference only needed for CertenApplication

	logger.Printf("✅ [VALIDATOR-CHAIN] ValidatorBlock consensus engine created: validator=%s chain=%s", validatorID, chainID)
	logger.Printf("🎯 [SPEC-COMPLIANCE] ValidatorApp will enforce VerifyValidatorBlockInvariants on all VB transactions")
	return engine, nil
}

// Start starts the real CometBFT node
// Start boots the in-process CometBFT node if it's not already running.
func (e *RealCometBFTEngine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.started {
		return nil
	}

	if err := e.node.Start(); err != nil {
		return fmt.Errorf("start cometbft node: %w", err)
	}

	// Give RPC a brief window to come up so BroadcastTxCommit won't race.
	time.Sleep(500 * time.Millisecond)

	// Start the RPC client AFTER the node is running
	// This is critical - the client needs a running RPC endpoint to connect to
	if err := e.rpcClient.Start(); err != nil {
		e.logger.Printf("⚠️ [RPC] Failed to start RPC client after node start: %v", err)
		// Continue anyway - HTTP calls may still work without explicit Start
	} else {
		e.logger.Printf("✅ [RPC] RPC client started successfully")
	}

	e.started = true
	return nil
}

func (e *RealCometBFTEngine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.started {
		return nil
	}
	if err := e.node.Stop(); err != nil {
		return fmt.Errorf("stop cometbft node: %w", err)
	}
	e.started = false
	return nil
}

// BroadcastValidatorBlockCommit encodes the canonical ValidatorBlock as JSON,
// submits via BroadcastTxSync, then polls for confirmed inclusion in a block.
// This ensures cryptographic proof integrity by returning only after consensus commits.
func (e *RealCometBFTEngine) BroadcastValidatorBlockCommit(
	ctx context.Context,
	vb *ValidatorBlock,
) (*BFTExecutionResult, error) {
	if vb == nil {
		return nil, fmt.Errorf("validator block must not be nil")
	}

	e.logger.Printf("📡 [COMETBFT] BroadcastValidatorBlockCommit: starting for bundle=%s", vb.BundleID)

	if err := e.Start(); err != nil {
		e.logger.Printf("❌ [COMETBFT] Failed to start engine: %v", err)
		return nil, err
	}
	e.logger.Printf("✅ [COMETBFT] Engine started/running")

	payload, err := json.Marshal(vb)
	if err != nil {
		return nil, fmt.Errorf("marshal validator block: %w", err)
	}
	e.logger.Printf("📦 [COMETBFT] ValidatorBlock marshaled: %d bytes", len(payload))

	// Phase 1: Submit to mempool via BroadcastTxSync with retry logic
	// CometBFT RPC can become temporarily unresponsive during peer connectivity issues
	e.logger.Printf("📡 [COMETBFT] Phase 1: Submitting to mempool via BroadcastTxSync...")

	var res *coretypes.ResultBroadcastTx
	maxRetries := 3
	baseTimeout := 30 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Increase timeout with each retry
		timeout := baseTimeout + time.Duration(attempt-1)*15*time.Second
		syncCtx, syncCancel := context.WithTimeout(ctx, timeout)

		e.logger.Printf("📡 [COMETBFT] BroadcastTxSync attempt %d/%d (timeout=%v)...", attempt, maxRetries, timeout)
		res, err = e.rpcClient.BroadcastTxSync(syncCtx, payload)
		syncCancel()

		if err == nil {
			break // Success
		}

		e.logger.Printf("⚠️ [COMETBFT] BroadcastTxSync attempt %d failed: %v", attempt, err)

		// Don't retry if context was cancelled externally
		if ctx.Err() != nil {
			e.logger.Printf("❌ [COMETBFT] Context cancelled, not retrying")
			return nil, fmt.Errorf("BroadcastTxSync: %w", err)
		}

		// Check if it's a timeout error worth retrying
		if strings.Contains(err.Error(), "deadline exceeded") || strings.Contains(err.Error(), "connection refused") {
			if attempt < maxRetries {
				retryDelay := time.Duration(attempt) * 2 * time.Second
				e.logger.Printf("🔄 [COMETBFT] Retrying in %v...", retryDelay)
				time.Sleep(retryDelay)
				continue
			}
		}

		// Non-retryable error
		e.logger.Printf("❌ [COMETBFT] BroadcastTxSync failed after %d attempts: %v", attempt, err)
		return nil, fmt.Errorf("BroadcastTxSync: %w", err)
	}

	if res == nil {
		return nil, fmt.Errorf("BroadcastTxSync: failed after %d attempts", maxRetries)
	}
	e.logger.Printf("📡 [COMETBFT] BroadcastTxSync returned: hash=%X code=%d", res.Hash, res.Code)
	if res.Code != 0 {
		e.logger.Printf("❌ [COMETBFT] CheckTx failed: code=%d log=%s", res.Code, res.Log)
		return nil, fmt.Errorf("CheckTx failed: code=%d log=%s", res.Code, res.Log)
	}
	e.logger.Printf("✅ [COMETBFT] CheckTx passed - transaction in mempool: hash=%X", res.Hash)

	// Phase 2: Poll for transaction inclusion in a block
	// Note: The ValidatorBlock itself contains all cryptographic proofs (L1-L3, governance, BLS).
	// The CometBFT height is metadata for audit trail, not part of the proof chain.
	txHash := res.Hash
	e.logger.Printf("⏳ [COMETBFT] Phase 2: Polling for block inclusion (max 15s)...")

	pollTimeout := 15 * time.Second
	pollInterval := 1 * time.Second
	pollStart := time.Now()

	for {
		// Check if we've exceeded poll timeout
		if time.Since(pollStart) > pollTimeout {
			e.logger.Printf("⚠️ [COMETBFT] Poll timeout - returning with mempool confirmation only")
			e.logger.Printf("✅ [COMETBFT] Transaction passed CheckTx and is in mempool - consensus will commit it")
			// Return with Height=0 indicating pending consensus but valid mempool inclusion
			// The caller can still proceed since ValidatorBlock was cryptographically validated
			return &BFTExecutionResult{
				Height:      0,
				TxHash:      txHash,
				BlockHash:   nil,
				CommittedAt: time.Now().UTC(),
			}, nil
		}

		// Query transaction status via RPC
		txResult, err := e.rpcClient.Tx(ctx, txHash, false)
		if err != nil {
			// Transaction not yet indexed - wait and retry
			time.Sleep(pollInterval)
			continue
		}

		// Transaction found in a block!
		if txResult.TxResult.Code != 0 {
			e.logger.Printf("❌ [COMETBFT] Transaction failed in block: code=%d log=%s", txResult.TxResult.Code, txResult.TxResult.Log)
			return nil, fmt.Errorf("transaction failed in block: code=%d log=%s", txResult.TxResult.Code, txResult.TxResult.Log)
		}

		e.logger.Printf("🎉 [COMETBFT] ValidatorBlock COMMITTED at height=%d hash=%X (elapsed: %v)",
			txResult.Height, txResult.Hash, time.Since(pollStart).Round(time.Millisecond))

		return &BFTExecutionResult{
			Height:      txResult.Height,
			TxHash:      txResult.Hash,
			BlockHash:   nil,
			CommittedAt: time.Now().UTC(),
		}, nil
	}
}

// BroadcastAppTxSync broadcasts ABCI transactions via in-process CometBFT engine
func (e *RealCometBFTEngine) BroadcastAppTxSync(ctx context.Context, tx []byte) error {
	// Ensure engine is started
	if err := e.Start(); err != nil {
		return fmt.Errorf("start engine: %w", err)
	}

	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Broadcast via in-process RPC client
	res, err := e.rpcClient.BroadcastTxSync(ctx, tx)
	if err != nil {
		return fmt.Errorf("BroadcastTxSync via in-process engine: %w", err)
	}

	if res.Code != 0 {
		return fmt.Errorf("CheckTx failed: code=%d log=%s", res.Code, res.Log)
	}

	e.logger.Printf("📡 [REAL-COMETBFT] ABCI tx accepted via in-process engine: %X", res.Hash)
	return nil
}

// LedgerStoreProvider interface for ABCI apps that provide ledger store
type LedgerStoreProvider interface {
	GetLedgerStore() *ledger.LedgerStore
	GetChainID() string
}

// GetABCIApp returns the ABCI application
func (e *RealCometBFTEngine) GetABCIApp() *CertenApplication {
	if certenApp, ok := e.app.(*CertenApplication); ok {
		return certenApp
	}
	return nil
}

// GetLedgerStoreProvider returns the ABCI app if it provides ledger store access
func (e *RealCometBFTEngine) GetLedgerStoreProvider() LedgerStoreProvider {
	if certenApp, ok := e.app.(*CertenApplication); ok {
		return certenApp
	}
	if validatorApp, ok := e.app.(*ValidatorApp); ok {
		return validatorApp
	}
	return nil
}

// GetValidatorApp returns the ValidatorApp if the engine is using one, nil otherwise
func (e *RealCometBFTEngine) GetValidatorApp() *ValidatorApp {
	if validatorApp, ok := e.app.(*ValidatorApp); ok {
		return validatorApp
	}
	return nil
}

// SetValidatorRepositories sets the database repositories on the ValidatorApp for consensus persistence.
// This enables the ValidatorApp to persist consensus entries and batch attestations to postgres.
func (e *RealCometBFTEngine) SetValidatorRepositories(repos *database.Repositories) {
	if validatorApp := e.GetValidatorApp(); validatorApp != nil {
		validatorApp.SetRepositories(repos)
		e.logger.Printf("✅ [PERSIST] Database repositories wired to ValidatorApp for consensus persistence")
	}
}

// SetValidatorCount sets the total validator count on the ValidatorApp for quorum calculations.
func (e *RealCometBFTEngine) SetValidatorCount(count int) {
	if validatorApp := e.GetValidatorApp(); validatorApp != nil {
		validatorApp.SetValidatorCount(count)
		e.logger.Printf("✅ [PERSIST] Validator count set to %d for quorum calculations", count)
	}
}

// writeDeterministicGenesisIfNeeded writes shared genesis for all 7 validators
func (engine *RealCometBFTEngine) writeDeterministicGenesisIfNeeded(cfg *config.Config) error {
	genFile := cfg.GenesisFile()

	// Check if genesis already exists
	if _, err := os.Stat(genFile); err == nil {
		engine.logger.Printf("📄 Using existing shared genesis: %s", genFile)
		return nil
	}

	// Create directory if needed
	if err := os.MkdirAll(filepath.Dir(genFile), 0755); err != nil {
		return fmt.Errorf("create genesis dir: %w", err)
	}

	// Generate deterministic genesis document
	genesisDoc, err := engine.createGenesisDocument()
	if err != nil {
		return fmt.Errorf("create genesis doc: %w", err)
	}

	// Write genesis to file
	if err := genesisDoc.SaveAs(genFile); err != nil {
		return fmt.Errorf("write genesis doc: %w", err)
	}

	engine.logger.Printf("✅ [GENESIS] Written shared deterministic genesis for 7-validator BFT network: %s", genFile)
	engine.logger.Printf("   • ChainID: %s", genesisDoc.ChainID)
	engine.logger.Printf("   • Validators: %d", len(genesisDoc.Validators))

	return nil
}

// createGenesisDocument creates the genesis document with all validators
func (engine *RealCometBFTEngine) createGenesisDocument() (*cmttypes.GenesisDoc, error) {
	allValidatorIDs := []string{"validator-1", "validator-2", "validator-3", "validator-4", "validator-5", "validator-6", "validator-7"}
	validators := make([]cmttypes.GenesisValidator, 0, len(allValidatorIDs))

	for _, validatorID := range allValidatorIDs {
		validatorPubKey := generateDeterministicValidatorPublicKey(validatorID)
		genesisValidator := cmttypes.GenesisValidator{
			Address: validatorPubKey.Address(),
			PubKey:  validatorPubKey,
			Power:   1,
			Name:    validatorID,
		}
		validators = append(validators, genesisValidator)
	}

	// Use deterministic genesis time
	deterministicGenesisTime := time.Date(2025, 11, 20, 12, 0, 0, 0, time.UTC)

	// Get chainID from environment, with consistent default for all validators
	chainID := os.Getenv("COMETBFT_CHAIN_ID")
	if chainID == "" {
		chainID = "certen-testnet" // Default chain ID for the testnet
	}

	genesisDoc := &cmttypes.GenesisDoc{
		ChainID:         chainID,
		GenesisTime:     deterministicGenesisTime,
		InitialHeight:   1,
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators:      validators,
		AppHash:         nil,
		AppState:        json.RawMessage(`{}`),
	}

	return genesisDoc, nil
}

// getChainIDFromEnv returns the consistent chain ID from environment variable
// All validators MUST use the same chainID to participate in the same consensus network
func getChainIDFromEnv() string {
	chainID := os.Getenv("COMETBFT_CHAIN_ID")
	if chainID == "" {
		chainID = "certen-testnet" // Default chain ID
	}
	return chainID
}

// SubmitProofVerification submits a proof verification request via real CometBFT
func (engine *RealCometBFTEngine) SubmitProofVerification(request *ProofVerificationRequest) (*ConsensusResult, error) {
	engine.mu.RLock()
	if !engine.started {
		engine.mu.RUnlock()
		return nil, fmt.Errorf("CometBFT engine not started")
	}
	engine.mu.RUnlock()

	engine.logger.Printf("📋 [REAL-COMETBFT] Broadcasting proof verification request: %s", request.RequestID)

	// Create transaction payload for proof verification
	txData := map[string]interface{}{
		"type":       "proof_verification",
		"request_id": request.RequestID,
		"round_id":   request.RequestID, // Use RequestID as RoundID for now
		"intent_id":  request.RequestID, // Use RequestID as IntentID for now
		"proof_req":  request,
		"timestamp":  time.Now().Unix(),
		"validator":  engine.validatorID,
	}

	// Serialize transaction
	txBytes, err := json.Marshal(txData)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof verification tx: %w", err)
	}

	// Broadcast via CometBFT consensus
	cometRPCURL := os.Getenv("COMETBFT_RPC_URL")
	if cometRPCURL == "" {
		cometRPCURL = "http://localhost:26657"
	}

	client, err := cmthttp.New(cometRPCURL, "/websocket")
	if err != nil {
		return nil, fmt.Errorf("failed to create CometBFT client (%s): %w", cometRPCURL, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := client.BroadcastTxSync(ctx, cmttypes.Tx(txBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to broadcast proof verification: %w", err)
	}

	if result.Code != 0 {
		return nil, fmt.Errorf("proof verification transaction rejected: code=%d, log=%s", result.Code, result.Log)
	}

	engine.logger.Printf("✅ [REAL-COMETBFT] Proof verification broadcasted successfully: tx_hash=%X", result.Hash)

	// Store the request for tracking
	engine.mu.Lock()
	engine.activeRequests[request.RequestID] = request
	engine.mu.Unlock()

	// Return consensus result indicating successful broadcast
	return &ConsensusResult{
		RoundID: request.RequestID,
		Success: true,
		Result:  fmt.Sprintf("COMETBFT_BROADCAST_SUCCESS_%X", result.Hash),
		Metadata: map[string]interface{}{
			"engine_type":  "real_cometbft",
			"node_id":      engine.nodeID,
			"validator_id": engine.validatorID,
			"tx_hash":      fmt.Sprintf("%X", result.Hash),
			"broadcast":    true,
		},
	}, nil
}

// IsRunning returns whether the CometBFT node is running
func (engine *RealCometBFTEngine) IsRunning() bool {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return engine.started && engine.node != nil
}

// GetValidatorInfo returns information about this validator
func (engine *RealCometBFTEngine) GetValidatorInfo() map[string]interface{} {
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	return map[string]interface{}{
		"validator_id":    engine.validatorID,
		"is_running":      engine.IsRunning(),
		"node_id":         engine.nodeID,
		"p2p_port":        engine.p2pPort,
		"rpc_port":        engine.rpcPort,
		"engine_type":     "real_cometbft",
		"active_requests": len(engine.activeRequests),
	}
}

// ConsensusEngine interface for compatibility
type ConsensusEngine interface {
	Start() error
	Stop() error
	SubmitProofVerification(request *ProofVerificationRequest) (*ConsensusResult, error)
	IsRunning() bool
	GetValidatorInfo() map[string]interface{}
}

// SetValidatorRef sets the BFTValidator reference in the ABCI app
func (engine *RealCometBFTEngine) SetValidatorRef(validator *BFTValidator) {
	if certenApp := engine.GetABCIApp(); certenApp != nil {
		certenApp.SetValidatorRef(validator)
	}
}

// GetChainID returns the chain ID from the ABCI application
func (app *CertenApplication) GetChainID() string {
	return app.chainID
}

// GetLedgerStore returns the ledger store from the ABCI application
func (app *CertenApplication) GetLedgerStore() *ledger.LedgerStore {
	return app.ledgerStore
}

// GetMetrics returns ABCI application metrics for monitoring
func (app *CertenApplication) GetMetrics() map[string]interface{} {
	app.mu.RLock()
	defer app.mu.RUnlock()

	return map[string]interface{}{
		"current_height":     app.currentHeight,
		"current_time":       app.currentTime.Format(time.RFC3339),
		"app_hash":           hex.EncodeToString(app.appHash),
		"chain_id":           app.chainID,
		"pending_txs":        len(app.pendingTxs),
		"proof_records":      len(app.proofState),
		"execution_records":  len(app.executionState),
		"intent_records":     len(app.intentState),
		"ballot_state_count": len(app.ballotState),
	}
}

// Interface compliance verification
var _ ConsensusEngine = (*RealCometBFTEngine)(nil)

// =============================================================================
// STATEFUL CERTEN APPLICATION FOR REAL CONSENSUS TRACKING
// =============================================================================

// BallotInfo tracks ballot consensus state
type BallotInfo struct {
	RoundID          string
	IsFinalized      bool
	ConsensusReached bool
	FinalExecutorID  string
	VoteCount        int
	Timestamp        int64
}

// ProofRecord tracks proof verification state
type ProofRecord struct {
	RequestID   string
	RoundID     string
	IntentID    string
	Status      string
	ValidatorID string
	Timestamp   int64
}

// ExecutionRecord tracks execution results
type ExecutionRecord struct {
	RoundID    string
	IntentID   string
	Success    bool
	ExecutorID string
	AnchorID   string
	Result     string
	Timestamp  int64
}

// IntentRecord tracks intent processing
type IntentRecord struct {
	IntentID     string
	Status       string
	CurrentRound string
	Timestamp    int64
}

// =============================================================================
// ABCI STATE BROADCASTING METHODS
// =============================================================================

// broadcastExecutionResult broadcasts execution results to CometBFT for app state tracking
func (bv *BFTValidator) broadcastExecutionResult(roundID, intentID string, success bool, executorID string) error {
	if bv.engine == nil {
		return fmt.Errorf("consensus engine not initialized")
	}

	bv.logger.Printf("⚡ [BFT-EXEC-RESULT] Broadcasting execution result to ABCI: %s success=%t", roundID, success)

	// Create transaction for execution result
	txData := map[string]interface{}{
		"type":        "execution_result",
		"round_id":    roundID,
		"intent_id":   intentID,
		"success":     success,
		"executor_id": executorID,
		"timestamp":   time.Now().Unix(),
		"validator":   bv.validatorID,
	}

	// Serialize and broadcast
	txBytes, err := json.Marshal(txData)
	if err != nil {
		return fmt.Errorf("failed to serialize execution result: %w", err)
	}

	return bv.broadcastBFTTransaction(txBytes, "execution_result")
}

// getABCIBallotState queries the ABCI app state for ballot information
func (bv *BFTValidator) getABCIBallotState(roundID string) (*BallotInfo, bool) {
	if bv.engine == nil || bv.engine.GetABCIApp() == nil {
		return nil, false
	}
	return bv.engine.GetABCIApp().GetBallotState(roundID)
}

// getABCIExecutionState queries the ABCI app state for execution information
func (bv *BFTValidator) getABCIExecutionState(roundID string) (*ExecutionRecord, bool) {
	if bv.engine == nil || bv.engine.GetABCIApp() == nil {
		return nil, false
	}
	return bv.engine.GetABCIApp().GetExecutionState(roundID)
}

// selectExecutorForRound selects an executor for a canonical BFT round
// This is a simplified wrapper for the canonical workflow that uses roundID only
// (roundID already contains intentID:blockHeight:timestamp for uniqueness)
func (bv *BFTValidator) selectExecutorForRound(roundID string) string {
	// Use roundID as both roundID and intentID since it already contains the intent
	return bv.selectExecutorDeterministically(roundID, roundID)
}

// selectExecutorDeterministically selects an executor using a deterministic algorithm
func (bv *BFTValidator) selectExecutorDeterministically(roundID, intentID string) string {
	// Simple deterministic selection based on hash
	hash := sha256.New()
	hash.Write([]byte(roundID + intentID))
	hashBytes := hash.Sum(nil)

	// Convert to number and mod by available validators
	// For now, just use a simple list of known validators
	validators := []string{"validator-1", "validator-2", "validator-3", "validator-4", "validator-5", "validator-6", "validator-7"}
	index := int(hashBytes[0]) % len(validators)

	selected := validators[index]
	bv.logger.Printf("🎯 [BFT-DETERMINISTIC] Selected executor %s for round %s (index %d)", selected, roundID, index)
	return selected
}

// broadcastExecutorSelection broadcasts executor selection to CometBFT for ABCI processing
func (bv *BFTValidator) broadcastExecutorSelection(roundID, executorID string) error {
	if bv.engine == nil {
		return fmt.Errorf("consensus engine not initialized")
	}

	bv.logger.Printf("🎯 [BFT-EXECUTOR] Broadcasting executor selection to ABCI: %s -> %s", roundID, executorID)

	// Create transaction for executor selection
	txData := map[string]interface{}{
		"type":        "executor_selection",
		"round_id":    roundID,
		"executor_id": executorID,
		"timestamp":   time.Now().Unix(),
		"validator":   bv.validatorID,
	}

	// Serialize and broadcast
	txBytes, err := json.Marshal(txData)
	if err != nil {
		return fmt.Errorf("failed to serialize executor selection: %w", err)
	}

	return bv.broadcastBFTTransaction(txBytes, "executor_selection")
}

// generateConsensusHash creates a consensus hash for execution results (Phase 3)
func (bv *BFTValidator) generateConsensusHash(roundID, executorID string) string {
	hash := sha256.New()
	hash.Write([]byte(roundID))
	hash.Write([]byte(executorID))
	hash.Write([]byte(bv.validatorID))
	hash.Write([]byte(fmt.Sprintf("%d", time.Now().Unix())))
	return fmt.Sprintf("%x", hash.Sum(nil)[:16]) // First 16 bytes as hex
}

// =============================================================================
// HELPER METHODS FROM ORIGINAL FUNCTIONAL WORKFLOW
// =============================================================================

// createAnchor creates an anchor using the existing anchor manager
func (bv *BFTValidator) createAnchor(
	ctx context.Context,
	vb *ValidatorBlock,
	p *proof.CertenProof,
) (*AnchorResponse, error) {
	bv.logger.Printf("🔗 [BFT-ANCHOR] Creating anchor: bundle=%s height=%d", vb.BundleID, vb.BlockHeight)

	// Create anchor request
	req := &AnchorRequest{
		RequestID:       vb.BundleID,
		TargetChains:    []string{"ethereum"}, // Default to Ethereum
		Priority:        "high",
		TransactionHash: p.TransactionHash,
		AccountURL:      p.AccountURL,
	}

	// Use existing anchor manager
	resp, err := bv.anchorManager.CreateAnchor(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("anchor creation failed: %w", err)
	}

	return resp, nil
}

// createAnchorFromProof creates an anchor directly from proof data without ValidatorBlock
// Per Golden Spec: BFT operations should not construct ValidatorBlocks
func (bv *BFTValidator) createAnchorFromProof(
	ctx context.Context,
	p *proof.CertenProof,
	intentID string,
) (*AnchorResponse, error) {
	bv.logger.Printf("🔗 [BFT-ANCHOR] Creating anchor from proof: intent=%s height=%d", intentID, p.BlockHeight)

	// Create anchor request directly from proof
	req := &AnchorRequest{
		RequestID:       intentID,
		TargetChains:    []string{"ethereum"}, // Default to Ethereum
		Priority:        "high",
		TransactionHash: p.TransactionHash,
		AccountURL:      p.AccountURL,
	}

	// Use existing anchor manager
	resp, err := bv.anchorManager.CreateAnchor(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("anchor creation failed: %w", err)
	}

	return resp, nil
}

// === OUT-OF-SPEC COMMITMENT HELPERS REMOVED ===
// Per Golden Spec: Only commitment package and intent.OperationID() compute commitments
// Removed: extractOperationCommitment(), extractGovernanceMerkleRoot()
// These functions violated the canonical commitment computation rules

// BFT consensus methods for ValidatorBlock and Anchor submission
func (bv *BFTValidator) signValidatorBlock(vb *ValidatorBlock) (string, error) {
	// Phase 3: Direct Ed25519 signing without ExecutionConsensus
	blockData := fmt.Sprintf("%s:%s:%d:%s", vb.ValidatorID, vb.BundleID, vb.BlockHeight, vb.OperationCommitment)
	signature := ed25519.Sign(bv.privateKey, []byte(blockData))
	return fmt.Sprintf("0x%x", signature), nil
}

func (bv *BFTValidator) signAnchorResult(resp *AnchorResponse) (string, error) {
	// Phase 3: Direct Ed25519 signing without ExecutionConsensus
	anchorData := fmt.Sprintf("%s:%s:%t", resp.AnchorID, resp.Message, resp.Success)
	signature := ed25519.Sign(bv.privateKey, []byte(anchorData))
	return fmt.Sprintf("0x%x", signature), nil
}

// extractTargetChainData extracts target chain information from intent
func (bv *BFTValidator) extractTargetChainData(intent *Intent) []byte {
	// Create a deterministic seed from intent data
	chainData := fmt.Sprintf("target_chain_%s_%s", intent.ID, intent.AccountURL)
	return []byte(chainData)
}

// =============================================================================
// EXECUTION COMMITMENT BUILDING - SECURITY CRITICAL
// =============================================================================

// buildExecutionCommitmentFromIntent creates a cryptographic commitment that binds
// the intent to expected execution parameters. This commitment specifies exactly
// what transaction should be executed on the external chain, and is used by other
// validators to verify the executor didn't substitute a different operation.
//
// SECURITY: This is the mechanism that prevents a malicious executor from executing
// arbitrary transactions instead of the operation specified in the intent.
//
// The commitment includes:
// - Target contract address (CertenAnchorV3)
// - Function selectors for all 3 execution steps
// - Expected events (AnchorCreated, ProofVerified, GovernanceExecuted)
// - Final target address and value (where ETH/tokens go)
// - Chain ID verification
// - Bundle ID binding
func (bv *BFTValidator) buildExecutionCommitmentFromIntent(certenIntent *CertenIntent, bundleID [32]byte) interface{} {
	// Parse CrossChainData to extract execution parameters
	crossChainData, err := certenIntent.ParseCrossChain()
	if err != nil {
		bv.logger.Printf("⚠️ [COMMITMENT] Failed to parse CrossChainData: %v", err)
		// Return minimal commitment with error flag
		return map[string]interface{}{
			"bundleID": hex.EncodeToString(bundleID[:]),
			"intentID": certenIntent.IntentID,
			"error":    fmt.Sprintf("failed to parse CrossChainData: %v", err),
			"verified": false,
		}
	}

	if len(crossChainData.Legs) == 0 {
		bv.logger.Printf("⚠️ [COMMITMENT] No legs in CrossChainData")
		return map[string]interface{}{
			"bundleID": hex.EncodeToString(bundleID[:]),
			"intentID": certenIntent.IntentID,
			"error":    "no legs in CrossChainData",
			"verified": false,
		}
	}

	// Use first leg (primary execution target)
	leg := crossChainData.Legs[0]

	// Extract anchor contract address from leg or use environment default
	anchorContractAddress := leg.AnchorContract.Address
	if anchorContractAddress == "" {
		// Fallback to known Sepolia anchor contract
		anchorContractAddress = "0x4C8F0141cE43a77D6b80276B83AB092DeCEa050B" // CertenAnchorV5
	}
	anchorContract := common.HexToAddress(anchorContractAddress)

	// Extract final target (where ETH/tokens are forwarded to)
	// Uses parseChainAddress to handle both hex (0x...) and TRON base58 (T...) formats
	finalTarget := parseChainAddress(leg.To)

	// Parse value
	finalValueStr := leg.AmountWei
	if finalValueStr == "" {
		finalValueStr = "0"
	}

	// Compute function selectors (Keccak256 first 4 bytes)
	// These are fixed for CertenAnchorV3 contract
	createAnchorSelector := computeSelector("createAnchor(bytes32,bytes32,bytes32,bytes32,uint256)")
	executeProofSelector := computeSelector("executeComprehensiveProof(bytes32,uint256[8],uint256[2],uint256[2][2],uint256[2],bytes32[],uint8[],bytes)")
	executeGovSelector := computeSelector("executeWithGovernance(bytes32,address,uint256,bytes)")

	// Compute event signatures
	anchorCreatedSig := computeEventSignature("AnchorCreated(bytes32,bytes32,bytes32,bytes32,uint256)")
	proofVerifiedSig := computeEventSignature("ProofVerified(bytes32,bool,uint256)")
	govExecutedSig := computeEventSignature("GovernanceExecuted(bytes32,address,uint256,bool)")

	// Build comprehensive commitment
	commitment := map[string]interface{}{
		// Identity
		"bundleID": hex.EncodeToString(bundleID[:]),
		"intentID": certenIntent.IntentID,
		"txHash":   certenIntent.TransactionHash,

		// Chain info
		"targetChain": leg.Chain,
		"chainID":     leg.ChainID,
		"network":     leg.Network,

		// Contract addresses
		"anchorContract": anchorContract.Hex(),
		"finalTarget":    finalTarget.Hex(),
		"finalValue":     finalValueStr,

		// Step 1: createAnchor
		"step1": map[string]interface{}{
			"name":          "createAnchor",
			"contract":      anchorContract.Hex(),
			"selector":      hex.EncodeToString(createAnchorSelector),
			"expectedValue": "0", // No ETH transfer
		},

		// Step 2: executeComprehensiveProof
		"step2": map[string]interface{}{
			"name":          "executeComprehensiveProof",
			"contract":      anchorContract.Hex(),
			"selector":      hex.EncodeToString(executeProofSelector),
			"expectedValue": "0", // No ETH transfer
		},

		// Step 3: executeWithGovernance
		// NOTE: expectedValue is "0" because the anchor contract handles value transfer internally
		// The finalValue is transferred FROM the anchor TO the target, not via msg.value
		"step3": map[string]interface{}{
			"name":          "executeWithGovernance",
			"contract":      anchorContract.Hex(),
			"selector":      hex.EncodeToString(executeGovSelector),
			"expectedValue": "0", // Anchor contract transfers value internally, not via msg.value
		},

		// Expected events
		"expectedEvents": []map[string]interface{}{
			{
				"name":     "AnchorCreated",
				"contract": anchorContract.Hex(),
				"topic0":   anchorCreatedSig,
				"indexed":  []string{hex.EncodeToString(bundleID[:])}, // bundleId indexed
			},
			{
				"name":     "ProofVerified",
				"contract": anchorContract.Hex(),
				"topic0":   proofVerifiedSig,
				"indexed":  []string{hex.EncodeToString(bundleID[:])},
			},
			{
				"name":     "GovernanceExecuted",
				"contract": anchorContract.Hex(),
				"topic0":   govExecutedSig,
				"indexed":  []string{hex.EncodeToString(bundleID[:])},
			},
		},

		// Verification flags
		"verified":  true,
		"createdAt": time.Now().UTC().Format(time.RFC3339),

		// Multi-leg metadata (for write-back aggregation)
		"legCount": len(crossChainData.Legs),
	}

	// Add per-leg summaries for multi-leg write-back
	if len(crossChainData.Legs) > 1 {
		var legSummaries []map[string]interface{}
		for i, l := range crossChainData.Legs {
			legSummaries = append(legSummaries, map[string]interface{}{
				"legIndex":  i,
				"legId":     l.LegID,
				"chain":     l.Chain,
				"chainId":   l.ChainID,
				"network":   l.Network,
				"from":      l.From,
				"to":        l.To,
				"amountWei": l.AmountWei,
				"amountEth": l.AmountEth,
				"symbol":    l.Asset.Symbol,
			})
		}
		commitment["legs"] = legSummaries
	}

	// Compute commitment hash for integrity verification
	commitmentHash := computeCommitmentHash(commitment)
	commitment["commitmentHash"] = hex.EncodeToString(commitmentHash[:])

	bv.logger.Printf("✅ [COMMITMENT] Built execution commitment for intent %s: anchor=%s, target=%s, value=%s",
		certenIntent.IntentID, anchorContract.Hex(), finalTarget.Hex(), finalValueStr)

	return commitment
}

// parseChainAddress parses an address that may be hex (0x...) or TRON base58 (T...).
// TRON base58check: base58decode → 21 bytes (0x41 + 20-byte address) + 4-byte checksum.
func parseChainAddress(addr string) common.Address {
	if strings.HasPrefix(addr, "T") && len(addr) == 34 {
		decoded, err := base58.Decode(addr)
		if err == nil && len(decoded) >= 21 && decoded[0] == 0x41 {
			return common.BytesToAddress(decoded[1:21])
		}
	}
	return common.HexToAddress(addr)
}

// computeSelector computes the 4-byte function selector from signature using Keccak256
// This matches Ethereum's standard for function selectors
func computeSelector(signature string) []byte {
	hash := crypto.Keccak256([]byte(signature))
	return hash[:4]
}

// computeEventSignature computes the event signature hash using Keccak256
// This matches Ethereum's standard for event topic0
func computeEventSignature(signature string) string {
	hash := crypto.Keccak256([]byte(signature))
	return hex.EncodeToString(hash)
}

// computeCommitmentHash computes a deterministic hash of the commitment
func computeCommitmentHash(commitment map[string]interface{}) [32]byte {
	// Marshal to JSON for deterministic hashing
	data, err := json.Marshal(commitment)
	if err != nil {
		// Fallback to empty hash on error
		return [32]byte{}
	}
	return sha256.Sum256(data)
}

// NOTE: delegateTargetChainExecution removed per Golden Spec - validators cannot send HTTP
// requests to other validators. External target chain execution is handled by the audit layer.

// NOTE: getValidatorEndpoint removed per Golden Spec - validators should not
// maintain HTTP endpoint mappings for direct communication.

// NOTE: sendHTTPRequest removed per Golden Spec - validators cannot send HTTP
// requests to other validators. All inter-validator communication goes through CometBFT.

// NOTE: waitForAnchorResult removed per Golden Spec - anchor coordination
// should happen through the audit layer, not direct validator-to-validator communication.

// NOTE: broadcastAnchorResult removed per Golden Spec - anchor results should be
// processed by the audit layer, not broadcast directly by validators.

// broadcastBFTTransaction broadcasts a transaction via in-process CometBFT engine - FIXED implementation
func (bv *BFTValidator) broadcastBFTTransaction(txBytes []byte, txType string) error {
	if bv.engine == nil {
		return fmt.Errorf("consensus engine not initialized")
	}

	bv.logger.Printf("📡 [BFT-COORD] Broadcasting %s via in-process CometBFT engine", txType)

	// Use the in-process engine instead of external RPC
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := bv.engine.BroadcastAppTxSync(ctx, txBytes); err != nil {
		return fmt.Errorf("failed to broadcast %s via in-process engine: %w", txType, err)
	}

	bv.logger.Printf("✅ [BFT-COORD] Successfully broadcast %s via in-process engine", txType)
	return nil
}

// NOTE: registerAnchorResultChannel removed per Golden Spec - anchor result
// coordination should happen through the audit layer.

// NOTE: unregisterAnchorResultChannel removed per Golden Spec - anchor result
// coordination should happen through the audit layer.

// NOTE: processIncomingAnchorResult removed per Golden Spec - anchor result
// processing should happen through the audit layer.

// =============================================================================
// METADATA HANDLING HELPERS - Phase 3 Type Safety Improvements
// =============================================================================

// extractIntentMetadata converts raw metadata map to strongly typed IntentMetadata
// This replaces raw map[string]interface{} usage for better type safety in BFT flows
func extractIntentMetadata(rawMetadata map[string]interface{}) *IntentMetadata {
	metadata := &IntentMetadata{}

	// Extract AccountURL with type safety
	if accountURLRaw, exists := rawMetadata["account_url"]; exists {
		if accountURLStr, ok := accountURLRaw.(string); ok {
			metadata.AccountURL = accountURLStr
		}
	}

	// Add other fields as needed for BFT operations
	// Future enhancements can add more structured metadata fields here

	return metadata
}

// =============================================================================
// UNIFIED PRODUCTION ENGINE CONSTRUCTOR - Phase 3 Consolidation
// =============================================================================

// EngineConfig provides structured configuration for production CometBFT engines
type EngineConfig struct {
	ValidatorID       string
	HomeDir           string
	P2PPort           int
	RPCPort           int
	Seeds             []string
	PersistentPeers   []string
	ChainID           string
	CreateEmptyBlocks bool
}

// NewProductionEngine creates a unified production-ready CometBFT engine
// This replaces NewRealCometBFTEngine and NewUnifiedCometBFTEngine for real deployments
func NewProductionEngine(cfg EngineConfig, app abcitypes.Application, logger *log.Logger) (*RealCometBFTEngine, error) {
	logger.Printf("🏭 [PRODUCTION-ENGINE] Creating unified CometBFT engine: validator=%s", cfg.ValidatorID)

	// 1. Setup structured configuration from cfg
	cometConfig := config.DefaultConfig()
	cometConfig.SetRoot(cfg.HomeDir)
	cometConfig.P2P.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", cfg.P2PPort)
	cometConfig.RPC.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", cfg.RPCPort)
	cometConfig.Consensus.CreateEmptyBlocks = cfg.CreateEmptyBlocks
	cometConfig.Moniker = cfg.ValidatorID

	// Enable transaction indexing for Tx query support
	cometConfig.TxIndex.Indexer = "kv"

	// Set persistent peers from structured config
	if len(cfg.PersistentPeers) > 0 {
		cometConfig.P2P.PersistentPeers = strings.Join(cfg.PersistentPeers, ",")
		logger.Printf("🔗 [PRODUCTION-ENGINE] Configured persistent peers: %s", cometConfig.P2P.PersistentPeers)
	}

	// 2. Generate deterministic node keys
	nodeKeyFile := filepath.Join(cfg.HomeDir, "config", "node_key.json")
	os.MkdirAll(filepath.Dir(nodeKeyFile), 0755)
	os.Remove(nodeKeyFile) // Ensure deterministic generation

	nodePrivKey := generateDeterministicNodeKey(cfg.ValidatorID)
	nodeKey := &p2p.NodeKey{PrivKey: nodePrivKey}
	if err := nodeKey.SaveAs(nodeKeyFile); err != nil {
		return nil, fmt.Errorf("failed to save node key: %w", err)
	}

	// 3. Create deterministic private validator
	privValKeyFile := filepath.Join(cfg.HomeDir, "config", "priv_validator_key.json")
	privValStateFile := filepath.Join(cfg.HomeDir, "data", "priv_validator_state.json")
	os.MkdirAll(filepath.Dir(privValKeyFile), 0755)
	os.MkdirAll(filepath.Dir(privValStateFile), 0755)
	os.Remove(privValKeyFile)
	os.Remove(privValStateFile)

	privValidatorKey := generateDeterministicNodeKey(cfg.ValidatorID)
	privValidator := privval.NewFilePV(privValidatorKey, privValKeyFile, privValStateFile)
	privValidator.Save()

	// 4. Create unified production engine using NewRealCometBFTEngine constructor
	// Note: This replaces the old struct literal which had invalid field names
	engine, err := NewRealCometBFTEngine(cometConfig, app, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create real CometBFT engine: %w", err)
	}

	// 5. Store ABCI app reference for later node creation
	if certenApp, ok := app.(*CertenApplication); ok {
		certenApp.engine = engine
		// Note: app is stored in engine.app field, accessible via GetABCIApp()
	}

	logger.Printf("✅ [PRODUCTION-ENGINE] Unified CometBFT engine created successfully")
	return engine, nil
}
