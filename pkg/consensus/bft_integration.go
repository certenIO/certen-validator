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
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/entitlement"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
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
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/ethereum/go-ethereum/common"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/kvdb"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
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

// Why an intent that is not permanently invalid failed, for the lifecycle's failure class (RB4-F13).
var (
	// ErrNotEntitled is an intent whose principal holds no CERTEN entitlement.
	ErrNotEntitled = errors.New("principal is not entitled to CERTEN execution")
	// ErrGovernanceUnsatisfied is an intent whose governance proof shows it lacks the authority it needs.
	ErrGovernanceUnsatisfied = errors.New("governance unsatisfied")
	// ErrGovernanceUnavailable is a governance proof that could not be produced - not a verdict on the intent.
	ErrGovernanceUnavailable = errors.New("governance proof unavailable")
)

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

// SigningKeyPageResolver names the key page that actually signed an intent's Accumulate
// transaction.
//
// G1 is built against one named page: its genesis is replayed to the execution block and its
// threshold is the threshold the proof reports, and the page's URL is hashed into the govRoot. So
// the page must be the one that authorised the transaction, established from the chain. It used to
// be GUESSED: the governance blob's required_key_page is the intent builder's template
// "<adi>/book/page" for multi-leg intents, and resolveKeyPageURL repaired that by string rule to
// "<book>/1". Under the Business Transaction Controls books (humans on page 1, the machine key on
// page 2) an automated payment is signed by page 2, so G1 named a page that did not sign.
//
// Implemented by proof.ChainKeyPageResolver. An error means no page of the book signed the
// transaction, and the caller must fail the proof rather than name a page.
type SigningKeyPageResolver interface {
	ResolveSigningKeyPage(ctx context.Context, principal, txHash, keyBook, declaredPage string) (string, error)
}

// resolveSigningKeyPage names the page G1 is built against, or fails.
//
// There is no fallback. A validator without a resolver cannot establish the page, and naming one
// anyway is exactly the guess this replaces.
func (bv *BFTValidator) resolveSigningKeyPage(ctx context.Context, ci *CertenIntent, gov *GovernanceData) (string, error) {
	bv.mu.RLock()
	resolver := bv.keyPageResolver
	bv.mu.RUnlock()
	if resolver == nil {
		return "", fmt.Errorf("no signing key page resolver is configured; the key page cannot be " +
			"established from the chain and will not be guessed")
	}
	if ci == nil || gov == nil {
		return "", fmt.Errorf("intent or governance data missing")
	}
	return resolver.ResolveSigningKeyPage(ctx, ci.AccountURL, ci.TransactionHash,
		gov.Authorization.RequiredKeyBook, gov.Authorization.RequiredKeyPage)
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

// ProofCycleOrchestratorInterface starts Phase 7-9 for one settled chain member.
//
// It has one entry point. The commitment names the chain the member settled on ("targetChain", the
// numeric chain id) - there is no default chain and no multi-leg grouping: every cycle is one chain
// member's (RB3-F45). txHashes and commitment are interface{} to avoid an import cycle with execution.
type ProofCycleOrchestratorInterface interface {
	StartProofCycleWithAccumulateRef(ctx context.Context, intentID string, userID string, bundleID [32]byte, txHashes interface{}, commitment interface{}, accumulateAccountURL string, accumulateTxHash string, bvn string) error
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
	// EnqueueForBatch queues one authorized intent in the period lane. Errors: ErrMemberAlreadyQueued
	// (this intent is already queued - not a refusal), ErrOperationAlreadyQueued (a replay),
	// ErrBatchUnavailable (CERTEN cannot settle it now); anything else is the intent's own defect.
	EnqueueForBatch(
		intentID string,
		adiURL string,
		chainID int64,
		account [20]byte,
		operationID [32]byte,
		legs interface{},
		attestation interface{},
		// governanceCommitment commits to who decided the intent (proof.GovernanceCommitment of the round's
		// decision, RB4-F66); the batch operation id aggregates it. It must equal the one the snapshot states.
		governanceCommitment [32]byte,
		commitHeight uint64,
		// commitPartition and commitTime identify the Accumulate minor block the intent was written
		// in (commitHeight is its height on commitPartition) and that block's consensus time. The time
		// is every validator's common clock for the member; zero means discovery could not read it,
		// and the member then resolves it from the partition and height.
		commitPartition string,
		commitTime time.Time,
		// accumTxHash is the Accumulate transaction that carried the intent. Evidence only; the batch
		// path never saw it before, which left canonical rows unable to say which transaction a member
		// came from. Empty is accepted and recorded as empty.
		accumTxHash string,
	) error

	// CheckMember reports whether EnqueueForBatch (onDemand false) or EnqueueOnDemand (onDemand
	// true) would accept the member, without queueing it. Errors are those the enqueues return:
	// ErrOperationAlreadyQueued for a replay, ErrBatchUnavailable for CERTEN's outage, anything else
	// for the intent's own defect. The same intent already queued is not an error here.
	CheckMember(onDemand bool, intentID, adiURL string, chainID int64, account [20]byte,
		operationID [32]byte, legs interface{}, commitHeight uint64) error

	// AnchorOf names the anchor the batch path settles chainID's members on (CERTEN_ANCHOR_V8_<chainId>).
	// An error is CERTEN unable to name it, never the intent's defect.
	AnchorOf(chainID int64) (common.Address, error)

	// EnqueueAfter queues a later member of a sequential cross-chain intent: settled only once its
	// predecessor (the intent's member on after.ChainID, queued first) has its outcome on chain.
	// Same errors as EnqueueForBatch.
	EnqueueAfter(
		intentID string,
		adiURL string,
		chainID int64,
		account [20]byte,
		operationID [32]byte,
		legs interface{},
		attestation interface{},
		// governanceCommitment commits to who decided the intent (proof.GovernanceCommitment of the round's
		// decision, RB4-F66); the batch operation id aggregates it. It must equal the one the snapshot states.
		governanceCommitment [32]byte,
		commitHeight uint64,
		commitPartition string,
		commitTime time.Time,
		accumTxHash string,
		after SequencePredecessor,
	) error

	// RemoveMember takes a member back out of its lane as if it had never been queued, so a
	// multi-chain intent can be rolled back when one of its chains cannot be queued.
	RemoveMember(onDemand bool, intentID string, chainID int64, operationID [32]byte)

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
		// governanceCommitment commits to who decided the intent (proof.GovernanceCommitment of the round's
		// decision, RB4-F66); the batch operation id aggregates it. It must equal the one the snapshot states.
		governanceCommitment [32]byte,
		commitHeight uint64,
		// commitPartition and commitTime identify the Accumulate minor block the intent was written
		// in (commitHeight is its height on commitPartition) and that block's consensus time. The time
		// is every validator's common clock for the member; zero means discovery could not read it,
		// and the member then resolves it from the partition and height.
		commitPartition string,
		commitTime time.Time,
		// accumTxHash is the Accumulate transaction that carried the intent. Evidence only; the batch
		// path never saw it before, which left canonical rows unable to say which transaction a member
		// came from. Empty is accepted and recorded as empty.
		accumTxHash string,
	) error
}

// BFTValidator represents a decentralized BFT validator with elected executor consensus
// Phase 3: BFTValidator now uses only CometBFT for consensus (no ExecutionConsensus)
type BFTValidator struct {
	// memberRepairs: members named for a re-driven proof cycle (RB4-F55 repair, member_repair.go).
	memberRepairState

	engine                BFTConsensusEngine
	anchorManager         AnchorManager
	proofGenerator        ProofGenerator
	governanceProofGen    GovernanceProofGenerator // G0/G1/G2 proof generator (runs AFTER L1-L4)
	keyPageResolver       SigningKeyPageResolver   // names the page G1 is built against, from the chain
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

// SetKeyPageResolver installs the resolver that names the key page G1 is built against. Required
// for governance proofs: without it an intent fails rather than proceeding with a guessed page.
func (bv *BFTValidator) SetKeyPageResolver(r SigningKeyPageResolver) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.keyPageResolver = r
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

	// Every intent, whatever its proof class, is built on its L1-L4 proof. on_cadence used to be built
	// without one, on anchor references that named no block ("pending_anchor_block_<height>",
	// "pending_anchor_tx_<intent>"), no governance and no BLS signature (RB3-F88); discovery already
	// refuses to reach consensus without the proof, so this is where that rule is kept, not assumed.
	if certenProof == nil {
		return nil, fmt.Errorf("%s intent %s reached consensus without its CertenProof; Certen has no degraded proof mode",
			proofClass, certenIntent.IntentID)
	}

	// Handle proof data extraction
	var blsSignature string
	var validatorSignatures []string
	var anchorRef AccumulateAnchorReference
	var liteClientProof *lcproof.CompleteProof

	// Governance proof variables. V6.1 A+++ requires these to be available BEFORE BLS signing.
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
	// PHASE 8 ITEM 2: which counted signatures' ordering rests on execution
	// inclusion rather than on a local block comparison. Taken off the same
	// wrapper as the receipts, for the same reason - the flag it qualifies
	// (ValidatedSignature.TimingVerified) is inside the govRoot preimage and
	// this must never be able to reach it.
	var govTimingBasis []proof.SignatureTimingBasis
	// RB4-F66: who decided the transaction, from the G1 vote record - the record the batch commits to. Beside the
	// results like the receipts: it must not reach G1Result, which is inside the ValidatorBlock's BundleID.
	var govDecision []byte
	var govAuthorization *proof.AuthorizationRecord
	var govVoteEvidence *govvote.Evidence
	var governanceLevel string
	var resolvedKeyPageURL string
	resolvedKeyBookURL := governanceData.Authorization.RequiredKeyBook

	bv.logger.Printf("✅ [CANONICAL-VB] Using real proof data for intent: %s", certenIntent.IntentID)
	blsSignature = certenProof.BLSAggregateSignature
	validatorSignatures = certenProof.ValidatorSignatures

	// The block's Accumulate anchor is the one its proof established, all of it, or there is no block
	// (RB3-F88). A partial proof used to be given "proof_pending_block_<height>" - the CometBFT height
	// standing in for an Accumulate one.
	anchorRef, err = accumulateAnchorOf(certenProof)
	if err != nil {
		return nil, fmt.Errorf("intent %s: %w", certenIntent.IntentID, err)
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
		keyPageURL, keyPageErr := bv.resolveSigningKeyPage(ctx, certenIntent, governanceData)
		if keyPageErr != nil {
			class := ErrGovernanceUnavailable
			if errors.Is(keyPageErr, proof.ErrNoSigningKeyPage) {
				class = ErrGovernanceUnsatisfied
			}
			return nil, fmt.Errorf("%w: governance proof for intent %s cannot name its key page: %w",
				class, certenIntent.IntentID, keyPageErr)
		}
		bv.logger.Printf("🔑 [GOV-PROOF] intent %s signed by key page %s (declared %q)",
			certenIntent.IntentID, keyPageURL, governanceData.Authorization.RequiredKeyPage)
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
			return nil, fmt.Errorf("%w: governance proof requires a key page: "+
				"G1/G2 cannot be established without one, and G0 alone is not a governance proof "+
				"(intent %s)", ErrGovernanceUnsatisfied, certenIntent.IntentID)
		}

		g0ProofWrapper, g0Err := bv.governanceProofGen.GenerateG0(ctx, govRequest)
		if g0Err != nil {
			return nil, fmt.Errorf("%w: G0 governance proof failed for intent %s: %w", ErrGovernanceUnavailable, certenIntent.IntentID, g0Err)
		}
		if g0ProofWrapper == nil || g0ProofWrapper.G0 == nil {
			return nil, fmt.Errorf("%w: G0 governance proof returned no result for intent %s", ErrGovernanceUnavailable, certenIntent.IntentID)
		}
		g0Proof = g0ProofWrapper.G0
		govReceipts = append(govReceipts, g0ProofWrapper.Receipts...)
		if !g0Proof.G0ProofComplete {
			return nil, fmt.Errorf("%w: G0 governance proof incomplete for intent %s", ErrGovernanceUnavailable, certenIntent.IntentID)
		}
		// G0 is final because its receipt is the chained proof's L1
		// receipt, ending at the root the BVN quorum signed, at the block
		// it signed it (pkg/proof/g0_binding.go). Two proofs of one entry
		// that disagree describe different facts.
		if err := proof.BindG0ToChainedProof(g0Proof, liteClientProof); err != nil {
			return nil, fmt.Errorf("%w: G0 governance proof for intent %s does not bind to its chained proof: %w",
				ErrGovernanceUnavailable, certenIntent.IntentID, err)
		}
		governanceLevel = "G0"
		bv.logger.Printf("✅ [GOV-PROOF] G0 proof generated: TXID=%s, ExecMBI=%d, Complete=%v",
			g0Proof.TXID, g0Proof.ExecMBI, g0Proof.G0ProofComplete)

		g1ProofWrapper, g1Err := bv.governanceProofGen.GenerateG1(ctx, govRequest)
		if g1Err != nil {
			class := governanceProofFailureClass(g1Err)
			return nil, fmt.Errorf("%w: G1 governance proof failed for intent %s: %w", class, certenIntent.IntentID, g1Err)
		}
		if g1ProofWrapper == nil || g1ProofWrapper.G1 == nil {
			return nil, fmt.Errorf("%w: G1 governance proof returned no result for intent %s", ErrGovernanceUnavailable, certenIntent.IntentID)
		}
		g1Proof = g1ProofWrapper.G1
		govReceipts = append(govReceipts, g1ProofWrapper.Receipts...)
		govTimingBasis = append(govTimingBasis, g1ProofWrapper.TimingBasis...)
		if !g1Proof.G1ProofComplete || !g1Proof.ThresholdSatisfied {
			return nil, fmt.Errorf("%w: G1 governance proof incomplete for intent %s "+
				"(complete=%v thresholdSatisfied=%v uniqueKeys=%d)",
				ErrGovernanceUnsatisfied, certenIntent.IntentID, g1Proof.G1ProofComplete, g1Proof.ThresholdSatisfied, g1Proof.UniqueValidKeys)
		}
		governanceLevel = "G1"
		bv.logger.Printf("✅ [GOV-PROOF] G1 proof generated: ThresholdSatisfied=%v, UniqueKeys=%d, Complete=%v",
			g1Proof.ThresholdSatisfied, g1Proof.UniqueValidKeys, g1Proof.G1ProofComplete)

		g2ProofWrapper, g2Err := bv.governanceProofGen.GenerateG2(ctx, govRequest)
		if g2Err != nil {
			class := governanceProofFailureClass(g2Err)
			return nil, fmt.Errorf("%w: G2 governance proof failed for intent %s: %w", class, certenIntent.IntentID, g2Err)
		}
		if g2ProofWrapper == nil || g2ProofWrapper.G2 == nil {
			return nil, fmt.Errorf("%w: G2 governance proof returned no result for intent %s", ErrGovernanceUnavailable, certenIntent.IntentID)
		}
		g2Proof = g2ProofWrapper.G2
		govReceipts = append(govReceipts, g2ProofWrapper.Receipts...)
		govTimingBasis = append(govTimingBasis, g2ProofWrapper.TimingBasis...)
		if !g2Proof.G2ProofComplete {
			return nil, fmt.Errorf("%w: G2 governance proof incomplete for intent %s "+
				"(payloadVerified=%v effectVerified=%v): the outcome is not bound, so this is a G1 claim "+
				"and must not be recorded as governance",
				ErrGovernanceUnsatisfied, certenIntent.IntentID, g2Proof.PayloadVerified, g2Proof.EffectVerified)
		}
		governanceLevel = "G2"
		bv.logger.Printf("✅ [GOV-PROOF] G2 proof generated: PayloadVerified=%v, EffectVerified=%v, Complete=%v",
			g2Proof.PayloadVerified, g2Proof.EffectVerified, g2Proof.G2ProofComplete)

		gdr, rec, derr := deriveGovernanceDecision(ctx, g0Proof, g1ProofWrapper, g2ProofWrapper)
		if derr != nil {
			return nil, fmt.Errorf("%w: intent %s: %w", ErrGovernanceUnavailable, certenIntent.IntentID, derr)
		}
		govDecision, govAuthorization, govVoteEvidence = gdr, rec, g1ProofWrapper.VoteEvidence
		commitment := proof.GovernanceCommitment(gdr)
		bv.logger.Printf("🧾 [GOV-DECISION] intent %s: governance decision %x (%d authority/ies)",
			certenIntent.IntentID, commitment[:8], len(rec.Authorities))
	} else {
		// Neither branch may proceed without governance. L1-L4 establishes
		// that the transaction exists; G0-G2 establishes that it was
		// authorised and what it did. Attesting with one and not the other
		// claims more than has been proven.
		if liteClientProof == nil {
			return nil, fmt.Errorf("%w: cannot generate governance proofs for intent %s: "+
				"the L1-L4 lite client proof is not available", ErrGovernanceUnavailable, certenIntent.IntentID)
		}
		if bv.governanceProofGen == nil {
			return nil, fmt.Errorf("%w: cannot generate governance proofs for intent %s: "+
				"the governance proof generator is not configured", ErrGovernanceUnavailable, certenIntent.IntentID)
		}
		return nil, fmt.Errorf("%w: governance proofs were not generated for intent %s", ErrGovernanceUnavailable, certenIntent.IntentID)
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
	certenProof.GovTimingBasis = govTimingBasis
	certenProof.GovDecision = govDecision
	certenProof.GovAuthorization = govAuthorization
	certenProof.GovVoteEvidence = govVoteEvidence
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
			// Refused here by name. It used to be logged and the block refused later by the builder
			// as "ensure BLS key is initialized", whatever the reason had been.
			return nil, fmt.Errorf("intent %s: BLS pre-execution signature: %w", certenIntent.IntentID, err)
		}
		blsSignature = sig
		bv.logger.Printf("🔐 [BLS-SIG-V6.1] Generated A+++ BLS signature for intent %s (gov=%s)",
			certenIntent.IntentID, governanceLevel)
	}
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
			Error: fmt.Errorf("intent %s refused: %w: principal %q has no entitlement evidence",
				certenIntent.IntentID, ErrNotEntitled, principal),
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
	// Placed after the entitlement check and before any money is spent. The
	// deadline is judged at deadlineInstant: an operation this validator already
	// committed at its commit's block time - the same on every node, however late
	// it is processed again (a restart, a repair) - and new work now (RB4-F60).
	// It used to be judged now, always: a committed intent re-derived after its
	// deadline was refused as permanently invalid and its members never proven.
	// ====================================================================
	execValidation, err := executionValidationEnabled()
	if err != nil {
		return &ExecutionTaskResult{Success: false, ExecutorID: bv.validatorID, Error: err}, nil
	}
	if execValidation {
		reader, _ := bv.engine.(committedOperationReader)
		deadlineAt, basis, dErr := deadlineInstant(reader, bv.validatorID, certenIntent, time.Now())
		if dErr != nil {
			// Not a verdict on the intent: whether it committed is unknown, so it is not judged. Retried.
			return &ExecutionTaskResult{Success: false, ExecutorID: bv.validatorID,
				Error: fmt.Errorf("intent %s: its deadline cannot be judged: %w", certenIntent.IntentID, dErr)}, nil
		}
		bv.logger.Printf("⏱️ [EXEC-VALIDATION] intent %s: deadline judged at %s (%s)",
			certenIntent.IntentID, deadlineAt.UTC().Format(time.RFC3339), basis)
		if err := certenIntent.ValidateForExecution(blockHeight, deadlineAt); err != nil {
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

	// ACCOUNT ANCHOR PIN. An intent that would point an account at an anchor CERTEN does not run is
	// refused here, on every validator, before anything is queued or sent - so no honest validator
	// ever signs for it. Not behind the execution-validation switch: it is a safety rule, not a
	// readiness check. See account_anchor_pin.go. With no policy wired, every such intent is refused.
	var anchorPolicy AccountAnchorPolicy
	if p, ok := bv.batchEnqueuer.(AccountAnchorPolicy); ok {
		anchorPolicy = p
	}
	if err := CheckIntentAccountAnchors(anchorPolicy, certenIntent); err != nil {
		bv.logger.Printf("🚫 [ANCHOR-PIN] refusing intent %s: %v", certenIntent.IntentID, err)
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			// PERMANENT: the intent's legs are final on Accumulate and will name the same anchor on
			// every pass.
			Error: fmt.Errorf("intent %s refused: %w: %w", certenIntent.IntentID, ErrIntentPermanentlyInvalid, err),
		}, nil
	}

	// SUPPORTED TARGET CHAINS. CERTEN executes only on Ethereum Sepolia, Base Sepolia and Arbitrum
	// Sepolia; every other chain runs retired contracts. Refused here, on every validator, before
	// anything is queued, signed or sent. See supported_chains.go.
	if err := CheckIntentTargetChains(certenIntent); err != nil {
		bv.logger.Printf("🚫 [TARGET-CHAIN] refusing intent %s: %v", certenIntent.IntentID, err)
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			// PERMANENT: the intent's legs are final on Accumulate and name the same chains on every
			// pass.
			Error: fmt.Errorf("intent %s refused: %w: %w", certenIntent.IntentID, ErrIntentPermanentlyInvalid, err),
		}, nil
	}

	// BATCH SETTLEMENT. The batch path is the only way CERTEN settles an intent. One it cannot
	// settle is refused here, by name, before the validator block is built, signed or broadcast -
	// the same plan and admission rules the enqueue below applies, so the two cannot disagree. See
	// batch_refusal.go.
	if err := bv.checkBatchable(certenIntent, blockHeight); err != nil {
		return bv.refusalResult(certenIntent, err), nil
	}

	// The authorization the governance proof states: the keys G1 counted, from Accumulate (RB3-F139).
	authLeaves, err := authorizationLeavesFromG1(g1Proof)
	if err != nil {
		return nil, fmt.Errorf("intent %s: %w", certenIntent.IntentID, err)
	}

	// Create builder inputs STRICTLY from canonical sources
	builderInputs := BuilderInputs{
		Intent: certenIntent, // canonical 4 blobs from IntentDiscovery
		Governance: GovernanceInputs{
			Leaves:                authLeaves,
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

	// Nothing past this point may act on a ValidatorBlock consensus has not committed (RB3-F98). It used
	// to proceed on CheckTx alone - "CometBFT is expected to commit it shortly" - unless the operator had
	// opted in to failing closed; production had not. A block admitted but not seen committed is
	// a retryable refusal: the resubmission asks the app's committed-operation index first, finds the
	// block committed, and continues from its height without broadcasting it again (RB3-F141).
	if err := requireCommitted(bftRes); err != nil {
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			Error:      err,
		}, nil
	}
	bv.logger.Printf("✅ [CANONICAL-BFT] ValidatorBlock COMMITTED at height %d, tx=%X", bftRes.Height, bftRes.TxHash)

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
	// There is no other path. An intent the batch path cannot settle was already refused by name
	// before signing (checkBatchable); intents on chains CERTEN does not run were refused before
	// that (CheckIntentTargetChains). The per-intent path this used to fall through to could not
	// settle, for the three reasons above, and is gone (owner decision 2026-09-26).
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
	if err := bv.enqueueForBatch(certenIntent, certenProof, vb,
		blockHeight, g0Proof, g1Proof, g2Proof, blsSignature, validatorSignatures,
		governanceLevel, blockHeight); err != nil {
		// checkBatchable accepted this intent before signing, so a refusal here is a race (another
		// intent queued the operation first) or an outage that began since. Still refused by name.
		return bv.refusalResult(certenIntent, err), nil
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

	bv.logger.Printf("⚡ [CANONICAL-BFT] Validator %s is ELECTED EXECUTOR for round %s - intent %s is queued for batch settlement",
		bv.validatorID, roundID, certenIntent.IntentID)

	// The enqueue already happened above, on EVERY validator - see the comment there for why that
	// is load-bearing. All that remains for the elected executor is to stop: the intent settles on
	// the batch period leader's flush, which may be a different node, and executing it here as well
	// would double-spend it.
	return &ExecutionTaskResult{
		Success: true,
		// Queued, not settled. The batch period leader's flush resolves it, possibly on another
		// node, and RunBatchMemberAttestation then carries the terminal outcome. Pending, with no
		// tx hash - there is no transaction yet, and claiming a failure here would be a guess about
		// work that has not started.
		TargetChainOutcome: TargetChainPending,
		ExecutorID:         bv.validatorID,
		ConsensusHash:      fmt.Sprintf("batch_queued_%s_%d", roundID, bftRes.Height),
	}, nil
}

// authorizationLeavesFromG1 builds the governance proof's authorization leaves from the G1 proof: one leaf
// per key whose signature G1 counted - the key page that signed, the SHA-256 of the key (as key pages store
// keys), and the signature itself - in a fixed order. The field is documented as derived from key book
// lookups, and G1 is that lookup: the governing pages read from Accumulate as of execution.
//
// They used to be built from the intent's own declared governance blob, with an invented key hash
// ("<authorization hash>-<i>"), the signer's id where the signature belongs, and a fabricated leaf when the
// intent declared none, so that the consensus invariant requiring leaves would pass (RB3-F139). G1 with a
// satisfied threshold is required before a block is built, so its counted signatures are never empty; a
// proof without them is refused, never given a leaf.
func authorizationLeavesFromG1(g1 *proof.G1Result) ([]AuthorizationLeaf, error) {
	if g1 == nil || !g1.G1ProofComplete || !g1.ThresholdSatisfied {
		return nil, fmt.Errorf("no complete G1 proof with a satisfied threshold to take the authorization from")
	}
	seen := map[string]bool{}
	var leaves []AuthorizationLeaf
	for i, vs := range g1.ValidatedSignatures {
		sig := vs.Signature
		pub, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(sig.PublicKey)), "0x"))
		if err != nil || len(pub) == 0 {
			return nil, fmt.Errorf("G1 counted signature %d carries no readable public key", i)
		}
		if strings.TrimSpace(sig.Signature) == "" || strings.TrimSpace(sig.Signer) == "" {
			return nil, fmt.Errorf("G1 counted signature %d names no signature or signer", i)
		}
		keyHash := sha256.Sum256(pub)
		leaf := AuthorizationLeaf{
			KeyPage:   strings.TrimSpace(sig.Signer),
			KeyHash:   hex.EncodeToString(keyHash[:]),
			Role:      "signer",
			Signature: strings.ToLower(strings.TrimPrefix(strings.TrimSpace(sig.Signature), "0x")),
		}
		id := leaf.KeyPage + "|" + leaf.KeyHash
		if seen[id] {
			continue // one key, one leaf: the vote counts unique keys
		}
		seen[id] = true
		leaves = append(leaves, leaf)
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("G1 counted no signature to state as an authorization")
	}
	sort.Slice(leaves, func(i, j int) bool {
		if leaves[i].KeyPage != leaves[j].KeyPage {
			return leaves[i].KeyPage < leaves[j].KeyPage
		}
		return leaves[i].KeyHash < leaves[j].KeyHash
	})
	return leaves, nil
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

// adoptGenesisForRotation gives the app the genesis validator set that consensus-key rotation is judged
// against (RB3-F95). It never stops the node: a genesis the rotation rules cannot use leaves the app with no
// set, and then every rotation is refused - identically on every node, since they share the genesis - while
// the chain runs exactly as before.
func adoptGenesisForRotation(app *ValidatorApp, genesisFile string, logger *log.Logger) {
	doc, err := cmttypes.GenesisDocFromFile(genesisFile)
	if err == nil {
		err = app.SetGenesis(doc)
	}
	if err != nil {
		logger.Printf("🚨 [ROTATION] the genesis %s cannot be used for validator rotation (%v): every rotation "+
			"will be refused on this chain", genesisFile, err)
		return
	}
	logger.Printf("🔑 [ROTATION] genesis validator set loaded: %d validators, chain %s", len(app.genesisValidators), doc.ChainID)
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
		// Starting fresh under a chain that has history is an app-hash mismatch at the handshake - a
		// crash loop - so the node does not start, and says why (RB3-F114). A genuine first boot has no
		// persisted state and recovers without error.
		return nil, nil, fmt.Errorf("recover the validator ledger: %w", err)
	}

	// Create minimal CometBFT config for ValidatorBlock consensus
	cfg := config.DefaultConfig()
	cfg.RootDir = filepath.Join("/app", "data", "validator-chain", validatorID)
	cfg.P2P.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", p2pPort)
	cfg.RPC.ListenAddress = fmt.Sprintf("tcp://0.0.0.0:%d", rpcPort)
	cfg.Moniker = validatorID
	cfg.DBBackend = "goleveldb"
	cfg.TxIndex.Indexer = "kv" // Enable tx indexing for Tx query support

	adoptGenesisForRotation(app, cfg.GenesisFile(), logger)

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
	// CometBFT's gRPC broadcast API is not served (RB3-F97): the HTTP/2 server behind it is open to
	// GO-2026-6443 (a request without :authority/Host panics the server) and no released grpc fixes it
	// yet. Nothing here sets it; a configuration that does is refused rather than served.
	if cometCfg.RPC != nil && cometCfg.RPC.GRPCListenAddress != "" {
		return nil, fmt.Errorf("the CometBFT gRPC broadcast API (rpc.grpc_laddr %q) is not served: GO-2026-6443", cometCfg.RPC.GRPCListenAddress)
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

	// The genesis is the chain's, provided by the operator; it is never generated here (RB3-F95). A
	// genesis written from code on a wiped volume is a different chain.
	if _, err := os.Stat(cometCfg.GenesisFile()); err != nil {
		return nil, fmt.Errorf("CometBFT genesis %s: %w - it is never generated at boot", cometCfg.GenesisFile(), err)
	}

	// CRITICAL FIX: Enable CometBFT logging to see consensus activity
	tmLogger := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout))
	tmLogger = tmLogger.With("module", "cometbft")

	// Index the committed chain before the node opens its stores: the handshake below replays blocks through
	// FinalizeBlock, and the committed-operation rule judges them against this index (RB3-F141). The check
	// that v9 rules reproduce this history runs here too, so a node never starts on state it would decide
	// differently.
	if va, ok := app.(*ValidatorApp); ok {
		if err := indexCommittedHistoryFromStores(cometCfg, dbProvider, va); err != nil {
			return nil, fmt.Errorf("index the committed chain: %w", err)
		}
	}

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

	// Consensus key, node key, signing state and genesis by the key-management rules (comet_keys.go,
	// RB3-F95): read from the persistent volume, never deleted, never overwritten, never derived from the
	// validator's name; a missing key is re-created only from its secret seed, or the node does not start.
	if _, err := ensureCometKeys(homeDir, validatorID, cometChainIDForFormulaCheck(), os.Getenv, logger); err != nil {
		return nil, fmt.Errorf("CometBFT keys for %s: %w", validatorID, err)
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
		// Starting fresh under a chain that has history is an app-hash mismatch at the handshake - a
		// crash loop - so the node does not start, and says why (RB3-F114). A genuine first boot has no
		// persisted state and recovers without error.
		return nil, fmt.Errorf("recover the validator ledger: %w", err)
	}

	adoptGenesisForRotation(app, cfg.GenesisFile(), logger)

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

	// Has this validator's block for this operation already committed? The app's committed-operation index
	// answers from committed state (RB3-F141). A proposer that did not see its first commit - the inclusion
	// poll gave up, discovery re-drove the intent, a restart forgot it - used to rebuild the block and
	// broadcast it again, and the chain committed it twice.
	app, ok := e.app.(*ValidatorApp)
	if !ok {
		return nil, fmt.Errorf("ValidatorBlocks commit through the ValidatorApp; this engine runs %T", e.app)
	}
	prior, committedThrough, err := app.CommittedOperation(vb.ValidatorID, vb.CrossChainProof.OperationID)
	if err != nil {
		return nil, err
	}
	if prior != nil {
		return alreadyCommitted(vb, prior, e.logger)
	}

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

	// Submit, then confirm inclusion. The outcome is decided by whether the transaction is admitted or
	// committed — looked up by hash when a reply is lost — not by the RPC acknowledgement alone
	// (bft_broadcast_confirm.go).
	return submitValidatorBlock(ctx, e.rpcClient, payload, committedThrough, defaultBroadcastTiming, e.logger)
}

// ErrOperationCommittedAsAnotherBlock is a validator's block for an operation that committed with a
// different bundle than the one just built. The chain holds the committed one; this one is never broadcast.
var ErrOperationCommittedAsAnotherBlock = errors.New("this validator's block for the operation committed as a different bundle")

// alreadyCommitted is the result of a ValidatorBlock whose operation this validator already committed: the
// committed block's height and transaction when it is the same bundle, a refusal naming both when not.
func alreadyCommitted(vb *ValidatorBlock, prior *ledger.CommittedOperation, logger *log.Logger) (*BFTExecutionResult, error) {
	if prior.BundleID != vb.BundleID {
		return nil, fmt.Errorf("%w: operation %s committed at height %d as bundle %s; the rebuilt block is bundle %s",
			ErrOperationCommittedAsAnotherBlock, vb.CrossChainProof.OperationID, prior.Height, prior.BundleID, vb.BundleID)
	}
	txHash, err := hex.DecodeString(prior.TxHash)
	if err != nil {
		return nil, fmt.Errorf("committed operation %s names transaction %q: %w", vb.CrossChainProof.OperationID, prior.TxHash, err)
	}
	logger.Printf("✅ [COMETBFT] ValidatorBlock %s already COMMITTED at height %d (tx %s) - not broadcast again",
		vb.BundleID, prior.Height, prior.TxHash)
	return &BFTExecutionResult{Height: prior.Height, TxHash: txHash, CommittedAt: prior.BlockTime}, nil
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
		// Each validator keeps its own persisted-height watermark (they may share one database), and
		// rebuilds heights it missed from its own block store.
		writerID := e.validatorID
		if writerID == "" {
			writerID = e.nodeID
		}
		validatorApp.EnableConsensusPersistence(repos, writerID,
			&rpcCommittedBlockSource{reader: e.rpcClient})
		e.logger.Printf("✅ [PERSIST] Database repositories wired to ValidatorApp for consensus persistence (writer=%s)", writerID)
	}
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

// buildExecutionCommitmentFromIntent builds the execution commitment of ONE member: what the intent
// commits to on chainID - the chain the member settled on - taken from the signed legs on that chain.
//
// It used to describe the retired per-intent workflow (CertenAnchorV3 createAnchor /
// executeComprehensiveProof / executeWithGovernance and their events) for the intent's FIRST leg,
// whichever chain the member settled on, on the leg's self-declared anchor or a compiled-in retired one,
// and to hash that together with "verified": true and the time it was built - and all of it was written
// back to Accumulate (RB3-F66). The calls a member was settled by are stated by the proof cycle from the
// chain (pkg/execution settlementSteps); this commitment carries only what the signed intent binds, and
// its hash is reproducible from the intent.
func (bv *BFTValidator) buildExecutionCommitmentFromIntent(certenIntent *CertenIntent, bundleID [32]byte, chainID int64) (map[string]interface{}, error) {
	crossChainData, err := certenIntent.ParseCrossChain()
	if err != nil {
		return nil, fmt.Errorf("crossChainData cannot be read: %w", err)
	}
	var member []CCLeg
	for _, l := range crossChainData.Legs {
		if l.ChainID == chainID {
			member = append(member, l)
		}
	}
	if len(member) == 0 {
		return nil, fmt.Errorf("intent %s has no leg on chain %d, the chain its member settled on", certenIntent.IntentID, chainID)
	}

	// The member's first leg on its chain, as the settlement reads it: the committed executionPayload's
	// target and value, parsed by the same MemberLegsForChain the batch path executes - so the commitment
	// can never state a target or value the settlement would not execute (a malformed or non-EVM target is
	// an error, not a base58 decode or an unvalidated HexToAddress; RB3-F69).
	leg := member[0]
	parsed, _, _, _, perr := MemberLegsForChain(certenIntent, chainID)
	if perr != nil {
		return nil, fmt.Errorf("intent %s member on chain %d: %w", certenIntent.IntentID, chainID, perr)
	}
	finalTarget, finalValue := common.BytesToAddress(parsed[0].Target[:]).Hex(), parsed[0].Value.String()

	commitment := map[string]interface{}{
		"bundleID":    hex.EncodeToString(bundleID[:]),
		"intentID":    certenIntent.IntentID,
		"txHash":      certenIntent.TransactionHash,
		"targetChain": leg.Chain,
		"chainID":     chainID,
		"network":     leg.Network,
		"finalTarget": finalTarget,
		"finalValue":  finalValue,
		// Multi-leg metadata, for the write-back's per-leg aggregation over the whole intent.
		"legCount": len(crossChainData.Legs),
	}
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

	commitmentHash, err := computeCommitmentHash(commitment)
	if err != nil {
		return nil, err
	}
	commitment["commitmentHash"] = hex.EncodeToString(commitmentHash[:])

	bv.logger.Printf("✅ [COMMITMENT] Built execution commitment for intent %s on chain %d: target=%s, value=%s",
		certenIntent.IntentID, chainID, commitment["finalTarget"], finalValue)
	return commitment, nil
}

// computeCommitmentHash computes a deterministic hash of the commitment
func computeCommitmentHash(commitment map[string]interface{}) ([32]byte, error) {
	// encoding/json writes map keys sorted, so the same commitment always hashes the same.
	data, err := json.Marshal(commitment)
	if err != nil {
		return [32]byte{}, fmt.Errorf("commitment cannot be encoded for its hash: %w", err)
	}
	return sha256.Sum256(data), nil
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

	// 2-3. Keys, signing state and genesis by the key-management rules (comet_keys.go, RB3-F95).
	if _, err := ensureCometKeys(cfg.HomeDir, cfg.ValidatorID, cometChainIDForFormulaCheck(), os.Getenv, logger); err != nil {
		return nil, fmt.Errorf("CometBFT keys for %s: %w", cfg.ValidatorID, err)
	}

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

// isAlreadyInMempool reports whether a BroadcastTxSync failure actually means the transaction is
// ALREADY QUEUED, because a peer validator broadcast the identical canonical block first.
//
// This is the mempool doing its job, not an error. It is deliberately NOT folded into
// isTransientBroadcastError: that one says "try again", and trying again here would only earn the
// same answer. This says "someone else already did it, carry on".
func isAlreadyInMempool(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "already exists in cache")
}

// isTransientBroadcastError reports whether a BroadcastTxSync failure is worth another attempt:
// a timeout, a refused connection, or a transport error on a connection the RPC dropped (EOF,
// reset, broken pipe). A CheckTx rejection is not an error here and never reaches this.
func isTransientBroadcastError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	for _, needle := range []string{
		"deadline exceeded", "connection refused", "EOF", "connection reset", "broken pipe",
		"no such host", "i/o timeout", "TLS handshake timeout", "server closed idle connection",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// SequencePredecessor places a later member of a sequential cross-chain intent: the intent's member
// immediately before it, on another chain, and how a failure of that member is treated.
type SequencePredecessor struct {
	// ChainID and OperationID name the predecessor member (queued before this one).
	ChainID     int64
	OperationID [32]byte
	// Position is this member's place in the intent's order: 1 for the second member, and so on.
	Position int
	// ContinueOnFailure: the intent's rollback policy is continue_on_failure.
	ContinueOnFailure bool
}

// accumulateAnchorOf is the Accumulate anchor a proof established: its block hash, height and transaction.
func accumulateAnchorOf(p *proof.CertenProof) (AccumulateAnchorReference, error) {
	a := p.AccumulateAnchor
	switch {
	case a == nil:
		return AccumulateAnchorReference{}, fmt.Errorf("the proof states no Accumulate anchor")
	case a.BlockHash == "":
		return AccumulateAnchorReference{}, fmt.Errorf("the proof's Accumulate anchor names no block hash")
	case a.BlockHeight == 0:
		return AccumulateAnchorReference{}, fmt.Errorf("the proof's Accumulate anchor names no block height")
	case a.TxHash == "":
		return AccumulateAnchorReference{}, fmt.Errorf("the proof's Accumulate anchor names no transaction")
	}
	return AccumulateAnchorReference{BlockHash: a.BlockHash, BlockHeight: a.BlockHeight, TxHash: a.TxHash, AccountURL: p.AccountURL}, nil
}

// ErrValidatorBlockNotCommitted is the retryable refusal for a ValidatorBlock admitted to the mempool but
// not seen committed within the inclusion window.
var ErrValidatorBlockNotCommitted = errors.New("ValidatorBlock admitted but not committed within the inclusion window (retryable)")

// requireCommitted refuses a broadcast result that does not show the block committed.
func requireCommitted(res *BFTExecutionResult) error {
	if res == nil || res.Height <= 0 {
		var tx []byte
		if res != nil {
			tx = res.TxHash
		}
		return fmt.Errorf("%w: tx=%X", ErrValidatorBlockNotCommitted, tx)
	}
	return nil
}

// cometChainIDForFormulaCheck is the chain id the retired public formula used (COMETBFT_CHAIN_ID, default
// certen-testnet), needed only to recognise a key that is still the formula's.
func cometChainIDForFormulaCheck() string {
	if id := strings.TrimSpace(os.Getenv("COMETBFT_CHAIN_ID")); id != "" {
		return id
	}
	return "certen-testnet"
}

// governanceProofFailureClass is what a failed G1 or G2 proof says about its intent: a proof that established the
// authority set did not vote to accept the transaction is a verdict (ErrGovernanceUnsatisfied); any other failure is
// a proof that could not be produced (ErrGovernanceUnavailable). Every G1/G2 failure used to be the latter, so the
// unsatisfied class could not be reached from the proofs that decide it (RB4-F62).
func governanceProofFailureClass(err error) error {
	if errors.Is(err, proof.ErrGovernanceNotSatisfied) {
		return ErrGovernanceUnsatisfied
	}
	return ErrGovernanceUnavailable
}

// deriveGovernanceDecision is who decided the transaction, from this validator's own G1 vote record: the record the
// batch commits to (RB4-F66). The record is evaluated again, here, from the evidence the proof carries for it - the
// chain-bound signatures, votes and page histories - and must be reached exactly. G2 evaluates G1 again, and its
// record must state the same decision - two runs of one proof that disagree about who decided establish neither. A
// record that is missing, unevidenced or cannot support a decision is an outage of the proof, not a verdict: G1
// already found the authorities satisfied.
func deriveGovernanceDecision(ctx context.Context, g0 *proof.G0Result, g1, g2 *proof.GovernanceProof) ([]byte,
	*proof.AuthorizationRecord, error) {
	if g1 == nil || g1.Authorization == nil {
		return nil, nil, fmt.Errorf("%w: the G1 proof carries no vote record, so who decided the transaction is not "+
			"established", ErrGovernanceUnavailable)
	}
	if g1.VoteEvidence == nil {
		return nil, nil, fmt.Errorf("%w: the G1 proof carries no evidence for its vote record, so the record is the "+
			"proof's word for who decided", ErrGovernanceUnavailable)
	}
	if err := proof.VerifyVoteEvidence(ctx, g0, g1.VoteEvidence, g1.Authorization); err != nil {
		return nil, nil, fmt.Errorf("%w: the G1 vote record: %w", ErrGovernanceUnavailable, err)
	}
	gdr, err := proof.GovernanceDecisionRecord(g0, g1.Authorization)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the governance decision cannot be recorded: %w", ErrGovernanceUnavailable, err)
	}
	if g2 == nil || g2.Authorization == nil {
		return nil, nil, fmt.Errorf("%w: the G2 proof carries no vote record, so its evaluation of G1 cannot be "+
			"compared", ErrGovernanceUnavailable)
	}
	again, err := proof.GovernanceDecisionRecord(g0, g2.Authorization)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: G2's evaluation of G1 cannot be recorded: %w", ErrGovernanceUnavailable, err)
	}
	if string(again) != string(gdr) {
		a, b := proof.GovernanceCommitment(gdr), proof.GovernanceCommitment(again)
		return nil, nil, fmt.Errorf("%w: G1 and G2 recorded different decisions (%x, %x)", ErrGovernanceUnavailable, a[:8], b[:8])
	}
	return gdr, g1.Authorization, nil
}
