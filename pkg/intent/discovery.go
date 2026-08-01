// Copyright 2025 Certen Protocol
//
// Intent Discovery Service - Monitor Accumulate blocks for CERTEN_INTENT transactions
// Discovers intent transactions and triggers validator consensus for processing
//
// PHASE 5 UPDATE: Intents are now routed to the batch system based on proofClass:
//   - on_demand → OnDemandHandler.ProcessTransaction (immediate anchoring)
//   - on_cadence → BatchCollector.AddOnCadenceTransaction (batched anchoring)
// This ensures PostgreSQL persistence, CertenAnchorProof assembly, and confirmation tracking.

package intent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/certen/independant-validator/pkg/entitlement"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/batch"
	"github.com/certen/independant-validator/pkg/commitment"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/proof"
)

// BFTConsensusProtocol interface for direct BFT consensus operations (to avoid import cycle)
// Per Golden Spec: Only the canonical method is supported - deprecated methods removed
type BFTConsensusProtocol interface {
	// ExecuteCanonicalIntentWithBFTConsensus is the ONLY supported method for BFT consensus.
	// It requires proper CertenIntent (canonical 4-blob structure) and CertenProof from the lite client.
	// Legacy methods with raw parameters violate the Golden Spec and have been removed.
	ExecuteCanonicalIntentWithBFTConsensus(ctx context.Context, certenIntent *consensus.CertenIntent, certenProof *proof.CertenProof, blockHeight uint64) error
}

const (
	CERTEN_INTENT_MEMO    = "CERTEN_INTENT"
	MAX_CONCURRENT_BLOCKS = 2000 // Increased to handle large block gaps during restarts
	INTENT_BATCH_SIZE     = 5
)

// IntentDiscoveryConfig contains configuration for intent discovery
type IntentDiscoveryConfig struct {
	BlockPollInterval   time.Duration `json:"block_poll_interval"`
	BFTTimeout          time.Duration `json:"bft_timeout"`
	MaxConcurrentBlocks int           `json:"max_concurrent_blocks"`
	IntentBatchSize     int           `json:"intent_batch_size"`
	MinStartHeight      uint64        `json:"min_start_height"` // Minimum starting height fallback

	// on_demand consensus-bound proof retry policy.
	// on_demand (financial) intents REQUIRE the L1-L3 consensus-bound chained proof and
	// must never silently downgrade to a basic account proof. The dominant failure mode is
	// benign DN-anchoring latency / transient DN-BVN CometBFT RPC blips, so a failed chained
	// proof is retried — first in-line (absorbs the common few-second anchoring lag without
	// holding state), then off the block-worker critical path via a decoupled retry queue.
	ChainedProofInlineRetries   int           `json:"chained_proof_inline_retries"`   // in-line attempts per pass (on_demand only)
	ChainedProofInlineBackoff   time.Duration `json:"chained_proof_inline_backoff"`   // base in-line backoff (exponential, capped)
	ChainedProofRequeueAttempts int           `json:"chained_proof_requeue_attempts"` // decoupled requeue attempts before terminal fail
	ChainedProofRequeueBackoff  time.Duration `json:"chained_proof_requeue_backoff"`  // base requeue backoff (exponential, capped 5m)
}

// errChainedProofUnavailable marks a RETRYABLE failure to build the consensus-bound L1-L3
// chained proof for an on_demand intent (typically DN-anchoring latency or a transient
// DN/BVN CometBFT RPC blip). It is returned BEFORE any execution/anchor side effect, so the
// intent is safely requeued with backoff. See processIntent.
var errChainedProofUnavailable = errors.New("consensus-bound chained proof unavailable (retryable)")

// errChainedProofTerminal marks a NON-retryable inability to build the chained proof for an
// on_demand intent (no real proof builder configured, or the intent lacks a txHash/partition).
// Retrying cannot help; the intent fails closed.
var errChainedProofTerminal = errors.New("consensus-bound chained proof unattainable (terminal)")

// intentRetryJob carries an on_demand intent whose consensus-bound proof was not yet available,
// for decoupled retry off the block-worker critical path.
type intentRetryJob struct {
	intent      *CertenIntent
	blockHeight uint64
	attempts    int
}

// IntentStatus represents the processing state of an intent
// Per E.4 remediation: Two-phase marking to handle processing failures
type IntentStatus int

const (
	IntentStatusPending    IntentStatus = iota // Not yet processed
	IntentStatusInProgress                     // Currently being processed
	IntentStatusCompleted                      // Successfully processed
	IntentStatusFailed                         // Processing failed, can be retried
	// IntentStatusFailedPermanent marks a failure no retry can fix — a
	// structural defect in bytes that are already final on Accumulate.
	// Terminal: never reprocessed.
	IntentStatusFailedPermanent
)

func (s IntentStatus) String() string {
	switch s {
	case IntentStatusPending:
		return "pending"
	case IntentStatusInProgress:
		return "in_progress"
	case IntentStatusCompleted:
		return "completed"
	case IntentStatusFailed:
		return "failed"
	case IntentStatusFailedPermanent:
		return "failed_permanent"
	default:
		return "unknown"
	}
}

// IntentDiscovery monitors Accumulate blockchain for Certen transaction intents
type IntentDiscovery struct {
	client         accumulate.Client
	accumulateURL  string
	config         *IntentDiscoveryConfig
	ledgerStore    LedgerStoreInterface // For persistence
	logger         *log.Logger
	bftConsensus   BFTConsensusProtocol
	proofGenerator *proof.LiteClientProofGenerator
	validatorID    string

	// PHASE 5: Batch system integration for PostgreSQL persistence and proof assembly
	batchCollector     *batch.Collector               // For on-cadence batching
	onDemandHandler    *batch.OnDemandHandler         // For immediate on-demand anchoring
	batchingEnabled    bool                           // Toggle for batch system routing
	governanceProofGen proof.GovernanceProofGenerator // For G0/G1/G2 proof generation

	// Intent lifecycle tracking (PostgreSQL)
	repos *database.Repositories // For lifecycle status persistence

	// Multi-leg intent support
	legCompletionHandler *LegCompletionHandler // For multi-leg coordination
	multiLegEnabled      bool                  // Toggle for multi-leg processing

	// Block monitoring state
	lastProcessedBlock uint64
	lastQueuedBlock    uint64 // highest block sent to workers (prevents re-queuing)
	finalizeCeiling    uint64 // watermark is not finalized past this (= latest - confirmLag); the last few heights stay re-scannable
	isMonitoring       bool
	stopCh             chan struct{}
	blockProcessCh     chan *BlockProcessJob
	processedBlocks    map[uint64]bool // tracks out-of-order block completions for watermark
	watermarkMu        sync.Mutex      // protects lastProcessedBlock, lastQueuedBlock, processedBlocks
	mu                 sync.RWMutex

	// Intent tracking - E.4 remediation: Two-phase status tracking
	intentStatus map[string]IntentStatus // Tracks status of each intent
	intentCount  int64                   // Total intents discovered

	// Entitlement pre-screen (see entitlement_prescreen.go). Advisory only —
	// declines work this node would otherwise do, never admits anything.
	entitlementStore   *entitlement.Store
	entitlementEnforce bool

	// on_demand consensus-bound proof retry queue (decoupled from block workers).
	// In-session only: across restart the persisted watermark prevents block re-scan and the
	// queue is empty, so no double-execution is possible; failed records remain lifecycle=failed
	// in PostgreSQL for alerting.
	retryCh chan *intentRetryJob
}

// LedgerStoreInterface defines the interface for ledger operations needed by intent discovery
type LedgerStoreInterface interface {
	SaveIntentLastBlock(height uint64) error
	LoadIntentLastBlock() (uint64, error)
}

// BlockProcessJob represents a block processing job
type BlockProcessJob struct {
	PartitionURL string
	BlockHeight  uint64
	BlockData    *accumulate.Block
}

// CertenIntent uses the canonical type from protocol package
// All intent processing must use this single canonical type

// DefaultIntentDiscoveryConfig returns a default configuration for intent discovery
func DefaultIntentDiscoveryConfig() *IntentDiscoveryConfig {
	return &IntentDiscoveryConfig{
		BlockPollInterval: 5 * time.Second,
		// Bounds the WHOLE canonical workflow, the G0/G1/G2 govproof CLI round trips
		// included (G1 alone measured ~27s against the Kermit endpoint). Too small a value
		// gets G2 KILLED mid-flight, which leaves governance at G1 and makes HIGH-004 refuse
		// every value-moving intent. Keep in step with main.go's CERTEN_BFT_TIMEOUT default.
		BFTTimeout:          180 * time.Second,
		MaxConcurrentBlocks: MAX_CONCURRENT_BLOCKS,
		IntentBatchSize:     INTENT_BATCH_SIZE,
		MinStartHeight:      946000, // Current testnet baseline
		// Short in-line retry catches the common few-second DN-anchoring lag without holding
		// a block worker long; the decoupled queue (10 attempts, 10s→5m exp backoff ≈ ~25min)
		// absorbs longer transient DN/BVN RPC outages off the critical path.
		ChainedProofInlineRetries:   3,
		ChainedProofInlineBackoff:   2 * time.Second,
		ChainedProofRequeueAttempts: 10,
		ChainedProofRequeueBackoff:  10 * time.Second,
	}
}

// NewIntentDiscovery creates a new intent discovery service with configuration and persistence
func NewIntentDiscovery(
	client accumulate.Client,
	accumulateURL string,
	config *IntentDiscoveryConfig,
	ledgerStore LedgerStoreInterface,
	proofGen *proof.LiteClientProofGenerator,
	validatorID string,
) *IntentDiscovery {
	if config == nil {
		config = DefaultIntentDiscoveryConfig()
	}

	// Defensive defaults: callers that build IntentDiscoveryConfig directly (not via
	// DefaultIntentDiscoveryConfig) leave the on_demand proof-retry fields zero, which would
	// neuter the retry path to a single attempt. Backfill so on_demand intents always get the
	// full in-line + decoupled requeue policy regardless of how the config was constructed.
	if config.ChainedProofInlineRetries <= 0 {
		config.ChainedProofInlineRetries = 3
	}
	if config.ChainedProofInlineBackoff <= 0 {
		config.ChainedProofInlineBackoff = 2 * time.Second
	}
	if config.ChainedProofRequeueAttempts <= 0 {
		config.ChainedProofRequeueAttempts = 10
	}
	if config.ChainedProofRequeueBackoff <= 0 {
		config.ChainedProofRequeueBackoff = 10 * time.Second
	}

	return &IntentDiscovery{
		client:             client,
		accumulateURL:      accumulateURL,
		config:             config,
		ledgerStore:        ledgerStore,
		logger:             log.New(log.Writer(), "[INTENT-DISCOVERY] ", log.LstdFlags),
		proofGenerator:     proofGen,
		validatorID:        validatorID,
		intentStatus:       make(map[string]IntentStatus), // E.4 remediation: Two-phase status tracking
		lastProcessedBlock: 0,
	}
}

// NewIntentDiscoveryLegacy creates a new intent discovery service with legacy signature for backward compatibility
// DEPRECATED: Use NewIntentDiscovery with proper config and ledger store
func NewIntentDiscoveryLegacy(client accumulate.Client, accumulateURL string) *IntentDiscovery {
	return NewIntentDiscovery(client, accumulateURL, nil, nil, nil, "")
}

// SetBFTConsensus sets the BFT consensus for processing discovered intents
func (id *IntentDiscovery) SetBFTConsensus(consensus BFTConsensusProtocol) {
	id.bftConsensus = consensus
	id.logger.Printf("🎯 BFT consensus configured for intent processing")
}

// SetBatchSystem configures the batch system for PostgreSQL persistence and proof assembly
// PHASE 5: This enables routing intents to the batch system based on proofClass
func (id *IntentDiscovery) SetBatchSystem(collector *batch.Collector, onDemand *batch.OnDemandHandler) {
	id.batchCollector = collector
	id.onDemandHandler = onDemand
	id.batchingEnabled = (collector != nil || onDemand != nil)
	if id.batchingEnabled {
		id.logger.Printf("🗄️ Batch system configured for intent routing:")
		if collector != nil {
			id.logger.Printf("   - On-Cadence: BatchCollector enabled")
		}
		if onDemand != nil {
			id.logger.Printf("   - On-Demand: OnDemandHandler enabled")
		}
	} else {
		id.logger.Printf("⚠️ Batch system not configured - intents will bypass PostgreSQL")
	}
}

// IsBatchingEnabled returns whether batch system routing is enabled
func (id *IntentDiscovery) IsBatchingEnabled() bool {
	return id.batchingEnabled
}

// SetGovernanceProofGenerator configures the governance proof generator for G0/G1/G2 proof generation
// This must be called before processing intents if governance proofs are desired
func (id *IntentDiscovery) SetGovernanceProofGenerator(gen proof.GovernanceProofGenerator) {
	id.governanceProofGen = gen
	if gen != nil {
		id.logger.Printf("✅ Governance proof generator configured for G0/G1/G2 proof generation")
	}
}

// SetLegCompletionHandler configures the leg completion handler for multi-leg intent coordination
func (id *IntentDiscovery) SetLegCompletionHandler(handler *LegCompletionHandler) {
	id.legCompletionHandler = handler
	id.multiLegEnabled = (handler != nil)
	if id.multiLegEnabled {
		id.logger.Printf("✅ Multi-leg intent coordination enabled via LegCompletionHandler")
	}
}

// IsMultiLegEnabled returns whether multi-leg processing is enabled
func (id *IntentDiscovery) IsMultiLegEnabled() bool {
	return id.multiLegEnabled
}

// SetRepositories configures database repositories for intent lifecycle tracking
func (id *IntentDiscovery) SetRepositories(repos *database.Repositories) {
	id.repos = repos
	if repos != nil {
		id.logger.Printf("✅ Intent lifecycle tracking enabled via PostgreSQL")
	}
}

// StartMonitoring begins monitoring Accumulate blockchain for Certen intents
// This method supports restart - each call creates fresh channels and workers
func (id *IntentDiscovery) StartMonitoring() {
	id.mu.Lock()
	if id.isMonitoring {
		id.mu.Unlock()
		id.logger.Printf("⚠️ Intent discovery already monitoring")
		return
	}

	// Reinitialize channels and state for restart capability
	id.isMonitoring = true
	id.stopCh = make(chan struct{})
	id.blockProcessCh = make(chan *BlockProcessJob, id.config.MaxConcurrentBlocks)
	id.retryCh = make(chan *intentRetryJob, 256)
	id.processedBlocks = make(map[uint64]bool)
	id.lastQueuedBlock = id.lastProcessedBlock // reset queue tracker to current watermark
	// Keep intent status across restarts to avoid reprocessing
	// E.4 remediation: Two-phase status tracking
	if id.intentStatus == nil {
		id.intentStatus = make(map[string]IntentStatus)
	}

	id.mu.Unlock()

	id.logger.Printf("🔍 Starting Certen Intent Discovery Service...")
	id.logger.Printf("📡 Monitoring Accumulate network: %s", id.accumulateURL)
	id.logger.Printf("🎯 Looking for transactions with memo: %s", CERTEN_INTENT_MEMO)
	id.logger.Printf("📊 Configuration:")
	id.logger.Printf("   - Block Poll Interval: %v", id.config.BlockPollInterval)
	id.logger.Printf("   - BFT Timeout: %v", id.config.BFTTimeout)
	id.logger.Printf("   - Max Concurrent Blocks: %d", id.config.MaxConcurrentBlocks)
	id.logger.Printf("   - Intent Batch Size: %d", id.config.IntentBatchSize)
	id.logger.Printf("   - Min Start Height: %d", id.config.MinStartHeight)

	// Start block processor workers
	for i := 0; i < 3; i++ {
		workerID := fmt.Sprintf("worker-%d", i+1)
		id.logger.Printf("🔧 Starting block processor: %s", workerID)
		go id.blockProcessor(workerID)
	}

	// Start the decoupled on_demand consensus-bound proof retry worker
	go id.retryWorker()

	// Start main monitoring loop
	go id.monitoringLoop()

	id.logger.Printf("✅ Intent discovery service started successfully with 3 workers + retry worker")
}

// StopMonitoring stops the intent discovery service
func (id *IntentDiscovery) StopMonitoring() {
	id.mu.Lock()
	defer id.mu.Unlock()

	if !id.isMonitoring {
		return
	}

	id.logger.Printf("🛑 Stopping intent discovery service...")
	close(id.stopCh)
	id.isMonitoring = false
	id.logger.Printf("✅ Intent discovery service stopped")
}

// monitoringLoop main loop that monitors for new blocks
func (id *IntentDiscovery) monitoringLoop() {
	ticker := time.NewTicker(id.config.BlockPollInterval)
	defer ticker.Stop()

	id.logger.Printf("🔄 Starting intent discovery monitoring loop...")

	// E.3 remediation: Initialize starting block height with retry and exponential backoff
	ctx := context.Background()
	var lastErr error
	for retries := 0; retries < 5; retries++ {
		if err := id.initializeStartingHeight(ctx); err != nil {
			lastErr = err
			backoff := time.Duration(1<<retries) * time.Second // 1s, 2s, 4s, 8s, 16s
			id.logger.Printf("⚠️ Failed to initialize height (attempt %d/5): %v, retrying in %v", retries+1, err, backoff)
			time.Sleep(backoff)
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		id.logger.Printf("❌ Failed to initialize starting height after 5 attempts, using fallback: %d", id.config.MinStartHeight)
		id.lastProcessedBlock = id.config.MinStartHeight
	}

	for {
		select {
		case <-id.stopCh:
			id.logger.Printf("🛑 Intent discovery monitoring loop stopping")
			return
		case <-ticker.C:
			if err := id.checkForNewBlocks(ctx); err != nil {
				id.logger.Printf("⚠️ Error checking blocks: %v", err)
			}
			// Periodic checkpoint persist (workers also persist via advanceWatermark)
			if id.ledgerStore != nil {
				if err := id.ledgerStore.SaveIntentLastBlock(id.lastProcessedBlock); err != nil {
					id.logger.Printf("⚠️ Failed to persist block height: %v", err)
				}
			}
		}
	}
}

// initializeStartingHeight determines the starting block height using persistence
func (id *IntentDiscovery) initializeStartingHeight(ctx context.Context) error {
	var startHeight uint64

	// Try to load persisted height first
	if id.ledgerStore != nil {
		persistedHeight, err := id.ledgerStore.LoadIntentLastBlock()
		if err != nil {
			id.logger.Printf("⚠️ Failed to load persisted block height: %v", err)
		} else if persistedHeight > 0 {
			startHeight = persistedHeight
			id.logger.Printf("📊 Loaded persisted last processed block: %d, will start from %d", persistedHeight, startHeight)
		}
	}

	// If no persisted height, determine from latest block
	if startHeight == 0 {
		latestBlock, err := id.client.GetLatestBlock(ctx)
		if err != nil {
			id.logger.Printf("❌ Failed to get latest block: %v", err)
			startHeight = id.config.MinStartHeight
			id.logger.Printf("📊 Using configured minimum starting height: %d", startHeight)
		} else {
			startHeight = latestBlock.Height - 5 // Start 5 blocks back to catch any missed
			id.logger.Printf("📊 Starting from latest block - 5: %d (latest: %d)", startHeight, latestBlock.Height)

			// Ensure we're not starting too far in the past
			if startHeight < id.config.MinStartHeight {
				startHeight = id.config.MinStartHeight
				id.logger.Printf("📊 Adjusted to minimum starting height: %d", startHeight)
			}
		}

		// Persist the initial height
		if id.ledgerStore != nil {
			if err := id.ledgerStore.SaveIntentLastBlock(startHeight); err != nil {
				id.logger.Printf("⚠️ Failed to persist initial block height: %v", err)
			}
		}
	}

	id.lastProcessedBlock = startHeight
	id.lastQueuedBlock = startHeight
	id.finalizeCeiling = startHeight
	return nil
}

// checkForNewBlocks scans every block from the watermark up to the latest directory
// height and queues each for processing. It MUST NOT advance the watermark past a
// height it has not searched.
//
// The previous implementation queried only the single latest directoryHeight per tick
// and jumped the watermark past every intermediate height, assuming those were empty
// CometBFT rounds. That is wrong for this network: Accumulate is event-driven
// (create_empty_blocks=false), and its DN minor blocks are dense/contiguous (verified
// against the v3 minor-block range query). The "skipped" heights are the REAL blocks
// that carry intents, so skipping them silently dropped any intent whose block was not
// exactly the latest height at poll time — the operator's "first intent after idle is
// not executed; a second submission is needed" symptom.
//
// A height with no Certen intent — or one that transiently fails to query — is a cheap
// no-op: SearchCertenTransactions catches per-partition errors and returns nothing, so
// the block simply advances. Because DN blocks are dense there is no efficiency loss
// versus enumerating them; a per-tick cap bounds the rare large catch-up.
func (id *IntentDiscovery) checkForNewBlocks(ctx context.Context) error {
	latestBlock, err := id.client.GetLatestBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}
	latest := latestBlock.Height

	id.watermarkMu.Lock()

	// Network switch detection (e.g., DevNet vs Kermit/Mainnet)
	if latest < id.lastProcessedBlock {
		id.logger.Printf("🔄 Network switch detected: current height %d < last processed %d", latest, id.lastProcessedBlock)
		id.lastProcessedBlock = latest
		id.lastQueuedBlock = latest
		id.finalizeCeiling = latest
		id.processedBlocks = make(map[uint64]bool)
		id.watermarkMu.Unlock()
		if id.ledgerStore != nil {
			if err := id.ledgerStore.SaveIntentLastBlock(latest); err != nil {
				id.logger.Printf("⚠️ Failed to persist reset height: %v", err)
			}
		}
		return nil
	}

	// Confirmation lag: finalize the watermark only up to (latest - confirmLag). The
	// last few heights stay unfinalized and are re-scanned on subsequent ticks, so an
	// intent whose block became queryable a tick after we first looked — or whose
	// search hit a transient per-partition error — is still caught. Re-scanning is
	// safe: discovered intents are de-duped by markInProgress/markCompleted, so a
	// re-scan can never re-execute an intent.
	const confirmLag = uint64(2)
	ceiling := latest
	if latest > confirmLag {
		ceiling = latest - confirmLag
	}
	id.finalizeCeiling = ceiling

	from := id.lastProcessedBlock + 1

	// Bound the burst on a large catch-up (cold start / long idle); the remaining
	// heights are picked up on subsequent ticks as the watermark advances.
	const maxPerTick = uint64(2000)
	hi := latest
	if from <= latest && hi-from+1 > maxPerTick {
		hi = from + maxPerTick - 1
	}
	id.lastQueuedBlock = latest
	id.watermarkMu.Unlock()

	if from > latest {
		return nil
	}
	// Only log genuine forward progress (more than just the re-scan window), to avoid
	// per-tick noise while idle.
	if hi-from+1 > confirmLag+1 {
		id.logger.Printf("🔎 Scanning blocks [%d -> %d] (latest %d, finalize<=%d)", from, hi, latest, ceiling)
	}

	for h := from; h <= hi; h++ {
		select {
		case id.blockProcessCh <- &BlockProcessJob{
			PartitionURL: "acc://dn.acme",
			BlockHeight:  h,
		}:
		case <-id.stopCh:
			return nil
		}
	}

	return nil
}

// blockProcessor processes blocks to find Certen intents
func (id *IntentDiscovery) blockProcessor(workerID string) {
	defer func() {
		if r := recover(); r != nil {
			id.logger.Printf("🚨 PANIC in block processor %s: %v", workerID, r)
		}
		id.logger.Printf("🛑 Block processor %s exited", workerID)
	}()

	id.logger.Printf("🔧 Block processor %s started and ready to process jobs", workerID)

	for {
		select {
		case <-id.stopCh:
			id.logger.Printf("🛑 Block processor %s stopping due to stop signal", workerID)
			return
		case job := <-id.blockProcessCh:
			id.logger.Printf("📦 Worker %s received job for block %d", workerID, job.BlockHeight)
			if err := id.processBlock(job, workerID); err != nil {
				id.logger.Printf("❌ Worker %s failed to process block %d: %v",
					workerID, job.BlockHeight, err)
			}
			// Advance watermark regardless of success/failure to prevent getting stuck.
			// Failed blocks are logged above; if the error was transient the block will
			// appear again on a future polling cycle once the watermark catches up.
			id.advanceWatermark(job.BlockHeight)
		}
	}
}

// advanceWatermark marks a block height as processed and advances the lastProcessedBlock
// watermark through any contiguous sequence of completed blocks. This ensures blocks
// processed out-of-order by concurrent workers are properly tracked without skipping any.
func (id *IntentDiscovery) advanceWatermark(height uint64) {
	id.watermarkMu.Lock()
	defer id.watermarkMu.Unlock()

	// Ignore stale blocks (already processed or from before a network switch reset)
	if height <= id.lastProcessedBlock || height > id.lastQueuedBlock {
		return
	}

	id.processedBlocks[height] = true

	// Advance lastProcessedBlock through contiguous completed blocks, but never past
	// the finalize ceiling (latest - confirmLag). Heights above the ceiling are left
	// unfinalized on purpose so they are re-scanned on subsequent ticks (safe: intents
	// are de-duped, so a re-scan cannot re-execute one).
	advanced := false
	for id.lastProcessedBlock+1 <= id.finalizeCeiling && id.processedBlocks[id.lastProcessedBlock+1] {
		delete(id.processedBlocks, id.lastProcessedBlock+1)
		id.lastProcessedBlock++
		advanced = true
	}

	if advanced {
		id.logger.Printf("📊 Watermark advanced to block %d (%d blocks pending completion)",
			id.lastProcessedBlock, len(id.processedBlocks))
		if id.ledgerStore != nil {
			if err := id.ledgerStore.SaveIntentLastBlock(id.lastProcessedBlock); err != nil {
				id.logger.Printf("⚠️ Failed to persist watermark: %v", err)
			}
		}
	}
}

// processBlock processes a single block looking for Certen intents using comprehensive v3 API search
func (id *IntentDiscovery) processBlock(job *BlockProcessJob, workerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	foundIntents := 0

	certenTransactions, err := id.client.SearchCertenTransactions(ctx, int64(job.BlockHeight))
	if err != nil {
		return err
	}

	for _, certenTx := range certenTransactions {
		// Filter to transactions in this specific block
		if certenTx.BlockHeight != int64(job.BlockHeight) { // Fixed: compare int64 to uint64
			continue
		}

		id.logger.Printf("🎯 Worker %s found CERTEN transaction in block %d: %s from partition %s",
			workerID, job.BlockHeight, certenTx.Hash, certenTx.Partition)

		// Convert CertenTransaction to our internal Intent format
		intent, err := id.convertCertenTransactionToIntent(certenTx)
		if err != nil {
			id.logger.Printf("⚠️ Failed to convert CERTEN transaction to intent: %v", err)
			continue
		}

		// Intent lifecycle: record discovery as authorized (validator only sees delivered intents)
		if id.repos != nil && id.repos.IntentLifecycle != nil {
			targetChain := ""
			if tc, _, tcErr := intent.GetTargetChain(); tcErr == nil {
				targetChain = tc
			}
			if lcErr := id.repos.IntentLifecycle.UpsertOnDiscovery(
				ctx, intent.IntentID, intent.TransactionHash,
				int64(job.BlockHeight), intent.UserID, intent.ProofClass, targetChain,
			); lcErr != nil {
				id.logger.Printf("⚠️ [LIFECYCLE] Failed to upsert lifecycle for %s: %v", intent.IntentID, lcErr)
			}
		}

		// E.4 remediation: Two-phase marking to handle processing failures
		// Phase 1: Mark as in_progress - prevents concurrent processing
		if !id.markInProgress(intent.IntentID) {
			status := id.getIntentStatus(intent.IntentID)
			id.logger.Printf("⚠️ Intent %s already %s, skipping", intent.IntentID, status.String())
			continue
		}

		id.logger.Printf("🎯 DISCOVERED NEW CERTEN INTENT in block %d!", job.BlockHeight)
		id.logger.Printf("   Intent ID: %s", intent.IntentID)
		id.logger.Printf("   Transaction: %s", intent.TransactionHash)
		id.logger.Printf("   Partition: %s", certenTx.Partition)
		id.logger.Printf("   Block Height: %d", job.BlockHeight)
		id.logger.Printf("   Intent Data: %+v", certenTx.IntentData)

		// Process the intent through consensus
		if err := id.processIntent(intent, job.BlockHeight); err != nil {
			id.logger.Printf("❌ Failed to process intent %s: %v", intent.IntentID, err)
			// E.4 remediation: Phase 2 (failure) - Mark as failed (allows re-acquire on retry),
			// unless the failure is structural and therefore final.
			id.markFailedClassified(intent.IntentID, err)

			// on_demand consensus-bound proof not yet available (benign DN-anchoring latency or a
			// transient DN/BVN CometBFT RPC blip): requeue off the block-worker critical path
			// instead of dropping the intent or silently downgrading to a basic proof. The error
			// is returned before any execution/anchor side effect, so the retry is replay-safe.
			if errors.Is(err, errChainedProofUnavailable) {
				id.logger.Printf("🔁 Intent %s requeued for consensus-bound proof retry", intent.IntentID)
				id.enqueueRetry(&intentRetryJob{intent: intent, blockHeight: job.BlockHeight})
			} else {
				id.logger.Printf("   Intent %s marked as 'failed'", intent.IntentID)
				// Intent lifecycle: record terminal failure (non-fatal)
				if id.repos != nil && id.repos.IntentLifecycle != nil {
					if lcErr := id.repos.IntentLifecycle.UpdateStatus(ctx, intent.IntentID,
						database.IntentLifecycleFailed,
						database.WithErrorMessage(err.Error()),
					); lcErr != nil {
						id.logger.Printf("⚠️ [LIFECYCLE] Failed to update lifecycle to failed for %s: %v", intent.IntentID, lcErr)
					}
				}
			}
		} else {
			foundIntents++
			// E.4 remediation: Phase 2 (success) - Mark as completed
			id.markCompleted(intent.IntentID)
			id.logger.Printf("✅ Intent %s processed successfully and marked complete", intent.IntentID)
		}
	}

	if foundIntents > 0 {
		id.logger.Printf("✅ Worker %s found and processed %d new intents in block %d",
			workerID, foundIntents, job.BlockHeight)
	}

	return nil
}

// convertCertenTransactionToIntent converts a CertenTransaction from v3 API to canonical CertenIntent format
func (id *IntentDiscovery) convertCertenTransactionToIntent(certenTx *accumulate.CertenTransaction) (*CertenIntent, error) {
	// Debug: Log the incoming CertenTransaction data
	id.logger.Printf("🔍 [DEBUG-CONVERSION-INPUT] Converting CertenTransaction %s with %d IntentData elements: %+v",
		certenTx.Hash, len(certenTx.IntentData), certenTx.IntentData)

	// Extract intent type from the transaction data
	intentType := "general" // Default

	// Initialize data containers for the 4 blobs using existing classification helpers
	var intentData, crossChainData, governanceData, replayData map[string]interface{}
	intentData = make(map[string]interface{})
	crossChainData = make(map[string]interface{})
	governanceData = make(map[string]interface{})
	replayData = make(map[string]interface{})

	// Extract the structured 4-blob data like legacy implementation
	// Legacy code properly extracts intentData, crossChainData, governanceData, replayData from the structured elements
	if intentDataBlob, ok := certenTx.IntentData["intentData"].(map[string]interface{}); ok {
		intentData = intentDataBlob
		id.logger.Printf("✅ [4-BLOB-EXTRACT] Found intentData blob with %d fields", len(intentData))
	}

	if crossChainBlob, ok := certenTx.IntentData["crossChainData"].(map[string]interface{}); ok {
		crossChainData = crossChainBlob
		id.logger.Printf("✅ [4-BLOB-EXTRACT] Found crossChainData blob with %d fields", len(crossChainData))
	}

	if governanceBlob, ok := certenTx.IntentData["governanceData"].(map[string]interface{}); ok {
		governanceData = governanceBlob
		id.logger.Printf("✅ [4-BLOB-EXTRACT] Found governanceData blob with %d fields", len(governanceData))
	}

	if replayBlob, ok := certenTx.IntentData["replayData"].(map[string]interface{}); ok {
		replayData = replayBlob
		id.logger.Printf("✅ [4-BLOB-EXTRACT] Found replayData blob with %d fields", len(replayData))
	}

	// Fallback: If no structured blobs found, copy remaining data to intentData
	if len(intentData) == 0 && len(crossChainData) == 0 && len(governanceData) == 0 && len(replayData) == 0 {
		id.logger.Printf("⚠️ [4-BLOB-EXTRACT] No structured blobs found, using fallback categorization")
		for key, value := range certenTx.IntentData {
			if dataElement, ok := value.(map[string]interface{}); ok {
				// Check if this element contains intent type information
				if typeVal, exists := dataElement["type"].(string); exists {
					intentType = typeVal
				}

				// Categorize data based on content and known patterns
				if id.isIntentData(dataElement) {
					for k, v := range dataElement {
						intentData[k] = v
					}
				} else if id.isCrossChainData(dataElement) {
					for k, v := range dataElement {
						crossChainData[k] = v
					}
				} else if id.isGovernanceData(dataElement) {
					for k, v := range dataElement {
						governanceData[k] = v
					}
				} else if id.isReplayData(dataElement) {
					for k, v := range dataElement {
						replayData[k] = v
					}
				} else {
					// Default to intent data if unknown
					intentData[key] = value
				}
			} else {
				// Non-structured data goes to intent data
				intentData[key] = value
			}
		}
	}

	// Validate that we have at least some intent data before building
	if len(intentData) == 0 && len(crossChainData) == 0 && len(governanceData) == 0 && len(replayData) == 0 {
		return nil, fmt.Errorf("transaction %s has no valid 4-blob structure", certenTx.Hash)
	}

	// Use BuildCertenIntent to construct the canonical struct.
	// This handles field extraction + raw-JSON marshalling.
	// Canonicalization & operation_id computation are done later in the consensus pipeline.
	intent, err := BuildCertenIntent(
		certenTx.Hash,
		intentData,
		crossChainData,
		governanceData,
		replayData,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build canonical CertenIntent: %w", err)
	}

	// Set partition info from CertenTransaction for L1-L3 proof generation
	// Normalize partition name to lowercase (e.g., "BVN0" -> "bvn0")
	if certenTx.Partition != "" {
		intent.Partition = strings.ToLower(certenTx.Partition)
	}

	// Authoritative account: prefer the REAL transaction principal (the account the
	// writeData provably lives on, extracted from header.principal during discovery)
	// over the intent's self-declared organizationAdi. A malformed or spoofed intent
	// can declare a wrong / non-existent org ADI (e.g. "acc://o.acme"); trusting it
	// sends the L1 chained-proof lookup to an account that has no such entry, which
	// then stalls forever as "chained proof unavailable (retryable)". The discovered
	// principal (already including the /data suffix) is the source of truth.
	if certenTx.AccountURL != "" {
		derived := intent.AccountURL
		intent.AccountURL = certenTx.AccountURL
		intent.OrganizationADI = strings.TrimSuffix(certenTx.AccountURL, "/data")
		if derived != "" && derived != certenTx.AccountURL {
			id.logger.Printf("🔗 [ACCOUNT] Proof account corrected to discovered principal %s (declared derived %q)",
				certenTx.AccountURL, derived)
		}
	}

	// Additional validation - ensure we have a proper intent ID
	if intent.IntentID == "" {
		return nil, fmt.Errorf("transaction %s produced invalid intent with empty IntentID", certenTx.Hash)
	}

	// Optional: For debugging purposes, compute the canonical 4-blob hash
	// Note: This is NOT stored in the intent; OperationCommitment will be computed
	// later in the consensus pipeline when building ValidatorBlock
	if id.logger != nil {
		// Marshal each blob for canonical hash computation (debugging only)
		intentJSON, _ := json.Marshal(intentData)
		crossJSON, _ := json.Marshal(crossChainData)
		govJSON, _ := json.Marshal(governanceData)
		replayJSON, _ := json.Marshal(replayData)

		// Canonicalize for debug hash
		canonIntent, _ := commitment.CanonicalizeJSON(intentJSON)
		canonCross, _ := commitment.CanonicalizeJSON(crossJSON)
		canonGov, _ := commitment.CanonicalizeJSON(govJSON)
		canonReplay, _ := commitment.CanonicalizeJSON(replayJSON)

		// Compute debug operation ID for logging
		_, debugOpID, debugErr := proof.ComputeCanonical4BlobHash(
			canonIntent, canonCross, canonGov, canonReplay,
		)
		if debugErr == nil {
			opID := "0x" + debugOpID

			// If intent.IntentID is empty, use the canonical operation hash as fallback
			if intent.IntentID == "" {
				intent.IntentID = opID
			}

			id.logger.Printf("🔄 Converted CERTEN transaction %s to intent %s (type: %s)",
				certenTx.Hash, intent.IntentID, intentType)
			id.logger.Printf("   Debug canonical operation_id: %s", opID)
			id.logger.Printf("   Intent has %d bytes intent data, %d bytes cross-chain data",
				len(intent.IntentData), len(intent.CrossChainData))
		}
	}

	return intent, nil
}

// parseCertenIntent has been removed - use convertCertenTransactionToIntent instead

// convertIntentToTransactionData converts a CertenIntent to batch.TransactionData
// This bridges the intent discovery system with the batch/proof assembly system
// govProof is the generated G0/G1/G2 governance proof (may be nil if not generated)
func (id *IntentDiscovery) convertIntentToTransactionData(intent *CertenIntent, certenProof *proof.CertenProof, govProof *proof.GovernanceProof) (*batch.TransactionData, error) {
	// Compute 32-byte transaction hash for Merkle tree
	// We hash the 4 canonical blobs to get a deterministic txHash
	txHash := sha256.Sum256(append(append(append(
		intent.IntentData,
		intent.CrossChainData...),
		intent.GovernanceData...),
		intent.ReplayData...))

	// Extract target chain from intent legs per Unified Multi-Chain Architecture
	targetChain, chainID, err := intent.GetTargetChain()
	if err != nil {
		id.logger.Printf("⚠️ Failed to extract target chain for intent %s: %v (using default)", intent.IntentID, err)
		// Default to sepolia for Ethereum testnets
		targetChain = "sepolia"
		chainID = 11155111
	} else {
		id.logger.Printf("✅ [TARGET-CHAIN] Extracted target chain '%s' (chainID: %d) from intent %s", targetChain, chainID, intent.IntentID)
	}

	// Build TransactionData for the batch system
	txData := &batch.TransactionData{
		AccumTxHash: intent.TransactionHash,
		AccountURL:  intent.AccountURL,
		TxHash:      txHash[:],
		IntentType:  "certen_intent",
		IntentData:  intent.IntentData,
		// Intent tracking: links validator proofs back to Firestore intents
		UserID:   intent.UserID,   // From intent_data.created_by
		IntentID: intent.IntentID, // From intent_data.intent_id
		// Multi-Chain Support: Target chain for anchoring
		TargetChain: targetChain,
	}

	// Extract Transaction Center metadata from CrossChainData
	// This populates from_chain, to_chain, from_address, to_address, amount, token_symbol
	if len(intent.CrossChainData) > 0 {
		var ccEnvelope consensus.CrossChainEnvelope
		if err := json.Unmarshal(intent.CrossChainData, &ccEnvelope); err == nil && len(ccEnvelope.Legs) > 0 {
			// Use first leg for primary transaction metadata
			leg := ccEnvelope.Legs[0]
			txData.FromChain = "accumulate" // Source is always Accumulate
			txData.ToChain = leg.Chain      // Target chain from leg
			txData.FromAddress = leg.From
			txData.ToAddress = leg.To
			// Prefer AmountEth (human-readable) for display; AmountWei may have
			// been computed with wrong decimals for non-EVM chains (SOL=9, not 18).
			if leg.AmountEth != "" {
				txData.Amount = leg.AmountEth
			} else if leg.AmountWei != "" {
				txData.Amount = leg.AmountWei
			}
			txData.TokenSymbol = leg.Asset.Symbol
			id.logger.Printf("✅ [TX-METADATA] Extracted: %s → %s, %s %s to %s",
				txData.FromChain, txData.ToChain, txData.Amount, txData.TokenSymbol, txData.ToAddress)
		}
	}

	// Extract ADI URL from GovernanceData
	if len(intent.GovernanceData) > 0 {
		var govData struct {
			OrganizationADI string `json:"organizationAdi"`
		}
		if err := json.Unmarshal(intent.GovernanceData, &govData); err == nil && govData.OrganizationADI != "" {
			txData.AdiURL = govData.OrganizationADI
		}
	}
	// Fallback to intent's OrganizationADI
	if txData.AdiURL == "" && intent.OrganizationADI != "" {
		txData.AdiURL = intent.OrganizationADI
	}

	// Extract created_at from IntentData for client timestamp
	if len(intent.IntentData) > 0 {
		var intentMeta struct {
			CreatedAt string `json:"created_at"`
		}
		if err := json.Unmarshal(intent.IntentData, &intentMeta); err == nil && intentMeta.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, intentMeta.CreatedAt); err == nil {
				txData.CreatedAtClient = &t
			}
		}
	}

	// Log chain ID for debugging (not stored in TransactionData directly)
	_ = chainID // Suppress unused warning

	// Add ChainedProof and GovProof if available from CertenProof
	if certenProof != nil && certenProof.LiteClientProof != nil {
		// Serialize the lite client proof as ChainedProof
		chainedBytes, err := json.Marshal(certenProof.LiteClientProof)
		if err == nil {
			txData.ChainedProof = chainedBytes
		}
	}

	// Add generated governance proof (G0/G1/G2) if available
	// This is the ACTUAL proof result, not the input config
	if govProof != nil {
		govProofBytes, err := json.Marshal(govProof)
		if err == nil {
			txData.GovProof = govProofBytes
			txData.GovLevel = string(govProof.Level)
			id.logger.Printf("✅ [GOV-PROOF] Storing generated %s proof for intent %s", govProof.Level, intent.IntentID)
		} else {
			id.logger.Printf("⚠️ [GOV-PROOF] Failed to serialize governance proof: %v", err)
		}
	} else if len(intent.GovernanceData) > 0 {
		// Fallback: store governance input config if no generated proof available
		// This is the legacy behavior - should be replaced with generated proof when available
		txData.GovProof = intent.GovernanceData
		// Parse to determine governance level from input config
		var govData struct {
			Authorization struct {
				SignatureThreshold int `json:"signature_threshold"`
			} `json:"authorization"`
		}
		if err := json.Unmarshal(intent.GovernanceData, &govData); err == nil {
			if govData.Authorization.SignatureThreshold >= 3 {
				txData.GovLevel = "G2"
			} else if govData.Authorization.SignatureThreshold >= 2 {
				txData.GovLevel = "G1"
			} else {
				txData.GovLevel = "G0"
			}
		}
		id.logger.Printf("⚠️ [GOV-PROOF] Using governance input config (no generated proof) for intent %s", intent.IntentID)
	}

	return txData, nil
}

// processIntent triggers consensus for the discovered intent
// PHASE 5: Now routes to batch system based on proofClass for PostgreSQL persistence
// Multi-Leg: Detects multi-leg intents and routes to chain-grouped leg processing
// chainedRetryBackoff returns an exponential backoff of base * 2^min(step, maxShift), capped
// at capDur. step is 0-based (first retry = step 0). Pure + bounded for deterministic testing.
func chainedRetryBackoff(base time.Duration, step, maxShift int, capDur time.Duration) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if step < 0 {
		step = 0
	}
	if step > maxShift {
		step = maxShift
	}
	d := base * time.Duration(1<<uint(step))
	if capDur > 0 && d > capDur {
		d = capDur
	}
	return d
}

// buildChainedCertenProof builds the L1-L3 consensus-bound CertenProof, retrying up to
// maxAttempts with exponential backoff to absorb DN-anchoring latency and transient DN/BVN
// CometBFT RPC failures. Fail-closed: returns the last error if every attempt fails (the
// underlying ProofBuilder is itself fail-closed — it recomputes each Merkle receipt and binds
// the BVN+DN consensus app_hash, so a returned proof is already cryptographically verified).
func (id *IntentDiscovery) buildChainedCertenProof(ctx context.Context, accountURL, txHash, partition, intentID string, maxAttempts int) (*proof.CertenProof, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	base := id.config.ChainedProofInlineBackoff
	if base <= 0 {
		base = 2 * time.Second
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		chainedProof, err := id.proofGenerator.GenerateChainedProof(ctx, accountURL, txHash, partition)
		if err == nil {
			complete := proof.ChainedProofToCompleteProof(chainedProof)
			id.logger.Printf("✅ [REAL-PROOF] L1-L3 chained proof generated for %s (attempt %d/%d):",
				intentID, attempt, maxAttempts)
			id.logger.Printf("   L1: TxChainIndex=%d, BVNMinorBlockIndex=%d",
				chainedProof.Layer1.TxChainIndex, chainedProof.Layer1.BVNMinorBlockIndex)
			id.logger.Printf("   L2: DNMinorBlockIndex=%d", chainedProof.Layer2.DNMinorBlockIndex)
			id.logger.Printf("   L3: DNConsensusHeight=%d", chainedProof.Layer3.DNConsensusHeight)

			req := &proof.ProofRequest{
				RequestID:       fmt.Sprintf("intent_%s", intentID),
				ProofType:       "chained_l1_l2_l3",
				TransactionHash: txHash,
				AccountURL:      accountURL,
			}
			adapter := proof.NewCertenProofAdapter(complete, req, id.validatorID)
			certenProof := adapter.ToCertenProof()
			if certenProof == nil {
				return nil, fmt.Errorf("chained proof adapter returned nil CertenProof for %s", intentID)
			}
			return certenProof, nil
		}

		lastErr = err
		if attempt < maxAttempts {
			wait := chainedRetryBackoff(base, attempt-1, 30, 30*time.Second)
			id.logger.Printf("⏳ [REAL-PROOF] chained proof attempt %d/%d failed for %s: %v — retrying in %v",
				attempt, maxAttempts, intentID, err, wait)
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, fmt.Errorf("chained proof retry aborted for %s: %w", intentID, ctx.Err())
			case <-id.stopCh:
				return nil, fmt.Errorf("chained proof retry aborted for %s: shutting down", intentID)
			}
		}
	}
	return nil, lastErr
}

// enqueueRetry submits an on_demand intent for decoupled retry. Non-blocking: if the queue is
// full the retry is dropped and the intent remains failed (lifecycle=failed) for alerting.
func (id *IntentDiscovery) enqueueRetry(job *intentRetryJob) {
	if id.retryCh == nil {
		return
	}
	select {
	case id.retryCh <- job:
	default:
		id.logger.Printf("⚠️ [RETRY] retry queue full — dropping retry for on_demand intent %s (remains failed)", job.intent.IntentID)
	}
}

// retryWorker drains the decoupled on_demand retry queue, re-attempting consensus-bound proof
// generation off the block-worker critical path. Safe to retry: the retryable error is returned
// before any execution/anchor side effect, and markInProgress + the persisted watermark prevent
// double-execution.
func (id *IntentDiscovery) retryWorker() {
	defer func() {
		if r := recover(); r != nil {
			id.logger.Printf("🚨 PANIC in intent retry worker: %v", r)
		}
		id.logger.Printf("🛑 Intent retry worker exited")
	}()
	id.logger.Printf("🔁 Intent retry worker started (on_demand consensus-bound proof requeue)")

	for {
		select {
		case <-id.stopCh:
			return
		case job := <-id.retryCh:
			id.handleRetryJob(job)
		}
	}
}

// handleRetryJob waits out the backoff for one retry job, re-processes the intent, and either
// marks it complete, re-enqueues it (if still retryable and attempts remain), or fails it closed.
func (id *IntentDiscovery) handleRetryJob(job *intentRetryJob) {
	job.attempts++
	maxAttempts := id.config.ChainedProofRequeueAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	base := id.config.ChainedProofRequeueBackoff
	if base <= 0 {
		base = 10 * time.Second
	}
	backoff := chainedRetryBackoff(base, job.attempts-1, 5, 5*time.Minute)

	select {
	case <-time.After(backoff):
	case <-id.stopCh:
		return
	}

	// Idempotency: skip if the intent already completed via any path.
	if id.getIntentStatus(job.intent.IntentID) == IntentStatusCompleted {
		return
	}
	if !id.markInProgress(job.intent.IntentID) {
		// Already in progress or completed elsewhere — do not double-process.
		return
	}

	id.logger.Printf("🔁 [RETRY %d/%d] Re-processing on_demand intent %s", job.attempts, maxAttempts, job.intent.IntentID)
	err := id.processIntent(job.intent, job.blockHeight)
	if err == nil {
		id.markCompleted(job.intent.IntentID)
		id.logger.Printf("✅ [RETRY] on_demand intent %s succeeded on retry %d/%d", job.intent.IntentID, job.attempts, maxAttempts)
		return
	}

	id.markFailedClassified(job.intent.IntentID, err)
	if errors.Is(err, errChainedProofUnavailable) && job.attempts < maxAttempts {
		id.logger.Printf("⏳ [RETRY] on_demand intent %s proof still unavailable (attempt %d/%d): %v",
			job.intent.IntentID, job.attempts, maxAttempts, err)
		id.enqueueRetry(job)
		return
	}

	// Exhausted retries or terminal error — fail closed and record for alerting.
	id.logger.Printf("❌ [RETRY] on_demand intent %s PERMANENTLY FAILED after %d attempt(s): %v",
		job.intent.IntentID, job.attempts, err)
	if id.repos != nil && id.repos.IntentLifecycle != nil {
		lctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if lcErr := id.repos.IntentLifecycle.UpdateStatus(lctx, job.intent.IntentID,
			database.IntentLifecycleFailed,
			database.WithErrorMessage(err.Error()),
		); lcErr != nil {
			id.logger.Printf("⚠️ [LIFECYCLE] Failed to mark retry-exhausted intent %s failed: %v", job.intent.IntentID, lcErr)
		}
		cancel()
	}
}

func (id *IntentDiscovery) processIntent(intent *CertenIntent, blockHeight uint64) error {
	id.logger.Printf("🚀 Processing Certen intent: %s", intent.IntentID)

	// ENTITLEMENT PRE-SCREEN.
	//
	// Cheap, local, and purely an optimisation — the authoritative gate is the
	// consensus rule in the ABCI app, which every validator runs and none can
	// skip. This one exists because building an L1-L4 chained proof is real CPU
	// (and, for on_demand, retries against Accumulate), and doing that work for
	// an intent that can never execute is free denial-of-service.
	//
	// Deliberately NOT a security boundary: it reads this node's cached
	// entitlement snapshot, which may lag. It only ever declines work this node
	// would otherwise do; it can never admit anything.
	if !id.entitlementPreScreen(intent) {
		return nil // refused; nothing spent, nothing to retry
	}

	// Detect if this is a multi-leg intent
	isMultiLeg, err := intent.IsMultiLeg()
	if err != nil {
		id.logger.Printf("⚠️ Failed to detect multi-leg status for %s: %v", intent.IntentID, err)
	}

	if isMultiLeg && id.multiLegEnabled {
		return id.processMultiLegIntent(intent, blockHeight)
	}

	// Prefer canonical AccountURL; fall back to orgAdi/data if missing
	accountURL := intent.AccountURL
	if accountURL == "" && intent.OrganizationADI != "" {
		accountURL = fmt.Sprintf("%s/data", intent.OrganizationADI)
	}
	id.logger.Printf("🏗️ Using data account for proof: %s", accountURL)

	// 1️⃣ Extract proof class - CRITICAL for routing
	proofClass, err := intent.GetProofClass()
	if err != nil {
		id.logger.Printf("❌ Failed to extract proof class for intent %s: %v", intent.IntentID, err)
		return fmt.Errorf("extract proof class for intent %s: %w", intent.IntentID, err)
	}
	id.logger.Printf("📋 Intent %s has proofClass: %s", intent.IntentID, proofClass)

	// 2️⃣ Generate a REAL L1-L3 chained proof via lite client's ProofBuilder
	var certenProof *proof.CertenProof

	if id.proofGenerator != nil {
		ctx, cancel := context.WithTimeout(context.Background(), id.config.BFTTimeout)
		defer cancel()

		// REAL L1-L3 consensus-bound chained proof (requires txHash, partition, CometBFT binding).
		realProofApplicable := id.proofGenerator.HasRealProofBuilder() && intent.TransactionHash != "" && intent.Partition != ""
		if realProofApplicable {
			// on_demand (financial) gets in-line retry to absorb DN-anchoring latency / transient
			// DN-BVN RPC blips; on_cadence makes a single attempt and may fall back to a basic proof.
			inlineAttempts := 1
			if proofClass == "on_demand" {
				inlineAttempts = id.config.ChainedProofInlineRetries
			}
			id.logger.Printf("🔗 [REAL-PROOF] Generating L1-L3 chained proof for %s (txHash=%s, partition=%s, attempts=%d)",
				intent.IntentID, intent.TransactionHash[:16]+"...", intent.Partition, inlineAttempts)

			cp, perr := id.buildChainedCertenProof(ctx, accountURL, intent.TransactionHash, intent.Partition, intent.IntentID, inlineAttempts)
			if perr != nil {
				id.logger.Printf("⚠️ [REAL-PROOF] L1-L3 chained proof unavailable for %s: %v", intent.IntentID, perr)
			} else {
				certenProof = cp
				id.logger.Printf("✅ [REAL-PROOF] CertenProof created with L1-L3 chained proof for %s", intent.IntentID)
			}
		}

		// on_demand (financial) intents REQUIRE the consensus-bound chained proof and must NEVER
		// silently downgrade to a basic account proof. If it is unavailable, fail closed HERE —
		// before any execution/anchor side effect — so the caller can requeue (retryable, e.g.
		// DN-anchoring latency / transient RPC) or surface a terminal failure (misconfig).
		if certenProof == nil && proofClass == "on_demand" {
			if !realProofApplicable {
				return fmt.Errorf("on_demand intent %s: %w (realBuilder=%v txHash=%q partition=%q)",
					intent.IntentID, errChainedProofTerminal,
					id.proofGenerator.HasRealProofBuilder(), intent.TransactionHash, intent.Partition)
			}
			return fmt.Errorf("on_demand intent %s: %w", intent.IntentID, errChainedProofUnavailable)
		}

		// Fallback: Basic proof (on_cadence only — on_demand returned above).
		if certenProof == nil {
			id.logger.Printf("📋 [BASIC-PROOF] Falling back to basic proof for %s", intent.IntentID)
			complete, err := id.proofGenerator.GenerateProofForIntent(ctx, accountURL)
			if err != nil {
				id.logger.Printf("⚠️ Failed to generate basic proof for %s: %v", intent.IntentID, err)

				// For on_demand intents, proof failure is a hard error
				if proofClass == "on_demand" {
					id.logger.Printf("❌ on_demand intent %s REQUIRES proof - cannot proceed without CertenProof", intent.IntentID)
					return fmt.Errorf("on_demand intent %s requires proof but proof generation failed: %w", intent.IntentID, err)
				} else {
					id.logger.Printf("⚠️ Proceeding without proof for %s intent %s (proof failure allowed for cadence intents)", proofClass, intent.IntentID)
				}
			} else {
				// Build a minimal ProofRequest for adapter
				req := &proof.ProofRequest{
					RequestID:       fmt.Sprintf("intent_%s", intent.IntentID),
					ProofType:       "account",
					TransactionHash: intent.TransactionHash,
					AccountURL:      accountURL,
				}

				adapter := proof.NewCertenProofAdapter(complete, req, id.validatorID)
				certenProof = adapter.ToCertenProof()
				if certenProof == nil {
					if proofClass == "on_demand" {
						return fmt.Errorf("on_demand intent %s: adapter returned nil CertenProof", intent.IntentID)
					}
					id.logger.Printf("⚠️ Adapter returned nil CertenProof for %s intent %s", proofClass, intent.IntentID)
				} else {
					id.logger.Printf("✅ Generated basic CertenProof for intent %s", intent.IntentID)
				}
			}
		}
	} else {
		// For on_demand intents, missing proof generator is a hard error
		if proofClass == "on_demand" {
			id.logger.Printf("❌ on_demand intent %s REQUIRES ProofGenerator but none configured", intent.IntentID)
			return fmt.Errorf("on_demand intent %s requires ProofGenerator but none configured", intent.IntentID)
		} else {
			id.logger.Printf("⚠️ No proofGenerator configured for %s intent %s", proofClass, intent.IntentID)
		}
	}

	// 2.5️⃣ Generate G0/G1/G2 governance proof BEFORE routing to batch system
	// This ensures the generated proof (not input config) is persisted to PostgreSQL
	var govProof *proof.GovernanceProof
	if id.governanceProofGen != nil && certenProof != nil {
		// Extract key page from governance data for G1+ proofs
		var keyPageURL string
		if len(intent.GovernanceData) > 0 {
			var govConfig struct {
				Authorization struct {
					RequiredKeyBook string `json:"required_key_book"`
				} `json:"authorization"`
			}
			if err := json.Unmarshal(intent.GovernanceData, &govConfig); err == nil {
				if govConfig.Authorization.RequiredKeyBook != "" {
					keyPageURL = govConfig.Authorization.RequiredKeyBook + "/1"
				}
			}
		}

		// Build governance request
		govRequest := &proof.GovernanceRequest{
			AccountURL:      accountURL,
			TransactionHash: intent.TransactionHash,
			KeyPage:         keyPageURL,
			Chain:           "main",
		}

		// G0→G1→G2 are generated in sequence below; each CLI level re-derives its predecessors,
		// so the full sequence needs ~90s. 30s cut off G1/G2 and committed G0-only. This budget is
		// independent of the consensus broadcast (which has its own context), so it can be generous.
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		// Generate G0 proof (Inclusion & Finality)
		g0Wrapper, g0Err := id.governanceProofGen.GenerateG0(ctx, govRequest)
		if g0Err != nil {
			id.logger.Printf("⚠️ [GOV-PROOF] G0 proof generation failed: %v", g0Err)
		} else if g0Wrapper != nil {
			govProof = g0Wrapper
			id.logger.Printf("✅ [GOV-PROOF] G0 proof generated for intent %s", intent.IntentID)

			// Try G1 if key page is available
			if keyPageURL != "" {
				g1Wrapper, g1Err := id.governanceProofGen.GenerateG1(ctx, govRequest)
				if g1Err != nil {
					id.logger.Printf("⚠️ [GOV-PROOF] G1 proof generation failed: %v", g1Err)
				} else if g1Wrapper != nil {
					govProof = g1Wrapper
					id.logger.Printf("✅ [GOV-PROOF] G1 proof generated for intent %s", intent.IntentID)

					// Try G2
					g2Wrapper, g2Err := id.governanceProofGen.GenerateG2(ctx, govRequest)
					if g2Err != nil {
						id.logger.Printf("⚠️ [GOV-PROOF] G2 proof generation failed: %v", g2Err)
					} else if g2Wrapper != nil {
						govProof = g2Wrapper
						id.logger.Printf("✅ [GOV-PROOF] G2 proof generated for intent %s", intent.IntentID)
					}
				}
			}
		}
		cancel()
	} else if id.governanceProofGen == nil {
		id.logger.Printf("⚠️ [GOV-PROOF] Governance proof generator not configured - using fallback")
	}

	// 3️⃣ PHASE 5: Route to batch system for PostgreSQL persistence and CertenAnchorProof assembly
	if id.batchingEnabled {
		if err := id.routeIntentToBatchSystem(intent, certenProof, govProof, proofClass, blockHeight); err != nil {
			id.logger.Printf("⚠️ Batch system routing failed for intent %s: %v", intent.IntentID, err)
			// Continue with BFT consensus even if batch routing fails
		} else {
			id.logger.Printf("✅ Intent %s routed to batch system for PostgreSQL persistence", intent.IntentID)
		}
	} else {
		id.logger.Printf("⚠️ Batch system not enabled - intent %s will not be persisted to PostgreSQL", intent.IntentID)
	}

	// 4️⃣ Execute via canonical BFT API – ValidatorBlock creation
	if id.bftConsensus != nil {
		ctx, cancel := context.WithTimeout(context.Background(), id.config.BFTTimeout)
		defer cancel()

		err = id.bftConsensus.ExecuteCanonicalIntentWithBFTConsensus(
			ctx,
			(*consensus.CertenIntent)(intent), // alias, but cast for clarity
			certenProof,
			blockHeight,
		)
		if err != nil {
			id.logger.Printf("❌ Canonical BFT consensus execution failed for intent %s: %v", intent.IntentID, err)
			return err
		}

		id.logger.Printf("✅ Canonical BFT consensus execution completed for intent: %s", intent.IntentID)
	} else {
		id.logger.Printf("⚠️ No BFT consensus configured - skipping ValidatorBlock creation for %s", intent.IntentID)
	}

	id.mu.Lock()
	id.intentCount++
	id.mu.Unlock()

	return nil
}

// routeIntentToBatchSystem routes an intent to the appropriate batch handler based on proofClass
// PHASE 5: This enables PostgreSQL persistence and CertenAnchorProof assembly
// govProof is the generated G0/G1/G2 governance proof (may be nil if not generated)
func (id *IntentDiscovery) routeIntentToBatchSystem(intent *CertenIntent, certenProof *proof.CertenProof, govProof *proof.GovernanceProof, proofClass string, blockHeight uint64) error {
	// Check if this is a multi-leg intent that should create per-leg batch transactions
	if len(intent.CrossChainData) > 0 {
		var ccEnvelope consensus.CrossChainEnvelope
		if err := json.Unmarshal(intent.CrossChainData, &ccEnvelope); err == nil && len(ccEnvelope.Legs) > 1 {
			id.logger.Printf("📦 [MULTI-LEG] Routing %d legs as separate batch transactions for intent %s",
				len(ccEnvelope.Legs), intent.IntentID)
			return id.routeMultiLegToBatchSystem(intent, ccEnvelope.Legs, certenProof, govProof, proofClass, blockHeight)
		}
	}

	// Convert intent to batch transaction data
	txData, err := id.convertIntentToTransactionData(intent, certenProof, govProof)
	if err != nil {
		return fmt.Errorf("convert intent to transaction data: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch proofClass {
	case "on_demand":
		// Immediate anchoring via OnDemandHandler
		if id.onDemandHandler == nil {
			return fmt.Errorf("on_demand intent %s but OnDemandHandler not configured", intent.IntentID)
		}

		id.logger.Printf("📦 Routing on_demand intent %s to OnDemandHandler", intent.IntentID)
		result, err := id.onDemandHandler.ProcessTransaction(ctx, txData)
		if err != nil {
			return fmt.Errorf("on_demand handler failed: %w", err)
		}

		if result.AnchorTriggered {
			id.logger.Printf("⚡ On-demand anchor triggered for intent %s (batch: %s)",
				intent.IntentID, result.BatchResult.BatchID)
		} else {
			id.logger.Printf("📦 Intent %s added to on-demand batch (size: %d)",
				intent.IntentID, result.TransactionResult.BatchSize)
		}

	case "on_cadence":
		// Batched anchoring via Collector
		if id.batchCollector == nil {
			return fmt.Errorf("on_cadence intent %s but BatchCollector not configured", intent.IntentID)
		}

		id.logger.Printf("📦 Routing on_cadence intent %s to BatchCollector", intent.IntentID)
		result, err := id.batchCollector.AddOnCadenceTransaction(ctx, txData)
		if err != nil {
			return fmt.Errorf("batch collector failed: %w", err)
		}

		id.logger.Printf("📦 Intent %s added to on-cadence batch %s (position: %d)",
			intent.IntentID, result.BatchID, result.TreeIndex)

	default:
		// Default to on_cadence for unknown proof classes
		id.logger.Printf("⚠️ Unknown proofClass '%s' for intent %s, defaulting to on_cadence", proofClass, intent.IntentID)
		if id.batchCollector != nil {
			_, err := id.batchCollector.AddOnCadenceTransaction(ctx, txData)
			if err != nil {
				return fmt.Errorf("batch collector (default) failed: %w", err)
			}
		}
	}

	return nil
}

// routeMultiLegToBatchSystem creates separate batch transactions for each leg of a multi-leg intent
func (id *IntentDiscovery) routeMultiLegToBatchSystem(
	intent *CertenIntent,
	legs []consensus.CCLeg,
	certenProof *proof.CertenProof,
	govProof *proof.GovernanceProof,
	proofClass string,
	blockHeight uint64,
) error {
	for i, leg := range legs {
		txData, err := id.convertLegToTransactionData(intent, &leg, i, certenProof, govProof)
		if err != nil {
			id.logger.Printf("⚠️ [MULTI-LEG] Failed to convert leg %d: %v", i, err)
			continue
		}
		// Tag with multi-leg metadata (generate UUID for leg_id since DB column is UUID type)
		txData.MultiLegIntentID = intent.IntentID
		txData.LegID = uuid.New().String()

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		switch proofClass {
		case "on_demand":
			if id.onDemandHandler == nil {
				cancel()
				return fmt.Errorf("on_demand but OnDemandHandler not configured")
			}
			result, err := id.onDemandHandler.ProcessTransaction(ctx, txData)
			if err != nil {
				cancel()
				return fmt.Errorf("on_demand handler failed for leg %d: %w", i, err)
			}
			if result.AnchorTriggered {
				id.logger.Printf("⚡ [MULTI-LEG] Leg %d anchor triggered (batch: %s)", i, result.BatchResult.BatchID)
			}

		case "on_cadence":
			if id.batchCollector == nil {
				cancel()
				return fmt.Errorf("on_cadence but BatchCollector not configured")
			}
			result, err := id.batchCollector.AddOnCadenceTransaction(ctx, txData)
			if err != nil {
				cancel()
				return fmt.Errorf("batch collector failed for leg %d: %w", i, err)
			}
			id.logger.Printf("📦 [MULTI-LEG] Leg %d added to batch %s (chain: %s)", i, result.BatchID, leg.Chain)

		default:
			if id.batchCollector != nil {
				_, err := id.batchCollector.AddOnCadenceTransaction(ctx, txData)
				if err != nil {
					cancel()
					return fmt.Errorf("batch collector (default) failed for leg %d: %w", i, err)
				}
			}
		}
		cancel()
	}
	return nil
}

// =============================================================================
// Multi-Leg Intent Processing
// =============================================================================

// processMultiLegIntent handles intents with multiple legs
// Routes legs grouped by target chain to the appropriate batch system
func (id *IntentDiscovery) processMultiLegIntent(intent *CertenIntent, blockHeight uint64) error {
	id.logger.Printf("🔀 Processing multi-leg intent: %s", intent.IntentID)

	// Get execution mode
	execMode, err := intent.GetExecutionMode()
	if err != nil {
		execMode = "sequential"
	}
	id.logger.Printf("   Execution mode: %s", execMode)

	// Get leg count
	legCount, err := intent.GetLegCount()
	if err != nil {
		return fmt.Errorf("get leg count: %w", err)
	}
	id.logger.Printf("   Leg count: %d", legCount)

	// Register intent with leg completion handler
	var intentRecord *MultiLegIntentRecord
	if id.legCompletionHandler != nil {
		record, err := id.legCompletionHandler.RegisterIntent((*consensus.CertenIntent)(intent), blockHeight)
		if err != nil {
			return fmt.Errorf("register multi-leg intent: %w", err)
		}
		intentRecord = record
		id.logger.Printf("   Registered with %d chain groups", len(record.ChainGroups))
	}

	// Group legs by target chain
	legsGrouped, err := intent.GetLegsGroupedByChain()
	if err != nil {
		return fmt.Errorf("group legs by chain: %w", err)
	}
	id.logger.Printf("   Chain groups: %v", func() []string {
		keys := make([]string, 0, len(legsGrouped))
		for k := range legsGrouped {
			keys = append(keys, k)
		}
		return keys
	}())

	// Generate proofs (same for all legs)
	accountURL := intent.AccountURL
	if accountURL == "" && intent.OrganizationADI != "" {
		accountURL = fmt.Sprintf("%s/data", intent.OrganizationADI)
	}

	proofClass, err := intent.GetProofClass()
	if err != nil {
		proofClass = "on_cadence"
	}

	// Generate CertenProof
	var certenProof *proof.CertenProof
	var govProof *proof.GovernanceProof

	if id.proofGenerator != nil {
		ctx, cancel := context.WithTimeout(context.Background(), id.config.BFTTimeout)
		defer cancel()

		// REAL L1-L3 consensus-bound chained proof (same fail-closed policy as single-leg).
		realProofApplicable := id.proofGenerator.HasRealProofBuilder() && intent.TransactionHash != "" && intent.Partition != ""
		if realProofApplicable {
			inlineAttempts := 1
			if proofClass == "on_demand" {
				inlineAttempts = id.config.ChainedProofInlineRetries
			}
			id.logger.Printf("🔗 [MULTI-LEG] Generating L1-L3 chained proof for %s (attempts=%d)", intent.IntentID, inlineAttempts)

			cp, perr := id.buildChainedCertenProof(ctx, accountURL, intent.TransactionHash, intent.Partition, intent.IntentID, inlineAttempts)
			if perr != nil {
				id.logger.Printf("⚠️ [MULTI-LEG] L1-L3 chained proof unavailable for %s: %v", intent.IntentID, perr)
			} else {
				certenProof = cp
				id.logger.Printf("✅ [MULTI-LEG] CertenProof created for all legs of %s", intent.IntentID)
			}
		}

		// on_demand multi-leg REQUIRES the consensus-bound chained proof — no silent downgrade.
		// Fail closed here; RegisterIntent (above) is idempotent so the requeue is replay-safe.
		if certenProof == nil && proofClass == "on_demand" {
			if !realProofApplicable {
				return fmt.Errorf("on_demand multi-leg intent %s: %w (realBuilder=%v txHash=%q partition=%q)",
					intent.IntentID, errChainedProofTerminal,
					id.proofGenerator.HasRealProofBuilder(), intent.TransactionHash, intent.Partition)
			}
			return fmt.Errorf("on_demand multi-leg intent %s: %w", intent.IntentID, errChainedProofUnavailable)
		}

		// Fallback to basic proof (on_cadence only — on_demand returned above).
		if certenProof == nil {
			id.logger.Printf("📋 [MULTI-LEG] Using basic proof for %s", intent.IntentID)
			complete, err := id.proofGenerator.GenerateProofForIntent(ctx, accountURL)
			if err != nil {
				id.logger.Printf("⚠️ [MULTI-LEG] Basic proof failed: %v", err)
			} else {
				req := &proof.ProofRequest{
					RequestID:       fmt.Sprintf("multileg_%s", intent.IntentID),
					ProofType:       "account",
					TransactionHash: intent.TransactionHash,
					AccountURL:      accountURL,
				}
				adapter := proof.NewCertenProofAdapter(complete, req, id.validatorID)
				certenProof = adapter.ToCertenProof()
			}
		}
	} else if proofClass == "on_demand" {
		// No proof generator configured at all — on_demand cannot proceed without a proof.
		return fmt.Errorf("on_demand multi-leg intent %s requires ProofGenerator but none configured", intent.IntentID)
	}

	// Generate governance proof if available
	if id.governanceProofGen != nil && certenProof != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		govRequest := &proof.GovernanceRequest{
			AccountURL:      accountURL,
			TransactionHash: intent.TransactionHash,
			Chain:           "main",
		}
		g0Wrapper, g0Err := id.governanceProofGen.GenerateG0(ctx, govRequest)
		if g0Err == nil && g0Wrapper != nil {
			govProof = g0Wrapper
		}
		cancel()
	}

	// Route based on execution mode
	switch execMode {
	case "sequential":
		// Execute first chain group, then next chain group
		err = id.routeSequentialChainGroups(intent, legsGrouped, certenProof, govProof, proofClass, blockHeight, intentRecord)
	case "parallel":
		// Execute all chain groups in parallel
		err = id.routeParallelChainGroups(intent, legsGrouped, certenProof, govProof, proofClass, blockHeight, intentRecord)
	case "atomic":
		// All chain groups must succeed or all rollback
		err = id.routeAtomicChainGroups(intent, legsGrouped, certenProof, govProof, proofClass, blockHeight, intentRecord)
	default:
		// Default to sequential
		err = id.routeSequentialChainGroups(intent, legsGrouped, certenProof, govProof, proofClass, blockHeight, intentRecord)
	}

	if err != nil {
		return fmt.Errorf("route multi-leg intent: %w", err)
	}

	id.logger.Printf("✅ Multi-leg intent %s routed to batch system", intent.IntentID)

	// Execute via BFT consensus
	if id.bftConsensus != nil {
		ctx, cancel := context.WithTimeout(context.Background(), id.config.BFTTimeout)
		defer cancel()

		err = id.bftConsensus.ExecuteCanonicalIntentWithBFTConsensus(
			ctx,
			(*consensus.CertenIntent)(intent),
			certenProof,
			blockHeight,
		)
		if err != nil {
			id.logger.Printf("❌ BFT consensus failed for multi-leg intent %s: %v", intent.IntentID, err)
			return err
		}
		id.logger.Printf("✅ BFT consensus completed for multi-leg intent: %s", intent.IntentID)
	}

	id.mu.Lock()
	id.intentCount++
	id.mu.Unlock()

	return nil
}

// routeSequentialChainGroups routes chain groups one at a time (sequential mode)
func (id *IntentDiscovery) routeSequentialChainGroups(
	intent *CertenIntent,
	legsGrouped map[string][]consensus.CCLeg,
	certenProof *proof.CertenProof,
	govProof *proof.GovernanceProof,
	proofClass string,
	blockHeight uint64,
	intentRecord *MultiLegIntentRecord,
) error {
	// For sequential mode, we only route the first chain group initially
	// Subsequent groups are triggered by the LegCompletionHandler when the first completes
	firstGroup := true
	for chainKey, legs := range legsGrouped {
		if firstGroup {
			id.logger.Printf("📦 [SEQUENTIAL] Routing first chain group %s with %d legs", chainKey, len(legs))
			if err := id.routeChainLegsToBatchSystem(intent, chainKey, legs, certenProof, govProof, proofClass, blockHeight); err != nil {
				return fmt.Errorf("route chain group %s: %w", chainKey, err)
			}
			firstGroup = false
		} else {
			id.logger.Printf("📋 [SEQUENTIAL] Chain group %s with %d legs queued for later", chainKey, len(legs))
		}
	}
	return nil
}

// routeParallelChainGroups routes all chain groups simultaneously (parallel mode)
func (id *IntentDiscovery) routeParallelChainGroups(
	intent *CertenIntent,
	legsGrouped map[string][]consensus.CCLeg,
	certenProof *proof.CertenProof,
	govProof *proof.GovernanceProof,
	proofClass string,
	blockHeight uint64,
	intentRecord *MultiLegIntentRecord,
) error {
	// Route all chain groups
	for chainKey, legs := range legsGrouped {
		id.logger.Printf("📦 [PARALLEL] Routing chain group %s with %d legs", chainKey, len(legs))
		if err := id.routeChainLegsToBatchSystem(intent, chainKey, legs, certenProof, govProof, proofClass, blockHeight); err != nil {
			return fmt.Errorf("route chain group %s: %w", chainKey, err)
		}
	}
	return nil
}

// routeAtomicChainGroups routes all chain groups with atomic rollback support
func (id *IntentDiscovery) routeAtomicChainGroups(
	intent *CertenIntent,
	legsGrouped map[string][]consensus.CCLeg,
	certenProof *proof.CertenProof,
	govProof *proof.GovernanceProof,
	proofClass string,
	blockHeight uint64,
	intentRecord *MultiLegIntentRecord,
) error {
	// For atomic mode, we route all groups but track them for potential rollback
	id.logger.Printf("⚛️ [ATOMIC] Routing all chain groups atomically")

	var errors []error
	for chainKey, legs := range legsGrouped {
		id.logger.Printf("📦 [ATOMIC] Routing chain group %s with %d legs", chainKey, len(legs))
		if err := id.routeChainLegsToBatchSystem(intent, chainKey, legs, certenProof, govProof, proofClass, blockHeight); err != nil {
			errors = append(errors, fmt.Errorf("chain group %s: %w", chainKey, err))
		}
	}

	if len(errors) > 0 {
		// In atomic mode, any failure should trigger rollback consideration
		id.logger.Printf("⚠️ [ATOMIC] %d chain groups failed - rollback may be needed", len(errors))
		return fmt.Errorf("atomic routing failed: %d errors", len(errors))
	}

	return nil
}

// routeChainLegsToBatchSystem routes all legs for a specific chain to that chain's anchor
func (id *IntentDiscovery) routeChainLegsToBatchSystem(
	intent *CertenIntent,
	chainKey string,
	legs []consensus.CCLeg,
	certenProof *proof.CertenProof,
	govProof *proof.GovernanceProof,
	proofClass string,
	blockHeight uint64,
) error {
	id.logger.Printf("📦 Routing %d legs for chain %s to batch system", len(legs), chainKey)

	// For each leg, create a transaction and route to batch system
	for i, leg := range legs {
		// Create transaction data for this leg
		txData, err := id.convertLegToTransactionData(intent, &leg, i, certenProof, govProof)
		if err != nil {
			id.logger.Printf("⚠️ Failed to convert leg %d to transaction data: %v", i, err)
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		switch proofClass {
		case "on_demand":
			if id.onDemandHandler == nil {
				cancel()
				return fmt.Errorf("on_demand but OnDemandHandler not configured")
			}
			id.logger.Printf("⚡ [LEG %d] Routing to OnDemandHandler", i)
			result, err := id.onDemandHandler.ProcessTransaction(ctx, txData)
			if err != nil {
				cancel()
				return fmt.Errorf("on_demand handler failed for leg %d: %w", i, err)
			}
			if result.AnchorTriggered {
				id.logger.Printf("⚡ [LEG %d] Anchor triggered (batch: %s)", i, result.BatchResult.BatchID)
			}

		case "on_cadence":
			if id.batchCollector == nil {
				cancel()
				return fmt.Errorf("on_cadence but BatchCollector not configured")
			}
			id.logger.Printf("📦 [LEG %d] Routing to BatchCollector", i)
			result, err := id.batchCollector.AddOnCadenceTransaction(ctx, txData)
			if err != nil {
				cancel()
				return fmt.Errorf("batch collector failed for leg %d: %w", i, err)
			}
			id.logger.Printf("📦 [LEG %d] Added to batch %s (position: %d)", i, result.BatchID, result.TreeIndex)
		}

		cancel()
	}

	return nil
}

// convertLegToTransactionData converts a single leg to batch.TransactionData
func (id *IntentDiscovery) convertLegToTransactionData(
	intent *CertenIntent,
	leg *consensus.CCLeg,
	legIndex int,
	certenProof *proof.CertenProof,
	govProof *proof.GovernanceProof,
) (*batch.TransactionData, error) {
	// Compute unique transaction hash for this leg
	legData := fmt.Sprintf("%s:leg:%d:%s", intent.TransactionHash, legIndex, leg.LegID)
	txHash := sha256.Sum256([]byte(legData))

	// Build TransactionData for this leg
	txData := &batch.TransactionData{
		AccumTxHash: intent.TransactionHash,
		AccountURL:  intent.AccountURL,
		TxHash:      txHash[:],
		IntentType:  "certen_intent",
		IntentData:  intent.IntentData,
		UserID:      intent.UserID,
		IntentID:    intent.IntentID,
		TargetChain: leg.Chain,
		FromChain:   "accumulate",
		ToChain:     leg.Chain,
		FromAddress: leg.From,
		ToAddress:   leg.To,
		TokenSymbol: leg.Asset.Symbol,
	}

	// Set amount — prefer human-readable AmountEth for display correctness
	if leg.AmountEth != "" {
		txData.Amount = leg.AmountEth
	} else if leg.AmountWei != "" {
		txData.Amount = leg.AmountWei
	}

	// Extract ADI URL
	if intent.OrganizationADI != "" {
		txData.AdiURL = intent.OrganizationADI
	}

	// Add proofs
	if certenProof != nil && certenProof.LiteClientProof != nil {
		chainedBytes, err := json.Marshal(certenProof.LiteClientProof)
		if err == nil {
			txData.ChainedProof = chainedBytes
		}
	}

	if govProof != nil {
		govProofBytes, err := json.Marshal(govProof)
		if err == nil {
			txData.GovProof = govProofBytes
			txData.GovLevel = string(govProof.Level)
		}
	}

	return txData, nil
}

// Helper methods

// isCertenIntent checks if a transaction is a Certen intent (CRITICAL legacy method)
func (id *IntentDiscovery) isCertenIntent(tx *accumulate.Transaction) bool {
	// Check for CERTEN_INTENT memo in transaction header
	// Accept both "CERTEN_INTENT" (canonical) and "certen-intent" (legacy) formats
	if header, ok := tx.Data["header"].(map[string]interface{}); ok {
		if memo, ok := header["memo"].(string); ok {
			if memo == CERTEN_INTENT_MEMO || strings.EqualFold(memo, "certen-intent") {
				return true
			}
		}
	}

	// Check for CERTEN_INTENT memo in transaction data (fallback)
	// Accept both "CERTEN_INTENT" (canonical) and "certen-intent" (legacy) formats
	if data, ok := tx.Data["memo"]; ok {
		if memo, ok := data.(string); ok {
			if memo == CERTEN_INTENT_MEMO || strings.EqualFold(memo, "certen-intent") {
				return true
			}
		}
	}

	// Also check if transaction type is writeData with correct structure
	if body, ok := tx.Data["body"].(map[string]interface{}); ok {
		if txType, ok := body["type"].(string); ok && txType == "writeData" {
			// Check for DoubleHashDataEntry with 4 data elements
			if entry, ok := body["entry"].(map[string]interface{}); ok {
				if entryType, ok := entry["type"].(string); ok && entryType == "doubleHash" {
					if data, ok := entry["data"].([]interface{}); ok && len(data) == 4 {
						return true
					}
				}
			}
		}
	}

	return false
}

// markInProgress atomically checks if an intent can be processed and marks it as in_progress
// E.4 remediation: Two-phase marking to handle processing failures
// Returns true if the intent was newly marked as in_progress, false if already processing/completed
func (id *IntentDiscovery) markInProgress(intentID string) bool {
	id.mu.Lock()
	defer id.mu.Unlock()

	status, exists := id.intentStatus[intentID]
	if exists {
		// Only allow processing if not already in_progress or completed.
		// Failed intents CAN be retried — EXCEPT permanently invalid ones,
		// which no retry can fix and which would otherwise be rediscovered and
		// re-refused on every poll for the life of the process.
		if status == IntentStatusInProgress ||
			status == IntentStatusCompleted ||
			status == IntentStatusFailedPermanent {
			return false // Already being processed, completed, or unfixable
		}
	}

	id.intentStatus[intentID] = IntentStatusInProgress
	id.intentCount++
	return true // Newly marked as in_progress
}

// markCompleted marks an intent as successfully completed
// E.4 remediation: Two-phase marking - final success state
func (id *IntentDiscovery) markCompleted(intentID string) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.intentStatus[intentID] = IntentStatusCompleted
}

// markFailed marks an intent as failed (can be retried later)
// E.4 remediation: Two-phase marking - failure state allows retry
//
// A permanently invalid intent is recorded as terminal instead, so it is not
// rediscovered and re-refused on every subsequent poll.
func (id *IntentDiscovery) markFailed(intentID string) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.intentStatus[intentID] = IntentStatusFailed
}

// markFailedTerminal records a failure that no retry can fix.
func (id *IntentDiscovery) markFailedTerminal(intentID string) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.intentStatus[intentID] = IntentStatusFailedPermanent
}

// markFailedClassified routes an intent to the retryable or terminal failure
// state based on the error. Classification lives here rather than at each call
// site so a new terminal condition only has to be wrapped, not wired.
func (id *IntentDiscovery) markFailedClassified(intentID string, err error) {
	if errors.Is(err, consensus.ErrIntentPermanentlyInvalid) {
		id.logger.Printf("⛔ Intent %s is permanently invalid; will not be retried: %v", intentID, err)
		id.markFailedTerminal(intentID)
		return
	}
	id.markFailed(intentID)
}

// getIntentStatus returns the current status of an intent
func (id *IntentDiscovery) getIntentStatus(intentID string) IntentStatus {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.intentStatus[intentID]
}

// DEPRECATED: Use markInProgress for race-free two-phase processing
func (id *IntentDiscovery) markIfNew(intentID string) bool {
	return id.markInProgress(intentID)
}

// DEPRECATED: Use getIntentStatus instead
func (id *IntentDiscovery) isIntentProcessed(intentID string) bool {
	id.mu.RLock()
	defer id.mu.RUnlock()
	status := id.intentStatus[intentID]
	return status == IntentStatusCompleted || status == IntentStatusInProgress
}

// DEPRECATED: Use markCompleted instead
func (id *IntentDiscovery) markIntentProcessed(intentID string) {
	id.markCompleted(intentID)
}

// GetMetrics returns discovery service metrics
func (id *IntentDiscovery) GetMetrics() map[string]interface{} {
	id.mu.RLock()
	defer id.mu.RUnlock()

	// E.4 remediation: Count intents by status
	var inProgress, completed, failed int
	for _, status := range id.intentStatus {
		switch status {
		case IntentStatusInProgress:
			inProgress++
		case IntentStatusCompleted:
			completed++
		case IntentStatusFailed:
			failed++
		}
	}

	return map[string]interface{}{
		"is_monitoring":        id.isMonitoring,
		"last_processed_block": id.lastProcessedBlock,
		"intents_discovered":   id.intentCount,
		"intents_total":        len(id.intentStatus),
		"intents_in_progress":  inProgress,
		"intents_completed":    completed,
		"intents_failed":       failed,
		"accumulate_url":       id.accumulateURL,
	}
}

// Data categorization helper methods for proper blob separation

// isIntentData checks if data should go into intentData blob
func (id *IntentDiscovery) isIntentData(data map[string]interface{}) bool {
	// Check for known intent data fields
	_, hasKind := data["kind"]
	_, hasVersion := data["version"]
	_, hasIntentType := data["intentType"]
	_, hasOrganizationADI := data["organizationAdi"]
	_, hasDescription := data["description"]

	return hasKind || hasVersion || hasIntentType || hasOrganizationADI || hasDescription
}

// isCrossChainData checks if data should go into crossChainData blob
func (id *IntentDiscovery) isCrossChainData(data map[string]interface{}) bool {
	// Check for known cross-chain fields
	_, hasProtocol := data["protocol"]
	_, hasLegs := data["legs"]
	_, hasOperationGroupId := data["operationGroupId"]
	_, hasTargetChain := data["targetChain"]
	_, hasAtomicity := data["atomicity"]
	_, hasChainId := data["chainId"]

	return hasProtocol || hasLegs || hasOperationGroupId || hasTargetChain || hasAtomicity || hasChainId
}

// isGovernanceData checks if data should go into governanceData blob
func (id *IntentDiscovery) isGovernanceData(data map[string]interface{}) bool {
	// Check for known governance fields
	_, hasAuthorization := data["authorization"]
	_, hasGovernance := data["governance"]
	_, hasRequiredKeyBook := data["required_key_book"]
	_, hasRequiredKeyPage := data["required_key_page"]
	_, hasSignatureThreshold := data["signature_threshold"]
	_, hasRoles := data["roles"]

	return hasAuthorization || hasGovernance || hasRequiredKeyBook || hasRequiredKeyPage || hasSignatureThreshold || hasRoles
}

// isReplayData checks if data should go into replayData blob
func (id *IntentDiscovery) isReplayData(data map[string]interface{}) bool {
	// Check for known replay protection fields
	_, hasNonce := data["nonce"]
	_, hasClientNonce := data["clientNonce"]
	_, hasClientOperationId := data["clientOperationId"]
	_, hasCreatedAt := data["createdAt"]
	_, hasNotBefore := data["notBefore"]
	_, hasExpiresAt := data["expiresAt"]
	_, hasReplayProtection := data["replayProtection"]
	_, hasMaxExecutionDelay := data["maxExecutionDelaySeconds"]

	return hasNonce || hasClientNonce || hasClientOperationId || hasCreatedAt || hasNotBefore || hasExpiresAt || hasReplayProtection || hasMaxExecutionDelay
}
