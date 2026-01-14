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
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/batch"
	"github.com/certen/independant-validator/pkg/commitment"
	"github.com/certen/independant-validator/pkg/consensus"
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
	CERTEN_INTENT_MEMO     = "CERTEN_INTENT"
	MAX_CONCURRENT_BLOCKS  = 2000  // Increased to handle large block gaps during restarts
	INTENT_BATCH_SIZE      = 5
)

// IntentDiscoveryConfig contains configuration for intent discovery
type IntentDiscoveryConfig struct {
	BlockPollInterval   time.Duration `json:"block_poll_interval"`
	BFTTimeout          time.Duration `json:"bft_timeout"`
	MaxConcurrentBlocks int           `json:"max_concurrent_blocks"`
	IntentBatchSize     int           `json:"intent_batch_size"`
	MinStartHeight      uint64        `json:"min_start_height"`  // Minimum starting height fallback
}

// IntentStatus represents the processing state of an intent
// Per E.4 remediation: Two-phase marking to handle processing failures
type IntentStatus int

const (
	IntentStatusPending    IntentStatus = iota // Not yet processed
	IntentStatusInProgress                     // Currently being processed
	IntentStatusCompleted                      // Successfully processed
	IntentStatusFailed                         // Processing failed, can be retried
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
	default:
		return "unknown"
	}
}

// IntentDiscovery monitors Accumulate blockchain for Certen transaction intents
type IntentDiscovery struct {
	client          accumulate.Client
	accumulateURL   string
	config          *IntentDiscoveryConfig
	ledgerStore     LedgerStoreInterface  // For persistence
	logger          *log.Logger
	bftConsensus    BFTConsensusProtocol
	proofGenerator  *proof.LiteClientProofGenerator
	validatorID     string

	// PHASE 5: Batch system integration for PostgreSQL persistence and proof assembly
	batchCollector       *batch.Collector               // For on-cadence batching
	onDemandHandler      *batch.OnDemandHandler         // For immediate on-demand anchoring
	batchingEnabled      bool                           // Toggle for batch system routing
	governanceProofGen   proof.GovernanceProofGenerator // For G0/G1/G2 proof generation

	// Block monitoring state
	lastProcessedBlock  uint64
	isMonitoring       bool
	stopCh             chan struct{}
	blockProcessCh     chan *BlockProcessJob
	mu                 sync.RWMutex

	// Intent tracking - E.4 remediation: Two-phase status tracking
	intentStatus       map[string]IntentStatus // Tracks status of each intent
	intentCount        int64                   // Total intents discovered
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
		BlockPollInterval:   5 * time.Second,
		BFTTimeout:          60 * time.Second,  // Increased from 30s for WAN latency
		MaxConcurrentBlocks: MAX_CONCURRENT_BLOCKS,
		IntentBatchSize:     INTENT_BATCH_SIZE,
		MinStartHeight:      946000,  // Current testnet baseline
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

	return &IntentDiscovery{
		client:           client,
		accumulateURL:    accumulateURL,
		config:           config,
		ledgerStore:      ledgerStore,
		logger:           log.New(log.Writer(), "[INTENT-DISCOVERY] ", log.LstdFlags),
		proofGenerator:   proofGen,
		validatorID:      validatorID,
		intentStatus:     make(map[string]IntentStatus), // E.4 remediation: Two-phase status tracking
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

	// Start main monitoring loop
	go id.monitoringLoop()

	id.logger.Printf("✅ Intent discovery service started successfully with 3 workers")
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
			id.logger.Printf("🔄 Intent discovery tick - checking for new blocks...")
			if err := id.checkForNewBlocks(ctx); err != nil {
				id.logger.Printf("⚠️ Error checking blocks: %v", err)
			} else {
				id.logger.Printf("✅ Block check completed at height: %d", id.lastProcessedBlock)
				// Persist the updated height
				if id.ledgerStore != nil {
					if err := id.ledgerStore.SaveIntentLastBlock(id.lastProcessedBlock); err != nil {
						id.logger.Printf("⚠️ Failed to persist last processed block height: %v", err)
					}
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
	return nil
}

// checkForNewBlocks checks for new blocks and queues them for processing
func (id *IntentDiscovery) checkForNewBlocks(ctx context.Context) error {
	// Use DN (Directory Network) as reference for latest block height
	latestBlock, err := id.client.GetLatestBlock(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	// Process any new blocks since last check, OR re-process recent blocks to show continuous activity
	var blocksToProcess []uint64

	if latestBlock.Height >= id.lastProcessedBlock {
		// Process new blocks (including current if we haven't processed it yet)
		for height := id.lastProcessedBlock + 1; height <= latestBlock.Height; height++ {
			blocksToProcess = append(blocksToProcess, height)
		}
		if len(blocksToProcess) > 0 {
			id.lastProcessedBlock = latestBlock.Height
			id.logger.Printf("🔍 Processing %d NEW blocks (heights %d to %d)",
				len(blocksToProcess), latestBlock.Height-uint64(len(blocksToProcess))+1, latestBlock.Height)
		} else {
			id.logger.Printf("⏳ No new blocks found (current height: %d) - waiting for new transactions", latestBlock.Height)
			return nil
		}
	} else {
		// Network switch detected (DevNet vs Kermit/Mainnet) - auto-reset to current chain
		id.logger.Printf("🔄 Network switch detected: current height %d < last processed %d", latestBlock.Height, id.lastProcessedBlock)
		id.logger.Printf("🔄 Auto-resetting to current chain height (starting from %d)", latestBlock.Height)

		// Reset to current height - will start processing from the next block
		id.lastProcessedBlock = latestBlock.Height

		// Persist the reset height
		if id.ledgerStore != nil {
			if err := id.ledgerStore.SaveIntentLastBlock(latestBlock.Height); err != nil {
				id.logger.Printf("⚠️ Failed to persist reset height: %v", err)
			}
		}

		// Process current block to catch any pending intents
		blocksToProcess = append(blocksToProcess, latestBlock.Height)
	}

	// Queue all blocks for processing
	for _, height := range blocksToProcess {
		select {
		case id.blockProcessCh <- &BlockProcessJob{
			PartitionURL: "acc://dn.acme", // Main partition
			BlockHeight:  height,
			BlockData:    &accumulate.Block{Height: height}, // Minimal block info
		}:
			id.logger.Printf("📦 Queued block %d for comprehensive CERTEN transaction search", height)
		case <-id.stopCh:
			return nil
		default:
			id.logger.Printf("⚠️ Block processing queue full, skipping block %d", height)
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
		}
	}
}

// processBlock processes a single block looking for Certen intents using comprehensive v3 API search
func (id *IntentDiscovery) processBlock(job *BlockProcessJob, workerID string) error {
	id.logger.Printf("🔍 Worker %s processing block %d using comprehensive v3 API search across all partitions...", workerID, job.BlockHeight)
	id.logger.Printf("🔍 Worker %s querying partitions: [acc://bvn1, acc://bvn2, acc://bvn3, acc://dn]", workerID)

	// Create context with timeout to prevent workers from hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	foundIntents := 0

	// Use the new comprehensive v3 API search across all partitions
	id.logger.Printf("🔍 Worker %s calling SearchCertenTransactions for block %d...", workerID, job.BlockHeight)
	certenTransactions, err := id.client.SearchCertenTransactions(ctx, int64(job.BlockHeight))
	if err != nil {
		id.logger.Printf("❌ Worker %s failed to search for CERTEN transactions: %v", workerID, err)
		return err
	}
	id.logger.Printf("✅ Worker %s completed SearchCertenTransactions call successfully", workerID)

	id.logger.Printf("📊 Worker %s searched all partitions and found %d potential CERTEN transactions for block %d",
		workerID, len(certenTransactions), job.BlockHeight)

	// Always log what we're doing, even if no transactions found
	if len(certenTransactions) == 0 {
		id.logger.Printf("🔍 Worker %s completed comprehensive transaction search - no CERTEN intents found in block %d", workerID, job.BlockHeight)
		id.logger.Printf("📊 Worker %s verified: Block %d processed across all BVN and DN partitions", workerID, job.BlockHeight)
	}

	for _, certenTx := range certenTransactions {
		// Filter to transactions in this specific block
		if certenTx.BlockHeight != int64(job.BlockHeight) {  // Fixed: compare int64 to uint64
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
			// E.4 remediation: Phase 2 (failure) - Mark as failed, allowing future retry
			id.markFailed(intent.IntentID)
			id.logger.Printf("   Intent %s marked as 'failed' - can be retried on next discovery", intent.IntentID)
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
	} else {
		id.logger.Printf("📊 Worker %s found no new intents in block %d", workerID, job.BlockHeight)
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

	// Build TransactionData for the batch system
	txData := &batch.TransactionData{
		AccumTxHash:  intent.TransactionHash,
		AccountURL:   intent.AccountURL,
		TxHash:       txHash[:],
		IntentType:   "certen_intent",
		IntentData:   intent.IntentData,
	}

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
func (id *IntentDiscovery) processIntent(intent *CertenIntent, blockHeight uint64) error {
	id.logger.Printf("🚀 Processing Certen intent: %s", intent.IntentID)

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

		// Try REAL L1-L3 chained proof first (requires txHash, partition, and CometBFT binding)
		if id.proofGenerator.HasRealProofBuilder() && intent.TransactionHash != "" && intent.Partition != "" {
			id.logger.Printf("🔗 [REAL-PROOF] Generating L1-L3 chained proof for %s (txHash=%s, partition=%s)",
				intent.IntentID, intent.TransactionHash[:16]+"...", intent.Partition)

			chainedProof, err := id.proofGenerator.GenerateChainedProof(ctx, accountURL, intent.TransactionHash, intent.Partition)
			if err != nil {
				id.logger.Printf("⚠️ [REAL-PROOF] L1-L3 chained proof failed for %s: %v", intent.IntentID, err)
				// Fall through to basic proof
			} else {
				// Convert ChainedProof to CompleteProof for adapter
				complete := proof.ChainedProofToCompleteProof(chainedProof)
				id.logger.Printf("✅ [REAL-PROOF] L1-L3 chained proof generated for %s:", intent.IntentID)
				id.logger.Printf("   L1: TxChainIndex=%d, BVNMinorBlockIndex=%d",
					chainedProof.Layer1.TxChainIndex, chainedProof.Layer1.BVNMinorBlockIndex)
				id.logger.Printf("   L2: DNMinorBlockIndex=%d", chainedProof.Layer2.DNMinorBlockIndex)
				id.logger.Printf("   L3: DNConsensusHeight=%d", chainedProof.Layer3.DNConsensusHeight)

				// Build ProofRequest for adapter
				req := &proof.ProofRequest{
					RequestID:       fmt.Sprintf("intent_%s", intent.IntentID),
					ProofType:       "chained_l1_l2_l3",
					TransactionHash: intent.TransactionHash,
					AccountURL:      accountURL,
				}

				adapter := proof.NewCertenProofAdapter(complete, req, id.validatorID)
				certenProof = adapter.ToCertenProof()
				if certenProof != nil {
					id.logger.Printf("✅ [REAL-PROOF] CertenProof created with L1-L3 chained proof for %s", intent.IntentID)
				}
			}
		}

		// Fallback: Basic proof if real L1-L3 proof not available
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

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

// Helper methods

// isCertenIntent checks if a transaction is a Certen intent (CRITICAL legacy method)
func (id *IntentDiscovery) isCertenIntent(tx *accumulate.Transaction) bool {
	// Check for CERTEN_INTENT memo in transaction header
	if header, ok := tx.Data["header"].(map[string]interface{}); ok {
		if memo, ok := header["memo"].(string); ok && memo == CERTEN_INTENT_MEMO {
			return true
		}
	}

	// Check for CERTEN_INTENT memo in transaction data (fallback)
	if data, ok := tx.Data["memo"]; ok {
		if memo, ok := data.(string); ok && memo == CERTEN_INTENT_MEMO {
			return true
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
		// Only allow processing if not already in_progress or completed
		// Failed intents CAN be retried
		if status == IntentStatusInProgress || status == IntentStatusCompleted {
			return false // Already being processed or completed
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
func (id *IntentDiscovery) markFailed(intentID string) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.intentStatus[intentID] = IntentStatusFailed
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

