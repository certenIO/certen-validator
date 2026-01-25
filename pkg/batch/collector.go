// Copyright 2025 Certen Protocol
//
// Batch Collector - Accumulates transactions into anchor batches
// Per Whitepaper Section 3.4.2: Validators batch transactions every ~15 minutes
//
// The collector:
// - Maintains an open batch for on-cadence transactions
// - Adds transactions with proper Merkle tree indexing
// - Tracks batch state (pending, closed)
// - Integrates with PostgreSQL via database repositories

package batch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/firestore"
	"github.com/certen/independant-validator/pkg/merkle"
)

// TransactionData represents a transaction to be added to a batch
type TransactionData struct {
	AccumTxHash  string          // Accumulate transaction hash
	AccountURL   string          // acc://... URL
	TxHash       []byte          // 32-byte transaction hash for Merkle tree
	ChainedProof json.RawMessage // Optional ChainedProof (L1-L3)
	GovProof     json.RawMessage // Optional GovernanceProof (G0-G2)
	GovLevel     string          // G0, G1, or G2
	IntentType   string          // Optional intent type
	IntentData   json.RawMessage // Optional intent data

	// Phase 2 additions: Extended metadata for governance proof generation
	KeyPage  string                 // Optional KeyPage URL for governance proofs
	Metadata map[string]interface{} // Optional metadata (e.g., signer info)

	// Intent tracking: Links validator proofs back to user intents in Firestore
	// These are populated when the intent can be resolved from Firestore
	UserID   string // Firestore user ID (optional)
	IntentID string // Firestore intent document ID (optional)

	// Multi-Chain Support: Target chain for anchoring
	// Per Unified Multi-Chain Architecture: Transactions specify their target chain
	TargetChain string // Target chain ID (e.g., "ethereum", "sepolia", "solana-devnet")
}

// Collector manages transaction batching for anchoring
type Collector struct {
	mu sync.RWMutex

	// Database access
	repos *database.Repositories

	// Current open batches (one per type)
	onCadenceBatch *activeBatch
	onDemandBatch  *activeBatch

	// Configuration
	validatorID    string
	maxBatchSize   int           // Max transactions per batch
	batchTimeout   time.Duration // Max time a batch can stay open (~15 min)
	maxOnDemand    int           // Max transactions in on-demand batch before immediate anchor

	// Logging
	logger *log.Logger

	// Firestore sync for real-time UI updates
	firestoreSyncService *firestore.SyncService
}

// activeBatch represents a batch being built
type activeBatch struct {
	batchID     uuid.UUID
	batchType   database.BatchType
	startTime   time.Time
	leaves      [][]byte                    // Transaction hashes for Merkle tree
	txData      []*TransactionData          // Original transaction data
	merkleTree  *merkle.Tree                // Built when batch is closed
}

// CollectorConfig holds collector configuration
type CollectorConfig struct {
	ValidatorID    string
	MaxBatchSize   int
	BatchTimeout   time.Duration
	MaxOnDemand    int
	Logger         *log.Logger
}

// DefaultCollectorConfig returns default configuration
func DefaultCollectorConfig() *CollectorConfig {
	return &CollectorConfig{
		ValidatorID:    "validator-default",
		MaxBatchSize:   1000,                  // Max 1000 txs per batch
		BatchTimeout:   15 * time.Minute,      // ~15 min batches per whitepaper
		MaxOnDemand:    5,                     // Small on-demand batches
		Logger:         log.New(log.Writer(), "[BatchCollector] ", log.LstdFlags),
	}
}

// NewCollector creates a new batch collector
func NewCollector(repos *database.Repositories, cfg *CollectorConfig) (*Collector, error) {
	if repos == nil {
		return nil, fmt.Errorf("repositories cannot be nil")
	}
	if cfg == nil {
		cfg = DefaultCollectorConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[BatchCollector] ", log.LstdFlags)
	}

	return &Collector{
		repos:          repos,
		validatorID:    cfg.ValidatorID,
		maxBatchSize:   cfg.MaxBatchSize,
		batchTimeout:   cfg.BatchTimeout,
		maxOnDemand:    cfg.MaxOnDemand,
		logger:         cfg.Logger,
	}, nil
}

// SetFirestoreSyncService sets the Firestore sync service for real-time UI updates
func (c *Collector) SetFirestoreSyncService(svc *firestore.SyncService) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.firestoreSyncService = svc
}

// AddOnCadenceTransaction adds a transaction to the current on-cadence batch
// This is the default path for ~$0.05/proof amortized cost
func (c *Collector) AddOnCadenceTransaction(ctx context.Context, tx *TransactionData) (*BatchTransactionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we have an open on-cadence batch
	if c.onCadenceBatch == nil {
		if err := c.createBatch(ctx, database.BatchTypeOnCadence); err != nil {
			return nil, fmt.Errorf("failed to create on-cadence batch: %w", err)
		}
	}

	// Add transaction to batch
	return c.addToBatch(ctx, c.onCadenceBatch, tx)
}

// AddOnDemandTransaction adds a transaction to an on-demand batch
// This is for immediate anchoring at ~$0.25/proof
func (c *Collector) AddOnDemandTransaction(ctx context.Context, tx *TransactionData) (*BatchTransactionResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure we have an open on-demand batch
	if c.onDemandBatch == nil {
		if err := c.createBatch(ctx, database.BatchTypeOnDemand); err != nil {
			return nil, fmt.Errorf("failed to create on-demand batch: %w", err)
		}
	}

	// Add transaction to batch
	result, err := c.addToBatch(ctx, c.onDemandBatch, tx)
	if err != nil {
		return nil, err
	}

	// Check if on-demand batch should be immediately closed
	if len(c.onDemandBatch.leaves) >= c.maxOnDemand {
		result.BatchReady = true
	}

	return result, nil
}

// createBatch creates a new batch in the database
func (c *Collector) createBatch(ctx context.Context, batchType database.BatchType) error {
	input := &database.NewAnchorBatch{
		BatchType:   batchType,
		ValidatorID: c.validatorID,
	}

	batch, err := c.repos.Batches.CreateBatch(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create batch in database: %w", err)
	}

	active := &activeBatch{
		batchID:   batch.BatchID,
		batchType: batchType,
		startTime: time.Now(),
		leaves:    make([][]byte, 0),
		txData:    make([]*TransactionData, 0),
	}

	if batchType == database.BatchTypeOnCadence {
		c.onCadenceBatch = active
	} else {
		c.onDemandBatch = active
	}

	c.logger.Printf("Created new %s batch: %s", batchType, batch.BatchID)
	return nil
}

// addToBatch adds a transaction to the specified batch
func (c *Collector) addToBatch(ctx context.Context, batch *activeBatch, tx *TransactionData) (*BatchTransactionResult, error) {
	// Validate transaction hash
	if len(tx.TxHash) != 32 {
		return nil, fmt.Errorf("transaction hash must be 32 bytes, got %d", len(tx.TxHash))
	}

	// Get tree index (position in Merkle tree)
	treeIndex := len(batch.leaves)

	// Add to in-memory batch
	leafCopy := make([]byte, 32)
	copy(leafCopy, tx.TxHash)
	batch.leaves = append(batch.leaves, leafCopy)
	batch.txData = append(batch.txData, tx)

	// Build merkle path placeholder (will be filled when batch is closed)
	// For now, store empty path - it will be computed when batch closes
	emptyPath := []database.MerklePathNode{}

	// Store in database
	dbTx := &database.NewBatchTransaction{
		BatchID:      batch.batchID,
		AccumTxHash:  tx.AccumTxHash,
		AccountURL:   tx.AccountURL,
		TreeIndex:    treeIndex,
		MerklePath:   emptyPath,
		TxHash:       tx.TxHash,
		ChainedProof: tx.ChainedProof,
		GovProof:     tx.GovProof,
		GovLevel:     database.GovernanceLevel(tx.GovLevel),
		IntentType:   tx.IntentType,
		IntentData:   tx.IntentData,
	}

	// Pass intent tracking fields if present (for Firestore linking)
	if tx.UserID != "" {
		dbTx.UserID = &tx.UserID
	}
	if tx.IntentID != "" {
		dbTx.IntentID = &tx.IntentID
	}

	storedTx, err := c.repos.Batches.AddTransaction(ctx, dbTx)
	if err != nil {
		// Rollback in-memory state
		batch.leaves = batch.leaves[:len(batch.leaves)-1]
		batch.txData = batch.txData[:len(batch.txData)-1]
		return nil, fmt.Errorf("failed to store transaction: %w", err)
	}

	// Serialize empty path for result
	merklePathJSON, _ := json.Marshal(emptyPath)

	result := &BatchTransactionResult{
		TransactionID: storedTx.ID,
		BatchID:       batch.batchID,
		TreeIndex:     treeIndex,
		MerklePath:    merklePathJSON,
		BatchType:     batch.batchType,
		BatchSize:     len(batch.leaves),
		BatchReady:    false,
	}

	c.logger.Printf("Added tx %s to %s batch %s (index=%d, size=%d)",
		tx.AccumTxHash[:16]+"...", batch.batchType, batch.batchID, treeIndex, len(batch.leaves))

	// Trigger Firestore sync for intent discovery (Stage 3)
	// This fires when we discover an intent from Accumulate
	if c.firestoreSyncService != nil && c.firestoreSyncService.IsEnabled() {
		go c.triggerIntentDiscoveredFirestoreEvent(tx, batch.batchType)
	}

	return result, nil
}

// BatchTransactionResult is returned when a transaction is added
type BatchTransactionResult struct {
	TransactionID int64              `json:"transaction_id"`
	BatchID       uuid.UUID          `json:"batch_id"`
	TreeIndex     int                `json:"tree_index"`
	MerklePath    json.RawMessage    `json:"merkle_path"` // Empty until batch closes
	BatchType     database.BatchType `json:"batch_type"`
	BatchSize     int                `json:"batch_size"`
	BatchReady    bool               `json:"batch_ready"` // True if batch should be closed/anchored
}

// ClosedBatchResult is returned when a batch is closed
// Extended with proof data aggregation per Phase 2 (HIGH-002, HIGH-003)
type ClosedBatchResult struct {
	BatchID          uuid.UUID                `json:"batch_id"`
	BatchType        database.BatchType       `json:"batch_type"`
	MerkleRoot       []byte                   `json:"merkle_root"`
	MerkleRootHex    string                   `json:"merkle_root_hex"`
	TxCount          int                      `json:"tx_count"`
	StartTime        time.Time                `json:"start_time"`
	EndTime          time.Time                `json:"end_time"`
	Duration         time.Duration            `json:"duration"`
	AccumulateHeight int64                    `json:"accumulate_height"`
	AccumulateHash   string                   `json:"accumulate_hash"`
	Proofs           []*merkle.InclusionProof `json:"proofs"`

	// ========== Phase 2 Additions: Proof Data Aggregation ==========

	// Transactions contains the original transaction data with proofs
	// This provides access to ChainedProof (L1-L3) and GovProof (G0-G2)
	Transactions []*TransactionData `json:"transactions,omitempty"`

	// AggregatedBPTRoot is the BPT root extracted from ChainedProofs
	// Per HIGH-002: This provides real cryptographic binding to Accumulate state
	AggregatedBPTRoot []byte `json:"aggregated_bpt_root,omitempty"`

	// AggregatedNetworkRoot is the Directory Network root from L3 proofs
	AggregatedNetworkRoot []byte `json:"aggregated_network_root,omitempty"`

	// GovernanceProofHashes contains SHA256 hashes of each governance proof
	// Used to compute the GovernanceRoot Merkle tree per HIGH-003
	GovernanceProofHashes [][]byte `json:"governance_proof_hashes,omitempty"`

	// AggregatedGovernanceRoot is the Merkle root of governance proof hashes
	// Per Phase 2 Task 2.2: This is computed from real governance proofs
	AggregatedGovernanceRoot [32]byte `json:"aggregated_governance_root,omitempty"`
}

// CloseOnCadenceBatch closes the current on-cadence batch
// Returns nil if no batch is open
func (c *Collector) CloseOnCadenceBatch(ctx context.Context, accumHeight int64, accumHash string) (*ClosedBatchResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.onCadenceBatch == nil {
		return nil, nil
	}

	result, err := c.closeBatch(ctx, c.onCadenceBatch, accumHeight, accumHash)
	if err != nil {
		return nil, err
	}

	c.onCadenceBatch = nil
	return result, nil
}

// CloseOnDemandBatch closes the current on-demand batch
func (c *Collector) CloseOnDemandBatch(ctx context.Context, accumHeight int64, accumHash string) (*ClosedBatchResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.onDemandBatch == nil {
		return nil, nil
	}

	result, err := c.closeBatch(ctx, c.onDemandBatch, accumHeight, accumHash)
	if err != nil {
		return nil, err
	}

	c.onDemandBatch = nil
	return result, nil
}

// closeBatch closes a batch, builds the Merkle tree, and updates the database
// Per Phase 2: Also extracts and aggregates proof data for real cryptographic binding
func (c *Collector) closeBatch(ctx context.Context, batch *activeBatch, accumHeight int64, accumHash string) (*ClosedBatchResult, error) {
	if len(batch.leaves) == 0 {
		// Empty batch - just mark as closed
		err := c.repos.Batches.CloseBatch(ctx, batch.batchID, make([]byte, 32), accumHeight, accumHash)
		if err != nil {
			return nil, fmt.Errorf("failed to close empty batch: %w", err)
		}
		return &ClosedBatchResult{
			BatchID:          batch.batchID,
			BatchType:        batch.batchType,
			TxCount:          0,
			StartTime:        batch.startTime,
			EndTime:          time.Now(),
			Duration:         time.Since(batch.startTime),
			AccumulateHeight: accumHeight,
			AccumulateHash:   accumHash,
		}, nil
	}

	// Build Merkle tree
	tree, err := merkle.BuildTree(batch.leaves)
	if err != nil {
		return nil, fmt.Errorf("failed to build merkle tree: %w", err)
	}
	batch.merkleTree = tree

	merkleRoot := tree.Root()
	endTime := time.Now()

	c.logger.Printf("Built Merkle tree for batch %s: root=%s, leaves=%d",
		batch.batchID, tree.RootHex()[:16]+"...", tree.LeafCount())

	// Generate and store proofs for each transaction
	proofs := make([]*merkle.InclusionProof, len(batch.leaves))
	for i := range batch.leaves {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			return nil, fmt.Errorf("failed to generate proof for leaf %d: %w", i, err)
		}
		proofs[i] = proof

		// Update the transaction in database with the merkle path
		pathJSON, err := proof.PathToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize proof path: %w", err)
		}

		// Update the merkle path in the database by tree index
		if err := c.repos.Batches.UpdateMerklePathByTreeIndex(ctx, batch.batchID, i, pathJSON); err != nil {
			c.logger.Printf("Warning: failed to update merkle path for tree index %d: %v", i, err)
			// Continue - the proof is still valid, just not persisted to DB
		}
	}

	// ========== Phase 2: Extract and Aggregate Proof Data ==========
	// Per HIGH-002 (CrossChainCommitment) and HIGH-003 (GovernanceRoot)
	aggregatedBPTRoot, aggregatedNetworkRoot, govProofHashes := c.extractProofData(batch.txData)

	if len(aggregatedBPTRoot) > 0 {
		c.logger.Printf("Extracted BPT root from batch: %s", hex.EncodeToString(aggregatedBPTRoot)[:16]+"...")
	}
	if len(govProofHashes) > 0 {
		c.logger.Printf("Extracted %d governance proof hashes for batch", len(govProofHashes))
	}

	// Close batch in database
	err = c.repos.Batches.CloseBatch(ctx, batch.batchID, merkleRoot, accumHeight, accumHash)
	if err != nil {
		return nil, fmt.Errorf("failed to close batch in database: %w", err)
	}

	c.logger.Printf("Closed %s batch %s: root=%s, txs=%d, duration=%s",
		batch.batchType, batch.batchID, tree.RootHex()[:16]+"...",
		len(batch.leaves), time.Since(batch.startTime))

	// Trigger Firestore sync for batch closed event (Stage 5)
	if c.firestoreSyncService != nil && c.firestoreSyncService.IsEnabled() {
		go c.triggerBatchClosedFirestoreEvent(batch, tree.RootHex())
	}

	return &ClosedBatchResult{
		BatchID:          batch.batchID,
		BatchType:        batch.batchType,
		MerkleRoot:       merkleRoot,
		MerkleRootHex:    tree.RootHex(),
		TxCount:          len(batch.leaves),
		StartTime:        batch.startTime,
		EndTime:          endTime,
		Duration:         endTime.Sub(batch.startTime),
		AccumulateHeight: accumHeight,
		AccumulateHash:   accumHash,
		Proofs:           proofs,
		// Phase 2 additions
		Transactions:          batch.txData,
		AggregatedBPTRoot:     aggregatedBPTRoot,
		AggregatedNetworkRoot: aggregatedNetworkRoot,
		GovernanceProofHashes: govProofHashes,
	}, nil
}

// extractProofData extracts BPT root, network root, and governance proof hashes from transactions
// Per Phase 2 HIGH-002 and HIGH-003: Real cryptographic binding instead of placeholders
func (c *Collector) extractProofData(txData []*TransactionData) (bptRoot, networkRoot []byte, govProofHashes [][]byte) {
	govProofHashes = make([][]byte, 0, len(txData))

	for _, tx := range txData {
		// Extract BPT root and network root from ChainedProof (L1-L3)
		// Use the first valid proof as the batch's BPT root (all should be consistent)
		if len(tx.ChainedProof) > 0 && len(bptRoot) == 0 {
			extractedBPT, extractedNetwork := c.extractBPTFromChainedProof(tx.ChainedProof)
			if len(extractedBPT) > 0 {
				bptRoot = extractedBPT
			}
			if len(extractedNetwork) > 0 {
				networkRoot = extractedNetwork
			}
		}

		// Hash each governance proof for Merkle tree building
		// Per HIGH-003: GovernanceRoot = Merkle root of all governance proof hashes
		if len(tx.GovProof) > 0 {
			hash := sha256.Sum256(tx.GovProof)
			govProofHashes = append(govProofHashes, hash[:])
		}
	}

	return bptRoot, networkRoot, govProofHashes
}

// ChainedProofData is a minimal struct for extracting BPT data from ChainedProof JSON
// This matches the structure in anchor_proof/types.go StateProofReference
type ChainedProofData struct {
	Layer2Anchor    string `json:"layer2_anchor"`
	Layer3Anchor    string `json:"layer3_anchor"`
	NetworkRootHash string `json:"network_root_hash"`
	// Alternative field names from different proof formats
	BPTRoot    string `json:"bpt_root"`
	L2Anchor   string `json:"l2_anchor"`
	L3Anchor   string `json:"l3_anchor"`
	DNRootHash string `json:"dn_root_hash"`
}

// extractBPTFromChainedProof extracts BPT root and network root from ChainedProof JSON
func (c *Collector) extractBPTFromChainedProof(proofJSON json.RawMessage) (bptRoot, networkRoot []byte) {
	var proof ChainedProofData
	if err := json.Unmarshal(proofJSON, &proof); err != nil {
		c.logger.Printf("Warning: failed to parse ChainedProof JSON: %v", err)
		return nil, nil
	}

	// Try different field names for BPT root (L2 anchor)
	bptHex := proof.Layer2Anchor
	if bptHex == "" {
		bptHex = proof.L2Anchor
	}
	if bptHex == "" {
		bptHex = proof.BPTRoot
	}

	if bptHex != "" {
		if decoded, err := hex.DecodeString(bptHex); err == nil && len(decoded) == 32 {
			bptRoot = decoded
		}
	}

	// Try different field names for network root (L3/DN anchor)
	networkHex := proof.NetworkRootHash
	if networkHex == "" {
		networkHex = proof.DNRootHash
	}
	if networkHex == "" {
		networkHex = proof.Layer3Anchor
	}
	if networkHex == "" {
		networkHex = proof.L3Anchor
	}

	if networkHex != "" {
		if decoded, err := hex.DecodeString(networkHex); err == nil && len(decoded) == 32 {
			networkRoot = decoded
		}
	}

	return bptRoot, networkRoot
}

// GetOnCadenceBatchInfo returns info about the current on-cadence batch
func (c *Collector) GetOnCadenceBatchInfo() *BatchInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.onCadenceBatch == nil {
		return nil
	}

	return &BatchInfo{
		BatchID:   c.onCadenceBatch.batchID,
		BatchType: c.onCadenceBatch.batchType,
		StartTime: c.onCadenceBatch.startTime,
		TxCount:   len(c.onCadenceBatch.leaves),
		Age:       time.Since(c.onCadenceBatch.startTime),
	}
}

// GetOnDemandBatchInfo returns info about the current on-demand batch
func (c *Collector) GetOnDemandBatchInfo() *BatchInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.onDemandBatch == nil {
		return nil
	}

	return &BatchInfo{
		BatchID:   c.onDemandBatch.batchID,
		BatchType: c.onDemandBatch.batchType,
		StartTime: c.onDemandBatch.startTime,
		TxCount:   len(c.onDemandBatch.leaves),
		Age:       time.Since(c.onDemandBatch.startTime),
	}
}

// BatchInfo provides information about an active batch
type BatchInfo struct {
	BatchID   uuid.UUID          `json:"batch_id"`
	BatchType database.BatchType `json:"batch_type"`
	StartTime time.Time          `json:"start_time"`
	TxCount   int                `json:"tx_count"`
	Age       time.Duration      `json:"age"`
}

// ShouldCloseOnCadenceBatch returns true if the on-cadence batch should be closed
// Based on age (>= batchTimeout) or size (>= maxBatchSize)
func (c *Collector) ShouldCloseOnCadenceBatch() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.onCadenceBatch == nil {
		return false
	}

	// Check timeout
	if time.Since(c.onCadenceBatch.startTime) >= c.batchTimeout {
		return true
	}

	// Check size
	if len(c.onCadenceBatch.leaves) >= c.maxBatchSize {
		return true
	}

	return false
}

// HasPendingOnCadenceBatch returns true if there's an open on-cadence batch
func (c *Collector) HasPendingOnCadenceBatch() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.onCadenceBatch != nil && len(c.onCadenceBatch.leaves) > 0
}

// HasPendingOnDemandBatch returns true if there's an open on-demand batch
func (c *Collector) HasPendingOnDemandBatch() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.onDemandBatch != nil && len(c.onDemandBatch.leaves) > 0
}

// triggerBatchClosedFirestoreEvent sends batch closed events to Firestore for each transaction
// This enables real-time UI updates for Stage 5 (Batch Consensus)
func (c *Collector) triggerBatchClosedFirestoreEvent(batch *activeBatch, merkleRootHex string) {
	if c.firestoreSyncService == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build batch transactions list for the event
	batchTxs := make([]firestore.BatchTransaction, 0, len(batch.txData))
	for i, tx := range batch.txData {
		batchTxs = append(batchTxs, firestore.BatchTransaction{
			AccumTxHash: tx.AccumTxHash,
			Position:    i,
			LeafHash:    hex.EncodeToString(tx.TxHash),
		})
	}

	// Determine proof class from batch type
	proofClass := "on_cadence"
	if batch.batchType == database.BatchTypeOnDemand {
		proofClass = "on_demand"
	}

	event := &firestore.BatchClosedEvent{
		BatchID:      batch.batchID.String(),
		MerkleRoot:   merkleRootHex,
		BatchSize:    len(batch.txData),
		ProofClass:   proofClass,
		Transactions: batchTxs,
	}

	if err := c.firestoreSyncService.OnBatchClosed(ctx, event); err != nil {
		c.logger.Printf("Warning: failed to send batch closed event to Firestore: %v", err)
	}
}

// triggerIntentDiscoveredFirestoreEvent sends intent discovered event to Firestore
// This enables real-time UI updates for Stage 3 (Intent Discovery)
func (c *Collector) triggerIntentDiscoveredFirestoreEvent(tx *TransactionData, batchType database.BatchType) {
	if c.firestoreSyncService == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Determine proof class from batch type
	proofClass := "on_cadence"
	if batchType == database.BatchTypeOnDemand {
		proofClass = "on_demand"
	}

	event := &firestore.IntentDiscoveredEvent{
		AccumTxHash:   tx.AccumTxHash,
		AccountURL:    tx.AccountURL,
		BlockHeight:   0, // Not tracked at this point
		DiscoveryTime: time.Now(),
		ProofClass:    proofClass,
		IntentType:    tx.IntentType,
		TargetChain:   "", // Will be determined during anchoring
	}

	if err := c.firestoreSyncService.OnIntentDiscovered(ctx, event); err != nil {
		c.logger.Printf("Warning: failed to send intent discovered event to Firestore: %v", err)
	}
}
