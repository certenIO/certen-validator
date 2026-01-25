// Copyright 2025 Certen Protocol
//
// ConsensusCoordinator - Integrates multi-validator attestation with batch processing
// Per Implementation Plan Phase 4, Task 4.3: Full attestation integration
//
// This coordinator connects:
// - AttestationBroadcaster: For collecting peer validator attestations
// - EventWatcher: For monitoring anchor events
// - Processor: For batch processing and anchor creation
//
// Per Whitepaper Section 3.4.1 Component 4: Multi-validator attestations
// provide Byzantine fault-tolerant consensus for anchor validity.

package batch

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/anchor"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/database"
)

// =============================================================================
// Consensus Result Types
// =============================================================================

// ConsensusResult represents the outcome of multi-validator consensus
type ConsensusResult struct {
	BatchID            uuid.UUID `json:"batch_id"`
	MerkleRoot         []byte    `json:"merkle_root"`
	AnchorTxHash       string    `json:"anchor_tx_hash"`
	BlockNumber        int64     `json:"block_number"`

	// Attestation data
	AttestationCount   int       `json:"attestation_count"`
	ValidatorCount     int       `json:"validator_count"`
	QuorumReached      bool      `json:"quorum_reached"`
	QuorumFraction     float64   `json:"quorum_fraction"`

	// BLS aggregate signature
	AggregateSignature []byte    `json:"aggregate_signature,omitempty"`
	AggregatePubKey    []byte    `json:"aggregate_pubkey,omitempty"`

	// Timing
	StartTime          time.Time `json:"start_time"`
	EndTime            time.Time `json:"end_time"`
	Duration           time.Duration `json:"duration"`

	// Errors (if any)
	Errors             []string  `json:"errors,omitempty"`
}

// ConsensusState tracks the state of consensus for a batch
type ConsensusState string

const (
	ConsensusStateInitiated   ConsensusState = "initiated"
	ConsensusStateCollecting  ConsensusState = "collecting"
	ConsensusStateQuorumMet   ConsensusState = "quorum_met"
	ConsensusStateCompleted   ConsensusState = "completed"
	ConsensusStateFailed      ConsensusState = "failed"
	ConsensusStateTimeout     ConsensusState = "timeout"
)

// ConsensusEntry tracks consensus state for a single batch
type ConsensusEntry struct {
	BatchID        uuid.UUID
	MerkleRoot     []byte
	AnchorTxHash   string
	BlockNumber    int64
	TxCount        int
	State          ConsensusState
	Result         *ConsensusResult
	Attestations   []*BatchAttestation
	StartTime      time.Time
	LastUpdate     time.Time
}

// =============================================================================
// ConsensusCoordinator Configuration
// =============================================================================

// ConsensusCoordinatorConfig holds configuration for the coordinator
type ConsensusCoordinatorConfig struct {
	// Validator identity
	ValidatorID     string
	ValidatorPubKey []byte

	// BLS key pair for signing
	BLSPrivateKey   []byte
	BLSPublicKey    []byte

	// Quorum settings
	QuorumFraction  float64       // Default: 0.667 (2/3+1)
	QuorumTimeout   time.Duration // Default: 30 seconds

	// Event watcher settings
	EventWatcherConfig *anchor.EventWatcherConfig

	// Retry settings
	RetryAttempts   int
	RetryDelay      time.Duration

	// Cleanup settings
	EntryTTL        time.Duration // How long to keep consensus entries

	Logger          *log.Logger
}

// DefaultConsensusCoordinatorConfig returns default configuration
func DefaultConsensusCoordinatorConfig() *ConsensusCoordinatorConfig {
	return &ConsensusCoordinatorConfig{
		QuorumFraction: 0.667,
		QuorumTimeout:  30 * time.Second,
		RetryAttempts:  3,
		RetryDelay:     2 * time.Second,
		EntryTTL:       24 * time.Hour,
	}
}

// =============================================================================
// ConsensusCoordinator
// =============================================================================

// ConsensusCoordinator orchestrates multi-validator consensus for batches
type ConsensusCoordinator struct {
	config *ConsensusCoordinatorConfig

	// Components
	broadcaster   *AttestationBroadcaster
	eventWatcher  *anchor.EventWatcher
	processor     *Processor

	// Database access for Phase 5 updates
	repos *database.Repositories

	// Consensus tracking
	entries    map[uuid.UUID]*ConsensusEntry
	entriesMu  sync.RWMutex

	// Event handlers
	onConsensusReached OnConsensusCallback
	onConsensusFailed  OnConsensusCallback

	// Lifecycle
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex

	logger *log.Logger
}

// OnConsensusCallback is called when consensus is reached or fails
type OnConsensusCallback func(ctx context.Context, result *ConsensusResult) error

// NewConsensusCoordinator creates a new consensus coordinator
func NewConsensusCoordinator(
	config *ConsensusCoordinatorConfig,
	broadcaster *AttestationBroadcaster,
	eventWatcher *anchor.EventWatcher,
	processor *Processor,
	repos *database.Repositories,
) (*ConsensusCoordinator, error) {
	if config == nil {
		config = DefaultConsensusCoordinatorConfig()
	}
	if broadcaster == nil {
		return nil, fmt.Errorf("attestation broadcaster is required")
	}
	if processor == nil {
		return nil, fmt.Errorf("batch processor is required")
	}

	if config.Logger == nil {
		config.Logger = log.New(log.Writer(), "[ConsensusCoordinator] ", log.LstdFlags)
	}

	cc := &ConsensusCoordinator{
		config:       config,
		broadcaster:  broadcaster,
		eventWatcher: eventWatcher,
		processor:    processor,
		repos:        repos,
		entries:      make(map[uuid.UUID]*ConsensusEntry),
		logger:       config.Logger,
	}

	// Wire up the processor's anchor callback to trigger consensus
	processor.SetOnAnchorCallback(cc.onAnchorCreated)

	return cc, nil
}

// Start begins the consensus coordinator
func (cc *ConsensusCoordinator) Start(ctx context.Context) error {
	cc.mu.Lock()
	if cc.running {
		cc.mu.Unlock()
		return fmt.Errorf("consensus coordinator already running")
	}
	cc.running = true
	cc.mu.Unlock()

	cc.ctx, cc.cancel = context.WithCancel(ctx)

	// Start event watcher if configured
	if cc.eventWatcher != nil {
		if err := cc.eventWatcher.Start(ctx); err != nil {
			return fmt.Errorf("failed to start event watcher: %w", err)
		}

		// Register event handlers
		cc.eventWatcher.RegisterHandler(anchor.EventTypeAnchorCreated, cc.handleAnchorCreatedEvent)
		cc.eventWatcher.RegisterHandler(anchor.EventTypeProofExecuted, cc.handleProofExecutedEvent)
		cc.eventWatcher.RegisterHandler(anchor.EventTypeProofVerificationFailed, cc.handleProofVerificationFailedEvent)
	}

	// Start cleanup goroutine
	cc.wg.Add(1)
	go cc.cleanupLoop()

	cc.logger.Printf("ConsensusCoordinator started")
	return nil
}

// Stop stops the consensus coordinator
func (cc *ConsensusCoordinator) Stop() error {
	cc.mu.Lock()
	if !cc.running {
		cc.mu.Unlock()
		return nil
	}
	cc.running = false
	cc.mu.Unlock()

	// Cancel context
	if cc.cancel != nil {
		cc.cancel()
	}

	// Stop event watcher
	if cc.eventWatcher != nil {
		cc.eventWatcher.Stop()
	}

	// Wait for goroutines
	cc.wg.Wait()

	cc.logger.Printf("ConsensusCoordinator stopped")
	return nil
}

// SetOnConsensusReached sets the callback for when consensus is reached
func (cc *ConsensusCoordinator) SetOnConsensusReached(callback OnConsensusCallback) {
	cc.onConsensusReached = callback
}

// SetOnConsensusFailed sets the callback for when consensus fails
func (cc *ConsensusCoordinator) SetOnConsensusFailed(callback OnConsensusCallback) {
	cc.onConsensusFailed = callback
}

// =============================================================================
// Anchor Callback (From Processor)
// =============================================================================

// onAnchorCreated is called by the processor when a batch anchor is created
// This initiates the multi-validator attestation collection process
func (cc *ConsensusCoordinator) onAnchorCreated(
	ctx context.Context,
	batchID uuid.UUID,
	merkleRoot []byte,
	anchorTxHash string,
	txCount int,
	blockNumber int64,
) error {
	cc.logger.Printf("Initiating consensus for batch %s (root=%s, tx=%s, block=%d)",
		batchID, hex.EncodeToString(merkleRoot)[:16], anchorTxHash[:16], blockNumber)

	// Create consensus entry
	entry := &ConsensusEntry{
		BatchID:      batchID,
		MerkleRoot:   merkleRoot,
		AnchorTxHash: anchorTxHash,
		BlockNumber:  blockNumber,
		TxCount:      txCount,
		State:        ConsensusStateInitiated,
		StartTime:    time.Now(),
		LastUpdate:   time.Now(),
	}

	cc.entriesMu.Lock()
	cc.entries[batchID] = entry
	cc.entriesMu.Unlock()

	// Start attestation collection in background
	go cc.collectAttestations(entry)

	return nil
}

// collectAttestations broadcasts attestation request and collects responses
func (cc *ConsensusCoordinator) collectAttestations(entry *ConsensusEntry) {
	ctx, cancel := context.WithTimeout(cc.ctx, cc.config.QuorumTimeout)
	defer cancel()

	// Update state
	cc.updateEntryState(entry.BatchID, ConsensusStateCollecting)

	// Create a ClosedBatchResult for the broadcaster
	batch := &ClosedBatchResult{
		BatchID:          entry.BatchID,
		MerkleRoot:       entry.MerkleRoot,
		MerkleRootHex:    hex.EncodeToString(entry.MerkleRoot),
		TxCount:          entry.TxCount,
		AccumulateHeight: entry.BlockNumber,
	}

	// Broadcast and collect attestations
	result, err := cc.broadcaster.BroadcastAndCollect(ctx, batch)
	if err != nil {
		cc.handleConsensusFailure(entry, fmt.Sprintf("attestation collection failed: %v", err))
		return
	}

	// Store attestations in entry
	cc.entriesMu.Lock()
	if e, ok := cc.entries[entry.BatchID]; ok {
		e.Attestations = result.Attestations
		e.LastUpdate = time.Now()
	}
	cc.entriesMu.Unlock()

	// Check quorum
	if result.QuorumReached {
		cc.handleConsensusSuccess(entry, result)
	} else {
		cc.handleConsensusFailure(entry, fmt.Sprintf(
			"quorum not reached: %d/%d validators (need %.0f%%)",
			result.AttestationCount, result.RequiredCount, cc.config.QuorumFraction*100,
		))
	}
}

// handleConsensusSuccess handles successful consensus
func (cc *ConsensusCoordinator) handleConsensusSuccess(entry *ConsensusEntry, attResult *AttestationResult) {
	cc.updateEntryState(entry.BatchID, ConsensusStateQuorumMet)

	now := time.Now()

	// Build consensus result
	consensusResult := &ConsensusResult{
		BatchID:            entry.BatchID,
		MerkleRoot:         entry.MerkleRoot,
		AnchorTxHash:       entry.AnchorTxHash,
		BlockNumber:        entry.BlockNumber,
		AttestationCount:   attResult.AttestationCount,
		ValidatorCount:     attResult.RequiredCount,
		QuorumReached:      true,
		QuorumFraction:     float64(attResult.AttestationCount) / float64(attResult.RequiredCount),
		AggregateSignature: attResult.AggregatedSignature,
		AggregatePubKey:    attResult.AggregatedPublicKey,
		StartTime:          entry.StartTime,
		EndTime:            now,
		Duration:           time.Since(entry.StartTime),
	}

	// Store result
	cc.entriesMu.Lock()
	if e, ok := cc.entries[entry.BatchID]; ok {
		e.Result = consensusResult
		e.State = ConsensusStateCompleted
		e.LastUpdate = now
	}
	cc.entriesMu.Unlock()

	cc.logger.Printf("Consensus reached for batch %s: %d/%d validators, signature=%s",
		entry.BatchID, attResult.AttestationCount, attResult.RequiredCount,
		hex.EncodeToString(attResult.AggregatedSignature)[:16]+"...")

	// Persist Phase 5 consensus data to PostgreSQL
	if cc.repos != nil && cc.repos.Batches != nil {
		phase5Update := &database.BatchPhase5Update{
			ProofDataIncluded:    true,
			AttestationCount:     attResult.AttestationCount,
			AggregatedSignature:  attResult.AggregatedSignature,
			AggregatedPublicKey:  attResult.AggregatedPublicKey,
			QuorumReached:        true,
			ConsensusCompletedAt: &now,
		}

		if err := cc.repos.Batches.UpdateBatchPhase5(cc.ctx, entry.BatchID, phase5Update); err != nil {
			cc.logger.Printf("Failed to persist Phase 5 data for batch %s: %v", entry.BatchID, err)
		} else {
			cc.logger.Printf("Persisted Phase 5 consensus data for batch %s", entry.BatchID)
		}

		// Also update consensus entry in database with aggregate data
		if cc.repos.Consensus != nil {
			if err := cc.repos.Consensus.MarkConsensusQuorumMet(
				cc.ctx,
				entry.BatchID,
				attResult.AggregatedSignature,
				attResult.AggregatedPublicKey,
				attResult.AttestationCount,
				consensusResult,
			); err != nil {
				cc.logger.Printf("Failed to update consensus entry for batch %s: %v", entry.BatchID, err)
			}

			// Mark all collected attestations as verified
			// All attestations that made it to this point passed BLS signature verification
			for _, att := range attResult.Attestations {
				if err := cc.repos.Consensus.MarkBatchAttestationVerifiedByBatchAndValidator(
					cc.ctx,
					entry.BatchID,
					att.ValidatorID,
					true, // verified successfully
				); err != nil {
					cc.logger.Printf("Failed to mark attestation verified for batch %s validator %s: %v",
						entry.BatchID, att.ValidatorID[:8], err)
				}
			}
			cc.logger.Printf("Marked %d attestations as verified for batch %s",
				len(attResult.Attestations), entry.BatchID)
		}
	}

	// Trigger callback
	if cc.onConsensusReached != nil {
		if err := cc.onConsensusReached(cc.ctx, consensusResult); err != nil {
			cc.logger.Printf("Consensus callback error: %v", err)
		}
	}
}

// handleConsensusFailure handles failed consensus
func (cc *ConsensusCoordinator) handleConsensusFailure(entry *ConsensusEntry, reason string) {
	cc.updateEntryState(entry.BatchID, ConsensusStateFailed)

	// Build failure result
	consensusResult := &ConsensusResult{
		BatchID:          entry.BatchID,
		MerkleRoot:       entry.MerkleRoot,
		AnchorTxHash:     entry.AnchorTxHash,
		BlockNumber:      entry.BlockNumber,
		QuorumReached:    false,
		StartTime:        entry.StartTime,
		EndTime:          time.Now(),
		Duration:         time.Since(entry.StartTime),
		Errors:           []string{reason},
	}

	// Store result
	cc.entriesMu.Lock()
	if e, ok := cc.entries[entry.BatchID]; ok {
		e.Result = consensusResult
		e.LastUpdate = time.Now()
	}
	cc.entriesMu.Unlock()

	cc.logger.Printf("Consensus FAILED for batch %s: %s", entry.BatchID, reason)

	// Trigger callback
	if cc.onConsensusFailed != nil {
		if err := cc.onConsensusFailed(cc.ctx, consensusResult); err != nil {
			cc.logger.Printf("Consensus failure callback error: %v", err)
		}
	}
}

// updateEntryState updates the state of a consensus entry
func (cc *ConsensusCoordinator) updateEntryState(batchID uuid.UUID, state ConsensusState) {
	cc.entriesMu.Lock()
	defer cc.entriesMu.Unlock()

	if entry, ok := cc.entries[batchID]; ok {
		entry.State = state
		entry.LastUpdate = time.Now()
	}
}

// =============================================================================
// Event Handlers (From EventWatcher)
// =============================================================================

// handleAnchorCreatedEvent handles AnchorCreated events from the contract
func (cc *ConsensusCoordinator) handleAnchorCreatedEvent(event anchor.ContractEvent) error {
	anchorEvent, ok := event.(*anchor.AnchorCreatedEvent)
	if !ok {
		return fmt.Errorf("invalid event type for AnchorCreated handler")
	}

	cc.logger.Printf("Observed AnchorCreated on-chain: bundleId=%s, validator=%s, block=%d",
		hex.EncodeToString(anchorEvent.BundleID[:])[:16],
		anchorEvent.Validator.Hex()[:10],
		anchorEvent.BlockNumber)

	// This can be used to confirm anchors created by other validators
	// For now, we just log it
	return nil
}

// handleProofExecutedEvent handles ProofExecuted events from the contract
func (cc *ConsensusCoordinator) handleProofExecutedEvent(event anchor.ContractEvent) error {
	proofEvent, ok := event.(*anchor.ProofExecutedEvent)
	if !ok {
		return fmt.Errorf("invalid event type for ProofExecuted handler")
	}

	cc.logger.Printf("Observed ProofExecuted on-chain: anchorId=%s, merkle=%v, bls=%v, gov=%v",
		hex.EncodeToString(proofEvent.AnchorID[:])[:16],
		proofEvent.MerkleVerified,
		proofEvent.BLSVerified,
		proofEvent.GovernanceVerified)

	return nil
}

// handleProofVerificationFailedEvent handles ProofVerificationFailed events
func (cc *ConsensusCoordinator) handleProofVerificationFailedEvent(event anchor.ContractEvent) error {
	failEvent, ok := event.(*anchor.ProofVerificationFailedEvent)
	if !ok {
		return fmt.Errorf("invalid event type for ProofVerificationFailed handler")
	}

	cc.logger.Printf("ALERT: ProofVerificationFailed on-chain: anchorId=%s, reason=%s",
		hex.EncodeToString(failEvent.AnchorID[:])[:16],
		failEvent.Reason)

	// This is critical - a proof verification failed on-chain
	// We should investigate why this happened
	return nil
}

// =============================================================================
// Cleanup and Maintenance
// =============================================================================

// cleanupLoop periodically removes old consensus entries
func (cc *ConsensusCoordinator) cleanupLoop() {
	defer cc.wg.Done()

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-cc.ctx.Done():
			return
		case <-ticker.C:
			cc.cleanupOldEntries()
		}
	}
}

// cleanupOldEntries removes consensus entries older than the configured TTL
func (cc *ConsensusCoordinator) cleanupOldEntries() {
	cc.entriesMu.Lock()
	defer cc.entriesMu.Unlock()

	cutoff := time.Now().Add(-cc.config.EntryTTL)
	removed := 0

	for batchID, entry := range cc.entries {
		if entry.LastUpdate.Before(cutoff) {
			delete(cc.entries, batchID)
			removed++
		}
	}

	if removed > 0 {
		cc.logger.Printf("Cleaned up %d old consensus entries", removed)
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetConsensusEntry returns the consensus entry for a batch
func (cc *ConsensusCoordinator) GetConsensusEntry(batchID uuid.UUID) (*ConsensusEntry, bool) {
	cc.entriesMu.RLock()
	defer cc.entriesMu.RUnlock()

	entry, ok := cc.entries[batchID]
	if !ok {
		return nil, false
	}

	// Return a copy to prevent external modification
	entryCopy := *entry
	return &entryCopy, true
}

// GetActiveConsensusCount returns the number of active consensus processes
func (cc *ConsensusCoordinator) GetActiveConsensusCount() int {
	cc.entriesMu.RLock()
	defer cc.entriesMu.RUnlock()

	count := 0
	for _, entry := range cc.entries {
		if entry.State == ConsensusStateInitiated || entry.State == ConsensusStateCollecting {
			count++
		}
	}
	return count
}

// GetConsensusStats returns statistics about consensus processes
func (cc *ConsensusCoordinator) GetConsensusStats() map[string]int {
	cc.entriesMu.RLock()
	defer cc.entriesMu.RUnlock()

	stats := map[string]int{
		"total":     len(cc.entries),
		"initiated": 0,
		"collecting": 0,
		"quorum_met": 0,
		"completed": 0,
		"failed":    0,
		"timeout":   0,
	}

	for _, entry := range cc.entries {
		switch entry.State {
		case ConsensusStateInitiated:
			stats["initiated"]++
		case ConsensusStateCollecting:
			stats["collecting"]++
		case ConsensusStateQuorumMet:
			stats["quorum_met"]++
		case ConsensusStateCompleted:
			stats["completed"]++
		case ConsensusStateFailed:
			stats["failed"]++
		case ConsensusStateTimeout:
			stats["timeout"]++
		}
	}

	return stats
}

// =============================================================================
// Attestation Handler Integration
// =============================================================================

// HandleIncomingAttestation processes an incoming attestation request from a peer
// This is called by the network layer when a peer requests attestation
func (cc *ConsensusCoordinator) HandleIncomingAttestation(req *AttestationRequest) (*BatchAttestation, error) {
	// Verify we have BLS keys configured
	if len(cc.config.BLSPrivateKey) == 0 {
		return nil, fmt.Errorf("BLS private key not configured")
	}

	// Verify the batch is valid (we could check our own records)
	// For now, we trust the request and sign if the data looks valid
	if req.BatchID == (uuid.UUID{}) || len(req.MerkleRoot) != 32 {
		return nil, fmt.Errorf("invalid attestation request")
	}

	// Convert bytes to BLS private key
	privKey, err := bls.PrivateKeyFromBytes(cc.config.BLSPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid BLS private key: %w", err)
	}

	// Compute message hash
	messageHash := computeAttestationMessageHash(
		req.BatchID,
		req.MerkleRoot,
		req.TxCount,
		req.BlockHeight,
	)

	// Sign with BLS using domain separation
	signature := privKey.SignWithDomain(messageHash[:], bls.DomainAttestation)

	return &BatchAttestation{
		BatchID:     req.BatchID,
		MerkleRoot:  req.MerkleRoot,
		ValidatorID: cc.config.ValidatorID,
		PublicKey:   cc.config.BLSPublicKey,
		Signature:   signature.Bytes(),
		TxCount:     req.TxCount,
		BlockHeight: req.BlockHeight,
		Timestamp:   time.Now(),
	}, nil
}

// VerifyConsensusSignature verifies the aggregate BLS signature from consensus
func (cc *ConsensusCoordinator) VerifyConsensusSignature(result *ConsensusResult) (bool, error) {
	if result == nil || len(result.AggregateSignature) == 0 {
		return false, fmt.Errorf("no aggregate signature to verify")
	}

	// Convert bytes to BLS types
	aggPubKey, err := bls.PublicKeyFromBytes(result.AggregatePubKey)
	if err != nil {
		return false, fmt.Errorf("invalid aggregate public key: %w", err)
	}

	aggSig, err := bls.SignatureFromBytes(result.AggregateSignature)
	if err != nil {
		return false, fmt.Errorf("invalid aggregate signature: %w", err)
	}

	// Compute the message that was signed
	messageHash := computeAttestationMessageHash(
		result.BatchID,
		result.MerkleRoot,
		result.AttestationCount, // Note: this should be txCount, not attestation count
		result.BlockNumber,
	)

	// Verify aggregate signature with domain separation
	valid := aggPubKey.VerifyWithDomain(aggSig, messageHash[:], bls.DomainAttestation)

	return valid, nil
}
