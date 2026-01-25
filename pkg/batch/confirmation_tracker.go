// Copyright 2025 Certen Protocol
//
// Confirmation Tracker - Monitors anchor confirmations on external chains
// Per Implementation Plan Priority 2.2: Track anchor confirmation status
//
// The confirmation tracker:
// - Periodically polls for unconfirmed anchors
// - Queries the Ethereum node for block confirmations
// - Updates anchor and proof status when confirmed
// - Marks anchors as finalized after reaching required confirmations

package batch

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// BlockInfoProvider provides information about blocks on the target chain
type BlockInfoProvider interface {
	// GetLatestBlockNumber returns the current block number
	GetLatestBlockNumber(ctx context.Context) (int64, error)
	// GetBlockHash returns the hash of a specific block
	GetBlockHash(ctx context.Context, blockNumber int64) (string, error)
	// GetBlockTimestamp returns the timestamp of a specific block
	GetBlockTimestamp(ctx context.Context, blockNumber int64) (time.Time, error)
}

// ConfirmationTracker monitors anchor confirmations
type ConfirmationTracker struct {
	mu sync.RWMutex

	// Dependencies
	repos         *database.Repositories
	blockProvider BlockInfoProvider

	// Configuration
	pollInterval          time.Duration
	requiredConfirmations int

	// State
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}

	// Logging
	logger *log.Logger
}

// ConfirmationTrackerConfig holds tracker configuration
type ConfirmationTrackerConfig struct {
	PollInterval          time.Duration
	RequiredConfirmations int // Number of confirmations for finality (default: 12 for Ethereum)
	Logger                *log.Logger
}

// DefaultConfirmationTrackerConfig returns default configuration
func DefaultConfirmationTrackerConfig() *ConfirmationTrackerConfig {
	return &ConfirmationTrackerConfig{
		PollInterval:          30 * time.Second,
		RequiredConfirmations: 12, // Standard Ethereum finality
		Logger:                log.New(log.Writer(), "[ConfirmationTracker] ", log.LstdFlags),
	}
}

// NewConfirmationTracker creates a new confirmation tracker
func NewConfirmationTracker(
	repos *database.Repositories,
	blockProvider BlockInfoProvider,
	cfg *ConfirmationTrackerConfig,
) (*ConfirmationTracker, error) {
	if repos == nil {
		return nil, fmt.Errorf("repositories cannot be nil")
	}
	if cfg == nil {
		cfg = DefaultConfirmationTrackerConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[ConfirmationTracker] ", log.LstdFlags)
	}

	return &ConfirmationTracker{
		repos:                 repos,
		blockProvider:         blockProvider,
		pollInterval:          cfg.PollInterval,
		requiredConfirmations: cfg.RequiredConfirmations,
		logger:                cfg.Logger,
	}, nil
}

// Start begins the confirmation tracking loop
func (t *ConfirmationTracker) Start(ctx context.Context) error {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return nil
	}

	t.stopCh = make(chan struct{})
	t.doneCh = make(chan struct{})
	t.running = true
	t.mu.Unlock()

	go t.run(ctx)

	t.logger.Printf("Started (polling every %s, %d confirmations for finality)",
		t.pollInterval, t.requiredConfirmations)
	return nil
}

// Stop stops the confirmation tracker
func (t *ConfirmationTracker) Stop() error {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return nil
	}

	close(t.stopCh)
	t.running = false
	t.mu.Unlock()

	<-t.doneCh

	t.logger.Println("Stopped")
	return nil
}

// run is the main tracking loop
func (t *ConfirmationTracker) run(ctx context.Context) {
	defer close(t.doneCh)

	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()

	// Initial check
	t.checkUnconfirmedAnchors(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.checkUnconfirmedAnchors(ctx)
		}
	}
}

// checkUnconfirmedAnchors checks all unconfirmed anchors for new confirmations
func (t *ConfirmationTracker) checkUnconfirmedAnchors(ctx context.Context) {
	// Get unconfirmed anchors from database
	anchors, err := t.repos.Anchors.GetUnconfirmedAnchors(ctx)
	if err != nil {
		t.logger.Printf("Failed to get unconfirmed anchors: %v", err)
		return
	}

	if len(anchors) == 0 {
		return
	}

	t.logger.Printf("Checking %d unconfirmed anchors", len(anchors))

	// Get current block number
	var latestBlock int64
	if t.blockProvider != nil {
		latestBlock, err = t.blockProvider.GetLatestBlockNumber(ctx)
		if err != nil {
			t.logger.Printf("Failed to get latest block number: %v", err)
			// Continue with best effort - use cached confirmations
		}
	}

	for _, anchor := range anchors {
		t.processAnchor(ctx, anchor, latestBlock)
	}
}

// processAnchor processes a single anchor for confirmation updates
func (t *ConfirmationTracker) processAnchor(ctx context.Context, anchor *database.AnchorRecord, latestBlock int64) {
	// Calculate confirmations
	var confirmations int
	if latestBlock > 0 && anchor.AnchorBlockNumber > 0 {
		confirmations = int(latestBlock - anchor.AnchorBlockNumber + 1)
		if confirmations < 0 {
			confirmations = 0
		}
	}

	// Get block hash and timestamp if we have a block provider
	var blockHash string
	var blockTimestamp time.Time
	if t.blockProvider != nil {
		var err error
		blockHash, err = t.blockProvider.GetBlockHash(ctx, anchor.AnchorBlockNumber)
		if err != nil {
			t.logger.Printf("Failed to get block hash for anchor %s: %v", anchor.AnchorID, err)
		}
		blockTimestamp, err = t.blockProvider.GetBlockTimestamp(ctx, anchor.AnchorBlockNumber)
		if err != nil {
			t.logger.Printf("Failed to get block timestamp for anchor %s: %v", anchor.AnchorID, err)
		}
	}

	// Update confirmations in database
	err := t.repos.Anchors.UpdateConfirmations(ctx, anchor.AnchorID, confirmations, blockHash, blockTimestamp)
	if err != nil {
		t.logger.Printf("Failed to update confirmations for anchor %s: %v", anchor.AnchorID, err)
		return
	}

	// Check if anchor has reached finality
	if confirmations >= t.requiredConfirmations {
		t.logger.Printf("Anchor %s reached finality (%d confirmations)", anchor.AnchorID, confirmations)

		// Mark anchor as final
		if err := t.repos.Anchors.MarkAnchorFinal(ctx, anchor.AnchorID); err != nil {
			t.logger.Printf("Failed to mark anchor %s as final: %v", anchor.AnchorID, err)
		}

		// Update all proofs associated with this anchor
		proofs, err := t.repos.Proofs.GetProofsByAnchorID(ctx, anchor.AnchorID)
		if err != nil {
			t.logger.Printf("Failed to get proofs for anchor %s: %v", anchor.AnchorID, err)
			return
		}

		for _, proof := range proofs {
			if err := t.repos.Proofs.UpdateAnchorConfirmations(ctx, proof.ProofID, confirmations, blockHash); err != nil {
				t.logger.Printf("Failed to update proof %s confirmations: %v", proof.ProofID, err)
			}
		}

		// Mark external chain results as finalized (Gap 5 fix)
		if t.repos.ProofArtifacts != nil {
			if ecCount, err := t.repos.ProofArtifacts.MarkExternalChainResultsFinalizedByAnchor(ctx, anchor.AnchorID); err != nil {
				t.logger.Printf("Failed to finalize external chain results for anchor %s: %v", anchor.AnchorID, err)
			} else if ecCount > 0 {
				t.logger.Printf("Finalized %d external chain results for anchor %s", ecCount, anchor.AnchorID)
			}

			// Mark BLS aggregations as finalized (Gap 6 fix)
			if blsCount, err := t.repos.ProofArtifacts.MarkBLSAggregationsFinalizedByAnchor(ctx, anchor.AnchorID); err != nil {
				t.logger.Printf("Failed to finalize BLS aggregations for anchor %s: %v", anchor.AnchorID, err)
			} else if blsCount > 0 {
				t.logger.Printf("Finalized %d BLS aggregations for anchor %s", blsCount, anchor.AnchorID)
			}
		}
	}
}

// ForceCheck manually triggers a confirmation check
func (t *ConfirmationTracker) ForceCheck(ctx context.Context) {
	t.checkUnconfirmedAnchors(ctx)
}

// GetStats returns tracker statistics
func (t *ConfirmationTracker) GetStats(ctx context.Context) (*ConfirmationStats, error) {
	totalAnchors, err := t.repos.Anchors.CountAnchors(ctx)
	if err != nil {
		return nil, err
	}

	finalAnchors, err := t.repos.Anchors.CountFinalAnchors(ctx)
	if err != nil {
		return nil, err
	}

	unconfirmedAnchors, err := t.repos.Anchors.GetUnconfirmedAnchors(ctx)
	if err != nil {
		return nil, err
	}

	t.mu.RLock()
	running := t.running
	t.mu.RUnlock()

	return &ConfirmationStats{
		TotalAnchors:          totalAnchors,
		FinalizedAnchors:      finalAnchors,
		PendingAnchors:        int64(len(unconfirmedAnchors)),
		RequiredConfirmations: t.requiredConfirmations,
		TrackerRunning:        running,
	}, nil
}

// ConfirmationStats holds confirmation tracker statistics
type ConfirmationStats struct {
	TotalAnchors          int64 `json:"total_anchors"`
	FinalizedAnchors      int64 `json:"finalized_anchors"`
	PendingAnchors        int64 `json:"pending_anchors"`
	RequiredConfirmations int   `json:"required_confirmations"`
	TrackerRunning        bool  `json:"tracker_running"`
}

// BatchAwareStatus provides batch-type-aware status for health checks
type BatchAwareStatus struct {
	TrackerStatus         string `json:"tracker_status"`
	TotalAnchors          int64  `json:"total_anchors"`
	FinalizedAnchors      int64  `json:"finalized_anchors"`
	PendingAnchors        int64  `json:"pending_anchors"`
	RequiredConfirmations int    `json:"required_confirmations"`
	StatusMessage         string `json:"status_message"`
	IsHealthy             bool   `json:"is_healthy"`
}

// GetBatchAwareStatus returns the confirmation tracker status with batch-aware context
// Per Implementation Plan: This method provides health check information that understands
// that on-cadence batch delays are expected and should not be flagged as issues
func (t *ConfirmationTracker) GetBatchAwareStatus(ctx context.Context) (*BatchAwareStatus, error) {
	stats, err := t.GetStats(ctx)
	if err != nil {
		return &BatchAwareStatus{
			TrackerStatus: "error",
			StatusMessage: fmt.Sprintf("Failed to get tracker stats: %v", err),
			IsHealthy:     false,
		}, err
	}

	status := &BatchAwareStatus{
		TotalAnchors:          stats.TotalAnchors,
		FinalizedAnchors:      stats.FinalizedAnchors,
		PendingAnchors:        stats.PendingAnchors,
		RequiredConfirmations: stats.RequiredConfirmations,
		IsHealthy:             true,
	}

	// Determine tracker status
	if !stats.TrackerRunning {
		status.TrackerStatus = "stopped"
		status.StatusMessage = "Confirmation tracker is not running."
		status.IsHealthy = false
		return status, nil
	}

	status.TrackerStatus = "running"

	// Build status message
	if stats.PendingAnchors > 0 {
		status.StatusMessage = fmt.Sprintf(
			"Tracking %d pending anchors. %d/%d confirmations required for finality. "+
				"Waiting for confirmations is normal operation.",
			stats.PendingAnchors, 0, stats.RequiredConfirmations)
	} else if stats.TotalAnchors > 0 {
		status.StatusMessage = fmt.Sprintf(
			"All %d anchors confirmed. System operating normally.",
			stats.FinalizedAnchors)
	} else {
		status.StatusMessage = "No anchors tracked yet. System ready."
	}

	return status, nil
}

// EthereumBlockProvider implements BlockInfoProvider for Ethereum
type EthereumBlockProvider struct {
	// getLatestBlock is called to get the latest block number
	getLatestBlock func(ctx context.Context) (int64, error)
	// getBlockInfo is called to get block hash and timestamp
	getBlockInfo func(ctx context.Context, blockNumber int64) (hash string, timestamp time.Time, err error)
}

// NewEthereumBlockProvider creates a new Ethereum block provider
func NewEthereumBlockProvider(
	getLatestBlock func(ctx context.Context) (int64, error),
	getBlockInfo func(ctx context.Context, blockNumber int64) (hash string, timestamp time.Time, err error),
) *EthereumBlockProvider {
	return &EthereumBlockProvider{
		getLatestBlock: getLatestBlock,
		getBlockInfo:   getBlockInfo,
	}
}

// GetLatestBlockNumber implements BlockInfoProvider
func (p *EthereumBlockProvider) GetLatestBlockNumber(ctx context.Context) (int64, error) {
	if p.getLatestBlock == nil {
		return 0, fmt.Errorf("getLatestBlock not configured")
	}
	return p.getLatestBlock(ctx)
}

// GetBlockHash implements BlockInfoProvider
func (p *EthereumBlockProvider) GetBlockHash(ctx context.Context, blockNumber int64) (string, error) {
	if p.getBlockInfo == nil {
		return "", fmt.Errorf("getBlockInfo not configured")
	}
	hash, _, err := p.getBlockInfo(ctx, blockNumber)
	return hash, err
}

// GetBlockTimestamp implements BlockInfoProvider
func (p *EthereumBlockProvider) GetBlockTimestamp(ctx context.Context, blockNumber int64) (time.Time, error) {
	if p.getBlockInfo == nil {
		return time.Time{}, fmt.Errorf("getBlockInfo not configured")
	}
	_, timestamp, err := p.getBlockInfo(ctx, blockNumber)
	return timestamp, err
}
