// Copyright 2025 Certen Protocol
//
// On-Demand Handler - Manages immediate anchoring for high-priority requests
// Per Whitepaper Section 3.4.2: On-demand anchoring at ~$0.25/proof
//
// The on-demand handler:
// - Processes high-priority proof requests immediately
// - Creates small batches (1-5 transactions)
// - Triggers immediate anchoring without waiting for batch interval
// - Provides faster confirmation at higher cost

package batch

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// OnDemandHandler manages immediate anchoring for high-priority requests
type OnDemandHandler struct {
	mu sync.Mutex

	// Dependencies
	collector *Collector
	callback  BatchReadyCallback

	// Configuration
	maxBatchSize   int           // Max transactions before auto-anchor (default 5)
	maxWaitTime    time.Duration // Max wait time before auto-anchor (default 30s)

	// State
	processing bool
	lastAnchor time.Time

	// Accumulate state provider
	getAccumState func() (height int64, hash string)

	// Logging
	logger *log.Logger
}

// OnDemandConfig holds configuration for on-demand handler
type OnDemandConfig struct {
	MaxBatchSize   int
	MaxWaitTime    time.Duration
	Callback       BatchReadyCallback
	GetAccumState  func() (int64, string)
	Logger         *log.Logger
}

// DefaultOnDemandConfig returns default configuration
func DefaultOnDemandConfig() *OnDemandConfig {
	return &OnDemandConfig{
		MaxBatchSize: 5,                  // Small batches for fast anchoring
		MaxWaitTime:  30 * time.Second,   // Don't wait too long
		Logger:       log.New(log.Writer(), "[OnDemand] ", log.LstdFlags),
	}
}

// NewOnDemandHandler creates a new on-demand handler
func NewOnDemandHandler(collector *Collector, cfg *OnDemandConfig) (*OnDemandHandler, error) {
	if collector == nil {
		return nil, ErrNilCollector
	}
	if cfg == nil {
		cfg = DefaultOnDemandConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[OnDemand] ", log.LstdFlags)
	}
	if cfg.GetAccumState == nil {
		cfg.GetAccumState = func() (int64, string) { return 0, "" }
	}

	return &OnDemandHandler{
		collector:     collector,
		callback:      cfg.Callback,
		maxBatchSize:  cfg.MaxBatchSize,
		maxWaitTime:   cfg.MaxWaitTime,
		getAccumState: cfg.GetAccumState,
		logger:        cfg.Logger,
	}, nil
}

// OnDemandResult is returned when an on-demand transaction is processed
type OnDemandResult struct {
	TransactionResult *BatchTransactionResult `json:"transaction_result"`
	BatchResult       *ClosedBatchResult      `json:"batch_result,omitempty"`
	Anchored          bool                    `json:"anchored"`
	AnchorTriggered   bool                    `json:"anchor_triggered"`
}

// ProcessTransaction adds a transaction and potentially triggers immediate anchoring
func (h *OnDemandHandler) ProcessTransaction(ctx context.Context, tx *TransactionData) (*OnDemandResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Add transaction to on-demand batch
	txResult, err := h.collector.AddOnDemandTransaction(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to add on-demand transaction: %w", err)
	}

	result := &OnDemandResult{
		TransactionResult: txResult,
		Anchored:          false,
		AnchorTriggered:   false,
	}

	// Check if we should trigger anchoring
	shouldAnchor := false
	reason := ""

	// Check batch size
	if txResult.BatchReady || txResult.BatchSize >= h.maxBatchSize {
		shouldAnchor = true
		reason = "batch full"
	}

	// Check time since last anchor
	if !h.lastAnchor.IsZero() && time.Since(h.lastAnchor) >= h.maxWaitTime {
		info := h.collector.GetOnDemandBatchInfo()
		if info != nil && info.TxCount > 0 {
			shouldAnchor = true
			reason = "wait timeout"
		}
	}

	if shouldAnchor {
		h.logger.Printf("Triggering on-demand anchor (reason=%s)", reason)

		// Get current Accumulate state
		height, hash := h.getAccumState()

		// Close the batch
		batchResult, err := h.collector.CloseOnDemandBatch(ctx, height, hash)
		if err != nil {
			h.logger.Printf("Failed to close on-demand batch: %v", err)
			// Continue - transaction was still added successfully
		} else if batchResult != nil {
			result.BatchResult = batchResult
			result.AnchorTriggered = true
			h.lastAnchor = time.Now()

			// Call the callback
			if h.callback != nil {
				if err := h.callback(ctx, batchResult); err != nil {
					h.logger.Printf("On-demand callback failed: %v", err)
				} else {
					result.Anchored = true
				}
			}
		}
	}

	return result, nil
}

// FlushBatch forces immediate anchoring of any pending on-demand transactions
func (h *OnDemandHandler) FlushBatch(ctx context.Context) (*ClosedBatchResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.collector.HasPendingOnDemandBatch() {
		return nil, nil
	}

	h.logger.Println("Flushing on-demand batch")

	height, hash := h.getAccumState()
	result, err := h.collector.CloseOnDemandBatch(ctx, height, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to flush on-demand batch: %w", err)
	}

	if result != nil {
		h.lastAnchor = time.Now()

		if h.callback != nil {
			if err := h.callback(ctx, result); err != nil {
				h.logger.Printf("Flush callback failed: %v", err)
			}
		}
	}

	return result, nil
}

// SetCallback sets the callback for when batches are ready
func (h *OnDemandHandler) SetCallback(cb BatchReadyCallback) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callback = cb
}

// SetAccumStateProvider sets the function to get current Accumulate state
func (h *OnDemandHandler) SetAccumStateProvider(fn func() (int64, string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.getAccumState = fn
}

// GetStats returns on-demand handler statistics
func (h *OnDemandHandler) GetStats() *OnDemandStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := &OnDemandStats{
		MaxBatchSize: h.maxBatchSize,
		MaxWaitTime:  h.maxWaitTime,
		LastAnchor:   h.lastAnchor,
		Processing:   h.processing,
	}

	info := h.collector.GetOnDemandBatchInfo()
	if info != nil {
		stats.PendingBatchID = info.BatchID
		stats.PendingTxCount = info.TxCount
		stats.PendingAge = info.Age
	}

	return stats
}

// OnDemandStats holds statistics for the on-demand handler
type OnDemandStats struct {
	MaxBatchSize   int           `json:"max_batch_size"`
	MaxWaitTime    time.Duration `json:"max_wait_time"`
	LastAnchor     time.Time     `json:"last_anchor"`
	Processing     bool          `json:"processing"`
	PendingBatchID interface{}   `json:"pending_batch_id,omitempty"`
	PendingTxCount int           `json:"pending_tx_count"`
	PendingAge     time.Duration `json:"pending_age"`
}
