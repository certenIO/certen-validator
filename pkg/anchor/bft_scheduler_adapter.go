// Copyright 2025 Certen Protocol
//
// BFT Scheduler Adapter - Bridges consensus.AnchorScheduler to AnchorSchedulerService
//
// This adapter enables the BFTValidator to queue on_cadence intents for batched execution
// per FIRST_PRINCIPLES 2.5: on_cadence and on_demand are NEVER interchangeable.

package anchor

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/verification"
)

// QueuedIntent represents an intent waiting for batched execution
type QueuedIntent struct {
	IntentID    string
	VBMeta      *verification.ValidatorBlockMetadata
	BFTMeta     *verification.BFTExecutionMetadata
	QueuedAt    time.Time
	ScheduledAt time.Time
}

// BFTSchedulerAdapter implements consensus.AnchorScheduler interface
// It bridges the BFTValidator to the AnchorSchedulerService for on_cadence batching
type BFTSchedulerAdapter struct {
	scheduler       *AnchorSchedulerService
	targetExecutor  verification.TargetChainExecutor
	logger          *log.Logger

	// Queued intents waiting for batch execution
	queuedIntents   map[string]*QueuedIntent
	mu              sync.RWMutex

	// Batch processing
	batchInterval   time.Duration
	nextBatchTime   time.Time
	stopChan        chan struct{}
	running         bool
}

// BFTSchedulerConfig contains configuration for the BFT scheduler adapter
type BFTSchedulerConfig struct {
	BatchInterval time.Duration // How often to process batches (default: 15 minutes)
	MinBatchSize  int           // Minimum intents to trigger a batch (default: 1)
	MaxBatchSize  int           // Maximum intents per batch (default: 100)
}

// DefaultBFTSchedulerConfig returns default configuration
func DefaultBFTSchedulerConfig() *BFTSchedulerConfig {
	return &BFTSchedulerConfig{
		BatchInterval: 15 * time.Minute,
		MinBatchSize:  1,
		MaxBatchSize:  100,
	}
}

// NewBFTSchedulerAdapter creates a new BFT scheduler adapter
func NewBFTSchedulerAdapter(
	scheduler *AnchorSchedulerService,
	targetExecutor verification.TargetChainExecutor,
	config *BFTSchedulerConfig,
	logger *log.Logger,
) *BFTSchedulerAdapter {
	if config == nil {
		config = DefaultBFTSchedulerConfig()
	}
	if logger == nil {
		logger = log.New(log.Writer(), "[BFT-SCHEDULER] ", log.LstdFlags)
	}

	return &BFTSchedulerAdapter{
		scheduler:      scheduler,
		targetExecutor: targetExecutor,
		logger:         logger,
		queuedIntents:  make(map[string]*QueuedIntent),
		batchInterval:  config.BatchInterval,
		nextBatchTime:  time.Now().Add(config.BatchInterval),
		stopChan:       make(chan struct{}),
	}
}

// QueueForCadence queues an intent for batched on-cadence execution
// Implements consensus.AnchorScheduler interface
func (a *BFTSchedulerAdapter) QueueForCadence(
	ctx context.Context,
	intentID string,
	vbMeta *verification.ValidatorBlockMetadata,
	bftMeta *verification.BFTExecutionMetadata,
) (time.Time, error) {
	if intentID == "" {
		return time.Time{}, fmt.Errorf("intentID cannot be empty")
	}
	if vbMeta == nil {
		return time.Time{}, fmt.Errorf("ValidatorBlockMetadata cannot be nil")
	}
	if bftMeta == nil {
		return time.Time{}, fmt.Errorf("BFTExecutionMetadata cannot be nil")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check for duplicate
	if _, exists := a.queuedIntents[intentID]; exists {
		return a.nextBatchTime, fmt.Errorf("intent %s already queued", intentID)
	}

	// CRITICAL FIX: Ensure nextBatchTime is always in the future
	// If nextBatchTime is in the past (no intents queued for a while), reset it to now + batchInterval
	now := time.Now()
	if a.nextBatchTime.Before(now) {
		a.nextBatchTime = now.Add(a.batchInterval)
		a.logger.Printf("🔄 [CADENCE-RESET] Resetting nextBatchTime to %s (was in the past)", a.nextBatchTime.Format(time.RFC3339))
	}

	// Calculate scheduled time - always in the future now
	scheduledAt := a.nextBatchTime

	// Queue the intent
	a.queuedIntents[intentID] = &QueuedIntent{
		IntentID:    intentID,
		VBMeta:      vbMeta,
		BFTMeta:     bftMeta,
		QueuedAt:    time.Now(),
		ScheduledAt: scheduledAt,
	}

	a.logger.Printf("📦 [QUEUE] Intent %s queued for cadence batch (scheduled: %s, queue size: %d)",
		intentID, scheduledAt.Format(time.RFC3339), len(a.queuedIntents))

	return scheduledAt, nil
}

// GetQueuedCount returns the number of intents waiting in the cadence queue
// Implements consensus.AnchorScheduler interface
func (a *BFTSchedulerAdapter) GetQueuedCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.queuedIntents)
}

// IsRunning returns whether the scheduler is actively processing
// Implements consensus.AnchorScheduler interface
func (a *BFTSchedulerAdapter) IsRunning() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.running
}

// Start starts the batch processing loop
func (a *BFTSchedulerAdapter) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return fmt.Errorf("scheduler already running")
	}
	a.running = true
	a.mu.Unlock()

	a.logger.Printf("🚀 [START] BFT Scheduler Adapter started (batch interval: %v)", a.batchInterval)

	go a.batchProcessingLoop(ctx)

	return nil
}

// Stop stops the batch processing loop
func (a *BFTSchedulerAdapter) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.running {
		return
	}

	a.running = false
	close(a.stopChan)
	a.logger.Printf("🛑 [STOP] BFT Scheduler Adapter stopped")
}

// batchProcessingLoop runs the background batch processing
func (a *BFTSchedulerAdapter) batchProcessingLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("🛑 [LOOP] Context cancelled, stopping batch processor")
			return
		case <-a.stopChan:
			a.logger.Printf("🛑 [LOOP] Stop signal received")
			return
		case <-ticker.C:
			a.checkAndProcessBatch(ctx)
		}
	}
}

// checkAndProcessBatch checks if it's time to process a batch
func (a *BFTSchedulerAdapter) checkAndProcessBatch(ctx context.Context) {
	a.mu.Lock()

	now := time.Now()
	if now.Before(a.nextBatchTime) && len(a.queuedIntents) == 0 {
		a.mu.Unlock()
		return
	}

	// Check if batch is due or we have queued intents past their scheduled time
	shouldProcess := false
	var dueIntents []*QueuedIntent

	for _, qi := range a.queuedIntents {
		if now.After(qi.ScheduledAt) || now.Equal(qi.ScheduledAt) {
			dueIntents = append(dueIntents, qi)
			shouldProcess = true
		}
	}

	if !shouldProcess {
		a.mu.Unlock()
		return
	}

	// Remove due intents from queue
	for _, qi := range dueIntents {
		delete(a.queuedIntents, qi.IntentID)
	}

	// Update next batch time
	a.nextBatchTime = now.Add(a.batchInterval)
	a.mu.Unlock()

	// Process the batch
	if len(dueIntents) > 0 {
		a.processBatch(ctx, dueIntents)
	}
}

// processBatch executes all intents in the batch
func (a *BFTSchedulerAdapter) processBatch(ctx context.Context, batch []*QueuedIntent) {
	a.logger.Printf("📦 [BATCH] Processing cadence batch with %d intents", len(batch))

	for i, qi := range batch {
		a.logger.Printf("📦 [BATCH] Executing intent %d/%d: %s (queued for %v)",
			i+1, len(batch), qi.IntentID, time.Since(qi.QueuedAt).Round(time.Second))

		// Execute via target chain executor
		execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		result, err := a.targetExecutor.SubmitAnchorFromValidatorBlock(execCtx, qi.VBMeta, qi.BFTMeta)
		cancel()

		if err != nil {
			a.logger.Printf("❌ [BATCH] Failed to execute intent %s: %v", qi.IntentID, err)
			continue
		}

		if result != nil {
			a.logger.Printf("✅ [BATCH] Intent %s executed successfully:", qi.IntentID)
			a.logger.Printf("   Create TX:     %s", result.CreateTxHash)
			a.logger.Printf("   Verify TX:     %s", result.VerifyTxHash)
			a.logger.Printf("   Governance TX: %s", result.GovernanceTxHash)
		}
	}

	a.logger.Printf("✅ [BATCH] Cadence batch complete (%d intents processed)", len(batch))
}

// GetNextBatchTime returns when the next batch will be processed
func (a *BFTSchedulerAdapter) GetNextBatchTime() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.nextBatchTime
}

// GetQueuedIntents returns a copy of all queued intents (for debugging/monitoring)
func (a *BFTSchedulerAdapter) GetQueuedIntents() []*QueuedIntent {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]*QueuedIntent, 0, len(a.queuedIntents))
	for _, qi := range a.queuedIntents {
		result = append(result, qi)
	}
	return result
}
