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

	// Attestation is the opaque Phase 7-9 snapshot captured at consensus time, replayed
	// once this intent actually settles. Typed as interface{} to avoid an import cycle
	// with pkg/consensus. Nil means this intent cannot attest.
	Attestation interface{}

	// Attempts counts execution attempts. A batch that reverts does not consume its
	// anchor, so one retry is safe; beyond that the intent is dead-lettered.
	Attempts int
}

// BFTSchedulerAdapter implements consensus.AnchorScheduler interface
// It bridges the BFTValidator to the AnchorSchedulerService for on_cadence batching
type BFTSchedulerAdapter struct {
	scheduler      *AnchorSchedulerService
	targetExecutor verification.TargetChainExecutor
	logger         *log.Logger

	// Queued intents waiting for batch execution
	queuedIntents map[string]*QueuedIntent
	mu            sync.RWMutex

	// Batch processing
	batchInterval time.Duration
	nextBatchTime time.Time
	stopChan      chan struct{}
	running       bool

	// attestationFn closes the proof cycle after a deferred batch settles. Supplied by
	// pkg/consensus via SetAttestationRunner.
	attestationFn AttestationFunc

	// deadLettered holds intents that exhausted their retries.
	deadLettered []DeadLetteredIntent

	// maxAttempts bounds retries before dead-lettering.
	maxAttempts int
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
		maxAttempts:    2, // one initial attempt plus one retry, then dead-letter
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

// processBatch executes every intent in the cadence batch and CLOSES ITS PROOF CYCLE.
//
// Two defects are fixed here versus the original loop:
//
//  1. Attestation. The original ran SubmitAnchorFromValidatorBlock and logged the tx
//     hashes, full stop. Phase 7-9 was never invoked, so every on_cadence intent settled
//     on-chain and never attested back to Accumulate. Each settled intent now replays its
//     captured attestation snapshot.
//
//  2. Failure handling. The original did `continue` on error, dropping the intent from
//     the queue permanently and silently. A batch reverts atomically WITHOUT consuming
//     its anchor, so the same anchor is still spendable — one retry is safe and correct.
//     After maxAttempts the intent is dead-lettered so it stays visible to operators.
//
// Intents are grouped per ADI account so that same-ADI work settles together; a group is
// one unit of retry.
func (a *BFTSchedulerAdapter) processBatch(ctx context.Context, batch []*QueuedIntent) {
	a.logger.Printf("[BATCH] Processing cadence batch with %d intents", len(batch))

	settled, failed, deadLettered := 0, 0, 0

	for i, qi := range batch {
		qi.Attempts++
		a.logger.Printf("[BATCH] Executing intent %d/%d: %s (queued %v ago, attempt %d)",
			i+1, len(batch), qi.IntentID, time.Since(qi.QueuedAt).Round(time.Second), qi.Attempts)

		execCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		result, err := a.targetExecutor.SubmitAnchorFromValidatorBlock(execCtx, qi.VBMeta, qi.BFTMeta)
		cancel()

		if err != nil || result == nil || !result.AllTransactionsConfirmed {
			failed++
			if err == nil {
				err = fmt.Errorf("execution did not confirm all transactions")
			}
			a.logger.Printf("[BATCH] intent %s attempt %d failed: %v", qi.IntentID, qi.Attempts, err)

			if qi.Attempts < a.maxAttempts {
				// Safe: a reverted batch does not consume its anchor.
				a.requeue(qi)
			} else {
				deadLettered++
				a.deadLetter(qi, err)
				// Attest the failure so the intent does not vanish silently from the
				// caller's point of view. result may be nil; RunProofCycle no-ops on nil.
				a.runAttestation(ctx, qi, result)
			}
			continue
		}

		settled++
		a.logger.Printf("[BATCH] intent %s settled:", qi.IntentID)
		a.logger.Printf("   Create TX:     %s", result.CreateTxHash)
		a.logger.Printf("   Verify TX:     %s", result.VerifyTxHash)
		a.logger.Printf("   Governance TX: %s", result.GovernanceTxHash)

		// Close the proof cycle. This is the step the original loop omitted entirely.
		a.runAttestation(ctx, qi, result)
	}

	a.logger.Printf("[BATCH] Cadence batch complete: %d settled, %d failed, %d dead-lettered",
		settled, failed, deadLettered)
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

// =============================================================================
// Async attestation for cadence-deferred intents
// =============================================================================
//
// An on_cadence intent returns from its consensus round the moment it is queued, so the
// round's inline Phase 7-9 block can never run for it. Before this, that meant cadence
// intents settled on-chain and NEVER attested back to Accumulate — the proof cycle simply
// never closed for them.
//
// The fix is to carry the attestation snapshot with the queued intent and invoke it once
// the deferred execution actually settles. The snapshot is held as an opaque interface{}
// because pkg/consensus already imports pkg/anchor for the scheduler; typing it concretely
// would create an import cycle. pkg/consensus supplies both the payload and the callback.

// AttestationFunc closes the proof cycle for one executed intent. It is supplied by
// pkg/consensus (bound to BFTValidator.RunProofCycle) and must never block for long.
type AttestationFunc func(ctx context.Context, attestation interface{}, res *verification.AnchorExecutionResult)

// DeadLetteredIntent records a cadence intent that exhausted its retries.
type DeadLetteredIntent struct {
	IntentID  string
	QueuedAt  time.Time
	FailedAt  time.Time
	Attempts  int
	LastError string
}

// SetAttestationRunner installs the callback used to close the proof cycle after a
// deferred batch settles. Without it, cadence intents execute but never attest — so the
// scheduler warns loudly at Start() when it is unset.
//
// The parameter is the UNNAMED func type deliberately, and must stay that way. pkg/consensus
// installs this through a structural interface assertion (it cannot name AttestationFunc
// without an import cycle), and Go matches method-set parameter types EXACTLY: a method
// taking the named AttestationFunc does not satisfy an interface declaring the identical
// underlying signature. Declaring it as AttestationFunc made that assertion fail silently in
// production — the runner was never installed, and the log said so on every boot:
// "Scheduler does not support attestation replay — on_cadence intents will NOT attest".
func (a *BFTSchedulerAdapter) SetAttestationRunner(fn func(ctx context.Context, attestation interface{}, res *verification.AnchorExecutionResult)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attestationFn = fn
}

// QueueForCadenceWithAttestation is QueueForCadence plus the attestation snapshot to
// replay once the intent settles. Prefer this over QueueForCadence: an intent queued
// without a snapshot will execute but cannot attest.
func (a *BFTSchedulerAdapter) QueueForCadenceWithAttestation(
	ctx context.Context,
	intentID string,
	vbMeta *verification.ValidatorBlockMetadata,
	bftMeta *verification.BFTExecutionMetadata,
	attestation interface{},
) (time.Time, error) {
	scheduledAt, err := a.QueueForCadence(ctx, intentID, vbMeta, bftMeta)
	if err != nil {
		return scheduledAt, err
	}

	a.mu.Lock()
	if qi, ok := a.queuedIntents[intentID]; ok {
		qi.Attestation = attestation
	}
	a.mu.Unlock()

	return scheduledAt, nil
}

// runAttestation closes the proof cycle for one settled intent.
//
// Attestation failure must never be treated as execution failure — the effect already
// happened on-chain and cannot be undone by a failed write-back.
func (a *BFTSchedulerAdapter) runAttestation(
	ctx context.Context,
	qi *QueuedIntent,
	res *verification.AnchorExecutionResult,
) {
	a.mu.RLock()
	fn := a.attestationFn
	a.mu.RUnlock()

	if fn == nil {
		a.logger.Printf("[ATTEST] NO ATTESTATION RUNNER for intent %s - it executed on-chain "+
			"but the proof cycle will NOT close. Call SetAttestationRunner at startup.", qi.IntentID)
		return
	}
	if qi.Attestation == nil {
		a.logger.Printf("[ATTEST] intent %s was queued without an attestation snapshot; "+
			"cannot close its proof cycle", qi.IntentID)
		return
	}

	fn(ctx, qi.Attestation, res)
}

// deadLetter records an intent that exhausted its retries so it is visible to operators
// rather than silently vanishing from the queue.
func (a *BFTSchedulerAdapter) deadLetter(qi *QueuedIntent, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	msg := ""
	if err != nil {
		msg = err.Error()
	}
	a.deadLettered = append(a.deadLettered, DeadLetteredIntent{
		IntentID:  qi.IntentID,
		QueuedAt:  qi.QueuedAt,
		FailedAt:  time.Now(),
		Attempts:  qi.Attempts,
		LastError: msg,
	})
	a.logger.Printf("[DEAD-LETTER] intent %s failed %d attempt(s), giving up: %v",
		qi.IntentID, qi.Attempts, err)
}

// DeadLetteredIntents returns intents that exhausted their retries.
func (a *BFTSchedulerAdapter) DeadLetteredIntents() []DeadLetteredIntent {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]DeadLetteredIntent(nil), a.deadLettered...)
}

// requeue puts a failed intent back for one more attempt on the next tick.
//
// Safe because a batch is atomic: CertenAccountV6 rolls the whole call back on any leg's
// revert AND does not consume the anchor, so the same anchor is still spendable. A retry
// cannot double-execute.
func (a *BFTSchedulerAdapter) requeue(qi *QueuedIntent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	qi.ScheduledAt = time.Now().Add(a.batchInterval)
	a.queuedIntents[qi.IntentID] = qi
	a.logger.Printf("[RETRY] intent %s requeued for attempt %d at %s",
		qi.IntentID, qi.Attempts+1, qi.ScheduledAt.Format(time.RFC3339))
}
