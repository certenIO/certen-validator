// Copyright 2025 Certen Protocol
//
// Batch Scheduler - Manages on-cadence batch timing
// Per Whitepaper Section 3.4.2: ~15 minute batch intervals for cost-effective anchoring
//
// The scheduler:
// - Runs a background timer for on-cadence batches
// - Triggers batch closing when timer fires or batch is full
// - Coordinates with the batch processor for anchoring

package batch

import (
	"context"
	"log"
	"sync"
	"time"
)

// SchedulerState represents the current state of the scheduler
type SchedulerState string

const (
	SchedulerStateStopped  SchedulerState = "stopped"
	SchedulerStateRunning  SchedulerState = "running"
	SchedulerStatePaused   SchedulerState = "paused"
)

// BatchReadyCallback is called when a batch is ready for anchoring
type BatchReadyCallback func(ctx context.Context, result *ClosedBatchResult) error

// Scheduler manages batch timing and triggers
type Scheduler struct {
	mu sync.RWMutex

	// Dependencies
	collector *Collector
	callback  BatchReadyCallback

	// Configuration
	interval time.Duration // Batch interval (~15 min)
	checkInterval time.Duration // How often to check (1 min)

	// State
	state     SchedulerState
	timer     *time.Timer
	stopCh    chan struct{}
	doneCh    chan struct{}

	// Accumulate state provider
	getAccumState func() (height int64, hash string)

	// Logging
	logger *log.Logger
}

// SchedulerConfig holds scheduler configuration
type SchedulerConfig struct {
	Interval      time.Duration     // Main batch interval (~15 min)
	CheckInterval time.Duration     // How often to check for ready batches
	Callback      BatchReadyCallback // Called when batch is ready
	GetAccumState func() (int64, string) // Gets current Accumulate state
	Logger        *log.Logger
}

// DefaultSchedulerConfig returns default configuration
func DefaultSchedulerConfig() *SchedulerConfig {
	return &SchedulerConfig{
		Interval:      15 * time.Minute,
		CheckInterval: 1 * time.Minute,
		Logger:        log.New(log.Writer(), "[BatchScheduler] ", log.LstdFlags),
	}
}

// NewScheduler creates a new batch scheduler
func NewScheduler(collector *Collector, cfg *SchedulerConfig) (*Scheduler, error) {
	if collector == nil {
		return nil, ErrNilCollector
	}
	if cfg == nil {
		cfg = DefaultSchedulerConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[BatchScheduler] ", log.LstdFlags)
	}
	if cfg.GetAccumState == nil {
		// Default: return 0, "" (will be overridden at runtime)
		cfg.GetAccumState = func() (int64, string) { return 0, "" }
	}

	return &Scheduler{
		collector:     collector,
		callback:      cfg.Callback,
		interval:      cfg.Interval,
		checkInterval: cfg.CheckInterval,
		state:         SchedulerStateStopped,
		getAccumState: cfg.GetAccumState,
		logger:        cfg.Logger,
	}, nil
}

// Start begins the scheduler
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == SchedulerStateRunning {
		return nil // Already running
	}

	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.state = SchedulerStateRunning

	go s.run(ctx)

	s.logger.Printf("Scheduler started (interval=%s, check=%s)", s.interval, s.checkInterval)
	return nil
}

// Stop stops the scheduler
func (s *Scheduler) Stop() error {
	s.mu.Lock()
	if s.state != SchedulerStateRunning {
		s.mu.Unlock()
		return nil
	}

	close(s.stopCh)
	s.state = SchedulerStateStopped
	s.mu.Unlock()

	// Wait for run loop to finish
	<-s.doneCh

	s.logger.Println("Scheduler stopped")
	return nil
}

// Pause temporarily pauses the scheduler
func (s *Scheduler) Pause() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == SchedulerStateRunning {
		s.state = SchedulerStatePaused
		s.logger.Println("Scheduler paused")
	}
}

// Resume resumes a paused scheduler
func (s *Scheduler) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == SchedulerStatePaused {
		s.state = SchedulerStateRunning
		s.logger.Println("Scheduler resumed")
	}
}

// State returns the current scheduler state
func (s *Scheduler) State() SchedulerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// run is the main scheduler loop
func (s *Scheduler) run(ctx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	// Track when the current batch was opened
	var batchStartTime time.Time
	hasBatch := false

	for {
		select {
		case <-ctx.Done():
			s.logger.Println("Scheduler context cancelled")
			return

		case <-s.stopCh:
			return

		case <-ticker.C:
			s.mu.RLock()
			state := s.state
			s.mu.RUnlock()

			if state != SchedulerStateRunning {
				continue
			}

			// Check if we have a pending batch
			info := s.collector.GetOnCadenceBatchInfo()
			if info == nil {
				hasBatch = false
				continue
			}

			if !hasBatch {
				batchStartTime = info.StartTime
				hasBatch = true
				s.logger.Printf("Tracking on-cadence batch %s (started %s ago)",
					info.BatchID, time.Since(info.StartTime).Round(time.Second))
			}

			// Check if batch should be closed
			shouldClose := false
			reason := ""

			// Check timeout
			if time.Since(batchStartTime) >= s.interval {
				shouldClose = true
				reason = "timeout"
			}

			// Check if collector says batch is ready
			if s.collector.ShouldCloseOnCadenceBatch() {
				shouldClose = true
				if reason == "" {
					reason = "size limit"
				}
			}

			if shouldClose && info.TxCount > 0 {
				s.logger.Printf("Closing on-cadence batch %s (reason=%s, txs=%d, age=%s)",
					info.BatchID, reason, info.TxCount, time.Since(batchStartTime).Round(time.Second))

				// Get current Accumulate state
				height, hash := s.getAccumState()

				// Close the batch
				result, err := s.collector.CloseOnCadenceBatch(ctx, height, hash)
				if err != nil {
					s.logger.Printf("Failed to close batch: %v", err)
					continue
				}

				hasBatch = false

				// Call the callback if set
				if s.callback != nil && result != nil {
					if err := s.callback(ctx, result); err != nil {
						s.logger.Printf("Batch callback failed: %v", err)
					}
				}
			}
		}
	}
}

// TriggerClose manually triggers closing the current on-cadence batch
// Useful for graceful shutdown or testing
func (s *Scheduler) TriggerClose(ctx context.Context) (*ClosedBatchResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.collector.HasPendingOnCadenceBatch() {
		return nil, nil
	}

	height, hash := s.getAccumState()
	result, err := s.collector.CloseOnCadenceBatch(ctx, height, hash)
	if err != nil {
		return nil, err
	}

	if s.callback != nil && result != nil {
		if err := s.callback(ctx, result); err != nil {
			s.logger.Printf("Batch callback failed: %v", err)
		}
	}

	return result, nil
}

// SetCallback sets the callback for when batches are ready
func (s *Scheduler) SetCallback(cb BatchReadyCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callback = cb
}

// SetAccumStateProvider sets the function to get current Accumulate state
func (s *Scheduler) SetAccumStateProvider(fn func() (int64, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getAccumState = fn
}

// GetInterval returns the current batch interval
func (s *Scheduler) GetInterval() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.interval
}

// SetInterval updates the batch interval (takes effect on next batch)
func (s *Scheduler) SetInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interval = d
	s.logger.Printf("Batch interval updated to %s", d)
}
