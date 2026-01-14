// Copyright 2025 Certen Protocol
//
// AnchorSchedulerService - Manages on-cadence and on-demand proof anchoring
//
// Pricing tiers per Whitepaper:
// - on_cadence: ~$0.05/proof, batched every ~15 minutes
// - on_demand: ~$0.25/proof, immediate processing
//
// This service coordinates with the AnchorManager and ProofLifecycleManager
// to schedule and execute anchoring operations.

package anchor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// Pricing Tiers
// =============================================================================

// AnchorClass defines the pricing tier for anchoring
type AnchorClass string

const (
	ClassOnCadence AnchorClass = "on_cadence"
	ClassOnDemand  AnchorClass = "on_demand"
)

// PricingTier defines the cost and delay for each anchor class
type PricingTier struct {
	TierID            string        `json:"tier_id"`
	TierName          string        `json:"tier_name"`
	BaseCostUSD       float64       `json:"base_cost_usd"`
	BatchDelaySeconds int           `json:"batch_delay_seconds"`
	Priority          int           `json:"priority"`
}

// DefaultPricingTiers returns the default pricing configuration
func DefaultPricingTiers() map[AnchorClass]PricingTier {
	return map[AnchorClass]PricingTier{
		ClassOnCadence: {
			TierID:            "on_cadence",
			TierName:          "On-Cadence (Batched)",
			BaseCostUSD:       0.05,
			BatchDelaySeconds: 900, // 15 minutes
			Priority:          1,
		},
		ClassOnDemand: {
			TierID:            "on_demand",
			TierName:          "On-Demand (Immediate)",
			BaseCostUSD:       0.25,
			BatchDelaySeconds: 0,
			Priority:          10,
		},
	}
}

// =============================================================================
// Anchor Request
// =============================================================================

// ScheduledAnchorRequest represents a request to anchor a proof via the scheduler
type ScheduledAnchorRequest struct {
	RequestID    uuid.UUID   `json:"request_id"`
	ProofID      uuid.UUID   `json:"proof_id"`
	AccountURL   string      `json:"account_url"`
	TxHash       string      `json:"tx_hash,omitempty"`
	AnchorClass  AnchorClass `json:"anchor_class"`
	TargetChain  string      `json:"target_chain"` // "ethereum", "bitcoin", etc.
	CallbackURL  string      `json:"callback_url,omitempty"`
	RequestedAt  time.Time   `json:"requested_at"`
	ScheduledFor time.Time   `json:"scheduled_for"`
	Status       string      `json:"status"` // "pending", "batched", "processing", "completed", "failed"
	BatchID      *uuid.UUID  `json:"batch_id,omitempty"`
	RetryCount   int         `json:"retry_count"`
	MaxRetries   int         `json:"max_retries"`
	Error        string      `json:"error,omitempty"`
}

// ScheduledAnchorBatch represents a batch of anchor requests
type ScheduledAnchorBatch struct {
	BatchID       uuid.UUID                 `json:"batch_id"`
	TargetChain   string                    `json:"target_chain"`
	AnchorClass   AnchorClass               `json:"anchor_class"`
	Requests      []*ScheduledAnchorRequest `json:"requests"`
	ScheduledFor  time.Time                 `json:"scheduled_for"`
	Status        string                    `json:"status"` // "pending", "processing", "completed", "failed"
	AnchorTxHash  string                    `json:"anchor_tx_hash,omitempty"`
	AnchorBlockNum int64                    `json:"anchor_block_num,omitempty"`
	ProcessedAt   *time.Time                `json:"processed_at,omitempty"`
	Error         string                    `json:"error,omitempty"`
}

// =============================================================================
// AnchorSchedulerService
// =============================================================================

// AnchorSchedulerService manages proof anchoring scheduling
type AnchorSchedulerService struct {
	// Configuration
	config *SchedulerConfig

	// Pricing tiers
	pricingTiers map[AnchorClass]PricingTier

	// Request queues (by chain and class)
	queues map[string]map[AnchorClass][]*ScheduledAnchorRequest
	mu     sync.RWMutex

	// Pending batches
	pendingBatches map[uuid.UUID]*ScheduledAnchorBatch
	batchMu        sync.RWMutex

	// Channels
	requestChan    chan *ScheduledAnchorRequest
	batchReadyChan chan *ScheduledAnchorBatch
	stopChan       chan struct{}

	// State
	running bool

	// Metrics
	metrics *SchedulerMetrics
}

// SchedulerConfig contains scheduler configuration
type SchedulerConfig struct {
	// Batch settings
	DefaultBatchSize     int           `json:"default_batch_size"`
	MaxBatchSize         int           `json:"max_batch_size"`
	BatchCheckInterval   time.Duration `json:"batch_check_interval"`

	// On-cadence settings
	OnCadenceInterval    time.Duration `json:"on_cadence_interval"` // ~15 minutes
	OnCadenceMinBatch    int           `json:"on_cadence_min_batch"` // Minimum to trigger

	// On-demand settings
	OnDemandMaxDelay     time.Duration `json:"on_demand_max_delay"` // Max wait for on-demand

	// Retry settings
	MaxRetries           int           `json:"max_retries"`
	RetryDelay           time.Duration `json:"retry_delay"`

	// Supported chains
	SupportedChains      []string      `json:"supported_chains"`
}

// DefaultSchedulerConfig returns default configuration
func DefaultSchedulerConfig() *SchedulerConfig {
	return &SchedulerConfig{
		DefaultBatchSize:   100,
		MaxBatchSize:       500,
		BatchCheckInterval: 30 * time.Second,
		OnCadenceInterval:  15 * time.Minute,
		OnCadenceMinBatch:  10,
		OnDemandMaxDelay:   30 * time.Second,
		MaxRetries:         3,
		RetryDelay:         5 * time.Second,
		SupportedChains:    []string{"ethereum", "bitcoin"},
	}
}

// SchedulerMetrics tracks scheduler metrics
type SchedulerMetrics struct {
	RequestsReceived   int64
	RequestsProcessed  int64
	RequestsFailed     int64
	BatchesCreated     int64
	BatchesCompleted   int64
	BatchesFailed      int64
	OnCadenceRequests  int64
	OnDemandRequests   int64
	LastBatchAt        time.Time
	AverageBatchSize   float64
}

// NewAnchorSchedulerService creates a new scheduler service
func NewAnchorSchedulerService(config *SchedulerConfig) (*AnchorSchedulerService, error) {
	if config == nil {
		config = DefaultSchedulerConfig()
	}

	// Initialize queues for each chain and class
	queues := make(map[string]map[AnchorClass][]*ScheduledAnchorRequest)
	for _, chain := range config.SupportedChains {
		queues[chain] = map[AnchorClass][]*ScheduledAnchorRequest{
			ClassOnCadence: make([]*ScheduledAnchorRequest, 0),
			ClassOnDemand:  make([]*ScheduledAnchorRequest, 0),
		}
	}

	return &AnchorSchedulerService{
		config:         config,
		pricingTiers:   DefaultPricingTiers(),
		queues:         queues,
		pendingBatches: make(map[uuid.UUID]*ScheduledAnchorBatch),
		requestChan:    make(chan *ScheduledAnchorRequest, 1000),
		batchReadyChan: make(chan *ScheduledAnchorBatch, 100),
		stopChan:       make(chan struct{}),
		metrics:        &SchedulerMetrics{},
	}, nil
}

// =============================================================================
// Request Submission
// =============================================================================

// SubmitRequest submits a new anchor request
func (s *AnchorSchedulerService) SubmitRequest(proofID uuid.UUID, accountURL, txHash string, class AnchorClass, targetChain string) (*ScheduledAnchorRequest, error) {
	// Validate chain
	if !s.isChainSupported(targetChain) {
		return nil, fmt.Errorf("unsupported chain: %s", targetChain)
	}

	// Validate class
	tier, ok := s.pricingTiers[class]
	if !ok {
		return nil, fmt.Errorf("invalid anchor class: %s", class)
	}

	// Create request
	now := time.Now()
	scheduledFor := now.Add(time.Duration(tier.BatchDelaySeconds) * time.Second)

	request := &ScheduledAnchorRequest{
		RequestID:    uuid.New(),
		ProofID:      proofID,
		AccountURL:   accountURL,
		TxHash:       txHash,
		AnchorClass:  class,
		TargetChain:  targetChain,
		RequestedAt:  now,
		ScheduledFor: scheduledFor,
		Status:       "pending",
		MaxRetries:   s.config.MaxRetries,
	}

	// Add to queue
	s.mu.Lock()
	s.queues[targetChain][class] = append(s.queues[targetChain][class], request)
	s.mu.Unlock()

	// Update metrics
	s.metrics.RequestsReceived++
	if class == ClassOnCadence {
		s.metrics.OnCadenceRequests++
	} else {
		s.metrics.OnDemandRequests++
	}

	// For on-demand, trigger immediate processing
	if class == ClassOnDemand {
		select {
		case s.requestChan <- request:
		default:
			// Channel full, will be processed by batch check
		}
	}

	return request, nil
}

// =============================================================================
// Batch Management
// =============================================================================

// Start starts the scheduler service
func (s *AnchorSchedulerService) Start(ctx context.Context) error {
	if s.running {
		return fmt.Errorf("scheduler already running")
	}

	s.running = true

	// Start batch check loop
	go s.batchCheckLoop(ctx)

	// Start on-demand processor
	go s.onDemandProcessor(ctx)

	return nil
}

// Stop stops the scheduler service
func (s *AnchorSchedulerService) Stop() {
	if !s.running {
		return
	}
	s.running = false
	close(s.stopChan)
}

// batchCheckLoop periodically checks for batches ready to process
func (s *AnchorSchedulerService) batchCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(s.config.BatchCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.checkAndCreateBatches()
		}
	}
}

// onDemandProcessor handles immediate on-demand requests
func (s *AnchorSchedulerService) onDemandProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case request := <-s.requestChan:
			if request.AnchorClass == ClassOnDemand {
				s.processOnDemandRequest(request)
			}
		}
	}
}

// checkAndCreateBatches checks queues and creates batches as needed
func (s *AnchorSchedulerService) checkAndCreateBatches() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	for chain, classQueues := range s.queues {
		// Check on-cadence queue
		onCadenceQueue := classQueues[ClassOnCadence]
		if len(onCadenceQueue) > 0 {
			// Find requests that are due
			var dueRequests []*ScheduledAnchorRequest
			var remaining []*ScheduledAnchorRequest

			for _, req := range onCadenceQueue {
				if req.ScheduledFor.Before(now) || req.ScheduledFor.Equal(now) {
					dueRequests = append(dueRequests, req)
				} else {
					remaining = append(remaining, req)
				}
			}

			// Create batch if we have enough or if batch is due
			if len(dueRequests) >= s.config.OnCadenceMinBatch ||
			   (len(dueRequests) > 0 && time.Since(dueRequests[0].RequestedAt) > s.config.OnCadenceInterval) {
				batch := s.createBatch(chain, ClassOnCadence, dueRequests)
				s.queues[chain][ClassOnCadence] = remaining

				// Add to pending batches
				s.batchMu.Lock()
				s.pendingBatches[batch.BatchID] = batch
				s.batchMu.Unlock()

				// Signal batch is ready
				select {
				case s.batchReadyChan <- batch:
				default:
				}
			}
		}

		// On-demand requests should be processed individually
		// but we can batch if multiple arrive at once
		onDemandQueue := classQueues[ClassOnDemand]
		if len(onDemandQueue) > 0 {
			// Process all pending on-demand requests as a batch
			batch := s.createBatch(chain, ClassOnDemand, onDemandQueue)
			s.queues[chain][ClassOnDemand] = make([]*ScheduledAnchorRequest, 0)

			s.batchMu.Lock()
			s.pendingBatches[batch.BatchID] = batch
			s.batchMu.Unlock()

			select {
			case s.batchReadyChan <- batch:
			default:
			}
		}
	}
}

// createBatch creates a new batch from requests
func (s *AnchorSchedulerService) createBatch(chain string, class AnchorClass, requests []*ScheduledAnchorRequest) *ScheduledAnchorBatch {
	batchID := uuid.New()

	// Update request statuses
	for _, req := range requests {
		req.Status = "batched"
		req.BatchID = &batchID
	}

	batch := &ScheduledAnchorBatch{
		BatchID:      batchID,
		TargetChain:  chain,
		AnchorClass:  class,
		Requests:     requests,
		ScheduledFor: time.Now(),
		Status:       "pending",
	}

	s.metrics.BatchesCreated++

	return batch
}

// processOnDemandRequest processes a single on-demand request immediately
func (s *AnchorSchedulerService) processOnDemandRequest(request *ScheduledAnchorRequest) {
	// Create a single-request batch
	s.mu.Lock()

	// Remove from queue if present
	queue := s.queues[request.TargetChain][ClassOnDemand]
	for i, req := range queue {
		if req.RequestID == request.RequestID {
			s.queues[request.TargetChain][ClassOnDemand] = append(queue[:i], queue[i+1:]...)
			break
		}
	}
	s.mu.Unlock()

	batch := s.createBatch(request.TargetChain, ClassOnDemand, []*ScheduledAnchorRequest{request})

	s.batchMu.Lock()
	s.pendingBatches[batch.BatchID] = batch
	s.batchMu.Unlock()

	select {
	case s.batchReadyChan <- batch:
	default:
	}
}

// =============================================================================
// Batch Processing Callbacks
// =============================================================================

// GetReadyBatches returns channel for receiving ready batches
func (s *AnchorSchedulerService) GetReadyBatches() <-chan *ScheduledAnchorBatch {
	return s.batchReadyChan
}

// MarkBatchCompleted marks a batch as successfully completed
func (s *AnchorSchedulerService) MarkBatchCompleted(batchID uuid.UUID, anchorTxHash string, blockNum int64) error {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	batch, ok := s.pendingBatches[batchID]
	if !ok {
		return fmt.Errorf("batch not found: %s", batchID)
	}

	now := time.Now()
	batch.Status = "completed"
	batch.AnchorTxHash = anchorTxHash
	batch.AnchorBlockNum = blockNum
	batch.ProcessedAt = &now

	// Update request statuses
	for _, req := range batch.Requests {
		req.Status = "completed"
	}

	s.metrics.BatchesCompleted++
	s.metrics.RequestsProcessed += int64(len(batch.Requests))
	s.metrics.LastBatchAt = now

	// Update average batch size
	total := s.metrics.BatchesCompleted
	s.metrics.AverageBatchSize = (s.metrics.AverageBatchSize*float64(total-1) + float64(len(batch.Requests))) / float64(total)

	delete(s.pendingBatches, batchID)

	return nil
}

// MarkBatchFailed marks a batch as failed
func (s *AnchorSchedulerService) MarkBatchFailed(batchID uuid.UUID, errorMsg string) error {
	s.batchMu.Lock()
	defer s.batchMu.Unlock()

	batch, ok := s.pendingBatches[batchID]
	if !ok {
		return fmt.Errorf("batch not found: %s", batchID)
	}

	batch.Status = "failed"
	batch.Error = errorMsg

	// Check if requests can be retried
	var retryRequests []*ScheduledAnchorRequest
	for _, req := range batch.Requests {
		req.RetryCount++
		if req.RetryCount < req.MaxRetries {
			req.Status = "pending"
			req.ScheduledFor = time.Now().Add(s.config.RetryDelay)
			retryRequests = append(retryRequests, req)
		} else {
			req.Status = "failed"
			req.Error = errorMsg
			s.metrics.RequestsFailed++
		}
	}

	// Re-queue retryable requests
	if len(retryRequests) > 0 {
		s.mu.Lock()
		s.queues[batch.TargetChain][batch.AnchorClass] = append(
			s.queues[batch.TargetChain][batch.AnchorClass],
			retryRequests...,
		)
		s.mu.Unlock()
	}

	s.metrics.BatchesFailed++
	delete(s.pendingBatches, batchID)

	return nil
}

// =============================================================================
// Query Methods
// =============================================================================

// GetRequest returns a request by ID
func (s *AnchorSchedulerService) GetRequest(requestID uuid.UUID) (*ScheduledAnchorRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, classQueues := range s.queues {
		for _, queue := range classQueues {
			for _, req := range queue {
				if req.RequestID == requestID {
					return req, nil
				}
			}
		}
	}

	// Check pending batches
	s.batchMu.RLock()
	defer s.batchMu.RUnlock()

	for _, batch := range s.pendingBatches {
		for _, req := range batch.Requests {
			if req.RequestID == requestID {
				return req, nil
			}
		}
	}

	return nil, fmt.Errorf("request not found: %s", requestID)
}

// GetBatch returns a batch by ID
func (s *AnchorSchedulerService) GetBatch(batchID uuid.UUID) (*ScheduledAnchorBatch, error) {
	s.batchMu.RLock()
	defer s.batchMu.RUnlock()

	batch, ok := s.pendingBatches[batchID]
	if !ok {
		return nil, fmt.Errorf("batch not found: %s", batchID)
	}

	return batch, nil
}

// GetQueueStatus returns the current queue status
func (s *AnchorSchedulerService) GetQueueStatus() map[string]map[AnchorClass]int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := make(map[string]map[AnchorClass]int)
	for chain, classQueues := range s.queues {
		status[chain] = make(map[AnchorClass]int)
		for class, queue := range classQueues {
			status[chain][class] = len(queue)
		}
	}

	return status
}

// GetMetrics returns scheduler metrics
func (s *AnchorSchedulerService) GetMetrics() SchedulerMetrics {
	return *s.metrics
}

// GetPricingTier returns the pricing tier for a class
func (s *AnchorSchedulerService) GetPricingTier(class AnchorClass) (PricingTier, error) {
	tier, ok := s.pricingTiers[class]
	if !ok {
		return PricingTier{}, fmt.Errorf("unknown class: %s", class)
	}
	return tier, nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// isChainSupported checks if a chain is supported
func (s *AnchorSchedulerService) isChainSupported(chain string) bool {
	for _, supported := range s.config.SupportedChains {
		if supported == chain {
			return true
		}
	}
	return false
}

// EstimateCost estimates the cost for an anchor request
func (s *AnchorSchedulerService) EstimateCost(class AnchorClass) (float64, error) {
	tier, ok := s.pricingTiers[class]
	if !ok {
		return 0, fmt.Errorf("unknown class: %s", class)
	}
	return tier.BaseCostUSD, nil
}
