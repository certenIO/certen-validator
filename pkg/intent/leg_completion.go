// Copyright 2025 Certen Protocol
//
// Leg Completion Handler - Tracks and coordinates multi-leg intent execution
// Manages leg dependencies and triggers dependent legs when their prerequisites complete.

package intent

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
)

// LegStatus represents the processing state of a leg
type LegStatus string

const (
	LegStatusPending    LegStatus = "pending"     // Waiting for dependencies or processing
	LegStatusReady      LegStatus = "ready"       // Dependencies satisfied, ready to execute
	LegStatusProcessing LegStatus = "processing"  // Currently being processed
	LegStatusBatched    LegStatus = "batched"     // Added to anchor batch
	LegStatusAnchored   LegStatus = "anchored"    // Anchor written to target chain
	LegStatusConfirmed  LegStatus = "confirmed"   // Anchor confirmed on target chain
	LegStatusExecuted   LegStatus = "executed"    // Transaction executed on target chain
	LegStatusCompleted  LegStatus = "completed"   // Full cycle complete
	LegStatusFailed     LegStatus = "failed"      // Execution failed
	LegStatusSkipped    LegStatus = "skipped"     // Skipped due to atomic rollback
)

// IntentStatus represents the overall status of a multi-leg intent
type MultiLegIntentStatus string

const (
	MultiLegStatusDiscovered      MultiLegIntentStatus = "discovered"
	MultiLegStatusProcessing      MultiLegIntentStatus = "processing"
	MultiLegStatusAnchoring       MultiLegIntentStatus = "anchoring"
	MultiLegStatusCompleted       MultiLegIntentStatus = "completed"
	MultiLegStatusPartialComplete MultiLegIntentStatus = "partial_complete"
	MultiLegStatusFailed          MultiLegIntentStatus = "failed"
	MultiLegStatusRolledBack      MultiLegIntentStatus = "rolled_back"
)

// LegRecord tracks the state of a single leg within an intent
type LegRecord struct {
	LegID           string       `json:"leg_id"`
	IntentID        string       `json:"intent_id"`
	LegIndex        int          `json:"leg_index"`
	LegExternalID   string       `json:"leg_external_id"`
	TargetChain     string       `json:"target_chain"`
	ChainID         int64        `json:"chain_id"`
	ChainKey        string       `json:"chain_key"`          // e.g., "ethereum:1"
	Role            string       `json:"role"`               // "source", "destination", "intermediate"
	SequenceOrder   int          `json:"sequence_order"`
	DependsOnLegs   []string     `json:"depends_on_legs"`
	Status          LegStatus    `json:"status"`
	ExecutionTxHash string       `json:"execution_tx_hash,omitempty"`
	ExecutionBlock  uint64       `json:"execution_block,omitempty"`
	ExecutionError  string       `json:"execution_error,omitempty"`
	BatchID         string       `json:"batch_id,omitempty"`
	AnchorID        string       `json:"anchor_id,omitempty"`
	ProofID         string       `json:"proof_id,omitempty"`
	RetryCount      int          `json:"retry_count"`
	MaxRetries      int          `json:"max_retries"`
	CreatedAt       time.Time    `json:"created_at"`
	CompletedAt     *time.Time   `json:"completed_at,omitempty"`
}

// ChainGroup represents a group of legs targeting the same chain
type ChainGroup struct {
	ChainKey     string       `json:"chain_key"`     // e.g., "ethereum:1"
	TargetChain  string       `json:"target_chain"`
	ChainID      int64        `json:"chain_id"`
	LegIDs       []string     `json:"leg_ids"`
	Status       LegStatus    `json:"status"`
	BatchID      string       `json:"batch_id,omitempty"`
	AnchorID     string       `json:"anchor_id,omitempty"`
	AnchorTxHash string       `json:"anchor_tx_hash,omitempty"`
}

// MultiLegIntentRecord tracks the overall state of a multi-leg intent
type MultiLegIntentRecord struct {
	IntentID         string               `json:"intent_id"`
	OperationID      string               `json:"operation_id"`
	UserID           string               `json:"user_id,omitempty"`
	OrganizationADI  string               `json:"organization_adi,omitempty"`
	AccumulateTxHash string               `json:"accumulate_tx_hash"`
	LegCount         int                  `json:"leg_count"`
	ExecutionMode    string               `json:"execution_mode"` // "sequential", "parallel", "atomic"
	ProofClass       string               `json:"proof_class"`    // "on_demand", "on_cadence"
	Status           MultiLegIntentStatus `json:"status"`
	CurrentLegIndex  int                  `json:"current_leg_index"`
	LegsCompleted    int                  `json:"legs_completed"`
	LegsFailed       int                  `json:"legs_failed"`
	LegsPending      int                  `json:"legs_pending"`
	ChainGroups      map[string]*ChainGroup `json:"chain_groups"` // keyed by chain_key
	Legs             map[string]*LegRecord  `json:"legs"`         // keyed by leg_external_id
	CreatedAt        time.Time            `json:"created_at"`
	CompletedAt      *time.Time           `json:"completed_at,omitempty"`
	ErrorMessage     string               `json:"error_message,omitempty"`
}

// LegCompletionHandler manages leg execution coordination for multi-leg intents
type LegCompletionHandler struct {
	logger     *log.Logger

	// In-memory tracking (can be extended to use PostgreSQL via LegStore interface)
	intents    map[string]*MultiLegIntentRecord // keyed by intent_id
	legs       map[string]*LegRecord            // keyed by leg_id (UUID)
	legsByIntent map[string][]string            // intent_id -> []leg_id
	mu         sync.RWMutex

	// Callback for triggering leg execution
	onLegReady func(ctx context.Context, intent *MultiLegIntentRecord, leg *LegRecord) error
}

// LegCompletionHandlerConfig contains configuration for the handler
type LegCompletionHandlerConfig struct {
	OnLegReady func(ctx context.Context, intent *MultiLegIntentRecord, leg *LegRecord) error
}

// NewLegCompletionHandler creates a new leg completion handler
func NewLegCompletionHandler(config *LegCompletionHandlerConfig) *LegCompletionHandler {
	h := &LegCompletionHandler{
		logger:       log.New(log.Writer(), "[LEG-COMPLETION] ", log.LstdFlags),
		intents:      make(map[string]*MultiLegIntentRecord),
		legs:         make(map[string]*LegRecord),
		legsByIntent: make(map[string][]string),
	}
	if config != nil && config.OnLegReady != nil {
		h.onLegReady = config.OnLegReady
	}
	return h
}

// RegisterIntent registers a new multi-leg intent and creates leg records
func (h *LegCompletionHandler) RegisterIntent(intent *consensus.CertenIntent, blockHeight uint64) (*MultiLegIntentRecord, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check if already registered
	if existing, ok := h.intents[intent.IntentID]; ok {
		return existing, nil
	}

	// Parse cross-chain data for legs
	ccEnvelope, err := intent.ParseCrossChain()
	if err != nil {
		return nil, fmt.Errorf("parse cross-chain data: %w", err)
	}

	// Get execution mode
	execMode, err := intent.GetExecutionMode()
	if err != nil {
		execMode = "sequential" // Default
	}

	// Get proof class
	proofClass, err := intent.GetProofClass()
	if err != nil {
		proofClass = "on_cadence" // Default
	}

	// Compute operation ID
	operationID, err := intent.OperationID()
	if err != nil {
		return nil, fmt.Errorf("compute operation ID: %w", err)
	}

	// Create intent record
	record := &MultiLegIntentRecord{
		IntentID:         intent.IntentID,
		OperationID:      operationID,
		UserID:           intent.UserID,
		OrganizationADI:  intent.OrganizationADI,
		AccumulateTxHash: intent.TransactionHash,
		LegCount:         len(ccEnvelope.Legs),
		ExecutionMode:    execMode,
		ProofClass:       proofClass,
		Status:           MultiLegStatusDiscovered,
		CurrentLegIndex:  0,
		LegsCompleted:    0,
		LegsFailed:       0,
		LegsPending:      len(ccEnvelope.Legs),
		ChainGroups:      make(map[string]*ChainGroup),
		Legs:             make(map[string]*LegRecord),
		CreatedAt:        time.Now(),
	}

	// Create leg records and group by chain
	for i, leg := range ccEnvelope.Legs {
		legID := fmt.Sprintf("%s-leg-%d", intent.IntentID, i)
		chainKey := leg.ChainKey()

		legRecord := &LegRecord{
			LegID:         legID,
			IntentID:      intent.IntentID,
			LegIndex:      i,
			LegExternalID: leg.LegID,
			TargetChain:   leg.Chain,
			ChainID:       leg.ChainID,
			ChainKey:      chainKey,
			Role:          leg.Role,
			SequenceOrder: leg.SequenceOrder,
			DependsOnLegs: leg.DependsOnLegs,
			Status:        LegStatusPending,
			MaxRetries:    leg.MaxRetries,
			CreatedAt:     time.Now(),
		}
		if legRecord.MaxRetries == 0 {
			legRecord.MaxRetries = 3 // Default
		}

		// Store leg record
		h.legs[legID] = legRecord
		h.legsByIntent[intent.IntentID] = append(h.legsByIntent[intent.IntentID], legID)
		record.Legs[leg.LegID] = legRecord

		// Add to chain group
		if group, ok := record.ChainGroups[chainKey]; ok {
			group.LegIDs = append(group.LegIDs, legID)
		} else {
			record.ChainGroups[chainKey] = &ChainGroup{
				ChainKey:    chainKey,
				TargetChain: leg.Chain,
				ChainID:     leg.ChainID,
				LegIDs:      []string{legID},
				Status:      LegStatusPending,
			}
		}
	}

	h.intents[intent.IntentID] = record

	h.logger.Printf("Registered multi-leg intent %s with %d legs across %d chains (mode: %s)",
		intent.IntentID, len(ccEnvelope.Legs), len(record.ChainGroups), execMode)

	return record, nil
}

// OnLegCompleted handles completion of a leg and triggers dependent legs
func (h *LegCompletionHandler) OnLegCompleted(ctx context.Context, legID string, txHash string, block uint64) error {
	h.mu.Lock()

	leg, ok := h.legs[legID]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("leg not found: %s", legID)
	}

	intent, ok := h.intents[leg.IntentID]
	if !ok {
		h.mu.Unlock()
		return fmt.Errorf("intent not found for leg: %s", leg.IntentID)
	}

	// Update leg status
	now := time.Now()
	leg.Status = LegStatusCompleted
	leg.ExecutionTxHash = txHash
	leg.ExecutionBlock = block
	leg.CompletedAt = &now

	// Update intent counters
	intent.LegsCompleted++
	intent.LegsPending--

	h.logger.Printf("Leg %s completed (intent: %s, tx: %s)", legID, leg.IntentID, txHash)

	// Find dependent legs that might now be ready
	var readyLegs []*LegRecord
	for _, otherLegID := range h.legsByIntent[leg.IntentID] {
		otherLeg := h.legs[otherLegID]
		if otherLeg.Status != LegStatusPending {
			continue
		}

		// Check if this leg depends on the completed leg
		dependsOnCompleted := false
		for _, depLegID := range otherLeg.DependsOnLegs {
			if depLegID == leg.LegExternalID {
				dependsOnCompleted = true
				break
			}
		}

		if dependsOnCompleted && h.checkAllDependenciesSatisfied(otherLeg, intent) {
			otherLeg.Status = LegStatusReady
			readyLegs = append(readyLegs, otherLeg)
			h.logger.Printf("Leg %s now ready (dependencies satisfied)", otherLeg.LegID)
		}
	}

	// Check if intent is complete
	h.updateIntentStatus(intent)

	h.mu.Unlock()

	// Trigger ready legs outside the lock
	for _, readyLeg := range readyLegs {
		if h.onLegReady != nil {
			if err := h.onLegReady(ctx, intent, readyLeg); err != nil {
				h.logger.Printf("Failed to trigger ready leg %s: %v", readyLeg.LegID, err)
			}
		}
	}

	return nil
}

// OnLegFailed handles failure of a leg
func (h *LegCompletionHandler) OnLegFailed(ctx context.Context, legID string, errorMsg string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	leg, ok := h.legs[legID]
	if !ok {
		return fmt.Errorf("leg not found: %s", legID)
	}

	intent, ok := h.intents[leg.IntentID]
	if !ok {
		return fmt.Errorf("intent not found for leg: %s", leg.IntentID)
	}

	// Check if retry is possible
	if leg.RetryCount < leg.MaxRetries {
		leg.RetryCount++
		leg.Status = LegStatusPending
		leg.ExecutionError = errorMsg
		h.logger.Printf("Leg %s failed, will retry (%d/%d): %s", legID, leg.RetryCount, leg.MaxRetries, errorMsg)
		return nil
	}

	// Max retries exceeded
	leg.Status = LegStatusFailed
	leg.ExecutionError = errorMsg
	intent.LegsFailed++
	intent.LegsPending--

	h.logger.Printf("Leg %s failed permanently after %d retries: %s", legID, leg.RetryCount, errorMsg)

	// Handle atomic mode rollback
	if intent.ExecutionMode == "atomic" {
		h.rollbackIntent(intent)
	} else {
		h.updateIntentStatus(intent)
	}

	return nil
}

// OnLegAnchored updates leg status when it's anchored to target chain
func (h *LegCompletionHandler) OnLegAnchored(legID string, batchID string, anchorID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	leg, ok := h.legs[legID]
	if !ok {
		return fmt.Errorf("leg not found: %s", legID)
	}

	leg.Status = LegStatusAnchored
	leg.BatchID = batchID
	leg.AnchorID = anchorID

	h.logger.Printf("Leg %s anchored (batch: %s, anchor: %s)", legID, batchID, anchorID)

	return nil
}

// OnChainGroupAnchored updates all legs in a chain group when anchored
func (h *LegCompletionHandler) OnChainGroupAnchored(intentID string, chainKey string, batchID string, anchorID string, anchorTxHash string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	intent, ok := h.intents[intentID]
	if !ok {
		return fmt.Errorf("intent not found: %s", intentID)
	}

	group, ok := intent.ChainGroups[chainKey]
	if !ok {
		return fmt.Errorf("chain group not found: %s", chainKey)
	}

	group.Status = LegStatusAnchored
	group.BatchID = batchID
	group.AnchorID = anchorID
	group.AnchorTxHash = anchorTxHash

	// Update all legs in the group
	for _, legID := range group.LegIDs {
		if leg, ok := h.legs[legID]; ok {
			leg.Status = LegStatusAnchored
			leg.BatchID = batchID
			leg.AnchorID = anchorID
		}
	}

	h.logger.Printf("Chain group %s anchored for intent %s (batch: %s, tx: %s)",
		chainKey, intentID, batchID, anchorTxHash)

	return nil
}

// GetIntent returns the intent record
func (h *LegCompletionHandler) GetIntent(intentID string) (*MultiLegIntentRecord, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	intent, ok := h.intents[intentID]
	return intent, ok
}

// GetLeg returns a leg record
func (h *LegCompletionHandler) GetLeg(legID string) (*LegRecord, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	leg, ok := h.legs[legID]
	return leg, ok
}

// GetReadyLegs returns all legs that are ready for execution
func (h *LegCompletionHandler) GetReadyLegs(intentID string) []*LegRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()

	intent, ok := h.intents[intentID]
	if !ok {
		return nil
	}

	var ready []*LegRecord
	for _, legID := range h.legsByIntent[intentID] {
		leg := h.legs[legID]
		if leg.Status == LegStatusReady {
			ready = append(ready, leg)
		} else if leg.Status == LegStatusPending && len(leg.DependsOnLegs) == 0 {
			// Leg with no dependencies is implicitly ready
			if h.checkAllDependenciesSatisfied(leg, intent) {
				ready = append(ready, leg)
			}
		}
	}

	return ready
}

// GetLegsForChain returns all legs for a specific chain
func (h *LegCompletionHandler) GetLegsForChain(intentID string, chainKey string) []*LegRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()

	intent, ok := h.intents[intentID]
	if !ok {
		return nil
	}

	group, ok := intent.ChainGroups[chainKey]
	if !ok {
		return nil
	}

	var legs []*LegRecord
	for _, legID := range group.LegIDs {
		if leg, ok := h.legs[legID]; ok {
			legs = append(legs, leg)
		}
	}

	return legs
}

// GetChainGroups returns all chain groups for an intent
func (h *LegCompletionHandler) GetChainGroups(intentID string) map[string]*ChainGroup {
	h.mu.RLock()
	defer h.mu.RUnlock()

	intent, ok := h.intents[intentID]
	if !ok {
		return nil
	}

	return intent.ChainGroups
}

// Internal helper methods

// checkAllDependenciesSatisfied checks if all dependencies for a leg are satisfied
func (h *LegCompletionHandler) checkAllDependenciesSatisfied(leg *LegRecord, intent *MultiLegIntentRecord) bool {
	for _, depLegID := range leg.DependsOnLegs {
		depLeg, ok := intent.Legs[depLegID]
		if !ok {
			// Dependency not found - can't be satisfied
			return false
		}
		if depLeg.Status != LegStatusCompleted {
			return false
		}
	}
	return true
}

// updateIntentStatus updates the overall intent status based on leg statuses
func (h *LegCompletionHandler) updateIntentStatus(intent *MultiLegIntentRecord) {
	if intent.LegsCompleted == intent.LegCount {
		intent.Status = MultiLegStatusCompleted
		now := time.Now()
		intent.CompletedAt = &now
		h.logger.Printf("Intent %s completed (all %d legs successful)", intent.IntentID, intent.LegCount)
	} else if intent.LegsFailed > 0 && intent.LegsPending == 0 {
		intent.Status = MultiLegStatusPartialComplete
		now := time.Now()
		intent.CompletedAt = &now
		h.logger.Printf("Intent %s partially complete (%d completed, %d failed)",
			intent.IntentID, intent.LegsCompleted, intent.LegsFailed)
	} else if intent.LegsFailed == intent.LegCount {
		intent.Status = MultiLegStatusFailed
		now := time.Now()
		intent.CompletedAt = &now
		h.logger.Printf("Intent %s failed (all %d legs failed)", intent.IntentID, intent.LegCount)
	} else if intent.LegsCompleted > 0 || intent.LegsFailed > 0 {
		intent.Status = MultiLegStatusProcessing
	}
}

// rollbackIntent marks all pending legs as skipped for atomic rollback
func (h *LegCompletionHandler) rollbackIntent(intent *MultiLegIntentRecord) {
	for _, legID := range h.legsByIntent[intent.IntentID] {
		leg := h.legs[legID]
		if leg.Status == LegStatusPending || leg.Status == LegStatusReady || leg.Status == LegStatusProcessing {
			leg.Status = LegStatusSkipped
			intent.LegsPending--
		}
	}

	intent.Status = MultiLegStatusRolledBack
	now := time.Now()
	intent.CompletedAt = &now
	h.logger.Printf("Intent %s rolled back (atomic mode, %d legs skipped)", intent.IntentID, intent.LegsPending)
}

// GetMetrics returns handler metrics
func (h *LegCompletionHandler) GetMetrics() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var completed, failed, pending int
	for _, intent := range h.intents {
		switch intent.Status {
		case MultiLegStatusCompleted:
			completed++
		case MultiLegStatusFailed, MultiLegStatusRolledBack:
			failed++
		default:
			pending++
		}
	}

	return map[string]interface{}{
		"total_intents":     len(h.intents),
		"total_legs":        len(h.legs),
		"intents_completed": completed,
		"intents_failed":    failed,
		"intents_pending":   pending,
	}
}
