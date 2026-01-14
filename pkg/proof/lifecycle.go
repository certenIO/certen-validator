// Copyright 2025 Certen Protocol
//
// ProofLifecycleManager - Manages proof state transitions and custody chain
//
// Lifecycle states per Whitepaper:
// - pending: Proof created, awaiting batch inclusion
// - batched: Included in anchor batch, awaiting external chain confirmation
// - anchored: Anchor confirmed on external chain
// - attested: Sufficient validator attestations (2/3+1 quorum)
// - verified: Full verification complete
// - failed: Verification or processing failed

package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/google/uuid"
)

// =============================================================================
// Lifecycle States
// =============================================================================

// ProofState represents the current lifecycle state of a proof
type ProofState string

const (
	StatePending  ProofState = "pending"
	StateBatched  ProofState = "batched"
	StateAnchored ProofState = "anchored"
	StateAttested ProofState = "attested"
	StateVerified ProofState = "verified"
	StateFailed   ProofState = "failed"
)

// StateTransition represents a valid state transition
type StateTransition struct {
	From ProofState
	To   ProofState
}

// ValidTransitions defines all valid state transitions
var ValidTransitions = []StateTransition{
	{StatePending, StateBatched},
	{StatePending, StateFailed},
	{StateBatched, StateAnchored},
	{StateBatched, StateFailed},
	{StateAnchored, StateAttested},
	{StateAnchored, StateFailed},
	{StateAttested, StateVerified},
	{StateAttested, StateFailed},
}

// =============================================================================
// ProofLifecycleManager
// =============================================================================

// ProofLifecycleManager manages proof state transitions and custody chain
type ProofLifecycleManager struct {
	repo           *database.ProofArtifactRepository
	validatorID    string
	totalValidators int

	// State change listeners
	listeners []StateChangeListener
	mu        sync.RWMutex

	// Metrics
	metrics *LifecycleMetrics
}

// StateChangeListener is called when proof state changes
type StateChangeListener func(proofID uuid.UUID, from, to ProofState, details map[string]interface{})

// LifecycleMetrics tracks lifecycle manager metrics
type LifecycleMetrics struct {
	TotalTransitions   int64
	SuccessTransitions int64
	FailedTransitions  int64
	CustodyEvents      int64
	LastTransitionAt   time.Time
}

// LifecycleConfig contains lifecycle manager configuration
type LifecycleConfig struct {
	ValidatorID     string
	TotalValidators int
	QuorumThreshold float64 // Default 2/3+1
}

// NewProofLifecycleManager creates a new lifecycle manager
func NewProofLifecycleManager(repo *database.ProofArtifactRepository, config *LifecycleConfig) (*ProofLifecycleManager, error) {
	if repo == nil {
		return nil, fmt.Errorf("repository cannot be nil")
	}
	if config == nil {
		config = &LifecycleConfig{
			ValidatorID:     "default-validator",
			TotalValidators: 4,
			QuorumThreshold: 2.0 / 3.0,
		}
	}

	return &ProofLifecycleManager{
		repo:            repo,
		validatorID:     config.ValidatorID,
		totalValidators: config.TotalValidators,
		listeners:       make([]StateChangeListener, 0),
		metrics:         &LifecycleMetrics{},
	}, nil
}

// =============================================================================
// State Transition Methods
// =============================================================================

// TransitionState transitions a proof to a new state with validation
func (m *ProofLifecycleManager) TransitionState(ctx context.Context, proofID uuid.UUID, newState ProofState, details map[string]interface{}) error {
	// Get current proof state
	proof, err := m.repo.GetProofByID(ctx, proofID)
	if err != nil {
		return fmt.Errorf("get proof: %w", err)
	}
	if proof == nil {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	currentState := ProofState(proof.Status)

	// Validate transition
	if !m.isValidTransition(currentState, newState) {
		return fmt.Errorf("invalid state transition: %s -> %s", currentState, newState)
	}

	// Record custody chain event
	if err := m.recordCustodyEvent(ctx, proofID, string(newState), "state_transition", details); err != nil {
		return fmt.Errorf("record custody event: %w", err)
	}

	// Update proof status based on state
	switch newState {
	case StateAnchored:
		anchorID, _ := details["anchor_id"].(uuid.UUID)
		anchorTxHash, _ := details["anchor_tx_hash"].(string)
		anchorBlockNum, _ := details["anchor_block_number"].(int64)
		anchorChain, _ := details["anchor_chain"].(string)
		if err := m.repo.UpdateProofAnchored(ctx, proofID, anchorID, anchorTxHash, anchorBlockNum, anchorChain); err != nil {
			return fmt.Errorf("update proof anchored: %w", err)
		}

	case StateVerified:
		if err := m.repo.UpdateProofVerified(ctx, proofID, true); err != nil {
			return fmt.Errorf("update proof verified: %w", err)
		}

	case StateFailed:
		if err := m.repo.UpdateProofVerified(ctx, proofID, false); err != nil {
			return fmt.Errorf("update proof failed: %w", err)
		}
	}

	// Notify listeners
	m.notifyListeners(proofID, currentState, newState, details)

	// Update metrics
	m.mu.Lock()
	m.metrics.TotalTransitions++
	if newState != StateFailed {
		m.metrics.SuccessTransitions++
	} else {
		m.metrics.FailedTransitions++
	}
	m.metrics.LastTransitionAt = time.Now()
	m.mu.Unlock()

	return nil
}

// isValidTransition checks if a state transition is allowed
func (m *ProofLifecycleManager) isValidTransition(from, to ProofState) bool {
	for _, t := range ValidTransitions {
		if t.From == from && t.To == to {
			return true
		}
	}
	return false
}

// =============================================================================
// Convenience Methods for State Transitions
// =============================================================================

// MarkBatched marks a proof as included in a batch
func (m *ProofLifecycleManager) MarkBatched(ctx context.Context, proofID uuid.UUID, batchID uuid.UUID, batchPosition int) error {
	return m.TransitionState(ctx, proofID, StateBatched, map[string]interface{}{
		"batch_id":       batchID,
		"batch_position": batchPosition,
	})
}

// MarkAnchored marks a proof as anchored on external chain
func (m *ProofLifecycleManager) MarkAnchored(ctx context.Context, proofID uuid.UUID, anchorID uuid.UUID, anchorTxHash string, anchorBlockNum int64, anchorChain string) error {
	return m.TransitionState(ctx, proofID, StateAnchored, map[string]interface{}{
		"anchor_id":           anchorID,
		"anchor_tx_hash":      anchorTxHash,
		"anchor_block_number": anchorBlockNum,
		"anchor_chain":        anchorChain,
	})
}

// MarkAttested marks a proof as having sufficient attestations
func (m *ProofLifecycleManager) MarkAttested(ctx context.Context, proofID uuid.UUID, attestationCount int) error {
	return m.TransitionState(ctx, proofID, StateAttested, map[string]interface{}{
		"attestation_count":   attestationCount,
		"required_quorum":     m.calculateQuorum(),
	})
}

// MarkVerified marks a proof as fully verified
func (m *ProofLifecycleManager) MarkVerified(ctx context.Context, proofID uuid.UUID, verificationDetails map[string]interface{}) error {
	return m.TransitionState(ctx, proofID, StateVerified, verificationDetails)
}

// MarkFailed marks a proof as failed
func (m *ProofLifecycleManager) MarkFailed(ctx context.Context, proofID uuid.UUID, reason string, errorDetails map[string]interface{}) error {
	details := map[string]interface{}{
		"reason": reason,
	}
	for k, v := range errorDetails {
		details[k] = v
	}
	return m.TransitionState(ctx, proofID, StateFailed, details)
}

// =============================================================================
// Custody Chain Management
// =============================================================================

// recordCustodyEvent creates a new custody chain event with hash linking
func (m *ProofLifecycleManager) recordCustodyEvent(ctx context.Context, proofID uuid.UUID, eventType, actorType string, details map[string]interface{}) error {
	// Get previous custody hash
	previousHash, err := m.repo.GetLatestCustodyHash(ctx, proofID)
	if err != nil {
		return fmt.Errorf("get latest custody hash: %w", err)
	}

	// Serialize event details
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("marshal event details: %w", err)
	}

	// Compute new hash: SHA256(previous_hash + event_type + details + timestamp)
	timestamp := time.Now()
	hashInput := fmt.Sprintf("%s%s%s%s",
		hex.EncodeToString(previousHash),
		eventType,
		string(detailsJSON),
		timestamp.Format(time.RFC3339Nano),
	)
	newHash := sha256.Sum256([]byte(hashInput))

	// Create custody chain event
	actorID := m.validatorID
	event := &database.NewCustodyChainEvent{
		ProofID:      proofID,
		EventType:    eventType,
		ActorType:    actorType,
		ActorID:      &actorID,
		PreviousHash: previousHash,
		CurrentHash:  newHash[:],
		EventDetails: detailsJSON,
	}

	_, err = m.repo.CreateCustodyChainEvent(ctx, event)
	if err != nil {
		return fmt.Errorf("create custody chain event: %w", err)
	}

	// Update metrics
	m.mu.Lock()
	m.metrics.CustodyEvents++
	m.mu.Unlock()

	return nil
}

// RecordRetrieval records when a proof is retrieved by an external party
func (m *ProofLifecycleManager) RecordRetrieval(ctx context.Context, proofID uuid.UUID, clientID, clientIP string) error {
	return m.recordCustodyEvent(ctx, proofID, "retrieved", "external", map[string]interface{}{
		"client_id": clientID,
		"client_ip": clientIP,
		"timestamp": time.Now(),
	})
}

// RecordBundleCreation records when a bundle is created for a proof
func (m *ProofLifecycleManager) RecordBundleCreation(ctx context.Context, proofID uuid.UUID, bundleID uuid.UUID, bundleHash string) error {
	return m.recordCustodyEvent(ctx, proofID, "bundle_created", "system", map[string]interface{}{
		"bundle_id":   bundleID,
		"bundle_hash": bundleHash,
	})
}

// RecordBundleDownload records when a bundle is downloaded
func (m *ProofLifecycleManager) RecordBundleDownload(ctx context.Context, proofID uuid.UUID, bundleID uuid.UUID, clientID, clientIP string) error {
	return m.recordCustodyEvent(ctx, proofID, "bundle_downloaded", "external", map[string]interface{}{
		"bundle_id": bundleID,
		"client_id": clientID,
		"client_ip": clientIP,
	})
}

// =============================================================================
// Quorum Calculation
// =============================================================================

// calculateQuorum calculates the required quorum (2/3+1)
func (m *ProofLifecycleManager) calculateQuorum() int {
	return (m.totalValidators * 2 / 3) + 1
}

// CheckQuorum checks if a proof has sufficient attestations
func (m *ProofLifecycleManager) CheckQuorum(ctx context.Context, proofID uuid.UUID) (bool, int, error) {
	attestations, err := m.repo.GetProofAttestationsByProof(ctx, proofID)
	if err != nil {
		return false, 0, fmt.Errorf("get attestations: %w", err)
	}

	// Count valid attestations
	validCount := 0
	for _, att := range attestations {
		if att.SignatureValid {
			validCount++
		}
	}

	required := m.calculateQuorum()
	return validCount >= required, validCount, nil
}

// =============================================================================
// Listener Management
// =============================================================================

// AddStateChangeListener adds a listener for state changes
func (m *ProofLifecycleManager) AddStateChangeListener(listener StateChangeListener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// notifyListeners notifies all registered listeners of a state change
func (m *ProofLifecycleManager) notifyListeners(proofID uuid.UUID, from, to ProofState, details map[string]interface{}) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, listener := range m.listeners {
		go listener(proofID, from, to, details)
	}
}

// =============================================================================
// Query Methods
// =============================================================================

// GetProofState returns the current state of a proof
func (m *ProofLifecycleManager) GetProofState(ctx context.Context, proofID uuid.UUID) (ProofState, error) {
	proof, err := m.repo.GetProofByID(ctx, proofID)
	if err != nil {
		return "", fmt.Errorf("get proof: %w", err)
	}
	if proof == nil {
		return "", fmt.Errorf("proof not found: %s", proofID)
	}

	return ProofState(proof.Status), nil
}

// GetCustodyChain returns the complete custody chain for a proof
func (m *ProofLifecycleManager) GetCustodyChain(ctx context.Context, proofID uuid.UUID) ([]database.CustodyChainEvent, error) {
	return m.repo.GetCustodyChainEvents(ctx, proofID)
}

// VerifyCustodyChain verifies the integrity of the custody chain
func (m *ProofLifecycleManager) VerifyCustodyChain(ctx context.Context, proofID uuid.UUID) (bool, error) {
	events, err := m.repo.GetCustodyChainEvents(ctx, proofID)
	if err != nil {
		return false, err
	}

	if len(events) == 0 {
		return true, nil // Empty chain is valid
	}

	// Verify hash chain
	for i := 1; i < len(events); i++ {
		// Each event's previous_hash should match the previous event's current_hash
		if !bytesEqualDB(events[i].PreviousHash, events[i-1].CurrentHash) {
			return false, nil
		}
	}

	return true, nil
}

// bytesEqualDB compares two byte slices for equality
func bytesEqualDB(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// =============================================================================
// Metrics
// =============================================================================

// GetMetrics returns lifecycle manager metrics
func (m *ProofLifecycleManager) GetMetrics() LifecycleMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m.metrics
}

// =============================================================================
// Batch Processing Helpers
// =============================================================================

// ProcessBatchAnchored processes anchor confirmation for a batch of proofs
func (m *ProofLifecycleManager) ProcessBatchAnchored(ctx context.Context, batchID uuid.UUID, anchorID uuid.UUID, anchorTxHash string, anchorBlockNum int64, anchorChain string) error {
	// Get all proofs in the batch
	proofs, err := m.repo.GetProofsByBatch(ctx, batchID)
	if err != nil {
		return fmt.Errorf("get proofs by batch: %w", err)
	}

	// Transition each proof to anchored state
	for _, proof := range proofs {
		if err := m.MarkAnchored(ctx, proof.ProofID, anchorID, anchorTxHash, anchorBlockNum, anchorChain); err != nil {
			// Log error but continue with other proofs
			continue
		}
	}

	return nil
}

// CheckBatchQuorum checks if all proofs in a batch have quorum
func (m *ProofLifecycleManager) CheckBatchQuorum(ctx context.Context, batchID uuid.UUID) (bool, error) {
	proofs, err := m.repo.GetProofsByBatch(ctx, batchID)
	if err != nil {
		return false, err
	}

	for _, proof := range proofs {
		hasQuorum, _, err := m.CheckQuorum(ctx, proof.ProofID)
		if err != nil {
			return false, err
		}
		if !hasQuorum {
			return false, nil
		}
	}

	return true, nil
}
