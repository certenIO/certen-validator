// Copyright 2025 Certen Protocol
//
// Firestore Sync Service
// Syncs proof cycle progress to Firestore for real-time UI updates

package firestore

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
)

// SyncService handles syncing proof cycle events to Firestore
type SyncService struct {
	client      *Client
	validatorID string
	logger      *log.Logger

	// Intent mapping cache (accumTxHash -> userID, intentID)
	intentCache     map[string]intentMapping
	intentCacheMu   sync.RWMutex
	intentCacheTTL  time.Duration

	// Audit trail hash chain state per user
	auditChains   map[string]string // userID -> latest entry hash
	auditChainsMu sync.RWMutex
}

// intentMapping caches the mapping from Accumulate tx hash to user intent
type intentMapping struct {
	UserID    string
	IntentID  string
	CachedAt  time.Time
}

// SyncServiceConfig holds configuration for the sync service
type SyncServiceConfig struct {
	Client         *Client
	ValidatorID    string
	Logger         *log.Logger
	IntentCacheTTL time.Duration // How long to cache intent mappings
}

// NewSyncService creates a new Firestore sync service
func NewSyncService(cfg *SyncServiceConfig) (*SyncService, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	if cfg.Client == nil {
		return nil, fmt.Errorf("Firestore client is required")
	}

	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[FirestoreSync] ", log.LstdFlags)
	}

	if cfg.IntentCacheTTL == 0 {
		cfg.IntentCacheTTL = 5 * time.Minute
	}

	return &SyncService{
		client:         cfg.Client,
		validatorID:    cfg.ValidatorID,
		logger:         cfg.Logger,
		intentCache:    make(map[string]intentMapping),
		intentCacheTTL: cfg.IntentCacheTTL,
		auditChains:    make(map[string]string),
	}, nil
}

// IsEnabled returns whether the sync service is enabled
func (s *SyncService) IsEnabled() bool {
	return s.client != nil && s.client.IsEnabled()
}

// ========================================================================================
// Stage 3: Intent Discovery
// ========================================================================================

// OnIntentDiscovered is called when the validator discovers an intent on Accumulate
func (s *SyncService) OnIntentDiscovered(ctx context.Context, data *IntentDiscoveredEvent) error {
	if !s.IsEnabled() {
		return nil
	}

	// Try to find the user/intent for this accumulate transaction
	userID, intentID, err := s.resolveIntent(ctx, data.AccumTxHash)
	if err != nil {
		s.logger.Printf("Warning: could not resolve intent for %s: %v", data.AccumTxHash, err)
		// Continue anyway - we'll create the snapshot with empty user/intent
		// This allows the data to be linked later when the intent is found
	}

	if userID == "" || intentID == "" {
		s.logger.Printf("Intent not found in Firestore for accumTxHash=%s, skipping Firestore sync", data.AccumTxHash)
		return nil
	}

	// Create stage 3 status snapshot
	snapshot := &StatusSnapshot{
		Stage:       StageIntentDiscovery,
		StageName:   StageNames[StageIntentDiscovery],
		Status:      StatusCompleted,
		Timestamp:   time.Now(),
		Source:      "validator",
		ValidatorID: s.validatorID,
		Data: map[string]interface{}{
			"accumTxHash":   data.AccumTxHash,
			"accountUrl":    data.AccountURL,
			"blockHeight":   data.BlockHeight,
			"discoveryTime": data.DiscoveryTime.Format(time.RFC3339),
			"proofClass":    data.ProofClass,
			"intentType":    data.IntentType,
			"targetChain":   data.TargetChain,
		},
	}

	// Get previous snapshot for chain integrity
	if prev, err := s.client.GetLatestStatusSnapshot(ctx, userID, intentID); err == nil && prev != nil {
		snapshot.PreviousSnapshotID = prev.SnapshotID
	}

	// Compute snapshot hash
	snapshot.SnapshotHash = s.computeSnapshotHash(snapshot)

	// Create the snapshot
	if err := s.client.CreateStatusSnapshot(ctx, userID, intentID, snapshot); err != nil {
		return fmt.Errorf("failed to create intent discovery snapshot: %w", err)
	}

	// Update intent status
	stage := int(StageIntentDiscovery)
	now := time.Now()
	if err := s.client.UpdateTransactionIntent(ctx, userID, intentID, &TransactionIntentUpdate{
		Status:       "processing",
		CurrentStage: &stage,
		LastUpdated:  &now,
	}); err != nil {
		s.logger.Printf("Warning: failed to update intent status: %v", err)
	}

	// Create audit entry
	if err := s.createAuditEntry(ctx, userID, intentID, data.AccumTxHash, "discovered",
		"Intent discovered by validator", map[string]interface{}{
			"blockHeight": data.BlockHeight,
			"proofClass":  data.ProofClass,
		}); err != nil {
		s.logger.Printf("Warning: failed to create audit entry: %v", err)
	}

	return nil
}

// IntentDiscoveredEvent contains data for the intent discovery event
type IntentDiscoveredEvent struct {
	AccumTxHash   string
	AccountURL    string
	BlockHeight   int64
	DiscoveryTime time.Time
	ProofClass    string // "on_cadence" or "on_demand"
	IntentType    string
	TargetChain   string
}

// ========================================================================================
// Stage 4: Proof Generation
// ========================================================================================

// OnProofGenerated is called when proofs are generated for a transaction
func (s *SyncService) OnProofGenerated(ctx context.Context, data *ProofGeneratedEvent) error {
	if !s.IsEnabled() {
		return nil
	}

	userID, intentID, err := s.resolveIntent(ctx, data.AccumTxHash)
	if err != nil || userID == "" || intentID == "" {
		s.logger.Printf("Intent not found for accumTxHash=%s, skipping proof generated sync", data.AccumTxHash)
		return nil
	}

	// Create stage 4 status snapshot
	snapshot := &StatusSnapshot{
		Stage:       StageProofGeneration,
		StageName:   StageNames[StageProofGeneration],
		Status:      StatusCompleted,
		Timestamp:   time.Now(),
		Source:      "validator",
		ValidatorID: s.validatorID,
		Data: map[string]interface{}{
			"proofId":          data.ProofID,
			"chainedLayers":    data.ChainedLayers,
			"governanceLevels": data.GovernanceLevels,
			"l1Generated":      data.L1Generated,
			"l2Generated":      data.L2Generated,
			"l3Generated":      data.L3Generated,
			"g0Generated":      data.G0Generated,
			"g1Generated":      data.G1Generated,
			"g2Generated":      data.G2Generated,
			"proofHash":        data.ProofHash,
		},
	}

	if prev, err := s.client.GetLatestStatusSnapshot(ctx, userID, intentID); err == nil && prev != nil {
		snapshot.PreviousSnapshotID = prev.SnapshotID
	}
	snapshot.SnapshotHash = s.computeSnapshotHash(snapshot)

	if err := s.client.CreateStatusSnapshot(ctx, userID, intentID, snapshot); err != nil {
		return fmt.Errorf("failed to create proof generated snapshot: %w", err)
	}

	// Update intent with proof ID
	stage := int(StageProofGeneration)
	now := time.Now()
	if err := s.client.UpdateTransactionIntent(ctx, userID, intentID, &TransactionIntentUpdate{
		CurrentStage: &stage,
		LastUpdated:  &now,
		ProofID:      data.ProofID,
	}); err != nil {
		s.logger.Printf("Warning: failed to update intent with proof ID: %v", err)
	}

	// Create audit entry
	if err := s.createAuditEntry(ctx, userID, intentID, data.AccumTxHash, "proof_generated",
		fmt.Sprintf("Generated L1-L%d and G0-G%d proofs", data.ChainedLayers, data.GovernanceLevels),
		map[string]interface{}{
			"proofId":   data.ProofID,
			"proofHash": data.ProofHash,
		}); err != nil {
		s.logger.Printf("Warning: failed to create audit entry: %v", err)
	}

	return nil
}

// ProofGeneratedEvent contains data for the proof generation event
type ProofGeneratedEvent struct {
	AccumTxHash      string
	ProofID          string
	ChainedLayers    int  // Number of L layers (1-3)
	GovernanceLevels int  // Number of G levels (0-2)
	L1Generated      bool
	L2Generated      bool
	L3Generated      bool
	G0Generated      bool
	G1Generated      bool
	G2Generated      bool
	ProofHash        string
}

// ========================================================================================
// Stage 5: Batch Consensus
// ========================================================================================

// OnBatchClosed is called when a batch is closed and merkle root computed
func (s *SyncService) OnBatchClosed(ctx context.Context, data *BatchClosedEvent) error {
	if !s.IsEnabled() {
		return nil
	}

	// For each transaction in the batch, create a status snapshot
	for _, tx := range data.Transactions {
		userID, intentID, err := s.resolveIntent(ctx, tx.AccumTxHash)
		if err != nil || userID == "" || intentID == "" {
			continue // Skip transactions we can't link
		}

		snapshot := &StatusSnapshot{
			Stage:       StageBatchConsensus,
			StageName:   StageNames[StageBatchConsensus],
			Status:      StatusCompleted,
			Timestamp:   time.Now(),
			Source:      "validator",
			ValidatorID: s.validatorID,
			Data: map[string]interface{}{
				"batchId":       data.BatchID,
				"batchPosition": tx.Position,
				"merkleRoot":    data.MerkleRoot,
				"leafHash":      tx.LeafHash,
				"batchSize":     data.BatchSize,
				"proofClass":    data.ProofClass,
			},
		}

		if prev, err := s.client.GetLatestStatusSnapshot(ctx, userID, intentID); err == nil && prev != nil {
			snapshot.PreviousSnapshotID = prev.SnapshotID
		}
		snapshot.SnapshotHash = s.computeSnapshotHash(snapshot)

		if err := s.client.CreateStatusSnapshot(ctx, userID, intentID, snapshot); err != nil {
			s.logger.Printf("Warning: failed to create batch closed snapshot for %s: %v", tx.AccumTxHash, err)
			continue
		}

		// Update intent with batch ID
		stage := int(StageBatchConsensus)
		now := time.Now()
		if err := s.client.UpdateTransactionIntent(ctx, userID, intentID, &TransactionIntentUpdate{
			CurrentStage: &stage,
			LastUpdated:  &now,
			BatchID:      data.BatchID,
		}); err != nil {
			s.logger.Printf("Warning: failed to update intent with batch ID: %v", err)
		}

		// Create audit entry
		if err := s.createAuditEntry(ctx, userID, intentID, tx.AccumTxHash, "batched",
			fmt.Sprintf("Added to batch %s at position %d", data.BatchID, tx.Position),
			map[string]interface{}{
				"batchId":    data.BatchID,
				"merkleRoot": data.MerkleRoot,
				"batchSize":  data.BatchSize,
			}); err != nil {
			s.logger.Printf("Warning: failed to create audit entry: %v", err)
		}
	}

	return nil
}

// BatchClosedEvent contains data for the batch closed event
type BatchClosedEvent struct {
	BatchID      string
	MerkleRoot   string
	BatchSize    int
	ProofClass   string
	Transactions []BatchTransaction
}

// BatchTransaction represents a transaction in a batch
type BatchTransaction struct {
	AccumTxHash string
	Position    int
	LeafHash    string
}

// ========================================================================================
// Stage 6: Ethereum Anchoring
// ========================================================================================

// OnAnchorSubmitted is called when the anchor is submitted to Ethereum
func (s *SyncService) OnAnchorSubmitted(ctx context.Context, data *AnchorSubmittedEvent) error {
	if !s.IsEnabled() {
		return nil
	}

	// For each transaction in the batch, create a status snapshot
	for _, accumTxHash := range data.TransactionHashes {
		userID, intentID, err := s.resolveIntent(ctx, accumTxHash)
		if err != nil || userID == "" || intentID == "" {
			continue
		}

		snapshot := &StatusSnapshot{
			Stage:       StageEthereumAnchoring,
			StageName:   StageNames[StageEthereumAnchoring],
			Status:      StatusCompleted,
			Timestamp:   time.Now(),
			Source:      "validator",
			ValidatorID: s.validatorID,
			Data: map[string]interface{}{
				"anchorTxHash":    data.AnchorTxHash,
				"blockNumber":     data.BlockNumber,
				"contractAddress": data.ContractAddress,
				"gasUsed":         data.GasUsed,
				"networkName":     data.NetworkName,
			},
		}

		if prev, err := s.client.GetLatestStatusSnapshot(ctx, userID, intentID); err == nil && prev != nil {
			snapshot.PreviousSnapshotID = prev.SnapshotID
		}
		snapshot.SnapshotHash = s.computeSnapshotHash(snapshot)

		if err := s.client.CreateStatusSnapshot(ctx, userID, intentID, snapshot); err != nil {
			s.logger.Printf("Warning: failed to create anchor submitted snapshot: %v", err)
			continue
		}

		// Update intent with anchor tx hash
		stage := int(StageEthereumAnchoring)
		now := time.Now()
		if err := s.client.UpdateTransactionIntent(ctx, userID, intentID, &TransactionIntentUpdate{
			CurrentStage: &stage,
			LastUpdated:  &now,
			AnchorTxHash: data.AnchorTxHash,
		}); err != nil {
			s.logger.Printf("Warning: failed to update intent with anchor tx: %v", err)
		}

		// Create audit entry
		if err := s.createAuditEntry(ctx, userID, intentID, accumTxHash, "anchored",
			fmt.Sprintf("Anchored on %s at block %d", data.NetworkName, data.BlockNumber),
			map[string]interface{}{
				"anchorTxHash": data.AnchorTxHash,
				"blockNumber":  data.BlockNumber,
				"network":      data.NetworkName,
			}); err != nil {
			s.logger.Printf("Warning: failed to create audit entry: %v", err)
		}
	}

	return nil
}

// AnchorSubmittedEvent contains data for the anchor submitted event
type AnchorSubmittedEvent struct {
	BatchID           string
	AnchorTxHash      string
	BlockNumber       int64
	ContractAddress   string
	GasUsed           int64
	NetworkName       string
	TransactionHashes []string // Accumulate tx hashes in this batch
}

// ========================================================================================
// Stage 7: Confirmation Tracking
// ========================================================================================

// OnConfirmationUpdate is called when Ethereum confirmations are updated
func (s *SyncService) OnConfirmationUpdate(ctx context.Context, data *ConfirmationUpdateEvent) error {
	if !s.IsEnabled() {
		return nil
	}

	for _, accumTxHash := range data.TransactionHashes {
		userID, intentID, err := s.resolveIntent(ctx, accumTxHash)
		if err != nil || userID == "" || intentID == "" {
			continue
		}

		status := StatusInProgress
		if data.IsConfirmed {
			status = StatusCompleted
		}

		snapshot := &StatusSnapshot{
			Stage:       StageConfirmationTracking,
			StageName:   StageNames[StageConfirmationTracking],
			Status:      status,
			Timestamp:   time.Now(),
			Source:      "validator",
			ValidatorID: s.validatorID,
			Data: map[string]interface{}{
				"anchorTxHash":          data.AnchorTxHash,
				"currentConfirmations":  data.CurrentConfirmations,
				"requiredConfirmations": data.RequiredConfirmations,
				"isConfirmed":           data.IsConfirmed,
				"blockNumber":           data.BlockNumber,
			},
		}

		if prev, err := s.client.GetLatestStatusSnapshot(ctx, userID, intentID); err == nil && prev != nil {
			snapshot.PreviousSnapshotID = prev.SnapshotID
		}
		snapshot.SnapshotHash = s.computeSnapshotHash(snapshot)

		if err := s.client.CreateStatusSnapshot(ctx, userID, intentID, snapshot); err != nil {
			s.logger.Printf("Warning: failed to create confirmation update snapshot: %v", err)
			continue
		}

		// Update intent with confirmation count
		stage := int(StageConfirmationTracking)
		now := time.Now()
		confirmations := int(data.CurrentConfirmations)
		if err := s.client.UpdateTransactionIntent(ctx, userID, intentID, &TransactionIntentUpdate{
			CurrentStage:          &stage,
			LastUpdated:           &now,
			EthereumConfirmations: &confirmations,
		}); err != nil {
			s.logger.Printf("Warning: failed to update intent with confirmations: %v", err)
		}
	}

	return nil
}

// ConfirmationUpdateEvent contains data for confirmation tracking updates
type ConfirmationUpdateEvent struct {
	BatchID               string
	AnchorTxHash          string
	CurrentConfirmations  int
	RequiredConfirmations int
	IsConfirmed           bool
	BlockNumber           int64
	TransactionHashes     []string
}

// ========================================================================================
// Stage 8: BLS Attestation
// ========================================================================================

// OnBLSAttestation is called when BLS attestation is complete
func (s *SyncService) OnBLSAttestation(ctx context.Context, data *BLSAttestationEvent) error {
	if !s.IsEnabled() {
		return nil
	}

	for _, accumTxHash := range data.TransactionHashes {
		userID, intentID, err := s.resolveIntent(ctx, accumTxHash)
		if err != nil || userID == "" || intentID == "" {
			continue
		}

		status := StatusInProgress
		if data.ThresholdMet {
			status = StatusCompleted
		}

		snapshot := &StatusSnapshot{
			Stage:       StageBLSAttestation,
			StageName:   StageNames[StageBLSAttestation],
			Status:      status,
			Timestamp:   time.Now(),
			Source:      "validator",
			ValidatorID: s.validatorID,
			Data: map[string]interface{}{
				"attestationId":           data.AttestationID,
				"validatorCount":          data.ValidatorCount,
				"participatingValidators": data.ParticipatingValidators,
				"totalWeight":             data.TotalWeight,
				"achievedWeight":          data.AchievedWeight,
				"thresholdMet":            data.ThresholdMet,
				"aggregateSignature":      data.AggregateSignature,
			},
		}

		if prev, err := s.client.GetLatestStatusSnapshot(ctx, userID, intentID); err == nil && prev != nil {
			snapshot.PreviousSnapshotID = prev.SnapshotID
		}
		snapshot.SnapshotHash = s.computeSnapshotHash(snapshot)

		if err := s.client.CreateStatusSnapshot(ctx, userID, intentID, snapshot); err != nil {
			s.logger.Printf("Warning: failed to create BLS attestation snapshot: %v", err)
			continue
		}

		// Update intent stage
		stage := int(StageBLSAttestation)
		now := time.Now()
		if err := s.client.UpdateTransactionIntent(ctx, userID, intentID, &TransactionIntentUpdate{
			CurrentStage: &stage,
			LastUpdated:  &now,
		}); err != nil {
			s.logger.Printf("Warning: failed to update intent stage: %v", err)
		}

		// Create audit entry if threshold met
		if data.ThresholdMet {
			if err := s.createAuditEntry(ctx, userID, intentID, accumTxHash, "attested",
				fmt.Sprintf("BLS attestation complete with %d/%d validators", len(data.ParticipatingValidators), data.ValidatorCount),
				map[string]interface{}{
					"attestationId":  data.AttestationID,
					"achievedWeight": data.AchievedWeight,
					"totalWeight":    data.TotalWeight,
				}); err != nil {
				s.logger.Printf("Warning: failed to create audit entry: %v", err)
			}
		}
	}

	return nil
}

// BLSAttestationEvent contains data for BLS attestation events
type BLSAttestationEvent struct {
	BatchID                 string
	AttestationID           string
	ValidatorCount          int
	ParticipatingValidators []string
	TotalWeight             int64
	AchievedWeight          int64
	ThresholdMet            bool
	AggregateSignature      string
	TransactionHashes       []string
}

// ========================================================================================
// Stage 9: Write Back
// ========================================================================================

// OnWriteBack is called when the result is written back to Accumulate
func (s *SyncService) OnWriteBack(ctx context.Context, data *WriteBackEvent) error {
	if !s.IsEnabled() {
		return nil
	}

	userID, intentID, err := s.resolveIntent(ctx, data.AccumTxHash)
	if err != nil || userID == "" || intentID == "" {
		s.logger.Printf("Intent not found for accumTxHash=%s, skipping write back sync", data.AccumTxHash)
		return nil
	}

	status := StatusCompleted
	if data.ResultStatus != "success" {
		status = StatusFailed
	}

	snapshot := &StatusSnapshot{
		Stage:       StageWriteBack,
		StageName:   StageNames[StageWriteBack],
		Status:      status,
		Timestamp:   time.Now(),
		Source:      "validator",
		ValidatorID: s.validatorID,
		Data: map[string]interface{}{
			"writeBackTxHash": data.WriteBackTxHash,
			"accumulateUrl":   data.AccumulateURL,
			"resultStatus":    data.ResultStatus,
			"executionProof":  data.ExecutionProof,
			"completionTime":  time.Now().Format(time.RFC3339),
		},
	}

	if status == StatusFailed {
		snapshot.ErrorMessage = data.ErrorMessage
		snapshot.ErrorCode = data.ErrorCode
	}

	if prev, err := s.client.GetLatestStatusSnapshot(ctx, userID, intentID); err == nil && prev != nil {
		snapshot.PreviousSnapshotID = prev.SnapshotID
	}
	snapshot.SnapshotHash = s.computeSnapshotHash(snapshot)

	if err := s.client.CreateStatusSnapshot(ctx, userID, intentID, snapshot); err != nil {
		return fmt.Errorf("failed to create write back snapshot: %w", err)
	}

	// Update intent to completed
	stage := int(StageWriteBack)
	now := time.Now()
	intentStatus := "completed"
	if status == StatusFailed {
		intentStatus = "failed"
	}
	if err := s.client.UpdateTransactionIntent(ctx, userID, intentID, &TransactionIntentUpdate{
		Status:       intentStatus,
		CurrentStage: &stage,
		LastUpdated:  &now,
		CompletedAt:  &now,
	}); err != nil {
		s.logger.Printf("Warning: failed to update intent to completed: %v", err)
	}

	// Create audit entry
	phase := "completed"
	action := "Proof cycle completed successfully"
	if status == StatusFailed {
		phase = "executed"
		action = fmt.Sprintf("Proof cycle failed: %s", data.ErrorMessage)
	}

	if err := s.createAuditEntry(ctx, userID, intentID, data.AccumTxHash, phase, action,
		map[string]interface{}{
			"writeBackTxHash": data.WriteBackTxHash,
			"resultStatus":    data.ResultStatus,
		}); err != nil {
		s.logger.Printf("Warning: failed to create audit entry: %v", err)
	}

	return nil
}

// WriteBackEvent contains data for the write back event
type WriteBackEvent struct {
	AccumTxHash     string
	WriteBackTxHash string
	AccumulateURL   string
	ResultStatus    string // "success" or "failed"
	ExecutionProof  string
	ErrorMessage    string
	ErrorCode       string
}

// ========================================================================================
// Helper Methods
// ========================================================================================

// resolveIntent finds the userID and intentID for an Accumulate transaction hash
func (s *SyncService) resolveIntent(ctx context.Context, accumTxHash string) (string, string, error) {
	// Check cache first
	s.intentCacheMu.RLock()
	if mapping, ok := s.intentCache[accumTxHash]; ok {
		if time.Since(mapping.CachedAt) < s.intentCacheTTL {
			s.intentCacheMu.RUnlock()
			return mapping.UserID, mapping.IntentID, nil
		}
	}
	s.intentCacheMu.RUnlock()

	// Query Firestore
	userID, intentID, err := s.client.FindIntentByAccumTxHash(ctx, accumTxHash)
	if err != nil {
		return "", "", err
	}

	// Cache the result
	if userID != "" && intentID != "" {
		s.intentCacheMu.Lock()
		s.intentCache[accumTxHash] = intentMapping{
			UserID:   userID,
			IntentID: intentID,
			CachedAt: time.Now(),
		}
		s.intentCacheMu.Unlock()
	}

	return userID, intentID, nil
}

// RegisterIntent manually registers an intent mapping (useful when intent is known)
func (s *SyncService) RegisterIntent(accumTxHash, userID, intentID string) {
	s.intentCacheMu.Lock()
	defer s.intentCacheMu.Unlock()

	s.intentCache[accumTxHash] = intentMapping{
		UserID:   userID,
		IntentID: intentID,
		CachedAt: time.Now(),
	}
}

// createAuditEntry creates an audit trail entry with chain integrity
func (s *SyncService) createAuditEntry(ctx context.Context, userID, intentID, accumTxHash, phase, action string, details map[string]interface{}) error {
	// Get previous hash for chain integrity
	previousHash := ""
	s.auditChainsMu.RLock()
	if hash, ok := s.auditChains[userID]; ok {
		previousHash = hash
	}
	s.auditChainsMu.RUnlock()

	// If no cached hash, try to get from Firestore
	if previousHash == "" {
		if prev, err := s.client.GetLatestAuditEntry(ctx, userID); err == nil && prev != nil {
			previousHash = prev.EntryHash
		}
	}

	entry := &AuditTrailEntry{
		EntryID:       uuid.New().String(),
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         phase,
		Action:        action,
		Actor:         fmt.Sprintf("validator-%s", s.validatorID),
		ActorType:     "service",
		Timestamp:     time.Now(),
		PreviousHash:  previousHash,
		Details:       details,
	}

	// Compute entry hash
	entry.EntryHash = s.computeAuditHash(entry)

	// Create the entry
	if err := s.client.CreateAuditEntry(ctx, userID, entry); err != nil {
		return err
	}

	// Update cached hash
	s.auditChainsMu.Lock()
	s.auditChains[userID] = entry.EntryHash
	s.auditChainsMu.Unlock()

	return nil
}

// computeSnapshotHash computes a hash for a status snapshot
func (s *SyncService) computeSnapshotHash(snapshot *StatusSnapshot) string {
	data := map[string]interface{}{
		"stage":              snapshot.Stage,
		"stageName":          snapshot.StageName,
		"status":             snapshot.Status,
		"timestamp":          snapshot.Timestamp.Unix(),
		"validatorId":        snapshot.ValidatorID,
		"data":               snapshot.Data,
		"previousSnapshotId": snapshot.PreviousSnapshotID,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// computeAuditHash computes a hash for an audit entry
func (s *SyncService) computeAuditHash(entry *AuditTrailEntry) string {
	data := map[string]interface{}{
		"transactionId": entry.TransactionID,
		"accumTxHash":   entry.AccumTxHash,
		"phase":         entry.Phase,
		"action":        entry.Action,
		"actor":         entry.Actor,
		"timestamp":     entry.Timestamp.Unix(),
		"previousHash":  entry.PreviousHash,
		"details":       entry.Details,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// ClearIntentCache clears the intent cache (useful for testing)
func (s *SyncService) ClearIntentCache() {
	s.intentCacheMu.Lock()
	defer s.intentCacheMu.Unlock()
	s.intentCache = make(map[string]intentMapping)
}
