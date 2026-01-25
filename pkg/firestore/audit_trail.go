// Copyright 2025 Certen Protocol
//
// Audit Trail Service
// Extended audit trail functionality for compliance and forensics

package firestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	gcpfirestore "cloud.google.com/go/firestore"
	"github.com/google/uuid"
)

// AuditTrailService provides comprehensive audit trail management
type AuditTrailService struct {
	client      *Client
	validatorID string
	logger      *log.Logger
}

// AuditTrailConfig holds configuration for the audit trail service
type AuditTrailConfig struct {
	Client      *Client
	ValidatorID string
	Logger      *log.Logger
}

// NewAuditTrailService creates a new audit trail service
func NewAuditTrailService(cfg *AuditTrailConfig) (*AuditTrailService, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	if cfg.Client == nil {
		return nil, fmt.Errorf("Firestore client is required")
	}

	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[AuditTrail] ", log.LstdFlags)
	}

	return &AuditTrailService{
		client:      cfg.Client,
		validatorID: cfg.ValidatorID,
		logger:      cfg.Logger,
	}, nil
}

// IsEnabled returns whether the audit trail service is enabled
func (a *AuditTrailService) IsEnabled() bool {
	return a.client != nil && a.client.IsEnabled()
}

// RecordIntentDiscovered records when a validator discovers an intent
func (a *AuditTrailService) RecordIntentDiscovered(ctx context.Context, userID, intentID, accumTxHash string, blockHeight int64, proofClass string) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "discovered",
		Action:        "Intent discovered on Accumulate blockchain",
		Details: map[string]interface{}{
			"blockHeight": blockHeight,
			"proofClass":  proofClass,
			"source":      "intent_discovery_service",
		},
	})
}

// RecordProofGenerated records when proofs are generated
func (a *AuditTrailService) RecordProofGenerated(ctx context.Context, userID, intentID, accumTxHash, proofID string, layers, govLevels int) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "proof_generated",
		Action:        fmt.Sprintf("Generated L1-L%d lite client proofs and G0-G%d governance proofs", layers, govLevels),
		ProofID:       proofID,
		Details: map[string]interface{}{
			"chainedLayers":    layers,
			"governanceLevels": govLevels,
		},
	})
}

// RecordBatchInclusion records when a transaction is included in a batch
func (a *AuditTrailService) RecordBatchInclusion(ctx context.Context, userID, intentID, accumTxHash, batchID string, position int, merkleRoot string) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "batched",
		Action:        fmt.Sprintf("Added to batch %s at position %d", batchID[:8], position),
		BatchID:       batchID,
		Details: map[string]interface{}{
			"batchPosition": position,
			"merkleRoot":    merkleRoot,
		},
	})
}

// RecordAnchorCreated records when an anchor is created on Ethereum
func (a *AuditTrailService) RecordAnchorCreated(ctx context.Context, userID, intentID, accumTxHash, anchorTxHash string, blockNumber int64, network string) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "anchored",
		Action:        fmt.Sprintf("Anchor created on %s at block %d", network, blockNumber),
		AnchorID:      anchorTxHash,
		Details: map[string]interface{}{
			"anchorTxHash": anchorTxHash,
			"blockNumber":  blockNumber,
			"network":      network,
		},
	})
}

// RecordAnchorConfirmed records when an anchor reaches sufficient confirmations
func (a *AuditTrailService) RecordAnchorConfirmed(ctx context.Context, userID, intentID, accumTxHash, anchorTxHash string, confirmations int) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "anchored",
		Action:        fmt.Sprintf("Anchor confirmed with %d confirmations", confirmations),
		AnchorID:      anchorTxHash,
		Details: map[string]interface{}{
			"anchorTxHash":  anchorTxHash,
			"confirmations": confirmations,
			"finalized":     true,
		},
	})
}

// RecordAttestationComplete records when BLS attestation reaches threshold
func (a *AuditTrailService) RecordAttestationComplete(ctx context.Context, userID, intentID, accumTxHash, attestationID string, validatorCount int, achievedWeight, totalWeight int64) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "attested",
		Action:        fmt.Sprintf("BLS attestation threshold met with %d validators", validatorCount),
		Details: map[string]interface{}{
			"attestationId":  attestationID,
			"validatorCount": validatorCount,
			"achievedWeight": achievedWeight,
			"totalWeight":    totalWeight,
			"thresholdMet":   true,
		},
	})
}

// RecordExecutionVerified records when execution is verified
func (a *AuditTrailService) RecordExecutionVerified(ctx context.Context, userID, intentID, accumTxHash string, success bool, details map[string]interface{}) error {
	action := "Execution verified successfully"
	if !success {
		action = "Execution verification failed"
	}

	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "executed",
		Action:        action,
		Details:       details,
	})
}

// RecordProofCycleComplete records when the entire proof cycle is complete
func (a *AuditTrailService) RecordProofCycleComplete(ctx context.Context, userID, intentID, accumTxHash, writeBackTxHash string) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "completed",
		Action:        "Proof cycle completed and result written back to Accumulate",
		Details: map[string]interface{}{
			"writeBackTxHash": writeBackTxHash,
			"completedAt":     time.Now().Format(time.RFC3339),
		},
	})
}

// RecordError records an error in the proof cycle
func (a *AuditTrailService) RecordError(ctx context.Context, userID, intentID, accumTxHash, phase, errorMessage, errorCode string) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         phase,
		Action:        fmt.Sprintf("Error: %s", errorMessage),
		Details: map[string]interface{}{
			"errorMessage": errorMessage,
			"errorCode":    errorCode,
			"isError":      true,
		},
	})
}

// RecordManualIntervention records when manual intervention occurs
func (a *AuditTrailService) RecordManualIntervention(ctx context.Context, userID, intentID, accumTxHash, reason, operator string) error {
	return a.createEntry(ctx, userID, AuditEntryParams{
		TransactionID: intentID,
		AccumTxHash:   accumTxHash,
		Phase:         "manual_intervention",
		Action:        fmt.Sprintf("Manual intervention: %s", reason),
		Details: map[string]interface{}{
			"reason":      reason,
			"operator":    operator,
			"interventionTime": time.Now().Format(time.RFC3339),
		},
	})
}

// AuditEntryParams holds parameters for creating an audit entry
type AuditEntryParams struct {
	TransactionID string
	AccumTxHash   string
	Phase         string
	Action        string
	ProofID       string
	BatchID       string
	AnchorID      string
	Details       map[string]interface{}
}

// createEntry creates an audit entry with chain integrity
func (a *AuditTrailService) createEntry(ctx context.Context, userID string, params AuditEntryParams) error {
	if !a.IsEnabled() {
		a.logger.Printf("Audit trail disabled - skipping entry for user=%s phase=%s", userID, params.Phase)
		return nil
	}

	// Get previous entry for chain integrity
	var previousHash string
	if prev, err := a.client.GetLatestAuditEntry(ctx, userID); err == nil && prev != nil {
		previousHash = prev.EntryHash
	}

	entry := &AuditTrailEntry{
		EntryID:       uuid.New().String(),
		TransactionID: params.TransactionID,
		AccumTxHash:   params.AccumTxHash,
		Phase:         params.Phase,
		Action:        params.Action,
		Actor:         fmt.Sprintf("validator-%s", a.validatorID),
		ActorType:     "service",
		Timestamp:     time.Now(),
		PreviousHash:  previousHash,
		Details:       params.Details,
		ProofID:       params.ProofID,
		BatchID:       params.BatchID,
		AnchorID:      params.AnchorID,
	}

	// Compute entry hash for chain integrity
	entry.EntryHash = a.computeEntryHash(entry)

	return a.client.CreateAuditEntry(ctx, userID, entry)
}

// computeEntryHash computes a SHA256 hash for chain integrity
func (a *AuditTrailService) computeEntryHash(entry *AuditTrailEntry) string {
	// Create a deterministic representation for hashing
	data := map[string]interface{}{
		"transactionId": entry.TransactionID,
		"accumTxHash":   entry.AccumTxHash,
		"phase":         entry.Phase,
		"action":        entry.Action,
		"actor":         entry.Actor,
		"actorType":     entry.ActorType,
		"timestamp":     entry.Timestamp.Unix(),
		"previousHash":  entry.PreviousHash,
		"details":       entry.Details,
		"proofId":       entry.ProofID,
		"batchId":       entry.BatchID,
		"anchorId":      entry.AnchorID,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		a.logger.Printf("Warning: failed to marshal audit entry for hashing: %v", err)
		return ""
	}

	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// VerifyAuditChain verifies the integrity of a user's audit trail
func (a *AuditTrailService) VerifyAuditChain(ctx context.Context, userID string) (*AuditChainVerification, error) {
	if !a.IsEnabled() {
		return nil, fmt.Errorf("audit trail service is disabled")
	}

	// Query all audit entries for the user, ordered by timestamp
	collPath := fmt.Sprintf("users/%s/auditTrail", userID)
	query := a.client.firestore.Collection(collPath).
		OrderBy("timestamp", gcpfirestore.Asc)

	docs, err := query.Documents(ctx).GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to query audit trail: %w", err)
	}

	result := &AuditChainVerification{
		UserID:     userID,
		EntryCount: len(docs),
		Verified:   true,
		CheckedAt:  time.Now(),
	}

	if len(docs) == 0 {
		return result, nil
	}

	var previousHash string
	for i, doc := range docs {
		var entry AuditTrailEntry
		if err := doc.DataTo(&entry); err != nil {
			result.Verified = false
			result.Errors = append(result.Errors, fmt.Sprintf("Entry %d: failed to parse: %v", i, err))
			continue
		}
		entry.EntryID = doc.Ref.ID

		// Verify previous hash matches
		if entry.PreviousHash != previousHash {
			result.Verified = false
			result.Errors = append(result.Errors, fmt.Sprintf("Entry %d (%s): previousHash mismatch - expected %s, got %s",
				i, entry.EntryID, previousHash, entry.PreviousHash))
		}

		// Verify entry hash
		computedHash := a.computeEntryHash(&entry)
		if entry.EntryHash != computedHash {
			result.Verified = false
			result.Errors = append(result.Errors, fmt.Sprintf("Entry %d (%s): entryHash mismatch - expected %s, got %s",
				i, entry.EntryID, computedHash, entry.EntryHash))
		}

		previousHash = entry.EntryHash
	}

	return result, nil
}

// AuditChainVerification holds the result of chain verification
type AuditChainVerification struct {
	UserID     string    `json:"userId"`
	EntryCount int       `json:"entryCount"`
	Verified   bool      `json:"verified"`
	Errors     []string  `json:"errors,omitempty"`
	CheckedAt  time.Time `json:"checkedAt"`
}

// GetAuditTrailForTransaction retrieves all audit entries for a specific transaction
func (a *AuditTrailService) GetAuditTrailForTransaction(ctx context.Context, userID, intentID string) ([]*AuditTrailEntry, error) {
	if !a.IsEnabled() {
		return nil, fmt.Errorf("audit trail service is disabled")
	}

	collPath := fmt.Sprintf("users/%s/auditTrail", userID)
	query := a.client.firestore.Collection(collPath).
		Where("transactionId", "==", intentID).
		OrderBy("timestamp", gcpfirestore.Asc)

	docs, err := query.Documents(ctx).GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to query audit trail: %w", err)
	}

	entries := make([]*AuditTrailEntry, 0, len(docs))
	for _, doc := range docs {
		var entry AuditTrailEntry
		if err := doc.DataTo(&entry); err != nil {
			a.logger.Printf("Warning: failed to parse audit entry %s: %v", doc.Ref.ID, err)
			continue
		}
		entry.EntryID = doc.Ref.ID
		entries = append(entries, &entry)
	}

	return entries, nil
}

// ExportAuditTrail exports the audit trail for a user in a portable format
func (a *AuditTrailService) ExportAuditTrail(ctx context.Context, userID string) (*AuditTrailExport, error) {
	if !a.IsEnabled() {
		return nil, fmt.Errorf("audit trail service is disabled")
	}

	collPath := fmt.Sprintf("users/%s/auditTrail", userID)
	query := a.client.firestore.Collection(collPath).
		OrderBy("timestamp", gcpfirestore.Asc)

	docs, err := query.Documents(ctx).GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to query audit trail: %w", err)
	}

	export := &AuditTrailExport{
		UserID:       userID,
		ExportedAt:   time.Now(),
		ExportFormat: "certen_audit_v1",
		Entries:      make([]*AuditTrailEntry, 0, len(docs)),
	}

	for _, doc := range docs {
		var entry AuditTrailEntry
		if err := doc.DataTo(&entry); err != nil {
			continue
		}
		entry.EntryID = doc.Ref.ID
		export.Entries = append(export.Entries, &entry)
	}

	// Compute export hash for integrity verification
	exportData, _ := json.Marshal(export.Entries)
	hash := sha256.Sum256(exportData)
	export.ExportHash = hex.EncodeToString(hash[:])

	return export, nil
}

// AuditTrailExport holds a complete export of a user's audit trail
type AuditTrailExport struct {
	UserID       string             `json:"userId"`
	ExportedAt   time.Time          `json:"exportedAt"`
	ExportFormat string             `json:"exportFormat"`
	ExportHash   string             `json:"exportHash"`
	Entries      []*AuditTrailEntry `json:"entries"`
}
