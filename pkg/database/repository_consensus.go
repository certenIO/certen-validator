// Copyright 2025 Certen Protocol
//
// Consensus Repository - CRUD operations for consensus entries and batch attestations
// Persists CometBFT consensus state and BLS attestations to postgres

package database

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ConsensusRepository handles consensus state persistence operations
type ConsensusRepository struct {
	client *Client
}

// NewConsensusRepository creates a new consensus repository
func NewConsensusRepository(client *Client) *ConsensusRepository {
	return &ConsensusRepository{client: client}
}

// ============================================================================
// CONSENSUS ENTRY OPERATIONS
// ============================================================================

// NewConsensusEntry is used to create a new consensus entry
type NewConsensusEntry struct {
	BatchID            uuid.UUID
	MerkleRoot         []byte
	AnchorTxHash       string
	BlockNumber        int64
	TxCount            int
	State              string // initiated, collecting, quorum_met, completed, failed, timeout
	AttestationCount   int
	RequiredCount      int
	QuorumFraction     float64
	AggregateSignature []byte
	AggregatePubKey    []byte
	StartTime          time.Time
	ResultJSON         interface{} // Will be marshaled to JSONB
}

// ConsensusEntry represents a stored consensus entry
type ConsensusEntry struct {
	EntryID            uuid.UUID
	BatchID            uuid.UUID
	MerkleRoot         []byte
	AnchorTxHash       string
	BlockNumber        int64
	TxCount            int
	State              string
	AttestationCount   int
	RequiredCount      int
	QuorumFraction     float64
	AggregateSignature []byte
	AggregatePubKey    []byte
	StartTime          time.Time
	LastUpdate         time.Time
	CompletedAt        *time.Time
	ResultJSON         json.RawMessage
	CreatedAt          time.Time
}

// CreateConsensusEntry creates a new consensus entry
func (r *ConsensusRepository) CreateConsensusEntry(ctx context.Context, input *NewConsensusEntry) (*ConsensusEntry, error) {
	entry := &ConsensusEntry{
		EntryID:            uuid.New(),
		BatchID:            input.BatchID,
		MerkleRoot:         input.MerkleRoot,
		AnchorTxHash:       input.AnchorTxHash,
		BlockNumber:        input.BlockNumber,
		TxCount:            input.TxCount,
		State:              input.State,
		AttestationCount:   input.AttestationCount,
		RequiredCount:      input.RequiredCount,
		QuorumFraction:     input.QuorumFraction,
		AggregateSignature: input.AggregateSignature,
		AggregatePubKey:    input.AggregatePubKey,
		StartTime:          input.StartTime,
		LastUpdate:         time.Now(),
	}

	// Marshal result JSON if provided
	var resultJSON []byte
	var err error
	if input.ResultJSON != nil {
		resultJSON, err = json.Marshal(input.ResultJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result JSON: %w", err)
		}
	}

	// Set completed_at if state is terminal
	var completedAt *time.Time
	if input.State == "completed" || input.State == "quorum_met" {
		now := time.Now()
		completedAt = &now
		entry.CompletedAt = completedAt
	}

	query := `
		INSERT INTO consensus_entries (
			entry_id, batch_id, merkle_root, anchor_tx_hash, block_number,
			tx_count, state, attestation_count, required_count, quorum_fraction,
			aggregate_signature, aggregate_pubkey, start_time, last_update,
			completed_at, result_json
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (batch_id) DO UPDATE SET
			state = EXCLUDED.state,
			attestation_count = EXCLUDED.attestation_count,
			aggregate_signature = EXCLUDED.aggregate_signature,
			aggregate_pubkey = EXCLUDED.aggregate_pubkey,
			last_update = EXCLUDED.last_update,
			completed_at = EXCLUDED.completed_at,
			result_json = EXCLUDED.result_json
		RETURNING entry_id, created_at`

	err = r.client.QueryRowContext(ctx, query,
		entry.EntryID, entry.BatchID, entry.MerkleRoot, entry.AnchorTxHash,
		entry.BlockNumber, entry.TxCount, entry.State, entry.AttestationCount,
		entry.RequiredCount, entry.QuorumFraction, entry.AggregateSignature,
		entry.AggregatePubKey, entry.StartTime, entry.LastUpdate,
		completedAt, resultJSON,
	).Scan(&entry.EntryID, &entry.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create consensus entry: %w", err)
	}

	return entry, nil
}

// GetConsensusEntry retrieves a consensus entry by batch ID
func (r *ConsensusRepository) GetConsensusEntry(ctx context.Context, batchID uuid.UUID) (*ConsensusEntry, error) {
	query := `
		SELECT entry_id, batch_id, merkle_root, anchor_tx_hash, block_number,
			tx_count, state, attestation_count, required_count, quorum_fraction,
			aggregate_signature, aggregate_pubkey, start_time, last_update,
			completed_at, result_json, created_at
		FROM consensus_entries
		WHERE batch_id = $1`

	entry := &ConsensusEntry{}
	err := r.client.QueryRowContext(ctx, query, batchID).Scan(
		&entry.EntryID, &entry.BatchID, &entry.MerkleRoot, &entry.AnchorTxHash,
		&entry.BlockNumber, &entry.TxCount, &entry.State, &entry.AttestationCount,
		&entry.RequiredCount, &entry.QuorumFraction, &entry.AggregateSignature,
		&entry.AggregatePubKey, &entry.StartTime, &entry.LastUpdate,
		&entry.CompletedAt, &entry.ResultJSON, &entry.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get consensus entry: %w", err)
	}

	return entry, nil
}

// UpdateConsensusState updates the state of a consensus entry
func (r *ConsensusRepository) UpdateConsensusState(ctx context.Context, batchID uuid.UUID, state string, attestationCount int) error {
	var completedAt *time.Time
	if state == "completed" || state == "quorum_met" {
		now := time.Now()
		completedAt = &now
	}

	query := `
		UPDATE consensus_entries
		SET state = $2, attestation_count = $3, last_update = NOW(), completed_at = $4
		WHERE batch_id = $1`

	_, err := r.client.ExecContext(ctx, query, batchID, state, attestationCount, completedAt)
	if err != nil {
		return fmt.Errorf("failed to update consensus state: %w", err)
	}

	return nil
}

// GetActiveConsensusEntries retrieves all active consensus entries
func (r *ConsensusRepository) GetActiveConsensusEntries(ctx context.Context) ([]*ConsensusEntry, error) {
	query := `
		SELECT entry_id, batch_id, merkle_root, anchor_tx_hash, block_number,
			tx_count, state, attestation_count, required_count, quorum_fraction,
			aggregate_signature, aggregate_pubkey, start_time, last_update,
			completed_at, result_json, created_at
		FROM consensus_entries
		WHERE state IN ('initiated', 'collecting')
		ORDER BY start_time ASC`

	rows, err := r.client.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active consensus entries: %w", err)
	}
	defer rows.Close()

	var entries []*ConsensusEntry
	for rows.Next() {
		entry := &ConsensusEntry{}
		err := rows.Scan(
			&entry.EntryID, &entry.BatchID, &entry.MerkleRoot, &entry.AnchorTxHash,
			&entry.BlockNumber, &entry.TxCount, &entry.State, &entry.AttestationCount,
			&entry.RequiredCount, &entry.QuorumFraction, &entry.AggregateSignature,
			&entry.AggregatePubKey, &entry.StartTime, &entry.LastUpdate,
			&entry.CompletedAt, &entry.ResultJSON, &entry.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan consensus entry: %w", err)
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// ============================================================================
// BATCH ATTESTATION OPERATIONS
// ============================================================================

// NewBatchAttestation is used to create a new batch attestation
type NewBatchAttestation struct {
	BatchID         uuid.UUID
	ValidatorID     string
	MerkleRoot      []byte
	BLSSignature    []byte
	BLSPublicKey    []byte
	TxCount         int
	BlockHeight     int64
	AttestationTime time.Time
	SignatureValid  *bool
}

// BatchAttestation represents a stored batch attestation
type BatchAttestation struct {
	AttestationID   uuid.UUID
	BatchID         uuid.UUID
	ValidatorID     string
	MerkleRoot      []byte
	BLSSignature    []byte
	BLSPublicKey    []byte
	TxCount         int
	BlockHeight     int64
	AttestationTime time.Time
	SignatureValid  *bool
	VerifiedAt      *time.Time
	CreatedAt       time.Time
}

// CreateBatchAttestation creates a new batch attestation
func (r *ConsensusRepository) CreateBatchAttestation(ctx context.Context, input *NewBatchAttestation) (*BatchAttestation, error) {
	attestation := &BatchAttestation{
		AttestationID:   uuid.New(),
		BatchID:         input.BatchID,
		ValidatorID:     input.ValidatorID,
		MerkleRoot:      input.MerkleRoot,
		BLSSignature:    input.BLSSignature,
		BLSPublicKey:    input.BLSPublicKey,
		TxCount:         input.TxCount,
		BlockHeight:     input.BlockHeight,
		AttestationTime: input.AttestationTime,
		SignatureValid:  input.SignatureValid,
	}

	query := `
		INSERT INTO batch_attestations (
			attestation_id, batch_id, validator_id, merkle_root,
			bls_signature, bls_public_key, tx_count, block_height,
			attestation_time, signature_valid
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (batch_id, validator_id) DO UPDATE SET
			bls_signature = EXCLUDED.bls_signature,
			bls_public_key = EXCLUDED.bls_public_key,
			attestation_time = EXCLUDED.attestation_time,
			signature_valid = EXCLUDED.signature_valid
		RETURNING attestation_id, created_at`

	err := r.client.QueryRowContext(ctx, query,
		attestation.AttestationID, attestation.BatchID, attestation.ValidatorID,
		attestation.MerkleRoot, attestation.BLSSignature, attestation.BLSPublicKey,
		attestation.TxCount, attestation.BlockHeight, attestation.AttestationTime,
		attestation.SignatureValid,
	).Scan(&attestation.AttestationID, &attestation.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create batch attestation: %w", err)
	}

	return attestation, nil
}

// GetBatchAttestations retrieves all attestations for a batch
func (r *ConsensusRepository) GetBatchAttestations(ctx context.Context, batchID uuid.UUID) ([]*BatchAttestation, error) {
	query := `
		SELECT attestation_id, batch_id, validator_id, merkle_root,
			bls_signature, bls_public_key, tx_count, block_height,
			attestation_time, signature_valid, verified_at, created_at
		FROM batch_attestations
		WHERE batch_id = $1
		ORDER BY attestation_time ASC`

	rows, err := r.client.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query batch attestations: %w", err)
	}
	defer rows.Close()

	var attestations []*BatchAttestation
	for rows.Next() {
		att := &BatchAttestation{}
		err := rows.Scan(
			&att.AttestationID, &att.BatchID, &att.ValidatorID, &att.MerkleRoot,
			&att.BLSSignature, &att.BLSPublicKey, &att.TxCount, &att.BlockHeight,
			&att.AttestationTime, &att.SignatureValid, &att.VerifiedAt, &att.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan batch attestation: %w", err)
		}
		attestations = append(attestations, att)
	}

	return attestations, rows.Err()
}

// CountBatchAttestations returns the number of attestations for a batch
func (r *ConsensusRepository) CountBatchAttestations(ctx context.Context, batchID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM batch_attestations WHERE batch_id = $1`

	var count int
	err := r.client.QueryRowContext(ctx, query, batchID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count batch attestations: %w", err)
	}

	return count, nil
}

// CountValidBatchAttestations returns the number of valid attestations for a batch
func (r *ConsensusRepository) CountValidBatchAttestations(ctx context.Context, batchID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM batch_attestations WHERE batch_id = $1 AND signature_valid = TRUE`

	var count int
	err := r.client.QueryRowContext(ctx, query, batchID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count valid batch attestations: %w", err)
	}

	return count, nil
}

// MarkAttestationValid marks an attestation as valid after verification
func (r *ConsensusRepository) MarkAttestationValid(ctx context.Context, attestationID uuid.UUID, valid bool) error {
	query := `
		UPDATE batch_attestations
		SET signature_valid = $2, verified_at = NOW()
		WHERE attestation_id = $1`

	_, err := r.client.ExecContext(ctx, query, attestationID, valid)
	if err != nil {
		return fmt.Errorf("failed to mark attestation valid: %w", err)
	}

	return nil
}

// GetRecentBatchAttestations returns recent batch attestations
func (r *ConsensusRepository) GetRecentBatchAttestations(ctx context.Context, limit int) ([]*BatchAttestation, error) {
	query := `
		SELECT attestation_id, batch_id, validator_id, merkle_root,
			bls_signature, bls_public_key, tx_count, block_height,
			attestation_time, signature_valid, verified_at, created_at
		FROM batch_attestations
		ORDER BY attestation_time DESC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent batch attestations: %w", err)
	}
	defer rows.Close()

	var attestations []*BatchAttestation
	for rows.Next() {
		att := &BatchAttestation{}
		err := rows.Scan(
			&att.AttestationID, &att.BatchID, &att.ValidatorID, &att.MerkleRoot,
			&att.BLSSignature, &att.BLSPublicKey, &att.TxCount, &att.BlockHeight,
			&att.AttestationTime, &att.SignatureValid, &att.VerifiedAt, &att.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan batch attestation: %w", err)
		}
		attestations = append(attestations, att)
	}

	return attestations, rows.Err()
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// DecodeHexString safely decodes a hex string to bytes
func DecodeHexString(s string) ([]byte, error) {
	// Remove 0x prefix if present
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}
