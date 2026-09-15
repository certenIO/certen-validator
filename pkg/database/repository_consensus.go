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
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
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

// ============================================================================
// COMMITTED-BLOCK PERSISTENCE (off the ABCI Commit path)
// ============================================================================

// CommittedConsensusEntry is a consensus entry derived from a committed ValidatorBlock. CompletedAt is
// supplied by the caller (the block time) instead of the wall clock, so every writer derives the same row.
type CommittedConsensusEntry struct {
	NewConsensusEntry
	CompletedAt *time.Time
}

// CommittedConsensusRecords is everything one committed CometBFT block contributes to consensus_entries
// and batch_attestations. A block without ValidatorBlocks has no records and still advances the watermark.
type CommittedConsensusRecords struct {
	Height       int64
	Entries      []CommittedConsensusEntry
	Attestations []NewBatchAttestation
}

// RejectedRecord is a row the database refused on its content (SQLSTATE class 22 data exception or 23
// integrity violation). Such a row can never be written, so it is skipped rather than retried — as the
// previous row-by-row writer logged and skipped it — and the rest of the block is still persisted.
type RejectedRecord struct {
	Table   string
	BatchID uuid.UUID
	Err     error
}

// isContentRejection reports a database refusal caused by the row itself, not by the connection or server.
func isContentRejection(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		class := string(pqErr.Code.Class())
		return class == "22" || class == "23"
	}
	return false
}

// execRow runs one insert inside a savepoint, so a content rejection rolls back only that row. It returns
// the rejection separately from a failure that must abort the block.
func execRow(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (rejected error, err error) {
	if _, err := tx.ExecContext(ctx, "SAVEPOINT committed_row"); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		if !isContentRejection(err) {
			return nil, err
		}
		if _, rbErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT committed_row"); rbErr != nil {
			return nil, rbErr
		}
		return err, nil
	}
	if _, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT committed_row"); err != nil {
		return nil, err
	}
	return nil, nil
}

// PersistCommittedBlock inserts one committed block's records and advances writerID's persisted height,
// atomically.
//
// Rows are inserted once and never rewritten (ON CONFLICT DO NOTHING). A committed ValidatorBlock is
// immutable, so a second insert has nothing to add, and later writers own the mutable columns:
// MarkConsensusQuorumMet (state, aggregates, result_json, completed_at) and the attestation verification
// flags. The previous upsert reset those columns on every Commit.
//
// The watermark only moves forward (GREATEST), so a replayed or out-of-order call cannot rewind it.
//
// A row the database refuses on its content is skipped and returned in rejected (see RejectedRecord); any
// other failure rolls the whole block back and is returned as err, for the caller to retry.
func (r *ConsensusRepository) PersistCommittedBlock(ctx context.Context, writerID string, rec *CommittedConsensusRecords) (rejected []RejectedRecord, err error) {
	if writerID == "" {
		return nil, fmt.Errorf("persist committed block: writer id is empty")
	}
	if rec == nil || rec.Height <= 0 {
		return nil, fmt.Errorf("persist committed block: invalid height")
	}

	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	const entryQuery = `
		INSERT INTO consensus_entries (
			entry_id, batch_id, merkle_root, anchor_tx_hash, block_number,
			tx_count, state, attestation_count, required_count, quorum_fraction,
			aggregate_signature, aggregate_pubkey, start_time, last_update,
			completed_at, result_json
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (batch_id) DO NOTHING`

	for i := range rec.Entries {
		e := &rec.Entries[i]
		var resultJSON []byte
		if e.ResultJSON != nil {
			var mErr error
			if resultJSON, mErr = json.Marshal(e.ResultJSON); mErr != nil {
				rejected = append(rejected, RejectedRecord{Table: "consensus_entries", BatchID: e.BatchID, Err: mErr})
				continue
			}
		}
		rej, err := execRow(ctx, tx.Tx(), entryQuery,
			uuid.New(), e.BatchID, e.MerkleRoot, e.AnchorTxHash, e.BlockNumber,
			e.TxCount, e.State, e.AttestationCount, e.RequiredCount, e.QuorumFraction,
			e.AggregateSignature, e.AggregatePubKey, e.StartTime, time.Now(),
			e.CompletedAt, resultJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("persist committed block %d: consensus entry for batch %s: %w", rec.Height, e.BatchID, err)
		}
		if rej != nil {
			rejected = append(rejected, RejectedRecord{Table: "consensus_entries", BatchID: e.BatchID, Err: rej})
		}
	}

	const attestationQuery = `
		INSERT INTO batch_attestations (
			attestation_id, batch_id, validator_id, merkle_root,
			bls_signature, bls_public_key, tx_count, block_height,
			attestation_time, signature_valid
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (batch_id, validator_id) DO NOTHING`

	for i := range rec.Attestations {
		a := &rec.Attestations[i]
		rej, err := execRow(ctx, tx.Tx(), attestationQuery,
			uuid.New(), a.BatchID, a.ValidatorID, a.MerkleRoot,
			a.BLSSignature, a.BLSPublicKey, a.TxCount, a.BlockHeight,
			a.AttestationTime, a.SignatureValid,
		)
		if err != nil {
			return nil, fmt.Errorf("persist committed block %d: batch attestation for batch %s: %w", rec.Height, a.BatchID, err)
		}
		if rej != nil {
			rejected = append(rejected, RejectedRecord{Table: "batch_attestations", BatchID: a.BatchID, Err: rej})
		}
	}

	if _, err := tx.Tx().ExecContext(ctx, `
		INSERT INTO consensus_persistence_progress (writer_id, persisted_height, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (writer_id) DO UPDATE SET
			persisted_height = GREATEST(consensus_persistence_progress.persisted_height, EXCLUDED.persisted_height),
			updated_at = NOW()`,
		writerID, rec.Height,
	); err != nil {
		return nil, fmt.Errorf("persist committed block %d: advance watermark: %w", rec.Height, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("persist committed block %d: commit: %w", rec.Height, err)
	}
	return rejected, nil
}

// LoadPersistedHeight returns the highest CometBFT height writerID has persisted. found is false when the
// writer has never persisted a block.
func (r *ConsensusRepository) LoadPersistedHeight(ctx context.Context, writerID string) (height int64, found bool, err error) {
	err = r.client.QueryRowContext(ctx,
		`SELECT persisted_height FROM consensus_persistence_progress WHERE writer_id = $1`, writerID,
	).Scan(&height)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("load persisted height for %s: %w", writerID, err)
	}
	return height, true, nil
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

// MarkBatchAttestationVerified marks a batch attestation as verified (alias for MarkAttestationValid)
func (r *ConsensusRepository) MarkBatchAttestationVerified(ctx context.Context, attestationID uuid.UUID, valid bool) error {
	return r.MarkAttestationValid(ctx, attestationID, valid)
}

// MarkBatchAttestationVerifiedByBatchAndValidator marks attestation verified by batch ID and validator ID
func (r *ConsensusRepository) MarkBatchAttestationVerifiedByBatchAndValidator(ctx context.Context, batchID uuid.UUID, validatorID string, valid bool) error {
	query := `
		UPDATE batch_attestations
		SET signature_valid = $3, verified_at = NOW()
		WHERE batch_id = $1 AND validator_id = $2`

	result, err := r.client.ExecContext(ctx, query, batchID, validatorID, valid)
	if err != nil {
		return fmt.Errorf("failed to mark batch attestation verified: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		// Not an error - attestation might not exist yet in database
		return nil
	}

	return nil
}

// UpdateConsensusAggregates updates the aggregated signature and public key for a consensus entry
func (r *ConsensusRepository) UpdateConsensusAggregates(ctx context.Context, batchID uuid.UUID, aggregateSig []byte, aggregatePubKey []byte, attestationCount int) error {
	query := `
		UPDATE consensus_entries
		SET aggregate_signature = $2,
			aggregate_pubkey = $3,
			attestation_count = $4,
			last_update = NOW()
		WHERE batch_id = $1`

	result, err := r.client.ExecContext(ctx, query, batchID, aggregateSig, aggregatePubKey, attestationCount)
	if err != nil {
		return fmt.Errorf("failed to update consensus aggregates: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("consensus entry not found for batch: %s", batchID)
	}

	return nil
}

// MarkConsensusQuorumMet updates consensus entry when quorum is reached
func (r *ConsensusRepository) MarkConsensusQuorumMet(ctx context.Context, batchID uuid.UUID, aggregateSig []byte, aggregatePubKey []byte, attestationCount int, resultJSON interface{}) error {
	now := time.Now()

	var resultJSONBytes []byte
	var err error
	if resultJSON != nil {
		resultJSONBytes, err = json.Marshal(resultJSON)
		if err != nil {
			return fmt.Errorf("failed to marshal result JSON: %w", err)
		}
	}

	query := `
		UPDATE consensus_entries
		SET state = 'quorum_met',
			aggregate_signature = $2,
			aggregate_pubkey = $3,
			attestation_count = $4,
			result_json = $5,
			completed_at = $6,
			last_update = $6
		WHERE batch_id = $1`

	result, err := r.client.ExecContext(ctx, query, batchID, aggregateSig, aggregatePubKey, attestationCount, resultJSONBytes, now)
	if err != nil {
		return fmt.Errorf("failed to mark consensus quorum met: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("consensus entry not found for batch: %s", batchID)
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
