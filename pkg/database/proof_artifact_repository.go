// Copyright 2025 Certen Protocol
//
// Proof Artifact Repository Interface
// Per PROOF_SCHEMA_DESIGN.md - API access patterns for proof storage

package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ProofArtifactRepository provides access to proof artifact storage
type ProofArtifactRepository struct {
	db *sql.DB
}

// NewProofArtifactRepository creates a new proof artifact repository
func NewProofArtifactRepository(db *sql.DB) *ProofArtifactRepository {
	return &ProofArtifactRepository{db: db}
}

// ============================================================================
// CORE PROOF ARTIFACT OPERATIONS
// ============================================================================

// CreateProofArtifact creates a new proof artifact
func (r *ProofArtifactRepository) CreateProofArtifact(ctx context.Context, input *NewProofArtifact) (*ProofArtifact, error) {
	// Compute artifact hash for integrity
	artifactHash := sha256.Sum256(input.ArtifactJSON)

	// Serialize merkle_path to JSON if provided
	var merklePathJSON []byte
	if len(input.MerklePath) > 0 {
		var err error
		merklePathJSON, err = json.Marshal(input.MerklePath)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal merkle_path: %w", err)
		}
	}

	query := `
		INSERT INTO proof_artifacts (
			proof_type, proof_version, accum_tx_hash, account_url,
			batch_id, merkle_root, leaf_hash, leaf_index, merkle_path,
			gov_level, proof_class, validator_id, status,
			artifact_json, artifact_hash, user_id, intent_id, created_at
		) VALUES (
			$1, '1.0', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending',
			$12, $13, $14, $15, NOW()
		)
		RETURNING proof_id, created_at`

	var proof ProofArtifact
	proof.ProofType = input.ProofType
	proof.ProofVersion = "1.0"
	proof.AccumTxHash = input.AccumTxHash
	proof.AccountURL = input.AccountURL
	proof.BatchID = input.BatchID
	proof.MerkleRoot = input.MerkleRoot
	proof.LeafHash = input.LeafHash
	proof.LeafIndex = input.LeafIndex
	proof.GovLevel = input.GovLevel
	proof.ProofClass = input.ProofClass
	proof.ValidatorID = input.ValidatorID
	proof.Status = ProofStatusPending
	proof.ArtifactJSON = input.ArtifactJSON
	proof.ArtifactHash = artifactHash[:]
	proof.UserID = input.UserID
	proof.IntentID = input.IntentID

	err := r.db.QueryRowContext(ctx, query,
		input.ProofType, input.AccumTxHash, input.AccountURL,
		input.BatchID, input.MerkleRoot, input.LeafHash, input.LeafIndex, merklePathJSON,
		input.GovLevel, input.ProofClass, input.ValidatorID,
		input.ArtifactJSON, artifactHash[:], input.UserID, input.IntentID,
	).Scan(&proof.ProofID, &proof.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create proof artifact: %w", err)
	}

	return &proof, nil
}

// GetProofByID retrieves a proof by its ID
func (r *ProofArtifactRepository) GetProofByID(ctx context.Context, proofID uuid.UUID) (*ProofArtifact, error) {
	query := `
		SELECT proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			   batch_id, batch_position, anchor_id, anchor_tx_hash, anchor_block_number, anchor_chain,
			   merkle_root, leaf_hash, leaf_index, gov_level, proof_class, validator_id,
			   status, verification_status, created_at, anchored_at, verified_at,
			   artifact_json, artifact_hash
		FROM proof_artifacts
		WHERE proof_id = $1`

	var proof ProofArtifact
	err := r.db.QueryRowContext(ctx, query, proofID).Scan(
		&proof.ProofID, &proof.ProofType, &proof.ProofVersion, &proof.AccumTxHash, &proof.AccountURL,
		&proof.BatchID, &proof.BatchPosition, &proof.AnchorID, &proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorChain,
		&proof.MerkleRoot, &proof.LeafHash, &proof.LeafIndex, &proof.GovLevel, &proof.ProofClass, &proof.ValidatorID,
		&proof.Status, &proof.VerificationStatus, &proof.CreatedAt, &proof.AnchoredAt, &proof.VerifiedAt,
		&proof.ArtifactJSON, &proof.ArtifactHash,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof: %w", err)
	}

	return &proof, nil
}

// GetProofByTxHash retrieves a proof by Accumulate transaction hash
func (r *ProofArtifactRepository) GetProofByTxHash(ctx context.Context, txHash string) (*ProofArtifact, error) {
	query := `
		SELECT proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			   batch_id, batch_position, anchor_id, anchor_tx_hash, anchor_block_number, anchor_chain,
			   merkle_root, leaf_hash, leaf_index, gov_level, proof_class, validator_id,
			   status, verification_status, created_at, anchored_at, verified_at,
			   artifact_json, artifact_hash
		FROM proof_artifacts
		WHERE accum_tx_hash = $1`

	var proof ProofArtifact
	err := r.db.QueryRowContext(ctx, query, txHash).Scan(
		&proof.ProofID, &proof.ProofType, &proof.ProofVersion, &proof.AccumTxHash, &proof.AccountURL,
		&proof.BatchID, &proof.BatchPosition, &proof.AnchorID, &proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorChain,
		&proof.MerkleRoot, &proof.LeafHash, &proof.LeafIndex, &proof.GovLevel, &proof.ProofClass, &proof.ValidatorID,
		&proof.Status, &proof.VerificationStatus, &proof.CreatedAt, &proof.AnchoredAt, &proof.VerifiedAt,
		&proof.ArtifactJSON, &proof.ArtifactHash,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof by tx hash: %w", err)
	}

	return &proof, nil
}

// GetProofsByAccount retrieves all proofs for an account (paginated)
func (r *ProofArtifactRepository) GetProofsByAccount(ctx context.Context, accountURL string, limit, offset int) ([]ProofSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT pa.proof_id, pa.proof_type, pa.accum_tx_hash, pa.account_url,
			   pa.gov_level, pa.status, pa.created_at, pa.anchored_at,
			   COALESCE((SELECT COUNT(*) FROM validator_attestations va WHERE va.proof_id = pa.proof_id), 0) as attestation_count
		FROM proof_artifacts pa
		WHERE pa.account_url = $1
		ORDER BY pa.created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, accountURL, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs by account: %w", err)
	}
	defer rows.Close()

	var summaries []ProofSummary
	for rows.Next() {
		var s ProofSummary
		if err := rows.Scan(
			&s.ProofID, &s.ProofType, &s.AccumTxHash, &s.AccountURL,
			&s.GovLevel, &s.Status, &s.CreatedAt, &s.AnchoredAt,
			&s.AttestationCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof summary: %w", err)
		}
		summaries = append(summaries, s)
	}

	return summaries, nil
}

// GetProofsByBatch retrieves all proofs in a batch
func (r *ProofArtifactRepository) GetProofsByBatch(ctx context.Context, batchID uuid.UUID) ([]ProofArtifact, error) {
	query := `
		SELECT proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			   batch_id, batch_position, anchor_id, anchor_tx_hash, anchor_block_number, anchor_chain,
			   merkle_root, leaf_hash, leaf_index, gov_level, proof_class, validator_id,
			   status, verification_status, created_at, anchored_at, verified_at,
			   artifact_json, artifact_hash
		FROM proof_artifacts
		WHERE batch_id = $1
		ORDER BY batch_position`

	rows, err := r.db.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs by batch: %w", err)
	}
	defer rows.Close()

	var proofs []ProofArtifact
	for rows.Next() {
		var p ProofArtifact
		if err := rows.Scan(
			&p.ProofID, &p.ProofType, &p.ProofVersion, &p.AccumTxHash, &p.AccountURL,
			&p.BatchID, &p.BatchPosition, &p.AnchorID, &p.AnchorTxHash, &p.AnchorBlockNumber, &p.AnchorChain,
			&p.MerkleRoot, &p.LeafHash, &p.LeafIndex, &p.GovLevel, &p.ProofClass, &p.ValidatorID,
			&p.Status, &p.VerificationStatus, &p.CreatedAt, &p.AnchoredAt, &p.VerifiedAt,
			&p.ArtifactJSON, &p.ArtifactHash,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, p)
	}

	return proofs, nil
}

// GetProofsByAnchorTx retrieves all proofs anchored in a specific transaction
func (r *ProofArtifactRepository) GetProofsByAnchorTx(ctx context.Context, anchorTxHash string) ([]ProofArtifact, error) {
	query := `
		SELECT pa.proof_id, pa.proof_type, pa.proof_version, pa.accum_tx_hash, pa.account_url,
			   pa.batch_id, pa.batch_position, pa.anchor_id, pa.anchor_tx_hash, pa.anchor_block_number, pa.anchor_chain,
			   pa.merkle_root, pa.leaf_hash, pa.leaf_index, pa.gov_level, pa.proof_class, pa.validator_id,
			   pa.status, pa.verification_status, pa.created_at, pa.anchored_at, pa.verified_at,
			   pa.artifact_json, pa.artifact_hash
		FROM proof_artifacts pa
		WHERE pa.anchor_tx_hash = $1
		ORDER BY pa.batch_position`

	rows, err := r.db.QueryContext(ctx, query, anchorTxHash)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs by anchor tx: %w", err)
	}
	defer rows.Close()

	var proofs []ProofArtifact
	for rows.Next() {
		var p ProofArtifact
		if err := rows.Scan(
			&p.ProofID, &p.ProofType, &p.ProofVersion, &p.AccumTxHash, &p.AccountURL,
			&p.BatchID, &p.BatchPosition, &p.AnchorID, &p.AnchorTxHash, &p.AnchorBlockNumber, &p.AnchorChain,
			&p.MerkleRoot, &p.LeafHash, &p.LeafIndex, &p.GovLevel, &p.ProofClass, &p.ValidatorID,
			&p.Status, &p.VerificationStatus, &p.CreatedAt, &p.AnchoredAt, &p.VerifiedAt,
			&p.ArtifactJSON, &p.ArtifactHash,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, p)
	}

	return proofs, nil
}

// QueryProofs executes a filtered query on proofs
func (r *ProofArtifactRepository) QueryProofs(ctx context.Context, filter *ProofArtifactFilter) ([]ProofSummary, error) {
	if filter == nil {
		filter = &ProofArtifactFilter{Limit: 50}
	}
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 1000 {
		filter.Limit = 1000
	}

	var conditions []string
	var args []interface{}
	argIndex := 1

	if filter.AccumTxHash != nil {
		conditions = append(conditions, fmt.Sprintf("pa.accum_tx_hash = $%d", argIndex))
		args = append(args, *filter.AccumTxHash)
		argIndex++
	}
	if filter.AccountURL != nil {
		conditions = append(conditions, fmt.Sprintf("pa.account_url = $%d", argIndex))
		args = append(args, *filter.AccountURL)
		argIndex++
	}
	if filter.BatchID != nil {
		conditions = append(conditions, fmt.Sprintf("pa.batch_id = $%d", argIndex))
		args = append(args, *filter.BatchID)
		argIndex++
	}
	if filter.AnchorTxHash != nil {
		conditions = append(conditions, fmt.Sprintf("pa.anchor_tx_hash = $%d", argIndex))
		args = append(args, *filter.AnchorTxHash)
		argIndex++
	}
	if filter.ProofType != nil {
		conditions = append(conditions, fmt.Sprintf("pa.proof_type = $%d", argIndex))
		args = append(args, *filter.ProofType)
		argIndex++
	}
	if filter.GovLevel != nil {
		conditions = append(conditions, fmt.Sprintf("pa.gov_level = $%d", argIndex))
		args = append(args, *filter.GovLevel)
		argIndex++
	}
	if filter.ProofClass != nil {
		conditions = append(conditions, fmt.Sprintf("pa.proof_class = $%d", argIndex))
		args = append(args, *filter.ProofClass)
		argIndex++
	}
	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("pa.status = $%d", argIndex))
		args = append(args, *filter.Status)
		argIndex++
	}
	if filter.ValidatorID != nil {
		conditions = append(conditions, fmt.Sprintf("pa.validator_id = $%d", argIndex))
		args = append(args, *filter.ValidatorID)
		argIndex++
	}
	if filter.AnchorChain != nil {
		conditions = append(conditions, fmt.Sprintf("pa.anchor_chain = $%d", argIndex))
		args = append(args, *filter.AnchorChain)
		argIndex++
	}
	if filter.CreatedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("pa.created_at >= $%d", argIndex))
		args = append(args, *filter.CreatedAfter)
		argIndex++
	}
	if filter.CreatedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("pa.created_at <= $%d", argIndex))
		args = append(args, *filter.CreatedBefore)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT pa.proof_id, pa.proof_type, pa.accum_tx_hash, pa.account_url,
			   pa.gov_level, pa.status, pa.created_at, pa.anchored_at,
			   COALESCE((SELECT COUNT(*) FROM validator_attestations va WHERE va.proof_id = pa.proof_id), 0) as attestation_count
		FROM proof_artifacts pa
		%s
		ORDER BY pa.created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs: %w", err)
	}
	defer rows.Close()

	var summaries []ProofSummary
	for rows.Next() {
		var s ProofSummary
		if err := rows.Scan(
			&s.ProofID, &s.ProofType, &s.AccumTxHash, &s.AccountURL,
			&s.GovLevel, &s.Status, &s.CreatedAt, &s.AnchoredAt,
			&s.AttestationCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof summary: %w", err)
		}
		summaries = append(summaries, s)
	}

	return summaries, nil
}

// UpdateProofAnchored updates a proof with anchor information
func (r *ProofArtifactRepository) UpdateProofAnchored(ctx context.Context, proofID uuid.UUID, anchorID uuid.UUID, anchorTxHash string, anchorBlockNumber int64, anchorChain string) error {
	query := `
		UPDATE proof_artifacts
		SET anchor_id = $1, anchor_tx_hash = $2, anchor_block_number = $3, anchor_chain = $4,
			status = 'anchored', anchored_at = NOW()
		WHERE proof_id = $5`

	result, err := r.db.ExecContext(ctx, query, anchorID, anchorTxHash, anchorBlockNumber, anchorChain, proofID)
	if err != nil {
		return fmt.Errorf("failed to update proof anchored: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// UpdateProofAnchoredSimple updates a proof with anchor tx info without requiring an anchor_records FK
// Use this when you have the Ethereum tx details but haven't created an anchor_records entry
func (r *ProofArtifactRepository) UpdateProofAnchoredSimple(ctx context.Context, proofID uuid.UUID, anchorTxHash string, anchorBlockNumber int64, anchorChain string) error {
	query := `
		UPDATE proof_artifacts
		SET anchor_tx_hash = $1, anchor_block_number = $2, anchor_chain = $3,
			status = 'anchored', anchored_at = NOW()
		WHERE proof_id = $4`

	result, err := r.db.ExecContext(ctx, query, anchorTxHash, anchorBlockNumber, anchorChain, proofID)
	if err != nil {
		return fmt.Errorf("failed to update proof anchored: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// UpdateProofVerified updates a proof's verification status
func (r *ProofArtifactRepository) UpdateProofVerified(ctx context.Context, proofID uuid.UUID, verified bool) error {
	status := VerificationStatusVerified
	if !verified {
		status = VerificationStatusFailed
	}

	query := `
		UPDATE proof_artifacts
		SET verification_status = $1, verified_at = NOW()
		WHERE proof_id = $2`

	result, err := r.db.ExecContext(ctx, query, status, proofID)
	if err != nil {
		return fmt.Errorf("failed to update proof verified: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// UpdateProofStatus updates the lifecycle status of a proof
func (r *ProofArtifactRepository) UpdateProofStatus(ctx context.Context, proofID uuid.UUID, status ProofStatus) error {
	query := `
		UPDATE proof_artifacts
		SET status = $2
		WHERE proof_id = $1`

	result, err := r.db.ExecContext(ctx, query, proofID, status)
	if err != nil {
		return fmt.Errorf("failed to update proof status: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// UpdateProofGovLevel updates the governance level of a proof
func (r *ProofArtifactRepository) UpdateProofGovLevel(ctx context.Context, proofID uuid.UUID, govLevel GovernanceLevel) error {
	query := `
		UPDATE proof_artifacts
		SET gov_level = $2
		WHERE proof_id = $1`

	result, err := r.db.ExecContext(ctx, query, proofID, govLevel)
	if err != nil {
		return fmt.Errorf("failed to update proof gov_level: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// UpdateProofFinalState updates the final state of a proof after cycle completes
// This is a comprehensive update that sets anchor info, status, gov_level, and verification in one call
func (r *ProofArtifactRepository) UpdateProofFinalState(ctx context.Context, proofID uuid.UUID, anchorTxHash string, anchorBlockNumber int64, anchorChain string, govLevel GovernanceLevel, verified bool) error {
	verificationStatus := VerificationStatusVerified
	if !verified {
		verificationStatus = VerificationStatusFailed
	}

	query := `
		UPDATE proof_artifacts
		SET anchor_tx_hash = $2, anchor_block_number = $3, anchor_chain = $4,
			gov_level = $5, status = 'anchored', verification_status = $6,
			anchored_at = NOW(), verified_at = NOW()
		WHERE proof_id = $1`

	result, err := r.db.ExecContext(ctx, query, proofID, anchorTxHash, anchorBlockNumber, anchorChain, govLevel, verificationStatus)
	if err != nil {
		return fmt.Errorf("failed to update proof final state: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// MarkProofBatched marks a proof as batched with batch information
func (r *ProofArtifactRepository) MarkProofBatched(ctx context.Context, proofID uuid.UUID, batchID uuid.UUID, batchPosition int) error {
	query := `
		UPDATE proof_artifacts
		SET status = 'batched', batch_id = $2, batch_position = $3
		WHERE proof_id = $1`

	result, err := r.db.ExecContext(ctx, query, proofID, batchID, batchPosition)
	if err != nil {
		return fmt.Errorf("failed to mark proof batched: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// MarkProofAttested marks a proof as attested with attestation count
func (r *ProofArtifactRepository) MarkProofAttested(ctx context.Context, proofID uuid.UUID, attestationCount int) error {
	query := `
		UPDATE proof_artifacts
		SET status = 'attested'
		WHERE proof_id = $1`

	result, err := r.db.ExecContext(ctx, query, proofID)
	if err != nil {
		return fmt.Errorf("failed to mark proof attested: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// MarkProofFailed marks a proof as failed with error details
func (r *ProofArtifactRepository) MarkProofFailed(ctx context.Context, proofID uuid.UUID) error {
	query := `
		UPDATE proof_artifacts
		SET status = 'failed'
		WHERE proof_id = $1`

	result, err := r.db.ExecContext(ctx, query, proofID)
	if err != nil {
		return fmt.Errorf("failed to mark proof failed: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// UpdateProofsByBatchStatus updates the status of all proofs in a batch
func (r *ProofArtifactRepository) UpdateProofsByBatchStatus(ctx context.Context, batchID uuid.UUID, status ProofStatus) error {
	query := `
		UPDATE proof_artifacts
		SET status = $2
		WHERE batch_id = $1`

	_, err := r.db.ExecContext(ctx, query, batchID, status)
	if err != nil {
		return fmt.Errorf("failed to update proofs by batch status: %w", err)
	}

	return nil
}

// MarkProofsAnchoredByBatch marks all proofs in a batch as anchored
func (r *ProofArtifactRepository) MarkProofsAnchoredByBatch(ctx context.Context, batchID uuid.UUID, anchorID uuid.UUID, anchorTxHash string, anchorBlockNumber int64, anchorChain string) error {
	query := `
		UPDATE proof_artifacts
		SET status = 'anchored',
			anchor_id = $2,
			anchor_tx_hash = $3,
			anchor_block_number = $4,
			anchor_chain = $5,
			anchored_at = NOW()
		WHERE batch_id = $1`

	_, err := r.db.ExecContext(ctx, query, batchID, anchorID, anchorTxHash, anchorBlockNumber, anchorChain)
	if err != nil {
		return fmt.Errorf("failed to mark proofs anchored by batch: %w", err)
	}

	return nil
}

// ============================================================================
// INTENT TRACKING OPERATIONS
// ============================================================================

// GetProofByIntentID retrieves a proof by Firestore intent ID
func (r *ProofArtifactRepository) GetProofByIntentID(ctx context.Context, intentID string) (*ProofArtifact, error) {
	query := `
		SELECT proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			   batch_id, batch_position, anchor_id, anchor_tx_hash, anchor_block_number, anchor_chain,
			   merkle_root, leaf_hash, leaf_index, gov_level, proof_class, validator_id,
			   status, verification_status, created_at, anchored_at, verified_at,
			   artifact_json, artifact_hash, user_id, intent_id
		FROM proof_artifacts
		WHERE intent_id = $1`

	var proof ProofArtifact
	err := r.db.QueryRowContext(ctx, query, intentID).Scan(
		&proof.ProofID, &proof.ProofType, &proof.ProofVersion, &proof.AccumTxHash, &proof.AccountURL,
		&proof.BatchID, &proof.BatchPosition, &proof.AnchorID, &proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorChain,
		&proof.MerkleRoot, &proof.LeafHash, &proof.LeafIndex, &proof.GovLevel, &proof.ProofClass, &proof.ValidatorID,
		&proof.Status, &proof.VerificationStatus, &proof.CreatedAt, &proof.AnchoredAt, &proof.VerifiedAt,
		&proof.ArtifactJSON, &proof.ArtifactHash, &proof.UserID, &proof.IntentID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof by intent ID: %w", err)
	}

	return &proof, nil
}

// GetProofsByUserID retrieves all proofs for a user (paginated)
func (r *ProofArtifactRepository) GetProofsByUserID(ctx context.Context, userID string, limit, offset int) ([]ProofSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT pa.proof_id, pa.proof_type, pa.accum_tx_hash, pa.account_url,
			   pa.gov_level, pa.status, pa.created_at, pa.anchored_at,
			   COALESCE((SELECT COUNT(*) FROM validator_attestations va WHERE va.proof_id = pa.proof_id), 0) as attestation_count
		FROM proof_artifacts pa
		WHERE pa.user_id = $1
		ORDER BY pa.created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs by user: %w", err)
	}
	defer rows.Close()

	var summaries []ProofSummary
	for rows.Next() {
		var s ProofSummary
		if err := rows.Scan(
			&s.ProofID, &s.ProofType, &s.AccumTxHash, &s.AccountURL,
			&s.GovLevel, &s.Status, &s.CreatedAt, &s.AnchoredAt,
			&s.AttestationCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof summary: %w", err)
		}
		summaries = append(summaries, s)
	}

	return summaries, nil
}

// UpdateProofIntentTracking updates the intent tracking fields for a proof
func (r *ProofArtifactRepository) UpdateProofIntentTracking(ctx context.Context, proofID uuid.UUID, userID, intentID *string) error {
	query := `
		UPDATE proof_artifacts
		SET user_id = COALESCE($2, user_id),
			intent_id = COALESCE($3, intent_id)
		WHERE proof_id = $1`

	result, err := r.db.ExecContext(ctx, query, proofID, userID, intentID)
	if err != nil {
		return fmt.Errorf("failed to update proof intent tracking: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof not found: %s", proofID)
	}

	return nil
}

// ============================================================================
// CHAINED PROOF LAYER OPERATIONS
// ============================================================================

// CreateChainedProofLayer creates a new layer record
func (r *ProofArtifactRepository) CreateChainedProofLayer(ctx context.Context, input *NewChainedProofLayer) (*ChainedProofLayer, error) {
	// Serialize receipt_entries to JSON if provided
	var receiptEntriesJSON []byte
	if len(input.ReceiptEntries) > 0 {
		var err error
		receiptEntriesJSON, err = json.Marshal(input.ReceiptEntries)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal receipt_entries: %w", err)
		}
	}

	query := `
		INSERT INTO chained_proof_layers (
			proof_id, layer_number, layer_name,
			bvn_partition, receipt_anchor,
			bvn_root, dn_root, anchor_sequence, bvn_partition_id,
			dn_block_hash, dn_block_height, consensus_timestamp,
			layer_json, source_hash, target_hash, receipt_entries, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW()
		)
		RETURNING layer_id, created_at`

	var layer ChainedProofLayer
	layer.ProofID = input.ProofID
	layer.LayerNumber = input.LayerNumber
	layer.LayerName = input.LayerName
	layer.BVNPartition = input.BVNPartition
	layer.ReceiptAnchor = input.ReceiptAnchor
	layer.BVNRoot = input.BVNRoot
	layer.DNRoot = input.DNRoot
	layer.AnchorSequence = input.AnchorSequence
	layer.BVNPartitionID = input.BVNPartitionID
	layer.DNBlockHash = input.DNBlockHash
	layer.DNBlockHeight = input.DNBlockHeight
	layer.ConsensusTimestamp = input.ConsensusTimestamp
	layer.LayerJSON = input.LayerJSON

	err := r.db.QueryRowContext(ctx, query,
		input.ProofID, input.LayerNumber, input.LayerName,
		input.BVNPartition, input.ReceiptAnchor,
		input.BVNRoot, input.DNRoot, input.AnchorSequence, input.BVNPartitionID,
		input.DNBlockHash, input.DNBlockHeight, input.ConsensusTimestamp,
		input.LayerJSON, input.SourceHash, input.TargetHash, receiptEntriesJSON,
	).Scan(&layer.LayerID, &layer.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create chained proof layer: %w", err)
	}

	return &layer, nil
}

// GetChainedProofLayers retrieves all layers for a proof
func (r *ProofArtifactRepository) GetChainedProofLayers(ctx context.Context, proofID uuid.UUID) ([]ChainedProofLayer, error) {
	query := `
		SELECT layer_id, proof_id, layer_number, layer_name,
			   bvn_partition, receipt_anchor,
			   bvn_root, dn_root, anchor_sequence, bvn_partition_id,
			   dn_block_hash, dn_block_height, consensus_timestamp,
			   layer_json, verified, verified_at, created_at
		FROM chained_proof_layers
		WHERE proof_id = $1
		ORDER BY layer_number`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("failed to query chained proof layers: %w", err)
	}
	defer rows.Close()

	var layers []ChainedProofLayer
	for rows.Next() {
		var l ChainedProofLayer
		if err := rows.Scan(
			&l.LayerID, &l.ProofID, &l.LayerNumber, &l.LayerName,
			&l.BVNPartition, &l.ReceiptAnchor,
			&l.BVNRoot, &l.DNRoot, &l.AnchorSequence, &l.BVNPartitionID,
			&l.DNBlockHash, &l.DNBlockHeight, &l.ConsensusTimestamp,
			&l.LayerJSON, &l.Verified, &l.VerifiedAt, &l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan chained proof layer: %w", err)
		}
		layers = append(layers, l)
	}

	return layers, nil
}

// ============================================================================
// GOVERNANCE PROOF LEVEL OPERATIONS
// ============================================================================

// CreateGovernanceProofLevel creates a new governance level record
func (r *ProofArtifactRepository) CreateGovernanceProofLevel(ctx context.Context, input *NewGovernanceProofLevel) (*GovernanceProofLevel, error) {
	query := `
		INSERT INTO governance_proof_levels (
			proof_id, gov_level, level_name,
			block_height, finality_timestamp, anchor_height, is_anchored,
			authority_url, key_page_count, threshold_m, threshold_n, signature_count,
			outcome_type, outcome_hash, binding_enforced,
			level_json, verified, verified_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
			CASE WHEN $17 = TRUE THEN NOW() ELSE NULL END, NOW()
		)
		RETURNING level_id, created_at`

	var level GovernanceProofLevel
	level.ProofID = input.ProofID
	level.GovLevel = input.GovLevel
	level.LevelName = input.LevelName
	level.BlockHeight = input.BlockHeight
	level.FinalityTimestamp = input.FinalityTimestamp
	level.AnchorHeight = input.AnchorHeight
	level.IsAnchored = input.IsAnchored
	level.AuthorityURL = input.AuthorityURL
	level.KeyPageCount = input.KeyPageCount
	level.ThresholdM = input.ThresholdM
	level.ThresholdN = input.ThresholdN
	level.SignatureCount = input.SignatureCount
	level.OutcomeType = input.OutcomeType
	level.OutcomeHash = input.OutcomeHash
	level.BindingEnforced = input.BindingEnforced
	level.LevelJSON = input.LevelJSON
	if input.Verified != nil {
		level.Verified = *input.Verified
	}

	err := r.db.QueryRowContext(ctx, query,
		input.ProofID, input.GovLevel, input.LevelName,
		input.BlockHeight, input.FinalityTimestamp, input.AnchorHeight, input.IsAnchored,
		input.AuthorityURL, input.KeyPageCount, input.ThresholdM, input.ThresholdN, input.SignatureCount,
		input.OutcomeType, input.OutcomeHash, input.BindingEnforced,
		input.LevelJSON, input.Verified,
	).Scan(&level.LevelID, &level.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create governance proof level: %w", err)
	}

	return &level, nil
}

// GetGovernanceProofLevels retrieves all governance levels for a proof
func (r *ProofArtifactRepository) GetGovernanceProofLevels(ctx context.Context, proofID uuid.UUID) ([]GovernanceProofLevel, error) {
	query := `
		SELECT level_id, proof_id, gov_level, level_name,
			   block_height, finality_timestamp, anchor_height, is_anchored,
			   authority_url, key_page_count, threshold_m, threshold_n, signature_count,
			   outcome_type, outcome_hash, binding_enforced,
			   level_json, verified, verified_at, created_at
		FROM governance_proof_levels
		WHERE proof_id = $1
		ORDER BY gov_level`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("failed to query governance proof levels: %w", err)
	}
	defer rows.Close()

	var levels []GovernanceProofLevel
	for rows.Next() {
		var l GovernanceProofLevel
		if err := rows.Scan(
			&l.LevelID, &l.ProofID, &l.GovLevel, &l.LevelName,
			&l.BlockHeight, &l.FinalityTimestamp, &l.AnchorHeight, &l.IsAnchored,
			&l.AuthorityURL, &l.KeyPageCount, &l.ThresholdM, &l.ThresholdN, &l.SignatureCount,
			&l.OutcomeType, &l.OutcomeHash, &l.BindingEnforced,
			&l.LevelJSON, &l.Verified, &l.VerifiedAt, &l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan governance proof level: %w", err)
		}
		levels = append(levels, l)
	}

	return levels, nil
}

// ============================================================================
// VALIDATOR ATTESTATION OPERATIONS
// ============================================================================

// CreateProofAttestation creates a new validator attestation for the proof_artifacts schema
func (r *ProofArtifactRepository) CreateProofAttestation(ctx context.Context, input *NewProofAttestation) (*ProofAttestation, error) {
	query := `
		INSERT INTO validator_attestations (
			proof_id, batch_id, validator_id, validator_pubkey,
			attested_hash, signature, anchor_tx_hash, merkle_root, block_number,
			signature_valid, attested_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()
		)
		RETURNING attestation_id, created_at`

	var att ProofAttestation
	att.ProofArtifactID = input.ProofArtifactID
	att.BatchID = input.BatchID
	att.ValidatorID = input.ValidatorID
	att.ValidatorPubkey = input.ValidatorPubkey
	att.AttestedHash = input.AttestedHash
	att.Signature = input.Signature
	att.AnchorTxHash = input.AnchorTxHash
	att.MerkleRoot = input.MerkleRoot
	att.BlockNumber = input.BlockNumber
	att.AttestedAt = input.AttestedAt
	if input.SignatureValid != nil {
		att.SignatureValid = *input.SignatureValid
	}

	err := r.db.QueryRowContext(ctx, query,
		input.ProofArtifactID, input.BatchID, input.ValidatorID, input.ValidatorPubkey,
		input.AttestedHash, input.Signature, input.AnchorTxHash, input.MerkleRoot, input.BlockNumber,
		input.SignatureValid, input.AttestedAt,
	).Scan(&att.AttestationID, &att.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create attestation: %w", err)
	}

	return &att, nil
}

// GetProofAttestationsByProof retrieves all attestations for a proof artifact
func (r *ProofArtifactRepository) GetProofAttestationsByProof(ctx context.Context, proofID uuid.UUID) ([]ProofAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, batch_id, validator_id, validator_pubkey,
			   attested_hash, signature, anchor_tx_hash, merkle_root, block_number,
			   signature_valid, verified_at, attested_at, created_at
		FROM validator_attestations
		WHERE proof_id = $1
		ORDER BY attested_at`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("failed to query attestations: %w", err)
	}
	defer rows.Close()

	var attestations []ProofAttestation
	for rows.Next() {
		var a ProofAttestation
		if err := rows.Scan(
			&a.AttestationID, &a.ProofArtifactID, &a.BatchID, &a.ValidatorID, &a.ValidatorPubkey,
			&a.AttestedHash, &a.Signature, &a.AnchorTxHash, &a.MerkleRoot, &a.BlockNumber,
			&a.SignatureValid, &a.VerifiedAt, &a.AttestedAt, &a.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan attestation: %w", err)
		}
		attestations = append(attestations, a)
	}

	return attestations, nil
}

// GetProofAttestationsByBatch retrieves all attestations for a batch
func (r *ProofArtifactRepository) GetProofAttestationsByBatch(ctx context.Context, batchID uuid.UUID) ([]ProofAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, batch_id, validator_id, validator_pubkey,
			   attested_hash, signature, anchor_tx_hash, merkle_root, block_number,
			   signature_valid, verified_at, attested_at, created_at
		FROM validator_attestations
		WHERE batch_id = $1
		ORDER BY attested_at`

	rows, err := r.db.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query attestations by batch: %w", err)
	}
	defer rows.Close()

	var attestations []ProofAttestation
	for rows.Next() {
		var a ProofAttestation
		if err := rows.Scan(
			&a.AttestationID, &a.ProofArtifactID, &a.BatchID, &a.ValidatorID, &a.ValidatorPubkey,
			&a.AttestedHash, &a.Signature, &a.AnchorTxHash, &a.MerkleRoot, &a.BlockNumber,
			&a.SignatureValid, &a.VerifiedAt, &a.AttestedAt, &a.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan attestation: %w", err)
		}
		attestations = append(attestations, a)
	}

	return attestations, nil
}

// CountValidAttestations counts valid attestations for a batch
func (r *ProofArtifactRepository) CountValidAttestations(ctx context.Context, batchID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM validator_attestations WHERE batch_id = $1 AND signature_valid = TRUE`
	var count int
	err := r.db.QueryRowContext(ctx, query, batchID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count valid attestations: %w", err)
	}
	return count, nil
}

// ============================================================================
// PROOF VERIFICATION OPERATIONS
// ============================================================================

// CreateVerificationRecord creates a verification audit log entry
func (r *ProofArtifactRepository) CreateVerificationRecord(ctx context.Context, proofID uuid.UUID, verificationType string, passed bool, errorMsg *string, verifierID *string, durationMS *int) (*ProofVerificationRecord, error) {
	query := `
		INSERT INTO verification_history (
			proof_id, verification_type, passed, error_message, verifier_id, duration_ms, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, NOW()
		)
		RETURNING verification_id, created_at`

	var v ProofVerificationRecord
	v.ProofID = proofID
	v.VerificationType = verificationType
	v.Passed = passed
	v.ErrorMessage = errorMsg
	v.VerifierID = verifierID
	v.DurationMS = durationMS

	err := r.db.QueryRowContext(ctx, query,
		proofID, verificationType, passed, errorMsg, verifierID, durationMS,
	).Scan(&v.VerificationID, &v.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create verification record: %w", err)
	}

	return &v, nil
}

// GetVerificationHistory retrieves verification history for a proof
func (r *ProofArtifactRepository) GetVerificationHistory(ctx context.Context, proofID uuid.UUID) ([]ProofVerificationRecord, error) {
	query := `
		SELECT verification_id, proof_id, verification_type, passed, error_message, error_code,
			   verifier_id, verification_method, duration_ms, artifacts_json, created_at
		FROM verification_history
		WHERE proof_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("failed to query verification history: %w", err)
	}
	defer rows.Close()

	var records []ProofVerificationRecord
	for rows.Next() {
		var v ProofVerificationRecord
		if err := rows.Scan(
			&v.VerificationID, &v.ProofID, &v.VerificationType, &v.Passed, &v.ErrorMessage, &v.ErrorCode,
			&v.VerifierID, &v.VerificationMethod, &v.DurationMS, &v.ArtifactsJSON, &v.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan verification record: %w", err)
		}
		records = append(records, v)
	}

	return records, nil
}

// ============================================================================
// FULL PROOF WITH DETAILS
// ============================================================================

// GetProofWithDetails retrieves a complete proof with all related records
func (r *ProofArtifactRepository) GetProofWithDetails(ctx context.Context, proofID uuid.UUID) (*ProofArtifactWithDetails, error) {
	// Get main proof
	proof, err := r.GetProofByID(ctx, proofID)
	if err != nil {
		return nil, err
	}
	if proof == nil {
		return nil, nil
	}

	result := &ProofArtifactWithDetails{ProofArtifact: *proof}

	// Get chained layers
	layers, err := r.GetChainedProofLayers(ctx, proofID)
	if err != nil {
		return nil, err
	}
	result.ChainedLayers = layers

	// Get governance levels
	govLevels, err := r.GetGovernanceProofLevels(ctx, proofID)
	if err != nil {
		return nil, err
	}
	result.GovernanceLevels = govLevels

	// Get attestations
	attestations, err := r.GetProofAttestationsByProof(ctx, proofID)
	if err != nil {
		return nil, err
	}
	result.Attestations = attestations

	// Get anchor reference
	anchorRef, err := r.GetAnchorReference(ctx, proofID)
	if err != nil {
		return nil, err
	}
	result.AnchorReference = anchorRef

	// Get verifications
	verifications, err := r.GetVerificationHistory(ctx, proofID)
	if err != nil {
		return nil, err
	}
	result.Verifications = verifications

	return result, nil
}

// CreateAnchorReference creates a new anchor reference record
func (r *ProofArtifactRepository) CreateAnchorReference(ctx context.Context, input *NewAnchorReference) (*AnchorReferenceRecord, error) {
	query := `
		INSERT INTO anchor_references (
			proof_id, target_chain, chain_id, network_name,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_timestamp,
			contract_address, confirmations, required_confirmations, is_confirmed, confirmed_at,
			gas_used, gas_price_wei, total_cost_wei, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW()
		)
		RETURNING reference_id, created_at`

	var ref AnchorReferenceRecord
	ref.ProofID = input.ProofID
	ref.TargetChain = input.TargetChain
	ref.ChainID = input.ChainID
	ref.NetworkName = input.NetworkName
	ref.AnchorTxHash = input.AnchorTxHash
	ref.AnchorBlockNumber = input.AnchorBlockNumber
	ref.AnchorBlockHash = input.AnchorBlockHash
	ref.AnchorTimestamp = input.AnchorTimestamp
	ref.ContractAddress = input.ContractAddress
	ref.Confirmations = input.Confirmations
	ref.RequiredConfirmations = input.RequiredConfirmations
	ref.IsConfirmed = input.IsConfirmed
	ref.ConfirmedAt = input.ConfirmedAt
	ref.GasUsed = input.GasUsed
	ref.GasPriceWei = input.GasPriceWei
	ref.TotalCostWei = input.TotalCostWei

	err := r.db.QueryRowContext(ctx, query,
		input.ProofID, input.TargetChain, input.ChainID, input.NetworkName,
		input.AnchorTxHash, input.AnchorBlockNumber, input.AnchorBlockHash, input.AnchorTimestamp,
		input.ContractAddress, input.Confirmations, input.RequiredConfirmations, input.IsConfirmed, input.ConfirmedAt,
		input.GasUsed, input.GasPriceWei, input.TotalCostWei,
	).Scan(&ref.ReferenceID, &ref.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create anchor reference: %w", err)
	}

	return &ref, nil
}

// GetAnchorReference retrieves anchor reference for a proof
func (r *ProofArtifactRepository) GetAnchorReference(ctx context.Context, proofID uuid.UUID) (*AnchorReferenceRecord, error) {
	query := `
		SELECT reference_id, proof_id, target_chain, chain_id, network_name,
			   anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_timestamp,
			   contract_address, confirmations, required_confirmations, is_confirmed, confirmed_at,
			   gas_used, gas_price_wei, total_cost_wei, created_at
		FROM anchor_references
		WHERE proof_id = $1`

	var ref AnchorReferenceRecord
	err := r.db.QueryRowContext(ctx, query, proofID).Scan(
		&ref.ReferenceID, &ref.ProofID, &ref.TargetChain, &ref.ChainID, &ref.NetworkName,
		&ref.AnchorTxHash, &ref.AnchorBlockNumber, &ref.AnchorBlockHash, &ref.AnchorTimestamp,
		&ref.ContractAddress, &ref.Confirmations, &ref.RequiredConfirmations, &ref.IsConfirmed, &ref.ConfirmedAt,
		&ref.GasUsed, &ref.GasPriceWei, &ref.TotalCostWei, &ref.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get anchor reference: %w", err)
	}

	return &ref, nil
}

// ============================================================================
// SYNC OPERATIONS (For Auditing Nodes)
// ============================================================================

// GetProofsModifiedSince retrieves proofs modified since a timestamp
func (r *ProofArtifactRepository) GetProofsModifiedSince(ctx context.Context, since time.Time, limit int) ([]ProofArtifact, error) {
	if limit <= 0 {
		limit = 1000
	}

	query := `
		SELECT proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			   batch_id, batch_position, anchor_id, anchor_tx_hash, anchor_block_number, anchor_chain,
			   merkle_root, leaf_hash, leaf_index, gov_level, proof_class, validator_id,
			   status, verification_status, created_at, anchored_at, verified_at,
			   artifact_json, artifact_hash
		FROM proof_artifacts
		WHERE created_at > $1 OR anchored_at > $1
		ORDER BY COALESCE(anchored_at, created_at)
		LIMIT $2`

	rows, err := r.db.QueryContext(ctx, query, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs modified since: %w", err)
	}
	defer rows.Close()

	var proofs []ProofArtifact
	for rows.Next() {
		var p ProofArtifact
		if err := rows.Scan(
			&p.ProofID, &p.ProofType, &p.ProofVersion, &p.AccumTxHash, &p.AccountURL,
			&p.BatchID, &p.BatchPosition, &p.AnchorID, &p.AnchorTxHash, &p.AnchorBlockNumber, &p.AnchorChain,
			&p.MerkleRoot, &p.LeafHash, &p.LeafIndex, &p.GovLevel, &p.ProofClass, &p.ValidatorID,
			&p.Status, &p.VerificationStatus, &p.CreatedAt, &p.AnchoredAt, &p.VerifiedAt,
			&p.ArtifactJSON, &p.ArtifactHash,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, p)
	}

	return proofs, nil
}

// GetBatchProofStats retrieves statistics for a batch
func (r *ProofArtifactRepository) GetBatchProofStats(ctx context.Context, batchID uuid.UUID) (*BatchProofStats, error) {
	query := `
		SELECT
			$1 as batch_id,
			COUNT(*) as proof_count,
			(SELECT COUNT(*) FROM validator_attestations WHERE batch_id = $1) as attestation_count,
			COUNT(*) FILTER (WHERE verification_status = 'verified') as verified_count,
			COUNT(*) FILTER (WHERE verification_status = 'failed') as failed_count
		FROM proof_artifacts
		WHERE batch_id = $1`

	var stats BatchProofStats
	err := r.db.QueryRowContext(ctx, query, batchID).Scan(
		&stats.BatchID, &stats.ProofCount, &stats.AttestationCount,
		&stats.VerifiedCount, &stats.FailedCount,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to get batch proof stats: %w", err)
	}

	return &stats, nil
}

// VerifyArtifactIntegrity checks if artifact hash matches stored hash
func (r *ProofArtifactRepository) VerifyArtifactIntegrity(ctx context.Context, proofID uuid.UUID) (bool, error) {
	proof, err := r.GetProofByID(ctx, proofID)
	if err != nil {
		return false, err
	}
	if proof == nil {
		return false, fmt.Errorf("proof not found: %s", proofID)
	}

	computedHash := sha256.Sum256(proof.ArtifactJSON)

	if len(proof.ArtifactHash) != len(computedHash[:]) {
		return false, nil
	}

	for i := range computedHash {
		if proof.ArtifactHash[i] != computedHash[i] {
			return false, nil
		}
	}

	return true, nil
}

// ============================================================================
// PROOF BUNDLE OPERATIONS
// ============================================================================

// CreateProofBundle creates a new proof bundle record
func (r *ProofArtifactRepository) CreateProofBundle(ctx context.Context, input *NewProofBundle) (*ProofBundle, error) {
	query := `
		INSERT INTO proof_bundles (
			proof_id, bundle_format, bundle_version,
			bundle_data, bundle_hash, bundle_size_bytes,
			includes_chained, includes_governance, includes_merkle, includes_anchor,
			attestation_count, expires_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()
		)
		RETURNING bundle_id, created_at`

	var bundle ProofBundle
	bundle.ProofID = input.ProofID
	bundle.BundleFormat = input.BundleFormat
	bundle.BundleVersion = input.BundleVersion
	bundle.BundleData = input.BundleData
	bundle.BundleHash = input.BundleHash
	bundle.BundleSizeBytes = input.BundleSizeBytes
	bundle.IncludesChained = input.IncludesChained
	bundle.IncludesGovernance = input.IncludesGovernance
	bundle.IncludesMerkle = input.IncludesMerkle
	bundle.IncludesAnchor = input.IncludesAnchor
	bundle.AttestationCount = input.AttestationCount
	bundle.ExpiresAt = input.ExpiresAt

	err := r.db.QueryRowContext(ctx, query,
		input.ProofID, input.BundleFormat, input.BundleVersion,
		input.BundleData, input.BundleHash, input.BundleSizeBytes,
		input.IncludesChained, input.IncludesGovernance, input.IncludesMerkle, input.IncludesAnchor,
		input.AttestationCount, input.ExpiresAt,
	).Scan(&bundle.BundleID, &bundle.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create proof bundle: %w", err)
	}

	return &bundle, nil
}

// GetProofBundleByID retrieves a bundle by its ID
func (r *ProofArtifactRepository) GetProofBundleByID(ctx context.Context, bundleID uuid.UUID) (*ProofBundle, error) {
	query := `
		SELECT bundle_id, proof_id, bundle_format, bundle_version,
			   bundle_data, bundle_hash, bundle_size_bytes,
			   includes_chained, includes_governance, includes_merkle, includes_anchor,
			   attestation_count, expires_at, created_at
		FROM proof_bundles
		WHERE bundle_id = $1`

	var bundle ProofBundle
	err := r.db.QueryRowContext(ctx, query, bundleID).Scan(
		&bundle.BundleID, &bundle.ProofID, &bundle.BundleFormat, &bundle.BundleVersion,
		&bundle.BundleData, &bundle.BundleHash, &bundle.BundleSizeBytes,
		&bundle.IncludesChained, &bundle.IncludesGovernance, &bundle.IncludesMerkle, &bundle.IncludesAnchor,
		&bundle.AttestationCount, &bundle.ExpiresAt, &bundle.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle: %w", err)
	}

	return &bundle, nil
}

// GetProofBundleByProofID retrieves the latest bundle for a proof
func (r *ProofArtifactRepository) GetProofBundleByProofID(ctx context.Context, proofID uuid.UUID) (*ProofBundle, error) {
	query := `
		SELECT bundle_id, proof_id, bundle_format, bundle_version,
			   bundle_data, bundle_hash, bundle_size_bytes,
			   includes_chained, includes_governance, includes_merkle, includes_anchor,
			   attestation_count, expires_at, created_at
		FROM proof_bundles
		WHERE proof_id = $1
		ORDER BY created_at DESC
		LIMIT 1`

	var bundle ProofBundle
	err := r.db.QueryRowContext(ctx, query, proofID).Scan(
		&bundle.BundleID, &bundle.ProofID, &bundle.BundleFormat, &bundle.BundleVersion,
		&bundle.BundleData, &bundle.BundleHash, &bundle.BundleSizeBytes,
		&bundle.IncludesChained, &bundle.IncludesGovernance, &bundle.IncludesMerkle, &bundle.IncludesAnchor,
		&bundle.AttestationCount, &bundle.ExpiresAt, &bundle.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle by proof ID: %w", err)
	}

	return &bundle, nil
}

// GetProofBundleByTxHash retrieves the latest bundle for a transaction
func (r *ProofArtifactRepository) GetProofBundleByTxHash(ctx context.Context, txHash string) (*ProofBundle, error) {
	query := `
		SELECT pb.bundle_id, pb.proof_id, pb.bundle_format, pb.bundle_version,
			   pb.bundle_data, pb.bundle_hash, pb.bundle_size_bytes,
			   pb.includes_chained, pb.includes_governance, pb.includes_merkle, pb.includes_anchor,
			   pb.attestation_count, pb.expires_at, pb.created_at
		FROM proof_bundles pb
		JOIN proof_artifacts pa ON pa.proof_id = pb.proof_id
		WHERE pa.accum_tx_hash = $1
		ORDER BY pb.created_at DESC
		LIMIT 1`

	var bundle ProofBundle
	err := r.db.QueryRowContext(ctx, query, txHash).Scan(
		&bundle.BundleID, &bundle.ProofID, &bundle.BundleFormat, &bundle.BundleVersion,
		&bundle.BundleData, &bundle.BundleHash, &bundle.BundleSizeBytes,
		&bundle.IncludesChained, &bundle.IncludesGovernance, &bundle.IncludesMerkle, &bundle.IncludesAnchor,
		&bundle.AttestationCount, &bundle.ExpiresAt, &bundle.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle by tx hash: %w", err)
	}

	return &bundle, nil
}

// ============================================================================
// CUSTODY CHAIN OPERATIONS
// ============================================================================

// CreateCustodyChainEvent creates a new custody chain audit event
func (r *ProofArtifactRepository) CreateCustodyChainEvent(ctx context.Context, input *NewCustodyChainEvent) (*CustodyChainEvent, error) {
	query := `
		INSERT INTO custody_chain_events (
			proof_id, event_type, event_timestamp,
			actor_type, actor_id, previous_hash, current_hash,
			event_details, signature
		) VALUES (
			$1, $2, NOW(), $3, $4, $5, $6, $7, $8
		)
		RETURNING event_id, event_timestamp, created_at`

	var event CustodyChainEvent
	event.ProofID = input.ProofID
	event.EventType = input.EventType
	event.ActorType = input.ActorType
	event.ActorID = input.ActorID
	event.PreviousHash = input.PreviousHash
	event.CurrentHash = input.CurrentHash
	event.EventDetails = input.EventDetails
	event.Signature = input.Signature

	err := r.db.QueryRowContext(ctx, query,
		input.ProofID, input.EventType,
		input.ActorType, input.ActorID, input.PreviousHash, input.CurrentHash,
		input.EventDetails, input.Signature,
	).Scan(&event.EventID, &event.EventTimestamp, &event.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create custody chain event: %w", err)
	}

	return &event, nil
}

// GetCustodyChainEvents retrieves custody chain events for a proof
func (r *ProofArtifactRepository) GetCustodyChainEvents(ctx context.Context, proofID uuid.UUID) ([]CustodyChainEvent, error) {
	query := `
		SELECT event_id, proof_id, event_type, event_timestamp,
			   actor_type, actor_id, previous_hash, current_hash,
			   event_details, signature, created_at
		FROM custody_chain_events
		WHERE proof_id = $1
		ORDER BY event_timestamp ASC`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("failed to query custody chain events: %w", err)
	}
	defer rows.Close()

	var events []CustodyChainEvent
	for rows.Next() {
		var e CustodyChainEvent
		if err := rows.Scan(
			&e.EventID, &e.ProofID, &e.EventType, &e.EventTimestamp,
			&e.ActorType, &e.ActorID, &e.PreviousHash, &e.CurrentHash,
			&e.EventDetails, &e.Signature, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan custody chain event: %w", err)
		}
		events = append(events, e)
	}

	return events, nil
}

// GetLatestCustodyHash retrieves the latest custody chain hash for a proof
func (r *ProofArtifactRepository) GetLatestCustodyHash(ctx context.Context, proofID uuid.UUID) ([]byte, error) {
	query := `
		SELECT current_hash
		FROM custody_chain_events
		WHERE proof_id = $1
		ORDER BY event_timestamp DESC
		LIMIT 1`

	var hash []byte
	err := r.db.QueryRowContext(ctx, query, proofID).Scan(&hash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest custody hash: %w", err)
	}

	return hash, nil
}

// ============================================================================
// BULK EXPORT OPERATIONS
// ============================================================================

// GetProofsForBulkExport retrieves proofs for bulk export with filters
func (r *ProofArtifactRepository) GetProofsForBulkExport(ctx context.Context, accountURLs []string, startDate, endDate time.Time, limit int) ([]ProofArtifactWithDetails, error) {
	if limit <= 0 {
		limit = 10000
	}
	if limit > 100000 {
		limit = 100000
	}

	// Build account URL filter
	var args []interface{}
	argIndex := 1
	accountFilter := ""
	if len(accountURLs) > 0 {
		placeholders := make([]string, len(accountURLs))
		for i, url := range accountURLs {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, url)
			argIndex++
		}
		accountFilter = "AND pa.account_url IN (" + strings.Join(placeholders, ", ") + ")"
	}

	query := fmt.Sprintf(`
		SELECT pa.proof_id, pa.proof_type, pa.proof_version, pa.accum_tx_hash, pa.account_url,
			   pa.batch_id, pa.batch_position, pa.anchor_id, pa.anchor_tx_hash, pa.anchor_block_number, pa.anchor_chain,
			   pa.merkle_root, pa.leaf_hash, pa.leaf_index, pa.gov_level, pa.proof_class, pa.validator_id,
			   pa.status, pa.verification_status, pa.created_at, pa.anchored_at, pa.verified_at,
			   pa.artifact_json, pa.artifact_hash
		FROM proof_artifacts pa
		WHERE pa.created_at >= $%d AND pa.created_at <= $%d
		%s
		ORDER BY pa.created_at
		LIMIT $%d`, argIndex, argIndex+1, accountFilter, argIndex+2)

	args = append(args, startDate, endDate, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs for export: %w", err)
	}
	defer rows.Close()

	var results []ProofArtifactWithDetails
	for rows.Next() {
		var p ProofArtifact
		if err := rows.Scan(
			&p.ProofID, &p.ProofType, &p.ProofVersion, &p.AccumTxHash, &p.AccountURL,
			&p.BatchID, &p.BatchPosition, &p.AnchorID, &p.AnchorTxHash, &p.AnchorBlockNumber, &p.AnchorChain,
			&p.MerkleRoot, &p.LeafHash, &p.LeafIndex, &p.GovLevel, &p.ProofClass, &p.ValidatorID,
			&p.Status, &p.VerificationStatus, &p.CreatedAt, &p.AnchoredAt, &p.VerifiedAt,
			&p.ArtifactJSON, &p.ArtifactHash,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}

		// Get related details for each proof
		details, err := r.GetProofWithDetails(ctx, p.ProofID)
		if err != nil {
			return nil, fmt.Errorf("failed to get proof details: %w", err)
		}
		if details != nil {
			results = append(results, *details)
		}
	}

	return results, nil
}

// RecordBundleDownloadLegacy records a bundle download for auditing (legacy signature)
func (r *ProofArtifactRepository) RecordBundleDownloadLegacy(ctx context.Context, bundleID uuid.UUID, apiKeyID *uuid.UUID, clientIP, userAgent string, responseCode, bytesSent int) error {
	query := `
		INSERT INTO bundle_downloads (
			bundle_id, api_key_id, client_ip, user_agent,
			response_code, bytes_sent, downloaded_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())`

	_, err := r.db.ExecContext(ctx, query, bundleID, apiKeyID, clientIP, userAgent, responseCode, bytesSent)
	if err != nil {
		return fmt.Errorf("failed to record bundle download: %w", err)
	}

	return nil
}

// RecordBundleDownload records a bundle download for auditing using NewBundleDownload type
func (r *ProofArtifactRepository) RecordBundleDownload(ctx context.Context, input *NewBundleDownload) error {
	query := `
		INSERT INTO bundle_downloads (
			bundle_id, api_key_id, client_ip, user_agent,
			response_code, bytes_sent, downloaded_at
		) VALUES ($1, $2, $3, $4, $5, $6, NOW())`

	var userAgent string
	if input.UserAgent != nil {
		userAgent = *input.UserAgent
	}

	_, err := r.db.ExecContext(ctx, query, input.BundleID, input.APIKeyID, input.ClientIP, userAgent, input.ResponseCode, input.BytesSent)
	if err != nil {
		return fmt.Errorf("failed to record bundle download: %w", err)
	}

	return nil
}

// ============================================================================
// LEVEL 4: EXTERNAL CHAIN RESULT OPERATIONS
// ============================================================================

// SaveExternalChainResult creates a new external chain execution result
func (r *ProofArtifactRepository) SaveExternalChainResult(ctx context.Context, input *NewExternalChainResult) (*ExternalChainResultRecord, error) {
	query := `
		INSERT INTO external_chain_results (
			proof_id, chain_id, chain_name, block_number, block_hash, transaction_hash,
			execution_status, gas_used, return_data,
			storage_proof_json, storage_proof_hash,
			sequence_number, previous_result_hash, result_hash,
			anchor_proof_hash, artifact_json, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW()
		)
		RETURNING result_id, created_at`

	var result ExternalChainResultRecord
	result.ProofID = input.ProofID
	result.ChainID = input.ChainID
	result.ChainName = input.ChainName
	result.BlockNumber = input.BlockNumber
	result.BlockHash = input.BlockHash
	result.TransactionHash = input.TransactionHash
	result.ExecutionStatus = input.ExecutionStatus
	result.GasUsed = input.GasUsed
	result.ReturnData = input.ReturnData
	result.StorageProofJSON = input.StorageProofJSON
	result.StorageProofHash = input.StorageProofHash
	result.SequenceNumber = input.SequenceNumber
	result.PreviousResultHash = input.PreviousResultHash
	result.ResultHash = input.ResultHash
	result.AnchorProofHash = input.AnchorProofHash
	result.ArtifactJSON = input.ArtifactJSON

	err := r.db.QueryRowContext(ctx, query,
		input.ProofID, input.ChainID, input.ChainName, input.BlockNumber, input.BlockHash, input.TransactionHash,
		input.ExecutionStatus, input.GasUsed, input.ReturnData,
		input.StorageProofJSON, input.StorageProofHash,
		input.SequenceNumber, input.PreviousResultHash, input.ResultHash,
		input.AnchorProofHash, input.ArtifactJSON,
	).Scan(&result.ResultID, &result.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to save external chain result: %w", err)
	}

	return &result, nil
}

// ExternalChainResultInput matches the actual database schema for external_chain_results
type ExternalChainResultInput struct {
	ProofID              *uuid.UUID // Optional FK to proof_artifacts
	BundleID             []byte
	OperationID          []byte
	ChainType            string // ethereum, bitcoin, solana, polygon
	ChainID              int64
	NetworkName          string
	TxHash               []byte
	TxIndex              int
	TxGasUsed            int64
	TxFromAddress        []byte
	TxToAddress          []byte
	BlockNumber          int64
	BlockHash            []byte
	BlockTimestamp       time.Time
	StateRoot            []byte
	TransactionsRoot     []byte
	ReceiptsRoot         []byte
	ExecutionStatus      int // 0 or 1
	ExecutionSuccess     bool
	RevertReason         string
	ContractAddress      []byte
	LogsJSON             json.RawMessage
	ConfirmationBlocks    int
	RequiredConfirmations int
	IsFinalized           bool
	FinalizedAt           *time.Time // Set when IsFinalized is true
	ResultHash            []byte
	ObserverValidatorID   string
	ObservedAt            time.Time
}

// SaveExternalChainResultV2 creates a new external chain execution result matching the actual schema
func (r *ProofArtifactRepository) SaveExternalChainResultV2(ctx context.Context, input *ExternalChainResultInput) (uuid.UUID, error) {
	query := `
		INSERT INTO external_chain_results (
			proof_id, bundle_id, operation_id, chain_type, chain_id, network_name,
			tx_hash, tx_index, tx_gas_used, tx_from_address, tx_to_address,
			block_number, block_hash, block_timestamp,
			state_root, transactions_root, receipts_root,
			execution_status, execution_success, revert_reason, contract_address, logs_json,
			confirmation_blocks, required_confirmations, is_finalized, finalized_at,
			result_hash, observer_validator_id, observed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29
		)
		RETURNING result_id`

	var resultID uuid.UUID
	err := r.db.QueryRowContext(ctx, query,
		input.ProofID, input.BundleID, input.OperationID, input.ChainType, input.ChainID, input.NetworkName,
		input.TxHash, input.TxIndex, input.TxGasUsed, input.TxFromAddress, input.TxToAddress,
		input.BlockNumber, input.BlockHash, input.BlockTimestamp,
		input.StateRoot, input.TransactionsRoot, input.ReceiptsRoot,
		input.ExecutionStatus, input.ExecutionSuccess, input.RevertReason, input.ContractAddress, input.LogsJSON,
		input.ConfirmationBlocks, input.RequiredConfirmations, input.IsFinalized, input.FinalizedAt,
		input.ResultHash, input.ObserverValidatorID, input.ObservedAt,
	).Scan(&resultID)

	if err != nil {
		return uuid.UUID{}, fmt.Errorf("failed to save external chain result: %w", err)
	}

	return resultID, nil
}

// GetExternalChainResultByID retrieves an external chain result by ID
func (r *ProofArtifactRepository) GetExternalChainResultByID(ctx context.Context, resultID uuid.UUID) (*ExternalChainResultRecord, error) {
	query := `
		SELECT result_id, proof_id, chain_id, chain_name, block_number, block_hash, transaction_hash,
			   execution_status, gas_used, return_data,
			   storage_proof_json, storage_proof_hash,
			   sequence_number, previous_result_hash, result_hash,
			   anchor_proof_hash, artifact_json, verified, verified_at, created_at
		FROM external_chain_results
		WHERE result_id = $1`

	var result ExternalChainResultRecord
	err := r.db.QueryRowContext(ctx, query, resultID).Scan(
		&result.ResultID, &result.ProofID, &result.ChainID, &result.ChainName, &result.BlockNumber, &result.BlockHash, &result.TransactionHash,
		&result.ExecutionStatus, &result.GasUsed, &result.ReturnData,
		&result.StorageProofJSON, &result.StorageProofHash,
		&result.SequenceNumber, &result.PreviousResultHash, &result.ResultHash,
		&result.AnchorProofHash, &result.ArtifactJSON, &result.Verified, &result.VerifiedAt, &result.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get external chain result: %w", err)
	}

	return &result, nil
}

// GetExternalChainResultsByProof retrieves all execution results for a proof
func (r *ProofArtifactRepository) GetExternalChainResultsByProof(ctx context.Context, proofID uuid.UUID) ([]ExternalChainResultRecord, error) {
	query := `
		SELECT result_id, proof_id, chain_id, chain_name, block_number, block_hash, transaction_hash,
			   execution_status, gas_used, return_data,
			   storage_proof_json, storage_proof_hash,
			   sequence_number, previous_result_hash, result_hash,
			   anchor_proof_hash, artifact_json, verified, verified_at, created_at
		FROM external_chain_results
		WHERE proof_id = $1
		ORDER BY sequence_number ASC`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("failed to query external chain results: %w", err)
	}
	defer rows.Close()

	var results []ExternalChainResultRecord
	for rows.Next() {
		var result ExternalChainResultRecord
		if err := rows.Scan(
			&result.ResultID, &result.ProofID, &result.ChainID, &result.ChainName, &result.BlockNumber, &result.BlockHash, &result.TransactionHash,
			&result.ExecutionStatus, &result.GasUsed, &result.ReturnData,
			&result.StorageProofJSON, &result.StorageProofHash,
			&result.SequenceNumber, &result.PreviousResultHash, &result.ResultHash,
			&result.AnchorProofHash, &result.ArtifactJSON, &result.Verified, &result.VerifiedAt, &result.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan external chain result: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}

// GetLatestExternalChainResult retrieves the most recent result for hash chain linking
func (r *ProofArtifactRepository) GetLatestExternalChainResult(ctx context.Context, proofID uuid.UUID) (*ExternalChainResultRecord, error) {
	query := `
		SELECT result_id, proof_id, chain_id, chain_name, block_number, block_hash, transaction_hash,
			   execution_status, gas_used, return_data,
			   storage_proof_json, storage_proof_hash,
			   sequence_number, previous_result_hash, result_hash,
			   anchor_proof_hash, artifact_json, verified, verified_at, created_at
		FROM external_chain_results
		WHERE proof_id = $1
		ORDER BY sequence_number DESC
		LIMIT 1`

	var result ExternalChainResultRecord
	err := r.db.QueryRowContext(ctx, query, proofID).Scan(
		&result.ResultID, &result.ProofID, &result.ChainID, &result.ChainName, &result.BlockNumber, &result.BlockHash, &result.TransactionHash,
		&result.ExecutionStatus, &result.GasUsed, &result.ReturnData,
		&result.StorageProofJSON, &result.StorageProofHash,
		&result.SequenceNumber, &result.PreviousResultHash, &result.ResultHash,
		&result.AnchorProofHash, &result.ArtifactJSON, &result.Verified, &result.VerifiedAt, &result.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest external chain result: %w", err)
	}

	return &result, nil
}

// VerifyExternalChainResultHashChain verifies the hash chain integrity for a proof's results
func (r *ProofArtifactRepository) VerifyExternalChainResultHashChain(ctx context.Context, proofID uuid.UUID) (bool, error) {
	results, err := r.GetExternalChainResultsByProof(ctx, proofID)
	if err != nil {
		return false, err
	}

	if len(results) == 0 {
		return true, nil // Empty chain is valid
	}

	// Verify hash chain: each result's PreviousResultHash should match previous result's ResultHash
	for i := 1; i < len(results); i++ {
		prev := results[i-1]
		curr := results[i]

		// Check previous hash linkage
		if len(curr.PreviousResultHash) != len(prev.ResultHash) {
			return false, nil
		}
		for j := range curr.PreviousResultHash {
			if curr.PreviousResultHash[j] != prev.ResultHash[j] {
				return false, nil
			}
		}

		// Check sequence number continuity
		if curr.SequenceNumber != prev.SequenceNumber+1 {
			return false, nil
		}
	}

	return true, nil
}

// ============================================================================
// LEVEL 4: BLS ATTESTATION OPERATIONS
// ============================================================================

// SaveBLSAttestation creates a new individual BLS attestation
func (r *ProofArtifactRepository) SaveBLSAttestation(ctx context.Context, input *NewBLSAttestation) (*BLSAttestationRecord, error) {
	query := `
		INSERT INTO bls_attestations (
			result_id, snapshot_id, validator_id, public_key,
			message_hash, signature, weight, subgroup_valid,
			attested_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()
		)
		RETURNING attestation_id, created_at`

	var att BLSAttestationRecord
	att.ResultID = input.ResultID
	att.SnapshotID = input.SnapshotID
	att.ValidatorID = input.ValidatorID
	att.PublicKey = input.PublicKey
	att.MessageHash = input.MessageHash
	att.Signature = input.Signature
	att.Weight = input.Weight
	att.SubgroupValid = input.SubgroupValid
	att.AttestedAt = input.AttestedAt

	err := r.db.QueryRowContext(ctx, query,
		input.ResultID, input.SnapshotID, input.ValidatorID, input.PublicKey,
		input.MessageHash, input.Signature, input.Weight, input.SubgroupValid,
		input.AttestedAt,
	).Scan(&att.AttestationID, &att.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to save BLS attestation: %w", err)
	}

	return &att, nil
}

// GetBLSAttestationByID retrieves a BLS attestation by ID
func (r *ProofArtifactRepository) GetBLSAttestationByID(ctx context.Context, attestationID uuid.UUID) (*BLSAttestationRecord, error) {
	query := `
		SELECT attestation_id, result_id, snapshot_id, validator_id, public_key,
			   message_hash, signature, weight, subgroup_valid,
			   signature_valid, verified_at, attested_at, created_at
		FROM bls_attestations
		WHERE attestation_id = $1`

	var att BLSAttestationRecord
	err := r.db.QueryRowContext(ctx, query, attestationID).Scan(
		&att.AttestationID, &att.ResultID, &att.SnapshotID, &att.ValidatorID, &att.PublicKey,
		&att.MessageHash, &att.Signature, &att.Weight, &att.SubgroupValid,
		&att.SignatureValid, &att.VerifiedAt, &att.AttestedAt, &att.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get BLS attestation: %w", err)
	}

	return &att, nil
}

// GetBLSAttestationsByResult retrieves all BLS attestations for a result
func (r *ProofArtifactRepository) GetBLSAttestationsByResult(ctx context.Context, resultID uuid.UUID) ([]BLSAttestationRecord, error) {
	query := `
		SELECT attestation_id, result_id, snapshot_id, validator_id, public_key,
			   message_hash, signature, weight, subgroup_valid,
			   signature_valid, verified_at, attested_at, created_at
		FROM bls_attestations
		WHERE result_id = $1
		ORDER BY attested_at ASC`

	rows, err := r.db.QueryContext(ctx, query, resultID)
	if err != nil {
		return nil, fmt.Errorf("failed to query BLS attestations: %w", err)
	}
	defer rows.Close()

	var attestations []BLSAttestationRecord
	for rows.Next() {
		var att BLSAttestationRecord
		if err := rows.Scan(
			&att.AttestationID, &att.ResultID, &att.SnapshotID, &att.ValidatorID, &att.PublicKey,
			&att.MessageHash, &att.Signature, &att.Weight, &att.SubgroupValid,
			&att.SignatureValid, &att.VerifiedAt, &att.AttestedAt, &att.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan BLS attestation: %w", err)
		}
		attestations = append(attestations, att)
	}

	return attestations, nil
}

// UpdateBLSAttestationVerified updates the verification status of a BLS attestation
func (r *ProofArtifactRepository) UpdateBLSAttestationVerified(ctx context.Context, attestationID uuid.UUID, valid bool) error {
	query := `
		UPDATE bls_attestations
		SET signature_valid = $1, verified_at = NOW()
		WHERE attestation_id = $2`

	result, err := r.db.ExecContext(ctx, query, valid, attestationID)
	if err != nil {
		return fmt.Errorf("failed to update BLS attestation verified: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("BLS attestation not found: %s", attestationID)
	}

	return nil
}

// VerifyBLSAttestationMessageConsistency checks if all attestations for a result signed the same message
func (r *ProofArtifactRepository) VerifyBLSAttestationMessageConsistency(ctx context.Context, resultID uuid.UUID) (bool, error) {
	attestations, err := r.GetBLSAttestationsByResult(ctx, resultID)
	if err != nil {
		return false, err
	}

	if len(attestations) == 0 {
		return true, nil // No attestations to check
	}

	expectedHash := attestations[0].MessageHash
	for i := 1; i < len(attestations); i++ {
		if len(attestations[i].MessageHash) != len(expectedHash) {
			return false, nil
		}
		for j := range expectedHash {
			if attestations[i].MessageHash[j] != expectedHash[j] {
				return false, nil
			}
		}
	}

	return true, nil
}

// ============================================================================
// LEVEL 4: AGGREGATED ATTESTATION OPERATIONS
// ============================================================================

// SaveAggregatedAttestation creates a new aggregated BLS attestation
func (r *ProofArtifactRepository) SaveAggregatedAttestation(ctx context.Context, input *NewAggregatedAttestation) (*AggregatedAttestationRecord, error) {
	query := `
		INSERT INTO aggregated_attestations (
			result_id, snapshot_id, message_hash,
			aggregated_signature, aggregated_public_key,
			participant_ids, participant_count,
			total_weight, threshold_weight, achieved_weight,
			threshold_met, message_consistency_valid,
			aggregated_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW()
		)
		RETURNING aggregation_id, created_at`

	var agg AggregatedAttestationRecord
	agg.ResultID = input.ResultID
	agg.SnapshotID = input.SnapshotID
	agg.MessageHash = input.MessageHash
	agg.AggregatedSignature = input.AggregatedSignature
	agg.AggregatedPublicKey = input.AggregatedPublicKey
	agg.ParticipantIDs = input.ParticipantIDs
	agg.ParticipantCount = input.ParticipantCount
	agg.TotalWeight = input.TotalWeight
	agg.ThresholdWeight = input.ThresholdWeight
	agg.AchievedWeight = input.AchievedWeight
	agg.ThresholdMet = input.ThresholdMet
	agg.MessageConsistencyValid = input.MessageConsistencyValid
	agg.AggregatedAt = input.AggregatedAt

	err := r.db.QueryRowContext(ctx, query,
		input.ResultID, input.SnapshotID, input.MessageHash,
		input.AggregatedSignature, input.AggregatedPublicKey,
		input.ParticipantIDs, input.ParticipantCount,
		input.TotalWeight, input.ThresholdWeight, input.AchievedWeight,
		input.ThresholdMet, input.MessageConsistencyValid,
		input.AggregatedAt,
	).Scan(&agg.AggregationID, &agg.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to save aggregated attestation: %w", err)
	}

	return &agg, nil
}

// GetAggregatedAttestationByID retrieves an aggregated attestation by ID
func (r *ProofArtifactRepository) GetAggregatedAttestationByID(ctx context.Context, aggregationID uuid.UUID) (*AggregatedAttestationRecord, error) {
	query := `
		SELECT aggregation_id, result_id, snapshot_id, message_hash,
			   aggregated_signature, aggregated_public_key,
			   participant_ids, participant_count,
			   total_weight, threshold_weight, achieved_weight,
			   threshold_met, message_consistency_valid,
			   aggregation_valid, verified_at, aggregated_at, created_at
		FROM aggregated_attestations
		WHERE aggregation_id = $1`

	var agg AggregatedAttestationRecord
	err := r.db.QueryRowContext(ctx, query, aggregationID).Scan(
		&agg.AggregationID, &agg.ResultID, &agg.SnapshotID, &agg.MessageHash,
		&agg.AggregatedSignature, &agg.AggregatedPublicKey,
		&agg.ParticipantIDs, &agg.ParticipantCount,
		&agg.TotalWeight, &agg.ThresholdWeight, &agg.AchievedWeight,
		&agg.ThresholdMet, &agg.MessageConsistencyValid,
		&agg.AggregationValid, &agg.VerifiedAt, &agg.AggregatedAt, &agg.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregated attestation: %w", err)
	}

	return &agg, nil
}

// GetAggregatedAttestationByResult retrieves the aggregated attestation for a result
func (r *ProofArtifactRepository) GetAggregatedAttestationByResult(ctx context.Context, resultID uuid.UUID) (*AggregatedAttestationRecord, error) {
	query := `
		SELECT aggregation_id, result_id, snapshot_id, message_hash,
			   aggregated_signature, aggregated_public_key,
			   participant_ids, participant_count,
			   total_weight, threshold_weight, achieved_weight,
			   threshold_met, message_consistency_valid,
			   aggregation_valid, verified_at, aggregated_at, created_at
		FROM aggregated_attestations
		WHERE result_id = $1
		ORDER BY aggregated_at DESC
		LIMIT 1`

	var agg AggregatedAttestationRecord
	err := r.db.QueryRowContext(ctx, query, resultID).Scan(
		&agg.AggregationID, &agg.ResultID, &agg.SnapshotID, &agg.MessageHash,
		&agg.AggregatedSignature, &agg.AggregatedPublicKey,
		&agg.ParticipantIDs, &agg.ParticipantCount,
		&agg.TotalWeight, &agg.ThresholdWeight, &agg.AchievedWeight,
		&agg.ThresholdMet, &agg.MessageConsistencyValid,
		&agg.AggregationValid, &agg.VerifiedAt, &agg.AggregatedAt, &agg.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregated attestation by result: %w", err)
	}

	return &agg, nil
}

// UpdateAggregatedAttestationVerified updates the verification status
func (r *ProofArtifactRepository) UpdateAggregatedAttestationVerified(ctx context.Context, aggregationID uuid.UUID, valid bool) error {
	query := `
		UPDATE aggregated_attestations
		SET aggregation_valid = $1, verified_at = NOW()
		WHERE aggregation_id = $2`

	result, err := r.db.ExecContext(ctx, query, valid, aggregationID)
	if err != nil {
		return fmt.Errorf("failed to update aggregated attestation verified: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("aggregated attestation not found: %s", aggregationID)
	}

	return nil
}

// ============================================================================
// LEVEL 4: VALIDATOR SET SNAPSHOT OPERATIONS
// ============================================================================

// SaveValidatorSetSnapshot creates a new validator set snapshot
func (r *ProofArtifactRepository) SaveValidatorSetSnapshot(ctx context.Context, input *NewValidatorSetSnapshot) (*ValidatorSetSnapshotRecord, error) {
	query := `
		INSERT INTO validator_set_snapshots (
			block_number, block_hash, validators_json,
			validator_root, validator_count, total_weight, threshold_weight,
			snapshot_hash, chain_id, chain_name, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()
		)
		RETURNING snapshot_id, created_at`

	var snapshot ValidatorSetSnapshotRecord
	snapshot.BlockNumber = input.BlockNumber
	snapshot.BlockHash = input.BlockHash
	snapshot.ValidatorsJSON = input.ValidatorsJSON
	snapshot.ValidatorRoot = input.ValidatorRoot
	snapshot.ValidatorCount = input.ValidatorCount
	snapshot.TotalWeight = input.TotalWeight
	snapshot.ThresholdWeight = input.ThresholdWeight
	snapshot.SnapshotHash = input.SnapshotHash
	snapshot.ChainID = input.ChainID
	snapshot.ChainName = input.ChainName

	err := r.db.QueryRowContext(ctx, query,
		input.BlockNumber, input.BlockHash, input.ValidatorsJSON,
		input.ValidatorRoot, input.ValidatorCount, input.TotalWeight, input.ThresholdWeight,
		input.SnapshotHash, input.ChainID, input.ChainName,
	).Scan(&snapshot.SnapshotID, &snapshot.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to save validator set snapshot: %w", err)
	}

	return &snapshot, nil
}

// GetValidatorSetSnapshotByID retrieves a snapshot by ID
func (r *ProofArtifactRepository) GetValidatorSetSnapshotByID(ctx context.Context, snapshotID uuid.UUID) (*ValidatorSetSnapshotRecord, error) {
	query := `
		SELECT snapshot_id, block_number, block_hash, validators_json,
			   validator_root, validator_count, total_weight, threshold_weight,
			   snapshot_hash, chain_id, chain_name, created_at
		FROM validator_set_snapshots
		WHERE snapshot_id = $1`

	var snapshot ValidatorSetSnapshotRecord
	err := r.db.QueryRowContext(ctx, query, snapshotID).Scan(
		&snapshot.SnapshotID, &snapshot.BlockNumber, &snapshot.BlockHash, &snapshot.ValidatorsJSON,
		&snapshot.ValidatorRoot, &snapshot.ValidatorCount, &snapshot.TotalWeight, &snapshot.ThresholdWeight,
		&snapshot.SnapshotHash, &snapshot.ChainID, &snapshot.ChainName, &snapshot.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get validator set snapshot: %w", err)
	}

	return &snapshot, nil
}

// GetValidatorSetSnapshotByHash retrieves a snapshot by its hash
func (r *ProofArtifactRepository) GetValidatorSetSnapshotByHash(ctx context.Context, snapshotHash []byte) (*ValidatorSetSnapshotRecord, error) {
	query := `
		SELECT snapshot_id, block_number, block_hash, validators_json,
			   validator_root, validator_count, total_weight, threshold_weight,
			   snapshot_hash, chain_id, chain_name, created_at
		FROM validator_set_snapshots
		WHERE snapshot_hash = $1`

	var snapshot ValidatorSetSnapshotRecord
	err := r.db.QueryRowContext(ctx, query, snapshotHash).Scan(
		&snapshot.SnapshotID, &snapshot.BlockNumber, &snapshot.BlockHash, &snapshot.ValidatorsJSON,
		&snapshot.ValidatorRoot, &snapshot.ValidatorCount, &snapshot.TotalWeight, &snapshot.ThresholdWeight,
		&snapshot.SnapshotHash, &snapshot.ChainID, &snapshot.ChainName, &snapshot.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get validator set snapshot by hash: %w", err)
	}

	return &snapshot, nil
}

// GetLatestValidatorSetSnapshot retrieves the most recent snapshot for a chain
func (r *ProofArtifactRepository) GetLatestValidatorSetSnapshot(ctx context.Context, chainID string) (*ValidatorSetSnapshotRecord, error) {
	query := `
		SELECT snapshot_id, block_number, block_hash, validators_json,
			   validator_root, validator_count, total_weight, threshold_weight,
			   snapshot_hash, chain_id, chain_name, created_at
		FROM validator_set_snapshots
		WHERE chain_id = $1
		ORDER BY block_number DESC
		LIMIT 1`

	var snapshot ValidatorSetSnapshotRecord
	err := r.db.QueryRowContext(ctx, query, chainID).Scan(
		&snapshot.SnapshotID, &snapshot.BlockNumber, &snapshot.BlockHash, &snapshot.ValidatorsJSON,
		&snapshot.ValidatorRoot, &snapshot.ValidatorCount, &snapshot.TotalWeight, &snapshot.ThresholdWeight,
		&snapshot.SnapshotHash, &snapshot.ChainID, &snapshot.ChainName, &snapshot.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest validator set snapshot: %w", err)
	}

	return &snapshot, nil
}

// ============================================================================
// LEVEL 4: PROOF CYCLE COMPLETION OPERATIONS
// ============================================================================

// SaveProofCycleCompletion creates a new proof cycle completion record
func (r *ProofArtifactRepository) SaveProofCycleCompletion(ctx context.Context, input *NewProofCycleCompletion) (*ProofCycleCompletionRecord, error) {
	query := `
		INSERT INTO proof_cycle_completions (
			proof_id, created_at, updated_at
		) VALUES (
			$1, NOW(), NOW()
		)
		RETURNING completion_id, created_at, updated_at`

	var completion ProofCycleCompletionRecord
	completion.ProofID = input.ProofID

	err := r.db.QueryRowContext(ctx, query, input.ProofID).Scan(
		&completion.CompletionID, &completion.CreatedAt, &completion.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to save proof cycle completion: %w", err)
	}

	return &completion, nil
}

// GetProofCycleCompletionByID retrieves a proof cycle completion by ID
func (r *ProofArtifactRepository) GetProofCycleCompletionByID(ctx context.Context, completionID uuid.UUID) (*ProofCycleCompletionRecord, error) {
	query := `
		SELECT completion_id, proof_id,
			   level1_complete, level1_proof_id, level1_hash,
			   level2_complete, level2_proof_id, level2_hash,
			   level3_complete, level3_proof_id, level3_hash,
			   level4_complete, level4_result_id, level4_hash,
			   bindings_valid, cycle_hash, all_levels_complete,
			   level1_at, level2_at, level3_at, level4_at, completed_at,
			   created_at, updated_at
		FROM proof_cycle_completions
		WHERE completion_id = $1`

	var c ProofCycleCompletionRecord
	err := r.db.QueryRowContext(ctx, query, completionID).Scan(
		&c.CompletionID, &c.ProofID,
		&c.Level1Complete, &c.Level1ProofID, &c.Level1Hash,
		&c.Level2Complete, &c.Level2ProofID, &c.Level2Hash,
		&c.Level3Complete, &c.Level3ProofID, &c.Level3Hash,
		&c.Level4Complete, &c.Level4ResultID, &c.Level4Hash,
		&c.BindingsValid, &c.CycleHash, &c.AllLevelsComplete,
		&c.Level1At, &c.Level2At, &c.Level3At, &c.Level4At, &c.CompletedAt,
		&c.CreatedAt, &c.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof cycle completion: %w", err)
	}

	return &c, nil
}

// GetProofCycleCompletionByProof retrieves the completion record for a proof
func (r *ProofArtifactRepository) GetProofCycleCompletionByProof(ctx context.Context, proofID uuid.UUID) (*ProofCycleCompletionRecord, error) {
	query := `
		SELECT completion_id, proof_id,
			   level1_complete, level1_proof_id, level1_hash,
			   level2_complete, level2_proof_id, level2_hash,
			   level3_complete, level3_proof_id, level3_hash,
			   level4_complete, level4_result_id, level4_hash,
			   bindings_valid, cycle_hash, all_levels_complete,
			   level1_at, level2_at, level3_at, level4_at, completed_at,
			   created_at, updated_at
		FROM proof_cycle_completions
		WHERE proof_id = $1`

	var c ProofCycleCompletionRecord
	err := r.db.QueryRowContext(ctx, query, proofID).Scan(
		&c.CompletionID, &c.ProofID,
		&c.Level1Complete, &c.Level1ProofID, &c.Level1Hash,
		&c.Level2Complete, &c.Level2ProofID, &c.Level2Hash,
		&c.Level3Complete, &c.Level3ProofID, &c.Level3Hash,
		&c.Level4Complete, &c.Level4ResultID, &c.Level4Hash,
		&c.BindingsValid, &c.CycleHash, &c.AllLevelsComplete,
		&c.Level1At, &c.Level2At, &c.Level3At, &c.Level4At, &c.CompletedAt,
		&c.CreatedAt, &c.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof cycle completion by proof: %w", err)
	}

	return &c, nil
}

// UpdateProofCycleLevel1 updates Level 1 completion status
func (r *ProofArtifactRepository) UpdateProofCycleLevel1(ctx context.Context, completionID uuid.UUID, proofID uuid.UUID, hash []byte) error {
	query := `
		UPDATE proof_cycle_completions
		SET level1_complete = TRUE, level1_proof_id = $1, level1_hash = $2, level1_at = NOW(), updated_at = NOW()
		WHERE completion_id = $3`

	result, err := r.db.ExecContext(ctx, query, proofID, hash, completionID)
	if err != nil {
		return fmt.Errorf("failed to update proof cycle level 1: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof cycle completion not found: %s", completionID)
	}

	return nil
}

// UpdateProofCycleLevel2 updates Level 2 completion status
func (r *ProofArtifactRepository) UpdateProofCycleLevel2(ctx context.Context, completionID uuid.UUID, proofID uuid.UUID, hash []byte) error {
	query := `
		UPDATE proof_cycle_completions
		SET level2_complete = TRUE, level2_proof_id = $1, level2_hash = $2, level2_at = NOW(), updated_at = NOW()
		WHERE completion_id = $3`

	result, err := r.db.ExecContext(ctx, query, proofID, hash, completionID)
	if err != nil {
		return fmt.Errorf("failed to update proof cycle level 2: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof cycle completion not found: %s", completionID)
	}

	return nil
}

// UpdateProofCycleLevel3 updates Level 3 completion status
func (r *ProofArtifactRepository) UpdateProofCycleLevel3(ctx context.Context, completionID uuid.UUID, proofID uuid.UUID, hash []byte) error {
	query := `
		UPDATE proof_cycle_completions
		SET level3_complete = TRUE, level3_proof_id = $1, level3_hash = $2, level3_at = NOW(), updated_at = NOW()
		WHERE completion_id = $3`

	result, err := r.db.ExecContext(ctx, query, proofID, hash, completionID)
	if err != nil {
		return fmt.Errorf("failed to update proof cycle level 3: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof cycle completion not found: %s", completionID)
	}

	return nil
}

// UpdateProofCycleLevel4 updates Level 4 completion status
func (r *ProofArtifactRepository) UpdateProofCycleLevel4(ctx context.Context, completionID uuid.UUID, resultID uuid.UUID, hash []byte) error {
	query := `
		UPDATE proof_cycle_completions
		SET level4_complete = TRUE, level4_result_id = $1, level4_hash = $2, level4_at = NOW(), updated_at = NOW()
		WHERE completion_id = $3`

	result, err := r.db.ExecContext(ctx, query, resultID, hash, completionID)
	if err != nil {
		return fmt.Errorf("failed to update proof cycle level 4: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof cycle completion not found: %s", completionID)
	}

	return nil
}

// CompleteProofCycle marks a proof cycle as fully complete with cross-level binding verification
func (r *ProofArtifactRepository) CompleteProofCycle(ctx context.Context, completionID uuid.UUID, bindingsValid bool, cycleHash []byte) error {
	query := `
		UPDATE proof_cycle_completions
		SET bindings_valid = $1, cycle_hash = $2, all_levels_complete = TRUE, completed_at = NOW(), updated_at = NOW()
		WHERE completion_id = $3
		AND level1_complete = TRUE AND level2_complete = TRUE AND level3_complete = TRUE AND level4_complete = TRUE`

	result, err := r.db.ExecContext(ctx, query, bindingsValid, cycleHash, completionID)
	if err != nil {
		return fmt.Errorf("failed to complete proof cycle: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("proof cycle completion not found or not all levels complete: %s", completionID)
	}

	return nil
}

// GetIncompleteProofCycles retrieves all incomplete proof cycles
func (r *ProofArtifactRepository) GetIncompleteProofCycles(ctx context.Context, limit int) ([]ProofCycleCompletionRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT completion_id, proof_id,
			   level1_complete, level1_proof_id, level1_hash,
			   level2_complete, level2_proof_id, level2_hash,
			   level3_complete, level3_proof_id, level3_hash,
			   level4_complete, level4_result_id, level4_hash,
			   bindings_valid, cycle_hash, all_levels_complete,
			   level1_at, level2_at, level3_at, level4_at, completed_at,
			   created_at, updated_at
		FROM proof_cycle_completions
		WHERE all_levels_complete = FALSE
		ORDER BY created_at ASC
		LIMIT $1`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query incomplete proof cycles: %w", err)
	}
	defer rows.Close()

	var completions []ProofCycleCompletionRecord
	for rows.Next() {
		var c ProofCycleCompletionRecord
		if err := rows.Scan(
			&c.CompletionID, &c.ProofID,
			&c.Level1Complete, &c.Level1ProofID, &c.Level1Hash,
			&c.Level2Complete, &c.Level2ProofID, &c.Level2Hash,
			&c.Level3Complete, &c.Level3ProofID, &c.Level3Hash,
			&c.Level4Complete, &c.Level4ResultID, &c.Level4Hash,
			&c.BindingsValid, &c.CycleHash, &c.AllLevelsComplete,
			&c.Level1At, &c.Level2At, &c.Level3At, &c.Level4At, &c.CompletedAt,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof cycle completion: %w", err)
		}
		completions = append(completions, c)
	}

	return completions, nil
}

// ============================================================================
// API KEY OPERATIONS
// ============================================================================

// GetAPIKeyByHash retrieves an API key by its hash
func (r *ProofArtifactRepository) GetAPIKeyByHash(ctx context.Context, keyHash []byte) (*APIKey, error) {
	query := `
		SELECT key_id, key_hash, client_name, client_type,
			   can_read_proofs, can_request_proofs, can_bulk_download,
			   rate_limit_per_min, is_active, expires_at,
			   description, contact_email, created_at, last_used_at
		FROM api_keys
		WHERE key_hash = $1`

	var key APIKey
	err := r.db.QueryRowContext(ctx, query, keyHash).Scan(
		&key.KeyID, &key.KeyHash, &key.ClientName, &key.ClientType,
		&key.CanReadProofs, &key.CanRequestProofs, &key.CanBulkDownload,
		&key.RateLimitPerMin, &key.IsActive, &key.ExpiresAt,
		&key.Description, &key.ContactEmail, &key.CreatedAt, &key.LastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	return &key, nil
}

// UpdateAPIKeyLastUsed updates the last used timestamp for an API key
func (r *ProofArtifactRepository) UpdateAPIKeyLastUsed(ctx context.Context, keyID uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = NOW() WHERE key_id = $1`
	_, err := r.db.ExecContext(ctx, query, keyID)
	return err
}

// CreateAPIKey creates a new API key
func (r *ProofArtifactRepository) CreateAPIKey(ctx context.Context, input *NewAPIKey) (*APIKey, error) {
	query := `
		INSERT INTO api_keys (
			key_hash, client_name, client_type,
			can_read_proofs, can_request_proofs, can_bulk_download,
			rate_limit_per_min, is_active, expires_at,
			description, contact_email, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW()
		)
		RETURNING key_id, created_at`

	var key APIKey
	key.KeyHash = input.KeyHash
	key.ClientName = input.ClientName
	key.ClientType = input.ClientType
	key.CanReadProofs = input.CanReadProofs
	key.CanRequestProofs = input.CanRequestProofs
	key.CanBulkDownload = input.CanBulkDownload
	key.RateLimitPerMin = input.RateLimitPerMin
	key.IsActive = input.IsActive
	key.ExpiresAt = input.ExpiresAt
	key.Description = input.Description
	key.ContactEmail = input.ContactEmail

	err := r.db.QueryRowContext(ctx, query,
		input.KeyHash, input.ClientName, input.ClientType,
		input.CanReadProofs, input.CanRequestProofs, input.CanBulkDownload,
		input.RateLimitPerMin, input.IsActive, input.ExpiresAt,
		input.Description, input.ContactEmail,
	).Scan(&key.KeyID, &key.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return &key, nil
}

// ============================================================================
// PROOF REQUEST OPERATIONS
// ============================================================================

// CreateProofRequest creates a new proof request
func (r *ProofArtifactRepository) CreateProofRequest(ctx context.Context, input *NewBundleProofRequest) (*BundleProofRequest, error) {
	query := `
		INSERT INTO proof_requests (
			accum_tx_hash, account_url, proof_class, governance_level,
			api_key_id, callback_url, status, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, NOW()
		)
		RETURNING request_id, created_at`

	var req BundleProofRequest
	req.AccumTxHash = input.AccumTxHash
	req.AccountURL = input.AccountURL
	req.ProofClass = input.ProofClass
	req.GovernanceLevel = input.GovernanceLevel
	req.APIKeyID = input.APIKeyID
	req.CallbackURL = input.CallbackURL
	req.Status = input.Status

	err := r.db.QueryRowContext(ctx, query,
		input.AccumTxHash, input.AccountURL, input.ProofClass, input.GovernanceLevel,
		input.APIKeyID, input.CallbackURL, input.Status,
	).Scan(&req.RequestID, &req.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create proof request: %w", err)
	}

	return &req, nil
}

// GetProofRequest retrieves a proof request by ID
func (r *ProofArtifactRepository) GetProofRequest(ctx context.Context, requestID uuid.UUID) (*BundleProofRequest, error) {
	query := `
		SELECT request_id, accum_tx_hash, account_url, proof_class, governance_level,
			   api_key_id, callback_url, status, proof_id, error_message, retry_count,
			   created_at, processed_at, completed_at
		FROM proof_requests
		WHERE request_id = $1`

	var req BundleProofRequest
	err := r.db.QueryRowContext(ctx, query, requestID).Scan(
		&req.RequestID, &req.AccumTxHash, &req.AccountURL, &req.ProofClass, &req.GovernanceLevel,
		&req.APIKeyID, &req.CallbackURL, &req.Status, &req.ProofID, &req.ErrorMessage, &req.RetryCount,
		&req.CreatedAt, &req.ProcessedAt, &req.CompletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof request: %w", err)
	}

	return &req, nil
}

// UpdateProofRequestStatus updates the status of a proof request
func (r *ProofArtifactRepository) UpdateProofRequestStatus(ctx context.Context, requestID uuid.UUID, status string, proofID *uuid.UUID, errorMsg *string) error {
	var query string
	var args []interface{}

	if status == "completed" && proofID != nil {
		query = `UPDATE proof_requests SET status = $1, proof_id = $2, completed_at = NOW() WHERE request_id = $3`
		args = []interface{}{status, proofID, requestID}
	} else if status == "failed" && errorMsg != nil {
		query = `UPDATE proof_requests SET status = $1, error_message = $2, retry_count = retry_count + 1 WHERE request_id = $3`
		args = []interface{}{status, errorMsg, requestID}
	} else if status == "processing" {
		query = `UPDATE proof_requests SET status = $1, processed_at = NOW() WHERE request_id = $2`
		args = []interface{}{status, requestID}
	} else {
		query = `UPDATE proof_requests SET status = $1 WHERE request_id = $2`
		args = []interface{}{status, requestID}
	}

	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}

// CountPendingProofRequests counts pending proof requests
func (r *ProofArtifactRepository) CountPendingProofRequests(ctx context.Context) (int, error) {
	query := `SELECT COUNT(*) FROM proof_requests WHERE status = 'pending'`
	var count int
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count pending requests: %w", err)
	}
	return count, nil
}

// ============================================================================
// COUNT AND STATISTICS OPERATIONS
// ============================================================================

// CountProofs counts proofs matching a filter
func (r *ProofArtifactRepository) CountProofs(ctx context.Context, filter *ProofArtifactFilter) (int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	if filter != nil {
		if filter.Status != nil {
			conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
			args = append(args, *filter.Status)
			argIndex++
		}
		if filter.ProofType != nil {
			conditions = append(conditions, fmt.Sprintf("proof_type = $%d", argIndex))
			args = append(args, *filter.ProofType)
			argIndex++
		}
		if filter.GovernanceLevel != nil {
			conditions = append(conditions, fmt.Sprintf("gov_level = $%d", argIndex))
			args = append(args, *filter.GovernanceLevel)
			argIndex++
		}
		if filter.CreatedAfter != nil {
			conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIndex))
			args = append(args, *filter.CreatedAfter)
			argIndex++
		}
		if filter.CreatedBefore != nil {
			conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIndex))
			args = append(args, *filter.CreatedBefore)
			argIndex++
		}
		if len(filter.AccountURLs) > 0 {
			placeholders := make([]string, len(filter.AccountURLs))
			for i, url := range filter.AccountURLs {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, url)
				argIndex++
			}
			conditions = append(conditions, "account_url IN ("+strings.Join(placeholders, ", ")+")")
		}
		if len(filter.Statuses) > 0 {
			placeholders := make([]string, len(filter.Statuses))
			for i, status := range filter.Statuses {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, status)
				argIndex++
			}
			conditions = append(conditions, "status IN ("+strings.Join(placeholders, ", ")+")")
		}
		if len(filter.GovernanceLevels) > 0 {
			placeholders := make([]string, len(filter.GovernanceLevels))
			for i, level := range filter.GovernanceLevels {
				placeholders[i] = fmt.Sprintf("$%d", argIndex)
				args = append(args, level)
				argIndex++
			}
			conditions = append(conditions, "gov_level IN ("+strings.Join(placeholders, ", ")+")")
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf("SELECT COUNT(*) FROM proof_artifacts %s", whereClause)

	var count int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count proofs: %w", err)
	}
	return count, nil
}

// CountAttestations counts attestations, optionally filtering to valid only
func (r *ProofArtifactRepository) CountAttestations(ctx context.Context, validOnly *bool) (int, error) {
	query := "SELECT COUNT(*) FROM validator_attestations"
	if validOnly != nil && *validOnly {
		query += " WHERE signature_valid = TRUE"
	}

	var count int
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count attestations: %w", err)
	}
	return count, nil
}

// CountBundleDownloads counts bundle downloads in a time range
func (r *ProofArtifactRepository) CountBundleDownloads(ctx context.Context, start, end time.Time) (int64, error) {
	query := `SELECT COUNT(*) FROM bundle_downloads WHERE downloaded_at >= $1 AND downloaded_at <= $2`
	var count int64
	err := r.db.QueryRowContext(ctx, query, start, end).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count bundle downloads: %w", err)
	}
	return count, nil
}

// GetBundleByProofID is an alias for GetProofBundleByProofID for compatibility
func (r *ProofArtifactRepository) GetBundleByProofID(ctx context.Context, proofID uuid.UUID) (*ProofBundle, error) {
	return r.GetProofBundleByProofID(ctx, proofID)
}

// QueryProofsForExport retrieves proofs for bulk export matching a filter - returns full ProofArtifact
func (r *ProofArtifactRepository) QueryProofsForExport(ctx context.Context, filter *ProofArtifactFilter) ([]ProofArtifact, error) {
	if filter == nil {
		filter = &ProofArtifactFilter{Limit: 1000}
	}
	if filter.Limit <= 0 {
		filter.Limit = 1000
	}
	if filter.Limit > 10000 {
		filter.Limit = 10000
	}

	var conditions []string
	var args []interface{}
	argIndex := 1

	if filter.CreatedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, *filter.CreatedAfter)
		argIndex++
	}
	if filter.CreatedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, *filter.CreatedBefore)
		argIndex++
	}
	if len(filter.AccountURLs) > 0 {
		placeholders := make([]string, len(filter.AccountURLs))
		for i, url := range filter.AccountURLs {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, url)
			argIndex++
		}
		conditions = append(conditions, "account_url IN ("+strings.Join(placeholders, ", ")+")")
	}
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, status := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, status)
			argIndex++
		}
		conditions = append(conditions, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if len(filter.GovernanceLevels) > 0 {
		placeholders := make([]string, len(filter.GovernanceLevels))
		for i, level := range filter.GovernanceLevels {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, level)
			argIndex++
		}
		conditions = append(conditions, "gov_level IN ("+strings.Join(placeholders, ", ")+")")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT proof_id, proof_type, proof_version, accum_tx_hash, account_url,
			   batch_id, batch_position, anchor_id, anchor_tx_hash, anchor_block_number, anchor_chain,
			   merkle_root, leaf_hash, leaf_index, gov_level, proof_class, validator_id,
			   status, verification_status, created_at, anchored_at, verified_at,
			   artifact_json, artifact_hash
		FROM proof_artifacts
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs for export: %w", err)
	}
	defer rows.Close()

	var proofs []ProofArtifact
	for rows.Next() {
		var p ProofArtifact
		if err := rows.Scan(
			&p.ProofID, &p.ProofType, &p.ProofVersion, &p.AccumTxHash, &p.AccountURL,
			&p.BatchID, &p.BatchPosition, &p.AnchorID, &p.AnchorTxHash, &p.AnchorBlockNumber, &p.AnchorChain,
			&p.MerkleRoot, &p.LeafHash, &p.LeafIndex, &p.GovLevel, &p.ProofClass, &p.ValidatorID,
			&p.Status, &p.VerificationStatus, &p.CreatedAt, &p.AnchoredAt, &p.VerifiedAt,
			&p.ArtifactJSON, &p.ArtifactHash,
		); err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, p)
	}

	return proofs, nil
}

// GetExternalChainResultIDByTxHash retrieves the result_id by tx_hash
func (r *ProofArtifactRepository) GetExternalChainResultIDByTxHash(ctx context.Context, txHash []byte) (*uuid.UUID, error) {
	query := `SELECT result_id FROM external_chain_results WHERE tx_hash = $1 LIMIT 1`
	var resultID uuid.UUID
	err := r.db.QueryRowContext(ctx, query, txHash).Scan(&resultID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get result ID by tx hash: %w", err)
	}
	return &resultID, nil
}

// GetExternalChainResultIDByResultHash retrieves the result_id by result_hash
func (r *ProofArtifactRepository) GetExternalChainResultIDByResultHash(ctx context.Context, resultHash []byte) (*uuid.UUID, error) {
	query := `SELECT result_id FROM external_chain_results WHERE result_hash = $1 LIMIT 1`
	var resultID uuid.UUID
	err := r.db.QueryRowContext(ctx, query, resultHash).Scan(&resultID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get result ID by result hash: %w", err)
	}
	return &resultID, nil
}

// ============================================================================
// FINALIZATION OPERATIONS
// ============================================================================

// MarkExternalChainResultFinalized marks an external chain result as finalized
func (r *ProofArtifactRepository) MarkExternalChainResultFinalized(ctx context.Context, resultID uuid.UUID) error {
	query := `
		UPDATE external_chain_results
		SET is_finalized = TRUE, finalized_at = NOW(), updated_at = NOW()
		WHERE result_id = $1`

	result, err := r.db.ExecContext(ctx, query, resultID)
	if err != nil {
		return fmt.Errorf("failed to mark external chain result finalized: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("external chain result not found: %s", resultID)
	}

	return nil
}

// MarkExternalChainResultFinalizedByTxHash marks an external chain result as finalized by transaction hash
func (r *ProofArtifactRepository) MarkExternalChainResultFinalizedByTxHash(ctx context.Context, txHash []byte) error {
	query := `
		UPDATE external_chain_results
		SET is_finalized = TRUE, finalized_at = NOW(), updated_at = NOW()
		WHERE tx_hash = $1`

	result, err := r.db.ExecContext(ctx, query, txHash)
	if err != nil {
		return fmt.Errorf("failed to mark external chain result finalized by tx hash: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("external chain result not found for tx hash")
	}

	return nil
}

// UpdateExternalChainResultConfirmations updates the confirmation count for a result
func (r *ProofArtifactRepository) UpdateExternalChainResultConfirmations(ctx context.Context, resultID uuid.UUID, confirmations int) error {
	query := `
		UPDATE external_chain_results
		SET confirmation_blocks = $2, updated_at = NOW()
		WHERE result_id = $1`

	result, err := r.db.ExecContext(ctx, query, resultID, confirmations)
	if err != nil {
		return fmt.Errorf("failed to update external chain result confirmations: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("external chain result not found: %s", resultID)
	}

	return nil
}

// LinkExternalChainResultsToProof links all external_chain_results with a given bundle_id to a proof_id
func (r *ProofArtifactRepository) LinkExternalChainResultsToProof(ctx context.Context, bundleID []byte, proofID uuid.UUID) (int64, error) {
	query := `
		UPDATE external_chain_results
		SET proof_id = $1, finalized_at = CASE WHEN is_finalized AND finalized_at IS NULL THEN NOW() ELSE finalized_at END, updated_at = NOW()
		WHERE bundle_id = $2 AND proof_id IS NULL`

	result, err := r.db.ExecContext(ctx, query, proofID, bundleID)
	if err != nil {
		return 0, fmt.Errorf("failed to link external chain results to proof: %w", err)
	}

	rows, _ := result.RowsAffected()
	return rows, nil
}

// MarkBLSAggregationFinalized marks a BLS aggregation as finalized
func (r *ProofArtifactRepository) MarkBLSAggregationFinalized(ctx context.Context, aggregationID uuid.UUID) error {
	query := `
		UPDATE aggregated_bls_attestations
		SET finalized_at = NOW()
		WHERE aggregation_id = $1`

	result, err := r.db.ExecContext(ctx, query, aggregationID)
	if err != nil {
		return fmt.Errorf("failed to mark BLS aggregation finalized: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("BLS aggregation not found: %s", aggregationID)
	}

	return nil
}

// MarkBLSAggregationVerified marks a BLS aggregation as verified
func (r *ProofArtifactRepository) MarkBLSAggregationVerified(ctx context.Context, aggregationID uuid.UUID, verified bool) error {
	query := `
		UPDATE aggregated_bls_attestations
		SET aggregate_verified = $2, verified_at = NOW()
		WHERE aggregation_id = $1`

	result, err := r.db.ExecContext(ctx, query, aggregationID, verified)
	if err != nil {
		return fmt.Errorf("failed to mark BLS aggregation verified: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("BLS aggregation not found: %s", aggregationID)
	}

	return nil
}

// MarkExternalChainResultsFinalizedByAnchor marks all external chain results for proofs
// associated with an anchor as finalized. This is called when an anchor reaches finality.
func (r *ProofArtifactRepository) MarkExternalChainResultsFinalizedByAnchor(ctx context.Context, anchorID uuid.UUID) (int64, error) {
	query := `
		UPDATE external_chain_results
		SET is_finalized = TRUE, finalized_at = NOW(), updated_at = NOW()
		WHERE proof_id IN (
			SELECT proof_id FROM proof_artifacts WHERE anchor_id = $1
		) AND is_finalized = FALSE`

	result, err := r.db.ExecContext(ctx, query, anchorID)
	if err != nil {
		return 0, fmt.Errorf("failed to mark external chain results finalized by anchor: %w", err)
	}

	rows, _ := result.RowsAffected()
	return rows, nil
}

// MarkBLSAggregationsFinalizedByAnchor marks all BLS aggregations for proofs
// associated with an anchor as finalized. This is called when an anchor reaches finality.
func (r *ProofArtifactRepository) MarkBLSAggregationsFinalizedByAnchor(ctx context.Context, anchorID uuid.UUID) (int64, error) {
	query := `
		UPDATE aggregated_bls_attestations
		SET finalized_at = NOW()
		WHERE result_id IN (
			SELECT ecr.result_id
			FROM external_chain_results ecr
			INNER JOIN proof_artifacts pa ON ecr.proof_id = pa.proof_id
			WHERE pa.anchor_id = $1
		) AND finalized_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, anchorID)
	if err != nil {
		return 0, fmt.Errorf("failed to mark BLS aggregations finalized by anchor: %w", err)
	}

	rows, _ := result.RowsAffected()
	return rows, nil
}

// GetUnfinalizedExternalChainResults retrieves external chain results that are not yet finalized
func (r *ProofArtifactRepository) GetUnfinalizedExternalChainResults(ctx context.Context, limit int) ([]ExternalChainResultRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT result_id, proof_id, chain_id, chain_name, block_number, block_hash, transaction_hash,
			   execution_status, gas_used, return_data,
			   storage_proof_json, storage_proof_hash,
			   sequence_number, previous_result_hash, result_hash,
			   anchor_proof_hash, artifact_json, verified, verified_at, created_at
		FROM external_chain_results
		WHERE is_finalized = FALSE
		ORDER BY created_at ASC
		LIMIT $1`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query unfinalized external chain results: %w", err)
	}
	defer rows.Close()

	var results []ExternalChainResultRecord
	for rows.Next() {
		var result ExternalChainResultRecord
		if err := rows.Scan(
			&result.ResultID, &result.ProofID, &result.ChainID, &result.ChainName, &result.BlockNumber, &result.BlockHash, &result.TransactionHash,
			&result.ExecutionStatus, &result.GasUsed, &result.ReturnData,
			&result.StorageProofJSON, &result.StorageProofHash,
			&result.SequenceNumber, &result.PreviousResultHash, &result.ResultHash,
			&result.AnchorProofHash, &result.ArtifactJSON, &result.Verified, &result.VerifiedAt, &result.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan external chain result: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}

// ============================================================================
// BLS RESULT ATTESTATIONS (actual schema)
// ============================================================================

// NewBLSResultAttestation is the input for creating a BLS result attestation
type NewBLSResultAttestation struct {
	ResultID             uuid.UUID
	ResultHash           []byte
	BundleID             []byte
	MessageHash          []byte
	ValidatorID          string
	ValidatorAddress     []byte
	ValidatorIndex       int
	BLSSignature         []byte
	BLSPublicKey         []byte
	SignatureDomain      string
	AttestedBlockNumber  int64
	AttestedBlockHash    []byte
	ConfirmationsAtAttest int
	AttestationTime      time.Time
}

// BLSResultAttestationRecord represents a stored BLS result attestation
type BLSResultAttestationRecord struct {
	AttestationID         uuid.UUID
	ResultID              uuid.UUID
	ResultHash            []byte
	BundleID              []byte
	MessageHash           []byte
	ValidatorID           string
	ValidatorAddress      []byte
	ValidatorIndex        int
	BLSSignature          []byte
	BLSPublicKey          []byte
	SignatureDomain       string
	AttestedBlockNumber   int64
	AttestedBlockHash     []byte
	ConfirmationsAtAttest int
	SignatureValid        *bool
	VerifiedAt            *time.Time
	VerificationError     *string
	AttestationTime       time.Time
	CreatedAt             time.Time
}

// SaveBLSResultAttestation creates a new BLS result attestation in bls_result_attestations table
func (r *ProofArtifactRepository) SaveBLSResultAttestation(ctx context.Context, input *NewBLSResultAttestation) (*BLSResultAttestationRecord, error) {
	domain := input.SignatureDomain
	if domain == "" {
		domain = "CERTEN_RESULT_ATTESTATION_V1"
	}

	query := `
		INSERT INTO bls_result_attestations (
			result_id, result_hash, bundle_id, message_hash,
			validator_id, validator_address, validator_index,
			bls_signature, bls_public_key, signature_domain,
			attested_block_number, attested_block_hash, confirmations_at_attest,
			attestation_time
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
		ON CONFLICT (result_id, validator_id) DO UPDATE SET
			bls_signature = EXCLUDED.bls_signature,
			bls_public_key = EXCLUDED.bls_public_key,
			attestation_time = EXCLUDED.attestation_time
		RETURNING attestation_id, created_at`

	var att BLSResultAttestationRecord
	att.ResultID = input.ResultID
	att.ResultHash = input.ResultHash
	att.BundleID = input.BundleID
	att.MessageHash = input.MessageHash
	att.ValidatorID = input.ValidatorID
	att.ValidatorAddress = input.ValidatorAddress
	att.ValidatorIndex = input.ValidatorIndex
	att.BLSSignature = input.BLSSignature
	att.BLSPublicKey = input.BLSPublicKey
	att.SignatureDomain = domain
	att.AttestedBlockNumber = input.AttestedBlockNumber
	att.AttestedBlockHash = input.AttestedBlockHash
	att.ConfirmationsAtAttest = input.ConfirmationsAtAttest
	att.AttestationTime = input.AttestationTime

	err := r.db.QueryRowContext(ctx, query,
		input.ResultID, input.ResultHash, input.BundleID, input.MessageHash,
		input.ValidatorID, input.ValidatorAddress, input.ValidatorIndex,
		input.BLSSignature, input.BLSPublicKey, domain,
		input.AttestedBlockNumber, input.AttestedBlockHash, input.ConfirmationsAtAttest,
		input.AttestationTime,
	).Scan(&att.AttestationID, &att.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to save BLS result attestation: %w", err)
	}

	return &att, nil
}

// GetBLSResultAttestationsByResult retrieves all BLS result attestations for a result
func (r *ProofArtifactRepository) GetBLSResultAttestationsByResult(ctx context.Context, resultID uuid.UUID) ([]BLSResultAttestationRecord, error) {
	query := `
		SELECT attestation_id, result_id, result_hash, bundle_id, message_hash,
			   validator_id, validator_address, validator_index,
			   bls_signature, bls_public_key, signature_domain,
			   attested_block_number, attested_block_hash, confirmations_at_attest,
			   signature_valid, verified_at, verification_error,
			   attestation_time, created_at
		FROM bls_result_attestations
		WHERE result_id = $1
		ORDER BY attestation_time ASC`

	rows, err := r.db.QueryContext(ctx, query, resultID)
	if err != nil {
		return nil, fmt.Errorf("failed to query BLS result attestations: %w", err)
	}
	defer rows.Close()

	var attestations []BLSResultAttestationRecord
	for rows.Next() {
		var att BLSResultAttestationRecord
		if err := rows.Scan(
			&att.AttestationID, &att.ResultID, &att.ResultHash, &att.BundleID, &att.MessageHash,
			&att.ValidatorID, &att.ValidatorAddress, &att.ValidatorIndex,
			&att.BLSSignature, &att.BLSPublicKey, &att.SignatureDomain,
			&att.AttestedBlockNumber, &att.AttestedBlockHash, &att.ConfirmationsAtAttest,
			&att.SignatureValid, &att.VerifiedAt, &att.VerificationError,
			&att.AttestationTime, &att.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan BLS result attestation: %w", err)
		}
		attestations = append(attestations, att)
	}

	return attestations, nil
}

// MarkBLSResultAttestationVerified marks a BLS result attestation as verified
func (r *ProofArtifactRepository) MarkBLSResultAttestationVerified(ctx context.Context, attestationID uuid.UUID, valid bool, errMsg *string) error {
	query := `
		UPDATE bls_result_attestations
		SET signature_valid = $2, verified_at = NOW(), verification_error = $3
		WHERE attestation_id = $1`

	result, err := r.db.ExecContext(ctx, query, attestationID, valid, errMsg)
	if err != nil {
		return fmt.Errorf("failed to mark BLS result attestation verified: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("BLS result attestation not found: %s", attestationID)
	}

	return nil
}

// ============================================================================
// AGGREGATED BLS ATTESTATIONS (actual schema)
// ============================================================================

// NewAggregatedBLSAttestation is the input for creating an aggregated BLS attestation
type NewAggregatedBLSAttestation struct {
	ResultID              uuid.UUID
	ResultHash            []byte
	BundleID              []byte
	MessageHash           []byte
	AttestedBlockNumber   int64
	AggregateSignature    []byte
	AggregatePublicKey    []byte
	ValidatorBitfield     []byte
	ValidatorCount        int
	ValidatorAddresses    [][]byte
	ValidatorIndices      []int32
	AttestationIDs        []uuid.UUID
	TotalVotingPower      string // Use string for NUMERIC(78,0)
	SignedVotingPower     string
	VotingPowerPercentage float64
	ThresholdNumerator    int
	ThresholdDenominator  int
	ThresholdMet          bool
	FirstAttestationAt    time.Time
	LastAttestationAt     time.Time
	AggregationHash       []byte
}

// AggregatedBLSAttestationRecord represents a stored aggregated BLS attestation
type AggregatedBLSAttestationRecord struct {
	AggregationID         uuid.UUID
	ResultID              uuid.UUID
	ResultHash            []byte
	BundleID              []byte
	MessageHash           []byte
	AttestedBlockNumber   int64
	AggregateSignature    []byte
	AggregatePublicKey    []byte
	ValidatorBitfield     []byte
	ValidatorCount        int
	TotalVotingPower      string
	SignedVotingPower     string
	VotingPowerPercentage float64
	ThresholdNumerator    int
	ThresholdDenominator  int
	ThresholdMet          bool
	FirstAttestationAt    time.Time
	LastAttestationAt     time.Time
	FinalizedAt           *time.Time
	AggregateVerified     *bool
	VerifiedAt            *time.Time
	VerificationError     *string
	AggregationHash       []byte
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// SaveAggregatedBLSAttestation creates a new aggregated BLS attestation in aggregated_bls_attestations table
func (r *ProofArtifactRepository) SaveAggregatedBLSAttestation(ctx context.Context, input *NewAggregatedBLSAttestation) (*AggregatedBLSAttestationRecord, error) {
	query := `
		INSERT INTO aggregated_bls_attestations (
			result_id, result_hash, bundle_id, message_hash, attested_block_number,
			aggregate_signature, aggregate_public_key, validator_bitfield,
			validator_count, validator_addresses, validator_indices, attestation_ids,
			total_voting_power, signed_voting_power, voting_power_percentage,
			threshold_numerator, threshold_denominator, threshold_met,
			first_attestation_at, last_attestation_at, aggregation_hash
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
		ON CONFLICT (result_id) DO UPDATE SET
			aggregate_signature = EXCLUDED.aggregate_signature,
			aggregate_public_key = EXCLUDED.aggregate_public_key,
			validator_bitfield = EXCLUDED.validator_bitfield,
			validator_count = EXCLUDED.validator_count,
			validator_addresses = EXCLUDED.validator_addresses,
			validator_indices = EXCLUDED.validator_indices,
			attestation_ids = EXCLUDED.attestation_ids,
			total_voting_power = EXCLUDED.total_voting_power,
			signed_voting_power = EXCLUDED.signed_voting_power,
			voting_power_percentage = EXCLUDED.voting_power_percentage,
			threshold_met = EXCLUDED.threshold_met,
			last_attestation_at = EXCLUDED.last_attestation_at,
			aggregation_hash = EXCLUDED.aggregation_hash,
			updated_at = NOW()
		RETURNING aggregation_id, created_at, updated_at`

	var agg AggregatedBLSAttestationRecord
	agg.ResultID = input.ResultID
	agg.ResultHash = input.ResultHash
	agg.BundleID = input.BundleID
	agg.MessageHash = input.MessageHash
	agg.AttestedBlockNumber = input.AttestedBlockNumber
	agg.AggregateSignature = input.AggregateSignature
	agg.AggregatePublicKey = input.AggregatePublicKey
	agg.ValidatorBitfield = input.ValidatorBitfield
	agg.ValidatorCount = input.ValidatorCount
	agg.TotalVotingPower = input.TotalVotingPower
	agg.SignedVotingPower = input.SignedVotingPower
	agg.VotingPowerPercentage = input.VotingPowerPercentage
	agg.ThresholdNumerator = input.ThresholdNumerator
	agg.ThresholdDenominator = input.ThresholdDenominator
	agg.ThresholdMet = input.ThresholdMet
	agg.FirstAttestationAt = input.FirstAttestationAt
	agg.LastAttestationAt = input.LastAttestationAt
	agg.AggregationHash = input.AggregationHash

	// Convert arrays to pq-compatible types for PostgreSQL
	// BYTEA[] - use pq.ByteaArray
	byteaArray := pq.ByteaArray(input.ValidatorAddresses)

	// INTEGER[] - use pq.Int32Array
	int32Array := pq.Int32Array(input.ValidatorIndices)

	// UUID[] - convert to string array for PostgreSQL
	uuidStrings := make([]string, len(input.AttestationIDs))
	for i, id := range input.AttestationIDs {
		uuidStrings[i] = id.String()
	}
	uuidArray := pq.StringArray(uuidStrings)

	err := r.db.QueryRowContext(ctx, query,
		input.ResultID, input.ResultHash, input.BundleID, input.MessageHash, input.AttestedBlockNumber,
		input.AggregateSignature, input.AggregatePublicKey, input.ValidatorBitfield,
		input.ValidatorCount, byteaArray, int32Array, uuidArray,
		input.TotalVotingPower, input.SignedVotingPower, input.VotingPowerPercentage,
		input.ThresholdNumerator, input.ThresholdDenominator, input.ThresholdMet,
		input.FirstAttestationAt, input.LastAttestationAt, input.AggregationHash,
	).Scan(&agg.AggregationID, &agg.CreatedAt, &agg.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to save aggregated BLS attestation: %w", err)
	}

	return &agg, nil
}

// GetAggregatedBLSAttestationByResult retrieves the aggregated BLS attestation for a result
func (r *ProofArtifactRepository) GetAggregatedBLSAttestationByResult(ctx context.Context, resultID uuid.UUID) (*AggregatedBLSAttestationRecord, error) {
	query := `
		SELECT aggregation_id, result_id, result_hash, bundle_id, message_hash, attested_block_number,
			   aggregate_signature, aggregate_public_key, validator_bitfield, validator_count,
			   total_voting_power, signed_voting_power, voting_power_percentage,
			   threshold_numerator, threshold_denominator, threshold_met,
			   first_attestation_at, last_attestation_at, finalized_at,
			   aggregate_verified, verified_at, verification_error, aggregation_hash,
			   created_at, updated_at
		FROM aggregated_bls_attestations
		WHERE result_id = $1`

	var agg AggregatedBLSAttestationRecord
	err := r.db.QueryRowContext(ctx, query, resultID).Scan(
		&agg.AggregationID, &agg.ResultID, &agg.ResultHash, &agg.BundleID, &agg.MessageHash, &agg.AttestedBlockNumber,
		&agg.AggregateSignature, &agg.AggregatePublicKey, &agg.ValidatorBitfield, &agg.ValidatorCount,
		&agg.TotalVotingPower, &agg.SignedVotingPower, &agg.VotingPowerPercentage,
		&agg.ThresholdNumerator, &agg.ThresholdDenominator, &agg.ThresholdMet,
		&agg.FirstAttestationAt, &agg.LastAttestationAt, &agg.FinalizedAt,
		&agg.AggregateVerified, &agg.VerifiedAt, &agg.VerificationError, &agg.AggregationHash,
		&agg.CreatedAt, &agg.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregated BLS attestation: %w", err)
	}

	return &agg, nil
}

// MarkAggregatedBLSAttestationFinalized marks an aggregated BLS attestation as finalized and verified
func (r *ProofArtifactRepository) MarkAggregatedBLSAttestationFinalized(ctx context.Context, aggregationID uuid.UUID, verified bool, errMsg *string) error {
	query := `
		UPDATE aggregated_bls_attestations
		SET finalized_at = NOW(), aggregate_verified = $2, verified_at = NOW(), verification_error = $3, updated_at = NOW()
		WHERE aggregation_id = $1`

	result, err := r.db.ExecContext(ctx, query, aggregationID, verified, errMsg)
	if err != nil {
		return fmt.Errorf("failed to mark aggregated BLS attestation finalized: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("aggregated BLS attestation not found: %s", aggregationID)
	}

	return nil
}

// Unused import fix
var _ = hex.EncodeToString
var _ = json.Marshal
