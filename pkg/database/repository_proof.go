// Copyright 2025 Certen Protocol
//
// Proof Repository - CRUD operations for Certen anchor proofs
// Per Whitepaper Section 3.4.1, a proof has 4 components:
// 1. Transaction Inclusion Proof (Merkle proof in batch)
// 2. Anchor Reference (ETH/BTC tx hash + block)
// 3. State Proof (ChainedProof from Accumulate L1-L3)
// 4. Authority Proof (GovernanceProof G0-G2)

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ProofRepository handles Certen anchor proof operations
type ProofRepository struct {
	client *Client
}

// NewProofRepository creates a new proof repository
func NewProofRepository(client *Client) *ProofRepository {
	return &ProofRepository{client: client}
}

// CurrentProofVersion is the current version of the proof format
const CurrentProofVersion = "1.0.0"

// ============================================================================
// CERTEN ANCHOR PROOF OPERATIONS
// ============================================================================

// CreateProof creates a new Certen anchor proof
func (r *ProofRepository) CreateProof(ctx context.Context, input *NewCertenAnchorProof) (*CertenAnchorProof, error) {
	// Serialize merkle inclusion proof
	merkleInclusionJSON, err := json.Marshal(input.MerkleInclusion)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize merkle inclusion: %w", err)
	}

	proof := &CertenAnchorProof{
		ProofID:           uuid.New(),
		BatchID:           input.BatchID,
		AnchorID:          uuid.NullUUID{UUID: input.AnchorID, Valid: input.AnchorID != uuid.Nil},
		TransactionID:     input.TransactionID,
		AccumTxHash:       input.AccumTxHash,
		AccountURL:        input.AccountURL,
		MerkleRoot:        input.MerkleRoot,
		MerkleInclusion:   merkleInclusionJSON,
		AnchorChain:       input.AnchorChain,
		AnchorTxHash:      input.AnchorTxHash,
		AnchorBlockNumber: input.AnchorBlockNumber,
		AnchorBlockHash:   sql.NullString{String: input.AnchorBlockHash, Valid: input.AnchorBlockHash != ""},
		AnchorConfirms:    0,
		AccumStateProof:   input.AccumStateProof,
		AccumBlockHeight:  sql.NullInt64{Int64: input.AccumBlockHeight, Valid: input.AccumBlockHeight > 0},
		AccumBVN:          sql.NullString{String: input.AccumBVN, Valid: input.AccumBVN != ""},
		GovProof:          input.GovProof,
		GovLevel:          sql.NullString{String: string(input.GovLevel), Valid: input.GovLevel != ""},
		GovValid:          input.GovProof != nil,
		Verified:          false,
		ValidatorID:       input.ValidatorID,
		ProofVersion:      CurrentProofVersion,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	query := `
		INSERT INTO certen_anchor_proofs (
			proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, validator_id, proof_version, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
		RETURNING proof_id, created_at, updated_at`

	err = r.client.QueryRowContext(ctx, query,
		proof.ProofID, proof.BatchID, proof.AnchorID, proof.TransactionID, proof.AccumTxHash,
		proof.AccountURL, proof.MerkleRoot, proof.MerkleInclusion, proof.AnchorChain,
		proof.AnchorTxHash, proof.AnchorBlockNumber, proof.AnchorBlockHash, proof.AnchorConfirms,
		proof.AccumStateProof, proof.AccumBlockHeight, proof.AccumBVN,
		proof.GovProof, proof.GovLevel, proof.GovValid,
		proof.Verified, proof.ValidatorID, proof.ProofVersion, proof.CreatedAt, proof.UpdatedAt,
	).Scan(&proof.ProofID, &proof.CreatedAt, &proof.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %w", err)
	}

	return proof, nil
}

// GetProof retrieves a proof by ID
func (r *ProofRepository) GetProof(ctx context.Context, proofID uuid.UUID) (*CertenAnchorProof, error) {
	query := `
		SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, verification_time, verification_details,
			validator_id, validator_signature, proof_version, created_at, updated_at
		FROM certen_anchor_proofs
		WHERE proof_id = $1`

	proof := &CertenAnchorProof{}
	err := r.client.QueryRowContext(ctx, query, proofID).Scan(
		&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
		&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
		&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
		&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
		&proof.GovProof, &proof.GovLevel, &proof.GovValid,
		&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
		&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrProofNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof: %w", err)
	}

	return proof, nil
}

// GetProofByAccumTxHash retrieves a proof by Accumulate transaction hash
func (r *ProofRepository) GetProofByAccumTxHash(ctx context.Context, accumTxHash string) (*CertenAnchorProof, error) {
	query := `
		SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, verification_time, verification_details,
			validator_id, validator_signature, proof_version, created_at, updated_at
		FROM certen_anchor_proofs
		WHERE accumulate_tx_hash = $1
		ORDER BY created_at DESC
		LIMIT 1`

	proof := &CertenAnchorProof{}
	err := r.client.QueryRowContext(ctx, query, accumTxHash).Scan(
		&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
		&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
		&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
		&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
		&proof.GovProof, &proof.GovLevel, &proof.GovValid,
		&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
		&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrProofNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof by accum tx hash: %w", err)
	}

	return proof, nil
}

// GetProofsByBatchID retrieves all proofs for a batch
func (r *ProofRepository) GetProofsByBatchID(ctx context.Context, batchID uuid.UUID) ([]*CertenAnchorProof, error) {
	query := `
		SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, verification_time, verification_details,
			validator_id, validator_signature, proof_version, created_at, updated_at
		FROM certen_anchor_proofs
		WHERE batch_id = $1
		ORDER BY transaction_id ASC`

	rows, err := r.client.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs by batch: %w", err)
	}
	defer rows.Close()

	var proofs []*CertenAnchorProof
	for rows.Next() {
		proof := &CertenAnchorProof{}
		err := rows.Scan(
			&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
			&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
			&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
			&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
			&proof.GovProof, &proof.GovLevel, &proof.GovValid,
			&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
			&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return proofs, rows.Err()
}

// GetProofsByAnchorID retrieves all proofs for an anchor
func (r *ProofRepository) GetProofsByAnchorID(ctx context.Context, anchorID uuid.UUID) ([]*CertenAnchorProof, error) {
	query := `
		SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, verification_time, verification_details,
			validator_id, validator_signature, proof_version, created_at, updated_at
		FROM certen_anchor_proofs
		WHERE anchor_id = $1
		ORDER BY created_at ASC`

	rows, err := r.client.QueryContext(ctx, query, anchorID)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs by anchor: %w", err)
	}
	defer rows.Close()

	var proofs []*CertenAnchorProof
	for rows.Next() {
		proof := &CertenAnchorProof{}
		err := rows.Scan(
			&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
			&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
			&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
			&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
			&proof.GovProof, &proof.GovLevel, &proof.GovValid,
			&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
			&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return proofs, rows.Err()
}

// GetProofsByAccountURL retrieves all proofs for a specific Accumulate account
func (r *ProofRepository) GetProofsByAccountURL(ctx context.Context, accountURL string, limit int) ([]*CertenAnchorProof, error) {
	query := `
		SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, verification_time, verification_details,
			validator_id, validator_signature, proof_version, created_at, updated_at
		FROM certen_anchor_proofs
		WHERE account_url = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.client.QueryContext(ctx, query, accountURL, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs by account: %w", err)
	}
	defer rows.Close()

	var proofs []*CertenAnchorProof
	for rows.Next() {
		proof := &CertenAnchorProof{}
		err := rows.Scan(
			&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
			&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
			&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
			&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
			&proof.GovProof, &proof.GovLevel, &proof.GovValid,
			&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
			&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return proofs, rows.Err()
}

// ============================================================================
// PROOF VERIFICATION OPERATIONS
// ============================================================================

// UpdateVerification updates the verification status of a proof
func (r *ProofRepository) UpdateVerification(ctx context.Context, proofID uuid.UUID, verified bool, details json.RawMessage) error {
	query := `
		UPDATE certen_anchor_proofs
		SET verified = $2,
			verification_time = $3,
			verification_details = $4,
			updated_at = $5
		WHERE proof_id = $1`

	_, err := r.client.ExecContext(ctx, query,
		proofID, verified, time.Now(), details, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update verification: %w", err)
	}

	return nil
}

// UpdateAnchorConfirmations updates the anchor confirmations for a proof
func (r *ProofRepository) UpdateAnchorConfirmations(ctx context.Context, proofID uuid.UUID, confirmations int, blockHash string) error {
	query := `
		UPDATE certen_anchor_proofs
		SET anchor_confirmations = $2,
			anchor_block_hash = $3,
			updated_at = $4
		WHERE proof_id = $1`

	_, err := r.client.ExecContext(ctx, query,
		proofID, confirmations,
		sql.NullString{String: blockHash, Valid: blockHash != ""},
		time.Now())
	if err != nil {
		return fmt.Errorf("failed to update anchor confirmations: %w", err)
	}

	return nil
}

// UpdateValidatorSignature adds a validator signature to the proof
func (r *ProofRepository) UpdateValidatorSignature(ctx context.Context, proofID uuid.UUID, signature []byte) error {
	query := `
		UPDATE certen_anchor_proofs
		SET validator_signature = $2, updated_at = $3
		WHERE proof_id = $1`

	_, err := r.client.ExecContext(ctx, query, proofID, signature, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update validator signature: %w", err)
	}

	return nil
}

// UpdateAnchorID links the proof to its anchor record after anchoring completes
func (r *ProofRepository) UpdateAnchorID(ctx context.Context, proofID uuid.UUID, anchorID uuid.UUID) error {
	query := `
		UPDATE certen_anchor_proofs
		SET anchor_id = $2, updated_at = $3
		WHERE proof_id = $1`

	_, err := r.client.ExecContext(ctx, query, proofID, anchorID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update anchor ID: %w", err)
	}

	return nil
}

// ============================================================================
// PROOF QUERY OPERATIONS
// ============================================================================

// GetUnverifiedProofs returns proofs that haven't been verified yet
func (r *ProofRepository) GetUnverifiedProofs(ctx context.Context, limit int) ([]*CertenAnchorProof, error) {
	query := `
		SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, verification_time, verification_details,
			validator_id, validator_signature, proof_version, created_at, updated_at
		FROM certen_anchor_proofs
		WHERE verified = false
		ORDER BY created_at ASC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query unverified proofs: %w", err)
	}
	defer rows.Close()

	var proofs []*CertenAnchorProof
	for rows.Next() {
		proof := &CertenAnchorProof{}
		err := rows.Scan(
			&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
			&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
			&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
			&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
			&proof.GovProof, &proof.GovLevel, &proof.GovValid,
			&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
			&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return proofs, rows.Err()
}

// GetVerifiedProofs returns verified proofs, optionally filtered by governance level
func (r *ProofRepository) GetVerifiedProofs(ctx context.Context, govLevel GovernanceLevel, limit int) ([]*CertenAnchorProof, error) {
	var query string
	var args []interface{}

	if govLevel != "" {
		query = `
			SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
				account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
				anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
				accumulate_state_proof, accumulate_block_height, accumulate_bvn,
				governance_proof, governance_level, governance_valid,
				verified, verification_time, verification_details,
				validator_id, validator_signature, proof_version, created_at, updated_at
			FROM certen_anchor_proofs
			WHERE verified = true AND governance_level = $1
			ORDER BY created_at DESC
			LIMIT $2`
		args = []interface{}{govLevel, limit}
	} else {
		query = `
			SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
				account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
				anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
				accumulate_state_proof, accumulate_block_height, accumulate_bvn,
				governance_proof, governance_level, governance_valid,
				verified, verification_time, verification_details,
				validator_id, validator_signature, proof_version, created_at, updated_at
			FROM certen_anchor_proofs
			WHERE verified = true
			ORDER BY created_at DESC
			LIMIT $1`
		args = []interface{}{limit}
	}

	rows, err := r.client.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query verified proofs: %w", err)
	}
	defer rows.Close()

	var proofs []*CertenAnchorProof
	for rows.Next() {
		proof := &CertenAnchorProof{}
		err := rows.Scan(
			&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
			&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
			&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
			&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
			&proof.GovProof, &proof.GovLevel, &proof.GovValid,
			&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
			&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return proofs, rows.Err()
}

// CountProofs returns the total number of proofs
func (r *ProofRepository) CountProofs(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM certen_anchor_proofs`

	var count int64
	err := r.client.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count proofs: %w", err)
	}

	return count, nil
}

// CountVerifiedProofs returns the number of verified proofs
func (r *ProofRepository) CountVerifiedProofs(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM certen_anchor_proofs WHERE verified = true`

	var count int64
	err := r.client.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count verified proofs: %w", err)
	}

	return count, nil
}

// GetRecentProofs returns the most recent proofs
func (r *ProofRepository) GetRecentProofs(ctx context.Context, limit int) ([]*CertenAnchorProof, error) {
	query := `
		SELECT proof_id, batch_id, anchor_id, transaction_id, accumulate_tx_hash,
			account_url, merkle_root, merkle_inclusion_proof, anchor_chain,
			anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_confirmations,
			accumulate_state_proof, accumulate_block_height, accumulate_bvn,
			governance_proof, governance_level, governance_valid,
			verified, verification_time, verification_details,
			validator_id, validator_signature, proof_version, created_at, updated_at
		FROM certen_anchor_proofs
		ORDER BY created_at DESC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent proofs: %w", err)
	}
	defer rows.Close()

	var proofs []*CertenAnchorProof
	for rows.Next() {
		proof := &CertenAnchorProof{}
		err := rows.Scan(
			&proof.ProofID, &proof.BatchID, &proof.AnchorID, &proof.TransactionID, &proof.AccumTxHash,
			&proof.AccountURL, &proof.MerkleRoot, &proof.MerkleInclusion, &proof.AnchorChain,
			&proof.AnchorTxHash, &proof.AnchorBlockNumber, &proof.AnchorBlockHash, &proof.AnchorConfirms,
			&proof.AccumStateProof, &proof.AccumBlockHeight, &proof.AccumBVN,
			&proof.GovProof, &proof.GovLevel, &proof.GovValid,
			&proof.Verified, &proof.VerificationTime, &proof.VerifyDetails,
			&proof.ValidatorID, &proof.ValidatorSig, &proof.ProofVersion, &proof.CreatedAt, &proof.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, proof)
	}

	return proofs, rows.Err()
}
