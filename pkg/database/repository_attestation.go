// Copyright 2025 Certen Protocol
//
// Attestation Repository - CRUD operations for validator attestations over proofs
// Validators sign attestations to cryptographically endorse proof validity

package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AttestationRepository handles validator attestation operations
type AttestationRepository struct {
	client *Client
}

// NewAttestationRepository creates a new attestation repository
func NewAttestationRepository(client *Client) *AttestationRepository {
	return &AttestationRepository{client: client}
}

// ============================================================================
// VALIDATOR ATTESTATION OPERATIONS
// ============================================================================

// NewValidatorAttestation is used to create a new attestation
type NewValidatorAttestation struct {
	ProofID            uuid.UUID
	ValidatorID        string
	ValidatorPubkey    []byte // 32 bytes Ed25519 public key
	Signature          []byte // 64 bytes Ed25519 signature
	AttestedMerkleRoot []byte // The merkle root being attested
	AttestedAnchorTx   string // The anchor tx hash being attested
}

// CreateAttestation creates a new validator attestation
func (r *AttestationRepository) CreateAttestation(ctx context.Context, input *NewValidatorAttestation) (*ValidatorAttestation, error) {
	attestation := &ValidatorAttestation{
		AttestationID:      uuid.New(),
		ProofID:            input.ProofID,
		ValidatorID:        input.ValidatorID,
		ValidatorPubkey:    input.ValidatorPubkey,
		Signature:          input.Signature,
		AttestedMerkleRoot: input.AttestedMerkleRoot,
		AttestedAnchorTx:   input.AttestedAnchorTx,
		AttestedAt:         time.Now(),
	}

	query := `
		INSERT INTO validator_attestations (
			attestation_id, proof_id, validator_id, validator_pubkey,
			signature, attested_merkle_root, attested_anchor_tx_hash, attested_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING attestation_id, attested_at`

	err := r.client.QueryRowContext(ctx, query,
		attestation.AttestationID, attestation.ProofID, attestation.ValidatorID,
		attestation.ValidatorPubkey, attestation.Signature, attestation.AttestedMerkleRoot,
		attestation.AttestedAnchorTx, attestation.AttestedAt,
	).Scan(&attestation.AttestationID, &attestation.AttestedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create attestation: %w", err)
	}

	return attestation, nil
}

// GetAttestation retrieves an attestation by ID
func (r *AttestationRepository) GetAttestation(ctx context.Context, attestationID uuid.UUID) (*ValidatorAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, validator_id, validator_pubkey,
			signature, attested_merkle_root, attested_anchor_tx_hash, attested_at
		FROM validator_attestations
		WHERE attestation_id = $1`

	attestation := &ValidatorAttestation{}
	err := r.client.QueryRowContext(ctx, query, attestationID).Scan(
		&attestation.AttestationID, &attestation.ProofID, &attestation.ValidatorID,
		&attestation.ValidatorPubkey, &attestation.Signature, &attestation.AttestedMerkleRoot,
		&attestation.AttestedAnchorTx, &attestation.AttestedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrAttestationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}

	return attestation, nil
}

// GetAttestationsByProof retrieves all attestations for a specific proof
func (r *AttestationRepository) GetAttestationsByProof(ctx context.Context, proofID uuid.UUID) ([]*ValidatorAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, validator_id, validator_pubkey,
			signature, attested_merkle_root, attested_anchor_tx_hash, attested_at
		FROM validator_attestations
		WHERE proof_id = $1
		ORDER BY attested_at ASC`

	rows, err := r.client.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("failed to query attestations by proof: %w", err)
	}
	defer rows.Close()

	var attestations []*ValidatorAttestation
	for rows.Next() {
		attestation := &ValidatorAttestation{}
		err := rows.Scan(
			&attestation.AttestationID, &attestation.ProofID, &attestation.ValidatorID,
			&attestation.ValidatorPubkey, &attestation.Signature, &attestation.AttestedMerkleRoot,
			&attestation.AttestedAnchorTx, &attestation.AttestedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan attestation: %w", err)
		}
		attestations = append(attestations, attestation)
	}

	return attestations, rows.Err()
}

// GetAttestationsByValidator retrieves all attestations from a specific validator
func (r *AttestationRepository) GetAttestationsByValidator(ctx context.Context, validatorID string, limit int) ([]*ValidatorAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, validator_id, validator_pubkey,
			signature, attested_merkle_root, attested_anchor_tx_hash, attested_at
		FROM validator_attestations
		WHERE validator_id = $1
		ORDER BY attested_at DESC
		LIMIT $2`

	rows, err := r.client.QueryContext(ctx, query, validatorID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query attestations by validator: %w", err)
	}
	defer rows.Close()

	var attestations []*ValidatorAttestation
	for rows.Next() {
		attestation := &ValidatorAttestation{}
		err := rows.Scan(
			&attestation.AttestationID, &attestation.ProofID, &attestation.ValidatorID,
			&attestation.ValidatorPubkey, &attestation.Signature, &attestation.AttestedMerkleRoot,
			&attestation.AttestedAnchorTx, &attestation.AttestedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan attestation: %w", err)
		}
		attestations = append(attestations, attestation)
	}

	return attestations, rows.Err()
}

// GetAttestationByValidatorAndProof checks if a validator has already attested to a proof
func (r *AttestationRepository) GetAttestationByValidatorAndProof(ctx context.Context, validatorID string, proofID uuid.UUID) (*ValidatorAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, validator_id, validator_pubkey,
			signature, attested_merkle_root, attested_anchor_tx_hash, attested_at
		FROM validator_attestations
		WHERE validator_id = $1 AND proof_id = $2`

	attestation := &ValidatorAttestation{}
	err := r.client.QueryRowContext(ctx, query, validatorID, proofID).Scan(
		&attestation.AttestationID, &attestation.ProofID, &attestation.ValidatorID,
		&attestation.ValidatorPubkey, &attestation.Signature, &attestation.AttestedMerkleRoot,
		&attestation.AttestedAnchorTx, &attestation.AttestedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrAttestationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation by validator and proof: %w", err)
	}

	return attestation, nil
}

// CountAttestationsForProof returns the number of attestations for a proof
func (r *AttestationRepository) CountAttestationsForProof(ctx context.Context, proofID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM validator_attestations WHERE proof_id = $1`

	var count int
	err := r.client.QueryRowContext(ctx, query, proofID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count attestations: %w", err)
	}

	return count, nil
}

// CountAttestationsByValidator returns the total number of attestations by a validator
func (r *AttestationRepository) CountAttestationsByValidator(ctx context.Context, validatorID string) (int64, error) {
	query := `SELECT COUNT(*) FROM validator_attestations WHERE validator_id = $1`

	var count int64
	err := r.client.QueryRowContext(ctx, query, validatorID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count validator attestations: %w", err)
	}

	return count, nil
}

// GetAttestationsByMerkleRoot retrieves attestations that attest to a specific merkle root
func (r *AttestationRepository) GetAttestationsByMerkleRoot(ctx context.Context, merkleRoot []byte) ([]*ValidatorAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, validator_id, validator_pubkey,
			signature, attested_merkle_root, attested_anchor_tx_hash, attested_at
		FROM validator_attestations
		WHERE attested_merkle_root = $1
		ORDER BY attested_at ASC`

	rows, err := r.client.QueryContext(ctx, query, merkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to query attestations by merkle root: %w", err)
	}
	defer rows.Close()

	var attestations []*ValidatorAttestation
	for rows.Next() {
		attestation := &ValidatorAttestation{}
		err := rows.Scan(
			&attestation.AttestationID, &attestation.ProofID, &attestation.ValidatorID,
			&attestation.ValidatorPubkey, &attestation.Signature, &attestation.AttestedMerkleRoot,
			&attestation.AttestedAnchorTx, &attestation.AttestedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan attestation: %w", err)
		}
		attestations = append(attestations, attestation)
	}

	return attestations, rows.Err()
}

// GetRecentAttestations returns the most recent attestations
func (r *AttestationRepository) GetRecentAttestations(ctx context.Context, limit int) ([]*ValidatorAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, validator_id, validator_pubkey,
			signature, attested_merkle_root, attested_anchor_tx_hash, attested_at
		FROM validator_attestations
		ORDER BY attested_at DESC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent attestations: %w", err)
	}
	defer rows.Close()

	var attestations []*ValidatorAttestation
	for rows.Next() {
		attestation := &ValidatorAttestation{}
		err := rows.Scan(
			&attestation.AttestationID, &attestation.ProofID, &attestation.ValidatorID,
			&attestation.ValidatorPubkey, &attestation.Signature, &attestation.AttestedMerkleRoot,
			&attestation.AttestedAnchorTx, &attestation.AttestedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan attestation: %w", err)
		}
		attestations = append(attestations, attestation)
	}

	return attestations, rows.Err()
}

// CountTotalAttestations returns the total number of attestations in the system
func (r *AttestationRepository) CountTotalAttestations(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM validator_attestations`

	var count int64
	err := r.client.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count total attestations: %w", err)
	}

	return count, nil
}

// GetDistinctValidators returns a list of distinct validator IDs that have submitted attestations
func (r *AttestationRepository) GetDistinctValidators(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT validator_id FROM validator_attestations ORDER BY validator_id`

	rows, err := r.client.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query distinct validators: %w", err)
	}
	defer rows.Close()

	var validators []string
	for rows.Next() {
		var validatorID string
		if err := rows.Scan(&validatorID); err != nil {
			return nil, fmt.Errorf("failed to scan validator ID: %w", err)
		}
		validators = append(validators, validatorID)
	}

	return validators, rows.Err()
}
