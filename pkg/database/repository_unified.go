// Copyright 2025 Certen Protocol
//
// Unified Repository - CRUD for Multi-Chain and Multi-Attestation Tables
// Handles unified_attestations, aggregated_attestations, chain_execution_results
//
// Per Unified Multi-Chain Architecture:
// - Scheme-agnostic attestation storage
// - Platform-agnostic chain execution storage
// - Links to proof_artifacts for complete tracking

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

// AttestationScheme represents the cryptographic scheme for attestations
type AttestationScheme string

const (
	AttestationSchemeBLS12381  AttestationScheme = "bls12-381"
	AttestationSchemeEd25519   AttestationScheme = "ed25519"
	AttestationSchemeSchnorr   AttestationScheme = "schnorr"
	AttestationSchemeThreshold AttestationScheme = "threshold"
)

// ChainPlatform represents the blockchain platform type
type ChainPlatform string

const (
	ChainPlatformEVM      ChainPlatform = "evm"
	ChainPlatformCosmWasm ChainPlatform = "cosmwasm"
	ChainPlatformSolana   ChainPlatform = "solana"
	ChainPlatformMove     ChainPlatform = "move"
	ChainPlatformTON      ChainPlatform = "ton"
	ChainPlatformNEAR     ChainPlatform = "near"
)

// ExecutionStatus represents the status of a chain execution
type ExecutionStatus int

const (
	ExecutionStatusPending ExecutionStatus = 0
	ExecutionStatusSuccess ExecutionStatus = 1
	ExecutionStatusFailed  ExecutionStatus = 2
)

// WorkflowStep represents the anchor workflow step
type WorkflowStep int

const (
	WorkflowStepCreate     WorkflowStep = 1
	WorkflowStepVerify     WorkflowStep = 2
	WorkflowStepGovernance WorkflowStep = 3
)

// =============================================================================
// UNIFIED ATTESTATION TYPES
// =============================================================================

// UnifiedAttestation represents a single validator attestation
type UnifiedAttestation struct {
	AttestationID       uuid.UUID         `db:"attestation_id" json:"attestation_id"`
	ProofID             uuid.NullUUID     `db:"proof_id" json:"proof_id,omitempty"`
	CycleID             string            `db:"cycle_id" json:"cycle_id"`
	Scheme              AttestationScheme `db:"scheme" json:"scheme"`
	ValidatorID         string            `db:"validator_id" json:"validator_id"`
	ValidatorIndex      sql.NullInt32     `db:"validator_index" json:"validator_index,omitempty"`
	PublicKey           []byte            `db:"public_key" json:"public_key"`
	Signature           []byte            `db:"signature" json:"signature"`
	MessageHash         []byte            `db:"message_hash" json:"message_hash"`
	Weight              int64             `db:"weight" json:"weight"`
	SignatureValid      sql.NullBool      `db:"signature_valid" json:"signature_valid,omitempty"`
	VerifiedAt          sql.NullTime      `db:"verified_at" json:"verified_at,omitempty"`
	VerificationNotes   sql.NullString    `db:"verification_notes" json:"verification_notes,omitempty"`
	AttestedBlockNumber sql.NullInt64     `db:"attested_block_number" json:"attested_block_number,omitempty"`
	AttestedBlockHash   []byte            `db:"attested_block_hash" json:"attested_block_hash,omitempty"`
	AttestedAt          time.Time         `db:"attested_at" json:"attested_at"`
	CreatedAt           time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time         `db:"updated_at" json:"updated_at"`
}

// NewUnifiedAttestation is input for creating a unified attestation
type NewUnifiedAttestation struct {
	ProofID             *uuid.UUID
	CycleID             string
	Scheme              AttestationScheme
	ValidatorID         string
	ValidatorIndex      *int32
	PublicKey           []byte
	Signature           []byte
	MessageHash         []byte
	Weight              int64
	AttestedBlockNumber *int64
	AttestedBlockHash   []byte
	AttestedAt          time.Time
}

// =============================================================================
// AGGREGATED ATTESTATION TYPES
// =============================================================================

// UnifiedAggregatedAttestation represents aggregated attestations (unified multi-chain)
type UnifiedAggregatedAttestation struct {
	AggregationID        uuid.UUID         `db:"aggregation_id" json:"aggregation_id"`
	ProofID              uuid.NullUUID     `db:"proof_id" json:"proof_id,omitempty"`
	CycleID              string            `db:"cycle_id" json:"cycle_id"`
	Scheme               AttestationScheme `db:"scheme" json:"scheme"`
	MessageHash          []byte            `db:"message_hash" json:"message_hash"`
	AggregatedSignature  []byte            `db:"aggregated_signature" json:"aggregated_signature,omitempty"`
	AggregatedPublicKey  []byte            `db:"aggregated_public_key" json:"aggregated_public_key,omitempty"`
	ParticipantIDs       json.RawMessage   `db:"participant_ids" json:"participant_ids"`
	ParticipantCount     int               `db:"participant_count" json:"participant_count"`
	ValidatorBitfield    []byte            `db:"validator_bitfield" json:"validator_bitfield,omitempty"`
	TotalWeight          int64             `db:"total_weight" json:"total_weight"`
	AchievedWeight       int64             `db:"achieved_weight" json:"achieved_weight"`
	ThresholdWeight      int64             `db:"threshold_weight" json:"threshold_weight"`
	ThresholdMet         bool              `db:"threshold_met" json:"threshold_met"`
	ThresholdNumerator   int               `db:"threshold_numerator" json:"threshold_numerator"`
	ThresholdDenominator int               `db:"threshold_denominator" json:"threshold_denominator"`
	AggregationValid     sql.NullBool      `db:"aggregation_valid" json:"aggregation_valid,omitempty"`
	VerifiedAt           sql.NullTime      `db:"verified_at" json:"verified_at,omitempty"`
	VerificationNotes    sql.NullString    `db:"verification_notes" json:"verification_notes,omitempty"`
	AttestationIDs       json.RawMessage   `db:"attestation_ids" json:"attestation_ids,omitempty"`
	FirstAttestationAt   sql.NullTime      `db:"first_attestation_at" json:"first_attestation_at,omitempty"`
	LastAttestationAt    sql.NullTime      `db:"last_attestation_at" json:"last_attestation_at,omitempty"`
	AggregatedAt         time.Time         `db:"aggregated_at" json:"aggregated_at"`
	CreatedAt            time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt            time.Time         `db:"updated_at" json:"updated_at"`
}

// NewUnifiedAggregatedAttestation is input for creating an aggregated attestation (unified)
type NewUnifiedAggregatedAttestation struct {
	ProofID              *uuid.UUID
	CycleID              string
	Scheme               AttestationScheme
	MessageHash          []byte
	AggregatedSignature  []byte // BLS only
	AggregatedPublicKey  []byte // BLS only
	ParticipantIDs       []string
	ParticipantCount     int
	ValidatorBitfield    []byte
	TotalWeight          int64
	AchievedWeight       int64
	ThresholdWeight      int64
	ThresholdMet         bool
	ThresholdNumerator   int
	ThresholdDenominator int
	AttestationIDs       []uuid.UUID
	FirstAttestationAt   *time.Time
	LastAttestationAt    *time.Time
	AggregatedAt         time.Time
}

// =============================================================================
// CHAIN EXECUTION RESULT TYPES
// =============================================================================

// ChainExecutionResult represents a chain execution result
type ChainExecutionResult struct {
	ResultID              uuid.UUID       `db:"result_id" json:"result_id"`
	ProofID               uuid.NullUUID   `db:"proof_id" json:"proof_id,omitempty"`
	CycleID               string          `db:"cycle_id" json:"cycle_id"`
	ChainPlatform         ChainPlatform   `db:"chain_platform" json:"chain_platform"`
	ChainID               string          `db:"chain_id" json:"chain_id"`
	NetworkName           sql.NullString  `db:"network_name" json:"network_name,omitempty"`
	TxHash                string          `db:"tx_hash" json:"tx_hash"`
	BlockNumber           sql.NullInt64   `db:"block_number" json:"block_number,omitempty"`
	BlockHash             sql.NullString  `db:"block_hash" json:"block_hash,omitempty"`
	BlockTimestamp        sql.NullTime    `db:"block_timestamp" json:"block_timestamp,omitempty"`
	Status                ExecutionStatus `db:"status" json:"status"`
	GasUsed               sql.NullInt64   `db:"gas_used" json:"gas_used,omitempty"`
	GasCost               sql.NullString  `db:"gas_cost" json:"gas_cost,omitempty"`
	Confirmations         int             `db:"confirmations" json:"confirmations"`
	RequiredConfirmations sql.NullInt32   `db:"required_confirmations" json:"required_confirmations,omitempty"`
	IsFinalized           bool            `db:"is_finalized" json:"is_finalized"`
	ResultHash            []byte          `db:"result_hash" json:"result_hash,omitempty"`
	MerkleProof           []byte          `db:"merkle_proof" json:"merkle_proof,omitempty"`
	ReceiptProof          []byte          `db:"receipt_proof" json:"receipt_proof,omitempty"`
	StateRoot             []byte          `db:"state_root" json:"state_root,omitempty"`
	TransactionsRoot      []byte          `db:"transactions_root" json:"transactions_root,omitempty"`
	ReceiptsRoot          []byte          `db:"receipts_root" json:"receipts_root,omitempty"`
	RawReceipt            json.RawMessage `db:"raw_receipt" json:"raw_receipt,omitempty"`
	Logs                  json.RawMessage `db:"logs" json:"logs,omitempty"`
	PlatformData          json.RawMessage `db:"platform_data" json:"platform_data,omitempty"`
	ObserverValidatorID   sql.NullString  `db:"observer_validator_id" json:"observer_validator_id,omitempty"`
	WorkflowStep          sql.NullInt16   `db:"workflow_step" json:"workflow_step,omitempty"`
	AnchorID              []byte          `db:"anchor_id" json:"anchor_id,omitempty"`
	SubmittedAt           sql.NullTime    `db:"submitted_at" json:"submitted_at,omitempty"`
	ConfirmedAt           sql.NullTime    `db:"confirmed_at" json:"confirmed_at,omitempty"`
	FinalizedAt           sql.NullTime    `db:"finalized_at" json:"finalized_at,omitempty"`
	CreatedAt             time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt             time.Time       `db:"updated_at" json:"updated_at"`
}

// NewChainExecutionResult is input for creating a chain execution result
type NewChainExecutionResult struct {
	ProofID               *uuid.UUID
	CycleID               string
	ChainPlatform         ChainPlatform
	ChainID               string
	NetworkName           string
	TxHash                string
	BlockNumber           *int64
	BlockHash             string
	BlockTimestamp        *time.Time
	Status                ExecutionStatus
	GasUsed               *int64
	GasCost               string
	Confirmations         int
	RequiredConfirmations *int
	IsFinalized           bool
	ResultHash            []byte
	MerkleProof           []byte
	ReceiptProof          []byte
	StateRoot             []byte
	TransactionsRoot      []byte
	ReceiptsRoot          []byte
	RawReceipt            json.RawMessage
	Logs                  json.RawMessage
	PlatformData          json.RawMessage
	ObserverValidatorID   string
	WorkflowStep          *WorkflowStep
	AnchorID              []byte
	SubmittedAt           *time.Time
}

// =============================================================================
// UNIFIED REPOSITORY
// =============================================================================

// UnifiedRepository handles CRUD for unified multi-chain tables
type UnifiedRepository struct {
	db *sql.DB
}

// NewUnifiedRepository creates a new unified repository
func NewUnifiedRepository(db *sql.DB) *UnifiedRepository {
	return &UnifiedRepository{db: db}
}

// =============================================================================
// UNIFIED ATTESTATION CRUD
// =============================================================================

// CreateUnifiedAttestation creates a new unified attestation
func (r *UnifiedRepository) CreateUnifiedAttestation(ctx context.Context, input *NewUnifiedAttestation) (uuid.UUID, error) {
	id := uuid.New()

	query := `
		INSERT INTO unified_attestations (
			attestation_id, proof_id, cycle_id, scheme, validator_id, validator_index,
			public_key, signature, message_hash, weight,
			attested_block_number, attested_block_hash, attested_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	var proofID interface{}
	if input.ProofID != nil {
		proofID = *input.ProofID
	}

	var validatorIndex interface{}
	if input.ValidatorIndex != nil {
		validatorIndex = *input.ValidatorIndex
	}

	var blockNumber interface{}
	if input.AttestedBlockNumber != nil {
		blockNumber = *input.AttestedBlockNumber
	}

	_, err := r.db.ExecContext(ctx, query,
		id, proofID, input.CycleID, input.Scheme, input.ValidatorID, validatorIndex,
		input.PublicKey, input.Signature, input.MessageHash, input.Weight,
		blockNumber, input.AttestedBlockHash, input.AttestedAt,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create unified attestation: %w", err)
	}

	return id, nil
}

// GetUnifiedAttestation retrieves a unified attestation by ID
func (r *UnifiedRepository) GetUnifiedAttestation(ctx context.Context, id uuid.UUID) (*UnifiedAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, cycle_id, scheme, validator_id, validator_index,
		       public_key, signature, message_hash, weight,
		       signature_valid, verified_at, verification_notes,
		       attested_block_number, attested_block_hash, attested_at,
		       created_at, updated_at
		FROM unified_attestations
		WHERE attestation_id = $1
	`

	var att UnifiedAttestation
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&att.AttestationID, &att.ProofID, &att.CycleID, &att.Scheme,
		&att.ValidatorID, &att.ValidatorIndex, &att.PublicKey, &att.Signature,
		&att.MessageHash, &att.Weight, &att.SignatureValid, &att.VerifiedAt,
		&att.VerificationNotes, &att.AttestedBlockNumber, &att.AttestedBlockHash,
		&att.AttestedAt, &att.CreatedAt, &att.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get unified attestation: %w", err)
	}

	return &att, nil
}

// GetUnifiedAttestationsByProof retrieves all attestations for a proof
func (r *UnifiedRepository) GetUnifiedAttestationsByProof(ctx context.Context, proofID uuid.UUID) ([]*UnifiedAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, cycle_id, scheme, validator_id, validator_index,
		       public_key, signature, message_hash, weight,
		       signature_valid, verified_at, verification_notes,
		       attested_block_number, attested_block_hash, attested_at,
		       created_at, updated_at
		FROM unified_attestations
		WHERE proof_id = $1
		ORDER BY attested_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("query attestations: %w", err)
	}
	defer rows.Close()

	var attestations []*UnifiedAttestation
	for rows.Next() {
		var att UnifiedAttestation
		err := rows.Scan(
			&att.AttestationID, &att.ProofID, &att.CycleID, &att.Scheme,
			&att.ValidatorID, &att.ValidatorIndex, &att.PublicKey, &att.Signature,
			&att.MessageHash, &att.Weight, &att.SignatureValid, &att.VerifiedAt,
			&att.VerificationNotes, &att.AttestedBlockNumber, &att.AttestedBlockHash,
			&att.AttestedAt, &att.CreatedAt, &att.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan attestation: %w", err)
		}
		attestations = append(attestations, &att)
	}

	return attestations, nil
}

// GetUnifiedAttestationsByScheme retrieves attestations by scheme for a proof
func (r *UnifiedRepository) GetUnifiedAttestationsByScheme(ctx context.Context, proofID uuid.UUID, scheme AttestationScheme) ([]*UnifiedAttestation, error) {
	query := `
		SELECT attestation_id, proof_id, cycle_id, scheme, validator_id, validator_index,
		       public_key, signature, message_hash, weight,
		       signature_valid, verified_at, verification_notes,
		       attested_block_number, attested_block_hash, attested_at,
		       created_at, updated_at
		FROM unified_attestations
		WHERE proof_id = $1 AND scheme = $2
		ORDER BY attested_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, proofID, scheme)
	if err != nil {
		return nil, fmt.Errorf("query attestations by scheme: %w", err)
	}
	defer rows.Close()

	var attestations []*UnifiedAttestation
	for rows.Next() {
		var att UnifiedAttestation
		err := rows.Scan(
			&att.AttestationID, &att.ProofID, &att.CycleID, &att.Scheme,
			&att.ValidatorID, &att.ValidatorIndex, &att.PublicKey, &att.Signature,
			&att.MessageHash, &att.Weight, &att.SignatureValid, &att.VerifiedAt,
			&att.VerificationNotes, &att.AttestedBlockNumber, &att.AttestedBlockHash,
			&att.AttestedAt, &att.CreatedAt, &att.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan attestation: %w", err)
		}
		attestations = append(attestations, &att)
	}

	return attestations, nil
}

// MarkUnifiedAttestationVerified marks an attestation as verified
func (r *UnifiedRepository) MarkUnifiedAttestationVerified(ctx context.Context, id uuid.UUID, valid bool, notes string) error {
	query := `
		UPDATE unified_attestations
		SET signature_valid = $2, verified_at = NOW(), verification_notes = $3
		WHERE attestation_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, valid, notes)
	if err != nil {
		return fmt.Errorf("mark attestation verified: %w", err)
	}

	return nil
}

// =============================================================================
// AGGREGATED ATTESTATION CRUD
// =============================================================================

// CreateAggregatedAttestation creates a new aggregated attestation
func (r *UnifiedRepository) CreateAggregatedAttestation(ctx context.Context, input *NewUnifiedAggregatedAttestation) (uuid.UUID, error) {
	id := uuid.New()

	participantIDsJSON, err := json.Marshal(input.ParticipantIDs)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal participant IDs: %w", err)
	}

	var attestationIDsJSON []byte
	if len(input.AttestationIDs) > 0 {
		attestationIDsJSON, err = json.Marshal(input.AttestationIDs)
		if err != nil {
			return uuid.Nil, fmt.Errorf("marshal attestation IDs: %w", err)
		}
	}

	query := `
		INSERT INTO aggregated_attestations (
			aggregation_id, proof_id, cycle_id, scheme, message_hash,
			aggregated_signature, aggregated_public_key,
			participant_ids, participant_count, validator_bitfield,
			total_weight, achieved_weight, threshold_weight, threshold_met,
			threshold_numerator, threshold_denominator,
			attestation_ids, first_attestation_at, last_attestation_at, aggregated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`

	var proofID interface{}
	if input.ProofID != nil {
		proofID = *input.ProofID
	}

	_, err = r.db.ExecContext(ctx, query,
		id, proofID, input.CycleID, input.Scheme, input.MessageHash,
		input.AggregatedSignature, input.AggregatedPublicKey,
		participantIDsJSON, input.ParticipantCount, input.ValidatorBitfield,
		input.TotalWeight, input.AchievedWeight, input.ThresholdWeight, input.ThresholdMet,
		input.ThresholdNumerator, input.ThresholdDenominator,
		attestationIDsJSON, input.FirstAttestationAt, input.LastAttestationAt, input.AggregatedAt,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create aggregated attestation: %w", err)
	}

	return id, nil
}

// GetAggregatedAttestation retrieves an aggregated attestation by ID
func (r *UnifiedRepository) GetAggregatedAttestation(ctx context.Context, id uuid.UUID) (*UnifiedAggregatedAttestation, error) {
	query := `
		SELECT aggregation_id, proof_id, cycle_id, scheme, message_hash,
		       aggregated_signature, aggregated_public_key,
		       participant_ids, participant_count, validator_bitfield,
		       total_weight, achieved_weight, threshold_weight, threshold_met,
		       threshold_numerator, threshold_denominator,
		       aggregation_valid, verified_at, verification_notes,
		       attestation_ids, first_attestation_at, last_attestation_at,
		       aggregated_at, created_at, updated_at
		FROM aggregated_attestations
		WHERE aggregation_id = $1
	`

	var agg UnifiedAggregatedAttestation
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&agg.AggregationID, &agg.ProofID, &agg.CycleID, &agg.Scheme, &agg.MessageHash,
		&agg.AggregatedSignature, &agg.AggregatedPublicKey,
		&agg.ParticipantIDs, &agg.ParticipantCount, &agg.ValidatorBitfield,
		&agg.TotalWeight, &agg.AchievedWeight, &agg.ThresholdWeight, &agg.ThresholdMet,
		&agg.ThresholdNumerator, &agg.ThresholdDenominator,
		&agg.AggregationValid, &agg.VerifiedAt, &agg.VerificationNotes,
		&agg.AttestationIDs, &agg.FirstAttestationAt, &agg.LastAttestationAt,
		&agg.AggregatedAt, &agg.CreatedAt, &agg.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get aggregated attestation: %w", err)
	}

	return &agg, nil
}

// GetAggregatedAttestationByProof retrieves aggregated attestation for a proof
func (r *UnifiedRepository) GetAggregatedAttestationByProof(ctx context.Context, proofID uuid.UUID, scheme AttestationScheme) (*UnifiedAggregatedAttestation, error) {
	query := `
		SELECT aggregation_id, proof_id, cycle_id, scheme, message_hash,
		       aggregated_signature, aggregated_public_key,
		       participant_ids, participant_count, validator_bitfield,
		       total_weight, achieved_weight, threshold_weight, threshold_met,
		       threshold_numerator, threshold_denominator,
		       aggregation_valid, verified_at, verification_notes,
		       attestation_ids, first_attestation_at, last_attestation_at,
		       aggregated_at, created_at, updated_at
		FROM aggregated_attestations
		WHERE proof_id = $1 AND scheme = $2
	`

	var agg UnifiedAggregatedAttestation
	err := r.db.QueryRowContext(ctx, query, proofID, scheme).Scan(
		&agg.AggregationID, &agg.ProofID, &agg.CycleID, &agg.Scheme, &agg.MessageHash,
		&agg.AggregatedSignature, &agg.AggregatedPublicKey,
		&agg.ParticipantIDs, &agg.ParticipantCount, &agg.ValidatorBitfield,
		&agg.TotalWeight, &agg.AchievedWeight, &agg.ThresholdWeight, &agg.ThresholdMet,
		&agg.ThresholdNumerator, &agg.ThresholdDenominator,
		&agg.AggregationValid, &agg.VerifiedAt, &agg.VerificationNotes,
		&agg.AttestationIDs, &agg.FirstAttestationAt, &agg.LastAttestationAt,
		&agg.AggregatedAt, &agg.CreatedAt, &agg.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get aggregated attestation by proof: %w", err)
	}

	return &agg, nil
}

// MarkAggregatedAttestationVerified marks an aggregation as verified
func (r *UnifiedRepository) MarkAggregatedAttestationVerified(ctx context.Context, id uuid.UUID, valid bool, notes string) error {
	query := `
		UPDATE aggregated_attestations
		SET aggregation_valid = $2, verified_at = NOW(), verification_notes = $3
		WHERE aggregation_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, valid, notes)
	if err != nil {
		return fmt.Errorf("mark aggregation verified: %w", err)
	}

	return nil
}

// =============================================================================
// CHAIN EXECUTION RESULT CRUD
// =============================================================================

// CreateChainExecutionResult creates a new chain execution result
func (r *UnifiedRepository) CreateChainExecutionResult(ctx context.Context, input *NewChainExecutionResult) (uuid.UUID, error) {
	id := uuid.New()

	query := `
		INSERT INTO chain_execution_results (
			result_id, proof_id, cycle_id, chain_platform, chain_id, network_name,
			tx_hash, block_number, block_hash, block_timestamp,
			status, gas_used, gas_cost, confirmations, required_confirmations, is_finalized,
			result_hash, merkle_proof, receipt_proof,
			state_root, transactions_root, receipts_root,
			raw_receipt, logs, platform_data,
			observer_validator_id, workflow_step, anchor_id, submitted_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)
	`

	var proofID interface{}
	if input.ProofID != nil {
		proofID = *input.ProofID
	}

	var blockNumber interface{}
	if input.BlockNumber != nil {
		blockNumber = *input.BlockNumber
	}

	var gasUsed interface{}
	if input.GasUsed != nil {
		gasUsed = *input.GasUsed
	}

	var requiredConfirmations interface{}
	if input.RequiredConfirmations != nil {
		requiredConfirmations = *input.RequiredConfirmations
	}

	var workflowStep interface{}
	if input.WorkflowStep != nil {
		workflowStep = *input.WorkflowStep
	}

	_, err := r.db.ExecContext(ctx, query,
		id, proofID, input.CycleID, input.ChainPlatform, input.ChainID, input.NetworkName,
		input.TxHash, blockNumber, input.BlockHash, input.BlockTimestamp,
		input.Status, gasUsed, input.GasCost, input.Confirmations, requiredConfirmations, input.IsFinalized,
		input.ResultHash, input.MerkleProof, input.ReceiptProof,
		input.StateRoot, input.TransactionsRoot, input.ReceiptsRoot,
		input.RawReceipt, input.Logs, input.PlatformData,
		input.ObserverValidatorID, workflowStep, input.AnchorID, input.SubmittedAt,
	)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create chain execution result: %w", err)
	}

	return id, nil
}

// GetChainExecutionResult retrieves a chain execution result by ID
func (r *UnifiedRepository) GetChainExecutionResult(ctx context.Context, id uuid.UUID) (*ChainExecutionResult, error) {
	query := `
		SELECT result_id, proof_id, cycle_id, chain_platform, chain_id, network_name,
		       tx_hash, block_number, block_hash, block_timestamp,
		       status, gas_used, gas_cost, confirmations, required_confirmations, is_finalized,
		       result_hash, merkle_proof, receipt_proof,
		       state_root, transactions_root, receipts_root,
		       raw_receipt, logs, platform_data,
		       observer_validator_id, workflow_step, anchor_id,
		       submitted_at, confirmed_at, finalized_at, created_at, updated_at
		FROM chain_execution_results
		WHERE result_id = $1
	`

	var result ChainExecutionResult
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&result.ResultID, &result.ProofID, &result.CycleID, &result.ChainPlatform,
		&result.ChainID, &result.NetworkName, &result.TxHash, &result.BlockNumber,
		&result.BlockHash, &result.BlockTimestamp, &result.Status, &result.GasUsed,
		&result.GasCost, &result.Confirmations, &result.RequiredConfirmations, &result.IsFinalized,
		&result.ResultHash, &result.MerkleProof, &result.ReceiptProof,
		&result.StateRoot, &result.TransactionsRoot, &result.ReceiptsRoot,
		&result.RawReceipt, &result.Logs, &result.PlatformData,
		&result.ObserverValidatorID, &result.WorkflowStep, &result.AnchorID,
		&result.SubmittedAt, &result.ConfirmedAt, &result.FinalizedAt,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get chain execution result: %w", err)
	}

	return &result, nil
}

// GetChainExecutionResultsByProof retrieves all execution results for a proof
func (r *UnifiedRepository) GetChainExecutionResultsByProof(ctx context.Context, proofID uuid.UUID) ([]*ChainExecutionResult, error) {
	query := `
		SELECT result_id, proof_id, cycle_id, chain_platform, chain_id, network_name,
		       tx_hash, block_number, block_hash, block_timestamp,
		       status, gas_used, gas_cost, confirmations, required_confirmations, is_finalized,
		       result_hash, merkle_proof, receipt_proof,
		       state_root, transactions_root, receipts_root,
		       raw_receipt, logs, platform_data,
		       observer_validator_id, workflow_step, anchor_id,
		       submitted_at, confirmed_at, finalized_at, created_at, updated_at
		FROM chain_execution_results
		WHERE proof_id = $1
		ORDER BY workflow_step ASC, created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, proofID)
	if err != nil {
		return nil, fmt.Errorf("query execution results: %w", err)
	}
	defer rows.Close()

	var results []*ChainExecutionResult
	for rows.Next() {
		var result ChainExecutionResult
		err := rows.Scan(
			&result.ResultID, &result.ProofID, &result.CycleID, &result.ChainPlatform,
			&result.ChainID, &result.NetworkName, &result.TxHash, &result.BlockNumber,
			&result.BlockHash, &result.BlockTimestamp, &result.Status, &result.GasUsed,
			&result.GasCost, &result.Confirmations, &result.RequiredConfirmations, &result.IsFinalized,
			&result.ResultHash, &result.MerkleProof, &result.ReceiptProof,
			&result.StateRoot, &result.TransactionsRoot, &result.ReceiptsRoot,
			&result.RawReceipt, &result.Logs, &result.PlatformData,
			&result.ObserverValidatorID, &result.WorkflowStep, &result.AnchorID,
			&result.SubmittedAt, &result.ConfirmedAt, &result.FinalizedAt,
			&result.CreatedAt, &result.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan execution result: %w", err)
		}
		results = append(results, &result)
	}

	return results, nil
}

// GetChainExecutionResultByTxHash retrieves a result by chain and tx hash
func (r *UnifiedRepository) GetChainExecutionResultByTxHash(ctx context.Context, chainID, txHash string) (*ChainExecutionResult, error) {
	query := `
		SELECT result_id, proof_id, cycle_id, chain_platform, chain_id, network_name,
		       tx_hash, block_number, block_hash, block_timestamp,
		       status, gas_used, gas_cost, confirmations, required_confirmations, is_finalized,
		       result_hash, merkle_proof, receipt_proof,
		       state_root, transactions_root, receipts_root,
		       raw_receipt, logs, platform_data,
		       observer_validator_id, workflow_step, anchor_id,
		       submitted_at, confirmed_at, finalized_at, created_at, updated_at
		FROM chain_execution_results
		WHERE chain_id = $1 AND tx_hash = $2
	`

	var result ChainExecutionResult
	err := r.db.QueryRowContext(ctx, query, chainID, txHash).Scan(
		&result.ResultID, &result.ProofID, &result.CycleID, &result.ChainPlatform,
		&result.ChainID, &result.NetworkName, &result.TxHash, &result.BlockNumber,
		&result.BlockHash, &result.BlockTimestamp, &result.Status, &result.GasUsed,
		&result.GasCost, &result.Confirmations, &result.RequiredConfirmations, &result.IsFinalized,
		&result.ResultHash, &result.MerkleProof, &result.ReceiptProof,
		&result.StateRoot, &result.TransactionsRoot, &result.ReceiptsRoot,
		&result.RawReceipt, &result.Logs, &result.PlatformData,
		&result.ObserverValidatorID, &result.WorkflowStep, &result.AnchorID,
		&result.SubmittedAt, &result.ConfirmedAt, &result.FinalizedAt,
		&result.CreatedAt, &result.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get execution result by tx hash: %w", err)
	}

	return &result, nil
}

// UpdateChainExecutionConfirmations updates confirmations for a result
func (r *UnifiedRepository) UpdateChainExecutionConfirmations(ctx context.Context, id uuid.UUID, confirmations int, isFinalized bool) error {
	query := `
		UPDATE chain_execution_results
		SET confirmations = $2, is_finalized = $3,
		    finalized_at = CASE WHEN $3 AND finalized_at IS NULL THEN NOW() ELSE finalized_at END
		WHERE result_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, confirmations, isFinalized)
	if err != nil {
		return fmt.Errorf("update confirmations: %w", err)
	}

	return nil
}

// UpdateChainExecutionStatus updates the status of a result
func (r *UnifiedRepository) UpdateChainExecutionStatus(ctx context.Context, id uuid.UUID, status ExecutionStatus, blockNumber int64, blockHash string) error {
	query := `
		UPDATE chain_execution_results
		SET status = $2, block_number = $3, block_hash = $4,
		    confirmed_at = CASE WHEN $2 = 1 AND confirmed_at IS NULL THEN NOW() ELSE confirmed_at END
		WHERE result_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, id, status, blockNumber, blockHash)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	return nil
}

// =============================================================================
// PROOF ARTIFACT UPDATES
// =============================================================================

// UpdateProofArtifactChainInfo updates chain info on proof artifacts
func (r *UnifiedRepository) UpdateProofArtifactChainInfo(ctx context.Context, proofID uuid.UUID, scheme AttestationScheme, platform ChainPlatform, targetChain string) error {
	query := `
		UPDATE proof_artifacts
		SET attestation_scheme = $2, chain_platform = $3, target_chain = $4
		WHERE proof_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, proofID, scheme, platform, targetChain)
	if err != nil {
		return fmt.Errorf("update proof artifact chain info: %w", err)
	}

	return nil
}

// LinkProofToUnifiedAttestation links a proof to its unified attestation
func (r *UnifiedRepository) LinkProofToUnifiedAttestation(ctx context.Context, proofID, aggregationID uuid.UUID) error {
	query := `
		UPDATE proof_artifacts
		SET unified_attestation_id = $2
		WHERE proof_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, proofID, aggregationID)
	if err != nil {
		return fmt.Errorf("link proof to unified attestation: %w", err)
	}

	return nil
}

// LinkProofToChainExecution links a proof to its chain execution result
func (r *UnifiedRepository) LinkProofToChainExecution(ctx context.Context, proofID, executionID uuid.UUID) error {
	query := `
		UPDATE proof_artifacts
		SET chain_execution_id = $2
		WHERE proof_id = $1
	`

	_, err := r.db.ExecContext(ctx, query, proofID, executionID)
	if err != nil {
		return fmt.Errorf("link proof to chain execution: %w", err)
	}

	return nil
}
