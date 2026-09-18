// Copyright 2025 Certen Protocol
//
// Level 4 proof records: external chain results with their hash chain, per-validator BLS attestations,
// aggregated attestations, the validator set they were counted against, and the per-proof record of all
// four proof levels.
//
// Each record lives in the shared schema's table for its concept (migration 00004): results in
// external_chain_results, BLS attestations in bls_result_attestations, result aggregates in
// aggregated_bls_attestations (cycle aggregates in aggregated_attestations), snapshots in
// validator_set_snapshots, level tracking in proof_cycle_completions. Writers go through the same inserts
// the orchestrators use, so there is one statement per table.

package database

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
)

// ============================================================================
// LEVEL 4: EXTERNAL CHAIN RESULTS AND THEIR HASH CHAIN
// ============================================================================

const externalChainResultColumns = `
	result_id, proof_id, bundle_id, operation_id, chain_type, chain_id::text, COALESCE(network_name, ''),
	block_number, block_hash, tx_hash, execution_status, tx_gas_used, return_data,
	storage_proof_json, storage_proof_hash,
	sequence_number, previous_result_hash, result_hash, anchor_proof_hash, artifact_json, snapshot_id,
	is_finalized, observer_validator_id, verified, verified_at, observed_at, created_at`

func scanExternalChainResult(scan func(...any) error) (*ExternalChainResultRecord, error) {
	var r ExternalChainResultRecord
	var proofID, snapshotID uuid.NullUUID
	var sequence sql.NullInt64
	var status int16
	if err := scan(
		&r.ResultID, &proofID, &r.BundleID, &r.OperationID, &r.ChainType, &r.ChainID, &r.ChainName,
		&r.BlockNumber, &r.BlockHash, &r.TransactionHash, &status, &r.GasUsed, &r.ReturnData,
		(*[]byte)(&r.StorageProofJSON), &r.StorageProofHash,
		&sequence, &r.PreviousResultHash, &r.ResultHash, &r.AnchorProofHash, (*[]byte)(&r.ArtifactJSON), &snapshotID,
		&r.IsFinalized, &r.ObserverValidatorID, &r.Verified, &r.VerifiedAt, &r.ObservedAt, &r.CreatedAt,
	); err != nil {
		return nil, err
	}
	r.ExecutionStatus = uint8(status)
	if proofID.Valid {
		r.ProofID = &proofID.UUID
	}
	if snapshotID.Valid {
		r.SnapshotID = &snapshotID.UUID
	}
	if sequence.Valid {
		r.SequenceNumber = &sequence.Int64
	}
	return &r, nil
}

// SaveExternalChainResult stores a result already bound to a proof and to its place in the result hash
// chain. It uses the same insert as SaveExternalChainResultV2.
func (r *ProofArtifactRepository) SaveExternalChainResult(ctx context.Context, input *NewExternalChainResult) (*ExternalChainResultRecord, error) {
	if input == nil {
		return nil, errors.New("external chain result input is required")
	}
	chainID, err := strconv.ParseInt(input.ChainID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("external chain result chain id %q is not numeric: %w", input.ChainID, err)
	}
	if input.SequenceNumber < 0 {
		return nil, fmt.Errorf("external chain result sequence number %d is negative", input.SequenceNumber)
	}
	proofID := input.ProofID
	sequence := input.SequenceNumber
	var finalizedAt = &input.ObservedAt
	if !input.IsFinalized {
		finalizedAt = nil
	}
	resultID, err := r.SaveExternalChainResultV2(ctx, &ExternalChainResultInput{
		ProofID:             &proofID,
		BundleID:            input.BundleID,
		OperationID:         input.OperationID,
		ChainType:           input.ChainType,
		ChainID:             chainID,
		NetworkName:         input.ChainName,
		TxHash:              input.TransactionHash,
		TxIndex:             input.TxIndex,
		TxGasUsed:           input.GasUsed,
		TxFromAddress:       input.TxFromAddress,
		TxToAddress:         input.TxToAddress,
		BlockNumber:         input.BlockNumber,
		BlockHash:           input.BlockHash,
		BlockTimestamp:      input.BlockTimestamp,
		StateRoot:           input.StateRoot,
		TransactionsRoot:    input.TransactionsRoot,
		ReceiptsRoot:        input.ReceiptsRoot,
		ExecutionStatus:     int(input.ExecutionStatus),
		ExecutionSuccess:    input.ExecutionStatus == 1,
		IsFinalized:         input.IsFinalized,
		FinalizedAt:         finalizedAt,
		ResultHash:          input.ResultHash,
		ObserverValidatorID: input.ObserverValidatorID,
		ObservedAt:          input.ObservedAt,
		SequenceNumber:      &sequence,
		PreviousResultHash:  input.PreviousResultHash,
		AnchorProofHash:     input.AnchorProofHash,
		ReturnData:          input.ReturnData,
		StorageProofJSON:    input.StorageProofJSON,
		StorageProofHash:    input.StorageProofHash,
		ArtifactJSON:        input.ArtifactJSON,
		SnapshotID:          input.SnapshotID,
	})
	if err != nil {
		return nil, err
	}
	record, err := r.GetExternalChainResultByID(ctx, resultID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("external chain result %s not found after insert", resultID)
	}
	return record, nil
}

// GetExternalChainResultByID retrieves an external chain result by ID
func (r *ProofArtifactRepository) GetExternalChainResultByID(ctx context.Context, resultID uuid.UUID) (*ExternalChainResultRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+externalChainResultColumns+` FROM external_chain_results WHERE result_id = $1`, resultID)
	result, err := scanExternalChainResult(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get external chain result: %w", err)
	}
	return result, nil
}

// GetExternalChainResultsByProof retrieves all execution results for a proof, in hash-chain order.
// Results written before the chain was persisted (no sequence number) come last, by observation time.
func (r *ProofArtifactRepository) GetExternalChainResultsByProof(ctx context.Context, proofID uuid.UUID) ([]ExternalChainResultRecord, error) {
	return r.queryExternalChainResults(ctx, `SELECT `+externalChainResultColumns+`
		FROM external_chain_results
		WHERE proof_id = $1
		ORDER BY sequence_number ASC NULLS LAST, observed_at ASC`, proofID)
}

// GetLatestExternalChainResult retrieves the most recent chained result for a proof, which is the
// predecessor the next result must link to.
func (r *ProofArtifactRepository) GetLatestExternalChainResult(ctx context.Context, proofID uuid.UUID) (*ExternalChainResultRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+externalChainResultColumns+`
		FROM external_chain_results
		WHERE proof_id = $1 AND sequence_number IS NOT NULL
		ORDER BY sequence_number DESC
		LIMIT 1`, proofID)
	result, err := scanExternalChainResult(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest external chain result: %w", err)
	}
	return result, nil
}

// GetUnfinalizedExternalChainResults retrieves external chain results that are not yet finalized
func (r *ProofArtifactRepository) GetUnfinalizedExternalChainResults(ctx context.Context, limit int) ([]ExternalChainResultRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.queryExternalChainResults(ctx, `SELECT `+externalChainResultColumns+`
		FROM external_chain_results
		WHERE is_finalized = FALSE
		ORDER BY created_at ASC
		LIMIT $1`, limit)
}

func (r *ProofArtifactRepository) queryExternalChainResults(ctx context.Context, query string, args ...any) ([]ExternalChainResultRecord, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query external chain results: %w", err)
	}
	defer rows.Close()
	var results []ExternalChainResultRecord
	for rows.Next() {
		result, err := scanExternalChainResult(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan external chain result: %w", err)
		}
		results = append(results, *result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read external chain results: %w", err)
	}
	return results, nil
}

// VerifyExternalChainResultHashChain verifies the hash chain over a proof's results: the chained results
// have consecutive sequence numbers, each links to its predecessor's result hash, and all of them bind
// the same anchor proof. A proof with no chained results is trivially valid; a mix of chained and
// unchained results is not, because the unchained ones sit outside the chain the write-back committed to.
func (r *ProofArtifactRepository) VerifyExternalChainResultHashChain(ctx context.Context, proofID uuid.UUID) (bool, error) {
	results, err := r.GetExternalChainResultsByProof(ctx, proofID)
	if err != nil {
		return false, err
	}
	return verifyResultHashChain(results), nil
}

func verifyResultHashChain(results []ExternalChainResultRecord) bool {
	chained := 0
	for _, result := range results {
		if result.SequenceNumber != nil {
			chained++
		}
	}
	if chained == 0 {
		return true
	}
	if chained != len(results) {
		return false
	}
	for i := 1; i < len(results); i++ {
		prev, curr := results[i-1], results[i]
		if *curr.SequenceNumber != *prev.SequenceNumber+1 {
			return false
		}
		if !bytes.Equal(curr.PreviousResultHash, prev.ResultHash) {
			return false
		}
		if !bytes.Equal(curr.AnchorProofHash, results[0].AnchorProofHash) {
			return false
		}
	}
	return true
}

// UpdateExternalChainResultHashChain records where a result sits in its target chain's hash chain and
// which anchor proof it binds. Used when the chain position is known only after the result was stored.
func (r *ProofArtifactRepository) UpdateExternalChainResultHashChain(ctx context.Context, resultID uuid.UUID, sequence int64, previousResultHash, anchorProofHash []byte) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE external_chain_results
		SET sequence_number = $2, previous_result_hash = $3, anchor_proof_hash = $4, updated_at = NOW()
		WHERE result_id = $1`, resultID, sequence, previousResultHash, anchorProofHash)
	if err != nil {
		return fmt.Errorf("failed to update external chain result hash chain: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("external chain result not found: %s", resultID)
	}
	return nil
}

// MarkExternalChainResultVerified records the outcome of verifying a result's evidence.
func (r *ProofArtifactRepository) MarkExternalChainResultVerified(ctx context.Context, resultID uuid.UUID, verified bool) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE external_chain_results SET verified = $2, verified_at = NOW(), updated_at = NOW()
		WHERE result_id = $1`, resultID, verified)
	if err != nil {
		return fmt.Errorf("failed to mark external chain result verified: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("external chain result not found: %s", resultID)
	}
	return nil
}

// ============================================================================
// LEVEL 4: BLS ATTESTATIONS
// ============================================================================

const blsAttestationColumns = `
	attestation_id, result_id, snapshot_id, result_hash, bundle_id,
	validator_id, validator_address, validator_index, bls_public_key,
	message_hash, signature_domain, bls_signature, weight, subgroup_valid, attested_block_number,
	COALESCE(signature_valid, FALSE), verified_at, attestation_time, created_at`

func scanBLSAttestation(scan func(...any) error) (*BLSAttestationRecord, error) {
	var a BLSAttestationRecord
	var snapshotID uuid.NullUUID
	if err := scan(
		&a.AttestationID, &a.ResultID, &snapshotID, &a.ResultHash, &a.BundleID,
		&a.ValidatorID, &a.ValidatorAddress, &a.ValidatorIndex, &a.PublicKey,
		&a.MessageHash, &a.SignatureDomain, &a.Signature, &a.Weight, &a.SubgroupValid, &a.AttestedBlockNumber,
		&a.SignatureValid, &a.VerifiedAt, &a.AttestedAt, &a.CreatedAt,
	); err != nil {
		return nil, err
	}
	if snapshotID.Valid {
		a.SnapshotID = &snapshotID.UUID
	}
	return &a, nil
}

// SaveBLSAttestation stores one validator's attestation over a result, through the same insert as
// SaveBLSResultAttestation.
func (r *ProofArtifactRepository) SaveBLSAttestation(ctx context.Context, input *NewBLSAttestation) (*BLSAttestationRecord, error) {
	if input == nil {
		return nil, errors.New("BLS attestation input is required")
	}
	saved, err := r.SaveBLSResultAttestation(ctx, &NewBLSResultAttestation{
		ResultID:              input.ResultID,
		ResultHash:            input.ResultHash,
		BundleID:              input.BundleID,
		MessageHash:           input.MessageHash,
		ValidatorID:           input.ValidatorID,
		ValidatorAddress:      input.ValidatorAddress,
		ValidatorIndex:        input.ValidatorIndex,
		BLSSignature:          input.Signature,
		BLSPublicKey:          input.PublicKey,
		SignatureDomain:       input.SignatureDomain,
		AttestedBlockNumber:   input.AttestedBlockNumber,
		AttestedBlockHash:     input.AttestedBlockHash,
		ConfirmationsAtAttest: input.ConfirmationsAtAttest,
		AttestationTime:       input.AttestedAt,
		SnapshotID:            input.SnapshotID,
		Weight:                input.Weight,
		SubgroupValid:         input.SubgroupValid,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save BLS attestation: %w", err)
	}
	record, err := r.GetBLSAttestationByID(ctx, saved.AttestationID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("BLS attestation %s not found after insert", saved.AttestationID)
	}
	return record, nil
}

// GetBLSAttestationByID retrieves a BLS attestation by ID
func (r *ProofArtifactRepository) GetBLSAttestationByID(ctx context.Context, attestationID uuid.UUID) (*BLSAttestationRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+blsAttestationColumns+` FROM bls_result_attestations WHERE attestation_id = $1`, attestationID)
	att, err := scanBLSAttestation(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get BLS attestation: %w", err)
	}
	return att, nil
}

// GetBLSAttestationsByResult retrieves all BLS attestations for a result
func (r *ProofArtifactRepository) GetBLSAttestationsByResult(ctx context.Context, resultID uuid.UUID) ([]BLSAttestationRecord, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+blsAttestationColumns+`
		FROM bls_result_attestations
		WHERE result_id = $1
		ORDER BY attestation_time ASC, validator_index ASC`, resultID)
	if err != nil {
		return nil, fmt.Errorf("failed to query BLS attestations: %w", err)
	}
	defer rows.Close()
	var attestations []BLSAttestationRecord
	for rows.Next() {
		att, err := scanBLSAttestation(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan BLS attestation: %w", err)
		}
		attestations = append(attestations, *att)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read BLS attestations: %w", err)
	}
	return attestations, nil
}

// UpdateBLSAttestationVerified updates the verification status of a BLS attestation
func (r *ProofArtifactRepository) UpdateBLSAttestationVerified(ctx context.Context, attestationID uuid.UUID, valid bool) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE bls_result_attestations
		SET signature_valid = $1, verified_at = NOW()
		WHERE attestation_id = $2`, valid, attestationID)
	if err != nil {
		return fmt.Errorf("failed to update BLS attestation verified: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("BLS attestation not found: %s", attestationID)
	}
	return nil
}

// VerifyBLSAttestationMessageConsistency checks that every attestation for a result signed the same
// message. An aggregate over attestations to different messages does not attest to anything.
func (r *ProofArtifactRepository) VerifyBLSAttestationMessageConsistency(ctx context.Context, resultID uuid.UUID) (bool, error) {
	attestations, err := r.GetBLSAttestationsByResult(ctx, resultID)
	if err != nil {
		return false, err
	}
	for i := 1; i < len(attestations); i++ {
		if !bytes.Equal(attestations[i].MessageHash, attestations[0].MessageHash) {
			return false, nil
		}
	}
	return true, nil
}

// ============================================================================
// LEVEL 4: AGGREGATED ATTESTATIONS
// ============================================================================

// Result-level aggregates (aggregated_bls_attestations) and cycle-level aggregates written by the unified
// orchestrator (aggregated_attestations) share one record shape; threshold weight is derived the same way
// for both: floor(total * numerator / denominator) + 1.
const resultAggregateSelect = `
	SELECT aggregation_id, 'result', result_id, NULL::varchar, snapshot_id, message_hash,
		aggregate_signature, aggregate_public_key, participant_ids, validator_count,
		total_voting_power::bigint, (total_voting_power * threshold_numerator / threshold_denominator)::bigint + 1,
		signed_voting_power::bigint, threshold_met, message_consistency_valid,
		COALESCE(aggregate_verified, FALSE), verified_at, last_attestation_at, created_at
	FROM aggregated_bls_attestations`

const cycleAggregateSelect = `
	SELECT aggregation_id, 'cycle', NULL::uuid, cycle_id, snapshot_id, message_hash,
		aggregated_signature, aggregated_public_key, participant_ids, participant_count,
		total_weight, threshold_weight, achieved_weight, threshold_met, message_consistency_valid,
		COALESCE(aggregation_valid, FALSE), verified_at, aggregated_at, COALESCE(created_at, aggregated_at)
	FROM aggregated_attestations`

func scanAggregatedAttestation(scan func(...any) error) (*AggregatedAttestationRecord, error) {
	var a AggregatedAttestationRecord
	var resultID, snapshotID uuid.NullUUID
	var cycleID sql.NullString
	if err := scan(
		&a.AggregationID, &a.Source, &resultID, &cycleID, &snapshotID, &a.MessageHash,
		&a.AggregatedSignature, &a.AggregatedPublicKey, (*[]byte)(&a.ParticipantIDs), &a.ParticipantCount,
		&a.TotalWeight, &a.ThresholdWeight, &a.AchievedWeight, &a.ThresholdMet, &a.MessageConsistencyValid,
		&a.AggregationValid, &a.VerifiedAt, &a.AggregatedAt, &a.CreatedAt,
	); err != nil {
		return nil, err
	}
	if resultID.Valid {
		a.ResultID = &resultID.UUID
	}
	if cycleID.Valid {
		a.CycleID = &cycleID.String
	}
	if snapshotID.Valid {
		a.SnapshotID = &snapshotID.UUID
	}
	return &a, nil
}

// SaveAggregatedAttestation stores a result-level aggregate through the same insert as
// SaveAggregatedBLSAttestation.
func (r *ProofArtifactRepository) SaveAggregatedAttestation(ctx context.Context, input *NewAggregatedAttestation) (*AggregatedAttestationRecord, error) {
	if input == nil {
		return nil, errors.New("aggregated attestation input is required")
	}
	numerator, denominator := input.ThresholdNumerator, input.ThresholdDenominator
	if numerator <= 0 || denominator <= 0 {
		numerator, denominator = 2, 3
	}
	if input.TotalWeight <= 0 {
		return nil, errors.New("aggregated attestation total weight must be positive")
	}
	percentage := float64(input.AchievedWeight) * 100 / float64(input.TotalWeight)
	saved, err := r.SaveAggregatedBLSAttestation(ctx, &NewAggregatedBLSAttestation{
		ResultID:                input.ResultID,
		ResultHash:              input.ResultHash,
		BundleID:                input.BundleID,
		MessageHash:             input.MessageHash,
		AttestedBlockNumber:     input.AttestedBlockNumber,
		AggregateSignature:      input.AggregatedSignature,
		AggregatePublicKey:      input.AggregatedPublicKey,
		ValidatorBitfield:       input.ValidatorBitfield,
		ValidatorCount:          input.ParticipantCount,
		ValidatorAddresses:      input.ValidatorAddresses,
		ValidatorIndices:        input.ValidatorIndices,
		AttestationIDs:          input.AttestationIDs,
		TotalVotingPower:        strconv.FormatInt(input.TotalWeight, 10),
		SignedVotingPower:       strconv.FormatInt(input.AchievedWeight, 10),
		VotingPowerPercentage:   percentage,
		ThresholdNumerator:      numerator,
		ThresholdDenominator:    denominator,
		ThresholdMet:            input.ThresholdMet,
		FirstAttestationAt:      input.FirstAttestationAt,
		LastAttestationAt:       input.LastAttestationAt,
		AggregationHash:         input.AggregationHash,
		SnapshotID:              input.SnapshotID,
		ParticipantIDs:          input.ParticipantIDs,
		MessageConsistencyValid: input.MessageConsistencyValid,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to save aggregated attestation: %w", err)
	}
	record, err := r.GetAggregatedAttestationByID(ctx, saved.AggregationID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, fmt.Errorf("aggregated attestation %s not found after insert", saved.AggregationID)
	}
	return record, nil
}

// GetAggregatedAttestationByID retrieves an aggregated attestation, result-level or cycle-level.
func (r *ProofArtifactRepository) GetAggregatedAttestationByID(ctx context.Context, aggregationID uuid.UUID) (*AggregatedAttestationRecord, error) {
	row := r.db.QueryRowContext(ctx,
		resultAggregateSelect+` WHERE aggregation_id = $1 UNION ALL `+cycleAggregateSelect+` WHERE aggregation_id = $1`, aggregationID)
	agg, err := scanAggregatedAttestation(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregated attestation: %w", err)
	}
	return agg, nil
}

// GetAggregatedAttestationByResult retrieves the aggregated attestation for a result
func (r *ProofArtifactRepository) GetAggregatedAttestationByResult(ctx context.Context, resultID uuid.UUID) (*AggregatedAttestationRecord, error) {
	row := r.db.QueryRowContext(ctx, resultAggregateSelect+` WHERE result_id = $1`, resultID)
	agg, err := scanAggregatedAttestation(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregated attestation by result: %w", err)
	}
	return agg, nil
}

// GetAggregatedAttestationByCycle retrieves the aggregate the unified orchestrator formed for a cycle.
func (r *ProofArtifactRepository) GetAggregatedAttestationByCycle(ctx context.Context, cycleID string) (*AggregatedAttestationRecord, error) {
	row := r.db.QueryRowContext(ctx, cycleAggregateSelect+` WHERE cycle_id = $1 ORDER BY aggregated_at DESC LIMIT 1`, cycleID)
	agg, err := scanAggregatedAttestation(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregated attestation by cycle: %w", err)
	}
	return agg, nil
}

// UpdateAggregatedAttestationVerified updates the verification status of an aggregate, whichever table
// it lives in.
func (r *ProofArtifactRepository) UpdateAggregatedAttestationVerified(ctx context.Context, aggregationID uuid.UUID, valid bool) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE aggregated_bls_attestations
		SET aggregate_verified = $1, verified_at = NOW(), updated_at = NOW()
		WHERE aggregation_id = $2`, valid, aggregationID)
	if err != nil {
		return fmt.Errorf("failed to update aggregated attestation verified: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		return nil
	}
	result, err = r.db.ExecContext(ctx, `
		UPDATE aggregated_attestations
		SET aggregation_valid = $1, verified_at = NOW(), updated_at = NOW()
		WHERE aggregation_id = $2`, valid, aggregationID)
	if err != nil {
		return fmt.Errorf("failed to update aggregated attestation verified: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("aggregated attestation not found: %s", aggregationID)
	}
	return nil
}

// ============================================================================
// LEVEL 4: VALIDATOR SET SNAPSHOTS
// ============================================================================

const validatorSetSnapshotColumns = `
	snapshot_id, block_number, block_hash, validators_json,
	validator_root, validator_count, total_weight, threshold_weight,
	snapshot_hash, chain_id, chain_name, created_at`

func scanValidatorSetSnapshot(scan func(...any) error) (*ValidatorSetSnapshotRecord, error) {
	var s ValidatorSetSnapshotRecord
	if err := scan(
		&s.SnapshotID, &s.BlockNumber, &s.BlockHash, (*[]byte)(&s.ValidatorsJSON),
		&s.ValidatorRoot, &s.ValidatorCount, &s.TotalWeight, &s.ThresholdWeight,
		&s.SnapshotHash, &s.ChainID, &s.ChainName, &s.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

// SaveValidatorSetSnapshot records a validator set. A set is identified by its snapshot hash, so saving
// the same set again returns the existing row instead of a duplicate.
func (r *ProofArtifactRepository) SaveValidatorSetSnapshot(ctx context.Context, input *NewValidatorSetSnapshot) (*ValidatorSetSnapshotRecord, error) {
	if input == nil {
		return nil, errors.New("validator set snapshot input is required")
	}
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO validator_set_snapshots (
			block_number, block_hash, validators_json,
			validator_root, validator_count, total_weight, threshold_weight,
			snapshot_hash, chain_id, chain_name
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (snapshot_hash) DO UPDATE SET snapshot_hash = EXCLUDED.snapshot_hash
		RETURNING `+validatorSetSnapshotColumns,
		input.BlockNumber, input.BlockHash, []byte(input.ValidatorsJSON),
		input.ValidatorRoot, input.ValidatorCount, input.TotalWeight, input.ThresholdWeight,
		input.SnapshotHash, input.ChainID, input.ChainName,
	)
	snapshot, err := scanValidatorSetSnapshot(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("failed to save validator set snapshot: %w", err)
	}
	return snapshot, nil
}

// GetValidatorSetSnapshotByID retrieves a snapshot by ID
func (r *ProofArtifactRepository) GetValidatorSetSnapshotByID(ctx context.Context, snapshotID uuid.UUID) (*ValidatorSetSnapshotRecord, error) {
	return r.getValidatorSetSnapshot(ctx, `WHERE snapshot_id = $1`, snapshotID)
}

// GetValidatorSetSnapshotByHash retrieves a snapshot by its hash
func (r *ProofArtifactRepository) GetValidatorSetSnapshotByHash(ctx context.Context, snapshotHash []byte) (*ValidatorSetSnapshotRecord, error) {
	return r.getValidatorSetSnapshot(ctx, `WHERE snapshot_hash = $1`, snapshotHash)
}

// GetLatestValidatorSetSnapshot retrieves the most recent snapshot for a chain
func (r *ProofArtifactRepository) GetLatestValidatorSetSnapshot(ctx context.Context, chainID string) (*ValidatorSetSnapshotRecord, error) {
	return r.getValidatorSetSnapshot(ctx, `WHERE chain_id = $1 ORDER BY block_number DESC, created_at DESC LIMIT 1`, chainID)
}

func (r *ProofArtifactRepository) getValidatorSetSnapshot(ctx context.Context, where string, arg any) (*ValidatorSetSnapshotRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+validatorSetSnapshotColumns+` FROM validator_set_snapshots `+where, arg)
	snapshot, err := scanValidatorSetSnapshot(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get validator set snapshot: %w", err)
	}
	return snapshot, nil
}

// ============================================================================
// LEVEL 4: PROOF CYCLE COMPLETIONS
// ============================================================================

const proofCycleCompletionColumns = `
	completion_id, proof_id, cycle_id,
	level1_complete, level1_proof_id, level1_hash,
	level2_complete, level2_proof_id, level2_hash,
	level3_complete, level3_proof_id, level3_hash,
	level4_complete, level4_result_id, level4_hash,
	bindings_valid, cycle_hash, all_levels_complete,
	level1_at, level2_at, level3_at, level4_at, completed_at,
	created_at, updated_at`

func scanProofCycleCompletion(scan func(...any) error) (*ProofCycleCompletionRecord, error) {
	var c ProofCycleCompletionRecord
	var cycleID sql.NullString
	var l1, l2, l3, l4 uuid.NullUUID
	if err := scan(
		&c.CompletionID, &c.ProofID, &cycleID,
		&c.Level1Complete, &l1, &c.Level1Hash,
		&c.Level2Complete, &l2, &c.Level2Hash,
		&c.Level3Complete, &l3, &c.Level3Hash,
		&c.Level4Complete, &l4, &c.Level4Hash,
		&c.BindingsValid, &c.CycleHash, &c.AllLevelsComplete,
		&c.Level1At, &c.Level2At, &c.Level3At, &c.Level4At, &c.CompletedAt,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if cycleID.Valid {
		c.CycleID = &cycleID.String
	}
	for _, pair := range []struct {
		src uuid.NullUUID
		dst **uuid.UUID
	}{{l1, &c.Level1ProofID}, {l2, &c.Level2ProofID}, {l3, &c.Level3ProofID}, {l4, &c.Level4ResultID}} {
		if pair.src.Valid {
			id := pair.src.UUID
			*pair.dst = &id
		}
	}
	return &c, nil
}

// SaveProofCycleCompletion creates the level-tracking record for a proof. A proof has one record, so
// saving again returns the existing one (and fills in a cycle id it lacked).
func (r *ProofArtifactRepository) SaveProofCycleCompletion(ctx context.Context, input *NewProofCycleCompletion) (*ProofCycleCompletionRecord, error) {
	if input == nil {
		return nil, errors.New("proof cycle completion input is required")
	}
	var cycleID any
	if input.CycleID != "" {
		cycleID = input.CycleID
	}
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO proof_cycle_completions (proof_id, cycle_id)
		VALUES ($1, $2)
		ON CONFLICT (proof_id) DO UPDATE SET
			cycle_id = COALESCE(proof_cycle_completions.cycle_id, EXCLUDED.cycle_id),
			updated_at = NOW()
		RETURNING `+proofCycleCompletionColumns, input.ProofID, cycleID)
	completion, err := scanProofCycleCompletion(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("failed to save proof cycle completion: %w", err)
	}
	return completion, nil
}

// GetProofCycleCompletionByID retrieves a proof cycle completion by ID
func (r *ProofArtifactRepository) GetProofCycleCompletionByID(ctx context.Context, completionID uuid.UUID) (*ProofCycleCompletionRecord, error) {
	return r.getProofCycleCompletion(ctx, `WHERE completion_id = $1`, completionID)
}

// GetProofCycleCompletionByProof retrieves the completion record for a proof
func (r *ProofArtifactRepository) GetProofCycleCompletionByProof(ctx context.Context, proofID uuid.UUID) (*ProofCycleCompletionRecord, error) {
	return r.getProofCycleCompletion(ctx, `WHERE proof_id = $1`, proofID)
}

// GetProofCycleCompletionByCycle retrieves the completion record written for a unified proof cycle
func (r *ProofArtifactRepository) GetProofCycleCompletionByCycle(ctx context.Context, cycleID string) (*ProofCycleCompletionRecord, error) {
	return r.getProofCycleCompletion(ctx, `WHERE cycle_id = $1 ORDER BY created_at DESC LIMIT 1`, cycleID)
}

func (r *ProofArtifactRepository) getProofCycleCompletion(ctx context.Context, where string, arg any) (*ProofCycleCompletionRecord, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+proofCycleCompletionColumns+` FROM proof_cycle_completions `+where, arg)
	completion, err := scanProofCycleCompletion(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof cycle completion: %w", err)
	}
	return completion, nil
}

// UpdateProofCycleLevel1 records Level 1 (the chained L1-L3 Accumulate proof) as complete.
func (r *ProofArtifactRepository) UpdateProofCycleLevel1(ctx context.Context, completionID uuid.UUID, proofID uuid.UUID, hash []byte) error {
	return r.updateProofCycleLevel(ctx, 1, "level1_proof_id", completionID, proofID, hash)
}

// UpdateProofCycleLevel2 records Level 2 (governance) as complete.
func (r *ProofArtifactRepository) UpdateProofCycleLevel2(ctx context.Context, completionID uuid.UUID, proofID uuid.UUID, hash []byte) error {
	return r.updateProofCycleLevel(ctx, 2, "level2_proof_id", completionID, proofID, hash)
}

// UpdateProofCycleLevel3 records Level 3 (the anchor) as complete.
func (r *ProofArtifactRepository) UpdateProofCycleLevel3(ctx context.Context, completionID uuid.UUID, proofID uuid.UUID, hash []byte) error {
	return r.updateProofCycleLevel(ctx, 3, "level3_proof_id", completionID, proofID, hash)
}

// UpdateProofCycleLevel4 records Level 4 (the external execution result) as complete.
func (r *ProofArtifactRepository) UpdateProofCycleLevel4(ctx context.Context, completionID uuid.UUID, resultID uuid.UUID, hash []byte) error {
	return r.updateProofCycleLevel(ctx, 4, "level4_result_id", completionID, resultID, hash)
}

func (r *ProofArtifactRepository) updateProofCycleLevel(ctx context.Context, level int, idColumn string, completionID, levelID uuid.UUID, hash []byte) error {
	if len(hash) == 0 {
		return fmt.Errorf("proof cycle level %d needs the hash it committed to", level)
	}
	var id any
	if levelID != uuid.Nil {
		id = levelID
	}
	query := fmt.Sprintf(`
		UPDATE proof_cycle_completions
		SET level%[1]d_complete = TRUE, %[2]s = $1, level%[1]d_hash = $2, level%[1]d_at = COALESCE(level%[1]d_at, NOW()), updated_at = NOW()
		WHERE completion_id = $3`, level, idColumn)
	result, err := r.db.ExecContext(ctx, query, id, hash, completionID)
	if err != nil {
		return fmt.Errorf("failed to update proof cycle level %d: %w", level, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("proof cycle completion not found: %s", completionID)
	}
	return nil
}

// ApplyProofCycleCompletionUpdate applies any subset of level results in one statement. Unset fields
// keep their stored value; a level marked complete gets its timestamp the first time.
func (r *ProofArtifactRepository) ApplyProofCycleCompletionUpdate(ctx context.Context, update *ProofCycleCompletionUpdate) error {
	if update == nil {
		return errors.New("proof cycle completion update is required")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE proof_cycle_completions SET
			level1_complete = COALESCE($2, level1_complete), level1_proof_id = COALESCE($3, level1_proof_id), level1_hash = COALESCE($4, level1_hash),
			level1_at = CASE WHEN $2 AND level1_at IS NULL THEN NOW() ELSE level1_at END,
			level2_complete = COALESCE($5, level2_complete), level2_proof_id = COALESCE($6, level2_proof_id), level2_hash = COALESCE($7, level2_hash),
			level2_at = CASE WHEN $5 AND level2_at IS NULL THEN NOW() ELSE level2_at END,
			level3_complete = COALESCE($8, level3_complete), level3_proof_id = COALESCE($9, level3_proof_id), level3_hash = COALESCE($10, level3_hash),
			level3_at = CASE WHEN $8 AND level3_at IS NULL THEN NOW() ELSE level3_at END,
			level4_complete = COALESCE($11, level4_complete), level4_result_id = COALESCE($12, level4_result_id), level4_hash = COALESCE($13, level4_hash),
			level4_at = CASE WHEN $11 AND level4_at IS NULL THEN NOW() ELSE level4_at END,
			bindings_valid = COALESCE($14, bindings_valid), cycle_hash = COALESCE($15, cycle_hash),
			all_levels_complete = COALESCE($16, all_levels_complete),
			completed_at = CASE WHEN $16 AND completed_at IS NULL THEN NOW() ELSE completed_at END,
			updated_at = NOW()
		WHERE completion_id = $1`,
		update.CompletionID,
		update.Level1Complete, update.Level1ProofID, nilIfEmptyBytes(update.Level1Hash),
		update.Level2Complete, update.Level2ProofID, nilIfEmptyBytes(update.Level2Hash),
		update.Level3Complete, update.Level3ProofID, nilIfEmptyBytes(update.Level3Hash),
		update.Level4Complete, update.Level4ResultID, nilIfEmptyBytes(update.Level4Hash),
		update.BindingsValid, nilIfEmptyBytes(update.CycleHash), update.AllLevelsComplete,
	)
	if err != nil {
		return fmt.Errorf("failed to apply proof cycle completion update: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("proof cycle completion not found: %s", update.CompletionID)
	}
	return nil
}

func nilIfEmptyBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// CompleteProofCycle marks a proof cycle as fully complete with its cross-level binding verdict and the
// cycle hash over all four levels. It refuses a cycle with any level still missing.
func (r *ProofArtifactRepository) CompleteProofCycle(ctx context.Context, completionID uuid.UUID, bindingsValid bool, cycleHash []byte) error {
	if len(cycleHash) == 0 {
		return errors.New("a completed proof cycle needs its cycle hash")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE proof_cycle_completions
		SET bindings_valid = $1, cycle_hash = $2, all_levels_complete = TRUE, completed_at = COALESCE(completed_at, NOW()), updated_at = NOW()
		WHERE completion_id = $3
		AND level1_complete AND level2_complete AND level3_complete AND level4_complete`,
		bindingsValid, cycleHash, completionID)
	if err != nil {
		return fmt.Errorf("failed to complete proof cycle: %w", err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("proof cycle completion not found or not all levels complete: %s", completionID)
	}
	return nil
}

// GetIncompleteProofCycles retrieves proof cycles that have not completed all four levels, oldest first.
func (r *ProofArtifactRepository) GetIncompleteProofCycles(ctx context.Context, limit int) ([]ProofCycleCompletionRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+proofCycleCompletionColumns+`
		FROM proof_cycle_completions
		WHERE all_levels_complete = FALSE
		ORDER BY created_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query incomplete proof cycles: %w", err)
	}
	defer rows.Close()
	var completions []ProofCycleCompletionRecord
	for rows.Next() {
		completion, err := scanProofCycleCompletion(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof cycle completion: %w", err)
		}
		completions = append(completions, *completion)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read incomplete proof cycles: %w", err)
	}
	return completions, nil
}
