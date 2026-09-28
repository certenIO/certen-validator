// Copyright 2025 Certen Protocol
//
// The anchor batch record as the validators write it (RecordAnchorQuorum, repository_anchor_quorum.go): the anchored root, the chain and its create and verify transactions, and the
// quorum evidence over it.

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

// AnchorBatchRecord is one anchor_batches row. A column the validators have not written is null, never a
// default: validator_id, for one, is NULL on every row the quorum path writes (a batch is the quorum's, not one
// validator's), and the chain's transactions are unknown until the validator that sent them records them.
type AnchorBatchRecord struct {
	BatchID          uuid.UUID `json:"batch_id"`
	BatchType        string    `json:"batch_type"`
	Status           string    `json:"status"`
	Lane             *string   `json:"lane"`
	MerkleRoot       *string   `json:"merkle_root"`
	TransactionCount int       `json:"transaction_count"`
	TargetChain      string    `json:"target_chain"`
	ChainID          *int64    `json:"chain_id"`
	BundleID         *string   `json:"bundle_id"`
	BatchOperationID *string   `json:"batch_operation_id"`
	ValidatorID      *string   `json:"validator_id"`

	AnchorCreateTx     *string `json:"anchor_create_tx"`
	AnchorTxHash       *string `json:"anchor_tx_hash"`
	AnchorBlockNumber  *int64  `json:"anchor_block_number"`
	AnchorCreateSender *string `json:"anchor_create_sender"`
	VerifyTx           *string `json:"verify_tx"`
	VerifyBlock        *int64  `json:"verify_block"`
	VerifySender       *string `json:"verify_sender"`
	GasUsed            *int64  `json:"gas_used"`

	MessageHash          *string         `json:"message_hash"`
	QuorumReached        bool            `json:"quorum_reached"`
	AttestationCount     int             `json:"attestation_count"`
	SignedVotingPower    *string         `json:"signed_voting_power"`
	TotalVotingPower     *string         `json:"total_voting_power"`
	Signers              json.RawMessage `json:"signers"`
	AggregatedSignature  *string         `json:"aggregated_signature"`
	AggregatedPublicKey  *string         `json:"aggregated_public_key"`
	EvidenceSource       *string         `json:"evidence_source"`
	ConsensusCompletedAt *time.Time      `json:"consensus_completed_at"`

	AccumulateBlockHeight *int64  `json:"accumulate_block_height"`
	AccumulateBlockHash   *string `json:"accumulate_block_hash"`
	BPTRoot               *string `json:"bpt_root"`
	GovernanceRoot        *string `json:"governance_root"`
	ErrorMessage          *string `json:"error_message"`

	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	StartedAt   *time.Time `json:"batch_start_time"`
	EndedAt     *time.Time `json:"batch_end_time"`
	ClosedAt    *time.Time `json:"closed_at"`
	AnchoredAt  *time.Time `json:"anchored_at"`
	ConfirmedAt *time.Time `json:"confirmed_at"`
}

// anchorBatchRecordColumns is the column list every batch reader selects, in scanAnchorBatchRecord's order.
const anchorBatchRecordColumns = `id, batch_type, status, lane, merkle_root, transaction_count, target_chain, chain_id,
			bundle_id, batch_operation_id, validator_id,
			anchor_create_tx, anchor_tx_hash, anchor_block_num, anchor_create_sender, verify_tx, verify_block,
			verify_sender, gas_used,
			message_hash, COALESCE(quorum_reached, FALSE), COALESCE(attestation_count, 0),
			signed_voting_power::text, total_voting_power::text, signers, aggregated_signature,
			aggregated_public_key, evidence_source, consensus_completed_at,
			accumulate_block_height, accumulate_block_hash, bpt_root, governance_root, error_message,
			created_at, updated_at, batch_start_time, batch_end_time, closed_at, anchored_at, confirmed_at`

func nullStringPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	return &v.String
}

func nullInt64Ptr(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	return &v.Int64
}

func nullTimePtr(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	return &v.Time
}

func hexPtr(b []byte) *string {
	if b == nil {
		return nil
	}
	s := hex.EncodeToString(b)
	return &s
}

// scanAnchorBatchRecord scans one row selected with anchorBatchRecordColumns. A column the validators have not
// written stays null. The scan's own error (sql.ErrNoRows included) is returned as is.
func scanAnchorBatchRecord(scan func(...any) error) (*AnchorBatchRecord, error) {
	var (
		rec                                                                    AnchorBatchRecord
		lane, bundleID, opID, validatorID, createTx, anchorTx, createSender    sql.NullString
		verifyTx, verifySender, messageHash, signedPower, totalPower, evidence sql.NullString
		accumHash, errorMessage                                                sql.NullString
		chainID, anchorBlock, verifyBlock, gasUsed, accumHeight                sql.NullInt64
		merkleRoot, aggSig, aggPub, bptRoot, govRoot, signers                  []byte
		consensusAt, startedAt, endedAt, closedAt, anchoredAt, confirmedAt     sql.NullTime
	)
	if err := scan(
		&rec.BatchID, &rec.BatchType, &rec.Status, &lane, &merkleRoot, &rec.TransactionCount, &rec.TargetChain,
		&chainID, &bundleID, &opID, &validatorID,
		&createTx, &anchorTx, &anchorBlock, &createSender, &verifyTx, &verifyBlock, &verifySender, &gasUsed,
		&messageHash, &rec.QuorumReached, &rec.AttestationCount,
		&signedPower, &totalPower, &signers, &aggSig, &aggPub, &evidence, &consensusAt,
		&accumHeight, &accumHash, &bptRoot, &govRoot, &errorMessage,
		&rec.CreatedAt, &rec.UpdatedAt, &startedAt, &endedAt, &closedAt, &anchoredAt, &confirmedAt,
	); err != nil {
		return nil, err
	}
	rec.Lane, rec.BundleID, rec.BatchOperationID, rec.ValidatorID = nullStringPtr(lane), nullStringPtr(bundleID), nullStringPtr(opID), nullStringPtr(validatorID)
	rec.AnchorCreateTx, rec.AnchorTxHash, rec.AnchorCreateSender = nullStringPtr(createTx), nullStringPtr(anchorTx), nullStringPtr(createSender)
	rec.VerifyTx, rec.VerifySender, rec.MessageHash = nullStringPtr(verifyTx), nullStringPtr(verifySender), nullStringPtr(messageHash)
	rec.SignedVotingPower, rec.TotalVotingPower, rec.EvidenceSource = nullStringPtr(signedPower), nullStringPtr(totalPower), nullStringPtr(evidence)
	rec.AccumulateBlockHash, rec.ErrorMessage = nullStringPtr(accumHash), nullStringPtr(errorMessage)
	rec.ChainID, rec.AnchorBlockNumber, rec.VerifyBlock = nullInt64Ptr(chainID), nullInt64Ptr(anchorBlock), nullInt64Ptr(verifyBlock)
	rec.GasUsed, rec.AccumulateBlockHeight = nullInt64Ptr(gasUsed), nullInt64Ptr(accumHeight)
	rec.MerkleRoot, rec.AggregatedSignature, rec.AggregatedPublicKey = hexPtr(merkleRoot), hexPtr(aggSig), hexPtr(aggPub)
	rec.BPTRoot, rec.GovernanceRoot = hexPtr(bptRoot), hexPtr(govRoot)
	if signers != nil {
		rec.Signers = json.RawMessage(signers)
	} else {
		rec.Signers = json.RawMessage("null")
	}
	rec.ConsensusCompletedAt = nullTimePtr(consensusAt)
	rec.StartedAt, rec.EndedAt, rec.ClosedAt = nullTimePtr(startedAt), nullTimePtr(endedAt), nullTimePtr(closedAt)
	rec.AnchoredAt, rec.ConfirmedAt = nullTimePtr(anchoredAt), nullTimePtr(confirmedAt)
	return &rec, nil
}

// oneAnchorBatch reads the single row a query selects; ErrBatchNotFound if it selects none.
func (r *BatchRepository) oneAnchorBatch(ctx context.Context, what, query string, args ...any) (*AnchorBatchRecord, error) {
	rec, err := scanAnchorBatchRecord(r.client.QueryRowContext(ctx, query, args...).Scan)
	if err == sql.ErrNoRows {
		return nil, ErrBatchNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", what, err)
	}
	return rec, nil
}

// GetBatch reads one anchor batch as the validators wrote it; ErrBatchNotFound if there is none. It read 13 of
// the row's columns into a type whose validator_id could not hold the NULL the quorum path writes, so it failed on
// every batch the validators record.
func (r *BatchRepository) GetBatch(ctx context.Context, batchID uuid.UUID) (*AnchorBatchRecord, error) {
	return r.oneAnchorBatch(ctx, "anchor batch "+batchID.String(), `
		SELECT `+anchorBatchRecordColumns+`
		FROM anchor_batches
		WHERE id = $1`, batchID)
}
