// Copyright 2026 Certen Protocol
//
// Restating consensus records from the commit that committed their height (RB3-F138, migration 00012).

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

// Correction record types for consensus records (migration 00012).
const (
	CorrectionRecordConsensusEntry   = "consensus_entry"
	CorrectionRecordBatchAttestation = "batch_attestation"
)

// StaleConsensusEntry is a consensus entry written by the old mapping: its result states no commit.
type StaleConsensusEntry struct {
	EntryID            uuid.UUID
	BatchID            uuid.UUID
	Height             int64
	State              string
	AttestationCount   int
	RequiredCount      int
	QuorumFraction     float64
	AggregateSignature []byte
	AggregatePubKey    []byte
	CompletedAt        sql.NullTime
	// StartTime is the committed block's time, as the mapping wrote it (the block header's).
	StartTime time.Time
}

// ConsensusCommitFacts is the commit of a height, as read from the node's block store: the evidence for a
// consensus record's correction.
type ConsensusCommitFacts struct {
	Height      int64     `json:"height"`
	BlockTime   time.Time `json:"block_time"`
	Signers     int       `json:"signers"`
	Validators  int       `json:"validators"`
	SignedPower int64     `json:"signed_power"`
	TotalPower  int64     `json:"total_power"`
	ReadAt      string    `json:"read_at"`
}

// ListStaleConsensusEntries returns the consensus entries whose result states no commit, oldest first.
func (r *EvidenceRepair) ListStaleConsensusEntries(ctx context.Context) ([]StaleConsensusEntry, error) {
	rows, err := r.client.QueryContext(ctx, `
		SELECT entry_id, batch_id, COALESCE(block_number, 0), state, attestation_count, required_count,
		       COALESCE(quorum_fraction, 0)::float8, aggregate_signature, aggregate_pubkey, completed_at, start_time
		FROM consensus_entries
		WHERE result_json IS NULL OR NOT (result_json ? 'commit')
		ORDER BY block_number, entry_id`)
	if err != nil {
		return nil, fmt.Errorf("list stale consensus entries: %w", err)
	}
	defer rows.Close()
	var out []StaleConsensusEntry
	for rows.Next() {
		var e StaleConsensusEntry
		var attestations, required sql.NullInt64
		if err := rows.Scan(&e.EntryID, &e.BatchID, &e.Height, &e.State, &attestations, &required,
			&e.QuorumFraction, &e.AggregateSignature, &e.AggregatePubKey, &e.CompletedAt, &e.StartTime); err != nil {
			return nil, fmt.Errorf("scan consensus entry: %w", err)
		}
		e.AttestationCount, e.RequiredCount = int(attestations.Int64), int(required.Int64)
		out = append(out, e)
	}
	return out, rows.Err()
}

// EarlierIncarnationFacts is why an entry's commit cannot be read: the block at its height in the node's
// block store is another block - the entry was committed by an earlier incarnation of the chain.
type EarlierIncarnationFacts struct {
	Height        int64     `json:"height"`
	BlockTime     time.Time `json:"block_time"`
	Basis         string    `json:"basis"`
	BundlesAtThat int       `json:"validator_blocks_at_that_height_now"`
	ReadAt        string    `json:"read_at"`
}

// CorrectConsensusEntryFromEarlierIncarnation restates an entry whose commit is in no block store: it was
// committed (it exists because its block was), at its block's time; its commit counts were never measured
// and are stated as unknown (NULL); no aggregate exists; the unverified signature validity of its batch is
// withdrawn. Conditional on the entry still stating no commit.
func (r *EvidenceRepair) CorrectConsensusEntryFromEarlierIncarnation(ctx context.Context, e StaleConsensusEntry, f EarlierIncarnationFacts, by string) (int64, error) {
	if e.StartTime.IsZero() || f.Height != e.Height {
		return 0, fmt.Errorf("entry %s: no block time, or facts for another height", e.EntryID)
	}
	extra := map[string]any{"commit": nil, "commit_unavailable": f.Basis}
	if len(e.AggregateSignature) > 0 {
		extra["proposer_v6_1_pre_exec_bls_signature"] = map[string]any{"signature": "0x" + hex.EncodeToString(e.AggregateSignature), "verified": false}
	}
	extraJSON, err := json.Marshal(extra)
	if err != nil {
		return 0, err
	}
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE consensus_entries
		SET state = 'completed', completed_at = start_time, attestation_count = NULL, required_count = NULL, quorum_fraction = NULL,
		    aggregate_signature = NULL, aggregate_pubkey = NULL,
		    result_json = COALESCE(result_json, '{}'::jsonb) || $2::jsonb, last_update = NOW()
		WHERE entry_id = $1 AND (result_json IS NULL OR NOT (result_json ? 'commit'))`,
		e.EntryID, string(extraJSON))
	if err != nil {
		return 0, fmt.Errorf("correct consensus entry %s: %w", e.EntryID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, ErrEvidenceChanged
	}
	var prevCompleted any
	if e.CompletedAt.Valid {
		prevCompleted = e.CompletedAt.Time.UTC().Format(time.RFC3339Nano)
	}
	reason := fmt.Sprintf("committed at height %d of an earlier incarnation of the chain (%s): its commit is in no block store, so its "+
		"counts were never measured; the entry stated state %q and %d attestation(s) of %d required, fraction %v - a governance level, "+
		"one self-attestation and a compiled-in count - and a single validator's V6.1 signature as the aggregate (RB3-F138)",
		e.Height, f.Basis, e.State, e.AttestationCount, e.RequiredCount, e.QuorumFraction)
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordConsensusEntry, e.EntryID.String(), reason,
		map[string]any{"state": e.State, "completed_at": prevCompleted, "attestation_count": e.AttestationCount,
			"required_count": e.RequiredCount, "quorum_fraction": e.QuorumFraction,
			"aggregate_signature": hex.EncodeToString(e.AggregateSignature), "aggregate_pubkey": hex.EncodeToString(e.AggregatePubKey)},
		map[string]any{"state": "completed", "completed_at": e.StartTime.UTC().Format(time.RFC3339), "attestation_count": nil,
			"required_count": nil, "quorum_fraction": nil, "aggregate_signature": nil, "aggregate_pubkey": nil},
		f, by); err != nil {
		return 0, err
	}
	withdrawn, err := withdrawConsensusAttestations(ctx, tx.Tx(), e.BatchID, f, by)
	if err != nil {
		return 0, err
	}
	return withdrawn, tx.Commit()
}

// withdrawConsensusAttestations withdraws the signature validity the old mapping claimed for a consensus
// batch's rows: nothing verified them. Only consensus batches - an anchor batch's rows were verified by the
// anchor's quorum proof.
func withdrawConsensusAttestations(ctx context.Context, tx *sql.Tx, batchID uuid.UUID, evidence any, by string) (int64, error) {
	res, err := tx.ExecContext(ctx, `
		UPDATE batch_attestations SET signature_valid = NULL
		WHERE batch_id = $1 AND signature_valid IS TRUE
		  AND NOT EXISTS (SELECT 1 FROM anchor_batches ab WHERE ab.id = $1)`, batchID)
	if err != nil {
		return 0, fmt.Errorf("withdraw attestation validity for batch %s: %w", batchID, err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		if _, err := recordCorrection(ctx, tx, CorrectionRecordBatchAttestation, batchID.String(),
			"the row stated signature_valid = true for a single validator's V6.1 pre-execution signature, stored with the "+
				"validator SET's public key; nothing verified it. Withdrawn to NULL - not verified (RB3-F138)",
			map[string]any{"signature_valid": true, "rows": n},
			map[string]any{"signature_valid": nil, "rows": n}, evidence, by); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// CorrectConsensusEntry restates an entry from its height's commit and withdraws the validity claimed for
// the signature rows of its batch, in one transaction with a correction record for each. The entry changes
// only while it still states no commit (ErrEvidenceChanged otherwise).
func (r *EvidenceRepair) CorrectConsensusEntry(ctx context.Context, e StaleConsensusEntry, c ConsensusCommitFacts, by string) (attestationsWithdrawn int64, err error) {
	if c.TotalPower <= 0 || c.SignedPower*3 <= c.TotalPower*2 || c.Height != e.Height {
		return 0, fmt.Errorf("entry %s: commit facts for height %d do not state a commit of height %d", e.EntryID, c.Height, e.Height)
	}
	required := int(c.TotalPower*2/3 + 1)
	fraction := float64(c.SignedPower) / float64(c.TotalPower)
	extra := map[string]any{
		"commit": map[string]any{"signers": c.Signers, "validators": c.Validators, "signed_power": c.SignedPower, "total_power": c.TotalPower},
	}
	if len(e.AggregateSignature) > 0 {
		extra["proposer_v6_1_pre_exec_bls_signature"] = map[string]any{"signature": "0x" + hex.EncodeToString(e.AggregateSignature), "verified": false}
	}
	extraJSON, err := json.Marshal(extra)
	if err != nil {
		return 0, err
	}

	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE consensus_entries
		SET state = 'completed', completed_at = $2, attestation_count = $3, required_count = $4, quorum_fraction = $5,
		    aggregate_signature = NULL, aggregate_pubkey = NULL,
		    result_json = COALESCE(result_json, '{}'::jsonb) || $6::jsonb, last_update = NOW()
		WHERE entry_id = $1 AND (result_json IS NULL OR NOT (result_json ? 'commit'))`,
		e.EntryID, c.BlockTime.UTC(), c.Signers, required, fraction, string(extraJSON))
	if err != nil {
		return 0, fmt.Errorf("correct consensus entry %s: %w", e.EntryID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, ErrEvidenceChanged
	}
	var prevCompleted any
	if e.CompletedAt.Valid {
		prevCompleted = e.CompletedAt.Time.UTC().Format(time.RFC3339Nano)
	}
	reason := fmt.Sprintf("height %d was committed by %d of %d validators (%d of %d voting power) at %s; the entry stated state %q, "+
		"%d attestation(s) of %d required and fraction %v - a governance level, one self-attestation and a compiled-in count - "+
		"and a single validator's V6.1 signature as the aggregate (RB3-F138)",
		c.Height, c.Signers, c.Validators, c.SignedPower, c.TotalPower, c.BlockTime.UTC().Format(time.RFC3339),
		e.State, e.AttestationCount, e.RequiredCount, e.QuorumFraction)
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordConsensusEntry, e.EntryID.String(), reason,
		map[string]any{"state": e.State, "completed_at": prevCompleted, "attestation_count": e.AttestationCount,
			"required_count": e.RequiredCount, "quorum_fraction": e.QuorumFraction,
			"aggregate_signature": hex.EncodeToString(e.AggregateSignature), "aggregate_pubkey": hex.EncodeToString(e.AggregatePubKey)},
		map[string]any{"state": "completed", "completed_at": c.BlockTime.UTC().Format(time.RFC3339), "attestation_count": c.Signers,
			"required_count": required, "quorum_fraction": fraction, "aggregate_signature": nil, "aggregate_pubkey": nil},
		c, by); err != nil {
		return 0, err
	}

	attestationsWithdrawn, err = withdrawConsensusAttestations(ctx, tx.Tx(), e.BatchID, c, by)
	if err != nil {
		return 0, err
	}
	return attestationsWithdrawn, tx.Commit()
}
