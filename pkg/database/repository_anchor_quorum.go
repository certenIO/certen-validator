// Copyright 2025 Certen Protocol
//
// Canonical anchor rows: one row per (chain_id, bundle_id), written once, from evidence the chain already
// confirmed. See migrations/018_anchor_quorum_evidence.sql for what was wrong before this existed.

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// AnchorQuorumSigner is one validator whose partial the aggregate covers.
type AnchorQuorumSigner struct {
	Address     string   `json:"address"`
	VotingPower *big.Int `json:"voting_power"`
}

// AnchorQuorumMemberRecord is one member of the attested batch, with the branch proving it is in the root.
type AnchorQuorumMemberRecord struct {
	IntentID    string
	AccumTxHash string
	ADIURL      string
	OperationID string
	Leaf        []byte
	LeafIndex   int
	Branch      []MerklePathNode

	// The settled leg. Recorded because the canonical row replaces a shadow row that carried it, and a
	// replacement that drops columns the console reads is a regression dressed as a cleanup.
	FromChain   string
	ToChain     string
	FromAddress string
	ToAddress   string
	Amount      string
	TokenSymbol string
	UserID      string
}

// AnchorQuorumRecord is everything one proven anchor contributes to the database.
type AnchorQuorumRecord struct {
	ChainID          int64
	BundleID         string
	Root             []byte
	BatchOperationID string
	MessageHash      string
	AnchorCreateTx   string
	VerifyTx         string
	VerifyBlock      int64
	// VerifiedAt is the time the quorum was confirmed on-chain, used as consensus_completed_at.
	VerifiedAt time.Time

	AggregateSignature []byte
	AggregatePubKey    []byte
	Signers            []AnchorQuorumSigner
	SignedVotingPower  *big.Int
	TotalVotingPower   *big.Int

	Lane           string // on_demand | on_cadence
	EvidenceSource string // live | chain_backfill
	TargetChain    string

	Members []AnchorQuorumMemberRecord
}

// AnchorQuorumConflict reports a canonical row that already exists with DIFFERENT evidence.
//
// This is the case that must never be resolved by overwriting. Two validators proving the same anchor
// derive the same aggregate over the same message, so a disagreement means one of them is describing an
// anchor the chain did not execute — a fact worth an alert, not a row update.
type AnchorQuorumConflict struct {
	ChainID      int64
	BundleID     string
	StoredRoot   string
	StoredSig    string
	IncomingRoot string
	IncomingSig  string
}

func (c *AnchorQuorumConflict) Error() string {
	return fmt.Sprintf(
		"anchor quorum conflict for chain %d bundle %s: stored root=%s sig=%s, incoming root=%s sig=%s",
		c.ChainID, c.BundleID, c.StoredRoot, c.StoredSig, c.IncomingRoot, c.IncomingSig)
}

// RecordAnchorQuorum writes one proven anchor: the canonical row, its members, and one attestation row per
// signer — in a single transaction.
//
// WRITE-ONCE. Every validator on the fleet proves the same anchors, so this runs seven times for one
// anchor; the first write wins and the rest are no-ops. `written` reports whether THIS call created the
// row. A row that exists with different evidence is returned as *AnchorQuorumConflict and nothing is
// changed: the chain is the source of truth and this table is a projection of it, so the correct response
// to a disagreement is to alert, not to pick a winner.
func (r *BatchRepository) RecordAnchorQuorum(
	ctx context.Context,
	rec *AnchorQuorumRecord,
) (written bool, err error) {
	if rec == nil {
		return false, fmt.Errorf("record anchor quorum: nil record")
	}
	if rec.ChainID == 0 || rec.BundleID == "" {
		return false, fmt.Errorf("record anchor quorum: chain id and bundle id are required")
	}
	if len(rec.Root) == 0 {
		return false, fmt.Errorf("record anchor quorum: bundle %s has no root", rec.BundleID)
	}
	if rec.EvidenceSource != "live" && rec.EvidenceSource != "chain_backfill" {
		return false, fmt.Errorf("record anchor quorum: evidence_source must be live or chain_backfill, got %q",
			rec.EvidenceSource)
	}

	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	// Is it already here? Read inside the transaction so the conflict check and the insert see one state.
	var (
		existingID   uuid.UUID
		existingRoot []byte
		existingSig  []byte
	)
	err = tx.Tx().QueryRowContext(ctx,
		`SELECT id, merkle_root, aggregated_signature FROM anchor_batches
		  WHERE chain_id = $1 AND bundle_id = $2`,
		rec.ChainID, rec.BundleID,
	).Scan(&existingID, &existingRoot, &existingSig)

	switch {
	case err == nil:
		// Same anchor, same evidence: nothing to add. Different evidence: refuse and report.
		if !bytesEqual(existingRoot, rec.Root) || !bytesEqual(existingSig, rec.AggregateSignature) {
			return false, &AnchorQuorumConflict{
				ChainID:      rec.ChainID,
				BundleID:     rec.BundleID,
				StoredRoot:   hexOrEmpty(existingRoot),
				StoredSig:    hexOrEmpty(existingSig),
				IncomingRoot: hexOrEmpty(rec.Root),
				IncomingSig:  hexOrEmpty(rec.AggregateSignature),
			}
		}
		return false, nil
	case err != sql.ErrNoRows:
		return false, fmt.Errorf("record anchor quorum: reading existing row: %w", err)
	}

	signersJSON, err := json.Marshal(normalizeSigners(rec.Signers))
	if err != nil {
		return false, fmt.Errorf("record anchor quorum: encoding signers: %w", err)
	}

	batchID := uuid.New()
	var inserted bool
	err = tx.Tx().QueryRowContext(ctx, `
		INSERT INTO anchor_batches (
			id, batch_type, status, merkle_root, target_chain, validator_id,
			transaction_count, tx_count,
			chain_id, bundle_id, batch_operation_id, anchor_create_tx, verify_tx, verify_block,
			message_hash, signers, signed_voting_power, total_voting_power,
			proof_data_included, attestation_count, aggregated_signature, aggregated_public_key,
			quorum_reached, consensus_completed_at, evidence_source, lane,
			anchor_tx_hash, anchored_at, confirmed_at, closed_at
		) VALUES (
			$1, $2, 'confirmed', $3, $4, NULL,
			$5, $5,
			$6, $7, $8, $9, $10, $11,
			$12, $13::jsonb, $14, $15,
			TRUE, $16, $17, $18,
			TRUE, $19, $20, $21,
			$9, $19, $19, $19
		)
		ON CONFLICT (chain_id, bundle_id) WHERE bundle_id IS NOT NULL DO NOTHING
		RETURNING TRUE`,
		batchID, batchTypeFor(rec.Lane), rec.Root, rec.TargetChain,
		len(rec.Members),
		rec.ChainID, rec.BundleID, nullIfEmpty(rec.BatchOperationID), nullIfEmpty(rec.AnchorCreateTx),
		nullIfEmpty(rec.VerifyTx), nullIfZero(rec.VerifyBlock),
		nullIfEmpty(rec.MessageHash), string(signersJSON),
		numericOrNil(rec.SignedVotingPower), numericOrNil(rec.TotalVotingPower),
		len(rec.Signers), rec.AggregateSignature, rec.AggregatePubKey,
		rec.VerifiedAt.UTC(), rec.EvidenceSource, nullIfEmpty(rec.Lane),
	).Scan(&inserted)

	if err == sql.ErrNoRows {
		// Another validator inserted between the read and the insert. Its row is the same evidence (they
		// prove the same anchor) and it won; nothing further to do.
		return false, tx.Commit()
	}
	if err != nil {
		return false, fmt.Errorf("record anchor quorum: inserting anchor %s: %w", rec.BundleID, err)
	}

	for i := range rec.Members {
		m := &rec.Members[i]
		pathJSON, mErr := json.Marshal(m.Branch)
		if mErr != nil {
			return false, fmt.Errorf("record anchor quorum: encoding branch for member %d: %w", i, mErr)
		}
		if _, mErr = tx.Tx().ExecContext(ctx, `
			INSERT INTO batch_transactions (
				batch_id, accumulate_tx_hash, account_url, tree_index, merkle_path, transaction_hash,
				intent_id, adi_url, from_chain, to_chain, from_address, to_address, amount, token_symbol,
				user_id, created_at
			) VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8,
			          COALESCE($9,''), COALESCE($10,''), COALESCE($11,''), COALESCE($12,''),
			          COALESCE($13,'0'), COALESCE($14,''), $15, NOW())`,
			batchID, m.AccumTxHash, m.ADIURL, m.LeafIndex, string(pathJSON), m.Leaf,
			nullIfEmpty(m.IntentID), nullIfEmpty(m.ADIURL),
			nullIfEmpty(m.FromChain), nullIfEmpty(m.ToChain), nullIfEmpty(m.FromAddress),
			nullIfEmpty(m.ToAddress), nullIfEmpty(m.Amount), nullIfEmpty(m.TokenSymbol),
			nullIfEmpty(m.UserID),
		); mErr != nil {
			return false, fmt.Errorf("record anchor quorum: member %d of anchor %s: %w", i, rec.BundleID, mErr)
		}
	}

	for _, s := range rec.Signers {
		if _, sErr := tx.Tx().ExecContext(ctx, `
			INSERT INTO batch_attestations (
				batch_id, validator_id, evm_address, voting_power, merkle_root,
				bls_signature, bls_public_key, tx_count, block_height, attestation_time, signature_valid
			) VALUES ($1, $2, $2, $3, $4, NULL, $5, $6, $7, $8, TRUE)
			ON CONFLICT (batch_id, validator_id) DO NOTHING`,
			batchID, s.Address, numericOrNil(s.VotingPower), rec.Root,
			rec.AggregatePubKey, len(rec.Members), rec.VerifyBlock, rec.VerifiedAt.UTC(),
		); sErr != nil {
			return false, fmt.Errorf("record anchor quorum: signer %s of anchor %s: %w",
				s.Address, rec.BundleID, sErr)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("record anchor quorum: commit for anchor %s: %w", rec.BundleID, err)
	}
	return true, nil
}

// AnchorQuorumRow is a canonical anchor as stored: the identity the contract uses, and the quorum proven
// over it. Distinct from AnchorBatch, which models the legacy collector's row.
type AnchorQuorumRow struct {
	BatchID           uuid.UUID
	ChainID           int64
	BundleID          string
	Root              []byte
	Lane              string
	EvidenceSource    string
	AnchorCreateTx    string
	VerifyTx          string
	VerifyBlock       int64
	QuorumReached     bool
	AttestationCount  int
	SignedVotingPower string
	TotalVotingPower  string
	MemberCount       int
	VerifiedAt        time.Time
}

// GetAnchorQuorum returns the canonical row for (chain, bundle), or nil when none exists.
func (r *BatchRepository) GetAnchorQuorum(ctx context.Context, chainID int64, bundleID string) (*AnchorQuorumRow, error) {
	const q = `
		SELECT id, chain_id, bundle_id, merkle_root, COALESCE(lane, ''), COALESCE(evidence_source, ''),
		       COALESCE(anchor_create_tx, ''), COALESCE(verify_tx, ''), COALESCE(verify_block, 0),
		       COALESCE(quorum_reached, FALSE), COALESCE(attestation_count, 0),
		       COALESCE(signed_voting_power::text, ''), COALESCE(total_voting_power::text, ''),
		       COALESCE(transaction_count, 0), COALESCE(consensus_completed_at, created_at)
		  FROM anchor_batches
		 WHERE chain_id = $1 AND bundle_id = $2`
	row := &AnchorQuorumRow{}
	err := r.client.QueryRowContext(ctx, q, chainID, bundleID).Scan(
		&row.BatchID, &row.ChainID, &row.BundleID, &row.Root, &row.Lane, &row.EvidenceSource,
		&row.AnchorCreateTx, &row.VerifyTx, &row.VerifyBlock,
		&row.QuorumReached, &row.AttestationCount,
		&row.SignedVotingPower, &row.TotalVotingPower, &row.MemberCount, &row.VerifiedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get anchor quorum %d/%s: %w", chainID, bundleID, err)
	}
	return row, nil
}

// normalizeSigners renders voting power as a string so a 256-bit value survives JSON intact.
func normalizeSigners(in []AnchorQuorumSigner) []map[string]string {
	out := make([]map[string]string, 0, len(in))
	for _, s := range in {
		power := "0"
		if s.VotingPower != nil {
			power = s.VotingPower.String()
		}
		out = append(out, map[string]string{"address": s.Address, "voting_power": power})
	}
	return out
}

func numericOrNil(v *big.Int) interface{} {
	if v == nil {
		return nil
	}
	return v.String()
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZero(v int64) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func hexOrEmpty(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("0x%x", b)
}

// batchTypeFor keeps batch_type honest when the lane is not known.
//
// batch_type is NOT NULL, constrained to on_cadence/on_demand/unknown (migration 021), and defaults to
// 'on_cadence'. A row reconstructed from the chain has no lane — nothing in the calldata or the anchor's
// state records how this fleet scheduled the batch — so omitting the column would let the default assert
// 'on_cadence' for every backfilled row. 'unknown' says what is actually true.
//
// The nullable `lane` column stays NULL in that case rather than repeating the word: NULL there already
// means "not recorded".
func batchTypeFor(lane string) string {
	if lane == "" {
		return "unknown"
	}
	return lane
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
