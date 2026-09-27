// Copyright 2025 Certen Protocol
//
// Corrections to stored anchor evidence. Until 2026-09-18 layer 5 stated the verify transaction's block
// for the anchor-create transaction, and the Certen anchor proofs built from it carried that block. The
// writers are fixed; these operations correct what they stored. Every one is conditional on the value it
// replaces, runs in one transaction with its evidence_corrections record (migration 00005), and changes
// only what a chain reading proves.

package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Correction record types, as evidence_corrections.record_type.
const (
	CorrectionRecordAnchorBatch = "anchor_batch"
	CorrectionRecordLayer5      = "layer5"
	CorrectionRecordCertenProof = "certen_anchor_proof"
)

// ErrEvidenceChanged reports that the row no longer holds the value a correction was computed from: another
// run corrected it first, or it changed underneath. Nothing was written.
var ErrEvidenceChanged = errors.New("evidence changed since it was read; not corrected")

// ErrProofDocumentNotCanonical reports a stored Certen proof whose document does not re-serialise to the
// exact bytes its hash covers, so it cannot be revised without changing parts nobody meant to change.
var ErrProofDocumentNotCanonical = errors.New("stored proof document does not re-serialise to its own bytes")

// EvidenceRepair corrects stored anchor evidence.
type EvidenceRepair struct {
	client *Client
}

// NewEvidenceRepair creates the repository.
func NewEvidenceRepair(client *Client) *EvidenceRepair {
	return &EvidenceRepair{client: client}
}

// CanonicalAnchor is a canonical anchor row. Empty strings and zeros are columns not recorded.
type CanonicalAnchor struct {
	BatchID        uuid.UUID
	ChainID        int64
	TargetChain    string
	BundleID       string
	Root           []byte
	AnchorCreateTx string
	AnchorTxHash   string
	AnchorBlockNum int64
	VerifyTx       string
	VerifyBlock    int64
	// The signers of anchor_create_tx and verify_tx (migration 00009).
	AnchorCreateSender string
	VerifySender       string
	// CompletedAt is consensus_completed_at as stored (zero when NULL).
	CompletedAt time.Time
}

// AnchorChainFacts is what reading an anchor transaction back from its chain established. It is stored
// with every correction as the reason the correction is true.
type AnchorChainFacts struct {
	ChainID     int64  `json:"chain_id"`
	TargetChain string `json:"target_chain"`
	TxHash      string `json:"tx_hash"`
	Succeeded   bool   `json:"succeeded"`
	BlockNumber int64  `json:"block_number"`
	BlockHash   string `json:"block_hash"`
	// BlockTime is the block's timestamp (unix seconds); zero where it was not read.
	BlockTime int64 `json:"block_time,omitempty"`
	Head      int64 `json:"head"`
	Depth     int   `json:"depth"`
	// BundleID and Root are what the transaction's createBatchAnchor calldata carries; the reading is only
	// accepted when they are the canonical row's.
	BundleID string `json:"bundle_id"`
	Root     string `json:"root"`
	// Sender is the transaction's signer, recovered from its signature; Contract the anchor it called.
	Sender   string `json:"sender,omitempty"`
	Contract string `json:"contract,omitempty"`
	ReadAt   string `json:"read_at"`
}

// ListCanonicalAnchors returns every canonical anchor row, including those that do not yet name their
// create transaction: the repair finds it (RB3-F33).
func (r *EvidenceRepair) ListCanonicalAnchors(ctx context.Context) ([]CanonicalAnchor, error) {
	rows, err := r.client.QueryContext(ctx, `
		SELECT id, COALESCE(chain_id, 0), COALESCE(target_chain, ''), bundle_id, merkle_root,
		       COALESCE(anchor_create_tx, ''), COALESCE(anchor_tx_hash, ''), COALESCE(anchor_block_num, 0),
		       COALESCE(verify_tx, ''), COALESCE(verify_block, 0),
		       COALESCE(anchor_create_sender, ''), COALESCE(verify_sender, ''), consensus_completed_at
		FROM anchor_batches
		WHERE bundle_id IS NOT NULL
		ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list canonical anchors: %w", err)
	}
	defer rows.Close()
	var anchors []CanonicalAnchor
	for rows.Next() {
		var a CanonicalAnchor
		var completed sql.NullTime
		if err := rows.Scan(&a.BatchID, &a.ChainID, &a.TargetChain, &a.BundleID, &a.Root,
			&a.AnchorCreateTx, &a.AnchorTxHash, &a.AnchorBlockNum, &a.VerifyTx, &a.VerifyBlock,
			&a.AnchorCreateSender, &a.VerifySender, &completed); err != nil {
			return nil, fmt.Errorf("scan canonical anchor: %w", err)
		}
		if completed.Valid {
			a.CompletedAt = completed.Time
		}
		anchors = append(anchors, a)
	}
	return anchors, rows.Err()
}

func recordCorrection(ctx context.Context, tx *sql.Tx, recordType, recordID, reason string, previous, corrected any, facts AnchorChainFacts, by string) (uuid.UUID, error) {
	prev, err := json.Marshal(previous)
	if err != nil {
		return uuid.Nil, err
	}
	next, err := json.Marshal(corrected)
	if err != nil {
		return uuid.Nil, err
	}
	evidence, err := json.Marshal(facts)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO evidence_corrections (record_type, record_id, reason, previous, corrected, chain_evidence, corrected_by)
		VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb, $7)
		RETURNING correction_id`,
		recordType, recordID, reason, string(prev), string(next), string(evidence), by).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("record correction: %w", err)
	}
	return id, nil
}

// CorrectAnchorBlock records the create transaction's block on its canonical row, where the row has none
// or a different one. anchor_tx_hash is filled with the create transaction when empty, so the block is read
// back with the transaction it belongs to.
func (r *EvidenceRepair) CorrectAnchorBlock(ctx context.Context, a CanonicalAnchor, facts AnchorChainFacts, by string) error {
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	previous := sql.NullInt64{Int64: a.AnchorBlockNum, Valid: a.AnchorBlockNum != 0}
	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE anchor_batches
		SET anchor_block_num = $2,
		    anchor_tx_hash   = COALESCE(NULLIF(anchor_tx_hash, ''), anchor_create_tx),
		    updated_at       = NOW()
		WHERE id = $1
		  AND LOWER(anchor_create_tx) = LOWER($3)
		  AND anchor_block_num IS NOT DISTINCT FROM $4
		  AND LOWER(COALESCE(NULLIF(anchor_tx_hash, ''), anchor_create_tx)) = LOWER(anchor_create_tx)`,
		a.BatchID, facts.BlockNumber, a.AnchorCreateTx, previous)
	if err != nil {
		return fmt.Errorf("correct anchor block for batch %s: %w", a.BatchID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrEvidenceChanged
	}
	var prevValue any
	if previous.Valid {
		prevValue = previous.Int64
	}
	reason := fmt.Sprintf("anchor-create transaction %s is in block %d on %s (read from its receipt)",
		a.AnchorCreateTx, facts.BlockNumber, facts.TargetChain)
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordAnchorBatch, a.BatchID.String(), reason,
		map[string]any{"anchor_block_num": prevValue, "anchor_tx_hash": a.AnchorTxHash},
		map[string]any{"anchor_block_num": facts.BlockNumber, "anchor_tx_hash": a.AnchorCreateTx},
		facts, by); err != nil {
		return err
	}
	return tx.Commit()
}

// CompleteAnchorCreate records the create transaction of a canonical row that has none (RB3-F33), with
// its block, and names it in anchor_tx_hash. anchor_tx_hash is replaced only from exactly the value read
// (a.AnchorTxHash) - empty, the create transaction, or a transaction the caller has established is not
// this anchor's creation (RB3-F134: the settlement's) - and the replaced value is kept in the correction.
// A row that changed since it was read is not touched: ErrEvidenceChanged.
func (r *EvidenceRepair) CompleteAnchorCreate(ctx context.Context, a CanonicalAnchor, facts AnchorChainFacts, by string) error {
	if a.AnchorCreateTx != "" || facts.TxHash == "" {
		return fmt.Errorf("complete anchor create for batch %s: the row already names %q, or no transaction was read", a.BatchID, a.AnchorCreateTx)
	}
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	previousBlock := sql.NullInt64{Int64: a.AnchorBlockNum, Valid: a.AnchorBlockNum != 0}
	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE anchor_batches
		SET anchor_create_tx = $2,
		    anchor_block_num = $3,
		    anchor_tx_hash   = $2,
		    updated_at       = NOW()
		WHERE id = $1
		  AND anchor_create_tx IS NULL
		  AND anchor_block_num IS NOT DISTINCT FROM $4
		  AND COALESCE(anchor_tx_hash, '') = $5`,
		a.BatchID, facts.TxHash, facts.BlockNumber, previousBlock, a.AnchorTxHash)
	if err != nil {
		return fmt.Errorf("complete anchor create for batch %s: %w", a.BatchID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrEvidenceChanged
	}
	var prevBlock, prevTx any
	if previousBlock.Valid {
		prevBlock = previousBlock.Int64
	}
	if a.AnchorTxHash != "" {
		prevTx = a.AnchorTxHash
	}
	reason := fmt.Sprintf("anchor %s on %s was created by transaction %s in block %d: the anchor's BatchAnchorCreated "+
		"log at its recorded creation time, and the transaction's own createBatchAnchor calldata",
		a.BundleID, facts.TargetChain, facts.TxHash, facts.BlockNumber)
	if a.AnchorTxHash != "" && !strings.EqualFold(a.AnchorTxHash, facts.TxHash) {
		reason += fmt.Sprintf("; anchor_tx_hash named %s, which is not this anchor's creation (RB3-F134)", a.AnchorTxHash)
	}
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordAnchorBatch, a.BatchID.String(), reason,
		map[string]any{"anchor_create_tx": nil, "anchor_tx_hash": prevTx, "anchor_block_num": prevBlock},
		map[string]any{"anchor_create_tx": facts.TxHash, "anchor_tx_hash": facts.TxHash, "anchor_block_num": facts.BlockNumber},
		facts, by); err != nil {
		return err
	}
	return tx.Commit()
}

// CorrectVerifyBlock records the verify transaction's block where the row has none or a different one.
func (r *EvidenceRepair) CorrectVerifyBlock(ctx context.Context, a CanonicalAnchor, facts AnchorChainFacts, by string) error {
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	previous := sql.NullInt64{Int64: a.VerifyBlock, Valid: a.VerifyBlock != 0}
	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE anchor_batches SET verify_block = $2, updated_at = NOW()
		WHERE id = $1 AND LOWER(verify_tx) = LOWER($3) AND verify_block IS NOT DISTINCT FROM $4`,
		a.BatchID, facts.BlockNumber, facts.TxHash, previous)
	if err != nil {
		return fmt.Errorf("correct verify block for batch %s: %w", a.BatchID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrEvidenceChanged
	}
	var prevValue any
	if previous.Valid {
		prevValue = previous.Int64
	}
	reason := fmt.Sprintf("verify transaction %s is in block %d on %s (read from its receipt)", facts.TxHash, facts.BlockNumber, facts.TargetChain)
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordAnchorBatch, a.BatchID.String(), reason,
		map[string]any{"verify_block": prevValue}, map[string]any{"verify_block": facts.BlockNumber}, facts, by); err != nil {
		return err
	}
	return tx.Commit()
}

// CorrectCompletedAt sets consensus_completed_at to the verify block's time, where the row states another
// (RB3-F131: the anchor's creation time; RB3-F133: a validator's clock), and the signer attestations that
// were stamped with the same stated time. Conditional on the stored time; recorded as one correction.
func (r *EvidenceRepair) CorrectCompletedAt(ctx context.Context, a CanonicalAnchor, verify AnchorChainFacts, by string) error {
	if verify.BlockTime <= 0 {
		return fmt.Errorf("correct completion time for batch %s: the verify block's time was not read", a.BatchID)
	}
	onChain := time.Unix(verify.BlockTime, 0).UTC()
	previous := sql.NullTime{Time: a.CompletedAt, Valid: !a.CompletedAt.IsZero()}
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE anchor_batches SET consensus_completed_at = $2, updated_at = NOW()
		WHERE id = $1 AND LOWER(verify_tx) = LOWER($3) AND consensus_completed_at IS NOT DISTINCT FROM $4`,
		a.BatchID, onChain, verify.TxHash, previous)
	if err != nil {
		return fmt.Errorf("correct completion time for batch %s: %w", a.BatchID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrEvidenceChanged
	}
	var attestations int64
	if previous.Valid {
		res, err := tx.Tx().ExecContext(ctx, `
			UPDATE batch_attestations SET attestation_time = $2 WHERE batch_id = $1 AND attestation_time = $3`,
			a.BatchID, onChain, previous.Time)
		if err != nil {
			return fmt.Errorf("correct attestation times for batch %s: %w", a.BatchID, err)
		}
		attestations, _ = res.RowsAffected()
	}
	var prevValue any
	if previous.Valid {
		prevValue = previous.Time.UTC().Format(time.RFC3339Nano)
	}
	reason := fmt.Sprintf("the quorum over anchor %s was confirmed on %s in verify block %d, at %s (the block's timestamp); "+
		"the row stated another time. %d signer attestation(s) stamped with the stated time were set to it too",
		a.BundleID, verify.TargetChain, verify.BlockNumber, onChain.Format(time.RFC3339), attestations)
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordAnchorBatch, a.BatchID.String(), reason,
		map[string]any{"consensus_completed_at": prevValue, "batch_attestations.attestation_time": prevValue},
		map[string]any{"consensus_completed_at": onChain.Format(time.RFC3339), "batch_attestations.attestation_time": onChain.Format(time.RFC3339),
			"batch_attestations_updated": attestations},
		verify, by); err != nil {
		return err
	}
	return tx.Commit()
}

// Anchor transactions whose sender RecordAnchorSender records.
const (
	AnchorSenderCreate = "anchor_create"
	AnchorSenderVerify = "verify"
)

// RecordAnchorSender records the signer of the row's create or verify transaction (RB3-F127): where the
// row has none, or - corrected - where it records one the signature contradicts. previous is the stored
// sender ("" for none); a row that no longer holds it, or no longer names the transaction the facts are
// about, is not touched (ErrEvidenceChanged).
func (r *EvidenceRepair) RecordAnchorSender(ctx context.Context, a CanonicalAnchor, which, previous string, facts AnchorChainFacts, by string) error {
	// One complete statement per column, so every statement is visible to the schema prepare gate.
	var senderCol, update string
	switch which {
	case AnchorSenderCreate:
		senderCol, update = "anchor_create_sender", `
		UPDATE anchor_batches SET anchor_create_sender = $2, updated_at = NOW()
		WHERE id = $1 AND anchor_create_sender IS NOT DISTINCT FROM NULLIF($4, '') AND LOWER(anchor_create_tx) = LOWER($3)`
	case AnchorSenderVerify:
		senderCol, update = "verify_sender", `
		UPDATE anchor_batches SET verify_sender = $2, updated_at = NOW()
		WHERE id = $1 AND verify_sender IS NOT DISTINCT FROM NULLIF($4, '') AND LOWER(verify_tx) = LOWER($3)`
	default:
		return fmt.Errorf("record anchor sender: unknown transaction %q", which)
	}
	sender := strings.ToLower(facts.Sender)
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	res, err := tx.Tx().ExecContext(ctx, update, a.BatchID, sender, facts.TxHash, previous)
	if err != nil {
		return fmt.Errorf("record %s sender for batch %s: %w", which, a.BatchID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrEvidenceChanged
	}
	reason := fmt.Sprintf("%s transaction %s on %s is signed by %s (recovered from its signature)", which, facts.TxHash, facts.TargetChain, sender)
	var prevValue any
	if previous != "" {
		prevValue = previous
		reason += fmt.Sprintf(", not %s as this row recorded", previous)
	}
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordAnchorBatch, a.BatchID.String(), reason,
		map[string]any{senderCol: prevValue}, map[string]any{senderCol: sender}, facts, by); err != nil {
		return err
	}
	return tx.Commit()
}

// Layer5Claim is a standing layer-5 row.
type Layer5Claim struct {
	LayerID   uuid.UUID
	ProofID   uuid.UUID
	LayerJSON json.RawMessage
}

// ListLayer5ForAnchorTx returns the standing layer-5 rows that name anchorTx as the anchor transaction.
func (r *EvidenceRepair) ListLayer5ForAnchorTx(ctx context.Context, anchorTx string) ([]Layer5Claim, error) {
	rows, err := r.client.QueryContext(ctx, `
		SELECT layer_id, proof_id, layer_json
		FROM chained_proof_layers
		WHERE layer_number = 5
		  AND superseded_at IS NULL
		  AND LOWER(layer_json->>'anchorTx') = LOWER($1)
		ORDER BY created_at, layer_id`, anchorTx)
	if err != nil {
		return nil, fmt.Errorf("list layer-5 rows for %s: %w", anchorTx, err)
	}
	defer rows.Close()
	var claims []Layer5Claim
	for rows.Next() {
		var c Layer5Claim
		var raw []byte
		if err := rows.Scan(&c.LayerID, &c.ProofID, &raw); err != nil {
			return nil, fmt.Errorf("scan layer-5 row: %w", err)
		}
		c.LayerJSON = raw
		claims = append(claims, c)
	}
	return claims, rows.Err()
}

// ReplaceLayer5 withdraws a standing layer-5 row and adds its corrected replacement: the withdrawn row is
// kept, marked superseded with the reason and linked to the row that replaces it.
func (r *EvidenceRepair) ReplaceLayer5(ctx context.Context, old Layer5Claim, corrected json.RawMessage, reason string, facts AnchorChainFacts, by string) (uuid.UUID, error) {
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	var current []byte
	err = tx.Tx().QueryRowContext(ctx, `
		SELECT layer_json FROM chained_proof_layers
		WHERE layer_id = $1 AND superseded_at IS NULL
		FOR UPDATE`, old.LayerID).Scan(&current)
	if err == sql.ErrNoRows {
		return uuid.Nil, ErrEvidenceChanged
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("lock layer-5 row %s: %w", old.LayerID, err)
	}
	if !jsonEqual(current, old.LayerJSON) {
		return uuid.Nil, ErrEvidenceChanged
	}

	var replacement uuid.UUID
	err = tx.Tx().QueryRowContext(ctx, `
		INSERT INTO chained_proof_layers (proof_id, layer_number, layer_name, layer_json, verified, verified_at, created_at)
		SELECT proof_id, layer_number, layer_name, $2::jsonb, TRUE, NOW(), NOW()
		FROM chained_proof_layers WHERE layer_id = $1
		RETURNING layer_id`, old.LayerID, string(corrected)).Scan(&replacement)
	if err != nil {
		return uuid.Nil, fmt.Errorf("add corrected layer-5 row for %s: %w", old.LayerID, err)
	}
	if _, err := tx.Tx().ExecContext(ctx, `
		UPDATE chained_proof_layers
		SET superseded_at = NOW(), superseded_reason = $2, superseded_by = $3, verified = FALSE
		WHERE layer_id = $1`, old.LayerID, reason, replacement); err != nil {
		return uuid.Nil, fmt.Errorf("withdraw layer-5 row %s: %w", old.LayerID, err)
	}
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordLayer5, old.LayerID.String(), reason,
		map[string]any{"layer_id": old.LayerID, "proof_id": old.ProofID, "layer_json": json.RawMessage(current)},
		map[string]any{"layer_id": replacement, "proof_id": old.ProofID, "layer_json": corrected},
		facts, by); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(); err != nil {
		return uuid.Nil, err
	}
	return replacement, nil
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return string(ja) == string(jb)
}

// CertenAnchorRevision is the anchor reference a Certen proof is revised to, from a chain reading.
type CertenAnchorRevision struct {
	Chain         TargetChain
	BlockNumber   int64
	BlockHash     string
	Confirmations int
	// TxHash, when set, replaces the anchor transaction the proof names (RB3-F134: proofs built from a
	// layer 5 that named the settlement's transaction).
	TxHash string
}

// certenProofState is what a revision replaces, kept in its correction record.
type certenProofState struct {
	FullProofJSON      string          `json:"full_proof_json"`
	AnchorTxHash       string          `json:"anchor_tx_hash"`
	ProofHash          string          `json:"proof_hash"`
	ValidatorSignature string          `json:"validator_signature"`
	AnchorChain        string          `json:"anchor_chain"`
	AnchorBlockNumber  int64           `json:"anchor_block_number"`
	AnchorBlockHash    *string         `json:"anchor_block_hash"`
	AnchorConfirmation int             `json:"anchor_confirmations"`
	IsVerified         bool            `json:"is_verified"`
	Verification       json.RawMessage `json:"verification_details,omitempty"`
}

// ReviseCertenProofAnchor replaces a Certen proof's anchor reference, recomputes its hash over the revised
// document and stores the signature sign returns over that hash. The proof must still carry expectedHash,
// and its stored document must re-serialise to exactly the bytes that hash covers; everything in it except
// the anchor reference is kept byte for byte. The previous document, hash and signature go to the
// correction record. The proof keeps its verification: nothing it was verified on changes.
func (r *EvidenceRepair) ReviseCertenProofAnchor(ctx context.Context, proofID uuid.UUID, expectedHash []byte, rev CertenAnchorRevision, scheme string, sign func(proofHash []byte) []byte, reason string, facts AnchorChainFacts, by string) (*CertenAnchorProof, error) {
	if sign == nil {
		return nil, errors.New("revising a Certen proof needs a signer")
	}
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	var (
		prev     certenProofState
		hash     []byte
		sig      []byte
		hashText sql.NullString
		details  []byte
	)
	err = tx.Tx().QueryRowContext(ctx, `
		SELECT full_proof_json, anchor_tx_hash, proof_hash, COALESCE(validator_signature, ''::bytea), COALESCE(anchor_chain, ''),
		       COALESCE(anchor_block_number, 0), anchor_block_hash, COALESCE(anchor_confirmations, 0),
		       COALESCE(is_verified, FALSE), verification_details
		FROM certen_anchor_proofs WHERE id = $1 FOR UPDATE`, proofID).Scan(
		&prev.FullProofJSON, &prev.AnchorTxHash, &hash, &sig, &prev.AnchorChain, &prev.AnchorBlockNumber, &hashText,
		&prev.AnchorConfirmation, &prev.IsVerified, &details)
	if err == sql.ErrNoRows {
		return nil, ErrProofNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock certen proof %s: %w", proofID, err)
	}
	if string(hash) != string(expectedHash) {
		return nil, ErrEvidenceChanged
	}
	if hashText.Valid {
		prev.AnchorBlockHash = &hashText.String
	}
	prev.ProofHash = hex.EncodeToString(hash)
	prev.ValidatorSignature = hex.EncodeToString(sig)
	prev.Verification = details

	var document certenProofDocument
	if err := json.Unmarshal([]byte(prev.FullProofJSON), &document); err != nil {
		return nil, fmt.Errorf("certen proof %s: stored document: %w", proofID, err)
	}
	if again, err := json.Marshal(document); err != nil || string(again) != prev.FullProofJSON {
		return nil, ErrProofDocumentNotCanonical
	}
	document.AnchorReference.Chain = rev.Chain
	document.AnchorReference.BlockNumber = rev.BlockNumber
	document.AnchorReference.BlockHash = rev.BlockHash
	anchorTx := prev.AnchorTxHash
	if rev.TxHash != "" {
		document.AnchorReference.TxHash = rev.TxHash
		anchorTx = rev.TxHash
	}
	fullJSON, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("serialise revised proof: %w", err)
	}
	anchorRefJSON, err := json.Marshal(document.AnchorReference)
	if err != nil {
		return nil, fmt.Errorf("serialise revised anchor reference: %w", err)
	}
	newHash := sha256.Sum256(fullJSON)
	signature := sign(newHash[:])
	if len(signature) == 0 {
		return nil, errors.New("the signer returned no signature")
	}
	// The quorum, the inclusion path and the root are unchanged, and the new hash covers the new document
	// by construction; what was verified stays verified, and nothing unverified becomes verified.
	verified := prev.IsVerified

	merged := map[string]any{}
	if len(details) > 0 {
		if err := json.Unmarshal(details, &merged); err != nil {
			merged = map[string]any{"previous_verification_details": json.RawMessage(details)}
		}
	}
	merged["signature_scheme"] = scheme
	merged["anchor_revised_from_proof_hash"] = prev.ProofHash
	merged["anchor_revised_by"] = by
	mergedJSON, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}

	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE certen_anchor_proofs
		SET full_proof_json      = $2,
		    proof_hash           = $3,
		    anchor_ref_json      = $4,
		    anchor_chain         = $5,
		    anchor_block_number  = $6,
		    anchor_block_hash    = $7,
		    anchor_confirmations = $8,
		    anchor_tx_hash       = $13,
		    validator_signature  = $9,
		    is_verified          = $10,
		    verified_at          = CASE WHEN $10 THEN COALESCE(verified_at, NOW()) ELSE NULL END,
		    verification_details = $11::jsonb,
		    updated_at           = NOW()
		WHERE id = $1 AND proof_hash = $12`,
		proofID, string(fullJSON), newHash[:], string(anchorRefJSON), string(rev.Chain), rev.BlockNumber,
		sql.NullString{String: rev.BlockHash, Valid: rev.BlockHash != ""}, rev.Confirmations, signature,
		verified, string(mergedJSON), expectedHash, anchorTx)
	if err != nil {
		return nil, fmt.Errorf("revise certen proof %s: %w", proofID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrEvidenceChanged
	}
	blockHash := rev.BlockHash
	next := certenProofState{
		FullProofJSON: string(fullJSON), AnchorTxHash: anchorTx, ProofHash: hex.EncodeToString(newHash[:]),
		ValidatorSignature: hex.EncodeToString(signature), AnchorChain: string(rev.Chain),
		AnchorBlockNumber: rev.BlockNumber, AnchorBlockHash: &blockHash,
		AnchorConfirmation: rev.Confirmations, IsVerified: verified, Verification: mergedJSON,
	}
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordCertenProof, proofID.String(), reason, prev, next, facts, by); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return NewProofRepository(r.client).GetProof(ctx, proofID)
}

// EvidenceCorrection is one recorded correction.
type EvidenceCorrection struct {
	CorrectionID  uuid.UUID       `json:"correction_id"`
	RecordType    string          `json:"record_type"`
	RecordID      string          `json:"record_id"`
	Reason        string          `json:"reason"`
	Previous      json.RawMessage `json:"previous"`
	Corrected     json.RawMessage `json:"corrected"`
	ChainEvidence json.RawMessage `json:"chain_evidence"`
	CorrectedBy   string          `json:"corrected_by"`
	CorrectedAt   string          `json:"corrected_at"`
}

// GetCorrections returns the corrections recorded for one record, oldest first.
func (r *EvidenceRepair) GetCorrections(ctx context.Context, recordType, recordID string) ([]EvidenceCorrection, error) {
	rows, err := r.client.QueryContext(ctx, `
		SELECT correction_id, record_type, record_id, reason, previous, corrected, chain_evidence, corrected_by,
		       to_char(corrected_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
		FROM evidence_corrections
		WHERE record_type = $1 AND record_id = $2
		ORDER BY corrected_at, correction_id`, recordType, strings.ToLower(recordID))
	if err != nil {
		return nil, fmt.Errorf("read corrections for %s %s: %w", recordType, recordID, err)
	}
	defer rows.Close()
	corrections := []EvidenceCorrection{}
	for rows.Next() {
		var c EvidenceCorrection
		var prev, next, evidence []byte
		if err := rows.Scan(&c.CorrectionID, &c.RecordType, &c.RecordID, &c.Reason, &prev, &next, &evidence,
			&c.CorrectedBy, &c.CorrectedAt); err != nil {
			return nil, fmt.Errorf("scan correction: %w", err)
		}
		c.Previous, c.Corrected, c.ChainEvidence = prev, next, evidence
		corrections = append(corrections, c)
	}
	return corrections, rows.Err()
}
