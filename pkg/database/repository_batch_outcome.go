package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// =============================================================================
// Batch outcome records (migration 00020, RB5 D4)
// =============================================================================

// BatchOutcomeEvidenceRecorder: the row was written by the validator that sent recordBatchOutcome, which holds the
// BLS aggregate. BatchOutcomeEvidenceChain: the row was rebuilt from the record transaction on the chain.
const (
	BatchOutcomeEvidenceRecorder = "recorder"
	BatchOutcomeEvidenceChain    = "chain"
)

// ErrBatchOutcomeContradiction: an outcome record written for an anchor differs from the one already stored for it.
var ErrBatchOutcomeContradiction = errors.New("a batch outcome record contradicts the one stored for its anchor")

// BatchOutcomeRecord is one recorded batch outcome with its leaves. Hex fields are 0x-prefixed lower case.
type BatchOutcomeRecord struct {
	ChainID                int64
	BundleID               string
	Registry               string
	OutcomeRoot            string
	MessageHash            string
	CertenValidatorSetRoot string
	AccumulateSetRoot      string
	AccumulateIncarnation  string
	LeafCount              int64
	RecordTx               string
	RecordBlock            int64
	Recorder               string
	Signers                []string
	SignerPowers           []*big.Int
	SignedVotingPower      *big.Int
	TotalVotingPower       *big.Int
	QuorumProof            []byte
	AggregateSignature     string // recorder rows only
	AggregatePublicKey     string // recorder rows only
	EvidenceSource         string
	Leaves                 []BatchOutcomeLeafRow
}

// BatchOutcomeLeafRow is one outcome leaf.
type BatchOutcomeLeafRow struct {
	LeafIndex    int64
	BatchLeaf    string
	OperationID  string
	Status       int
	Tx           string
	BlockNumber  int64
	BlockHash    string
	ReceiptsRoot string
	EffectsHash  string
	LeafHash     string
}

// BatchOutcomeRepository writes and reads batch outcome records.
type BatchOutcomeRepository struct {
	client *Client
}

// NewBatchOutcomeRepository binds the repository to a client.
func NewBatchOutcomeRepository(client *Client) *BatchOutcomeRepository {
	return &BatchOutcomeRepository{client: client}
}

func (rec *BatchOutcomeRecord) validate() error {
	switch {
	case rec == nil:
		return fmt.Errorf("nil batch outcome record")
	case rec.LeafCount <= 0 || int64(len(rec.Leaves)) != rec.LeafCount:
		return fmt.Errorf("batch outcome %s: %d leaves for a leaf count of %d", rec.BundleID, len(rec.Leaves), rec.LeafCount)
	case len(rec.Signers) == 0 || len(rec.Signers) != len(rec.SignerPowers):
		return fmt.Errorf("batch outcome %s: %d signers, %d powers", rec.BundleID, len(rec.Signers), len(rec.SignerPowers))
	case rec.SignedVotingPower == nil || rec.TotalVotingPower == nil:
		return fmt.Errorf("batch outcome %s: no voting powers", rec.BundleID)
	case rec.EvidenceSource != BatchOutcomeEvidenceRecorder && rec.EvidenceSource != BatchOutcomeEvidenceChain:
		return fmt.Errorf("batch outcome %s: evidence source %q", rec.BundleID, rec.EvidenceSource)
	}
	sum := new(big.Int)
	for i, p := range rec.SignerPowers {
		if p == nil || p.Sign() <= 0 {
			return fmt.Errorf("batch outcome %s: signer %d has no power", rec.BundleID, i)
		}
		sum.Add(sum, p)
	}
	if sum.Cmp(rec.SignedVotingPower) != 0 {
		return fmt.Errorf("batch outcome %s: the signers' powers sum to %s, the record states %s", rec.BundleID, sum, rec.SignedVotingPower)
	}
	for i, l := range rec.Leaves {
		if l.LeafIndex != int64(i) {
			return fmt.Errorf("batch outcome %s: leaf %d is stored as index %d", rec.BundleID, i, l.LeafIndex)
		}
	}
	return nil
}

func powersJSON(ps []*big.Int) ([]byte, error) {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return json.Marshal(out)
}

// RecordBatchOutcome stores rec and its leaves in one transaction, written once. A record already stored for the anchor
// must state the same on-chain facts and the same leaves (ErrBatchOutcomeContradiction otherwise); a 'recorder' write
// completes a 'chain' row with the BLS aggregate only the recorder holds.
func (r *BatchOutcomeRepository) RecordBatchOutcome(ctx context.Context, rec *BatchOutcomeRecord) error {
	if err := rec.validate(); err != nil {
		return err
	}
	signers, err := json.Marshal(rec.Signers)
	if err != nil {
		return err
	}
	powers, err := powersJSON(rec.SignerPowers)
	if err != nil {
		return err
	}
	var aggSig, aggKey interface{}
	if rec.EvidenceSource == BatchOutcomeEvidenceRecorder {
		aggSig, aggKey = rec.AggregateSignature, rec.AggregatePublicKey
	}
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("batch outcome %s: %w", rec.BundleID, err)
	}
	defer tx.Rollback()

	var inserted bool
	err = tx.Tx().QueryRowContext(ctx, `
		INSERT INTO batch_outcome_records (chain_id, bundle_id, registry, outcome_root, message_hash, certen_validator_set_root,
			accumulate_set_root, accumulate_incarnation, leaf_count, record_tx, record_block, recorder, signers, signer_powers,
			signed_voting_power, total_voting_power, quorum_proof, aggregate_signature, aggregate_public_key, evidence_source)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (chain_id, bundle_id) DO NOTHING
		RETURNING true`,
		rec.ChainID, rec.BundleID, rec.Registry, rec.OutcomeRoot, rec.MessageHash, rec.CertenValidatorSetRoot,
		rec.AccumulateSetRoot, rec.AccumulateIncarnation, rec.LeafCount, rec.RecordTx, rec.RecordBlock, rec.Recorder,
		signers, powers, rec.SignedVotingPower.String(), rec.TotalVotingPower.String(), rec.QuorumProof, aggSig, aggKey,
		rec.EvidenceSource).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		stored, gerr := r.batchOutcome(ctx, tx.Tx(), rec.ChainID, rec.BundleID)
		if gerr != nil {
			return gerr
		}
		if why := sameBatchOutcome(stored, rec); why != "" {
			return fmt.Errorf("%w: chain %d anchor %s: %s", ErrBatchOutcomeContradiction, rec.ChainID, rec.BundleID, why)
		}
		if stored.EvidenceSource == BatchOutcomeEvidenceChain && rec.EvidenceSource == BatchOutcomeEvidenceRecorder {
			if _, err := tx.Tx().ExecContext(ctx, `
				UPDATE batch_outcome_records SET aggregate_signature = $3, aggregate_public_key = $4, evidence_source = 'recorder'
				WHERE chain_id = $1 AND bundle_id = $2`, rec.ChainID, rec.BundleID, rec.AggregateSignature, rec.AggregatePublicKey); err != nil {
				return fmt.Errorf("batch outcome %s: %w", rec.BundleID, err)
			}
		}
		return tx.Commit()
	}
	if err != nil {
		return fmt.Errorf("batch outcome %s: %w", rec.BundleID, err)
	}
	for _, l := range rec.Leaves {
		if _, err := tx.Tx().ExecContext(ctx, `
			INSERT INTO batch_outcome_leaves (chain_id, bundle_id, leaf_index, batch_leaf, operation_id, status, tx, block_number,
				block_hash, receipts_root, effects_hash, leaf_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			rec.ChainID, rec.BundleID, l.LeafIndex, l.BatchLeaf, l.OperationID, l.Status, l.Tx, l.BlockNumber, l.BlockHash,
			l.ReceiptsRoot, l.EffectsHash, l.LeafHash); err != nil {
			return fmt.Errorf("batch outcome %s leaf %d: %w", rec.BundleID, l.LeafIndex, err)
		}
	}
	return tx.Commit()
}

// sameBatchOutcome names the first difference between a stored record and another write of it, "" when they state the
// same record. The aggregate and the evidence source are not compared: a 'chain' row lacks the aggregate.
func sameBatchOutcome(a, b *BatchOutcomeRecord) string {
	pairs := []struct{ name, x, y string }{
		{"registry", a.Registry, b.Registry}, {"outcome root", a.OutcomeRoot, b.OutcomeRoot},
		{"message hash", a.MessageHash, b.MessageHash}, {"CERTEN set root", a.CertenValidatorSetRoot, b.CertenValidatorSetRoot},
		{"Accumulate set root", a.AccumulateSetRoot, b.AccumulateSetRoot},
		{"incarnation", a.AccumulateIncarnation, b.AccumulateIncarnation}, {"record transaction", a.RecordTx, b.RecordTx},
		{"recorder", a.Recorder, b.Recorder}, {"signers", strings.Join(a.Signers, ","), strings.Join(b.Signers, ",")},
		{"signed power", a.SignedVotingPower.String(), b.SignedVotingPower.String()},
		{"total power", a.TotalVotingPower.String(), b.TotalVotingPower.String()},
	}
	for _, p := range pairs {
		if !strings.EqualFold(p.x, p.y) {
			return fmt.Sprintf("%s %s is stored, %s is written", p.name, p.x, p.y)
		}
	}
	if a.RecordBlock != b.RecordBlock || a.LeafCount != b.LeafCount {
		return fmt.Sprintf("record block %d/%d leaves stored, %d/%d written", a.RecordBlock, a.LeafCount, b.RecordBlock, b.LeafCount)
	}
	if !bytes.Equal(a.QuorumProof, b.QuorumProof) {
		return "the quorum proof differs"
	}
	for i := range a.SignerPowers {
		if a.SignerPowers[i].Cmp(b.SignerPowers[i]) != 0 {
			return fmt.Sprintf("signer %d's power differs", i)
		}
	}
	for i := range a.Leaves {
		if a.Leaves[i] != b.Leaves[i] {
			return fmt.Sprintf("leaf %d differs", i)
		}
	}
	if a.EvidenceSource == BatchOutcomeEvidenceRecorder && b.EvidenceSource == BatchOutcomeEvidenceRecorder &&
		(a.AggregateSignature != b.AggregateSignature || a.AggregatePublicKey != b.AggregatePublicKey) {
		return "the recorder's aggregate differs"
	}
	return ""
}

// BatchOutcome is the stored record of an anchor's outcome; nil when none is stored.
func (r *BatchOutcomeRepository) BatchOutcome(ctx context.Context, chainID int64, bundleID string) (*BatchOutcomeRecord, error) {
	rec, err := r.batchOutcome(ctx, r.client.DB(), chainID, strings.ToLower(bundleID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return rec, err
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

func (r *BatchOutcomeRepository) batchOutcome(ctx context.Context, q queryer, chainID int64, bundleID string) (*BatchOutcomeRecord, error) {
	rec := &BatchOutcomeRecord{ChainID: chainID, BundleID: bundleID}
	var signers, powers []byte
	var signed, total string
	var aggSig, aggKey sql.NullString
	err := q.QueryRowContext(ctx, `
		SELECT registry, outcome_root, message_hash, certen_validator_set_root, accumulate_set_root, accumulate_incarnation,
			leaf_count, record_tx, record_block, recorder, signers, signer_powers, signed_voting_power::text,
			total_voting_power::text, quorum_proof, aggregate_signature, aggregate_public_key, evidence_source
		FROM batch_outcome_records WHERE chain_id = $1 AND bundle_id = $2`, chainID, bundleID).Scan(
		&rec.Registry, &rec.OutcomeRoot, &rec.MessageHash, &rec.CertenValidatorSetRoot, &rec.AccumulateSetRoot,
		&rec.AccumulateIncarnation, &rec.LeafCount, &rec.RecordTx, &rec.RecordBlock, &rec.Recorder, &signers, &powers,
		&signed, &total, &rec.QuorumProof, &aggSig, &aggKey, &rec.EvidenceSource)
	if err != nil {
		return nil, err
	}
	rec.AggregateSignature, rec.AggregatePublicKey = aggSig.String, aggKey.String
	if err := json.Unmarshal(signers, &rec.Signers); err != nil {
		return nil, fmt.Errorf("batch outcome %s signers: %w", bundleID, err)
	}
	var ps []string
	if err := json.Unmarshal(powers, &ps); err != nil {
		return nil, fmt.Errorf("batch outcome %s powers: %w", bundleID, err)
	}
	for _, p := range ps {
		v, ok := new(big.Int).SetString(p, 10)
		if !ok {
			return nil, fmt.Errorf("batch outcome %s: power %q", bundleID, p)
		}
		rec.SignerPowers = append(rec.SignerPowers, v)
	}
	var ok1, ok2 bool
	rec.SignedVotingPower, ok1 = new(big.Int).SetString(signed, 10)
	rec.TotalVotingPower, ok2 = new(big.Int).SetString(total, 10)
	if !ok1 || !ok2 {
		return nil, fmt.Errorf("batch outcome %s: voting powers %q/%q", bundleID, signed, total)
	}
	rows, err := q.QueryContext(ctx, `
		SELECT leaf_index, batch_leaf, operation_id, status, tx, block_number, block_hash, receipts_root, effects_hash, leaf_hash
		FROM batch_outcome_leaves WHERE chain_id = $1 AND bundle_id = $2 ORDER BY leaf_index`, chainID, bundleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var l BatchOutcomeLeafRow
		if err := rows.Scan(&l.LeafIndex, &l.BatchLeaf, &l.OperationID, &l.Status, &l.Tx, &l.BlockNumber, &l.BlockHash,
			&l.ReceiptsRoot, &l.EffectsHash, &l.LeafHash); err != nil {
			return nil, err
		}
		rec.Leaves = append(rec.Leaves, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if int64(len(rec.Leaves)) != rec.LeafCount {
		return nil, fmt.Errorf("batch outcome %s: %d leaves stored for a leaf count of %d", bundleID, len(rec.Leaves), rec.LeafCount)
	}
	return rec, nil
}

// AttestedAnchorsWithoutOutcome lists the V8.2 batch anchors of a chain whose quorum proof is recorded as executed
// (a verify transaction) and whose outcome is not stored, oldest first: a HINT of the outcomes still to record. The
// chain decides; nothing is concluded from this list.
func (r *BatchOutcomeRepository) AttestedAnchorsWithoutOutcome(ctx context.Context, chainID int64, limit int) ([]string, error) {
	rows, err := r.client.DB().QueryContext(ctx, `
		SELECT a.bundle_id FROM anchor_batches a
		WHERE a.chain_id = $1 AND a.anchor_version = 'v8_2' AND a.bundle_id IS NOT NULL AND a.verify_tx IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM batch_outcome_records o WHERE o.chain_id = a.chain_id AND o.bundle_id = lower(a.bundle_id))
		GROUP BY a.bundle_id
		ORDER BY min(a.created_at)
		LIMIT $2`, chainID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, strings.ToLower(b))
	}
	return out, rows.Err()
}
