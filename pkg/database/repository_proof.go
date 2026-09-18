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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

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

const certenAnchorProofColumns = `
	id, proof_artifact_id, batch_id, anchor_id, transaction_id, accum_tx_hash, account_url,
	merkle_root, merkle_proof_json,
	COALESCE(anchor_chain, ''), COALESCE(anchor_tx_hash, ''), COALESCE(anchor_block_number, 0),
	anchor_block_hash, anchor_confirmations, anchor_ref_json,
	chained_proof_json, accumulate_block_height, accumulate_bvn,
	governance_proof_json, governance_level, governance_valid,
	full_proof_json, proof_hash,
	is_verified, verified_at, verification_details,
	COALESCE(validator_id, ''), validator_signature, proof_version, created_at, updated_at`

func scanCertenAnchorProof(scan func(...any) error) (*CertenAnchorProof, error) {
	p := &CertenAnchorProof{}
	var merkleInclusion, anchorRef, stateProof, govProof, fullProof sql.NullString
	if err := scan(
		&p.ProofID, &p.ProofArtifactID, &p.BatchID, &p.AnchorID, &p.TransactionID, &p.AccumTxHash, &p.AccountURL,
		&p.MerkleRoot, &merkleInclusion,
		&p.AnchorChain, &p.AnchorTxHash, &p.AnchorBlockNumber,
		&p.AnchorBlockHash, &p.AnchorConfirms, &anchorRef,
		&stateProof, &p.AccumBlockHeight, &p.AccumBVN,
		&govProof, &p.GovLevel, &p.GovValid,
		&fullProof, &p.ProofHash,
		&p.Verified, &p.VerificationTime, (*[]byte)(&p.VerifyDetails),
		&p.ValidatorID, &p.ValidatorSig, &p.ProofVersion, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	for _, pair := range []struct {
		src sql.NullString
		dst *json.RawMessage
	}{{merkleInclusion, &p.MerkleInclusion}, {anchorRef, &p.AnchorRef}, {stateProof, &p.AccumStateProof}, {govProof, &p.GovProof}, {fullProof, &p.FullProof}} {
		if pair.src.Valid {
			*pair.dst = json.RawMessage(pair.src.String)
		}
	}
	return p, nil
}

// certenProofDocument is the canonical four-component proof. Its JSON is full_proof_json and its sha256 is
// proof_hash, so the field order and names here are part of the proof format (CurrentProofVersion).
type certenProofDocument struct {
	Version              string              `json:"version"`
	AccumTxHash          string              `json:"accumulate_tx_hash"`
	AccountURL           string              `json:"account_url"`
	TransactionInclusion certenInclusionPart `json:"transaction_inclusion"`
	AnchorReference      certenAnchorRefPart `json:"anchor_reference"`
	StateProof           json.RawMessage     `json:"state_proof"`
	AuthorityProof       certenAuthorityPart `json:"authority_proof"`
}

type certenInclusionPart struct {
	MerkleRoot string           `json:"merkle_root"`
	LeafHash   string           `json:"leaf_hash,omitempty"`
	LeafIndex  int              `json:"leaf_index"`
	Path       []MerklePathNode `json:"path"`
}

type certenAnchorRefPart struct {
	Chain       TargetChain `json:"chain"`
	TxHash      string      `json:"tx_hash"`
	BlockNumber int64       `json:"block_number"`
	BlockHash   string      `json:"block_hash,omitempty"`
}

type certenAuthorityPart struct {
	Level GovernanceLevel `json:"level"`
	Valid bool            `json:"valid"`
	Proof json.RawMessage `json:"proof"`
}

func jsonOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

// CreateProof creates the Certen anchor proof for one transaction. The four components are assembled into
// full_proof_json and hashed into proof_hash. A proof artifact has at most one Certen proof, so creating it
// again for the same artifact returns the stored proof unchanged.
func (r *ProofRepository) CreateProof(ctx context.Context, input *NewCertenAnchorProof) (*CertenAnchorProof, error) {
	if input == nil {
		return nil, errors.New("certen anchor proof input is required")
	}
	if input.AccumTxHash == "" || input.AccountURL == "" {
		return nil, errors.New("certen anchor proof needs the Accumulate transaction hash and account")
	}
	if len(input.MerkleRoot) == 0 || input.AnchorTxHash == "" {
		return nil, errors.New("certen anchor proof needs its merkle root and anchor transaction")
	}
	govLevel := input.GovLevel
	if govLevel == "" {
		govLevel = GovLevelG0
	}
	path := input.MerkleInclusion
	if path == nil {
		path = []MerklePathNode{}
	}
	inclusion := certenInclusionPart{
		MerkleRoot: hex.EncodeToString(input.MerkleRoot),
		LeafIndex:  input.LeafIndex,
		Path:       path,
	}
	if len(input.LeafHash) > 0 {
		inclusion.LeafHash = hex.EncodeToString(input.LeafHash)
	}
	anchorRef := certenAnchorRefPart{
		Chain:       input.AnchorChain,
		TxHash:      input.AnchorTxHash,
		BlockNumber: input.AnchorBlockNumber,
		BlockHash:   input.AnchorBlockHash,
	}
	document := certenProofDocument{
		Version:              CurrentProofVersion,
		AccumTxHash:          input.AccumTxHash,
		AccountURL:           input.AccountURL,
		TransactionInclusion: inclusion,
		AnchorReference:      anchorRef,
		StateProof:           jsonOrNull(input.AccumStateProof),
		AuthorityProof:       certenAuthorityPart{Level: govLevel, Valid: input.GovValid, Proof: jsonOrNull(input.GovProof)},
	}
	fullJSON, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize certen proof: %w", err)
	}
	inclusionJSON, err := json.Marshal(inclusion)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize merkle inclusion: %w", err)
	}
	anchorRefJSON, err := json.Marshal(anchorRef)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize anchor reference: %w", err)
	}
	proofHash := sha256.Sum256(fullJSON)

	nullUUID := func(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: id != uuid.Nil} }
	nullText := func(raw json.RawMessage) sql.NullString {
		return sql.NullString{String: string(raw), Valid: len(raw) > 0}
	}
	row := r.client.QueryRowContext(ctx, `
		INSERT INTO certen_anchor_proofs (
			proof_artifact_id, batch_id, anchor_id, transaction_id, accum_tx_hash, account_url,
			merkle_root, merkle_proof_json,
			anchor_chain, anchor_tx_hash, anchor_block_number, anchor_block_hash, anchor_ref_json,
			chained_proof_json, accumulate_block_height, accumulate_bvn,
			governance_proof_json, governance_level, governance_valid,
			full_proof_json, proof_hash, validator_id, proof_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
		ON CONFLICT (proof_artifact_id) WHERE proof_artifact_id IS NOT NULL
		DO UPDATE SET updated_at = certen_anchor_proofs.updated_at
		RETURNING `+certenAnchorProofColumns,
		nullUUID(input.ProofArtifactID), nullUUID(input.BatchID), nullUUID(input.AnchorID),
		sql.NullInt64{Int64: input.TransactionID, Valid: input.TransactionID > 0},
		input.AccumTxHash, input.AccountURL,
		input.MerkleRoot, string(inclusionJSON),
		string(input.AnchorChain), input.AnchorTxHash, input.AnchorBlockNumber,
		sql.NullString{String: input.AnchorBlockHash, Valid: input.AnchorBlockHash != ""}, string(anchorRefJSON),
		nullText(input.AccumStateProof), sql.NullInt64{Int64: input.AccumBlockHeight, Valid: input.AccumBlockHeight > 0},
		sql.NullString{String: input.AccumBVN, Valid: input.AccumBVN != ""},
		nullText(input.GovProof), string(govLevel), input.GovValid,
		string(fullJSON), proofHash[:],
		sql.NullString{String: input.ValidatorID, Valid: input.ValidatorID != ""}, CurrentProofVersion,
	)
	proof, err := scanCertenAnchorProof(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof: %w", err)
	}
	return proof, nil
}

// VerifyProofHash reports whether a stored proof's hash still matches its full proof document.
func (p *CertenAnchorProof) VerifyProofHash() bool {
	if len(p.FullProof) == 0 || len(p.ProofHash) != sha256.Size {
		return false
	}
	sum := sha256.Sum256(p.FullProof)
	return string(sum[:]) == string(p.ProofHash)
}

func (r *ProofRepository) getOne(ctx context.Context, where string, args ...any) (*CertenAnchorProof, error) {
	row := r.client.QueryRowContext(ctx, `SELECT `+certenAnchorProofColumns+` FROM certen_anchor_proofs `+where, args...)
	proof, err := scanCertenAnchorProof(row.Scan)
	if err == sql.ErrNoRows {
		return nil, ErrProofNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get proof: %w", err)
	}
	return proof, nil
}

func (r *ProofRepository) getMany(ctx context.Context, where string, args ...any) ([]*CertenAnchorProof, error) {
	rows, err := r.client.QueryContext(ctx, `SELECT `+certenAnchorProofColumns+` FROM certen_anchor_proofs `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query proofs: %w", err)
	}
	defer rows.Close()
	var proofs []*CertenAnchorProof
	for rows.Next() {
		proof, err := scanCertenAnchorProof(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan proof: %w", err)
		}
		proofs = append(proofs, proof)
	}
	return proofs, rows.Err()
}

// GetProof retrieves a proof by ID
func (r *ProofRepository) GetProof(ctx context.Context, proofID uuid.UUID) (*CertenAnchorProof, error) {
	return r.getOne(ctx, `WHERE id = $1`, proofID)
}

// GetProofByArtifactID retrieves the Certen proof built for a proof artifact
func (r *ProofRepository) GetProofByArtifactID(ctx context.Context, artifactID uuid.UUID) (*CertenAnchorProof, error) {
	return r.getOne(ctx, `WHERE proof_artifact_id = $1`, artifactID)
}

// GetProofByAccumTxHash retrieves the most recent proof for an Accumulate transaction hash
func (r *ProofRepository) GetProofByAccumTxHash(ctx context.Context, accumTxHash string) (*CertenAnchorProof, error) {
	return r.getOne(ctx, `WHERE accum_tx_hash = $1 ORDER BY created_at DESC LIMIT 1`, TransactionHashKey(accumTxHash))
}

// GetProofsByBatchID retrieves all proofs in a batch
func (r *ProofRepository) GetProofsByBatchID(ctx context.Context, batchID uuid.UUID) ([]*CertenAnchorProof, error) {
	return r.getMany(ctx, `WHERE batch_id = $1 ORDER BY created_at ASC`, batchID)
}

// GetProofsByAnchorID retrieves all proofs for an anchor
func (r *ProofRepository) GetProofsByAnchorID(ctx context.Context, anchorID uuid.UUID) ([]*CertenAnchorProof, error) {
	return r.getMany(ctx, `WHERE anchor_id = $1 ORDER BY created_at ASC`, anchorID)
}

// GetProofsByAnchorTxHash retrieves all proofs whose anchor is the given transaction
func (r *ProofRepository) GetProofsByAnchorTxHash(ctx context.Context, anchorTxHash string) ([]*CertenAnchorProof, error) {
	return r.getMany(ctx, `WHERE anchor_tx_hash = $1 ORDER BY created_at ASC`, anchorTxHash)
}

// GetProofsByAccountURL retrieves proofs for an account
func (r *ProofRepository) GetProofsByAccountURL(ctx context.Context, accountURL string, limit int) ([]*CertenAnchorProof, error) {
	if limit <= 0 {
		limit = 100
	}
	return r.getMany(ctx, `WHERE account_url = $1 ORDER BY created_at DESC LIMIT $2`, accountURL, limit)
}

func (r *ProofRepository) execOne(ctx context.Context, what string, proofID uuid.UUID, query string, args ...any) error {
	result, err := r.client.ExecContext(ctx, query, append([]any{proofID}, args...)...)
	if err != nil {
		return fmt.Errorf("failed to update %s: %w", what, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrProofNotFound
	}
	return nil
}

// UpdateVerification updates the verification status of a proof
func (r *ProofRepository) UpdateVerification(ctx context.Context, proofID uuid.UUID, verified bool, details json.RawMessage) error {
	return r.execOne(ctx, "verification", proofID, `
		UPDATE certen_anchor_proofs
		SET is_verified = $2, verified_at = NOW(), verification_details = $3, updated_at = NOW()
		WHERE id = $1`, verified, nullableJSON(details))
}

// UpdateAnchorConfirmations updates the anchor confirmations for a proof. The block hash is recorded if it
// was not known when the proof was created; a different one is refused, because the proof names a block.
func (r *ProofRepository) UpdateAnchorConfirmations(ctx context.Context, proofID uuid.UUID, confirmations int, blockHash string) error {
	err := r.execOne(ctx, "anchor confirmations", proofID, `
		UPDATE certen_anchor_proofs
		SET anchor_confirmations = GREATEST(anchor_confirmations, $2),
			anchor_block_hash = COALESCE(anchor_block_hash, $3),
			updated_at = NOW()
		WHERE id = $1 AND (anchor_block_hash IS NULL OR $3::varchar IS NULL OR anchor_block_hash = $3)`,
		confirmations, sql.NullString{String: blockHash, Valid: blockHash != ""})
	if !errors.Is(err, ErrProofNotFound) {
		return err
	}
	if _, getErr := r.GetProof(ctx, proofID); getErr != nil {
		return getErr
	}
	return fmt.Errorf("%w: proof %s names a different anchor block than %s", ErrAnchorBlockMismatch, proofID, blockHash)
}

// UpdateValidatorSignature adds the validator's signature over the proof hash
func (r *ProofRepository) UpdateValidatorSignature(ctx context.Context, proofID uuid.UUID, signature []byte) error {
	if len(signature) == 0 {
		return errors.New("validator signature is empty")
	}
	return r.execOne(ctx, "validator signature", proofID, `
		UPDATE certen_anchor_proofs SET validator_signature = $2, updated_at = NOW() WHERE id = $1`, signature)
}

// UpdateAnchorID links the proof to its anchor record after anchoring completes
func (r *ProofRepository) UpdateAnchorID(ctx context.Context, proofID uuid.UUID, anchorID uuid.UUID) error {
	return r.execOne(ctx, "anchor ID", proofID, `
		UPDATE certen_anchor_proofs SET anchor_id = $2, updated_at = NOW() WHERE id = $1`, anchorID)
}

// UpdateBatchID links the proof to the batch it was anchored in, once that batch is known
func (r *ProofRepository) UpdateBatchID(ctx context.Context, proofID uuid.UUID, batchID uuid.UUID) error {
	return r.execOne(ctx, "batch ID", proofID, `
		UPDATE certen_anchor_proofs SET batch_id = $2, updated_at = NOW() WHERE id = $1`, batchID)
}

// ============================================================================
// PROOF QUERY OPERATIONS
// ============================================================================

// GetUnverifiedProofs returns proofs that haven't been verified yet
func (r *ProofRepository) GetUnverifiedProofs(ctx context.Context, limit int) ([]*CertenAnchorProof, error) {
	return r.getMany(ctx, `WHERE is_verified = false ORDER BY created_at ASC LIMIT $1`, limit)
}

// GetVerifiedProofs returns verified proofs, optionally filtered by governance level
func (r *ProofRepository) GetVerifiedProofs(ctx context.Context, govLevel GovernanceLevel, limit int) ([]*CertenAnchorProof, error) {
	if govLevel != "" {
		return r.getMany(ctx, `WHERE is_verified = true AND governance_level = $1 ORDER BY created_at DESC LIMIT $2`, govLevel, limit)
	}
	return r.getMany(ctx, `WHERE is_verified = true ORDER BY created_at DESC LIMIT $1`, limit)
}

// CountProofs returns the total number of proofs
func (r *ProofRepository) CountProofs(ctx context.Context) (int64, error) {
	var count int64
	if err := r.client.QueryRowContext(ctx, `SELECT COUNT(*) FROM certen_anchor_proofs`).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count proofs: %w", err)
	}
	return count, nil
}

// CountVerifiedProofs returns the number of verified proofs
func (r *ProofRepository) CountVerifiedProofs(ctx context.Context) (int64, error) {
	var count int64
	if err := r.client.QueryRowContext(ctx, `SELECT COUNT(*) FROM certen_anchor_proofs WHERE is_verified = true`).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count verified proofs: %w", err)
	}
	return count, nil
}

// GetRecentProofs returns the most recent proofs
func (r *ProofRepository) GetRecentProofs(ctx context.Context, limit int) ([]*CertenAnchorProof, error) {
	return r.getMany(ctx, `ORDER BY created_at DESC LIMIT $1`, limit)
}
