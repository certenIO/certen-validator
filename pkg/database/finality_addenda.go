// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// FinalityAddendaRepository stores the staged finality addenda of settled legs (migration 00027). It is INSERT-ONLY: it has
// Append and reads, and no method that changes or removes a row. The table refuses UPDATE, DELETE and TRUNCATE itself
// (trigger, SQLSTATE 23001), so the property does not rest on this file alone.
//
// It implements finality.AddendumStore and finality.LegSource.
type FinalityAddendaRepository struct {
	client *Client
}

func NewFinalityAddendaRepository(client *Client) *FinalityAddendaRepository {
	return &FinalityAddendaRepository{client: client}
}

var (
	_ finality.AddendumStore = (*FinalityAddendaRepository)(nil)
	_ finality.LegSource     = (*FinalityAddendaRepository)(nil)
)

// pgCode returns a PostgreSQL error's SQLSTATE, or "".
func pgCode(err error) pq.ErrorCode {
	var pe *pq.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// Append writes a as the next addendum of its proof. Inside one transaction it reads the proof's last addendum and refuses
// (finality_addendum_chain_broken) an addendum that does not extend it exactly: wrong seq, a prevHash that is not the last
// ownHash, a level that does not rise, another chain. A concurrent writer that appended the same seq first makes this a
// finality_append_conflict, never an overwrite. The table's trigger refuses the same things for any other writer.
func (r *FinalityAddendaRepository) Append(ctx context.Context, a finality.Addendum) error {
	tx, err := r.client.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var seq int64
	var level int16
	var chain int64
	var own []byte
	err = tx.QueryRowContext(ctx, `SELECT seq, level, chain, own_hash FROM proof_finality_addenda
		WHERE proof_id = $1 ORDER BY seq DESC LIMIT 1`, a.ProofID).Scan(&seq, &level, &chain, &own)
	switch {
	case err == sql.ErrNoRows:
		if a.Seq != 1 || a.PrevHash != [32]byte{} {
			return finality.NewState(finality.CodeChainBroken, "check", "first", "seq", a.Seq, "proof_id", a.ProofID)
		}
	case err != nil:
		return err
	default:
		if a.Seq != uint64(seq)+1 {
			if a.Seq <= uint64(seq) {
				return finality.NewState(finality.CodeAppendConflict, "proof_id", a.ProofID, "seq", a.Seq, "stored_through", seq)
			}
			return finality.NewState(finality.CodeChainBroken, "check", "seq", "seq", a.Seq, "want", seq+1)
		}
		if string(a.PrevHash[:]) != string(own) {
			return finality.NewState(finality.CodeChainBroken, "check", "prev_hash", "seq", a.Seq)
		}
		if int16(a.Level) <= level {
			return finality.NewState(finality.CodeChainBroken, "check", "level_not_monotone", "seq", a.Seq, "prev_level", finality.Level(level), "level", a.Level)
		}
		if a.Chain != uint64(chain) {
			return finality.NewState(finality.CodeChainBroken, "check", "chain", "seq", a.Seq, "chain", a.Chain, "prev_chain", chain)
		}
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		a.ProofID, int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:])
	if err != nil {
		switch pgCode(err) {
		case "23505": // unique_violation: another writer took this seq between our read and our insert
			return finality.NewState(finality.CodeAppendConflict, "proof_id", a.ProofID, "seq", a.Seq)
		case "23001": // restrict_violation: the trigger refused it
			return finality.NewState(finality.CodeChainBroken, "check", "database_guard", "seq", a.Seq, "cause", err.Error())
		}
		return err
	}
	return tx.Commit()
}

// Chain returns a proof's addenda in ascending seq (empty when it has none). The original digest is not stored: the caller
// holds it (the stored proof's artifact hash) and passes it to finality.VerifyChain.
func (r *FinalityAddendaRepository) Chain(ctx context.Context, proofID string) ([]finality.Addendum, error) {
	rows, err := r.client.DB().QueryContext(ctx, `SELECT seq, level, chain, kind, evidence, prev_hash, own_hash
		FROM proof_finality_addenda WHERE proof_id = $1 ORDER BY seq`, proofID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []finality.Addendum
	for rows.Next() {
		var seq, chain int64
		var level int16
		var prev, own []byte
		a := finality.Addendum{ProofID: proofID}
		if err := rows.Scan(&seq, &level, &chain, &a.Kind, &a.Evidence, &prev, &own); err != nil {
			return nil, err
		}
		if len(prev) != 32 || len(own) != 32 {
			return nil, fmt.Errorf("addendum %d of %s: stored hashes are %d and %d bytes", seq, proofID, len(prev), len(own))
		}
		a.Seq, a.Level, a.Chain = uint64(seq), finality.Level(level), uint64(chain)
		copy(a.PrevHash[:], prev)
		copy(a.OwnHash[:], own)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SettledLegs lists stored proofs that carry a settlement (their bundle's component 5, the execution proof), ascending by
// proof id after `after`, leaving out proofs whose chain already stands at finalized. The settlement itself is loaded per
// leg by LegSettlement.
func (r *FinalityAddendaRepository) SettledLegs(ctx context.Context, after string, limit int) ([]finality.LegRef, error) {
	if limit <= 0 {
		limit = 200
	}
	query := `
		SELECT pa.proof_id::text, pa.artifact_hash, pa.artifact_json #>> '{proof_components,5_execution_proof,chain_id}'
		FROM proof_artifacts pa
		WHERE pa.artifact_json #> '{proof_components,5_execution_proof,block_header_rlp}' IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM proof_finality_addenda f WHERE f.proof_id = pa.proof_id::text AND f.level = 3)`
	args := []any{}
	if after != "" {
		query += ` AND pa.proof_id > $1::uuid`
		args = append(args, after)
	}
	query += fmt.Sprintf(` ORDER BY pa.proof_id LIMIT $%d`, len(args)+1)
	args = append(args, limit)
	rows, err := r.client.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []finality.LegRef
	for rows.Next() {
		var ref finality.LegRef
		var digest []byte
		var chain sql.NullString
		if err := rows.Scan(&ref.ProofID, &digest, &chain); err != nil {
			return nil, err
		}
		if len(digest) != 32 {
			return nil, fmt.Errorf("proof %s: artifact_hash is %d bytes", ref.ProofID, len(digest))
		}
		copy(ref.Digest[:], digest)
		id, perr := strconv.ParseUint(chain.String, 10, 64)
		if perr != nil {
			// A settlement that does not name its chain cannot be upgraded; the worker reports it by name (chain 0 has no profile).
			id = 0
		}
		ref.Chain = id
		out = append(out, ref)
	}
	return out, rows.Err()
}

// LegSettlement loads a leg's L6 evidence from its stored bundle (component 5): the block header and the transaction and
// receipt proofs, verified here before they are handed on. Evidence that does not verify is a named finality_included_invalid
// state, not a partial settlement.
func (r *FinalityAddendaRepository) LegSettlement(ctx context.Context, ref finality.LegRef) (finality.Settlement, error) {
	var raw []byte
	err := r.client.DB().QueryRowContext(ctx, `SELECT artifact_json #> '{proof_components,5_execution_proof}'
		FROM proof_artifacts WHERE proof_id = $1::uuid`, ref.ProofID).Scan(&raw)
	if err != nil {
		return finality.Settlement{}, err
	}
	var settlement ethproof.Settlement
	if err := json.Unmarshal(raw, &settlement); err != nil {
		return finality.Settlement{}, finality.NewState(finality.CodeIncludedInvalid, "proof_id", ref.ProofID, "cause", err.Error())
	}
	subject, err := finality.SubjectOfSettlement(&settlement)
	if err != nil {
		return finality.Settlement{}, err
	}
	return finality.Settlement{Chain: ref.Chain, Subject: subject, Included: &settlement}, nil
}

// LegRef returns one stored proof's leg: its original digest and the chain its bundle's execution proof settled on. A proof
// whose bundle carries no execution proof (component 5) has no leg: the named finality_included_unavailable state.
func (r *FinalityAddendaRepository) LegRef(ctx context.Context, proofID string) (finality.LegRef, error) {
	ref := finality.LegRef{ProofID: proofID}
	var digest []byte
	var chain, header sql.NullString
	err := r.client.DB().QueryRowContext(ctx, `SELECT artifact_hash, artifact_json #>> '{proof_components,5_execution_proof,chain_id}',
		artifact_json #>> '{proof_components,5_execution_proof,block_header_rlp}' FROM proof_artifacts WHERE proof_id = $1::uuid`, proofID).Scan(&digest, &chain, &header)
	if err != nil {
		return ref, err
	}
	if len(digest) != 32 {
		return ref, fmt.Errorf("proof %s: artifact_hash is %d bytes", proofID, len(digest))
	}
	copy(ref.Digest[:], digest)
	if !header.Valid || header.String == "" {
		return ref, finality.NewState(finality.CodeIncludedUnavailable, "proof_id", proofID, "reason", "the stored bundle carries no execution proof (component 5)")
	}
	if id, perr := strconv.ParseUint(chain.String, 10, 64); perr == nil {
		ref.Chain = id
	}
	return ref, nil
}
