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

// appendInsertError names the database refusal of the INSERT of addendum seq of proof id: a unique violation is the append
// race (finality_append_conflict); a restrict violation is the table trigger refusing a row the repository did not refuse itself
// (a concurrent writer changed the chain between the read and the insert), the registered go_operational state
// finality_guard_refused carrying the database message in its cause - it is not one of the closed finality_chain_broken checks.
// Any other error is returned unchanged.
func appendInsertError(id string, seq uint64, err error) error {
	switch pgCode(err) {
	case "23505": // unique_violation: another writer took this seq (or this level) between our read and our insert
		return finality.NewState(finality.CodeAppendConflict, "proof_id", id, "seq", seq)
	case "23001": // restrict_violation: the trigger refused it
		return finality.NewState(finality.CodeGuardRefused, "proof_id", id, "seq", seq, "cause", err.Error())
	}
	return err
}

// Append writes a as the next addendum of its proof. Inside one transaction it reads the proof's stored addenda and refuses
// (finality_chain_broken) an addendum that does not extend them exactly: wrong seq, a prevHash that is not the last ownHash,
// a level that is not stored (included is derived and never stored) or a chain other than the proof's, and refuses a second
// addendum at a level the proof already holds (level_already_present). A concurrent writer that appended the same seq first
// makes this a finality_append_conflict, never an overwrite. The table's trigger refuses the same things for any other writer.
//
// This minimal reconcile does NOT yet lock the proof's last row nor run the S7 verifier inside the transaction (V2_SPEC_S7
// 2.4): that behavioural step belongs to the next package, RB11-B2B.
func (r *FinalityAddendaRepository) Append(ctx context.Context, a finality.Addendum) error {
	id := finality.ProofIDString(a.ProofID)
	if !a.Level.Stored() {
		return finality.ChainBroken(a.Seq, finality.CheckKind, "chain", a.Chain, "level", a.Level, "kind", a.Kind)
	}
	tx, err := r.client.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var seq int64
	var chain int64
	var own []byte
	err = tx.QueryRowContext(ctx, `SELECT seq, chain, own_hash FROM proof_finality_addenda
		WHERE proof_id = $1 ORDER BY seq DESC LIMIT 1`, id).Scan(&seq, &chain, &own)
	switch {
	case err == sql.ErrNoRows:
		if a.Seq != 1 {
			return finality.ChainBroken(a.Seq, finality.CheckSeqGap, "want", uint64(1))
		}
		if a.PrevHash != [32]byte{} {
			return finality.ChainBroken(a.Seq, finality.CheckPrevHash)
		}
	case err != nil:
		return err
	default:
		if a.Seq != uint64(seq)+1 {
			if a.Seq <= uint64(seq) {
				return finality.NewState(finality.CodeAppendConflict, "proof_id", id, "seq", a.Seq, "stored_through", seq)
			}
			return finality.ChainBroken(a.Seq, finality.CheckSeqGap, "want", uint64(seq)+1)
		}
		if string(a.PrevHash[:]) != string(own) {
			return finality.ChainBroken(a.Seq, finality.CheckPrevHash)
		}
		if a.Chain != uint64(chain) {
			return finality.ChainBroken(a.Seq, finality.CheckKind, "chain", a.Chain, "stored_chain", uint64(chain))
		}
		var held int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM proof_finality_addenda WHERE proof_id = $1 AND level = $2`, id, int16(a.Level)).Scan(&held); err != nil {
			return err
		}
		if held > 0 {
			return finality.NewState(finality.CodeLevelAlreadyPresent, "chain", a.Chain, "level", a.Level)
		}
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:])
	if err != nil {
		return appendInsertError(id, a.Seq, err)
	}
	return tx.Commit()
}

// Chain returns a proof's addenda in ascending seq (empty when it has none). D0 is not stored: it is the leg binding of the
// proof's Settlement block, recomputed by the caller and passed to finality.VerifyChain.
func (r *FinalityAddendaRepository) Chain(ctx context.Context, proofID string) ([]finality.Addendum, error) {
	pid, err := finality.ParseProofID(proofID)
	if err != nil {
		return nil, err
	}
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
		a := finality.Addendum{ProofID: pid}
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
		SELECT pa.proof_id::text, pa.artifact_json #>> '{proof_components,5_execution_proof,chain_id}'
		FROM proof_artifacts pa
		WHERE pa.artifact_json #> '{proof_components,5_execution_proof,block_header_rlp}' IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM proof_finality_addenda f WHERE f.proof_id = pa.proof_id AND f.level = 3)`
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
		var chain sql.NullString
		if err := rows.Scan(&ref.ProofID, &chain); err != nil {
			return nil, err
		}
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

// LegRef returns one stored proof's leg: the chain its bundle's execution proof settled on. A proof
// whose bundle carries no execution proof (component 5) has no leg: the named finality_included_unavailable state.
func (r *FinalityAddendaRepository) LegRef(ctx context.Context, proofID string) (finality.LegRef, error) {
	ref := finality.LegRef{ProofID: proofID}
	var chain, header sql.NullString
	err := r.client.DB().QueryRowContext(ctx, `SELECT artifact_json #>> '{proof_components,5_execution_proof,chain_id}',
		artifact_json #>> '{proof_components,5_execution_proof,block_header_rlp}' FROM proof_artifacts WHERE proof_id = $1::uuid`, proofID).Scan(&chain, &header)
	if err != nil {
		return ref, err
	}
	if !header.Valid || header.String == "" {
		return ref, finality.IncludedUnavailable(finality.IncludedNoExecutionProof, "proof_id", proofID)
	}
	if id, perr := strconv.ParseUint(chain.String, 10, 64); perr == nil {
		ref.Chain = id
	}
	return ref, nil
}
