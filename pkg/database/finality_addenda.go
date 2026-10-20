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
	// afterRead is a test seam: it runs after the chain was read under the lock and before the INSERT.
	afterRead func(attempt int)
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

// maxAppendAttempts bounds the retries of one Append that lost a race on the unique (proof_id, seq) / (proof_id, level) key.
const maxAppendAttempts = 4

// appendHook, when set by a test, runs after the chain was read under the lock and before the INSERT: the place where a writer
// that does not take the lock (another binary, a manual SQL session) can slip a row in.
// (a field of the repository, never a package variable, so parallel tests cannot see each other's hook).

// Append extends a proof's addendum chain by one addendum and stores it ONLY if it verifies (V2_SPEC_S7 2.4). In ONE
// transaction it
//
//  1. takes the proof's lock - pg_advisory_xact_lock keyed by the proof id, which also covers an empty chain - and a row lock on
//     the last addendum (SELECT ... FOR UPDATE), so racing upgraders of one leg queue here;
//  2. reads the stored chain and, via finality.PlanAppend, recomputes it under D0 = LegBinding of the VERIFIED Settlement block
//     (never a value read from a file or supplied by the caller): a chain forged under another binding is finality_chain_broken
//     and nothing is appended to it;
//  3. forms the next link (seq, prev_hash, own_hash) itself and runs the registered Kind verifier on the evidence
//     (Registry.JudgeAddendum): a refused build leaves no row and returns the verifier's named state;
//  4. inserts. A unique violation (a writer that did not take the lock took this seq or this level) or a refusal by the table's
//     trigger rolls back and retries from step 1, which then reports level_already_present or appends at the next seq; after
//     maxAppendAttempts it is the named finality_append_conflict (or finality_guard_refused).
//
// The settlement must be the proof's own: its derived block must equal the block of the bundle stored under proof_id, else
// finality_block_mismatch{field:"leg"}. The stored row is returned. The table's trigger refuses the same things for any other writer.
func (r *FinalityAddendaRepository) Append(ctx context.Context, req finality.AppendRequest) (finality.Addendum, error) {
	id := finality.ProofIDString(req.ProofID)
	want, err := finality.DeriveIncluded(req.Chain, req.Settlement)
	if err != nil {
		return finality.Addendum{}, err
	}
	ref, err := r.LegRef(ctx, id)
	if err != nil {
		return finality.Addendum{}, err
	}
	own, err := r.LegSettlement(ctx, ref)
	if err != nil {
		return finality.Addendum{}, err
	}
	have, err := finality.DeriveIncluded(ref.Chain, own.Included)
	if err != nil {
		return finality.Addendum{}, err
	}
	if have.Chain != want.Chain || have.Number != want.Number || have.Hash != want.Hash {
		return finality.Addendum{}, finality.BlockMismatch("leg", have.Triple(), want.Triple())
	}
	var lost error
	for attempt := 1; attempt <= maxAppendAttempts; attempt++ {
		a, retry, err := r.appendOnce(ctx, id, req, attempt)
		if !retry {
			return a, err
		}
		lost = err
	}
	// every attempt lost: the chain kept moving under writers that do not take the lock, or the table refused what the chain we
	// read justified. A guard refusal stays what it is; a lost race is the named conflict at the chain as it now stands.
	if n, ok := finality.AsNamed(lost); ok && n.Code == finality.CodeGuardRefused {
		return finality.Addendum{}, lost
	}
	stored, err := chainOf(ctx, r.client.DB(), id)
	if err != nil {
		return finality.Addendum{}, err
	}
	return finality.Addendum{}, finality.NewState(finality.CodeAppendConflict, "proof_id", id, "seq", uint64(len(stored)+1), "stored_through", len(stored))
}

// appendOnce is one attempt; retry is true only for a lost race on the unique key.
func (r *FinalityAddendaRepository) appendOnce(ctx context.Context, id string, req finality.AppendRequest, attempt int) (finality.Addendum, bool, error) {
	tx, err := r.client.DB().BeginTx(ctx, nil)
	if err != nil {
		return finality.Addendum{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, id); err != nil {
		return finality.Addendum{}, false, err
	}
	// the row lock of the spec: the last addendum, if the chain has one (the advisory lock already covers the empty chain)
	var lastSeq int64
	switch err := tx.QueryRowContext(ctx, `SELECT seq FROM proof_finality_addenda WHERE proof_id = $1 ORDER BY seq DESC LIMIT 1 FOR UPDATE`, id).Scan(&lastSeq); {
	case err == sql.ErrNoRows:
	case err != nil:
		return finality.Addendum{}, false, err
	}
	stored, err := chainOf(ctx, tx, id)
	if err != nil {
		return finality.Addendum{}, false, err
	}
	a, _, err := finality.PlanAppend(req, stored)
	if err != nil {
		return finality.Addendum{}, false, err // a refused build leaves nothing: the deferred rollback ends the transaction
	}
	if r.afterRead != nil {
		r.afterRead(attempt)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO proof_finality_addenda (proof_id, seq, level, chain, kind, evidence, prev_hash, own_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, int64(a.Seq), int16(a.Level), int64(a.Chain), a.Kind, a.Evidence, a.PrevHash[:], a.OwnHash[:]); err != nil {
		named := appendInsertError(id, a.Seq, err)
		// 23505: a writer that did not take the lock took this seq or this level; 23001: the table's trigger refused a row that
		// the chain we read no longer justifies. Either way the chain moved under us: read it again.
		code := pgCode(err)
		return finality.Addendum{}, code == "23505" || code == "23001", named
	}
	if err := tx.Commit(); err != nil {
		return finality.Addendum{}, false, err
	}
	return a, false, nil
}

// addendaQueryer is the read half shared by *sql.DB and *sql.Tx.
type addendaQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// chainOf reads a proof's addenda in ascending seq.
func chainOf(ctx context.Context, q addendaQueryer, proofID string) ([]finality.Addendum, error) {
	pid, err := finality.ParseProofID(proofID)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT seq, level, chain, kind, evidence, prev_hash, own_hash
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

// Chain returns a proof's addenda in ascending seq (empty when it has none). D0 is not stored: it is the leg binding of the
// proof's Settlement block, recomputed by the caller and passed to finality.VerifyChain.
func (r *FinalityAddendaRepository) Chain(ctx context.Context, proofID string) ([]finality.Addendum, error) {
	return chainOf(ctx, r.client.DB(), proofID)
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
