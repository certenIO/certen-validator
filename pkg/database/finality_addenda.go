// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
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

// maxBundleJSON bounds a stored bundle once decompressed. The bundle is a certen_v1 document of a few hundred KiB; a stored
// value that decompresses past this is refused by name without being read further (a decompression bomb costs the bound, not
// its size).
const maxBundleJSON = 16 << 20

// maxStoredBundle bounds a stored bundle before it is fetched: proof_bundles.bundle_data is read only after its octet_length is
// known to be within this many (compressed) bytes.
const maxStoredBundle = 16 << 20

// bundleFormatV1 is the only proof_bundles.bundle_format the leg source reads: the gzip of the bundle JSON that
// pkg/proof CertenProofBundle.ToCompressedJSON writes.
const bundleFormatV1 = "certen_v1"

// SettledLegs lists every stored proof that has a bundle, NEWEST FIRST (by the proof's creation time, then its id, both
// descending), leaving out proofs whose chain already stands at finalized. A backlog of old legs therefore never stands in front
// of a new one. Each leg carries the id of the proof's NEWEST bundle (LegRef.BundleID), which LegSettlement reads and the upgrader
// remembers when that bundle holds no execution proof. The cursor `after` is the proof id the previous page ended with; the next
// page starts after that proof's own (created_at, proof_id), so a proof stored between two pages is newer than the cursor: this
// walk does not see it, the next listing starts with it, and nothing already returned is returned again. A cursor that names no
// proof is refused (an empty page would end the pass as if the backlog were done).
//
// There is no filter on what the bundle holds or on settlement_block_number: a prefilter that can drop a settled leg is below the
// claim that every settled leg gets its evidence. Whether the bundle holds an execution proof is decided per leg by LegSettlement
// (a named state), and the upgrader reads a bundle that holds none once. The chain is the cycle summary's chain_id
// (proof_artifacts.artifact_json is the summary; it never carries proof_components).
func (r *FinalityAddendaRepository) SettledLegs(ctx context.Context, after string, limit int) ([]finality.LegRef, error) {
	if limit <= 0 {
		limit = 200
	}
	query := `
		SELECT pa.proof_id::text, pa.artifact_json ->> 'chain_id', pb.bundle_id::text
		FROM proof_artifacts pa
		JOIN LATERAL (SELECT bundle_id FROM proof_bundles WHERE proof_id = pa.proof_id
			ORDER BY created_at DESC, bundle_id DESC LIMIT 1) pb ON true
		WHERE NOT EXISTS (SELECT 1 FROM proof_finality_addenda f WHERE f.proof_id = pa.proof_id AND f.level = 3)`
	args := []any{}
	if after != "" {
		var cursorAt time.Time
		if err := r.client.DB().QueryRowContext(ctx, `SELECT created_at FROM proof_artifacts WHERE proof_id = $1::uuid`, after).Scan(&cursorAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("settled legs: the cursor %s names no stored proof", after)
			}
			return nil, err
		}
		query += ` AND (pa.created_at, pa.proof_id) < ($1::timestamptz, $2::uuid)`
		args = append(args, cursorAt, after)
	}
	query += fmt.Sprintf(` ORDER BY pa.created_at DESC, pa.proof_id DESC LIMIT $%d`, len(args)+1)
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
		if err := rows.Scan(&ref.ProofID, &chain, &ref.BundleID); err != nil {
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

// executionProof is component 5 of a stored bundle: the raw JSON of its execution proof, the chain it names, and the settlement
// the proof row records (NULL until the proof's settlement was classified) that the served evidence must be for.
type executionProof struct {
	raw          json.RawMessage
	chain        uint64
	settlementTx sql.NullString
	settlementAt sql.NullInt64
	bundleID     string // the bundle component 5 was read from
}

// bundleInvalid is the named state of a stored bundle the source cannot read.
func bundleInvalid(proofID string, cause string) *finality.StateError {
	return finality.NewState(finality.CodeIncludedInvalid, "proof_id", proofID, "cause", cause)
}

// gunzipBounded decompresses a stored bundle, reading at most maxBundleJSON bytes of output.
func gunzipBounded(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxBundleJSON+1))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	if len(out) > maxBundleJSON {
		return nil, fmt.Errorf("the bundle decompresses past %d bytes", maxBundleJSON)
	}
	return out, nil
}

// idHex is a proof id as the bundle writer states it in bundle_integrity.custody_chain_hash: lower-case hex without dashes.
func idHex(id string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(id)), "-", "")
}

// executionProofOf reads component 5 (proof_components.5_execution_proof) of one stored bundle of a proof, the bundle bundleID names or,
// when it is empty, the proof's NEWEST: the one source of
// a leg's L6 evidence, shared by LegRef and LegSettlement (and so by the upgrader and by cmd/proofverify). proof_artifacts.artifact_json
// is only the cycle summary and is never a source.
//
//   - A proof that does not exist is sql.ErrNoRows.
//   - finality_included_unavailable{no_execution_proof_component} (no settlement yet) is: the proof has no bundle, or its bundle's component 5 is absent,
//     JSON null or {}. Nothing is wrong and nothing was served.
//   - finality_included_unavailable{no_block_header}: component 5 is non-empty but its block_header_rlp is absent, null or empty (the
//     bundles written before the header was captured).
//   - Everything else that is not a usable execution proof is the named finality_included_invalid state with its cause: a bundle
//     that is not certen_v1, is stored over the size bound, is not gzip, is truncated, decompresses past the bound, is not a JSON
//     object (a top-level null included), was written for another proof (bundle_integrity.custody_chain_hash is not this proof's
//     id; the writer, pkg/execution generateAndPersistBundle, has set it to the proof id on every bundle since 2026-01-26), or
//     whose non-empty component 5 is not an object, has a block_header_rlp that is present but not a non-empty 0x-hex string, or
//     names no chain_id that is a decimal number.
func (r *FinalityAddendaRepository) executionProofOf(ctx context.Context, proofID, bundleID string) (*executionProof, error) {
	ep := &executionProof{}
	var foundID, format sql.NullString
	var size sql.NullInt64
	err := r.client.DB().QueryRowContext(ctx, `SELECT pa.settlement_tx_hash, pa.settlement_block_number, pb.bundle_id::text, pb.bundle_format, pb.size
		FROM proof_artifacts pa
		LEFT JOIN LATERAL (SELECT bundle_id, bundle_format, octet_length(bundle_data) AS size FROM proof_bundles WHERE proof_id = pa.proof_id AND ($2::text = '' OR bundle_id::text = $2::text)
			ORDER BY created_at DESC, bundle_id DESC LIMIT 1) pb ON true
		WHERE pa.proof_id = $1::uuid`, proofID, bundleID).Scan(&ep.settlementTx, &ep.settlementAt, &foundID, &format, &size)
	if err != nil {
		return nil, err
	}
	if !foundID.Valid {
		return nil, finality.IncludedUnavailable(finality.IncludedNoExecutionProof, "proof_id", proofID)
	}
	if format.String != bundleFormatV1 {
		return nil, bundleInvalid(proofID, "bundle_format "+format.String+" is not "+bundleFormatV1)
	}
	if size.Int64 > maxStoredBundle {
		return nil, bundleInvalid(proofID, fmt.Sprintf("the stored bundle is %d bytes, the bound is %d", size.Int64, int64(maxStoredBundle)))
	}
	var data []byte
	if err := r.client.DB().QueryRowContext(ctx, `SELECT bundle_data FROM proof_bundles WHERE bundle_id = $1::uuid`, foundID.String).Scan(&data); err != nil {
		return nil, err
	}
	doc, err := gunzipBounded(data)
	if err != nil {
		return nil, bundleInvalid(proofID, err.Error())
	}
	if string(bytes.TrimSpace(doc)) == "null" {
		return nil, bundleInvalid(proofID, "the bundle is JSON null")
	}
	var bundle struct {
		BundleIntegrity struct {
			CustodyChainHash string `json:"custody_chain_hash"`
		} `json:"bundle_integrity"`
		ProofComponents struct {
			Execution json.RawMessage `json:"5_execution_proof"`
		} `json:"proof_components"`
	}
	if err := json.Unmarshal(doc, &bundle); err != nil {
		return nil, bundleInvalid(proofID, "the bundle is not JSON of the certen_v1 shape: "+err.Error())
	}
	if got := idHex(bundle.BundleIntegrity.CustodyChainHash); got == "" {
		return nil, bundleInvalid(proofID, "bundle_integrity.custody_chain_hash is empty: the writer sets it to the proof id")
	} else if got != idHex(proofID) {
		return nil, bundleInvalid(proofID, fmt.Sprintf("the bundle was written for proof %s: bundle_integrity.custody_chain_hash is the proof id the writer sets, and it is not this proof's", got))
	}
	raw := bundle.ProofComponents.Execution
	if len(raw) == 0 || string(raw) == "null" {
		return nil, finality.IncludedUnavailable(finality.IncludedNoExecutionProof, "proof_id", proofID)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, bundleInvalid(proofID, "the bundle's execution proof is not a JSON object")
	}
	if len(members) == 0 {
		return nil, finality.IncludedUnavailable(finality.IncludedNoExecutionProof, "proof_id", proofID)
	}
	// A component 5 without its header is what bundles written before the header was captured hold (the same keys otherwise, and a
	// corrupt one cannot be told from it): nothing can be judged for it, and it is not a failure. A header that is present and
	// unusable is corrupt.
	rawHeader, present := members["block_header_rlp"]
	if !present || string(bytes.TrimSpace(rawHeader)) == "null" {
		return nil, finality.IncludedUnavailable(finality.IncludedNoBlockHeader, "proof_id", proofID)
	}
	var header string
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, bundleInvalid(proofID, "the bundle's execution proof block_header_rlp is not a string")
	}
	if header == "" {
		return nil, finality.IncludedUnavailable(finality.IncludedNoBlockHeader, "proof_id", proofID)
	}
	if raw, err := hexutil.Decode(header); err != nil || len(raw) == 0 {
		return nil, bundleInvalid(proofID, "the bundle's execution proof block_header_rlp is not a non-empty 0x-prefixed hex string")
	}
	var chain string
	if err := json.Unmarshal(members["chain_id"], &chain); err != nil || chain == "" {
		return nil, bundleInvalid(proofID, "the bundle's execution proof names no chain_id (a non-empty decimal string)")
	}
	id, err := strconv.ParseUint(chain, 10, 64)
	if err != nil {
		return nil, bundleInvalid(proofID, fmt.Sprintf("the bundle's execution proof chain_id %q is not a decimal chain id", chain))
	}
	ep.raw, ep.chain, ep.bundleID = raw, id, foundID.String
	return ep, nil
}

// LegSettlement loads a leg's L6 evidence from its stored bundle (component 5): the block header and the transaction and
// receipt proofs, verified here before they are handed on. Evidence that does not verify is a named finality_included_invalid
// state, not a partial settlement. The leg's chain is the execution proof's own; the reference's chain (the cycle summary's
// chain_id) must agree with it when the reference has one, and a disagreement is a named finality_included_invalid state. The
// evidence must also be for the settlement the proof row records: when proof_artifacts.settlement_tx_hash and
// settlement_block_number are set, the proven transaction hash and the verified header's block number must equal them, else
// finality_included_invalid naming both. (The writer sets them from the same observation as component 5.) A NULL column is not
// checked, and the Settlement is returned marked Unrecorded: the writer records the settlement right after the bundle, and the
// upgrader counts and reports such legs. The bundle read is the one ref.BundleID names (the newest when it is empty).
func (r *FinalityAddendaRepository) LegSettlement(ctx context.Context, ref finality.LegRef) (finality.Settlement, error) {
	ep, err := r.executionProofOf(ctx, ref.ProofID, ref.BundleID)
	if err != nil {
		return finality.Settlement{}, err
	}
	if ref.Chain == 0 {
		return finality.Settlement{}, bundleInvalid(ref.ProofID, fmt.Sprintf("the proof's summary names no usable chain_id, but its bundle's execution proof settled on chain %d", ep.chain))
	}
	if ref.Chain != 0 && ref.Chain != ep.chain {
		return finality.Settlement{}, bundleInvalid(ref.ProofID, fmt.Sprintf("the bundle's execution proof settled on chain %d, the proof's summary names chain %d", ep.chain, ref.Chain))
	}
	var settlement ethproof.Settlement
	if err := json.Unmarshal(ep.raw, &settlement); err != nil {
		return finality.Settlement{}, bundleInvalid(ref.ProofID, err.Error())
	}
	subject, err := finality.SubjectOfSettlement(&settlement)
	if err != nil {
		return finality.Settlement{}, err
	}
	provenTx := hex.EncodeToString(settlement.TxHash[:])
	if ep.settlementTx.Valid && strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ep.settlementTx.String)), "0x") != provenTx {
		return finality.Settlement{}, bundleInvalid(ref.ProofID, fmt.Sprintf("the bundle proves transaction 0x%s, the proof's settlement_tx_hash is %s", provenTx, ep.settlementTx.String))
	}
	if ep.settlementAt.Valid && ep.settlementAt.Int64 != int64(subject.BlockNumber) {
		return finality.Settlement{}, bundleInvalid(ref.ProofID, fmt.Sprintf("the bundle proves block %d, the proof's settlement_block_number is %d", subject.BlockNumber, ep.settlementAt.Int64))
	}
	// A proof row that does not record its settlement yet (the writer records it right after the bundle) is served without the
	// check against the recorded one, and says so: the upgrader counts such legs.
	return finality.Settlement{Chain: ep.chain, Subject: subject, Included: &settlement, Unrecorded: !ep.settlementTx.Valid || !ep.settlementAt.Valid}, nil
}

// LegRef returns one stored proof's leg: the chain its bundle's execution proof settled on. A proof whose bundle carries no
// execution proof (component 5) has no leg: the named finality_included_unavailable state.
func (r *FinalityAddendaRepository) LegRef(ctx context.Context, proofID string) (finality.LegRef, error) {
	ref := finality.LegRef{ProofID: proofID}
	ep, err := r.executionProofOf(ctx, proofID, "")
	if err != nil {
		return ref, err
	}
	ref.Chain, ref.BundleID = ep.chain, ep.bundleID
	return ref, nil
}
