// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
)

// IdentityCaptureStore is the INSERT-ONLY store of the S8 capture rows (migration 00031, proof_identity_capture). It implements
// capture.Store and passes storetest.Run; a verifier never reads it. Put of the same bytes is a no-op and of different bytes is
// capture.ErrCaptureConflict; the decision and the insert are one statement (ON CONFLICT DO NOTHING) so seven validators writing the same
// key concurrently are safe.
type IdentityCaptureStore struct{ client *Client }

func NewIdentityCaptureStore(client *Client) *IdentityCaptureStore {
	return &IdentityCaptureStore{client: client}
}

var _ capture.Store = (*IdentityCaptureStore)(nil)

func (s *IdentityCaptureStore) Put(ctx context.Context, k capture.Key, data []byte) error {
	if err := capture.CheckKey(k); err != nil {
		return err
	}
	if len(data) > capture.MaxItemBytes() {
		return capture.ErrItemTooLarge
	}
	if k.Chain > math.MaxInt64 {
		return fmt.Errorf("%w: chain %d is above the signed 64-bit column", capture.ErrBadKey, k.Chain)
	}
	res, err := s.client.DB().ExecContext(ctx, `INSERT INTO proof_identity_capture (chain, anchor_id, block_hash, item, bytes)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (chain, anchor_id, block_hash, item) DO NOTHING`,
		int64(k.Chain), k.AnchorID[:], k.BlockHash[:], k.Item, data)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 1 {
		return nil
	}
	old, ok, err := s.Get(ctx, k)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("capture: key %s: neither inserted nor found", k)
	}
	if !bytes.Equal(old, data) {
		return fmt.Errorf("%w: %s", capture.ErrCaptureConflict, k)
	}
	return nil
}

func (s *IdentityCaptureStore) Get(ctx context.Context, k capture.Key) ([]byte, bool, error) {
	if k.Chain > math.MaxInt64 {
		return nil, false, nil // no row can exist at a chain the signed column cannot hold
	}
	var b []byte
	err := s.client.DB().QueryRowContext(ctx, `SELECT bytes FROM proof_identity_capture WHERE chain = $1 AND anchor_id = $2 AND block_hash = $3 AND item = $4`,
		int64(k.Chain), k.AnchorID[:], k.BlockHash[:], k.Item).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func (s *IdentityCaptureStore) ListByAnchor(ctx context.Context, chain uint64, anchorID [32]byte) ([]capture.Key, error) {
	if chain > math.MaxInt64 {
		return nil, nil
	}
	rows, err := s.client.DB().QueryContext(ctx, `SELECT block_hash, item FROM proof_identity_capture WHERE chain = $1 AND anchor_id = $2 ORDER BY block_hash, item COLLATE "C"`, int64(chain), anchorID[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []capture.Key
	for rows.Next() {
		k := capture.Key{Chain: chain, AnchorID: anchorID}
		var h []byte
		if err := rows.Scan(&h, &k.Item); err != nil {
			return nil, err
		}
		copy(k.BlockHash[:], h)
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *IdentityCaptureStore) ListByBlock(ctx context.Context, chain uint64, anchorID, blockHash [32]byte) ([]capture.Row, error) {
	if chain > math.MaxInt64 {
		return nil, nil
	}
	rows, err := s.client.DB().QueryContext(ctx, `SELECT item, bytes FROM proof_identity_capture WHERE chain = $1 AND anchor_id = $2 AND block_hash = $3 ORDER BY item COLLATE "C"`, int64(chain), anchorID[:], blockHash[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []capture.Row
	for rows.Next() {
		r := capture.Row{Key: capture.Key{Chain: chain, AnchorID: anchorID, BlockHash: blockHash}}
		if err := rows.Scan(&r.Item, &r.Bytes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Named refusals of the container repository.
var (
	// ErrContractIdentityTooLarge: the container is longer than ci.MaxContractIdentityBytes (never truncated, never stored).
	ErrContractIdentityTooLarge = errors.New("contract identity: container exceeds MaxContractIdentityBytes")
	// ErrContractIdentityDigest: the digest is not ci.DigestOf of the stated leg and container (storage consistency).
	ErrContractIdentityDigest = errors.New("contract identity: digest does not match the leg and container")
	// ErrContractIdentityMalformed: the bytes are not a CIE1 container, or it names another chain or leg than the one stated.
	ErrContractIdentityMalformed = errors.New("contract identity: container is malformed or names another leg")
	// ErrContractIdentityBetterPresent: a Stated container is refused when a captured one is already stored.
	ErrContractIdentityBetterPresent = errors.New("contract identity: better_present: a captured container is already stored")
)

// ContractIdentityRow is one stored container.
type ContractIdentityRow struct {
	ProofID     string
	Seq         uint64
	Chain       uint64
	BlockNumber uint64
	BlockHash   [32]byte
	Evidence    []byte
	Digest      [32]byte
}

// ContractIdentityRepository is the only write path of proof_contract_identity. It has Append and reads and no method that changes or
// removes a row (the table refuses UPDATE/DELETE/TRUNCATE itself). It runs no verifier: the verifier is injected into capture.Appender,
// whose Sink this repository provides (SinkFor), so a container a verifier refuses never reaches Append.
type ContractIdentityRepository struct{ client *Client }

func NewContractIdentityRepository(client *Client) *ContractIdentityRepository {
	return &ContractIdentityRepository{client: client}
}

// allStated reports whether neither part of the container is captured.
func allStated(c *ci.Container) bool {
	return c.Settle.Tag == ci.TagStated && c.Attest.Tag == ci.TagStated
}

// Append stores the container as the next seq of the proof and returns that seq. The same container as the greatest seq is a no-op that
// returns the stored seq (appended false). The seq decision and the insert are ONE transaction under a per-proof advisory lock, so seven
// validators sharing one Postgres cannot interleave a read and an insert.
func (r *ContractIdentityRepository) Append(ctx context.Context, proofID string, chain uint64, leg ci.BlockRef, container []byte, digest [32]byte) (uint64, bool, error) {
	if len(container) > ci.MaxContractIdentityBytes {
		return 0, false, fmt.Errorf("%w: %d bytes", ErrContractIdentityTooLarge, len(container))
	}
	if chain == 0 || chain > math.MaxInt64 || leg.Number > math.MaxInt64 {
		return 0, false, fmt.Errorf("%w: chain %d block %d", ErrContractIdentityMalformed, chain, leg.Number)
	}
	if ci.DigestOf(chain, leg.Number, leg.Hash, container) != digest {
		return 0, false, ErrContractIdentityDigest
	}
	c, err := ci.Decode(container, ci.DefaultLimits())
	if err != nil || c.Chain != chain || c.Leg != leg {
		return 0, false, fmt.Errorf("%w: %v", ErrContractIdentityMalformed, err)
	}
	sum := sha256.Sum256(container)
	tx, err := r.client.DB().BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('proof_contract_identity:' || $1::text, 0))`, proofID); err != nil {
		return 0, false, err
	}
	var (
		seq      sql.NullInt64
		lastSum  []byte
		lastBody []byte
	)
	if err := tx.QueryRowContext(ctx, `SELECT seq, evidence_sha256, evidence FROM proof_contract_identity WHERE proof_id = $1::uuid ORDER BY seq DESC LIMIT 1`, proofID).Scan(&seq, &lastSum, &lastBody); err != nil && err != sql.ErrNoRows {
		return 0, false, err
	}
	next := int64(1)
	if seq.Valid {
		if bytes.Equal(lastSum, sum[:]) {
			return uint64(seq.Int64), false, nil
		}
		if lc, derr := ci.Decode(lastBody, ci.DefaultLimits()); derr == nil && !allStated(lc) && allStated(c) {
			return 0, false, ErrContractIdentityBetterPresent
		}
		next = seq.Int64 + 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO proof_contract_identity (proof_id, seq, chain, block_number, block_hash, evidence, evidence_sha256, digest)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`, proofID, next, int64(chain), int64(leg.Number), leg.Hash[:], container, sum[:], digest[:]); err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return uint64(next), true, nil
}

// Latest returns the greatest-seq container of a proof, or ok=false when it has none.
func (r *ContractIdentityRepository) Latest(ctx context.Context, proofID string) (ContractIdentityRow, bool, error) {
	row := ContractIdentityRow{ProofID: proofID}
	var seq, chain, number int64
	var hash, digest []byte
	err := r.client.DB().QueryRowContext(ctx, `SELECT seq, chain, block_number, block_hash, evidence, digest FROM proof_contract_identity WHERE proof_id = $1::uuid ORDER BY seq DESC LIMIT 1`, proofID).
		Scan(&seq, &chain, &number, &hash, &row.Evidence, &digest)
	if err == sql.ErrNoRows {
		return row, false, nil
	}
	if err != nil {
		return row, false, err
	}
	if len(hash) != 32 || len(digest) != 32 {
		return row, false, fmt.Errorf("contract identity row of %s: block_hash %d bytes, digest %d bytes", proofID, len(hash), len(digest))
	}
	row.Seq, row.Chain, row.BlockNumber = uint64(seq), uint64(chain), uint64(number)
	copy(row.BlockHash[:], hash)
	copy(row.Digest[:], digest)
	return row, true, nil
}

// SinkFor is the capture.Sink of one proof: the production sink of capture.Appender.
func (r *ContractIdentityRepository) SinkFor(proofID string) capture.Sink {
	return proofSink{repo: r, proofID: proofID}
}

type proofSink struct {
	repo    *ContractIdentityRepository
	proofID string
}

func (s proofSink) AppendContainer(ctx context.Context, chain uint64, leg ci.BlockRef, container []byte, digest [32]byte) error {
	_, _, err := s.repo.Append(ctx, s.proofID, chain, leg, container, digest)
	return err
}
