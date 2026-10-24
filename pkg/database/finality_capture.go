// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"

	"github.com/certen/independant-validator/pkg/finality"
)

// FinalityCaptureStore is the INSERT-ONLY store of the leg-independent L1 captures (migration 00028, V2_SPEC_S7 2.8): the
// capturers write rows on every new parent-chain head and the attesting builders read them later. It has Put and reads and no
// method that changes or removes a row; the table refuses UPDATE, DELETE and TRUNCATE itself (trigger, SQLSTATE 23001). A
// verifier never reads it. It implements finality.CaptureStore.
type FinalityCaptureStore struct {
	client *Client
}

func NewFinalityCaptureStore(client *Client) *FinalityCaptureStore {
	return &FinalityCaptureStore{client: client}
}

var _ finality.CaptureStore = (*FinalityCaptureStore)(nil)

// Put inserts the row. The same bytes under an existing key are a no-op (nil); different bytes are finality.ErrCaptureConflict
// and the stored row is untouched. Concurrent Puts of one key are safe: the primary key serialises them and the loser reads
// the winner's bytes.
func (s *FinalityCaptureStore) Put(ctx context.Context, k finality.CaptureKey, data []byte) error {
	if err := finality.CheckCaptureItem(k.Item); err != nil {
		return err
	}
	if k.Chain == 0 {
		return fmt.Errorf("finality: capture key %s: chain 0", k)
	}
	if err := checkStoredKey(k.Chain, k.L1Block); err != nil {
		return err
	}
	res, err := s.client.DB().ExecContext(ctx, `INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (chain, l1_block, l1_hash, item) DO NOTHING`,
		int64(k.Chain), int64(k.L1Block), k.L1Hash[:], k.Item, data)
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
		return fmt.Errorf("finality: capture key %s: neither inserted nor found", k)
	}
	if !bytes.Equal(old, data) {
		return fmt.Errorf("%w: %s", finality.ErrCaptureConflict, k)
	}
	return nil
}

// Get returns the bytes of a row.
func (s *FinalityCaptureStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if !holdable(k.Chain, k.L1Block) {
		return nil, false, nil // no row can exist at a key the signed 64-bit columns cannot hold
	}
	var b []byte
	err := s.client.DB().QueryRowContext(ctx, `SELECT bytes FROM proof_finality_capture
		WHERE chain = $1 AND l1_block = $2 AND l1_hash = $3 AND item = $4`, int64(k.Chain), int64(k.L1Block), k.L1Hash[:], k.Item).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// ListByBlock returns every row of (chain, l1Block), ascending by (l1Hash, item): a reorged height lists both hashes.
func (s *FinalityCaptureStore) ListByBlock(ctx context.Context, chain, l1Block uint64) ([]finality.CaptureRow, error) {
	if !holdable(chain, l1Block) {
		return nil, nil
	}
	rows, err := s.client.DB().QueryContext(ctx, `SELECT l1_hash, item, bytes FROM proof_finality_capture
		WHERE chain = $1 AND l1_block = $2 ORDER BY l1_hash, item`, int64(chain), int64(l1Block))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []finality.CaptureRow
	for rows.Next() {
		r := finality.CaptureRow{CaptureKey: finality.CaptureKey{Chain: chain, L1Block: l1Block}}
		var h []byte
		if err := rows.Scan(&h, &r.Item, &r.Bytes); err != nil {
			return nil, err
		}
		if len(h) != 32 {
			return nil, fmt.Errorf("capture row at %d: l1_hash is %d bytes", l1Block, len(h))
		}
		copy(r.L1Hash[:], h)
		out = append(out, r)
	}
	return out, rows.Err()
}

// BlockBounds is the lowest and highest L1 block of the chain's rows of exactly this item (finality.BlockBounder): one aggregate query,
// no row listing and no bytes read.
func (s *FinalityCaptureStore) BlockBounds(ctx context.Context, chain uint64, item string) (uint64, uint64, bool, error) {
	var lo, hi sql.NullInt64
	if err := s.client.DB().QueryRowContext(ctx, `SELECT min(l1_block), max(l1_block) FROM proof_finality_capture WHERE chain = $1 AND item = $2`, int64(chain), item).Scan(&lo, &hi); err != nil {
		return 0, 0, false, err
	}
	if !lo.Valid || !hi.Valid || lo.Int64 < 0 {
		return 0, 0, false, nil
	}
	return uint64(lo.Int64), uint64(hi.Int64), true, nil
}

// ListByRange returns the keys of a chain whose L1 block is in [from, to] and whose item starts with itemPrefix (empty = all),
// ascending by (l1Block, l1Hash, item). The bytes are fetched with Get, so a range scan never loads the blobs.
func (s *FinalityCaptureStore) ListByRange(ctx context.Context, chain, from, to uint64, itemPrefix string) ([]finality.CaptureKey, error) {
	if to < from || !holdable(chain, from) {
		return nil, nil // an empty or inverted range, or one that starts above the largest block the table holds
	}
	if to > finality.MaxCaptureBlock {
		to = finality.MaxCaptureBlock // clamped, never wrapped into a negative bigint
	}
	rows, err := s.client.DB().QueryContext(ctx, `SELECT l1_block, l1_hash, item FROM proof_finality_capture
		WHERE chain = $1 AND l1_block BETWEEN $2 AND $3 AND starts_with(item, $4) ORDER BY l1_block, l1_hash, item`,
		int64(chain), int64(from), int64(to), itemPrefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []finality.CaptureKey
	for rows.Next() {
		k := finality.CaptureKey{Chain: chain}
		var blk int64
		var h []byte
		if err := rows.Scan(&blk, &h, &k.Item); err != nil {
			return nil, err
		}
		if len(h) != 32 {
			return nil, fmt.Errorf("capture row at %d: l1_hash is %d bytes", blk, len(h))
		}
		k.L1Block = uint64(blk)
		copy(k.L1Hash[:], h)
		out = append(out, k)
	}
	return out, rows.Err()
}

// holdable reports whether the signed 64-bit columns (chain, l1_block) can hold the key: a value above MaxInt64 would wrap to a
// negative bigint, so no row can exist there and a read of it is simply empty.
func holdable(chain, l1Block uint64) bool {
	return chain <= math.MaxInt64 && l1Block <= finality.MaxCaptureBlock
}

// checkStoredKey is the Put guard of the same bound: a key the table cannot hold is the named state
// finality_evidence_too_large{part, count, limit} (the family of the capture bounds) and never a raw CHECK error of the database.
func checkStoredKey(chain, l1Block uint64) error {
	if chain > math.MaxInt64 {
		return finality.EvidenceTooLarge("capture.chain", chain, math.MaxInt64)
	}
	if l1Block > finality.MaxCaptureBlock {
		return finality.EvidenceTooLarge("capture.l1_block", l1Block, finality.MaxCaptureBlock)
	}
	return nil
}

var _ finality.BlockPutter = (*FinalityCaptureStore)(nil)

// PutBlock stores the rows in ONE transaction: every row is inserted (or found identical) or none is (RB11-DBFIX D7). A key already
// stored with other bytes is finality.ErrCaptureConflict and the transaction is rolled back, so the rows of the call that preceded
// it are not stored either.
func (s *FinalityCaptureStore) PutBlock(ctx context.Context, rows []finality.CaptureRow) error {
	for _, r := range rows {
		if err := finality.CheckCaptureItem(r.Item); err != nil {
			return err
		}
		if r.Chain == 0 {
			return fmt.Errorf("finality: capture key %s: chain 0", r.CaptureKey)
		}
		if err := checkStoredKey(r.Chain, r.L1Block); err != nil {
			return err
		}
	}
	// rows are inserted in key order so that two writers of the same block (every validator captures the same blocks into one database)
	// queue on the first key instead of deadlocking on each other
	rows = append([]finality.CaptureRow(nil), rows...)
	sort.Slice(rows, func(i, j int) bool { return captureKeyLess(rows[i].CaptureKey, rows[j].CaptureKey) })
	tx, err := s.client.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range rows {
		res, err := tx.ExecContext(ctx, `INSERT INTO proof_finality_capture (chain, l1_block, l1_hash, item, bytes)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (chain, l1_block, l1_hash, item) DO NOTHING`,
			int64(r.Chain), int64(r.L1Block), r.L1Hash[:], r.Item, r.Bytes)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err == nil && n == 1 {
			continue
		}
		var old []byte
		if err := tx.QueryRowContext(ctx, `SELECT bytes FROM proof_finality_capture WHERE chain = $1 AND l1_block = $2 AND l1_hash = $3 AND item = $4`,
			int64(r.Chain), int64(r.L1Block), r.L1Hash[:], r.Item).Scan(&old); err != nil {
			return fmt.Errorf("finality: capture key %s: neither inserted nor found: %w", r.CaptureKey, err)
		}
		if !bytes.Equal(old, r.Bytes) {
			return fmt.Errorf("%w: %s", finality.ErrCaptureConflict, r.CaptureKey)
		}
	}
	return tx.Commit()
}

var _ finality.BlockSizer = (*FinalityCaptureStore)(nil)

// BlockSizes returns the size in bytes of every row stored under (chain, l1Block, l1Hash), by item, without transferring the bytes.
func (s *FinalityCaptureStore) BlockSizes(ctx context.Context, chain, l1Block uint64, l1Hash [32]byte) (map[string]int64, error) {
	out := map[string]int64{}
	if !holdable(chain, l1Block) {
		return out, nil
	}
	rows, err := s.client.DB().QueryContext(ctx, `SELECT item, octet_length(bytes)::bigint FROM proof_finality_capture
		WHERE chain = $1 AND l1_block = $2 AND l1_hash = $3`, int64(chain), int64(l1Block), l1Hash[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item string
		var n int64
		if err := rows.Scan(&item, &n); err != nil {
			return nil, err
		}
		out[item] = n
	}
	return out, rows.Err()
}

// captureKeyLess is the order PutBlock inserts in: chain, then block, then hash (bytewise), then item. Every writer of a block uses
// the same order, so two of them queue on the first key they share instead of each holding what the other waits for.
func captureKeyLess(a, b finality.CaptureKey) bool {
	if a.Chain != b.Chain {
		return a.Chain < b.Chain
	}
	if a.L1Block != b.L1Block {
		return a.L1Block < b.L1Block
	}
	if c := bytes.Compare(a.L1Hash[:], b.L1Hash[:]); c != 0 {
		return c < 0
	}
	return a.Item < b.Item
}
