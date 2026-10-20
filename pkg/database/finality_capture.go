// Copyright 2026 Certen Protocol

package database

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

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

// ListByRange returns the keys of a chain whose L1 block is in [from, to] and whose item starts with itemPrefix (empty = all),
// ascending by (l1Block, l1Hash, item). The bytes are fetched with Get, so a range scan never loads the blobs.
func (s *FinalityCaptureStore) ListByRange(ctx context.Context, chain, from, to uint64, itemPrefix string) ([]finality.CaptureKey, error) {
	if to < from {
		return nil, nil
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
