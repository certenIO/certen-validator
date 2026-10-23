// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// CaptureKey addresses one capture row of V2_SPEC_S7 2.8: (chain, l1_block, l1_hash, item). Chain is the ROLLUP chain the row
// serves, L1Block and L1Hash name the parent-chain block, and Item names the captured thing. A reorg yields a second row for
// the same height under another hash; a row is never updated or deleted.
type CaptureKey struct {
	Chain   uint64
	L1Block uint64
	L1Hash  [32]byte
	Item    string
}

func (k CaptureKey) String() string {
	return fmt.Sprintf("chain %d l1 %d %x item %s", k.Chain, k.L1Block, k.L1Hash[:4], k.Item)
}

// CaptureRow is a key and its bytes.
type CaptureRow struct {
	CaptureKey
	Bytes []byte
}

// ErrCaptureConflict: the key is already stored with different bytes. A capture row is insert-only.
var ErrCaptureConflict = errors.New("finality: capture row exists with different bytes")

var captureItemRE = regexp.MustCompile(`^[a-z0-9_-]+(/[a-z0-9_-]+)*$`)

// MaxCaptureItem is the longest item name (the column is wider; the capturers' own names are far shorter).
const MaxCaptureItem = 120

// CheckCaptureItem refuses an item name outside the documented alphabet: lower-case letters, digits, '_' and '-' separated by
// single '/'.
func CheckCaptureItem(item string) error {
	if len(item) > MaxCaptureItem || !captureItemRE.MatchString(item) {
		return fmt.Errorf("finality: bad capture item name %q", item)
	}
	return nil
}

// CaptureStore is the insert-only store the capturers write and the attesting builders read (V2_SPEC_S7 2.8). The production
// implementation is pkg/database.FinalityCaptureStore over proof_finality_capture; a verifier never reads it. Put of the same
// bytes under an existing key is a no-op and of different bytes is ErrCaptureConflict.
type CaptureStore interface {
	Put(ctx context.Context, k CaptureKey, data []byte) error
	Get(ctx context.Context, k CaptureKey) ([]byte, bool, error)
	// ListByBlock returns every row of (chain, l1Block), ascending by (l1Hash, item).
	ListByBlock(ctx context.Context, chain, l1Block uint64) ([]CaptureRow, error)
	// ListByRange returns the KEYS (no bytes) of a chain whose L1 block is in [from, to] and whose item has the prefix
	// (empty = all), ascending by (l1Block, l1Hash, item).
	ListByRange(ctx context.Context, chain, from, to uint64, itemPrefix string) ([]CaptureKey, error)
}

// BlockPutter is a CaptureStore that admits the rows of one captured block as a unit (RB11-DBFIX D7): every row is stored or none
// is. A capture of a block that is written one row at a time can be cut anywhere - by the per-leg byte bound, by an I/O failure -
// and then the row that names the block as captured (the inbox row of a Base block, the batch record of an Arbitrum batch) lists
// rows that are not there, so a builder would attest from half a block. The production store (pkg/database.FinalityCaptureStore)
// writes the rows in one transaction, and the budgeted store (pkg/finality/runtime.BudgetedStore) reserves the block's planned
// total before the first row is written and refuses the whole block if the reservation does not fit the bound.
type BlockPutter interface {
	// PutBlock stores every row or none. As for Put, a row already stored with the same bytes is a no-op and one stored with other
	// bytes is ErrCaptureConflict, in which case no row of the call is stored.
	PutBlock(ctx context.Context, rows []CaptureRow) error
}

// PutBlock stores the rows of one captured block through the store's own all-or-nothing PutBlock. A store without one (the directory
// store of the one-shot recorder, and doubles) has no admission bound to cross, so its rows are written in the order given and the
// first error is returned: a caller lists the row that NAMES the block (the inbox row, the batch record) LAST, so a cut leaves rows
// nothing names yet and never a name without its rows. The stores the validator runs on (the database store and the budgeted store
// in front of it) do implement BlockPutter, and a test pins that.
func PutBlock(ctx context.Context, s CaptureStore, rows []CaptureRow) error {
	if bp, ok := s.(BlockPutter); ok {
		return bp.PutBlock(ctx, rows)
	}
	for _, r := range rows {
		if err := s.Put(ctx, r.CaptureKey, r.Bytes); err != nil {
			return err
		}
	}
	return nil
}

// BlockSizer is an optional read of a CaptureStore: the size in bytes of every row stored under (chain, l1Block, l1Hash), by item, without
// the bytes. The budgeted store reads it at every admission, so a block that other writers have grown is counted as it stands.
type BlockSizer interface {
	BlockSizes(ctx context.Context, chain, l1Block uint64, l1Hash [32]byte) (map[string]int64, error)
}
