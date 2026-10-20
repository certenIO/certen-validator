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
