// Copyright 2026 Certen Protocol

// Package capture is the builder side of S8 (V2_SPEC_S8 r3.2, Q2): it captures, near the head and beside the observation, the proof
// nodes and code bytes a contract-identity verifier reads, stores them in its own insert-only store, and assembles the CIE1 container.
// Nothing here enters a hashed input, nothing here is read by a verifier, and nothing here blocks settlement, attestation or write-back.
package capture

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/finality"
)

// Key addresses one capture row of V2_SPEC_S8 Q2 (WHERE stored, item 1): (chain, anchor_id, block_hash, item). BlockHash is the hash of
// the block the item was read at (the settlement block for the settle station, B_v for the attestation station); AnchorID is shared by
// every member leg of a batch. A reorg yields a second row under another hash; a row is never updated or deleted.
type Key struct {
	Chain     uint64
	AnchorID  [32]byte
	BlockHash [32]byte
	Item      string
}

func (k Key) String() string {
	return fmt.Sprintf("chain %d anchor %s block %s item %s", k.Chain, hex.EncodeToString(k.AnchorID[:4]), hex.EncodeToString(k.BlockHash[:4]), k.Item)
}

// Row is a key and its bytes.
type Row struct {
	Key
	Bytes []byte
}

// MaxItemBytes bounds one item: the container bound (a canonical node set can never be larger than the container that carries it).
func MaxItemBytes() int { return ci.DefaultLimits().MaxContainerBytes }

var (
	// ErrCaptureConflict: the key is stored with different bytes. A capture row is insert-only; honest captures of one key are
	// byte-identical, so a conflict on a captured item is an alarm and on a Stated item means another validator stated first.
	ErrCaptureConflict = errors.New("capture: row exists with different bytes")
	// ErrItemTooLarge: the item is longer than MaxItemBytes (never truncated, never stored).
	ErrItemTooLarge = errors.New("capture: item exceeds MaxItemBytes")
	// ErrBadKey: the item name is outside the alphabet of finality.CheckCaptureItem, or the key has a zero hash.
	ErrBadKey = errors.New("capture: bad key")
)

// CheckKey refuses a key a store must never hold: the item alphabet is the S7 rule (finality.CheckCaptureItem: lower-case letters,
// digits, '_' and '-' separated by single '/'), and a zero anchor id or block hash names nothing.
func CheckKey(k Key) error {
	if err := finality.CheckCaptureItem(k.Item); err != nil {
		return fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	if k.AnchorID == ([32]byte{}) || k.BlockHash == ([32]byte{}) {
		return fmt.Errorf("%w: zero anchor id or block hash", ErrBadKey)
	}
	return nil
}

// Store is the insert-only store of the S8 capture rows. Put of the same bytes under an existing key is a no-op and of different bytes is
// ErrCaptureConflict; the decision and the insert are ONE atomic step (seven validators write the same key concurrently). The production
// implementation (Postgres, WP-S8-5) must pass storetest.Run. A verifier never reads it.
type Store interface {
	Put(ctx context.Context, k Key, data []byte) error
	Get(ctx context.Context, k Key) ([]byte, bool, error)
	// ListByAnchor returns the KEYS (no bytes) of (chain, anchorID) ascending by (BlockHash, Item) bytewise.
	ListByAnchor(ctx context.Context, chain uint64, anchorID [32]byte) ([]Key, error)
	// ListByBlock returns every row of (chain, anchorID, blockHash) ascending by Item.
	ListByBlock(ctx context.Context, chain uint64, anchorID, blockHash [32]byte) ([]Row, error)
}
