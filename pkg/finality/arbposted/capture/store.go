// Copyright 2026 Certen Protocol

// Package capture is the leg-independent CAPTURE phase of the Arbitrum Sepolia l1_posted kind (V2_SPEC_S7 section 2.8). Public
// Sepolia providers serve eth_getProof only near the head, while a kind is verifiable only once its L1 blocks are covered by a
// finalized head (13-19 minutes later), so everything the builder needs from L1 is captured on every parent-chain head, into an
// INSERT-ONLY store, and attested later from the stored bytes.
//
// A capture row is keyed (chain, l1Block, l1Hash, item). chain is the ROLLUP chain id the capture serves (421614), l1Block and
// l1Hash name the parent-chain block the row belongs to (a reorg yields a second row for the same height under another hash),
// and item is one of the names documented in records.go. A row is never updated or deleted; the same key with identical bytes
// is a no-op and with different bytes is ErrExists. Nothing here is ever read by a verifier.
package capture

import (
	"github.com/certen/independant-validator/pkg/finality"
)

// ErrExists: the key is already stored with different bytes. A capture row is insert-only.
var ErrExists = finality.ErrCaptureConflict

// Key addresses one capture row: the framework's key.
type Key = finality.CaptureKey

// Row is a key and its bytes.
type Row = finality.CaptureRow

// CheckItem refuses an item name outside the documented alphabet (the DirStore maps '/' to '+' and must stay reversible).
func CheckItem(item string) error { return finality.CheckCaptureItem(item) }

// CaptureStore is the insert-only row store: the framework's interface. The production table is proof_finality_capture
// (pkg/database.FinalityCaptureStore); MemStore and DirStore implement the same contract for tests and for the live runner.
// A prefix scan across all blocks is ListByRange(ctx, chain, 0, finality.MaxCaptureBlock, prefix).
type CaptureStore = finality.CaptureStore

// MemStore is the in-memory CaptureStore.
type MemStore = finality.MemCaptureStore

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return finality.NewMemCaptureStore() }

// DirStore keeps rows as files (finality.DirCaptureStore): <dir>/<chain>/<l1Block>-<l1Hash hex>/<item with '/' as '+'>.
type DirStore = finality.DirCaptureStore

// NewDirStore opens (creating it if needed) a store under dir.
func NewDirStore(dir string) (*DirStore, error) { return finality.NewDirCaptureStore(dir) }
