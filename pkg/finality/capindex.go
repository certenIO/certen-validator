// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-A: the capture index. The capture store (V2_SPEC_S7 2.8) keeps the leg-independent L1 bytes of a chain; a build used to
// read the window of that store its leg can need and decompress every channel in it, again for every attempt. The index is built as
// captures arrive, stored as more insert-only rows of the SAME table under item names `idx/g<generation>/<family>/...`, and lets a
// build load only the rows of its own channel. It is an optimisation and never evidence: a builder takes locators from it, assembles
// the evidence from the captured rows and runs the kind's verifier on the result exactly as before, so a wrong or missing index row can
// produce a named pending or failed state and never an addendum the unindexed path would not also produce.
//
// This file is the chain-independent part (item names, conflict-aware writes, the cursor, the indexer contract, the named state). A
// chain's own package owns its codecs and its lookup (Base: pkg/finality/baseposted/index*.go; Arbitrum follows with the same
// framework).

// EnvIndexGeneration selects the generation of the Base index rows a process reads and writes. Rows of a generation are never
// updated or removed (the table is insert-only); the way to rebuild an index whose rows were wrong is to start the next generation,
// which backfills from the captured rows under new item names while the old rows stay as history.
const EnvIndexGeneration = "CERTEN_FINALITY_BASE_INDEX_GENERATION"

// DefaultIndexGeneration is generation 1.
const DefaultIndexGeneration uint32 = 1

// IndexItem is the item name of an index row: idx/g<generation>/<family>/<part>/<part>.... Every part must already satisfy the
// capture item alphabet (lower-case letters, digits, '_' and '-').
func IndexItem(gen uint32, family string, parts ...string) string {
	var b strings.Builder
	b.WriteString("idx/g")
	b.WriteString(strconv.FormatUint(uint64(gen), 10))
	b.WriteByte('/')
	b.WriteString(family)
	for _, p := range parts {
		b.WriteByte('/')
		b.WriteString(p)
	}
	return b.String()
}

// IndexPrefix is the item prefix every row of a (generation, family) has.
func IndexPrefix(gen uint32, family string) string { return IndexItem(gen, family) + "/" }

// ErrIndexConflict: an index row already exists with different bytes. Index rows are a pure function of captured bytes, so two
// writers (seven validators share one database) always write the same bytes; a different row is a defect or corruption and is a
// named error, never an overwrite and never ignored.
var ErrIndexConflict = errors.New("finality: index row exists with different bytes")

// IndexConflictError names the row.
type IndexConflictError struct {
	Key CaptureKey
}

func (e *IndexConflictError) Error() string {
	return fmt.Sprintf("%v: %s", ErrIndexConflict, e.Key)
}

// Is makes errors.Is(err, ErrIndexConflict) true.
func (e *IndexConflictError) Is(target error) bool { return target == ErrIndexConflict }

// IndexPut writes an index row to the insert-only store: the same bytes under an existing key are a no-op, different bytes are an
// *IndexConflictError (counted by chain and family).
func IndexPut(ctx context.Context, s CaptureStore, family string, k CaptureKey, data []byte) error {
	err := s.Put(ctx, k, data)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrCaptureConflict) {
		metrics.IncFinalityIndexConflict(k.Chain, family)
		return &IndexConflictError{Key: k}
	}
	return err
}

// IndexCursorItem is the cursor row of a (generation, family): keyed at the block the index has processed through, under the zero
// hash, 8 bytes (the block, big endian), insert-only like the capture loop's own cursor.
func IndexCursorItem(gen uint32, family string) string { return IndexItem(gen, family, "cursor") }

// ReadIndexCursor is the lowest and the highest block of the cursor rows (ok false: the index has not processed anything).
func ReadIndexCursor(ctx context.Context, s CaptureStore, chain uint64, gen uint32, family string) (lo, hi uint64, ok bool, err error) {
	return BlockBoundsOf(ctx, s, chain, IndexCursorItem(gen, family))
}

// WriteIndexCursor records that the index has processed through block.
func WriteIndexCursor(ctx context.Context, s CaptureStore, chain uint64, gen uint32, family string, block uint64) error {
	var v [8]byte
	for i := 0; i < 8; i++ {
		v[7-i] = byte(block >> (8 * i))
	}
	return IndexPut(ctx, s, family, CaptureKey{Chain: chain, L1Block: block, Item: IndexCursorItem(gen, family)}, v[:])
}

// CodeIndexInconsistent is the named state of an index that disagrees with the captured rows or with itself (go_operational,
// class U). Reasons are a closed set (testdata/finality/states.json).
const CodeIndexInconsistent = "index_inconsistent"

// Reasons of CodeIndexInconsistent.
const (
	IndexEntryCorrupt       = "entry_corrupt"               // an index row does not decode or fails its checksum
	IndexPinsChanged        = "pins_changed"                // the row was written under other pins than the builder's
	IndexRowMissing         = "row_missing"                 // a capture row the index names is not in the store
	IndexRowsDisagree       = "rows_disagree"               // the rows read do not match what the index says of them
	IndexDuplicateAfterOpen = "duplicate_frame_after_close" // a frame arrived after the channel closed and breaks it
	IndexSelfCheckMismatch  = "self_check_mismatch"         // a recomputation from the captured rows differs from the stored row
	IndexCoverageOverflow   = "coverage_overflow"           // the channel covers more runs than an entry stores
)

// IndexInconsistent builds the named state; extra are further key, value pairs of the state (all registered).
func IndexInconsistent(chain uint64, family, reason string, extra ...any) *StateError {
	kv := append([]any{"chain", chain, "family", family, "reason", reason}, extra...)
	return NewState(CodeIndexInconsistent, kv...)
}

// CodeCaptureGap is the named state of a leg whose channel the capture does not hold although captured channels of later L2 time exist:
// the capture has a hole (go_operational, class U).
const CodeCaptureGap = "l1_capture_gap"

// CodeIndexDisabled is the named state of a capture index that a bad setting switched off: the validator keeps running and the builder
// reads the window (go_operational). The reason is the class of the fault; the value of the setting is never part of the state.
const CodeIndexDisabled = "finality_index_disabled"

// Reasons of finality_index_disabled.
const (
	IndexSettingSwitchInvalid = "switch_invalid" // the switch is not true/false, 1/0, yes/no or on/off
	IndexSettingNotInteger    = "not_an_integer"
	IndexSettingOutOfRange    = "out_of_range" // below the minimum or above the maximum the setting allows
)

// IndexDisabledState builds finality_index_disabled for the setting key.
func IndexDisabledState(chain uint64, key, reason string) *StateError {
	return NewState(CodeIndexDisabled, "chain", chain, "key", key, "reason", reason)
}

// AnnounceIndexDisabled logs the state, sets the gauge certen_finality_index_disabled and records it for /health/detailed.
func AnnounceIndexDisabled(logf func(format string, args ...any), st *StateError) {
	chain, _ := st.Fields["chain"].(uint64)
	key, _ := st.Fields["key"].(string)
	reason, _ := st.Fields["reason"].(string)
	logf("[FINALITY] capture index DISABLED, the window reader serves: %s", st.Error())
	metrics.SetFinalityIndexDisabled(chain, "bi", key, reason)
	metrics.SetFinalityChainIndexDisabledReason(chain, st.Error())
}

// GapStateUnrecorded is the gap_state of an l1_capture_gap the index INFERS: no durable gap record names the hole, but captured channels of
// later L2 time exist past the capture retry window and none covers the leg. The record-backed states are GapOpen, GapUnavailableProven and
// GapRetentionExpired (gaps.go); the registry (testdata/finality/states.json) requires each producer's own fields by this discriminator.
const GapStateUnrecorded = "unrecorded"

// StepReport is what one indexer step did (logged and exported as metrics by the runner).
type StepReport struct {
	Blocks       int           // captured blocks digested in this step
	Entries      int           // channel entries written
	Late         int           // blocks digested by the reconcile walk (arrived after the cursor passed them)
	Through      uint64        // the cursor after the step
	Target       uint64        // the capture cursor the step ran towards
	Open         int           // channels in the frame table that are not complete
	Elapsed      time.Duration // wall time
	BytesRead    int64         // capture bytes read by the step
	StoppedByCap string        // why the step ended before Target: "", "blocks", "time", "budget"
}

// CaptureIndexer is the contract of a chain's indexer: it is driven by the chain's capture loop after each tick (concurrency 1).
type CaptureIndexer interface {
	Chain() uint64
	Family() string
	// Step processes captured blocks above the cursor up to upTo (the capture cursor), bounded by its own block, time and memory
	// limits, and advances the cursor. A step that cannot finish is not an error: the cursor says how far it got.
	Step(ctx context.Context, upTo uint64) (StepReport, error)
	// SelfCheck recomputes sample stored rows from the captured rows and compares bytes; a difference is the named state
	// index_inconsistent{self_check_mismatch}.
	SelfCheck(ctx context.Context, sample int) error
}
