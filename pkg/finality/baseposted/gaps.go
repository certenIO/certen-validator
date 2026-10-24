// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-CAPTURE-GAP: what a capture failure is called, and the one capture call both the live loop and the backfill make.

// CodeCaptureGap is the named state of a leg whose sequencer window holds blocks the capture loop has not captured (a recorded gap):
// the channel that carries the leg's batch is not among the captured rows and may lie in the gap, so "not posted yet" cannot be said.
// It is the hole-aware counterpart of CodeCaptureNotCovering, which stays the state of a leg posted before the capture existed.
const CodeCaptureGap = "l1_capture_gap"

// CodeCaptureRowConflict is the named state of a capture whose row already exists with other bytes. A capture row is insert-only, and a
// backfill or a second validator may write a row only when it is byte-identical to the stored one.
const CodeCaptureRowConflict = "capture_row_conflict"

// BlockFetchError: the L1 block (its header and transactions) could not be read from any provider.
type BlockFetchError struct {
	Block uint64
	Err   error
}

func (e *BlockFetchError) Error() string {
	return fmt.Sprintf("baseposted: L1 block %d could not be read: %v", e.Block, e.Err)
}

func (e *BlockFetchError) Unwrap() error { return e.Err }

// BlobsGone reports whether err is the evidence that every beacon endpoint pruned the blobs (a StatusError with Gone set).
func BlobsGone(err error) (*StatusError, bool) {
	var se *StatusError
	if errors.As(err, &se) && se.Gone {
		return se, true
	}
	return nil, false
}

// CaptureFailure is a capture that failed with a named state (batcher_state_unavailable, l1_blob_unavailable, capture_row_conflict).
type CaptureFailure struct {
	Block uint64
	State *finality.StateError
	Err   error
}

func (e *CaptureFailure) Error() string {
	if e.State != nil {
		return fmt.Sprintf("%s: %v", e.State.Error(), e.Err)
	}
	return e.Err.Error()
}

func (e *CaptureFailure) Unwrap() error { return e.Err }

// ClassOfFailure is the gap class of a failed capture.
func ClassOfFailure(err error) finality.GapClass {
	var cf *CaptureFailure
	if errors.As(err, &cf) && cf.State != nil {
		switch cf.State.Code {
		case "batcher_state_unavailable":
			return finality.GapStateProofUnavailable
		case "l1_blob_unavailable":
			return finality.GapBlobUnavailable
		}
		return finality.GapCaptureFailed
	}
	var bf *BlockFetchError
	if errors.As(err, &bf) {
		return finality.GapBlockUnavailable
	}
	return finality.GapCaptureFailed
}

// BlockCapturer is what a gap backfill needs of a capturer: capture one L1 block (the same code as the live capture) and say which block
// hash it read and whether the block held batch-inbox transactions. A failure is a *CaptureFailure when it has a named state.
type BlockCapturer interface {
	CaptureBlockHash(ctx context.Context, n uint64) (hash [32]byte, hasInbox bool, err error)
}

// CapturerOf adapts a Capturer to BlockCapturer. The capture is the Capturer's own CaptureBlock on a COPY (so the wrapped capturer's
// Record hook and the live loop that owns it are undisturbed and the two can run concurrently); only the block read is observed.
func CapturerOf(c *Capturer) BlockCapturer { return capturerAdapter{c} }

type capturerAdapter struct{ c *Capturer }

type hashingL1 struct {
	L1Source
	mu   sync.Mutex
	hash map[uint64][32]byte
}

func (h *hashingL1) Block(ctx context.Context, n uint64) (L1BlockData, error) {
	b, err := h.L1Source.Block(ctx, n)
	if err == nil {
		h.mu.Lock()
		h.hash[n] = b.Hash
		h.mu.Unlock()
	}
	return b, err
}

func (a capturerAdapter) CaptureBlockHash(ctx context.Context, n uint64) ([32]byte, bool, error) {
	cc := *a.c
	var st *finality.StateError
	cc.Record = func(_ uint64, s *finality.StateError) { st = s }
	hl := &hashingL1{L1Source: cc.L1, hash: map[uint64][32]byte{}}
	cc.L1 = hl
	ok, err := cc.CaptureBlock(ctx, n)
	hl.mu.Lock()
	hash := hl.hash[n]
	hl.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrCaptureConflict) {
			st = finality.NewState(CodeCaptureRowConflict, "chain", cc.Chain, "l1_block", n)
		}
		if st != nil {
			return hash, false, &CaptureFailure{Block: n, State: st, Err: err}
		}
		return hash, false, err
	}
	return hash, ok, nil
}

// CaptureBlockHashOf is CapturerOf(c).CaptureBlockHash, for a caller that holds the Capturer only.
func CaptureBlockHashOf(ctx context.Context, c *Capturer, n uint64) ([32]byte, bool, error) {
	return capturerAdapter{c}.CaptureBlockHash(ctx, n)
}

// gapState is the named state of a leg whose window [origin, end] holds gap blocks, or nil when it holds none. The state names the part
// of the gap INSIDE the window and the most urgent state among its pieces: an open block outranks a proved-unavailable one, which
// outranks an expired one (the backfill is still working where it is open).
func gapState(pieces []finality.GapRange, origin, end uint64, archive bool) *finality.StateError {
	if len(pieces) == 0 {
		return nil
	}
	rank := map[finality.GapState]int{finality.GapOpen: 3, finality.GapUnavailableProven: 2, finality.GapRetentionExpired: 1}
	best := pieces[0].State
	for _, p := range pieces {
		if rank[p.State] > rank[best] {
			best = p.State
		}
	}
	var first *finality.GapRange
	var ranges, blocks uint64
	for i := range pieces {
		if pieces[i].State != best {
			continue
		}
		if first == nil {
			first = &pieces[i]
		}
		ranges++
		blocks += pieces[i].Blocks()
	}
	arch := "unset"
	if archive {
		arch = "set"
	}
	return finality.NewState(CodeCaptureGap, "chain", uint64(Chain), "kind", KindName, "from", first.From, "to", first.To, "gap_state", string(best),
		"ranges", ranges, "blocks", blocks, "epoch_l1_block", origin, "window_end_l1_block", end, "archive_provider", arch)
}
