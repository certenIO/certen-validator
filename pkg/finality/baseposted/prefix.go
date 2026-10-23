// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL: the parts of the Backfiller that serve the capture-store PREFIX (finality/prefix.go): which open block to take
// next, and the claim that keeps seven validators sharing one database from fetching the same blocks.
//
// ORDER. A block of a prefix window can be captured only while its blobs are served, and every provider prunes the OLDEST blobs first, so
// each block has a deadline and the deadline of the oldest block comes first: the oldest-first order saves, at every moment, the data
// that is lost soonest (earliest deadline first, optimal for the number of blocks saved before their deadlines). A leg is covered only
// when ALL blocks of its window are, so one more rule: a window that already holds a block the providers have PROVED unavailable
// (unavailable_proven or retention_expired, awaiting an archive) cannot complete from these providers, and capturing its other blocks
// before the windows that still can complete would spend the budget on legs that stay unserved. The order is therefore
//
//  1. blocks of windows with no proven-unavailable block, oldest first;
//  2. the holes of the live range (the CAPTURE-GAP framework, unchanged: random pick);
//  3. blocks of windows that hold a proven-unavailable block, oldest first (kept, so a later archive finds the rest already captured).

// isPrefixOnly: the piece is open only because of prefix requests (a piece that a hole also covers is a hole).
func isPrefixOnly(p finality.GapRange) bool {
	return len(p.Classes) == 1 && p.Classes[0] == finality.GapCapturePrefix
}

// deadWindows marks each window that holds a block in a terminal state (an end row and no fill).
func deadWindows(pieces []finality.GapRange, wins []finality.PrefixWindow) []bool {
	dead := make([]bool, len(wins))
	for _, p := range pieces {
		if p.State == finality.GapOpen {
			continue
		}
		for i, w := range wins {
			if p.From <= w.To && p.To >= w.From {
				dead[i] = true
			}
		}
	}
	return dead
}

// blockLive: the block lies in at least one window that can still complete.
func blockLive(n uint64, wins []finality.PrefixWindow, dead []bool) bool {
	for i, w := range wins {
		if n >= w.From && n <= w.To && !dead[i] {
			return true
		}
	}
	return false
}

// nextPrefixBlock is the lowest open block of the prefix-only pieces (ascending) that skipped does not exclude and whose liveness is live.
func nextPrefixBlock(pieces []finality.GapRange, wins []finality.PrefixWindow, dead []bool, live bool, skipped func(uint64) bool) (uint64, bool) {
	for _, p := range pieces {
		if p.State != finality.GapOpen || !isPrefixOnly(p) {
			continue
		}
		for n := p.From; n <= p.To; n++ {
			if skipped(n) || blockLive(n, wins, dead) != live {
				continue
			}
			return n, true
		}
	}
	return 0, false
}

// claimState is what one Step knows of its claims: the chunks another validator holds, the chunks it holds itself, and whether the store
// could not take a claim (the prefix phases of the step then do nothing).
type claimState struct {
	lost, held map[uint64]bool
	failed     bool
}

// Lease is the cross-validator claim on a chunk of prefix blocks. A claim is one insert-only row whose KEY holds the chunk and the time
// bucket and whose BYTES hold the claimant: the first writer of a (chunk, bucket) wins, any other claimant meets the store's own
// "same key, other bytes" refusal (ErrCaptureConflict) and has lost; the holder claiming again is a no-op. Nothing is updated or deleted
// and nothing needs releasing: a claim ends with its bucket, so a validator that dies holding one blocks its chunk for one bucket.
type Lease struct {
	Store  CaptureStore
	Chain  uint64
	Holder [16]byte      // unique to the process (NewLease draws it at random)
	Span   time.Duration // the bucket: how long a claim lasts (default 10 minutes)
	Chunk  uint64        // blocks per claim, aligned at multiples of Chunk (default 8)
}

const (
	// DefaultLeaseSpan is how long a chunk stays claimed: long enough for a validator to work through a chunk at the gap-fill pace, short
	// enough that a chunk whose holder is gone is retaken within one backoff.
	DefaultLeaseSpan = 10 * time.Minute
	// DefaultLeaseChunk is the claim granularity; it equals the default blocks per backfill tick.
	DefaultLeaseChunk uint64 = 8
	leaseMagic               = "CGCL1"
	// GapClaimPrefix is the item prefix of the claim rows; it is not one of the gap bookkeeping prefixes, so no gap reader sees a claim.
	GapClaimPrefix = "gapclaim/"
)

// NewLease returns a lease for the chain with a fresh random holder.
func NewLease(store CaptureStore, chain uint64) (*Lease, error) {
	l := &Lease{Store: store, Chain: chain}
	if _, err := rand.Read(l.Holder[:]); err != nil {
		return nil, fmt.Errorf("baseposted: drawing a claim holder: %w", err)
	}
	return l, nil
}

func (l *Lease) span() time.Duration {
	if l.Span >= time.Second {
		return l.Span
	}
	return DefaultLeaseSpan
}

func (l *Lease) chunk() uint64 {
	if l.Chunk > 0 {
		return l.Chunk
	}
	return DefaultLeaseChunk
}

// ChunkStart is the first block of the chunk n belongs to.
func (l *Lease) ChunkStart(n uint64) uint64 { return n - n%l.chunk() }

// Claim tries to take the chunk starting at chunkStart for the time bucket of now. won is false (and err nil) when another holder owns it
// for this bucket; err is a store failure.
func (l *Lease) Claim(ctx context.Context, now time.Time, chunkStart uint64) (won bool, err error) {
	if l.Store == nil {
		return false, errors.New("baseposted: a lease needs a store")
	}
	bucket := uint64(now.Unix()) / uint64(l.span()/time.Second)
	h := sha256.New()
	h.Write([]byte("certen:gapclaim:v1"))
	var be [8]byte
	binary.BigEndian.PutUint64(be[:], bucket)
	h.Write(be[:])
	var key [32]byte
	copy(key[:], h.Sum(nil))
	k := CaptureKey{Chain: l.Chain, L1Block: chunkStart, L1Hash: key, Item: fmt.Sprintf("%s%d", GapClaimPrefix, chunkStart)}
	err = l.Store.Put(ctx, k, append([]byte(leaseMagic), l.Holder[:]...))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, finality.ErrCaptureConflict):
		return false, nil
	}
	return false, err
}

// prefixPhase takes blocks of the prefix-only pieces, oldest first, whose windows are live (or, for live=false, dead), claiming each chunk
// before its first block when a Lease is set. A chunk another validator holds for this bucket is skipped (counted); a store that cannot
// take claims ends the phase (counted, logged): no claim, no fetch.
func (b *Backfiller) prefixPhase(ctx context.Context, pieces []finality.GapRange, wins []finality.PrefixWindow, dead []bool, live bool,
	skip, taken map[uint64]bool, max int, pol BackfillPolicy, rep *BackfillReport) {
	chunk := DefaultLeaseChunk
	if b.Lease != nil {
		chunk = b.Lease.chunk()
	}
	if b.claims.failed {
		return // the store could not take a claim earlier in this step: no claim, no fetch
	}
	lost, held := b.claims.lost, b.claims.held
	skipped := func(n uint64) bool { return skip[n] || taken[n] || lost[n-n%chunk] }
	for rep.Attempted < max && ctx.Err() == nil {
		n, ok := nextPrefixBlock(pieces, wins, dead, live, skipped)
		if !ok {
			return
		}
		cs := n - n%chunk
		if b.Lease != nil && !held[cs] {
			won, err := b.Lease.Claim(ctx, b.now(), cs)
			if err != nil {
				rep.LeaseErrors++
				b.claims.failed = true
				b.logf("[FINALITY] gap backfill chain %d: the claim on prefix blocks %d-%d could not be taken (%v): no prefix block is fetched this step", b.Chain, cs, cs+chunk-1, ethrpc.RedactError(err))
				return
			}
			if !won {
				lost[cs] = true
				rep.LeaseLost++
				continue
			}
			held[cs] = true
		}
		taken[n] = true
		if fills, err := b.Store.ListByRange(ctx, b.Chain, n, n, finality.GapFillPrefix); err == nil && len(fills) > 0 {
			rep.Skipped++ // another validator closed it since the listing
			continue
		}
		rep.Attempted++
		rep.PrefixAttempted++
		before := rep.Filled
		b.attempt(ctx, n, pol, rep)
		rep.PrefixFilled += rep.Filled - before
	}
}
