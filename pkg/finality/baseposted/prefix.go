// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"

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

// withoutPrefixOnly returns the pieces that are not only a prefix request's (the pieces of the live range, and those a prefix window shares with a hole).
func withoutPrefixOnly(pieces []finality.GapRange) []finality.GapRange {
	out := make([]finality.GapRange, 0, len(pieces))
	for _, p := range pieces {
		if !isPrefixOnly(p) {
			out = append(out, p)
		}
	}
	return out
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

// Lease is the cross-validator claim on a chunk of prefix blocks; it lives in the finality package (the Arbitrum prefix scan claims too).
type Lease = finality.Lease

const (
	DefaultLeaseSpan  = finality.DefaultLeaseSpan
	DefaultLeaseChunk = finality.DefaultLeaseChunk
	GapClaimPrefix    = finality.GapClaimPrefix
)

// NewLease returns a lease for the chain with a fresh random holder.
func NewLease(store CaptureStore, chain uint64) (*Lease, error) {
	return finality.NewLease(store, chain)
}

// prefixPhase takes blocks of the prefix-only pieces, oldest first, whose windows are live (or, for live=false, dead), claiming each chunk
// before its first block when a Lease is set. A chunk another validator holds for this bucket is skipped (counted); a store that cannot
// take claims ends the phase (counted, logged): no claim, no fetch.
func (b *Backfiller) prefixPhase(ctx context.Context, pieces []finality.GapRange, wins []finality.PrefixWindow, dead []bool, live bool,
	skip, taken map[uint64]bool, max int, pol BackfillPolicy, rep *BackfillReport) {
	chunk := DefaultLeaseChunk
	if b.Lease != nil {
		chunk = b.Lease.ChunkBlocks()
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
