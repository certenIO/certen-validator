// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12 OPS-A2 F18: a fork-aware builder. The capture store is keyed (chain, l1_block, l1_hash, item), so a height that was reorged holds the
// rows of BOTH twins. A channel whose frame sits in a twin block gets that frame twice (or only from the orphan), which no reader could
// assemble and the finalized-chain check of Build refuses, although the canonical twin's frames are captured and the channel is provable.
// Where the window holds a twin height the builder keeps only the rows of the block the L1 provider names at that height, for the window reader
// and the index path alike (the window reader serves such a window: the index digests stay per hash and are not rewritten). The provider is
// untrusted; its answer only selects among rows already captured, and Build's spine check from the finalized head remains the authority, so a
// wrong answer can only make a build fail.

// twinHeights returns the heights of [from, to] at which the capture holds the header of more than one block. The listing is key-only and
// costs the header rows of the window.
func (b *Builder) twinHeights(ctx context.Context, from, to uint64) (map[uint64]bool, error) {
	ks, err := b.Store.ListByRange(ctx, uint64(Chain), from, to, ItemHeader)
	if err != nil {
		return nil, err
	}
	seen := map[uint64]map[[32]byte]bool{}
	for _, k := range ks {
		if seen[k.L1Block] == nil {
			seen[k.L1Block] = map[[32]byte]bool{}
		}
		seen[k.L1Block][k.L1Hash] = true
	}
	var out map[uint64]bool
	for h, hs := range seen {
		if len(hs) > 1 {
			if out == nil {
				out = map[uint64]bool{}
			}
			out[h] = true
		}
	}
	return out, nil
}

// dropOrphans removes, at every twin height, the rows of the blocks the provider does not name there. Without a provider (or without twins)
// the rows are returned as they are.
func (b *Builder) dropOrphans(ctx context.Context, txs []capturedTx, twins map[uint64]bool) ([]capturedTx, error) {
	if len(twins) == 0 || b.L1 == nil {
		return txs, nil
	}
	canon := map[uint64][32]byte{}
	out := make([]capturedTx, 0, len(txs))
	dropped := 0
	for _, t := range txs {
		if !twins[t.key.L1Block] {
			out = append(out, t)
			continue
		}
		h, ok := canon[t.key.L1Block]
		if !ok {
			blk, err := b.L1.Block(ctx, t.key.L1Block)
			if err != nil {
				return nil, st("finality_source_unavailable", "reason", "l1_header", "endpoints", "headers")
			}
			h = blk.Hash
			canon[t.key.L1Block] = h
		}
		if t.key.L1Hash != h {
			dropped++
			continue
		}
		out = append(out, t)
	}
	if dropped > 0 {
		metrics.AddFinalityCaptureOrphanRowsIgnored(uint64(Chain), dropped)
	}
	return out, nil
}

// markOrphanFrames records, for every frame of the channel that sits in a block the FINALIZED chain does not hold at its height (byNumber is the
// spine Build verified from the finalized head: it is the authority, not the provider), the orphan mark of that block, so that a gap fill of it
// stops closing the height and the backfill fills the canonical block (RB12 OPS-A2 F18). Best effort: a failing store changes no answer.
func (b *Builder) markOrphanFrames(ctx context.Context, frames []capturedTx, byNumber map[uint64][32]byte) {
	for _, f := range frames {
		if h, on := byNumber[f.key.L1Block]; on && h != f.key.L1Hash {
			_ = finality.RecordGapOrphan(ctx, b.Store, uint64(Chain), f.key.L1Block, f.key.L1Hash)
		}
	}
}
