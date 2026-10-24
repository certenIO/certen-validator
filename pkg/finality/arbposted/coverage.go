// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// RB12-ARCHIVE-BACKFILL, Arbitrum: a leg whose batch was posted before the capture started used to be "awaiting_batch_post" for ever. Its
// batch lies in an L1 window the leg's own header gives: the L2 header carries, in its mixHash, the L1 block number the sequencer saw
// (bytes 8..16: sendCount, l1BlockNumber, arbOSVersion), and the SequencerInbox accepts a batch only within its time bounds of that number:
// a message with L1 block number m is in a batch posted at an L1 block in [m - futureBlocks, m + delayBlocks]. The header is authenticated
// by the hash of the leg's block reference, so the window is derived from nothing a provider said.

const (
	// MaxDelayBlocks and MaxFutureBlocks are SequencerInbox.maxTimeVariation().delayBlocks and futureBlocks of the pinned Arbitrum Sepolia
	// deployment (0x6c97...be0D), read with eth_call on 2026-10-23: 7200 and 64 (delaySeconds 5400 and futureSeconds 768 are not used).
	MaxDelayBlocks  uint64 = 7200
	MaxFutureBlocks uint64 = 64
	// coverageSlack is how many blocks before its first cursor row the capture may have started scanning (its start-back is 32).
	coverageSlack uint64 = 64
	// windowCompleteMargin is how far behind the capture cursor the end of a window must lie before it is called complete.
	windowCompleteMargin uint64 = 96
	// CodeWindowNoChannel is the state of a leg whose complete window holds no batch with its block (the same code as Base).
	CodeWindowNoChannel = "l1_posted_not_found"
	// CodeCaptureNotCovering and CodeCaptureGap are the Base codes: the same facts about the same kind of store.
	CodeCaptureNotCovering = "l1_capture_not_covering"
	CodeCaptureGap         = "l1_capture_gap"
)

// l1BlockNumberOf reads the L1 block number from the mixHash (header item 13) of a raw Arbitrum L2 header.
func l1BlockNumberOf(raw []byte) (uint64, bool) {
	var items []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &items); err != nil || len(items) < 14 {
		return 0, false
	}
	var mix []byte
	if err := rlp.DecodeBytes(items[13], &mix); err != nil || len(mix) != 32 {
		return 0, false
	}
	var n uint64
	for _, x := range mix[8:16] {
		n = n<<8 | uint64(x)
	}
	return n, true
}

// coverage judges a leg whose batch is not among the captured batches: it returns the named state when the window in which the batch can lie
// predates the capture (not requested, or requested and not yet scanned), holds an unfilled block, or was scanned completely without it; nil
// means the batch may simply not be posted yet.
func (b *Builder) coverage(ctx context.Context, ref finality.BlockRef, hdr finality.HeaderFields, txs [][]byte) (*finality.StateError, error) {
	hasStd := false
	for _, tx := range txs {
		if ethproof.TxType(tx) <= 4 {
			hasStd = true
			break
		}
	}
	if !hasStd || hdr.Hash != ref.Hash {
		return nil, nil // such a block has no batch message to look for; a header that is not the reference's is not read
	}
	l1, ok := l1BlockNumberOf(ref.HeaderRLP)
	if !ok {
		return nil, nil
	}
	start := uint64(0)
	if l1 > MaxFutureBlocks {
		start = l1 - MaxFutureBlocks
	}
	end := l1 + MaxDelayBlocks
	first, last, known, err := finality.BlockBoundsOf(ctx, b.Store, b.Chain(), capture.ItemCursor)
	if err != nil {
		return nil, err
	}
	if !known {
		return nil, nil // a store without a cursor says nothing about what it covers
	}
	slack := b.CursorSlack
	if slack == 0 {
		slack = coverageSlack
	}
	var lower uint64
	if first > slack {
		lower = first - slack
	}
	if start < lower {
		below := end
		if below >= lower {
			below = lower - 1
		}
		ws, err := finality.PrefixWindowsOf(ctx, b.Store, b.Chain())
		if err != nil {
			return nil, err
		}
		merged := finality.MergePrefixWindows(ws)
		if ok, _ := finality.PrefixCovers(merged, start, below); !ok {
			verdict := finality.PrefixOff
			if b.Prefix.Enabled() {
				if verdict, err = finality.RequestPrefix(ctx, b.Store, b.Chain(), start, below, b.Prefix); err != nil {
					return nil, err
				}
			}
			if verdict != finality.PrefixRecorded && verdict != finality.PrefixKnown {
				lowest, _ := finality.PrefixLowest(merged)
				return finality.NewState(CodeCaptureNotCovering, "chain", b.Chain(), "kind", KindName, "epoch_l1_block", start, "window_end_l1_block", end,
					"capture_first_l1_block", first, "capture_slack", slack, "archive_provider", "n/a", "prefix_state", string(verdict),
					"prefix_lowest_l1_block", lowest, "prefix_blocks", finality.PrefixBlocks(merged)), nil
			}
		}
	}
	pieces, err := finality.GapsIn(ctx, b.Store, b.Chain(), start, end)
	if err != nil {
		return nil, err
	}
	if gs := gapState(pieces, start, end); gs != nil {
		return gs, nil
	}
	if last >= windowCompleteMargin && end <= last-windowCompleteMargin {
		return finality.NewState(CodeWindowNoChannel, "chain", b.Chain(), "kind", KindName, "from", start, "to", end, "covered_to", last), nil
	}
	return nil, nil
}

// gapState is the l1_capture_gap of the window: the most urgent state among the unfilled pieces inside it (open outranks the terminal ones).
func gapState(pieces []finality.GapRange, origin, end uint64) *finality.StateError {
	return finality.CaptureGapState(finality.ChainArbitrumSepolia, KindName, pieces, origin, end, "n/a") // the one builder, shared with Base
}
