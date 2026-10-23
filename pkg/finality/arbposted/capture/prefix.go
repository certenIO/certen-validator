// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL, Arbitrum: the SequencerInbox batches posted BEFORE the capture loop started. A leg whose L2 block was sequenced
// earlier asks for the L1 window in which its batch can lie (arbposted.Builder, finality.RequestPrefix: a gap row of class capture_prefix
// over L1 blocks); this scan closes those windows. It reads the SequencerBatchDelivered logs of at most Blocks L1 blocks per tick (one
// eth_getLogs answer), captures every event with the SAME captureBatch as the live scan (header, transaction, accumulator consistency,
// the batch record and its calldata as one unit), registers the blobs and the near-head proof of each batch with the live retry machinery
// (bounded per tick), and only then records a scan row for the range (finality.RecordGapScan): a range with an event that could not be
// captured is not marked and is read again. Blocks without an event hold no row to fill under, which is why the range is the unit.

// PrefixScan configures the scan; a nil *PrefixScan on a Capturer means no prefix is scanned.
type PrefixScan struct {
	// Lease is the claim that keeps validators sharing one database from reading the same range (nil: no claims).
	Lease *finality.Lease
	// Blocks is the L1 blocks one scan reads (default 400, the live scan's per-tick bound); the lease chunk is the same size.
	Blocks uint64
	// Now is the clock of the claim period (nil: time.Now).
	Now func() time.Time
}

// DefaultPrefixScanBlocks is the L1 blocks one prefix scan reads.
const DefaultPrefixScanBlocks uint64 = 400

const (
	// PrefixBlobsPerTick and PrefixProofsPerTick bound the retries of the batches a prefix scan registered: a window holds some 800 batches
	// and the live tick must not wait on them.
	PrefixBlobsPerTick  = 6
	PrefixProofsPerTick = 62
)

func (p *PrefixScan) blocks() uint64 {
	if p.Blocks > 0 {
		return p.Blocks
	}
	return DefaultPrefixScanBlocks
}

func (p *PrefixScan) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// maxPrefixClaims bounds the chunks one tick tries to claim before it gives up for the tick.
const maxPrefixClaims = 8

// scanPrefix reads at most one range of the open prefix windows, oldest first.
func (c *Capturer) scanPrefix(ctx context.Context, rep *Report) error {
	p := c.Prefix
	if p == nil {
		return nil
	}
	pieces, err := finality.GapsIn(ctx, c.Store, c.Cfg.Chain, 0, finality.MaxCaptureBlock)
	if err != nil {
		return fmt.Errorf("reading the open prefix windows: %w", err)
	}
	blocks := p.blocks()
	lost := map[uint64]bool{}
	for tries := 0; tries < maxPrefixClaims && ctx.Err() == nil; tries++ {
		a, b, ok := nextPrefixRange(pieces, blocks, lost)
		if !ok {
			return nil
		}
		cs := a - a%blocks
		if p.Lease != nil {
			won, err := p.Lease.Claim(ctx, p.now(), cs)
			if err != nil {
				rep.PrefixLeaseErrors++
				return fmt.Errorf("the claim on L1 blocks %d-%d could not be taken: %w", cs, cs+blocks-1, ethrpc.RedactError(err))
			}
			if !won {
				lost[cs] = true
				rep.PrefixLeaseLost++
				continue
			}
		}
		return c.scanPrefixRange(ctx, a, b, rep)
	}
	return nil
}

// nextPrefixRange is the oldest range [a, b] of open prefix blocks within one claim chunk whose chunk is not lost.
func nextPrefixRange(pieces []finality.GapRange, blocks uint64, lost map[uint64]bool) (a, b uint64, ok bool) {
	for _, pc := range pieces {
		if pc.State != finality.GapOpen || !hasClass(pc, finality.GapCapturePrefix) {
			continue
		}
		for n := pc.From; n <= pc.To; {
			cs := n - n%blocks
			if lost[cs] {
				n = cs + blocks
				continue
			}
			end := cs + blocks - 1
			if end > pc.To {
				end = pc.To
			}
			return n, end, true
		}
	}
	return 0, 0, false
}

func hasClass(p finality.GapRange, c finality.GapClass) bool {
	for _, x := range p.Classes {
		if x == c {
			return true
		}
	}
	return false
}

func (c *Capturer) scanPrefixRange(ctx context.Context, a, b uint64, rep *Report) error {
	logs, err := c.L1.Logs(ctx, c.Cfg.Inbox, TopicBatchDelivered, nil, a, b)
	if err != nil {
		return fmt.Errorf("logs of L1 blocks %d-%d: %w", a, b, ethrpc.RedactError(err))
	}
	sort.Slice(logs, func(i, j int) bool {
		if logs[i].BlockNumber != logs[j].BlockNumber {
			return logs[i].BlockNumber < logs[j].BlockNumber
		}
		return logs[i].LogIndex < logs[j].LogIndex
	})
	var fresh []uint64
	for _, lg := range logs {
		if lg.BlockNumber < a || lg.BlockNumber > b {
			return fmt.Errorf("the provider answered a log of block %d for the range %d-%d; the range is read again", lg.BlockNumber, a, b)
		}
		n, err := c.captureBatch(ctx, lg, rep)
		if err != nil {
			return fmt.Errorf("batch event at block %d: %w", lg.BlockNumber, err)
		}
		if n != nil {
			fresh = append(fresh, *n)
		}
	}
	for _, n := range fresh {
		if pp := c.needProof[n]; pp != nil {
			pp.prefix = true
		}
		if pb := c.needBlobs[n]; pb != nil {
			pb.prefix = true
		}
	}
	if err := finality.RecordGapScan(ctx, c.Store, c.Cfg.Chain, a, b); err != nil {
		return fmt.Errorf("recording the scan of L1 blocks %d-%d: %w", a, b, err)
	}
	rep.PrefixScanned += b - a + 1
	rep.PrefixBatches += len(fresh)
	return nil
}
