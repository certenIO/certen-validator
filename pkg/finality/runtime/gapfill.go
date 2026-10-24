// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/metrics"
)

// Defaults of the gap backfill loop (RB12-CAPTURE-GAP).
const (
	// DefaultGapBlocksPerTick bounds the blocks one backfill tick captures (concurrency is one block at a time).
	DefaultGapBlocksPerTick = 8
	// DefaultGapAuditSpacing is the longest run of blocks without a captured inbox block that is NOT suspected: the production Base table
	// (1,923 inbox blocks over 19,300 blocks, 2026-10-23) has no spacing above 19 outside the three outage holes, so 40 is twice the
	// observed maximum; a quiet run longer than that is scanned again once and closed by fills.
	DefaultGapAuditSpacing = 40
	// DefaultGapAuditEvery is the number of ticks between spacing audits (the first tick audits); at the 12 s interval it is an hour.
	DefaultGapAuditEvery = 300
	// DefaultGapBlockBytes is the working set one backfill tick reserves from the memory budget: a block of transactions, up to nine
	// 128 KiB blobs with their KZG work, and the trie proofs, with room to spare.
	DefaultGapBlockBytes int64 = 16 << 20
	maxGapRangesLogged         = 8
)

// GapBackfillLoop is the capture loop that closes the recorded capture gaps of one chain (finality.Capturer). It audits the capture store
// for runs without a captured block, then fills the open gaps from the normal providers while the data is retained: the same capture
// call as the live loop, one block at a time, throttled to PerTick blocks per tick and to the process memory budget. It records what it
// does as insert-only rows (fills, notes, ends) and names every range it works on in its log.
type GapBackfillLoop struct {
	ChainID      uint64
	Store        finality.CaptureStore
	Backfill     *baseposted.Backfiller
	Every        time.Duration
	PerTick      int
	AuditSpacing uint64
	AuditEvery   int
	Memory       *finality.MemoryBudget
	BlockBytes   int64
	Logf         func(string, ...any)
	Clock        loopClock

	lastSig        string
	lastOpenBlocks uint64
	auditSig       string
	filledTotal    int
}

var _ finality.Capturer = (*GapBackfillLoop)(nil)

// Chain implements finality.Capturer.
func (l *GapBackfillLoop) Chain() uint64 { return l.ChainID }

// Name implements finality.Capturer.
func (l *GapBackfillLoop) Name() string { return "base-sepolia/gapfill" }

func (l *GapBackfillLoop) logf(f string, a ...any) {
	if l.Logf != nil {
		l.Logf(f, a...)
	}
}

func (l *GapBackfillLoop) perTick() int {
	if l.PerTick > 0 {
		return l.PerTick
	}
	return DefaultGapBlocksPerTick
}

func (l *GapBackfillLoop) auditSpacing() uint64 {
	if l.AuditSpacing > 0 {
		return l.AuditSpacing
	}
	return DefaultGapAuditSpacing
}

func (l *GapBackfillLoop) auditEvery() int {
	if l.AuditEvery > 0 {
		return l.AuditEvery
	}
	return DefaultGapAuditEvery
}

func (l *GapBackfillLoop) blockBytes() int64 {
	if l.BlockBytes > 0 {
		return l.BlockBytes
	}
	return DefaultGapBlockBytes
}

// Run implements finality.Capturer: tick, wait Every, until ctx ends.
func (l *GapBackfillLoop) Run(ctx context.Context) error {
	every := l.Every
	if every < finality.MinPoll {
		every = finality.MinPoll
	}
	tick := 0
	for ctx.Err() == nil {
		tick++
		if err := l.Tick(ctx, tick); err != nil && ctx.Err() == nil {
			l.logf("[FINALITY] gap backfill %s: tick %d: %v", l.Name(), tick, ethrpc.RedactError(err))
		}
		if !l.Clock.wait(ctx, every) {
			return nil
		}
	}
	return nil
}

func rangesText(ps []finality.GapRange, state finality.GapState) (string, uint64, int) {
	var parts []string
	var blocks uint64
	n := 0
	for _, p := range ps {
		if p.State != state {
			continue
		}
		n++
		blocks += p.Blocks()
		if len(parts) < maxGapRangesLogged {
			parts = append(parts, p.String())
		}
	}
	text := strings.Join(parts, " ")
	if n > len(parts) {
		text += fmt.Sprintf(" ... (%d more)", n-len(parts))
	}
	return text, blocks, n
}

// Tick audits (on the first tick and every AuditEvery ticks), reports the recorded gaps, and backfills at most PerTick blocks.
func (l *GapBackfillLoop) Tick(ctx context.Context, tick int) error {
	chain := l.ChainID
	if tick == 1 || (tick-1)%l.auditEvery() == 0 {
		l.audit(ctx)
	}
	pieces, err := finality.GapsIn(ctx, l.Store, chain, 0, finality.MaxCaptureBlock)
	if err != nil {
		return fmt.Errorf("reading the recorded capture gaps: %w", err)
	}
	openText, openBlocks, openRanges := rangesText(pieces, finality.GapOpen)
	_, proven, _ := rangesText(pieces, finality.GapUnavailableProven)
	_, expired, _ := rangesText(pieces, finality.GapRetentionExpired)
	metrics.SetFinalityGapBlocks(chain, openBlocks, proven, expired, uint64(openRanges))
	if sig := fmt.Sprintf("%s|%d|%d", openText, proven, expired); sig != l.lastSig {
		l.lastSig = sig
		if openBlocks > 0 || proven > 0 || expired > 0 {
			l.logf("[FINALITY] gap backfill %s: %d open gap blocks in %d ranges %s; %d blocks proven unavailable, %d past retention",
				l.Name(), openBlocks, openRanges, openText, proven, expired)
		}
	}
	if len(pieces) == 0 || l.Backfill == nil {
		l.lastOpenBlocks = openBlocks
		return nil
	}
	release, rerr := l.Memory.Reserve(chain, "gapfill", l.blockBytes())
	if rerr != nil {
		l.logf("[FINALITY] gap backfill %s: this tick is skipped, nothing is lost: %s", l.Name(), rerr.Error())
		return nil
	}
	defer release()
	rep, err := l.Backfill.Step(ctx, l.perTick())
	if err != nil {
		return fmt.Errorf("backfill step: %w", err)
	}
	l.filledTotal += rep.Filled
	metrics.AddFinalityGapBackfilled(chain, rep.Filled)
	for class, n := range rep.FailedByClass {
		for i := 0; i < n; i++ {
			metrics.IncFinalityGapBackfillFailure(chain, class)
		}
	}
	for kind, n := range rep.EndedByKind {
		metrics.AddFinalityGapEnded(chain, kind, n)
	}
	if rep.Attempted > 0 {
		l.logf("[FINALITY] gap backfill %s: attempted %d blocks, captured %d, failed %d (kept open, retried with backoff), ended %d; %d blocks still open",
			l.Name(), rep.Attempted, rep.Filled, rep.Failed, rep.Ended, rep.Open)
	}
	metrics.SetFinalityGapBlocks(chain, rep.Open, rep.UnavailableProven, rep.RetentionExpired, uint64(openRanges))
	if rep.Open == 0 && (l.lastOpenBlocks > 0 || openBlocks > 0) {
		l.logf("[FINALITY] gap backfill %s: every recorded capture gap is closed (%d blocks backfilled by this process; %d proven unavailable, %d past retention remain recorded)",
			l.Name(), l.filledTotal, rep.UnavailableProven, rep.RetentionExpired)
	}
	l.lastOpenBlocks = rep.Open
	return nil
}

// audit records the runs without a captured inbox block as unproven gaps and names them once (and again whenever the set changes).
func (l *GapBackfillLoop) audit(ctx context.Context) {
	found, err := finality.AuditSpacing(ctx, l.Store, l.ChainID, baseposted.ItemInbox, 0, finality.MaxCaptureBlock, l.auditSpacing())
	if err != nil {
		l.logf("[FINALITY] gap backfill %s: spacing audit failed: %v", l.Name(), ethrpc.RedactError(err))
		return
	}
	text, blocks, n := rangesText(found, finality.GapOpen)
	if sig := fmt.Sprintf("%d|%s", blocks, text); sig != l.auditSig && n > 0 {
		l.auditSig = sig
		l.logf("[FINALITY] gap backfill %s: spacing audit: %d ranges (%d blocks) have no captured batch-inbox block for more than %d blocks and are recorded as unproven capture gaps (spacing_unproven): %s",
			l.Name(), n, blocks, l.auditSpacing(), text)
	}
}
