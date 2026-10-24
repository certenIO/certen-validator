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
	// OnFilled, when set, is told the blocks a step captured: the capture index digests them and completes the channels they touch at its
	// next step (finality.LateBlockNoter), instead of waiting for its rotating walk of the table.
	OnFilled func(blocks []uint64)

	lastSig        string
	lastOpenBlocks uint64
	auditSig       string
	prefixSig      string
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
	l.reportPrefix(ctx, pieces)
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
	if l.OnFilled != nil && len(rep.FilledBlocks) > 0 {
		l.OnFilled(rep.FilledBlocks)
	}
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
		l.logf("[FINALITY] gap backfill %s: attempted %d blocks (%d of them prefix blocks), captured %d, failed %d (kept open, retried with backoff), ended %d; %d blocks still open",
			l.Name(), rep.Attempted, rep.PrefixAttempted, rep.Filled, rep.Failed, rep.Ended, rep.Open)
	}
	metrics.AddFinalityPrefixBackfilled(chain, rep.PrefixFilled)
	metrics.AddFinalityPrefixLease(chain, "lost", rep.LeaseLost)
	metrics.AddFinalityPrefixLease(chain, "error", rep.LeaseErrors)
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
	// The audit covers the region the capture loop scanned (from its first cursor row on). Captured prefix blocks lie below it, in windows that
	// were asked for, with the unrequested stretches between them: a run between two of those is not a hole, so the audit never reaches below
	// the loop's own start (RB12-ARCHIVE-BACKFILL).
	lo := uint64(0)
	if cov, known, cerr := finality.CaptureCoverageOf(ctx, l.Store, l.ChainID); cerr != nil {
		l.logf("[FINALITY] gap backfill %s: spacing audit skipped, the capture coverage cannot be read: %v", l.Name(), ethrpc.RedactError(cerr))
		return
	} else if known {
		lo = cov.First
	}
	found, err := finality.AuditSpacing(ctx, l.Store, l.ChainID, baseposted.ItemInbox, lo, finality.MaxCaptureBlock, l.auditSpacing())
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

// reportPrefix sets the prefix gauges from the requested windows and the unfilled pieces (every tick, so the gauges are live from the
// first one) and names, once per change, the windows that cannot be completed without a blob archive.
func (l *GapBackfillLoop) reportPrefix(ctx context.Context, pieces []finality.GapRange) {
	metrics.AddFinalityPrefixBackfilled(l.ChainID, 0) // the counters exist from the first tick
	metrics.AddFinalityPrefixLease(l.ChainID, "lost", 0)
	metrics.AddFinalityPrefixLease(l.ChainID, "error", 0)
	wins, err := finality.PrefixWindowsOf(ctx, l.Store, l.ChainID)
	if err != nil {
		l.logf("[FINALITY] gap backfill %s: the prefix windows could not be read: %v", l.Name(), ethrpc.RedactError(err))
		return
	}
	st := baseposted.PrefixWindowStates(wins, pieces)
	metrics.SetFinalityPrefixWindows(l.ChainID, st[baseposted.PrefixWindowComplete], st[baseposted.PrefixWindowOpen],
		st[baseposted.PrefixWindowUnavailableProven], st[baseposted.PrefixWindowRetentionExpired], finality.PrefixBlocks(finality.MergePrefixWindows(wins)))
	sig := fmt.Sprintf("%d|%d|%d|%d", st[baseposted.PrefixWindowComplete], st[baseposted.PrefixWindowOpen],
		st[baseposted.PrefixWindowUnavailableProven], st[baseposted.PrefixWindowRetentionExpired])
	if sig == l.prefixSig {
		return
	}
	l.prefixSig = sig
	if len(wins) == 0 {
		return
	}
	l.logf("[FINALITY] gap backfill %s: %d prefix windows requested (%d blocks): %d complete, %d being captured, %d cannot be completed from these providers (blobs proven unavailable: a blob archive, OD4, would close them), %d past retention",
		l.Name(), len(wins), finality.PrefixBlocks(finality.MergePrefixWindows(wins)), st[baseposted.PrefixWindowComplete], st[baseposted.PrefixWindowOpen],
		st[baseposted.PrefixWindowUnavailableProven], st[baseposted.PrefixWindowRetentionExpired])
}
