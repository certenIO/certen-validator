// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
	"github.com/certen/independant-validator/pkg/metrics"
)

// loopClock is the clock and the wait of a capture loop (tests script them: a loop never spins, it waits Every between ticks).
type loopClock struct {
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
}

func (c loopClock) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c loopClock) wait(ctx context.Context, d time.Duration) bool {
	after := c.After
	if after == nil {
		after = time.After
	}
	select {
	case <-ctx.Done():
		return false
	case <-after(d):
		return true
	}
}

// statusSink records a capture loop's named unavailability state in the status table under the chain's pseudo proof id
// (CaptureStatusProofID) and counts it. A status that cannot be written is logged and never stops the loop.
type statusSink struct {
	store finality.BuilderStatusStore
	logf  func(string, ...any)
	now   func() time.Time
	pins  *finality.Pins // the pins the builder runs under: every row records their hash (nil = nothing recorded)
}

func (s statusSink) put(ctx context.Context, chain uint64, target finality.Level, st *finality.StateError) {
	metrics.IncFinalityStatus(chain, target.String(), st.Code)
	if s.store == nil {
		return
	}
	at := time.Now()
	if s.now != nil {
		at = s.now()
	}
	row := finality.BuilderStatusOf(CaptureStatusProofID(chain), chain, target, finality.LevelNone, nil, st, false, at).WithPins(s.pins)
	if err := s.store.UpsertStatus(ctx, row); err != nil && ctx.Err() == nil {
		metrics.IncFinalityStatusWriteFailure(chain)
		s.logf("[FINALITY] capture status of chain %d (%s) was not written: %v", chain, st.Code, ethrpc.RedactError(err))
	}
}

// cursorItem is the capture row that remembers how far a loop has scanned. It is keyed at the scanned block under the zero hash
// (a cursor is about no particular block hash) and is insert-only like every capture row.
const cursorItem = finality.CaptureCursorItem

func readCursor(ctx context.Context, store finality.CaptureStore, chain uint64) (uint64, bool, error) {
	keys, err := store.ListByRange(ctx, chain, 0, finality.MaxCaptureBlock, cursorItem)
	if err != nil {
		return 0, false, err
	}
	var best uint64
	found := false
	for _, k := range keys {
		if k.Item == cursorItem && (!found || k.L1Block > best) {
			best, found = k.L1Block, true
		}
	}
	return best, found, nil
}

func writeCursor(ctx context.Context, store finality.CaptureStore, chain, block uint64) error {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], block)
	return store.Put(ctx, finality.CaptureKey{Chain: chain, L1Block: block, Item: cursorItem}, v[:])
}

// BasePostedLoop follows the Sepolia head and captures, for every L1 block that holds a Base batch-inbox transaction, the frame
// transaction with its trie proof, its blobs with commitments and proofs, and the SystemConfig proofs at that block (V2_SPEC_S7
// 2.8, leg-independent, not delayed by any eta). A block whose proofs or blobs cannot be had is a named state in the status table
// (batcher_state_unavailable, l1_blob_unavailable); it is retried while the block is inside a provider's window (ProofWindow)
// or for as long as an archive provider is configured, then handed to the gap backfill (GapBackfillLoop) as an open, durably recorded
// capture gap; the leg keeps the level it has and a leg judged inside the gap is told so by name (l1_capture_gap). It implements
// finality.Capturer.
type BasePostedLoop struct {
	Cap          *baseposted.Capturer
	Store        finality.CaptureStore
	Status       finality.BuilderStatusStore
	Pins         *finality.Pins // the pins the loop's status rows record the hash of
	Every        time.Duration
	MaxPerTick   int
	StartBack    uint64
	ProofWindow  uint64 // L1 blocks a block stays retryable without an archive provider (default 96)
	HasArchive   bool
	MaxRetryAge  uint64 // with an archive provider: blocks after which a retry is given up (default 20000)
	Logf         func(string, ...any)
	Clock        loopClock
	retry        map[uint64]*retryEntry
	gapRecorded  map[uint64]bool
	mu           sync.Mutex
	lastState    map[uint64]*finality.StateError
	capturedHead uint64
	cursor       uint64
	cursorHave   bool
	cursorKnown  bool
	// Index, when set, is stepped after every tick (RB12-INDEX-A): it digests the blocks the capture has stored and indexes the channels
	// they complete. Memory is the per-process budget its working set is reserved against.
	Index  finality.CaptureIndexer
	Memory *finality.MemoryBudget
}

type retryEntry struct {
	attempts int
	nextTick int
}

var _ finality.Capturer = (*BasePostedLoop)(nil)

// Chain implements finality.Capturer.
func (l *BasePostedLoop) Chain() uint64 { return finality.ChainBaseSepolia }

// Name implements finality.Capturer.
func (l *BasePostedLoop) Name() string { return "base-sepolia/inbox" }

func (l *BasePostedLoop) window() uint64 {
	if l.ProofWindow > 0 {
		return l.ProofWindow
	}
	return 96
}

func (l *BasePostedLoop) maxAge() uint64 {
	if l.MaxRetryAge > 0 {
		return l.MaxRetryAge
	}
	return 20000
}

func (l *BasePostedLoop) perTick() int {
	if l.MaxPerTick > 0 {
		return l.MaxPerTick
	}
	return 64
}

// init allocates the retry bookkeeping; Tick is exported and may be called without Run.
func (l *BasePostedLoop) init() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.retry == nil {
		l.retry, l.lastState = map[uint64]*retryEntry{}, map[uint64]*finality.StateError{}
	}
	if l.gapRecorded == nil {
		l.gapRecorded = map[uint64]bool{}
	}
}

// Run implements finality.Capturer: tick, wait Every, until ctx ends.
func (l *BasePostedLoop) Run(ctx context.Context) error {
	l.init()
	every := l.Every
	if every < finality.MinPoll {
		every = finality.MinPoll
	}
	tick := 0
	for ctx.Err() == nil {
		tick++
		if err := l.Tick(ctx, tick); err != nil && ctx.Err() == nil {
			l.Logf("[FINALITY] capturer %s: tick %d: %v", l.Name(), tick, ethrpc.RedactError(err))
		}
		if !l.Clock.wait(ctx, every) {
			return nil
		}
	}
	return nil
}

// Tick makes one capture round: it scans the blocks from the cursor to the head (at most MaxPerTick), then retries the blocks
// whose capture failed. It returns an error only for a failure to follow the head at all (no head, no cursor store) or to record
// what it could not capture: the cursor never passes a block that was neither captured nor durably recorded as a gap (RB12-F13).
func (l *BasePostedLoop) Tick(ctx context.Context, tick int) error {
	l.init()
	chain := l.Chain()
	sink := statusSink{store: l.Status, logf: l.Logf, now: l.Clock.Now, pins: l.Pins}
	head, err := l.Cap.L1.Head(ctx)
	if err != nil {
		return fmt.Errorf("the Sepolia head is unavailable: %w", err)
	}
	// the cursor rows are read once per process (they accumulate, one per tick) and then held in memory
	l.mu.Lock()
	cur, have, known := l.cursor, l.cursorHave, l.cursorKnown
	l.mu.Unlock()
	if !known {
		if cur, have, err = readCursor(ctx, l.Store, chain); err != nil {
			return fmt.Errorf("reading the capture cursor: %w", err)
		}
	}
	from := head
	switch {
	case have:
		from = cur + 1
	case head > l.StartBack:
		from = head - l.StartBack
	default:
		from = 0
	}
	// A cursor further behind the head than the provider window (the validator was down, or stalled) is not crawled block by block
	// through blocks no near-head provider can prove: the missed range is recorded as ONE capture gap for the gap backfill (which asks
	// the archive provider, throttled, and keeps retrying), and the scan resumes at the window. Nothing is skipped silently.
	if have && head > l.window() {
		if boundary := head - l.window(); from < boundary {
			if err := finality.RecordGap(ctx, l.Store, chain, from, boundary-1, finality.GapOutageUnscanned); err != nil {
				return fmt.Errorf("recording the capture gap %d-%d: %w", from, boundary-1, err)
			}
			metrics.IncFinalityGapRecorded(chain, string(finality.GapOutageUnscanned))
			l.Logf("[FINALITY] capturer %s: the cursor %d is %d blocks behind the head %d (provider window %d): L1 blocks %d-%d are recorded as capture gap (outage_unscanned) for the gap backfill; scanning resumes at %d",
				l.Name(), cur, head-cur, head, l.window(), from, boundary-1, boundary)
			from = boundary
		}
	}
	if from > head {
		metrics.SetFinalityCaptureLag(chain, l.Name(), 0)
		l.runIndex(ctx, sink, cur)
		return nil
	}
	to := head
	if n := uint64(l.perTick()); to-from+1 > n {
		to = from + n - 1
	}
	var states = map[uint64]*finality.StateError{}
	l.Cap.Record = func(block uint64, s *finality.StateError) { states[block] = s }
	captured, errs := l.Cap.CaptureRange(ctx, from, to)
	for _, b := range captured {
		l.Logf("[FINALITY] capturer %s: captured L1 block %d", l.Name(), b)
	}
	// the cursor passes a block only when it was tried: a stop (the process is told to end) in the middle of the round leaves it behind
	// the blocks that were never read, and a failed block is recorded as a durable gap BEFORE the cursor moves
	safeTo := to
	var recordErr error
	l.mu.Lock()
	for n := from; n <= to; n++ {
		e, failed := errs[n]
		if !failed {
			continue
		}
		if ctx.Err() != nil {
			safeTo = n - 1
			break
		}
		st := states[n]
		if st == nil {
			// a failure that is not a registered unavailability (a provider error, an inconsistent answer): its cause is logged
			// redacted and the block is retried; nothing is recorded as a state the registry does not name
			l.Logf("[FINALITY] capturer %s: L1 block %d not captured: %v", l.Name(), n, ethrpc.RedactError(e))
		}
		if gerr := l.recordGap(ctx, n, st, e); gerr != nil && recordErr == nil {
			recordErr = gerr
		}
		l.retry[n] = &retryEntry{nextTick: tick + 1}
		if st != nil {
			l.lastState[n] = st
			sink.put(ctx, chain, finality.LevelL1Posted, st)
			l.Logf("[FINALITY] capturer %s: %s", l.Name(), st.Error())
		}
	}
	l.mu.Unlock()
	if recordErr != nil {
		return fmt.Errorf("recording a capture gap (the cursor stays at %d and the range is scanned again): %w", cur, recordErr)
	}
	if ctx.Err() != nil && safeTo < from {
		return nil // nothing of this round was tried
	}
	if err := writeCursor(ctx, l.Store, chain, safeTo); err != nil {
		return fmt.Errorf("writing the capture cursor: %w", err)
	}
	l.mu.Lock()
	l.cursor, l.cursorHave, l.cursorKnown = safeTo, true, true
	l.mu.Unlock()
	l.retryFailed(ctx, tick, head, sink)
	l.mu.Lock()
	l.capturedHead = safeTo
	l.mu.Unlock()
	metrics.SetFinalityLastCapturedBlock(chain, l.Name(), safeTo)
	metrics.SetFinalityCaptureLag(chain, l.Name(), head-safeTo)
	l.runIndex(ctx, sink, safeTo)
	return nil
}

// recordGap writes the durable gap row (and a note with the redacted provider text) of a block that could not be captured, once per
// process per block; the row itself is idempotent in the store, so every validator may write it.
func (l *BasePostedLoop) recordGap(ctx context.Context, n uint64, st *finality.StateError, cause error) error {
	if l.gapRecorded[n] {
		return nil
	}
	var failure error = cause
	if st != nil {
		failure = &baseposted.CaptureFailure{Block: n, State: st, Err: cause}
	}
	class := baseposted.ClassOfFailure(failure)
	if err := finality.RecordGap(ctx, l.Store, l.Chain(), n, n, class); err != nil {
		return err
	}
	l.gapRecorded[n] = true
	metrics.IncFinalityGapRecorded(l.Chain(), string(class))
	if err := finality.RecordGapNote(ctx, l.Store, l.Chain(), n, class, cause.Error()); err != nil {
		l.Logf("[FINALITY] capturer %s: the note of the gap at L1 block %d was not recorded: %v", l.Name(), n, ethrpc.RedactError(err))
	}
	return nil
}

// noteLate tells the capture index (when it can be told) that block was captured after the index cursor may have passed it.
func (l *BasePostedLoop) noteLate(block uint64) {
	if nt, ok := l.Index.(finality.LateBlockNoter); ok {
		nt.NoteLate(block)
	}
}

// runIndex steps the capture index towards the capture cursor. Indexing never stops the capture: a failed step is logged (redacted) and a
// named inconsistency is recorded in the status table under the chain's capture pseudo id.
func (l *BasePostedLoop) runIndex(ctx context.Context, sink statusSink, upTo uint64) {
	if l.Index == nil || ctx.Err() != nil {
		return
	}
	ictx := finality.WithMemoryBudget(ctx, l.Memory)
	if _, err := l.Index.Step(ictx, upTo); err != nil && ctx.Err() == nil {
		if st, ok := finality.AsNamed(err); ok {
			sink.put(ctx, l.Chain(), finality.LevelL1Posted, st)
		}
		l.Logf("[FINALITY] index %s: step to L1 block %d: %v", l.Index.Family(), upTo, ethrpc.RedactError(err))
	}
}

// retryFailed retries the held blocks with a doubling gap between attempts. A block older than the provider window without an
// archive provider (or older than MaxRetryAge with one) is handed to the gap backfill: it is already a recorded, open capture gap, and
// the backfill retries it for as long as it is open (with the archive provider when there is one). Nothing is given up here.
func (l *BasePostedLoop) retryFailed(ctx context.Context, tick int, head uint64, sink statusSink) {
	l.mu.Lock()
	var due []uint64
	for n, e := range l.retry {
		age := head - n
		if head < n {
			age = 0
		}
		limit := l.window()
		if l.HasArchive {
			limit = l.maxAge()
		}
		if age > limit {
			delete(l.retry, n)
			l.Logf("[FINALITY] capturer %s: L1 block %d handed to the gap backfill at head %d (%d blocks old, retry limit %d, archive provider configured: %t); it stays an open capture gap and the backfill retries it with backoff",
				l.Name(), n, head, age, limit, l.HasArchive)
			continue
		}
		if tick >= e.nextTick {
			due = append(due, n)
		}
	}
	l.mu.Unlock()
	for _, n := range due {
		if ctx.Err() != nil {
			return
		}
		hash, inbox, err := baseposted.CaptureBlockHashOf(ctx, l.Cap, n)
		var st *finality.StateError
		var cf *baseposted.CaptureFailure
		if errors.As(err, &cf) {
			st = cf.State
		}
		l.mu.Lock()
		e := l.retry[n]
		if err == nil {
			delete(l.retry, n)
			delete(l.lastState, n)
			if ferr := finality.RecordGapFill(ctx, l.Store, l.Chain(), n, hash, inbox); ferr != nil {
				l.Logf("[FINALITY] capturer %s: the fill of L1 block %d was not recorded (the gap backfill closes it): %v", l.Name(), n, ethrpc.RedactError(ferr))
			}
			l.Logf("[FINALITY] capturer %s: L1 block %d captured on retry (inbox transactions: %t)", l.Name(), n, inbox)
			l.noteLate(n)
		} else if e != nil {
			e.attempts++
			gap := 1 << uint(min(e.attempts, 6))
			e.nextTick = tick + gap
			if st != nil {
				sink.put(ctx, l.Chain(), finality.LevelL1Posted, st)
			}
		}
		l.mu.Unlock()
	}
}

// ArbPostedLoop drives arbposted/capture.Capturer: on every tick it scans the SequencerInbox's batch events from its cursor,
// stores each batch with its data, fetches the blobs, and captures the Bridge accumulator proofs at a near-head block. A batch
// whose proof could not be captured inside any provider's window is recorded by the capturer itself and, here, as the named
// state l1_proof_window_unavailable in the status table. It implements finality.Capturer.
type ArbPostedLoop struct {
	Cap       *capture.Capturer
	Providers []string // host labels of the L1 providers, for the state's providers field
	Status    finality.BuilderStatusStore
	Pins      *finality.Pins // the pins the loop's status rows record the hash of
	Every     time.Duration
	Logf      func(string, ...any)
	Clock     loopClock
	// Notes, when set, is told which blocks got the last of their blob rows this tick (the batch index may have passed them while they were incomplete).
	// The index itself runs in its own loop (ArbIndexLoop): it can never delay a capture tick.
	Notes finality.LateBlockNoter
}

var _ finality.Capturer = (*ArbPostedLoop)(nil)

// Chain implements finality.Capturer.
func (l *ArbPostedLoop) Chain() uint64 { return finality.ChainArbitrumSepolia }

// Name implements finality.Capturer.
func (l *ArbPostedLoop) Name() string { return "arbitrum-sepolia/sequencer-inbox" }

// Run implements finality.Capturer.
func (l *ArbPostedLoop) Run(ctx context.Context) error {
	every := l.Every
	if every < finality.MinPoll {
		every = finality.MinPoll
	}
	sink := statusSink{store: l.Status, logf: l.Logf, now: l.Clock.Now, pins: l.Pins}
	for ctx.Err() == nil {
		rep, err := l.Cap.Tick(ctx)
		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			l.Logf("[FINALITY] capturer %s: tick: %v", l.Name(), ethrpc.RedactError(err))
		default:
			metrics.SetFinalityLastCapturedBlock(l.Chain(), l.Name(), rep.ScannedTo)
			if rep.Head >= rep.ScannedTo {
				metrics.SetFinalityCaptureLag(l.Chain(), l.Name(), rep.Head-rep.ScannedTo)
			}
			for _, e := range rep.Errors {
				l.Logf("[FINALITY] capturer %s: %s", l.Name(), e)
			}
			l.reportPrefix(ctx, rep)
			if len(rep.Unavailable) > 0 {
				st := finality.NewState("l1_proof_window_unavailable", "l1_block", rep.Head, "providers", l.Providers)
				sink.put(ctx, l.Chain(), finality.LevelL1Posted, st)
				l.Logf("[FINALITY] capturer %s: %s (batches %v)", l.Name(), st.Error(), rep.Unavailable)
			}
			l.noteBlobs(rep)
		}
		if !l.Clock.wait(ctx, every) {
			return nil
		}
	}
	return nil
}

// reportPrefix sets the prefix gauges of the Arbitrum store (every tick, from the first), counts the scan and names it once when it did something.
func (l *ArbPostedLoop) reportPrefix(ctx context.Context, rep capture.Report) {
	chain := l.Chain()
	metrics.AddFinalityPrefixBackfilled(chain, int(rep.PrefixScanned))
	metrics.AddFinalityPrefixLease(chain, "lost", rep.PrefixLeaseLost)
	metrics.AddFinalityPrefixLease(chain, "error", rep.PrefixLeaseErrors)
	wins, err := finality.PrefixWindowsOf(ctx, l.Cap.Store, chain)
	if err != nil {
		l.Logf("[FINALITY] capturer %s: the prefix windows could not be read: %v", l.Name(), ethrpc.RedactError(err))
		return
	}
	pieces, err := finality.GapsIn(ctx, l.Cap.Store, chain, 0, finality.MaxCaptureBlock)
	if err != nil {
		l.Logf("[FINALITY] capturer %s: the capture gaps could not be read: %v", l.Name(), ethrpc.RedactError(err))
		return
	}
	st := baseposted.PrefixWindowStates(wins, pieces)
	metrics.SetFinalityPrefixWindows(chain, st[baseposted.PrefixWindowComplete], st[baseposted.PrefixWindowOpen],
		st[baseposted.PrefixWindowUnavailableProven], st[baseposted.PrefixWindowRetentionExpired], finality.PrefixBlocks(finality.MergePrefixWindows(wins)))
	if rep.PrefixScanned > 0 {
		l.Logf("[FINALITY] capturer %s: prefix scan: %d L1 blocks scanned, %d batches captured (%d prefix windows: %d complete, %d being scanned)",
			l.Name(), rep.PrefixScanned, rep.PrefixBatches, len(wins), st[baseposted.PrefixWindowComplete], st[baseposted.PrefixWindowOpen])
	}
}

// noteBlobs tells the batch index (when there is one) which blocks got the last of their blob rows this tick: the index may have passed them while
// they were incomplete. Any other filler of batch rows below the index cursor (the archive backfill's Arbitrum prefix scan) calls the same
// finality.LateBlockNoter.
func (l *ArbPostedLoop) noteBlobs(rep capture.Report) {
	if l.Notes == nil {
		return
	}
	for _, b := range rep.BlobBlocks {
		l.Notes.NoteLate(b)
	}
}

// ArbIndexLoop drives the Arbitrum batch index (RB12-INDEX-B) in its own goroutine, so that indexing - a backfill of a whole table takes many steps - can never
// delay or starve a capture tick (V-INDEX note 1: the Base index runs inside the capture goroutine). Each tick it steps the indexer towards the highest cursor
// row the capture has written, under the process memory budget; a failed step is logged (redacted) and a named inconsistency is recorded in the status
// table under the chain's capture pseudo id. It implements finality.Capturer.
type ArbIndexLoop struct {
	Index  finality.CaptureIndexer
	Store  finality.CaptureStore // the store the capture cursor rows are read from
	Memory *finality.MemoryBudget
	Status finality.BuilderStatusStore
	Pins   *finality.Pins
	Every  time.Duration
	Logf   func(string, ...any)
	Clock  loopClock
}

var _ finality.Capturer = (*ArbIndexLoop)(nil)

// Chain implements finality.Capturer.
func (l *ArbIndexLoop) Chain() uint64 { return finality.ChainArbitrumSepolia }

// Name implements finality.Capturer.
func (l *ArbIndexLoop) Name() string { return "arbitrum-sepolia/batch-index" }

// Run implements finality.Capturer: step, wait Every, until ctx ends.
func (l *ArbIndexLoop) Run(ctx context.Context) error {
	every := l.Every
	if every < finality.MinPoll {
		every = finality.MinPoll
	}
	sink := statusSink{store: l.Status, logf: l.Logf, now: l.Clock.Now, pins: l.Pins}
	for ctx.Err() == nil {
		l.runIndex(ctx, sink)
		if !l.Clock.wait(ctx, every) {
			return nil
		}
	}
	return nil
}

// runIndex steps the batch index towards the capture cursor.
func (l *ArbIndexLoop) runIndex(ctx context.Context, sink statusSink) {
	if l.Index == nil || ctx.Err() != nil {
		return
	}
	_, upTo, ok, err := finality.BlockBoundsOf(ctx, l.Store, l.Chain(), capture.ItemCursor)
	if err != nil || !ok {
		if err != nil && ctx.Err() == nil {
			l.Logf("[FINALITY] index %s: the capture cursor is unreadable: %v", l.Index.Family(), ethrpc.RedactError(err))
		}
		return
	}
	ictx := finality.WithMemoryBudget(ctx, l.Memory)
	if _, err := l.Index.Step(ictx, upTo); err != nil && ctx.Err() == nil {
		if st, named := finality.AsNamed(err); named {
			sink.put(ctx, l.Chain(), finality.LevelL1Posted, st)
		}
		l.Logf("[FINALITY] index %s: step to L1 block %d: %v", l.Index.Family(), upTo, ethrpc.RedactError(err))
	}
}
