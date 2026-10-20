// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"encoding/binary"
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
	row := finality.BuilderStatusOf(CaptureStatusProofID(chain), chain, target, finality.LevelNone, nil, st, false, at)
	if err := s.store.UpsertStatus(ctx, row); err != nil && ctx.Err() == nil {
		metrics.IncFinalityStatusWriteFailure(chain)
		s.logf("[FINALITY] capture status of chain %d (%s) was not written: %v", chain, st.Code, ethrpc.RedactError(err))
	}
}

// cursorItem is the capture row that remembers how far a loop has scanned. It is keyed at the scanned block under the zero hash
// (a cursor is about no particular block hash) and is insert-only like every capture row.
const cursorItem = "runtime/cursor"

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
// or for as long as an archive provider is configured, then given up with the state left in the table: the leg keeps the level
// it has. It implements finality.Capturer.
type BasePostedLoop struct {
	Cap          *baseposted.Capturer
	Store        finality.CaptureStore
	Status       finality.BuilderStatusStore
	Every        time.Duration
	MaxPerTick   int
	StartBack    uint64
	ProofWindow  uint64 // L1 blocks a block stays retryable without an archive provider (default 96)
	HasArchive   bool
	MaxRetryAge  uint64 // with an archive provider: blocks after which a retry is given up (default 20000)
	Logf         func(string, ...any)
	Clock        loopClock
	retry        map[uint64]*retryEntry
	mu           sync.Mutex
	lastState    map[uint64]*finality.StateError
	capturedHead uint64
	cursor       uint64
	cursorHave   bool
	cursorKnown  bool
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
// whose capture failed. It returns an error only for a failure to follow the head at all (no head, no cursor store).
func (l *BasePostedLoop) Tick(ctx context.Context, tick int) error {
	l.init()
	chain := l.Chain()
	sink := statusSink{store: l.Status, logf: l.Logf, now: l.Clock.Now}
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
	if from > head {
		metrics.SetFinalityCaptureLag(chain, l.Name(), 0)
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
	l.mu.Lock()
	for n, e := range errs {
		if ctx.Err() != nil {
			break
		}
		st := states[n]
		if st == nil {
			// a failure that is not a registered unavailability (a provider error, an inconsistent answer): its cause is logged
			// redacted and the block is retried; nothing is recorded as a state the registry does not name
			l.Logf("[FINALITY] capturer %s: L1 block %d not captured: %v", l.Name(), n, ethrpc.RedactError(e))
		}
		l.retry[n] = &retryEntry{nextTick: tick + 1}
		if st != nil {
			l.lastState[n] = st
			sink.put(ctx, chain, finality.LevelL1Posted, st)
			l.Logf("[FINALITY] capturer %s: %s", l.Name(), st.Error())
		}
	}
	l.mu.Unlock()
	// the cursor passes `to` only when every block of the range was tried; a failed block is held in the retry set
	if err := writeCursor(ctx, l.Store, chain, to); err != nil {
		return fmt.Errorf("writing the capture cursor: %w", err)
	}
	l.mu.Lock()
	l.cursor, l.cursorHave, l.cursorKnown = to, true, true
	l.mu.Unlock()
	l.retryFailed(ctx, tick, head, sink)
	l.mu.Lock()
	l.capturedHead = to
	l.mu.Unlock()
	metrics.SetFinalityLastCapturedBlock(chain, l.Name(), to)
	metrics.SetFinalityCaptureLag(chain, l.Name(), head-to)
	return nil
}

// retryFailed retries the held blocks with a doubling gap between attempts. A block older than the provider window without an
// archive provider (or older than MaxRetryAge with one) is given up: its named state stays in the status table.
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
			l.Logf("[FINALITY] capturer %s: L1 block %d given up at head %d (%d blocks old, retry limit %d, archive provider configured: %t); the legs it would have served keep their level",
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
		var st *finality.StateError
		l.Cap.Record = func(_ uint64, s *finality.StateError) { st = s }
		ok, err := l.Cap.CaptureBlock(ctx, n)
		l.mu.Lock()
		e := l.retry[n]
		if err == nil {
			delete(l.retry, n)
			delete(l.lastState, n)
			l.Logf("[FINALITY] capturer %s: L1 block %d captured on retry (inbox transactions: %t)", l.Name(), n, ok)
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
	Every     time.Duration
	Logf      func(string, ...any)
	Clock     loopClock
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
	sink := statusSink{store: l.Status, logf: l.Logf, now: l.Clock.Now}
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
			if len(rep.Unavailable) > 0 {
				st := finality.NewState("l1_proof_window_unavailable", "l1_block", rep.Head, "providers", l.Providers)
				sink.put(ctx, l.Chain(), finality.LevelL1Posted, st)
				l.Logf("[FINALITY] capturer %s: %s (batches %v)", l.Name(), st.Error(), rep.Unavailable)
			}
		}
		if !l.Clock.wait(ctx, every) {
			return nil
		}
	}
	return nil
}
