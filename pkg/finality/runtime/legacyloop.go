// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"fmt"
	goruntime "runtime"
	"sort"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr"
	"github.com/certen/independant-validator/pkg/metrics"
)

// The states of a legacy leg in the loop (the `state` label of certen_finality_legacy_headers).
const (
	LegacyPending       = legacyhdr.StatePending
	LegacyReconstructed = legacyhdr.StateReconstructed
	LegacyUnserved      = legacyhdr.StateUnserved
	LegacyInvalid       = legacyhdr.StateInvalid
)

// The working set one leg may hold while it is judged: the provider response (bounded by legacyhdr.DefaultMaxResponse) three times
// over (the body, its JSON, the rebuilt header and proofs), and, for a scan, one decompressed bundle (bounded by 16 MiB) three times
// over. Both are reserved against the process memory budget before the bytes are read and given back on every exit path.
const (
	legacyLegReserve  = 3 * legacyhdr.DefaultMaxResponse
	legacyScanReserve = 3 * 16 << 20
)

// LegacyHeaderLoop reconstructs, for ONE chain, the block headers of the legacy legs (RB12-LEGACY-191): it lists the chain's legs
// whose stored execution proof has no block_header_rlp, asks the chain's configured providers for each block by its stored hash
// (availability only), verifies the header against the stored hash, block number, roots and proofs (legacyhdr.Leg.Verify) and
// keeps it as one insert-only capture row the leg source reads. It implements finality.Capturer.
//
//   - Idempotent: a header already in the store is verified and never fetched again; a restart or the other six validators repeat
//     nothing but a Get. A duplicate Put is byte-identical (the key is the hash of the bytes).
//   - Budgeted and paced: at most PerTick legs per tick, Gap between legs and pages, a reservation against the process memory budget
//     around every leg and scan (released with defer), and no leg starts while the heap is over the gate the upgrader uses.
//   - Named, never weaker: a leg no provider can serve is finality_included_unavailable{legacy_header_unserved} (the chain, the block
//     and how each provider failed), asked again with exponential backoff; a leg whose stored component contradicts the true block, or
//     cannot be read, is finality_included_invalid{check|cause}. Both are written as builder status rows (class unavailable) for the
//     chain's stored levels and counted in certen_finality_legacy_headers.
type LegacyHeaderLoop struct {
	ChainID uint64
	Legs    legacyhdr.LegLister
	Source  legacyhdr.HeaderSource
	Store   finality.CaptureStore
	Status  finality.BuilderStatusStore
	// Targets are the stored levels the chain offers (status rows are written for each).
	Targets []finality.Level
	Budget  *finality.MemoryBudget
	// HeapInUse is the heap gauge the gate reads (default: runtime.MemStats.HeapInuse).
	HeapInUse func() uint64

	Every       time.Duration // between ticks (default 60s)
	PerTick     int           // legs judged per tick (default 8)
	Gap         time.Duration // between legs and between scan pages (default 250ms)
	PageSize    int           // proofs examined per scan page (default 100)
	RescanEvery time.Duration // between scans of the leg list (default 6h)
	RetryMin    time.Duration // first wait after an unserved leg (default 10m), doubled per attempt
	RetryMax    time.Duration // longest wait (default 6h)
	Logf        func(string, ...any)
	Clock       loopClock

	mu       sync.Mutex
	legs     map[string]*legacyLeg
	lastScan time.Time
	scanned  bool
	last     string // the last summary line logged
}

type legacyLeg struct {
	cand     legacyhdr.Candidate
	state    string
	attempts int
	next     time.Time
	cause    string
}

var _ finality.Capturer = (*LegacyHeaderLoop)(nil)

// Chain implements finality.Capturer.
func (l *LegacyHeaderLoop) Chain() uint64 { return l.ChainID }

// Name implements finality.Capturer.
func (l *LegacyHeaderLoop) Name() string { return fmt.Sprintf("legacy-header/%d", l.ChainID) }

func (l *LegacyHeaderLoop) every() time.Duration    { return durOr(l.Every, 60*time.Second) }
func (l *LegacyHeaderLoop) gap() time.Duration      { return durOr(l.Gap, 250*time.Millisecond) }
func (l *LegacyHeaderLoop) rescan() time.Duration   { return durOr(l.RescanEvery, 6*time.Hour) }
func (l *LegacyHeaderLoop) retryMin() time.Duration { return durOr(l.RetryMin, 10*time.Minute) }
func (l *LegacyHeaderLoop) retryMax() time.Duration { return durOr(l.RetryMax, 6*time.Hour) }
func (l *LegacyHeaderLoop) perTick() int {
	if l.PerTick > 0 {
		return l.PerTick
	}
	return 8
}
func (l *LegacyHeaderLoop) pageSize() int {
	if l.PageSize > 0 {
		return l.PageSize
	}
	return 100
}
func (l *LegacyHeaderLoop) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
	}
}

func durOr(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (l *LegacyHeaderLoop) heap() uint64 {
	if l.HeapInUse != nil {
		return l.HeapInUse()
	}
	var m goruntime.MemStats
	goruntime.ReadMemStats(&m)
	return m.HeapInuse
}

// Run implements finality.Capturer: a tick, then Every, until ctx ends.
func (l *LegacyHeaderLoop) Run(ctx context.Context) error {
	for {
		if err := l.Tick(ctx); err != nil && ctx.Err() == nil {
			l.logf("[FINALITY] %s: %s", l.Name(), ethrpc.RedactText(err.Error()))
		}
		if !l.Clock.wait(ctx, l.every()) {
			return nil
		}
	}
}

// Tick is one pass: a scan of the leg list when one is due, then up to PerTick legs that are due. It returns an error only for a
// failure of the scan itself (the legs already known are still judged).
func (l *LegacyHeaderLoop) Tick(ctx context.Context) (scanErr error) {
	defer l.publish()
	now := l.Clock.now()
	l.mu.Lock()
	due := !l.scanned || now.Sub(l.lastScan) >= l.rescan()
	l.mu.Unlock()
	if due {
		scanErr = l.scan(ctx)
		if ctx.Err() == nil {
			metrics.SetFinalityLegacyScan(l.ChainID, scanErr != nil)
		}
		if scanErr == nil {
			l.mu.Lock()
			l.scanned, l.lastScan = true, now
			l.mu.Unlock()
		}
	}
	for _, id := range l.dueLegs(now) {
		if ctx.Err() != nil {
			return scanErr
		}
		if gate := finality.HeapGate(l.budgetLimit()); l.heap() > gate {
			l.logf("[FINALITY] %s: no leg started: heap in use is over the gate %d (the legs stay due)", l.Name(), gate)
			metrics.IncFinalityMemoryRefused(l.ChainID, "legacy-header")
			return scanErr
		}
		stop := l.judge(ctx, id)
		if stop {
			return scanErr
		}
		if !l.Clock.wait(ctx, l.gap()) {
			return scanErr
		}
	}
	return scanErr
}

func (l *LegacyHeaderLoop) budgetLimit() int64 {
	if l.Budget != nil {
		return l.Budget.Limit()
	}
	return finality.DefaultMemoryBudget
}

// dueLegs are the proof ids to judge this tick: pending legs, and unserved ones whose backoff has passed, lowest block first (the
// oldest blocks are the ones a provider prunes first), at most PerTick.
func (l *LegacyHeaderLoop) dueLegs(now time.Time) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ids []string
	for id, g := range l.legs {
		if g.state == LegacyPending || (g.state == LegacyUnserved && !now.Before(g.next)) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := l.legs[ids[i]].cand.Leg, l.legs[ids[j]].cand.Leg
		if a.BlockNumber != b.BlockNumber {
			return a.BlockNumber < b.BlockNumber
		}
		return ids[i] < ids[j]
	})
	if len(ids) > l.perTick() {
		ids = ids[:l.perTick()]
	}
	return ids
}

// scan lists the chain's legacy legs page by page and merges them into the loop's state: a leg already known keeps its state unless
// its bundle changed.
func (l *LegacyHeaderLoop) scan(ctx context.Context) error {
	rel, err := l.Budget.Reserve(l.ChainID, "legacy-scan", legacyScanReserve)
	if err != nil {
		return err
	}
	defer rel()
	seen := map[string]bool{}
	after := ""
	for {
		cands, next, err := l.Legs.LegacyLegs(ctx, l.ChainID, after, l.pageSize())
		if err != nil {
			return fmt.Errorf("listing the legacy legs of chain %d: %w", l.ChainID, err)
		}
		l.mu.Lock()
		if l.legs == nil {
			l.legs = map[string]*legacyLeg{}
		}
		for _, c := range cands {
			seen[c.Leg.ProofID] = true
			if old, ok := l.legs[c.Leg.ProofID]; ok && old.cand.Leg.BundleID == c.Leg.BundleID {
				continue
			}
			g := &legacyLeg{cand: c, state: LegacyPending}
			l.legs[c.Leg.ProofID] = g
		}
		l.mu.Unlock()
		if next == "" {
			break
		}
		after = next
		if !l.Clock.wait(ctx, l.gap()) {
			return ctx.Err()
		}
	}
	// a leg a complete scan no longer lists (finalized elsewhere, or its bundle gained a header) is not this loop's any more
	l.mu.Lock()
	for id := range l.legs {
		if !seen[id] {
			delete(l.legs, id)
		}
	}
	l.mu.Unlock()
	return nil
}

// judge reconstructs one leg. It returns true when the tick must stop (the memory budget refused the leg).
func (l *LegacyHeaderLoop) judge(ctx context.Context, id string) (stop bool) {
	l.mu.Lock()
	g := l.legs[id]
	l.mu.Unlock()
	if g == nil {
		return false
	}
	rel, err := l.Budget.Reserve(l.ChainID, "legacy-header", legacyLegReserve)
	if err != nil {
		l.logf("[FINALITY] %s: leg %s not started: %v (it stays due)", l.Name(), id, err)
		return true
	}
	defer rel()

	state, cause, st := l.reconstruct(ctx, g)
	if ctx.Err() != nil {
		return true // an interrupted attempt judges nothing
	}
	now := l.Clock.now()
	l.mu.Lock()
	g.state, g.cause = state, cause
	if state == LegacyUnserved {
		g.attempts++
		wait := l.retryMin()
		for i := 1; i < g.attempts && wait < l.retryMax(); i++ {
			wait *= 2
		}
		if wait > l.retryMax() {
			wait = l.retryMax()
		}
		g.next = now.Add(wait)
	}
	l.mu.Unlock()
	if st != nil {
		l.putStatus(ctx, g.cand.Leg.ProofID, st)
	}
	return false
}

// reconstruct is the judgement of one leg: its state, a log-safe cause, and the named state of an unserved or invalid leg. A
// candidate the lister could not read as a leg is invalid by the state it carries and is never asked of a provider; every other leg
// is legacyhdr.Judge (the code the offline command runs too).
func (l *LegacyHeaderLoop) reconstruct(ctx context.Context, g *legacyLeg) (state, cause string, st *finality.StateError) {
	leg := g.cand.Leg
	if g.cand.Err != nil {
		named, ok := finality.AsNamed(g.cand.Err)
		if !ok {
			named = finality.NewState(finality.CodeIncludedInvalid, "proof_id", leg.ProofID, "cause", g.cand.Err.Error())
		}
		return LegacyInvalid, named.Error(), named
	}
	logf := func(format string, args ...any) { l.logf("[FINALITY] "+l.Name()+": "+format, args...) }
	out := legacyhdr.Judge(ctx, leg, l.Store, l.Source, logf)
	return out.State, out.Cause, out.Named
}

// putStatus writes the leg's named state as a builder status row for each stored level the chain offers. A write that fails is
// logged and counted and never stops the loop (the next judgement writes it again).
func (l *LegacyHeaderLoop) putStatus(ctx context.Context, proofID string, st *finality.StateError) {
	for _, target := range l.Targets {
		metrics.IncFinalityStatus(l.ChainID, target.String(), st.Code)
		if l.Status == nil {
			continue
		}
		row := finality.BuilderStatusOf(proofID, l.ChainID, target, finality.LevelNone, nil, st, false, l.Clock.now())
		if err := l.Status.UpsertStatus(ctx, row); err != nil && ctx.Err() == nil {
			metrics.IncFinalityStatusWriteFailure(l.ChainID)
			l.logf("[FINALITY] %s: the %s status row of %s was not written: %s", l.Name(), target, proofID, ethrpc.RedactText(err.Error()))
		}
	}
}

// Counts is how many known legs stand in each state.
func (l *LegacyHeaderLoop) Counts() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := map[string]int{LegacyPending: 0, LegacyReconstructed: 0, LegacyUnserved: 0, LegacyInvalid: 0}
	for _, g := range l.legs {
		c[g.state]++
	}
	return c
}

// publish sets the gauge for every state and logs the counts when they changed (a routine tick with nothing new stays quiet).
func (l *LegacyHeaderLoop) publish() {
	c := l.Counts()
	for state, n := range c {
		metrics.SetFinalityLegacyHeaders(l.ChainID, state, n)
	}
	line := fmt.Sprintf("%d pending, %d reconstructed, %d unserved, %d invalid", c[LegacyPending], c[LegacyReconstructed], c[LegacyUnserved], c[LegacyInvalid])
	l.mu.Lock()
	changed := line != l.last
	l.last = line
	l.mu.Unlock()
	if changed {
		l.logf("[FINALITY] %s legacy legs (execution proof without block_header_rlp): %s", l.Name(), line)
	}
}
