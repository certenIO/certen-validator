// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-SEPOLIA-SPINE (live defect F6, 2026-10-23): the execution-header spine of an eth-sepolia/finalized/v1 proof is every header from the
// leg block up to the finalized head (about 4.6 thousand on a day-old leg, at most max_spine_headers = 16384). A public provider serves
// them in about three minutes when it does not throttle, and the build used to throw away all it had fetched whenever its 300 s ended,
// so eleven legs never finished. The spine is now fetched in resumable CHUNKS:
//
//   - The spine is walked from the finalized head DOWN. The head's hash is authenticated by the light client (the verifier checks that
//     again), and every header names its parent by hash, so each chunk is authenticated, at the moment it is fetched, against the hash the
//     chunk above it commits to. A header a provider invents can never become part of a kept chunk.
//   - A chunk is a window of SpineWindow headers aligned to a multiple of SpineWindow (the first window above the leg is cut at the leg
//     block: nothing below the leg is ever asked for). A complete window is kept as one insert-only capture row addressed by
//     (chain, last block, hash of the last header, item "spine/n<count>"): the key commits, through the parent links, to every byte of the
//     row, so the same chunk is the same row for every leg and every validator (byte-identical duplicates are accepted; a row that is not
//     what its key says is the named state finality_spine_row_invalid). The window that ends at the head is never complete and is not kept.
//   - Chunks are also kept in this process (a bounded cache), so a store that is slow or briefly down loses no progress, and several legs
//     asking for the same chunk at once fetch it once.
//   - An attempt spends at most AttemptBudget of time on NEW work (reading kept chunks costs nothing against it). When it is spent, or the
//     provider throttles, or fails, the attempt ends with the named progress state finality_pending{awaiting_spine, have, need,
//     next_attempt_at} and the next attempt starts at the first chunk that is not kept.
//
// The evidence a finished walk produces is the same bytes as before (spine[0] the finalized head, then each parent down to the leg block),
// and Kind.Verify judges it exactly as before; nothing here is trusted by a verifier.

// Sizes and bounds of the spine fetch.
const (
	// SpineWindow is the number of headers in a kept chunk. It is part of every chunk's item name, so a different value would address
	// different rows and could never be confused with these.
	SpineWindow = 40
	// DefaultSpineBudget is the time one attempt may spend on new fetches (Prover.SpineBudget).
	DefaultSpineBudget = 150 * time.Second
	// SpineCacheBytes bounds the chunks (and finalized-head headers) kept in this process: room for one maximal spine and a half.
	SpineCacheBytes = 24 << 20
	// SpineResumeDelay is the time between two attempts of a spine that is making progress.
	SpineResumeDelay = 2 * time.Second
	// SpineErrorBase and SpineErrorMax bound the wait after an attempt that fetched nothing: base, doubled per such attempt in a row.
	SpineErrorBase = 30 * time.Second
	SpineErrorMax  = 15 * time.Minute

	spineItemPrefix = "spine/n"
	spineHeadCap    = 64 // finalized-head headers kept in process
	maxStallKeys    = 4096
)

// SpineItem is the capture item of a chunk of count headers.
func SpineItem(count int) string { return fmt.Sprintf("%s%d", spineItemPrefix, count) }

// Span is a run of consecutive execution blocks of the spine: Start..End inclusive. Stored spans are complete windows (ending at a
// multiple of SpineWindow minus one, starting at the window start or at the leg block) and are kept; the one span that ends at the
// finalized head's parent is not.
type Span struct {
	Start, End uint64
	Stored     bool
}

// Count is the number of headers of the span.
func (s Span) Count() int { return int(s.End-s.Start) + 1 }

// PlanSpans is the chunk planner: the spans that cover first..last (the leg block up to the parent of the finalized head), in the order
// they are walked, highest first. The first span is the one that ends at last; it is kept only when last closes a window. Every
// further span is a complete window, cut at first. Nil when last < first (the finalized head is the leg block itself).
func PlanSpans(first, last uint64) []Span {
	if last < first {
		return nil
	}
	var out []Span
	end := last
	if last%SpineWindow != SpineWindow-1 {
		start := last - last%SpineWindow
		if start < first {
			start = first
		}
		out = append(out, Span{Start: start, End: last})
		if start == first {
			return out
		}
		end = start - 1
	}
	for {
		start := end - (SpineWindow - 1)
		if start < first {
			start = first
		}
		out = append(out, Span{Start: start, End: end, Stored: true})
		if start == first {
			return out
		}
		end = start - 1
	}
}

// SpineProgress is the pair finality_pending{awaiting_spine} reports: have is the number of spine headers (the finalized head and the
// headers below it) already obtained and authenticated from the top down, need the length of the whole spine. done is the number of
// spans of the plan that are complete; head says whether the finalized head's own header is in hand.
func SpineProgress(spans []Span, head bool, done int) (have, need int) {
	for i, s := range spans {
		need += s.Count()
		if i < done {
			have += s.Count()
		}
	}
	need++
	if head {
		have++
	} else {
		have = 0
	}
	return have, need
}

// BudgetAllows decides whether another fetch may start: the time spent on new work so far plus the longest single fetch of this attempt
// (the best guess of the next one) must fit the budget. The first fetch of an attempt (nothing spent, nothing known) is allowed whenever
// there is a budget at all.
func BudgetAllows(spent, longest, budget time.Duration) bool {
	return budget > 0 && spent+longest <= budget
}

// AttemptBudget is the time an attempt may spend on new fetches: cap (DefaultSpineBudget when zero), and, when the caller's context has a
// deadline (left >= 0), never more than what is left of it minus a reserve for assembling and verifying (a fifth, at least 10 s). A
// context with less than that left allows no new work at all: the attempt still reads what is kept.
func AttemptBudget(cap, left time.Duration) time.Duration {
	if cap <= 0 {
		cap = DefaultSpineBudget
	}
	if left < 0 {
		return cap
	}
	reserve := left / 5
	if reserve < 10*time.Second {
		reserve = 10 * time.Second
	}
	if left <= reserve {
		return 0
	}
	if b := left - reserve; b < cap {
		return b
	}
	return cap
}

// PauseKind is why an attempt stopped before the spine was complete.
type PauseKind int

const (
	// PauseBudget: the attempt spent its time on new work (progress was made).
	PauseBudget PauseKind = iota
	// PauseThrottled: a provider answered 429 and the wait did not fit this attempt.
	PauseThrottled
	// PauseError: a provider or the store failed.
	PauseError
)

// PauseAfter is the time to the next attempt. A spent budget resumes after SpineResumeDelay. A throttle waits what the provider asked
// (at least SpineResumeDelay, at most MaxRetryAfterKept) and, when it stated nothing, as an error does: SpineErrorBase doubled once
// per earlier attempt in a row that fetched nothing, never above SpineErrorMax. stalls is that number of earlier attempts.
func PauseAfter(kind PauseKind, retryAfter time.Duration, stalls int) time.Duration {
	switch kind {
	case PauseBudget:
		return SpineResumeDelay
	case PauseThrottled:
		if retryAfter > 0 {
			if retryAfter < SpineResumeDelay {
				return SpineResumeDelay
			}
			if retryAfter > MaxRetryAfterKept {
				return MaxRetryAfterKept
			}
			return retryAfter
		}
	}
	d := SpineErrorBase
	for i := 0; i < stalls && d < SpineErrorMax; i++ {
		d *= 2
	}
	if d > SpineErrorMax {
		d = SpineErrorMax
	}
	return d
}

// ---- the chunk bytes ----

// spineFault says how a chunk differs from what its address promises.
type spineFault struct {
	Reason string
	At     uint64 // the header number the fault was found at (0: not about one header)
	Want   [32]byte
	Got    [32]byte
	Hashes bool
	Cause  string
}

func (f *spineFault) Error() string {
	s := f.Reason
	if f.At != 0 {
		s += fmt.Sprintf(" at block %d", f.At)
	}
	if f.Cause != "" {
		s += ": " + f.Cause
	}
	return s
}

// encodeSpan is the bytes of a chunk: the RLP list of its raw header RLPs, ascending. It is deterministic, so a chunk is the same bytes
// whichever validator wrote it.
func encodeSpan(hs [][]byte) []byte {
	raws := make([]rlp.RawValue, len(hs))
	for i, h := range hs {
		raws[i] = h
	}
	enc, err := rlp.EncodeToBytes(raws)
	if err != nil { // a RawValue list cannot fail to encode unless an element is not valid RLP; checkSpan has read every element first
		return nil
	}
	return enc
}

// decodeSpan splits the bytes of a chunk into its header RLPs (slices of enc, nothing is copied).
func decodeSpan(enc []byte) ([][]byte, *spineFault) {
	content, rest, err := rlp.SplitList(enc)
	if err != nil || len(rest) != 0 {
		return nil, &spineFault{Reason: SpineRowMalformed, Cause: "not one RLP list"}
	}
	var hs [][]byte
	for len(content) > 0 {
		kind, _, tail, err := rlp.Split(content)
		if err != nil || kind != rlp.List {
			return nil, &spineFault{Reason: SpineRowMalformed, Cause: fmt.Sprintf("element %d is not an RLP list", len(hs))}
		}
		hs = append(hs, content[:len(content)-len(tail)])
		content = tail
	}
	return hs, nil
}

// checkSpan is the linkage check: hs must be exactly the headers sp.Start..sp.End, each readable, numbered one above the last, each the
// parent of the next, and the last one must be the header whose hash is wantTop (the hash the chunk above, or the finalized head, commits
// to). It returns the parent hash of the first header: what the next chunk down must end with.
func checkSpan(hs [][]byte, sp Span, wantTop [32]byte) ([32]byte, *spineFault) {
	var zero [32]byte
	if len(hs) != sp.Count() {
		return zero, &spineFault{Reason: SpineRowMalformed, Cause: fmt.Sprintf("%d headers, the item names %d", len(hs), sp.Count())}
	}
	var first, prev finality.HeaderFields
	for i, raw := range hs {
		f, err := finality.ReadHeader(raw)
		if err != nil {
			return zero, &spineFault{Reason: SpineRowMalformed, At: sp.Start + uint64(i), Cause: "a header cannot be read"}
		}
		if f.Number != sp.Start+uint64(i) {
			return zero, &spineFault{Reason: SpineRowNumbers, At: sp.Start + uint64(i), Cause: fmt.Sprintf("header number %d", f.Number)}
		}
		if i > 0 && f.ParentHash != prev.Hash {
			return zero, &spineFault{Reason: SpineRowNotChained, At: f.Number, Want: prev.Hash, Got: f.ParentHash, Hashes: true}
		}
		if i == 0 {
			first = f
		}
		prev = f
	}
	if prev.Hash != wantTop {
		return zero, &spineFault{Reason: SpineRowTopMismatch, At: sp.End, Want: wantTop, Got: prev.Hash, Hashes: true}
	}
	return first.ParentHash, nil
}

// spineRowInvalid is the named state of a kept chunk that fails its check.
func spineRowInvalid(sp Span, f *spineFault) *finality.StateError {
	s := finality.NewState(CodeSpineRowInvalid, "chain", finality.ChainSepolia, "block", sp.End, "reason", f.Reason, "item", SpineItem(sp.Count()))
	if f.At != 0 {
		s.Fields["at"] = f.At
	}
	if f.Hashes {
		s.Fields["want_hash"], s.Fields["got_hash"] = f.Want, f.Got
	}
	return s
}

// ---- the process cache ----

type spineKey struct {
	End   uint64
	Top   [32]byte
	Count int
}

// spineEntry is a checked chunk: its bytes, its headers (slices of enc) and the parent hash of its first header.
type spineEntry struct {
	enc    []byte
	hs     [][]byte
	parent [32]byte
}

type spineCache struct {
	mu    sync.Mutex
	m     map[spineKey]*spineEntry
	order []spineKey
	bytes int
	cap   int
}

func (c *spineCache) get(k spineKey) (*spineEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	return e, ok
}

// put keeps e under k, dropping the oldest entries to stay within the byte bound. An entry larger than the bound is not kept.
func (c *spineCache) put(k spineKey, e *spineEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[k]; ok || len(e.enc) > c.cap {
		return
	}
	if c.m == nil {
		c.m = map[spineKey]*spineEntry{}
	}
	for c.bytes+len(e.enc) > c.cap && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		if oe, ok := c.m[old]; ok {
			c.bytes -= len(oe.enc)
			delete(c.m, old)
		}
	}
	c.m[k] = e
	c.order = append(c.order, k)
	c.bytes += len(e.enc)
}

type lockEntry struct {
	ch   chan struct{}
	refs int
}

// spineLocks serialises the fetch of one chunk inside the process: the second leg that wants a chunk waits for the first and then finds
// it in the cache.
type spineLocks struct {
	mu sync.Mutex
	m  map[spineKey]*lockEntry
}

func (l *spineLocks) acquire(ctx context.Context, k spineKey) (release func(), err error) {
	l.mu.Lock()
	if l.m == nil {
		l.m = map[spineKey]*lockEntry{}
	}
	e := l.m[k]
	if e == nil {
		e = &lockEntry{ch: make(chan struct{}, 1)}
		l.m[k] = e
	}
	e.refs++
	l.mu.Unlock()
	drop := func() {
		l.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(l.m, k)
		}
		l.mu.Unlock()
	}
	select {
	case e.ch <- struct{}{}:
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() { once.Do(func() { <-e.ch; drop() }) }, nil
}

// spineCore is the per-prover state of the spine fetch.
type spineCore struct {
	chunks spineCache
	locks  spineLocks

	mu     sync.Mutex
	heads  map[[32]byte][]byte // finalized-head headers by hash (immutable, so safe to keep)
	order  [][32]byte
	stalls map[[32]byte]int // legs (by block hash) whose last attempts fetched nothing, and how many in a row
}

func newSpineCore() *spineCore { return &spineCore{chunks: spineCache{cap: SpineCacheBytes}} }

func (c *spineCore) head(h [32]byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.heads[h]
	return b, ok
}

func (c *spineCore) putHead(h [32]byte, raw []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.heads[h]; ok {
		return
	}
	if c.heads == nil {
		c.heads = map[[32]byte][]byte{}
	}
	if len(c.order) >= spineHeadCap {
		delete(c.heads, c.order[0])
		c.order = c.order[1:]
	}
	c.heads[h] = raw
	c.order = append(c.order, h)
}

// noteAttempt records the outcome of an attempt for the leg and returns the number of attempts in a row before it that fetched nothing.
func (c *spineCore) noteAttempt(leg [32]byte, progressed bool, kind PauseKind) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if progressed {
		delete(c.stalls, leg)
		return 0
	}
	n := c.stalls[leg]
	if kind != PauseBudget {
		if c.stalls == nil || len(c.stalls) >= maxStallKeys {
			c.stalls = map[[32]byte]int{}
		}
		c.stalls[leg] = n + 1
	}
	return n
}

func (c *spineCore) finished(leg [32]byte) {
	c.mu.Lock()
	delete(c.stalls, leg)
	c.mu.Unlock()
}

// ---- one attempt ----

// spinePause is the error a walk ends with when it stopped but nothing is wrong with the evidence: the attempt ends with the progress
// state. It is never returned to the upgrader as an error.
type spinePause struct {
	kind       PauseKind
	retryAfter time.Duration
	cause      string
}

func (p *spinePause) Error() string { return "spine paused: " + p.cause }

type spineRun struct {
	p       *Prover
	sc      *spineCore
	ctx     context.Context
	leg     finality.BlockRef
	budget  time.Duration
	spent   time.Duration // time spent on new fetches in this attempt
	longest time.Duration // the longest single fetch of this attempt
	have    int
	need    int
	fetched int // headers fetched in this attempt
	reused  int // chunks read from the process cache or the store
	chunks  int // chunks fetched
}

func (p *Prover) spineCore() *spineCore {
	p.coreOnce.Do(func() { p.sc = newSpineCore() })
	return p.sc
}

// spineFor returns the spine of the proof for the finalized update c: the header of the finalized head first, then each parent down to the
// leg block. When the walk stops early it returns the progress state (finality_pending{awaiting_spine}) and no spine; a chunk that is not
// what its address says is an error that names it (finality_spine_row_invalid).
func (p *Prover) spineFor(ctx context.Context, leg finality.BlockRef, c candidate) ([][]byte, *finality.PendingState, error) {
	r := &spineRun{p: p, sc: p.spineCore(), ctx: ctx, leg: leg, budget: AttemptBudget(p.SpineBudget, timeLeft(ctx))}
	r.need = 1
	if c.execNumber > leg.Number {
		r.need = int(c.execNumber-leg.Number) + 1
	}
	spine, err := r.walk(c)
	if err == nil {
		r.sc.finished(leg.Hash)
		r.logDone()
		return spine, nil, nil
	}
	var sp *spinePause
	if errors.As(err, &sp) {
		return nil, r.pending(sp), nil
	}
	return nil, nil, err
}

func (r *spineRun) logf(format string, args ...any) {
	if r.p.Logf != nil {
		r.p.Logf(format, args...)
	}
}

func (r *spineRun) logDone() {
	r.logf("[FINALITY] sepolia spine of leg %d complete: %d headers (%d fetched in %d chunks, %d chunks reused, %s of new work)",
		r.leg.Number, r.need, r.fetched, r.chunks, r.reused, r.spent.Round(time.Millisecond))
}

func (r *spineRun) pending(sp *spinePause) *finality.PendingState {
	stalls := r.sc.noteAttempt(r.leg.Hash, r.fetched > 0, sp.kind)
	next := r.p.now().Add(PauseAfter(sp.kind, sp.retryAfter, stalls)).UTC()
	j := map[string]any{"have": uint64(r.have), "need": uint64(r.need), "next_attempt_at": next.Format(time.RFC3339)}
	if sp.cause != "" {
		j["cause"] = sp.cause
	}
	r.logf("[FINALITY] sepolia spine of leg %d: have %d of %d headers (%d fetched in %d chunks, %d chunks reused), next attempt %s: %s",
		r.leg.Number, r.have, r.need, r.fetched, r.chunks, r.reused, next.Format(time.RFC3339), sp.cause)
	return &finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
		Reason: PendingAwaitingSpine, ETA: next, Judged: j}
}

// causeOf turns a provider or store error into the text of a pause: redacted and bounded.
func causeOf(what string, err error) string {
	return ethrpc.RedactText(what + ": " + err.Error())
}

// failed classifies an error of a fetch or a store call: a context that ended, or a provider or store that failed, pauses the spine; a
// named state of the framework (the memory budget) stops the build as it is.
func (r *spineRun) failed(what string, err error) error {
	if _, named := finality.AsNamed(err); named {
		return err
	}
	var se *SourceError
	if errors.As(err, &se) {
		if ra, throttled := se.Throttle(); throttled {
			return &spinePause{kind: PauseThrottled, retryAfter: ra, cause: causeOf(what, err)}
		}
	}
	return &spinePause{kind: PauseError, cause: causeOf(what, err)}
}

type spineHead struct {
	raw    []byte
	fields finality.HeaderFields
}

// head obtains the header of the finalized head by its hash, from the process or the provider.
func (r *spineRun) head(hash [32]byte) (spineHead, error) {
	raw, ok := r.sc.head(hash)
	if !ok {
		t0 := r.p.now()
		got, err := r.p.Exec.HeaderByHash(r.ctx, hash)
		r.note(t0)
		if err != nil {
			return spineHead{}, r.failed("the finalized head's header", err)
		}
		f, ferr := finality.ReadHeader(got)
		if ferr != nil || f.Hash != hash {
			return spineHead{}, &spinePause{kind: PauseError, cause: "the endpoint served a different block for the finalized head's hash"}
		}
		raw = got
		r.sc.putHead(hash, raw)
	}
	f, err := finality.ReadHeader(raw)
	if err != nil {
		return spineHead{}, &spinePause{kind: PauseError, cause: "the finalized head's header cannot be read"}
	}
	if err := finality.ReserveRow(r.ctx, len(raw)); err != nil {
		return spineHead{}, err
	}
	return spineHead{raw: raw, fields: f}, nil
}

// note adds the time since t0 to the new work of the attempt.
func (r *spineRun) note(t0 time.Time) {
	d := r.p.now().Sub(t0)
	if d < 0 {
		d = 0
	}
	r.spent += d
	if d > r.longest {
		r.longest = d
	}
}

func (r *spineRun) walk(c candidate) ([][]byte, error) {
	h0, err := r.head(c.execHash)
	if err != nil {
		return nil, err
	}
	r.have = 1
	if h0.fields.Number <= r.leg.Number {
		r.need = 1 // the head is the leg block (or below it: the verifier names that)
		return [][]byte{h0.raw}, nil
	}
	r.need = int(h0.fields.Number-r.leg.Number) + 1
	spans := PlanSpans(r.leg.Number, h0.fields.Number-1)
	want := h0.fields.ParentHash
	parts := make([][][]byte, 0, len(spans))
	for _, sp := range spans {
		e, err := r.span(sp, want)
		if err != nil {
			return nil, err
		}
		parts = append(parts, e.hs)
		want = e.parent
		r.have += sp.Count()
	}
	out := make([][]byte, 0, r.need)
	out = append(out, h0.raw)
	for _, hs := range parts {
		for j := len(hs) - 1; j >= 0; j-- {
			out = append(out, hs[j])
		}
	}
	return out, nil
}

func (r *spineRun) key(sp Span, want [32]byte) finality.CaptureKey {
	return finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: sp.End, L1Hash: want, Item: SpineItem(sp.Count())}
}

// span returns the checked chunk for sp whose last header has hash want: from the process, from the store, or from the provider.
func (r *spineRun) span(sp Span, want [32]byte) (*spineEntry, error) {
	k := spineKey{End: sp.End, Top: want, Count: sp.Count()}
	e, ok := r.sc.chunks.get(k)
	if ok {
		r.reused++
	} else if sp.Stored && r.p.Store != nil {
		enc, found, err := r.p.Store.Get(r.ctx, r.key(sp, want))
		if err != nil {
			return nil, r.failed("reading a kept spine chunk", err)
		}
		if found {
			if e, err = r.entry(enc, sp, want); err != nil {
				return nil, err
			}
			r.sc.chunks.put(k, e)
			r.reused++
			ok = true
		}
	}
	if !ok {
		var err error
		if e, err = r.fetch(sp, want, k); err != nil {
			return nil, err
		}
	}
	if err := finality.ReserveRow(r.ctx, len(e.enc)); err != nil {
		return nil, err
	}
	return e, nil
}

// entry checks stored bytes against the address they were read from. A fault is a named state, not a pause: the row is wrong.
func (r *spineRun) entry(enc []byte, sp Span, want [32]byte) (*spineEntry, error) {
	hs, f := decodeSpan(enc)
	if f != nil {
		return nil, spineRowInvalid(sp, f)
	}
	parent, f := checkSpan(hs, sp, want)
	if f != nil {
		return nil, spineRowInvalid(sp, f)
	}
	return &spineEntry{enc: enc, hs: hs, parent: parent}, nil
}

// fetch gets sp from the provider (new work, counted against the attempt's budget), checks that it chains to want, keeps it and returns it.
func (r *spineRun) fetch(sp Span, want [32]byte, k spineKey) (*spineEntry, error) {
	if !BudgetAllows(r.spent, r.longest, r.budget) {
		return nil, &spinePause{kind: PauseBudget, cause: fmt.Sprintf("the attempt's budget of %s for new work is spent", r.budget.Round(time.Second))}
	}
	rel, err := r.sc.locks.acquire(r.ctx, k)
	if err != nil {
		return nil, r.failed("waiting for another leg's fetch of the same chunk", err)
	}
	defer rel()
	if e, ok := r.sc.chunks.get(k); ok { // another leg fetched it while this one waited
		r.reused++
		return e, nil
	}
	t0 := r.p.now()
	hs, err := r.p.Exec.HeadersByNumber(r.ctx, sp.Start, sp.End)
	r.note(t0)
	if err != nil {
		return nil, r.failed(fmt.Sprintf("fetching headers %d..%d", sp.Start, sp.End), err)
	}
	parent, f := checkSpan(hs, sp, want)
	if f != nil {
		// the provider served headers that do not chain to the finalized head: it is the provider that is wrong, nothing was kept
		return nil, &spinePause{kind: PauseError, cause: ethrpc.RedactText(fmt.Sprintf("the endpoint served headers %d..%d that do not chain to the finalized head (%s)", sp.Start, sp.End, f.Error()))}
	}
	enc := encodeSpan(hs)
	dec, _ := decodeSpan(enc) // the headers of the kept entry are slices of its bytes, so the provider's copies can be freed
	e := &spineEntry{enc: enc, hs: dec, parent: parent}
	r.sc.chunks.put(k, e) // in process first: a store that fails now loses no progress
	r.fetched += sp.Count()
	r.chunks++
	if sp.Stored && r.p.Store != nil {
		if err := r.p.Store.Put(r.ctx, r.key(sp, want), enc); err != nil {
			if errors.Is(err, finality.ErrCaptureConflict) {
				return nil, spineRowInvalid(sp, &spineFault{Reason: SpineRowConflict})
			}
			return nil, r.failed("keeping a spine chunk", err)
		}
	}
	return e, nil
}
