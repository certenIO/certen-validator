// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-F3 (live, 2026-10-23): seven validators were killed by the host's OOM killer minutes after the RB11 deploy. A Base l1_posted
// build read EVERY captured block into memory for each leg (1.4 x the capture store: about 2.1 GB at the 1.5 GB the production table
// held), the upgrader ran four such builds at once in each process, and nothing bounded the sum. The builders now read only the
// window of the store a leg can need, and everything a builder holds is reserved here first: a request the process budget cannot
// cover waits (bounded) for another build to release, and is the named state finality_memory_budget_exceeded when it still cannot be
// covered. That state is a hold of the PROCESS, not a failure of the leg (RB12-P0LIVE-FIX D2): nothing is built, the leg is asked
// again at the pending interval, and no back-off, suspect or failure count is charged to it.

// EnvMemoryBudget is the per-process byte budget of the finality builders' in-flight working sets. The default is DefaultMemoryBudget.
const EnvMemoryBudget = "CERTEN_FINALITY_MEMORY_BUDGET_BYTES"

// DefaultMemoryBudget is the default budget: 2 GiB of reserved working set per process. The upgrader additionally holds new attempts
// back while the Go heap in use is above twice the budget (HeapGate), so the process stays well under a 6 GiB container limit.
const DefaultMemoryBudget int64 = 2 << 30

// MinMemoryBudget is the smallest accepted budget: below it no leg's evidence (a few MiB, Base l1_posted about 1 MiB of blobs plus
// the window's rows) could be reserved at all, and a budget that refuses everything is a misconfiguration, not a limit.
const MinMemoryBudget int64 = 64 << 20

// DefaultMemoryWait is how long a reservation that does not fit waits for another build to release before it is refused by name. It is
// well inside BuildTimeout (5 minutes), so a build that waited still has its time to read.
const DefaultMemoryWait = 45 * time.Second

// CodeMemoryBudget is the named state of a reservation (or an attempt) the memory budget refuses (go_operational). The upgrader stores
// it as a pending row with the time of the next ask: a hold of the process, never a failure of the leg.
const CodeMemoryBudget = "finality_memory_budget_exceeded"

// MemoryBudgetFromEnv reads EnvMemoryBudget (bytes). A value that is not a number of at least MinMemoryBudget refuses startup by name.
func MemoryBudgetFromEnv() (int64, error) {
	return envvar.Int64(EnvMemoryBudget, DefaultMemoryBudget, MinMemoryBudget)
}

// HeapGate is the heap in use above which no new leg attempt starts: twice the budget.
func HeapGate(budget int64) uint64 { return uint64(budget) * 2 }

// ticket is one build in the budget: its age (builds are served oldest first), what it holds, and where it stands in a wait.
type ticket struct {
	age     uint64
	held    int64
	waiting bool // blocked in a reservation
	victim  bool // told to give up what it holds so that the others can go on
	yielded bool // was told so (its build must be run again after another build has finished)
}

// MemoryBudget counts the bytes the finality builders of one process hold at once. It is safe for concurrent use.
//
// A reservation that does not fit does not fail at once: it waits (at most Wait) for another build to release. Builds that all wait
// for each other would never be woken, so when EVERY build in the budget is blocked the youngest one that holds something gives it
// all back and is refused (it yields: the older builds can then finish, and the upgrader runs the yielded build again after one has).
// The oldest build is therefore never made to give up, and a request larger than the whole budget, or larger than what is left when
// the build holds all of it, is refused at once: waiting could not help it.
type MemoryBudget struct {
	limit int64
	wait  time.Duration

	mu       sync.Mutex
	used     int64
	age      uint64
	tickets  map[*ticket]struct{} // the builds in progress
	waiting  int                  // how many of them are blocked in a reservation
	finished uint64               // builds that ended without having yielded
	changed  chan struct{}        // closed (and replaced) whenever bytes are given back or the set of builds changes
}

// NewMemoryBudget returns a budget of limit bytes (limit <= 0 means DefaultMemoryBudget) whose reservations wait DefaultMemoryWait.
func NewMemoryBudget(limit int64) *MemoryBudget {
	if limit <= 0 {
		limit = DefaultMemoryBudget
	}
	return &MemoryBudget{limit: limit, wait: DefaultMemoryWait, tickets: map[*ticket]struct{}{}, changed: make(chan struct{})}
}

// WithWait sets how long a reservation that does not fit waits for a release (zero or less: it is refused at once). Call it before the
// budget is shared.
func (b *MemoryBudget) WithWait(d time.Duration) *MemoryBudget {
	b.wait = d
	return b
}

// Limit is the budget in bytes.
func (b *MemoryBudget) Limit() int64 { return b.limit }

// Wait is how long a reservation that does not fit waits for a release.
func (b *MemoryBudget) Wait() time.Duration { return b.wait }

// Used is the number of bytes reserved now.
func (b *MemoryBudget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// wake tells every waiter that something changed. b.mu is held.
func (b *MemoryBudget) wake() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// stopWait takes t out of the blocked count. b.mu is held.
func (b *MemoryBudget) stopWait(t *ticket) {
	if t != nil && t.waiting {
		t.waiting = false
		b.waiting--
	}
}

// yieldYoungest marks the youngest blocked build that holds something as the one to give it back. b.mu is held.
func (b *MemoryBudget) yieldYoungest() {
	var v *ticket
	for t := range b.tickets {
		if t.waiting && t.held > 0 && (v == nil || t.age > v.age) {
			v = t
		}
	}
	if v != nil && !v.victim {
		v.victim = true
		b.wake()
	}
}

// acquire takes n bytes for t (nil: a plain reservation that never waits). It reports whether they were granted and, when not, the bytes
// in use at the moment of the refusal.
func (b *MemoryBudget) acquire(ctx context.Context, t *ticket, n int64) (granted bool, used int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	defer b.stopWait(t)
	var timer *time.Timer
	expired := false
	for {
		if t != nil {
			if _, live := b.tickets[t]; !live { // the build ended (its root hold was released): nothing more is reserved for it
				return false, b.used
			}
		}
		if b.used+n <= b.limit {
			b.used += n
			if t != nil {
				t.held += n
				t.victim = false
			}
			return true, b.used
		}
		if t != nil && t.victim {
			t.victim = false
			t.yielded = true
			return false, b.used
		}
		if t == nil || b.wait <= 0 || n > b.limit || b.used == t.held || expired || ctx.Err() != nil {
			return false, b.used
		}
		if !t.waiting {
			t.waiting = true
			b.waiting++
		}
		if b.waiting >= len(b.tickets) {
			b.yieldYoungest()
			if t.victim {
				continue
			}
		}
		if timer == nil {
			timer = time.NewTimer(b.wait)
			defer timer.Stop()
		}
		ch := b.changed
		b.mu.Unlock()
		select {
		case <-ch:
		case <-timer.C:
			expired = true
		case <-ctx.Done():
		}
		b.mu.Lock()
	}
}

// reserve is acquire with the named refusal.
func (b *MemoryBudget) reserve(ctx context.Context, t *ticket, chain uint64, what string, n int64) error {
	granted, used := b.acquire(ctx, t, n)
	if granted {
		return nil
	}
	return b.refusal(chain, what, n, used)
}

func (b *MemoryBudget) refusal(chain uint64, what string, n, used int64) error {
	metrics.IncFinalityMemoryRefused(chain, what)
	return NewState(CodeMemoryBudget, "chain", chain, "what", what, "requested", uint64(n), "in_use", uint64(used), "limit", uint64(b.limit))
}

// give returns n bytes (t is the build they were held for; nil for a plain reservation).
func (b *MemoryBudget) give(t *ticket, n int64) {
	b.mu.Lock()
	b.used -= n
	if t != nil {
		t.held -= n
	}
	b.wake()
	b.mu.Unlock()
}

// newAge is the age of a build that starts now: later builds are younger.
func (b *MemoryBudget) newAge() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.age++
	return b.age
}

// join registers a build of the given age.
func (b *MemoryBudget) join(age uint64) *ticket {
	t := &ticket{age: age}
	b.mu.Lock()
	b.tickets[t] = struct{}{}
	b.mu.Unlock()
	return t
}

// leave gives back the n bytes of the build's root hold and takes the build out of the budget. It returns the number of builds that have
// ended without yielding (this one counts when it did not yield) and whether this one yielded.
func (b *MemoryBudget) leave(t *ticket, n int64) (finished uint64, yielded bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	t.held -= n
	b.stopWait(t)
	delete(b.tickets, t)
	if !t.yielded {
		b.finished++
	}
	b.wake()
	return b.finished, t.yielded
}

// waitFinished blocks until a build that did not yield has ended since mark, or no build is left in the budget, or d has passed or ctx
// is done. It reports whether the yielded build may be run again.
func (b *MemoryBudget) waitFinished(ctx context.Context, mark uint64, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	b.mu.Lock()
	for {
		if b.finished > mark || len(b.tickets) == 0 {
			b.mu.Unlock()
			return true
		}
		ch := b.changed
		b.mu.Unlock()
		select {
		case <-ch:
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		}
		b.mu.Lock()
	}
}

// Reserve takes n bytes for what (a short token naming the working set) of chain, or returns the named state
// finality_memory_budget_exceeded carrying what was asked, what is reserved and the limit. A plain reservation does not wait; the
// builders reserve through a Hold, which does. The returned release gives the bytes back; it is safe to call more than once. A nil
// budget reserves nothing and always succeeds.
func (b *MemoryBudget) Reserve(chain uint64, what string, n int64) (release func(), err error) {
	if b == nil || n <= 0 {
		return func() {}, nil
	}
	if err := b.reserve(context.Background(), nil, chain, what, n); err != nil {
		return func() {}, err
	}
	var once sync.Once
	return func() { once.Do(func() { b.give(nil, n) }) }, nil
}

type budgetKey struct{}

// WithMemoryBudget returns ctx carrying the budget the builders called under it must reserve against.
func WithMemoryBudget(ctx context.Context, b *MemoryBudget) context.Context {
	return context.WithValue(ctx, budgetKey{}, b)
}

// MemoryBudgetOf is the budget ctx carries (nil when none: tests and one-shot recorders run unbounded).
func MemoryBudgetOf(ctx context.Context) *MemoryBudget {
	b, _ := ctx.Value(budgetKey{}).(*MemoryBudget)
	return b
}

type holdKey struct{}

// WithHold returns ctx carrying the hold of one build: the generic loaders of capture rows reserve what they read against it
// (ReserveRow), so a builder that reads rows through them needs no accounting of its own.
func WithHold(ctx context.Context, h *Hold) context.Context {
	return context.WithValue(ctx, holdKey{}, h)
}

// RowCost is the heap a loaded row costs per stored byte, rounded up: measured 1.43 on Base blob rows (the row, the frame data decoded
// from it and the frames), taken as 3/2.
func RowCost(n int) int64 { return int64(n) * 3 / 2 }

// ReserveRow reserves the cost of n stored bytes just read against the hold ctx carries (none: unbounded, tests and recorders). A
// refusal is the named state finality_memory_budget_exceeded and the caller must stop reading. The wait for a release ends with ctx.
func ReserveRow(ctx context.Context, n int) error {
	h, _ := ctx.Value(holdKey{}).(*Hold)
	if h == nil {
		return nil
	}
	return h.AddCtx(ctx, RowCost(n))
}

// Hold accumulates the reservations of one build (or of a part of it) and gives them all back at once. Release is terminal: nothing
// can be reserved through a released hold, and a reservation racing with the release is given back. A Hold is safe for concurrent use.
type Hold struct {
	ctx    context.Context
	chain  uint64
	what   string
	budget *MemoryBudget
	t      *ticket
	root   bool // this hold started the build's ticket (a hold made under another hold of the build shares its ticket)

	mu       sync.Mutex
	closed   bool
	held     int64
	finished uint64 // set by Release of a root hold: builds ended without yielding at that moment
	yielded  bool   // set by Release of a root hold: the build gave up what it held for an older build
}

// NewHold starts a hold for what of chain against the budget ctx carries. Under a hold already in ctx it belongs to the same build.
func NewHold(ctx context.Context, chain uint64, what string) *Hold {
	return newHold(ctx, chain, what, 0)
}

// newHold is NewHold for a build of the given age (0: a build that starts now), so that a build run again keeps its place.
func newHold(ctx context.Context, chain uint64, what string, age uint64) *Hold {
	h := &Hold{ctx: ctx, chain: chain, what: what, budget: MemoryBudgetOf(ctx)}
	if h.budget == nil {
		return h
	}
	if parent, _ := ctx.Value(holdKey{}).(*Hold); parent != nil && parent.budget == h.budget && parent.t != nil {
		h.t = parent.t
		return h
	}
	if age == 0 {
		age = h.budget.newAge()
	}
	h.t, h.root = h.budget.join(age), true
	return h
}

// Add reserves n more bytes (the budget of ctx; nothing when ctx carries none). A released hold refuses by name.
func (h *Hold) Add(n int64) error { return h.AddCtx(h.ctx, n) }

// AddCtx is Add whose wait for a release ends with ctx.
func (h *Hold) AddCtx(ctx context.Context, n int64) error {
	if h.budget == nil || n <= 0 {
		return nil
	}
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return h.budget.refusal(h.chain, h.what+"/released", n, h.budget.Used())
	}
	if err := h.budget.reserve(ctx, h.t, h.chain, h.what, n); err != nil {
		return err
	}
	h.mu.Lock()
	if h.closed { // the hold was released while this reservation was being made: it is not kept
		h.mu.Unlock()
		h.budget.give(h.t, n)
		return h.budget.refusal(h.chain, h.what+"/released", n, h.budget.Used())
	}
	h.held += n
	h.mu.Unlock()
	return nil
}

// Release gives every reservation of the hold back. It is terminal and may be called more than once.
func (h *Hold) Release() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	n := h.held
	h.held = 0
	h.mu.Unlock()
	if h.budget == nil {
		return
	}
	if !h.root {
		if n > 0 {
			h.budget.give(h.t, n)
		}
		return
	}
	finished, yielded := h.budget.leave(h.t, n)
	h.mu.Lock()
	h.finished, h.yielded = finished, yielded
	h.mu.Unlock()
}

// Yielded reports, after Release of the root hold of a build, whether the build gave up what it held so that an older build could
// finish, and how many builds had ended without yielding by then. Such a build must be run again once another one has ended
// (MemoryBudget.waitFinished).
func (h *Hold) Yielded() (yielded bool, finished uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.yielded, h.finished
}
