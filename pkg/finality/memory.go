// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"sync"

	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-F3 (live, 2026-10-23): seven validators were killed by the host's OOM killer minutes after the RB11 deploy. A Base l1_posted
// build read EVERY captured block into memory for each leg (1.4 x the capture store: about 2.1 GB at the 1.5 GB the production table
// held), the upgrader ran four such builds at once in each process, and nothing bounded the sum. The builders now read only the
// window of the store a leg can need, and everything a builder holds is reserved here first: a request the process budget cannot
// cover is the named state finality_memory_budget_exceeded (class U, nothing is built, the leg is asked again later), never a crash.

// EnvMemoryBudget is the per-process byte budget of the finality builders' in-flight working sets. The default is DefaultMemoryBudget.
const EnvMemoryBudget = "CERTEN_FINALITY_MEMORY_BUDGET_BYTES"

// DefaultMemoryBudget is the default budget: 2 GiB of reserved working set per process. The upgrader additionally holds new attempts
// back while the Go heap in use is above twice the budget (HeapGate), so the process stays well under a 6 GiB container limit.
const DefaultMemoryBudget int64 = 2 << 30

// MinMemoryBudget is the smallest accepted budget: below it no leg's evidence (a few MiB, Base l1_posted about 1 MiB of blobs plus
// the window's rows) could be reserved at all, and a budget that refuses everything is a misconfiguration, not a limit.
const MinMemoryBudget int64 = 64 << 20

// CodeMemoryBudget is the named state of a reservation (or an attempt) the memory budget refuses (go_operational, class U).
const CodeMemoryBudget = "finality_memory_budget_exceeded"

// MemoryBudgetFromEnv reads EnvMemoryBudget (bytes). A value that is not a number of at least MinMemoryBudget refuses startup by name.
func MemoryBudgetFromEnv() (int64, error) {
	return envvar.Int64(EnvMemoryBudget, DefaultMemoryBudget, MinMemoryBudget)
}

// HeapGate is the heap in use above which no new leg attempt starts: twice the budget.
func HeapGate(budget int64) uint64 { return uint64(budget) * 2 }

// MemoryBudget counts the bytes the finality builders of one process hold at once. It is safe for concurrent use.
type MemoryBudget struct {
	limit int64
	mu    sync.Mutex
	used  int64
}

// NewMemoryBudget returns a budget of limit bytes (limit <= 0 means DefaultMemoryBudget).
func NewMemoryBudget(limit int64) *MemoryBudget {
	if limit <= 0 {
		limit = DefaultMemoryBudget
	}
	return &MemoryBudget{limit: limit}
}

// Limit is the budget in bytes.
func (b *MemoryBudget) Limit() int64 { return b.limit }

// Used is the number of bytes reserved now.
func (b *MemoryBudget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Reserve takes n bytes for what (a short token naming the working set) of chain, or returns the named state
// finality_memory_budget_exceeded carrying what was asked, what is reserved and the limit. The returned release gives the bytes back;
// it is safe to call more than once. A nil budget reserves nothing and always succeeds.
func (b *MemoryBudget) Reserve(chain uint64, what string, n int64) (release func(), err error) {
	if b == nil || n <= 0 {
		return func() {}, nil
	}
	b.mu.Lock()
	if b.used+n > b.limit {
		used := b.used
		b.mu.Unlock()
		metrics.IncFinalityMemoryRefused(chain, what)
		return func() {}, NewState(CodeMemoryBudget, "chain", chain, "what", what, "requested", uint64(n), "in_use", uint64(used), "limit", uint64(b.limit))
	}
	b.used += n
	b.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			b.used -= n
			b.mu.Unlock()
		})
	}, nil
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
// refusal is the named state finality_memory_budget_exceeded and the caller must stop reading.
func ReserveRow(ctx context.Context, n int) error {
	h, _ := ctx.Value(holdKey{}).(*Hold)
	if h == nil {
		return nil
	}
	return h.Add(RowCost(n))
}

// Hold accumulates reservations of one build and gives them all back at once.
type Hold struct {
	ctx     context.Context
	chain   uint64
	what    string
	release []func()
}

// NewHold starts a hold for what of chain against the budget ctx carries.
func NewHold(ctx context.Context, chain uint64, what string) *Hold {
	return &Hold{ctx: ctx, chain: chain, what: what}
}

// Add reserves n more bytes (the budget of ctx; nothing when ctx carries none).
func (h *Hold) Add(n int64) error {
	rel, err := MemoryBudgetOf(h.ctx).Reserve(h.chain, h.what, n)
	if err != nil {
		return err
	}
	h.release = append(h.release, rel)
	return nil
}

// Release gives every reservation of the hold back.
func (h *Hold) Release() {
	for _, r := range h.release {
		r()
	}
	h.release = nil
}
