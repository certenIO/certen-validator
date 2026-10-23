// Copyright 2026 Certen Protocol

package runtime

import (
	"container/list"
	"context"
	"sort"
	"sync"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// maxBudgetGroups bounds the in-memory accounting of the budgeted store (one entry per captured L1 block).
const maxBudgetGroups = 8192

type groupKey struct {
	chain uint64
	block uint64
	hash  [32]byte
}

type group struct {
	key   groupKey
	items map[string]int64 // item -> bytes stored or reserved
	total int64
}

// BudgetedStore enforces the V2_SPEC_S7 2.8 capture bound in front of the durable store: no single row, and no single captured L1
// block (the rows one batch-inbox transaction or one rollup event leaves), exceeds MaxLegBytes.
//
// The unit of admission is a PutBlock: the rows of one captured block are RESERVED against the block's budget before the first row
// is written, atomically with every other writer of this process, and the whole call is refused if the reservation does not fit - so
// a capture of a block is stored whole or not at all, and the row that names the block as captured (the inbox row of a Base block,
// the batch record of an Arbitrum batch) never lists rows that were not written. A Put is a PutBlock of one row; a capturer that
// writes a block's rows with several Puts gets the bound per row, not per block, which is why the capturers call finality.PutBlock.
// A refusal is the named state finality_evidence_too_large{part, count, limit}, is counted
// (certen_finality_capture_refused_total) and stores NOTHING. Retention deletes nothing: the inner store is insert-only and this
// wrapper has no delete.
//
// The accounting of a block is SEEDED from the durable store the first time this process touches the block (and again after the
// block's entry was evicted), so a restart, or rows another validator wrote into the same database, count against the bound as
// they stand. A row another process adds to a block after the seed is not counted until the block is seeded again; the durable
// guarantee that survives everything is the store's own insert-only key.
type BudgetedStore struct {
	Inner       finality.CaptureStore
	MaxLegBytes int64
	// OnPut is told of every stored row's size (default: certen_finality_capture_bytes_total{chain}).
	OnPut func(chain uint64, n int)
	// OnRefused is told of every refusal (default: certen_finality_capture_refused_total{chain,code}).
	OnRefused func(chain uint64, code string)

	mu     sync.Mutex
	groups map[groupKey]*list.Element
	lru    *list.List
}

var (
	_ finality.CaptureStore = (*BudgetedStore)(nil)
	_ finality.BlockPutter  = (*BudgetedStore)(nil)
)

// NewBudgetedStore wraps inner with the per-leg bound.
func NewBudgetedStore(inner finality.CaptureStore, maxLegBytes int64) *BudgetedStore {
	return &BudgetedStore{Inner: inner, MaxLegBytes: maxLegBytes}
}

func (s *BudgetedStore) limit() int64 {
	if s.MaxLegBytes <= 0 {
		return DefaultMaxCaptureBytesPerLeg
	}
	return s.MaxLegBytes
}

func (s *BudgetedStore) refuse(chain uint64, part string, count, limit int64) error {
	st := finality.EvidenceTooLarge(part, uint64(count), uint64(limit))
	if s.OnRefused != nil {
		s.OnRefused(chain, st.Code)
	} else {
		metrics.IncFinalityCaptureRefused(chain, st.Code)
	}
	return st
}

// ensure makes sure the block has an accounting entry, seeding it from the durable store when it has none.
func (s *BudgetedStore) ensure(ctx context.Context, gk groupKey) error {
	s.mu.Lock()
	if _, ok := s.groups[gk]; ok {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	stored, err := s.Inner.ListByBlock(ctx, gk.chain, gk.block)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[gk]; ok { // another goroutine seeded it first; its entry already holds what it reserved since
		return nil
	}
	if s.groups == nil {
		s.groups, s.lru = map[groupKey]*list.Element{}, list.New()
	}
	g := &group{key: gk, items: map[string]int64{}}
	for _, r := range stored {
		if r.L1Hash == gk.hash {
			g.items[r.Item] = int64(len(r.Bytes))
			g.total += int64(len(r.Bytes))
		}
	}
	s.groups[gk] = s.lru.PushFront(g)
	for s.lru.Len() > maxBudgetGroups {
		old := s.lru.Back()
		s.lru.Remove(old)
		delete(s.groups, old.Value.(*group).key)
	}
	return nil
}

// Put implements finality.CaptureStore: a block of one row.
func (s *BudgetedStore) Put(ctx context.Context, k finality.CaptureKey, data []byte) error {
	return s.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: k, Bytes: data}})
}

// PutBlock implements finality.BlockPutter: it reserves the planned total of every block the rows belong to, refuses the whole call
// if one reservation does not fit, and only then writes. Rows of one call may belong to several blocks (L1 heights or hashes); each
// has its own budget.
func (s *BudgetedStore) PutBlock(ctx context.Context, rows []finality.CaptureRow) error {
	limit := s.limit()
	for _, r := range rows {
		if n := int64(len(r.Bytes)); n > limit {
			return s.refuse(r.Chain, "capture.row:"+r.Item, n, limit)
		}
	}
	keys := map[groupKey]bool{}
	for _, r := range rows {
		keys[groupKey{r.Chain, r.L1Block, r.L1Hash}] = true
	}
	ordered := make([]groupKey, 0, len(keys))
	for gk := range keys {
		ordered = append(ordered, gk)
	}
	sort.Slice(ordered, func(i, j int) bool { // a fixed order, so concurrent calls seed and reserve identically
		a, b := ordered[i], ordered[j]
		if a.chain != b.chain {
			return a.chain < b.chain
		}
		if a.block != b.block {
			return a.block < b.block
		}
		return string(a.hash[:]) < string(b.hash[:])
	})

	// reserve: under one lock, every block's planned addition is checked, and only if all fit are they all applied. A block whose entry
	// was evicted between its seed and the reservation is seeded again (a bounded number of times) and never counted from nothing.
	type reservation struct {
		g     *group
		items map[string]int64 // the items this call newly reserved
	}
	var reserved map[groupKey]*reservation
	for attempt := 0; ; attempt++ {
		for _, gk := range ordered {
			if err := s.ensure(ctx, gk); err != nil {
				return err
			}
		}
		s.mu.Lock()
		reserved = map[groupKey]*reservation{}
		evicted := false
		for _, gk := range ordered {
			el, ok := s.groups[gk]
			if !ok {
				evicted = true
				break
			}
			s.lru.MoveToFront(el)
			g := el.Value.(*group)
			add := map[string]int64{}
			var sum int64
			for _, r := range rows {
				if (groupKey{r.Chain, r.L1Block, r.L1Hash}) != gk {
					continue
				}
				if _, have := g.items[r.Item]; have {
					continue // already stored or reserved: an identical re-put counts once, a conflicting one is the store's refusal
				}
				if _, dup := add[r.Item]; dup {
					continue
				}
				add[r.Item] = int64(len(r.Bytes))
				sum += int64(len(r.Bytes))
			}
			if total := g.total + sum; total > limit {
				s.mu.Unlock()
				return s.refuse(gk.chain, "capture.block", total, limit)
			}
			reserved[gk] = &reservation{g: g, items: add}
		}
		if evicted && attempt < 3 {
			s.mu.Unlock()
			continue
		}
		if evicted {
			s.mu.Unlock()
			return s.refuse(ordered[0].chain, "capture.block", limit+1, limit) // the accounting cannot hold the block: refused, never counted from nothing
		}
		for _, res := range reserved {
			for item, n := range res.items {
				res.g.items[item] = n
				res.g.total += n
			}
		}
		s.mu.Unlock()
		break
	}

	// write; a call the store refuses (a conflict, an I/O error) gives its reservation back, except for rows that are stored
	written := map[finality.CaptureKey]bool{}
	var err error
	if bp, ok := s.Inner.(finality.BlockPutter); ok {
		if err = bp.PutBlock(ctx, rows); err == nil {
			for _, r := range rows {
				written[r.CaptureKey] = true
			}
		}
	} else {
		for _, r := range rows {
			if err = s.Inner.Put(ctx, r.CaptureKey, r.Bytes); err != nil {
				break
			}
			written[r.CaptureKey] = true
		}
	}
	s.mu.Lock()
	for gk, res := range reserved {
		for item, n := range res.items {
			if written[finality.CaptureKey{Chain: gk.chain, L1Block: gk.block, L1Hash: gk.hash, Item: item}] {
				continue
			}
			if cur, ok := res.g.items[item]; ok && cur == n {
				delete(res.g.items, item)
				res.g.total -= n
			}
		}
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	for gk, res := range reserved {
		for _, n := range res.items {
			if s.OnPut != nil {
				s.OnPut(gk.chain, int(n))
			} else {
				metrics.AddFinalityCaptureBytes(gk.chain, int(n))
			}
		}
	}
	return nil
}

// Get implements finality.CaptureStore.
func (s *BudgetedStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	return s.Inner.Get(ctx, k)
}

// ListByBlock implements finality.CaptureStore.
func (s *BudgetedStore) ListByBlock(ctx context.Context, chain, l1Block uint64) ([]finality.CaptureRow, error) {
	return s.Inner.ListByBlock(ctx, chain, l1Block)
}

// ListByRange implements finality.CaptureStore.
func (s *BudgetedStore) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	return s.Inner.ListByRange(ctx, chain, from, to, prefix)
}
