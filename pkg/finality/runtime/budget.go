// Copyright 2026 Certen Protocol

package runtime

import (
	"container/list"
	"context"
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
	items map[string]int64
	total int64
}

// BudgetedStore enforces the V2_SPEC_S7 2.8 capture bound in front of the durable store: no single row, and no single captured L1
// block (the rows one batch-inbox transaction or one rollup event leaves), exceeds MaxLegBytes. A Put over the bound is
// refused with the named state finality_evidence_too_large{part, count, limit}, is counted
// (certen_finality_capture_refused_total) and stores NOTHING: a partial capture of a block is never written, so a builder
// never attests from half a block. Retention deletes nothing: the inner store is insert-only and this wrapper has no delete.
//
// The accounting is per process; a restart recounts a block from the rows it writes again (an identical re-Put is a no-op in
// the store and counts once here). The durable bound that survives restarts is the store's own insert-only key.
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

var _ finality.CaptureStore = (*BudgetedStore)(nil)

// NewBudgetedStore wraps inner with the per-leg bound.
func NewBudgetedStore(inner finality.CaptureStore, maxLegBytes int64) *BudgetedStore {
	return &BudgetedStore{Inner: inner, MaxLegBytes: maxLegBytes}
}

func (s *BudgetedStore) refuse(k finality.CaptureKey, part string, count, limit int64) error {
	st := finality.EvidenceTooLarge(part, uint64(count), uint64(limit))
	if s.OnRefused != nil {
		s.OnRefused(k.Chain, st.Code)
	} else {
		metrics.IncFinalityCaptureRefused(k.Chain, st.Code)
	}
	return st
}

// Put implements finality.CaptureStore.
func (s *BudgetedStore) Put(ctx context.Context, k finality.CaptureKey, data []byte) error {
	n := int64(len(data))
	limit := s.MaxLegBytes
	if limit <= 0 {
		limit = DefaultMaxCaptureBytesPerLeg
	}
	if n > limit {
		return s.refuse(k, "capture.row:"+k.Item, n, limit)
	}
	gk := groupKey{k.Chain, k.L1Block, k.L1Hash}
	s.mu.Lock()
	if s.groups == nil {
		s.groups, s.lru = map[groupKey]*list.Element{}, list.New()
	}
	var g *group
	if e, ok := s.groups[gk]; ok {
		s.lru.MoveToFront(e)
		g = e.Value.(*group)
	} else {
		g = &group{key: gk, items: map[string]int64{}}
		s.groups[gk] = s.lru.PushFront(g)
		for s.lru.Len() > maxBudgetGroups {
			old := s.lru.Back()
			s.lru.Remove(old)
			delete(s.groups, old.Value.(*group).key)
		}
	}
	prev, had := g.items[k.Item]
	total := g.total - prev + n
	if total > limit {
		s.mu.Unlock()
		return s.refuse(k, "capture.block", total, limit)
	}
	s.mu.Unlock()

	if err := s.Inner.Put(ctx, k, data); err != nil {
		return err
	}
	s.mu.Lock()
	if cur, ok := s.groups[gk]; ok {
		g = cur.Value.(*group)
		prev2, had2 := g.items[k.Item]
		g.items[k.Item] = n
		g.total += n - prev2
		had = had2
	}
	s.mu.Unlock()
	if !had {
		if s.OnPut != nil {
			s.OnPut(k.Chain, len(data))
		} else {
			metrics.AddFinalityCaptureBytes(k.Chain, len(data))
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
// BlockBounds forwards finality.BlockBounder to the inner store (its fast form when it has one, else the key listing).
func (s *BudgetedStore) BlockBounds(ctx context.Context, chain uint64, item string) (uint64, uint64, bool, error) {
	return finality.BlockBoundsOf(ctx, s.Inner, chain, item)
}

func (s *BudgetedStore) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	return s.Inner.ListByRange(ctx, chain, from, to, prefix)
}
