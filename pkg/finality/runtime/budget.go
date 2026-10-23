// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"sort"
	"sync"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

type groupKey struct {
	chain uint64
	block uint64
	hash  [32]byte
}

// pending is a row some call of this process has reserved and not finished writing; holders is the number of in-flight calls that
// mean to write it (the first reserved it, later calls with the identical row joined it).
type pending struct {
	n       int64
	holders int
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
// What a block already holds is READ FROM THE DURABLE STORE AT EVERY CALL (the row sizes of the block, finality.BlockSizer when the
// store has it, else a block listing), not remembered from the first time this process touched the block: a restart, and rows
// another validator wrote into the same database since this process last looked, count against the bound as they stand. This process
// keeps the rows its own in-flight calls have reserved and not yet finished writing, and the read of the store, the decision and the
// reservation are ONE critical section (mu is held across the read, which is one size query per block): a call that reads after
// another call of this process has finished sees that call's rows in the store, and a call that reads while another is still writing
// sees that call's reservation (a reservation ends only after the write returned, or when the call panics, and a row visible in both
// is counted once). So two calls of one process never both fit into the same space. Calls of one process therefore wait for each
// other's size read, bounded by the context of the call that holds the lock. The one window that remains is between VALIDATORS: a row
// another validator writes into the block between this call's read and its write is counted by the next call, not this one. The
// durable guarantees that survive it are the store's insert-only key and that every validator runs the same capture, which writes the
// same rows; a bound that no concurrent writer of any process can cross would be a lock in the database (the per-block sum taken
// inside the PutBlock transaction), which is not part of this package.
type BudgetedStore struct {
	Inner       finality.CaptureStore
	MaxLegBytes int64
	// OnPut is told of every stored row's size (default: certen_finality_capture_bytes_total{chain}).
	OnPut func(chain uint64, n int)
	// OnRefused is told of every refusal (default: certen_finality_capture_refused_total{chain,code}).
	OnRefused func(chain uint64, code string)

	mu       sync.Mutex
	inflight map[groupKey]map[string]*pending
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

// stored reads the sizes of the rows the durable store holds for the block (chain, height, hash), by item.
func (s *BudgetedStore) stored(ctx context.Context, gk groupKey) (map[string]int64, error) {
	if bs, ok := s.Inner.(finality.BlockSizer); ok {
		return bs.BlockSizes(ctx, gk.chain, gk.block, gk.hash)
	}
	rows, err := s.Inner.ListByBlock(ctx, gk.chain, gk.block)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, r := range rows {
		if r.L1Hash == gk.hash {
			out[r.Item] = int64(len(r.Bytes))
		}
	}
	return out, nil
}

// Put implements finality.CaptureStore: a block of one row.
func (s *BudgetedStore) Put(ctx context.Context, k finality.CaptureKey, data []byte) error {
	return s.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: k, Bytes: data}})
}

// hold is what one call reserved in one block: the rows it newly reserved (with their sizes) and the rows of another in-flight call
// of this process that it joined.
type hold struct {
	fresh  map[string]int64
	joined map[string]bool
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
	sort.Slice(ordered, func(i, j int) bool { // a fixed order, so concurrent calls read and reserve identically
		a, b := ordered[i], ordered[j]
		if a.chain != b.chain {
			return a.chain < b.chain
		}
		if a.block != b.block {
			return a.block < b.block
		}
		return string(a.hash[:]) < string(b.hash[:])
	})
	holds, err := s.reserve(ctx, rows, ordered, limit)
	if err != nil {
		return err
	}

	// write; whatever the outcome - success, error or a panic out of the inner store - the call's reservations end with it: the rows it
	// wrote are in the store and the next call reads them there, the rows it did not write are free again
	err = func() error {
		defer s.release(holds)
		if bp, ok := s.Inner.(finality.BlockPutter); ok {
			return bp.PutBlock(ctx, rows)
		}
		for _, r := range rows {
			if err := s.Inner.Put(ctx, r.CaptureKey, r.Bytes); err != nil {
				return err
			}
		}
		return nil
	}()
	if err != nil {
		return err
	}
	for gk, h := range holds {
		for _, n := range h.fresh {
			if s.OnPut != nil {
				s.OnPut(gk.chain, int(n))
			} else {
				metrics.AddFinalityCaptureBytes(gk.chain, int(n))
			}
		}
	}
	return nil
}

// reserve reads what the store holds for every block of the call, checks the planned additions against it plus the reservations of
// the in-flight calls of this process, and reserves all of them or none. The read, the decision and the reservation happen under one
// hold of mu: see the type's comment.
func (s *BudgetedStore) reserve(ctx context.Context, rows []finality.CaptureRow, ordered []groupKey, limit int64) (map[groupKey]*hold, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := make(map[groupKey]map[string]int64, len(ordered))
	for _, gk := range ordered {
		m, err := s.stored(ctx, gk)
		if err != nil {
			return nil, err
		}
		held[gk] = m
	}
	holds := make(map[groupKey]*hold, len(ordered))
	for _, gk := range ordered {
		var total int64
		for _, n := range held[gk] {
			total += n
		}
		for item, p := range s.inflight[gk] {
			if _, visible := held[gk][item]; !visible {
				total += p.n // reserved by a call that has not finished writing it, so the read cannot show it yet
			}
		}
		h := &hold{fresh: map[string]int64{}, joined: map[string]bool{}}
		var sum int64
		for _, r := range rows {
			if (groupKey{r.Chain, r.L1Block, r.L1Hash}) != gk {
				continue
			}
			if _, have := held[gk][r.Item]; have {
				continue // already stored: an identical re-put counts once, a conflicting one is the store's refusal
			}
			if _, dup := h.fresh[r.Item]; dup || h.joined[r.Item] {
				continue
			}
			if _, mine := s.inflight[gk][r.Item]; mine {
				h.joined[r.Item] = true // counted in total by the call that reserved it; held on until this call has finished too
				continue
			}
			n := int64(len(r.Bytes))
			h.fresh[r.Item] = n
			sum += n
		}
		if total+sum > limit {
			return nil, s.refuse(gk.chain, "capture.block", total+sum, limit)
		}
		holds[gk] = h
	}
	if s.inflight == nil {
		s.inflight = map[groupKey]map[string]*pending{}
	}
	for gk, h := range holds {
		if s.inflight[gk] == nil {
			s.inflight[gk] = map[string]*pending{}
		}
		for item, n := range h.fresh {
			s.inflight[gk][item] = &pending{n: n, holders: 1}
		}
		for item := range h.joined {
			s.inflight[gk][item].holders++
		}
	}
	return holds, nil
}

// release ends a call's reservations (a row stays reserved while any other in-flight call of this process still means to write it).
func (s *BudgetedStore) release(holds map[groupKey]*hold) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for gk, h := range holds {
		release := func(item string) {
			if p := s.inflight[gk][item]; p != nil {
				if p.holders--; p.holders <= 0 {
					delete(s.inflight[gk], item)
				}
			}
		}
		for item := range h.fresh {
			release(item)
		}
		for item := range h.joined {
			release(item)
		}
		if len(s.inflight[gk]) == 0 {
			delete(s.inflight, gk)
		}
	}
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
