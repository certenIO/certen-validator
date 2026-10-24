// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"sort"
	"sync"
)

// MemStore is the in-memory Store: the reference the conformance suite is written against. The check and the insert of a Put happen under
// one lock (known defect class 1).
type MemStore struct {
	mu   sync.Mutex
	rows map[Key][]byte
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return &MemStore{rows: map[Key][]byte{}} }

func (s *MemStore) Put(ctx context.Context, k Key, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := CheckKey(k); err != nil {
		return err
	}
	if len(data) > MaxItemBytes() {
		return ErrItemTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.rows[k]; ok {
		if bytes.Equal(old, data) {
			return nil
		}
		return ErrCaptureConflict
	}
	s.rows[k] = append([]byte(nil), data...)
	return nil
}

func (s *MemStore) Get(ctx context.Context, k Key) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.rows[k]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), b...), true, nil
}

func keyLess(a, b Key) bool {
	if c := bytes.Compare(a.BlockHash[:], b.BlockHash[:]); c != 0 {
		return c < 0
	}
	return a.Item < b.Item
}

func (s *MemStore) ListByAnchor(ctx context.Context, chain uint64, anchorID [32]byte) ([]Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Key{}
	for k := range s.rows {
		if k.Chain == chain && k.AnchorID == anchorID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return keyLess(out[i], out[j]) })
	return out, nil
}

func (s *MemStore) ListByBlock(ctx context.Context, chain uint64, anchorID, blockHash [32]byte) ([]Row, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Row{}
	for k, v := range s.rows {
		if k.Chain == chain && k.AnchorID == anchorID && k.BlockHash == blockHash {
			out = append(out, Row{Key: k, Bytes: append([]byte(nil), v...)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Item < out[j].Item })
	return out, nil
}
