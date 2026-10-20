// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/certen/independant-validator/pkg/finality"
)

// editStore is a CaptureStore test double whose rows a test may rewrite, drop or re-key through rows. The production stores and
// finality.MemCaptureStore are insert-only; the builder tests need a store they can damage the way a faulty database would.
type editStore struct {
	mu   sync.Mutex
	rows map[CaptureKey][]byte
}

func newEditStore() *editStore { return &editStore{rows: map[CaptureKey][]byte{}} }

func (m *editStore) Put(_ context.Context, k CaptureKey, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.rows[k]; ok {
		if bytes.Equal(old, data) {
			return nil
		}
		return ErrCaptureConflict
	}
	m.rows[k] = append([]byte(nil), data...)
	return nil
}

func (m *editStore) Get(_ context.Context, k CaptureKey) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.rows[k]
	return append([]byte(nil), v...), ok, nil
}

func (m *editStore) ListByBlock(_ context.Context, chain, l1Block uint64) ([]finality.CaptureRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []finality.CaptureRow
	for k, v := range m.rows {
		if k.Chain == chain && k.L1Block == l1Block {
			out = append(out, finality.CaptureRow{CaptureKey: k, Bytes: append([]byte(nil), v...)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].L1Hash[:], out[j].L1Hash[:]); c != 0 {
			return c < 0
		}
		return out[i].Item < out[j].Item
	})
	return out, nil
}

func (m *editStore) ListByRange(_ context.Context, chain, from, to uint64, itemPrefix string) ([]CaptureKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CaptureKey
	for k := range m.rows {
		if k.Chain == chain && k.L1Block >= from && k.L1Block <= to && strings.HasPrefix(k.Item, itemPrefix) {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].L1Block != out[j].L1Block {
			return out[i].L1Block < out[j].L1Block
		}
		if c := bytes.Compare(out[i].L1Hash[:], out[j].L1Hash[:]); c != 0 {
			return c < 0
		}
		return out[i].Item < out[j].Item
	})
	return out, nil
}
