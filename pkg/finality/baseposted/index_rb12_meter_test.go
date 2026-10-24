// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// meterStore counts what a build reads of a capture store: the bytes of the rows it Gets, the rows it Gets and the keys its listings return.
type meterStore struct {
	finality.CaptureStore
	bytes atomic.Int64
	gets  atomic.Int64
	keys  atomic.Int64
}

func (m *meterStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	b, ok, err := m.CaptureStore.Get(ctx, k)
	m.bytes.Add(int64(len(b)))
	m.gets.Add(1)
	return b, ok, err
}

func (m *meterStore) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	ks, err := m.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
	m.keys.Add(int64(len(ks)))
	return ks, err
}

// BlockBounds forwards the aggregate query of a store that has it (the database store does).
func (m *meterStore) BlockBounds(ctx context.Context, chain uint64, item string) (uint64, uint64, bool, error) {
	if bb, ok := m.CaptureStore.(finality.BlockBounder); ok {
		return bb.BlockBounds(ctx, chain, item)
	}
	ks, err := m.CaptureStore.ListByRange(ctx, chain, 0, finality.MaxCaptureBlock, item)
	if err != nil {
		return 0, 0, false, err
	}
	var lo, hi uint64
	ok := false
	for _, k := range ks {
		if k.Item != item {
			continue
		}
		if !ok || k.L1Block < lo {
			lo = k.L1Block
		}
		if !ok || k.L1Block > hi {
			hi = k.L1Block
		}
		ok = true
	}
	return lo, hi, ok, nil
}

func (m *meterStore) reset() { m.bytes.Store(0); m.gets.Store(0); m.keys.Store(0) }

// buildCost is what one search cost: stored bytes read, rows read, keys listed, the peak heap above the start and the wall time.
type buildCost struct {
	bytes, gets, keys int64
	heap              uint64
	wall              time.Duration
}

// measureSearch runs the builder's search for the leg timestamp ts of an L2 block, with the heap sampled every millisecond (the method
// of V-RB12-P0-LIVE).
func measureSearch(t testing.TB, b *Builder, m *meterStore, bp *Pins, ts uint64) (searched, error, buildCost) {
	t.Helper()
	m.reset()
	runtime.GC()
	var m0 runtime.MemStats
	runtime.ReadMemStats(&m0)
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak.Load() {
				peak.Store(ms.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	start := time.Now()
	hold := finality.NewHold(context.Background(), uint64(Chain), "test_search")
	sr, err := b.search(context.Background(), bp, finality.HeaderFields{Number: 48333406, Timestamp: ts}, hold)
	wall := time.Since(start)
	hold.Release()
	close(stop)
	<-done
	c := buildCost{bytes: m.bytes.Load(), gets: m.gets.Load(), keys: m.keys.Load(), wall: wall}
	if p := peak.Load(); p > m0.HeapAlloc {
		c.heap = p - m0.HeapAlloc
	}
	return sr, err, c
}
