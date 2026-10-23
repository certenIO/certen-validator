// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"sync"
	"time"
)

// ---- a clock the tests move ----

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_790_000_000, 0).UTC()} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---- a provider with a cost model ----

// modelHeaders serves the headers of byNum/byHash and charges the fake clock for them: perHdr per header of a HeadersByNumber call. A call
// that would take longer than limit (a provider timeout, or the build's own) fails after charging limit and delivers NOTHING, which is
// what the production source does with the batches it had already fetched. hook may fail or alter a call.
type modelHeaders struct {
	byNum  map[uint64][]byte
	byHash map[[32]byte][]byte
	clock  *fakeClock
	perHdr time.Duration
	limit  time.Duration

	mu        sync.Mutex
	calls     [][2]uint64
	served    map[uint64]int
	hashCalls int
	hook      func(call int, from, to uint64, out [][]byte) ([][]byte, error)
}

func (m *modelHeaders) HeaderByHash(_ context.Context, h [32]byte) ([]byte, error) {
	m.mu.Lock()
	m.hashCalls++
	m.mu.Unlock()
	if b, ok := m.byHash[h]; ok {
		return b, nil
	}
	return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "model", Op: "headers", Reason: "unknown hash"}}}
}

func (m *modelHeaders) HeadersByNumber(_ context.Context, from, to uint64) ([][]byte, error) {
	m.mu.Lock()
	m.calls = append(m.calls, [2]uint64{from, to})
	call := len(m.calls)
	if m.served == nil {
		m.served = map[uint64]int{}
	}
	m.mu.Unlock()
	cost := time.Duration(to-from+1) * m.perHdr
	if m.clock != nil {
		if m.limit > 0 && cost > m.limit {
			m.clock.Advance(m.limit)
			return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "model", Op: "headers", Reason: "timeout"}}}
		}
		m.clock.Advance(cost)
	}
	var out [][]byte
	for n := from; n <= to; n++ {
		b, ok := m.byNum[n]
		if !ok {
			return nil, &SourceError{Failures: []EndpointFailure{{Endpoint: "model", Op: "headers", Reason: "unknown number"}}}
		}
		out = append(out, b)
	}
	m.mu.Lock()
	for n := from; n <= to; n++ {
		m.served[n]++
	}
	hook := m.hook
	m.mu.Unlock()
	if hook != nil {
		return hook(call, from, to, out)
	}
	return out, nil
}

func (m *modelHeaders) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// repeated is the number of header numbers served more than once, and the total served.
func (m *modelHeaders) repeated() (repeated, distinct int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.served {
		distinct++
		if n > 1 {
			repeated++
		}
	}
	return repeated, distinct
}

func (m *modelHeaders) firstFrom() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return 0
	}
	return m.calls[0][0]
}

func recordedModel(l recordedLeg, clk *fakeClock, perHdr, limit time.Duration) *modelHeaders {
	return &modelHeaders{byNum: l.hdrs.byNum, byHash: l.hdrs.byHash, clock: clk, perHdr: perHdr, limit: limit}
}
