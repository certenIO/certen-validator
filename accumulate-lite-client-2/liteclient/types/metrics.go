// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package types

import (
	"sync/atomic"
	"time"
)

// Metrics provides simple counters for monitoring lite client performance.
// These metrics help track cache efficiency and proof generation success rates.
type Metrics struct {
	// Cache metrics
	CacheHits      int64 `json:"cache_hits"`
	CacheMisses    int64 `json:"cache_misses"`
	CacheEvictions int64 `json:"cache_evictions"`

	// Proof metrics
	ProofRequests  int64 `json:"proof_requests"`
	ProofSuccesses int64 `json:"proof_successes"`
	ProofFailures  int64 `json:"proof_failures"`

	// Performance metrics
	AccountRequests int64 `json:"account_requests"`
	TotalLatencyMs  int64 `json:"total_latency_ms"`

	// Timestamps
	StartTime time.Time `json:"start_time"`
	LastReset time.Time `json:"last_reset"`
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	now := time.Now()
	return &Metrics{
		StartTime: now,
		LastReset: now,
	}
}

// RecordCacheHit increments the cache hit counter.
func (m *Metrics) RecordCacheHit() {
	atomic.AddInt64(&m.CacheHits, 1)
}

// RecordCacheMiss increments the cache miss counter.
func (m *Metrics) RecordCacheMiss() {
	atomic.AddInt64(&m.CacheMisses, 1)
}

// RecordCacheEviction increments the cache eviction counter.
func (m *Metrics) RecordCacheEviction() {
	atomic.AddInt64(&m.CacheEvictions, 1)
}

// RecordProofRequest increments the proof request counter.
func (m *Metrics) RecordProofRequest() {
	atomic.AddInt64(&m.ProofRequests, 1)
}

// RecordProofSuccess increments the proof success counter.
func (m *Metrics) RecordProofSuccess() {
	atomic.AddInt64(&m.ProofSuccesses, 1)
}

// RecordProofFailure increments the proof failure counter.
func (m *Metrics) RecordProofFailure() {
	atomic.AddInt64(&m.ProofFailures, 1)
}

// RecordAccountRequest records an account request and its latency.
func (m *Metrics) RecordAccountRequest(latencyMs int64) {
	atomic.AddInt64(&m.AccountRequests, 1)
	atomic.AddInt64(&m.TotalLatencyMs, latencyMs)
}

// GetCacheHitRate returns the cache hit rate as a percentage.
func (m *Metrics) GetCacheHitRate() float64 {
	hits := atomic.LoadInt64(&m.CacheHits)
	misses := atomic.LoadInt64(&m.CacheMisses)
	total := hits + misses

	if total == 0 {
		return 0.0
	}

	return float64(hits) / float64(total) * 100.0
}

// GetProofSuccessRate returns the proof success rate as a percentage.
func (m *Metrics) GetProofSuccessRate() float64 {
	successes := atomic.LoadInt64(&m.ProofSuccesses)
	requests := atomic.LoadInt64(&m.ProofRequests)

	if requests == 0 {
		return 0.0
	}

	return float64(successes) / float64(requests) * 100.0
}

// GetAverageLatencyMs returns the average request latency in milliseconds.
func (m *Metrics) GetAverageLatencyMs() float64 {
	total := atomic.LoadInt64(&m.TotalLatencyMs)
	requests := atomic.LoadInt64(&m.AccountRequests)

	if requests == 0 {
		return 0.0
	}

	return float64(total) / float64(requests)
}

// Reset resets all counters to zero.
func (m *Metrics) Reset() {
	atomic.StoreInt64(&m.CacheHits, 0)
	atomic.StoreInt64(&m.CacheMisses, 0)
	atomic.StoreInt64(&m.CacheEvictions, 0)
	atomic.StoreInt64(&m.ProofRequests, 0)
	atomic.StoreInt64(&m.ProofSuccesses, 0)
	atomic.StoreInt64(&m.ProofFailures, 0)
	atomic.StoreInt64(&m.AccountRequests, 0)
	atomic.StoreInt64(&m.TotalLatencyMs, 0)
	m.LastReset = time.Now()
}
