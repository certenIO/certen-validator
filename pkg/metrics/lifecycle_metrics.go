// Copyright 2026 Certen Protocol
//
// Intent lifecycle row metrics (RB8-F, defect D4).
//
// # WHY THESE EXIST
//
// Discovery wrote an intent's lifecycle row in one attempt and only logged a failure. Four settled intents were left
// without a row (2026-10-18), their proof cycle died "intent lifecycle not found", and nothing but a log line said so.
// The row is now written with a bounded retry, kept on a durable queue while it cannot be written, and created by
// the proof cycle when it is still missing there. These series make each of those visible.
//
//	certen_lifecycle_upsert_attempts_total{result}   every attempt to write a discovered intent's row (ok, error, timeout)
//	certen_lifecycle_upsert_duration_seconds         how long an attempt took (a stalled database shows here)
//	certen_lifecycle_upsert_retried_total            writes that needed more than one attempt
//	certen_lifecycle_upsert_queued_total             writes that exhausted their attempts and went to the queue
//	certen_lifecycle_upsert_queue_depth              rows waiting on the queue now (an intent with no row yet)
//	certen_lifecycle_upsert_queue_oldest_seconds     age of the oldest waiting row
//	certen_lifecycle_created_by_proof_cycle_total    rows the proof cycle had to create because discovery had not
//	certen_db_pool_*                                 database/sql pool: open, in use, waits and wait time
//	certen_db_lock_waiters                           sessions of this database waiting on a lock (pg_stat_activity)
package metrics

import (
	"database/sql"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	lifecycleUpsertAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certen_lifecycle_upsert_attempts_total",
		Help: "Attempts to write a discovered intent's lifecycle row, by result (ok, error, timeout).",
	}, []string{"result"})
	lifecycleUpsertDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "certen_lifecycle_upsert_duration_seconds",
		Help:    "Duration of one attempt to write a discovered intent's lifecycle row.",
		Buckets: []float64{0.005, 0.025, 0.1, 0.5, 1, 2.5, 5, 10, 20},
	})
	lifecycleUpsertRetried = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_lifecycle_upsert_retried_total",
		Help: "Lifecycle row writes that needed more than one attempt.",
	})
	lifecycleUpsertQueued = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_lifecycle_upsert_queued_total",
		Help: "Lifecycle row writes that exhausted their attempts and were kept on the durable queue.",
	})
	lifecycleUpsertQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_lifecycle_upsert_queue_depth",
		Help: "Discovered intents whose lifecycle row is waiting on the queue (they have no row yet).",
	})
	lifecycleUpsertQueueOldest = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_lifecycle_upsert_queue_oldest_seconds",
		Help: "Age of the oldest lifecycle row write waiting on the queue; 0 when the queue is empty.",
	})
	lifecycleCreatedByProofCycle = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_lifecycle_created_by_proof_cycle_total",
		Help: "Lifecycle rows the proof cycle created because discovery had not written them.",
	})
	dbLockWaiters = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certen_db_lock_waiters",
		Help: "Sessions of this database waiting on a lock when last sampled (pg_stat_activity).",
	})
	dbLockProbeErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certen_db_lock_probe_errors_total",
		Help: "Samples of the database's lock waiters that failed.",
	})
)

// RecordLifecycleUpsertAttempt records one attempt: result is "ok", "error" or "timeout".
func RecordLifecycleUpsertAttempt(result string, d time.Duration) {
	lifecycleUpsertAttempts.WithLabelValues(result).Inc()
	lifecycleUpsertDuration.Observe(d.Seconds())
}

// RecordLifecycleUpsertRetried counts a write that needed more than one attempt.
func RecordLifecycleUpsertRetried() { lifecycleUpsertRetried.Inc() }

// RecordLifecycleUpsertQueued counts a write kept on the queue after its attempts ran out.
func RecordLifecycleUpsertQueued() { lifecycleUpsertQueued.Inc() }

// SetLifecycleUpsertQueue records the queue's depth and the age of its oldest entry.
func SetLifecycleUpsertQueue(depth int, oldest time.Duration) {
	lifecycleUpsertQueueDepth.Set(float64(depth))
	lifecycleUpsertQueueOldest.Set(oldest.Seconds())
}

// RecordLifecycleCreatedByProofCycle counts a row the proof cycle created.
func RecordLifecycleCreatedByProofCycle() { lifecycleCreatedByProofCycle.Inc() }

// SetDBLockWaiters records the sessions waiting on a lock.
func SetDBLockWaiters(n int) { dbLockWaiters.Set(float64(n)) }

// RecordDBLockProbeError counts a failed sample.
func RecordDBLockProbeError() { dbLockProbeErrors.Inc() }

var dbPoolOnce sync.Once

// RegisterDBPool exposes one database/sql pool's statistics. The first call registers; a later call (a second
// client in a test) is ignored, never a duplicate-registration panic.
func RegisterDBPool(stats func() sql.DBStats) {
	dbPoolOnce.Do(func() {
		prometheus.MustRegister(
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "certen_db_pool_open_connections", Help: "Connections open in the pool, in use and idle."},
				func() float64 { return float64(stats().OpenConnections) }),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "certen_db_pool_in_use_connections", Help: "Connections currently in use."},
				func() float64 { return float64(stats().InUse) }),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "certen_db_pool_max_open_connections", Help: "The pool's limit on open connections."},
				func() float64 { return float64(stats().MaxOpenConnections) }),
			prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "certen_db_pool_wait_total", Help: "Times a caller had to wait for a free connection."},
				func() float64 { return float64(stats().WaitCount) }),
			prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "certen_db_pool_wait_seconds_total", Help: "Total time callers waited for a free connection."},
				func() float64 { return stats().WaitDuration.Seconds() }),
		)
	})
}

// registerLifecycleMetrics is called from RegisterMetrics.
func registerLifecycleMetrics() {
	prometheus.MustRegister(lifecycleUpsertAttempts)
	prometheus.MustRegister(lifecycleUpsertDuration)
	prometheus.MustRegister(lifecycleUpsertRetried)
	prometheus.MustRegister(lifecycleUpsertQueued)
	prometheus.MustRegister(lifecycleUpsertQueueDepth)
	prometheus.MustRegister(lifecycleUpsertQueueOldest)
	prometheus.MustRegister(lifecycleCreatedByProofCycle)
	prometheus.MustRegister(dbLockWaiters)
	prometheus.MustRegister(dbLockProbeErrors)
}

// Recommended alert rules:
//
//   - alert: CertenLifecycleRowsQueued
//     expr: certen_lifecycle_upsert_queue_depth > 0
//     for: 10m
//     labels: {severity: warning}
//     annotations:
//     summary: "Discovered intents have no lifecycle row yet (the database refused the write for 10 minutes); their proof cycle will create it, but the gateway reads 404 until then"
//
//   - alert: CertenLifecycleUpsertFailing
//     expr: increase(certen_lifecycle_upsert_attempts_total{result!="ok"}[15m]) > 5
//     labels: {severity: warning}
//     annotations:
//     summary: "Lifecycle row writes are failing; see certen_lifecycle_upsert_duration_seconds and certen_db_pool_wait_seconds_total"
//
//   - alert: CertenLifecycleRowCreatedByProofCycle
//     expr: increase(certen_lifecycle_created_by_proof_cycle_total[1h]) > 0
//     labels: {severity: info}
//     annotations:
//     summary: "A proof cycle had to create an intent's lifecycle row: discovery did not; read the [LIFECYCLE] lines of that intent"
//
//   - alert: CertenDBPoolWaiting
//     expr: rate(certen_db_pool_wait_seconds_total[5m]) > 0.5 or certen_db_lock_waiters > 0
//     for: 5m
//     labels: {severity: warning}
//     annotations:
//     summary: "Callers wait for a database connection or sessions wait on a lock"
