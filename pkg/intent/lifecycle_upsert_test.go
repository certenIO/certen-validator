// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"io"
	"log"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
)

// RB8-F (defect D4, production 2026-10-18T00:43-00:45Z): four of five intents in one Directory Network block were
// left without an intent_lifecycle row. Discovery logged "upsert intent lifecycle: context deadline exceeded" for
// each, on all seven validators, 0-1s after the intent was found - while the same discovery loop wrote its shadow
// proof rows to the same database in the same seconds. It was no database stall: processBlock's 30s context, made
// for the block search, was reused for the lifecycle write of every later intent of the block, and the first
// intent's processing (a ~6 minute certificate wait) had long expired it. The write was also a single attempt that
// only logged, so nothing ever wrote the row again.

// rowLog is a fake lifecycle table: it records every call, the state of the context it was called with, and can be
// made to fail.
type rowLog struct {
	mu        sync.Mutex
	rows      map[string]string // intent id -> "single" | "multi"
	calls     int
	expiredOn int // calls whose context was already done when the write began
	ctxs      []context.Context
	failFirst int   // the first N calls fail with failErr
	failErr   error // nil: context.DeadlineExceeded
	failAll   bool
	chains    map[string][]string
}

func (r *rowLog) enter(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.ctxs = append(r.ctxs, ctx)
	if ctx.Err() != nil {
		r.expiredOn++
		return ctx.Err()
	}
	if r.failAll || r.calls <= r.failFirst {
		if r.failErr != nil {
			return r.failErr
		}
		return context.DeadlineExceeded
	}
	return nil
}

func (r *rowLog) put(id, kind string, chains []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rows == nil {
		r.rows = map[string]string{}
		r.chains = map[string][]string{}
	}
	if _, ok := r.rows[id]; !ok { // ON CONFLICT DO NOTHING
		r.rows[id] = kind
		r.chains[id] = chains
	}
}

func (r *rowLog) UpsertOnDiscovery(ctx context.Context, intentID, _ string, _ int64, _ time.Time, _, _, _ string) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	r.put(intentID, "single", nil)
	return nil
}

func (r *rowLog) UpsertOnDiscoveryMultiLeg(ctx context.Context, intentID, _ string, _ int64, _ time.Time, _, _, _ string,
	chains []string, _ int, _ string) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	r.put(intentID, "multi", chains)
	return nil
}

func (r *rowLog) has(id string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.rows[id]
	return k, ok
}

func (r *rowLog) setFailAll(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failAll = v
}

func (r *rowLog) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// fastPolicy keeps the tests quick without changing what they prove.
func fastPolicy() lifecycleRetryPolicy {
	return lifecycleRetryPolicy{Attempts: 4, AttemptTimeout: time.Second, Backoff: time.Millisecond}
}

func lifecycleDiscovery(client accumulate.Client, rows *rowLog, queue RetryJournal) *IntentDiscovery {
	id := &IntentDiscovery{client: client, config: DefaultIntentDiscoveryConfig(), logger: log.New(io.Discard, "", 0),
		intentStatus: map[string]IntentStatus{}, stopCh: make(chan struct{}), retries: nil}
	id.lifecycleRows = rows
	id.lifecycleQueue = queue
	id.lifecyclePolicy = fastPolicy()
	return id
}

func convertedIntent(t *testing.T, tx *accumulate.CertenTransaction) *CertenIntent {
	t.Helper()
	ci, err := (&IntentDiscovery{logger: log.New(io.Discard, "", 0)}).convertCertenTransactionToIntent(tx)
	if err != nil {
		t.Fatal(err)
	}
	return ci
}

// The root cause. Two intents sit in one block; the first takes longer to process than the search context lives
// (the production first intent took 6 minutes against 30 seconds). The second intent's row must still be written,
// on a context that is alive.
func TestEveryIntentOfABlockGetsItsRowAfterAnEarlierOneRanLong(t *testing.T) {
	first := blockTx("aa11", "long-first", 500)
	second := blockTx("bb22", "later-second", 500)
	rows := &rowLog{}
	id := lifecycleDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{first, second}}, rows, nil)
	id.blockSearchTimeout = 40 * time.Millisecond
	// The block job hands its intents to the intent workers (RB8-H); the rows are written by the block job before it does.
	id.retries = openJournal(t, filepath.Join(t.TempDir(), "intent_retries.json"))
	startIntentWorkers(t, id, 2)
	id.blockProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		if ci.TransactionHash == first.Hash {
			time.Sleep(150 * time.Millisecond) // far longer than the search context lives
		}
		return consensus.TargetChainPending, nil
	}

	if err := id.processBlock(&BlockProcessJob{BlockHeight: 500}, "test"); err != nil {
		t.Fatalf("processBlock: %v", err)
	}
	for _, want := range []*accumulate.CertenTransaction{first, second} {
		ci := convertedIntent(t, want)
		if _, ok := rows.has(ci.IntentID); !ok {
			t.Fatalf("intent %s (tx %s) has no lifecycle row: its write ran on the block search's expired context (calls %d, on an expired context %d)",
				ci.IntentID, want.Hash, rows.callCount(), rows.expiredOn)
		}
	}
	if rows.expiredOn != 0 {
		t.Fatalf("%d lifecycle write(s) began on a context that was already done", rows.expiredOn)
	}
}

// A write that times out is retried with a context of its own each time, and the row lands.
func TestALifecycleWriteIsRetriedOnAFreshContextEachAttempt(t *testing.T) {
	rows := &rowLog{failFirst: 2}
	id := lifecycleDiscovery(&blockClient{}, rows, nil)
	ci := convertedIntent(t, blockTx("cc33", "retried-write", 501))

	if err := id.recordDiscoveryLifecycle(ci, 501); err != nil {
		t.Fatalf("recordDiscoveryLifecycle: %v", err)
	}
	if _, ok := rows.has(ci.IntentID); !ok {
		t.Fatal("the row was not written after two timeouts")
	}
	if got := rows.callCount(); got != 3 {
		t.Fatalf("expected 3 attempts (2 timeouts, then success), got %d", got)
	}
	seen := map[context.Context]bool{}
	for _, c := range rows.ctxs {
		if seen[c] {
			t.Fatal("an attempt reused an earlier attempt's context")
		}
		seen[c] = true
	}
	if id.lifecycleQueueDepth() != 0 {
		t.Fatal("a write that succeeded is on the queue")
	}
}

// A write that keeps failing is not dropped and not left to a log line: it is kept on the durable queue, serviced
// by the discovery loop, outlives the process, and ends only when the row is written.
func TestAFailingLifecycleWriteIsQueuedServicedAndOutlivesTheProcess(t *testing.T) {
	tx := blockTx("dd44", "queued-write", 502)
	client := &blockClient{txs: []*accumulate.CertenTransaction{tx}}
	path := filepath.Join(t.TempDir(), "lifecycle_upserts.json")
	rows := &rowLog{failAll: true, failErr: errors.New("pq: the database is shutting down")}
	id := lifecycleDiscovery(client, rows, openJournal(t, path))
	ci := convertedIntent(t, tx)

	if err := id.recordDiscoveryLifecycle(ci, 502); err != nil {
		t.Fatalf("a queued write is not an error: %v", err)
	}
	if got := rows.callCount(); got != 4 {
		t.Fatalf("expected the 4 bounded attempts, got %d", got)
	}
	if _, ok := rows.has(ci.IntentID); ok {
		t.Fatal("the row exists although every attempt failed")
	}
	held := kept(t, id.lifecycleQueue)
	if len(held) != 1 || held[0].IntentID != ci.IntentID || held[0].BlockHeight != 502 || held[0].LastError == "" || held[0].Attempts != 4 {
		t.Fatalf("the failed write must be kept with its block, cause and attempts, kept %+v", held)
	}
	if id.lifecycleQueueDepth() != 1 {
		t.Fatalf("queue depth %d, want 1", id.lifecycleQueueDepth())
	}

	// The process ends and a new one starts on the same file: the write is still owed.
	after := lifecycleDiscovery(client, rows, openJournal(t, path))
	if after.lifecycleQueueDepth() != 1 {
		t.Fatalf("the restarted process lost the owed write (depth %d)", after.lifecycleQueueDepth())
	}

	// While the database stays down the servicing keeps the entry; it never drops it.
	after.serviceLifecycleQueue()
	if after.lifecycleQueueDepth() != 1 {
		t.Fatal("a servicing pass that could not write dropped the entry")
	}

	// The database recovers; the next pass writes the row, rebuilt from its block, and ends the entry.
	rows.setFailAll(false)
	after.serviceLifecycleQueue()
	if _, ok := rows.has(ci.IntentID); !ok {
		t.Fatal("the servicing pass did not write the owed row")
	}
	if after.lifecycleQueueDepth() != 0 {
		t.Fatal("a written row stayed on the queue")
	}
	if left := kept(t, after.lifecycleQueue); len(left) != 0 {
		t.Fatalf("a written row stayed in the journal: %+v", left)
	}
}

// A multi-leg intent whose write timed out is retried AS multi-leg. It used to fall through to the single-leg write
// when the multi-leg one failed - and the row, written once with ON CONFLICT DO NOTHING, then kept the wrong shape.
func TestAMultiLegWriteIsNeverDowngradedToSingleLegOnAFailure(t *testing.T) {
	tx := blockTx("ee55", "multi-write", 503)
	ci := convertedIntent(t, tx)
	ci.CrossChainData = []byte(`{"legs":[{"legId":"a","chain":"ethereum","chainId":11155111},{"legId":"b","chain":"base","chainId":84532}]}`)
	rows := &rowLog{failFirst: 1}
	id := lifecycleDiscovery(&blockClient{}, rows, nil)

	if err := id.recordDiscoveryLifecycle(ci, 503); err != nil {
		t.Fatal(err)
	}
	if kind, ok := rows.has(ci.IntentID); !ok || kind != "multi" {
		t.Fatalf("the multi-leg intent's row is %q (present %v), want multi", kind, ok)
	}
	if len(rows.chains[ci.IntentID]) != 2 {
		t.Fatalf("the multi-leg row lost its chains: %v", rows.chains[ci.IntentID])
	}
}

// A queue that is full of owed writes still takes one more; without any durable journal the write is kept in memory
// and said so, never dropped.
func TestAQueuedWriteWithoutAJournalIsKeptInMemory(t *testing.T) {
	rows := &rowLog{failAll: true}
	id := lifecycleDiscovery(&blockClient{}, rows, nil)
	ci := convertedIntent(t, blockTx("ff66", "memory-queued", 504))
	if err := id.recordDiscoveryLifecycle(ci, 504); err != nil {
		t.Fatal(err)
	}
	if id.lifecycleQueueDepth() != 1 {
		t.Fatalf("depth %d, want 1", id.lifecycleQueueDepth())
	}
	rows.setFailAll(false)
	id.serviceLifecycleQueue()
	if _, ok := rows.has(ci.IntentID); !ok || id.lifecycleQueueDepth() != 0 {
		t.Fatal("the in-memory entry was not written and ended")
	}
}
