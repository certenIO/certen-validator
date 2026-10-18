// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/certen/independant-validator/pkg/metrics"
)

// Discovery's write of an intent's lifecycle row (RB8-F, defect D4).
//
// Production 2026-10-18: five intents of one Directory Network block were found by one search. The first took six
// minutes to process; the other four had their row written on the block search's 30 second context, which had
// expired, so every write failed instantly with "context deadline exceeded" - on all seven validators, while the same
// loop wrote other rows to the same database. The write was one attempt that only logged, so the four intents
// settled on chain with no intent_lifecycle row, their proof cycle died "intent lifecycle not found", and the gateway
// answered 404 for ever.
//
// Now: every write runs on a context of its own, is retried a bounded number of times with backoff, each failure is
// logged with its attempt and duration, and a write that still fails is OWED - kept on a durable queue serviced by
// the discovery loop until the row exists. The proof cycle also creates a missing row from its own request
// (execution.ensureLifecycleInProcess), so an intent that reaches it is never refused for want of one.

// LifecycleQueueFile is the journal file (in the validator's data directory) the owed lifecycle row writes are kept in.
const LifecycleQueueFile = "lifecycle_upserts.json"

// lifecycleRowWriter is the part of the lifecycle repository discovery's row write needs.
type lifecycleRowWriter interface {
	UpsertOnDiscovery(ctx context.Context, intentID, txHash string, blockHeight int64, executedBy time.Time,
		userID, proofClass, targetChain string) error
	UpsertOnDiscoveryMultiLeg(ctx context.Context, intentID, txHash string, blockHeight int64, executedBy time.Time,
		userID, proofClass, targetChain string, targetChains []string, legCount int, executionMode string) error
}

// lifecycleRetryPolicy bounds one row write: Attempts tries of AttemptTimeout each, Backoff doubling between them.
// The worst case is Attempts*AttemptTimeout plus the backoffs (40s + 1.75s by default).
type lifecycleRetryPolicy struct {
	Attempts       int
	AttemptTimeout time.Duration
	Backoff        time.Duration
}

const (
	defaultLifecycleAttempts       = 4
	defaultLifecycleAttemptTimeout = 10 * time.Second
	defaultLifecycleBackoff        = 250 * time.Millisecond
	// defaultBlockSearchTimeout bounds the block search only. It is not a context for anything done afterwards.
	defaultBlockSearchTimeout = 30 * time.Second
	// lifecycleQueueInterval is how often discovery services the owed row writes.
	lifecycleQueueInterval = 15 * time.Second
)

func (p lifecycleRetryPolicy) withDefaults() lifecycleRetryPolicy {
	if p.Attempts <= 0 {
		p.Attempts = defaultLifecycleAttempts
	}
	if p.AttemptTimeout <= 0 {
		p.AttemptTimeout = defaultLifecycleAttemptTimeout
	}
	if p.Backoff <= 0 {
		p.Backoff = defaultLifecycleBackoff
	}
	return p
}

// owedLifecycle is one row write that has not succeeded yet.
type owedLifecycle struct {
	intent    *CertenIntent // nil after a restart until it is rebuilt from its block
	intentID  string
	height    uint64
	attempts  int
	firstSeen time.Time
	lastErr   string
}

// SetLifecycleQueue gives discovery the journal its owed row writes are kept in. Without one an owed write lives in
// memory only and is lost with the process (the proof cycle's own create-if-missing remains).
func (id *IntentDiscovery) SetLifecycleQueue(j RetryJournal) { id.lifecycleQueue = j }

// lifecycleWriter is where discovered intents' rows are written; nil when no store is wired.
func (id *IntentDiscovery) lifecycleWriter() lifecycleRowWriter {
	if id.lifecycleRows != nil {
		return id.lifecycleRows
	}
	if id.repos != nil && id.repos.IntentLifecycle != nil {
		return id.repos.IntentLifecycle
	}
	return nil
}

// discoveryRow is exactly what discovery writes for one intent, built once so that every attempt, the queue and a
// restart write the same row.
type discoveryRow struct {
	intentID, txHash, userID, proofClass, targetChain string
	height                                            int64
	executedBy                                        time.Time
	multi                                             bool
	chains                                            []string
	legCount                                          int
	execMode                                          string
}

// buildDiscoveryRow reads an intent's shape the way discovery always has. A multi-leg intent is recorded with its
// legs, chains and execution mode; one whose shape cannot be read is recorded single-leg (the row still carries the
// identifiers cost attribution and settlement join on).
func buildDiscoveryRow(intent *CertenIntent, height uint64) discoveryRow {
	r := discoveryRow{
		intentID: intent.IntentID, txHash: intent.TransactionHash, height: int64(height),
		executedBy: intent.BlockTime, userID: intent.UserID, proofClass: intent.ProofClass,
	}
	if tc, _, err := intent.GetTargetChain(); err == nil {
		r.targetChain = tc
	}
	if isMulti, err := intent.IsMultiLeg(); err == nil && isMulti {
		if legCount, err := intent.GetLegCount(); err == nil && legCount > 0 {
			r.multi, r.legCount = true, legCount
			mode, err := intent.GetExecutionMode()
			if err != nil {
				mode = "sequential" // the router's own default
			}
			r.execMode = mode
			if grouped, err := intent.GetLegsGroupedByChain(); err == nil {
				for chainKey := range grouped {
					r.chains = append(r.chains, chainKey)
				}
				sort.Strings(r.chains) // stable across nodes; the map order is not
			}
		}
	}
	return r
}

func (r discoveryRow) query() string {
	if r.multi {
		return "UpsertOnDiscoveryMultiLeg"
	}
	return "UpsertOnDiscovery"
}

// write is one attempt. A multi-leg row that failed is never rewritten as single-leg: the row is written once
// (ON CONFLICT DO NOTHING), so a downgrade after a transient failure would keep the wrong shape for good.
func (r discoveryRow) write(ctx context.Context, w lifecycleRowWriter) error {
	if r.multi {
		return w.UpsertOnDiscoveryMultiLeg(ctx, r.intentID, r.txHash, r.height, r.executedBy, r.userID, r.proofClass,
			r.targetChain, r.chains, r.legCount, r.execMode)
	}
	return w.UpsertOnDiscovery(ctx, r.intentID, r.txHash, r.height, r.executedBy, r.userID, r.proofClass, r.targetChain)
}

// attempt runs one write on a context made for it, logging and measuring it.
func (id *IntentDiscovery) lifecycleAttempt(w lifecycleRowWriter, r discoveryRow, n, of int, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	err := r.write(ctx, w)
	d := time.Since(start)
	result := "ok"
	switch {
	case err == nil:
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		result = "timeout"
	default:
		result = "error"
	}
	metrics.RecordLifecycleUpsertAttempt(result, d)
	if err != nil {
		id.logger.Printf("⚠️ [LIFECYCLE] intent %s: %s attempt %d/%d failed after %s (%s): %v",
			r.intentID, r.query(), n, of, d.Round(time.Millisecond), result, err)
	}
	return err
}

// recordDiscoveryLifecycle writes the lifecycle row of a discovered intent: bounded retries, each on a fresh
// context; a write that still fails is owed on the queue, never dropped. It returns an error only when the owed
// write could not be made durable (it is still held in memory and serviced).
func (id *IntentDiscovery) recordDiscoveryLifecycle(intent *CertenIntent, height uint64) error {
	w := id.lifecycleWriter()
	if w == nil {
		return nil
	}
	row := buildDiscoveryRow(intent, height)
	policy := id.lifecyclePolicy.withDefaults()

	var last error
	for n := 1; n <= policy.Attempts; n++ {
		last = id.lifecycleAttempt(w, row, n, policy.Attempts, policy.AttemptTimeout)
		if last == nil {
			if n > 1 {
				metrics.RecordLifecycleUpsertRetried()
				id.logger.Printf("✅ [LIFECYCLE] intent %s: row written on attempt %d/%d", row.intentID, n, policy.Attempts)
			}
			return nil
		}
		if n < policy.Attempts {
			select {
			case <-id.stopCh:
				return id.oweLifecycle(intent, height, n, last)
			case <-time.After(policy.Backoff << (n - 1)):
			}
		}
	}
	metrics.RecordLifecycleUpsertRetried()
	return id.oweLifecycle(intent, height, policy.Attempts, last)
}

// oweLifecycle keeps a row write that has not succeeded: in memory with its intent, and in the journal.
func (id *IntentDiscovery) oweLifecycle(intent *CertenIntent, height uint64, attempts int, cause error) error {
	metrics.RecordLifecycleUpsertQueued()
	id.lifecycleMu.Lock()
	if id.lifecycleOwed == nil {
		id.lifecycleOwed = map[string]*owedLifecycle{}
	}
	o := id.lifecycleOwed[intent.IntentID]
	if o == nil {
		o = &owedLifecycle{intentID: intent.IntentID, firstSeen: time.Now().UTC()}
		id.lifecycleOwed[intent.IntentID] = o
	}
	o.intent, o.height, o.attempts, o.lastErr = intent, height, attempts, cause.Error()
	id.lifecycleMu.Unlock()
	id.logger.Printf("🚨 [LIFECYCLE] intent %s has no lifecycle row after %d attempt(s) (%v): its write is queued and serviced every %s until it exists",
		intent.IntentID, attempts, cause, lifecycleQueueInterval)
	var keepErr error
	if id.lifecycleQueue != nil {
		keepErr = id.lifecycleQueue.Keep(PendingRetry{IntentID: intent.IntentID, BlockHeight: height, Attempts: attempts, LastError: cause.Error()})
		if keepErr != nil {
			id.logger.Printf("🚨 [LIFECYCLE] intent %s: the queued write could not be made durable (%v); it is held in memory", intent.IntentID, keepErr)
		}
	} else {
		id.logger.Printf("🚨 [LIFECYCLE] intent %s: no lifecycle queue journal is configured; the queued write is held in memory only", intent.IntentID)
	}
	id.publishLifecycleQueue()
	if keepErr != nil {
		return fmt.Errorf("queue lifecycle write of %s: %w", intent.IntentID, keepErr)
	}
	return nil
}

// owedLifecycleEntries is every owed write: those held in memory and those only the journal knows (an earlier run's).
func (id *IntentDiscovery) owedLifecycleEntries() []*owedLifecycle {
	id.lifecycleMu.Lock()
	out := make([]*owedLifecycle, 0, len(id.lifecycleOwed))
	seen := map[string]bool{}
	for _, o := range id.lifecycleOwed {
		cp := *o
		out = append(out, &cp)
		seen[o.intentID] = true
	}
	id.lifecycleMu.Unlock()
	if id.lifecycleQueue != nil {
		if list, err := id.lifecycleQueue.List(); err != nil {
			id.logger.Printf("🚨 [LIFECYCLE] the lifecycle queue journal cannot be read: %v", err)
		} else {
			for _, p := range list {
				if !seen[p.IntentID] {
					out = append(out, &owedLifecycle{intentID: p.IntentID, height: p.BlockHeight, attempts: p.Attempts,
						firstSeen: p.FirstSeen, lastErr: p.LastError})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].firstSeen.Before(out[j].firstSeen) })
	return out
}

// lifecycleQueueDepth is the number of rows owed.
func (id *IntentDiscovery) lifecycleQueueDepth() int { return len(id.owedLifecycleEntries()) }

// publishLifecycleQueue sets the queue gauges.
func (id *IntentDiscovery) publishLifecycleQueue() {
	entries := id.owedLifecycleEntries()
	var oldest time.Duration
	for _, o := range entries {
		if !o.firstSeen.IsZero() {
			if age := time.Since(o.firstSeen); age > oldest {
				oldest = age
			}
		}
	}
	metrics.SetLifecycleUpsertQueue(len(entries), oldest)
}

// serviceLifecycleQueue makes one attempt for every owed row write. A write that succeeds leaves the queue; one that
// fails stays, counted. An entry only the journal knows is rebuilt from its block first, exactly as discovery built
// it; a block that cannot be searched now leaves the entry for the next pass.
func (id *IntentDiscovery) serviceLifecycleQueue() {
	w := id.lifecycleWriter()
	if w == nil {
		return
	}
	policy := id.lifecyclePolicy.withDefaults()
	for _, o := range id.owedLifecycleEntries() {
		intent := o.intent
		if intent == nil {
			rebuilt, err := id.intentInBlock(o.height, o.intentID)
			if err != nil {
				id.logger.Printf("⚠️ [LIFECYCLE] intent %s: its owed row cannot be rebuilt from block %d yet: %v", o.intentID, o.height, err)
				continue
			}
			intent = rebuilt
		}
		row := buildDiscoveryRow(intent, o.height)
		if err := id.lifecycleAttempt(w, row, o.attempts+1, o.attempts+1, policy.AttemptTimeout); err != nil {
			id.lifecycleMu.Lock()
			if cur := id.lifecycleOwed[o.intentID]; cur != nil {
				cur.attempts, cur.lastErr = o.attempts+1, err.Error()
			} else {
				if id.lifecycleOwed == nil {
					id.lifecycleOwed = map[string]*owedLifecycle{}
				}
				id.lifecycleOwed[o.intentID] = &owedLifecycle{intent: intent, intentID: o.intentID, height: o.height,
					attempts: o.attempts + 1, firstSeen: o.firstSeen, lastErr: err.Error()}
			}
			id.lifecycleMu.Unlock()
			if id.lifecycleQueue != nil {
				if kErr := id.lifecycleQueue.Keep(PendingRetry{IntentID: o.intentID, BlockHeight: o.height, Attempts: o.attempts + 1, LastError: err.Error()}); kErr != nil {
					id.logger.Printf("🚨 [LIFECYCLE] intent %s: the owed write's journal entry was not updated: %v", o.intentID, kErr)
				}
			}
			continue
		}
		id.lifecycleMu.Lock()
		delete(id.lifecycleOwed, o.intentID)
		id.lifecycleMu.Unlock()
		if id.lifecycleQueue != nil {
			if dErr := id.lifecycleQueue.Drop(o.intentID); dErr != nil {
				// Kept, it is written again at the next pass and ends again there (the write is idempotent).
				id.logger.Printf("⚠️ [LIFECYCLE] intent %s: its written row's journal entry stays: %v", o.intentID, dErr)
			}
		}
		id.logger.Printf("✅ [LIFECYCLE] intent %s: owed row written (queued since %s)", o.intentID, o.firstSeen.Format(time.RFC3339))
	}
	id.publishLifecycleQueue()
}

// lifecycleQueueLoop services the owed row writes until discovery stops; it is part of discovery's own loop set.
func (id *IntentDiscovery) lifecycleQueueLoop() {
	defer func() {
		if r := recover(); r != nil {
			id.logger.Printf("🚨 PANIC in lifecycle queue loop: %v", r)
		}
	}()
	t := time.NewTicker(lifecycleQueueInterval)
	defer t.Stop()
	for {
		id.serviceLifecycleQueue()
		select {
		case <-id.stopCh:
			return
		case <-t.C:
		}
	}
}

// RequestLifecycleRows owes the lifecycle row of each named intent (repair: the running validator services the
// journal and writes the row from the intent's own block). It writes nothing to the database itself.
func RequestLifecycleRows(j RetryJournal, entries []PendingRetry) error {
	for _, e := range entries {
		e.Attempts, e.LastError = 0, "requested by repair lifecycle-rows"
		if err := j.Keep(e); err != nil {
			return err
		}
	}
	return nil
}
