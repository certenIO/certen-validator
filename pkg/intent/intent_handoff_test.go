// Copyright 2026 Certen Protocol

package intent

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
)

// RB8-H (the remaining hold behind the 2026-10-18 lifecycle defect, D4): a block job processed the intents it found itself,
// one after another, and held its block worker for the whole of the slowest - the production first intent took six
// minutes. The watermark could not pass the block, the intents behind the first waited for it, and a few such blocks hold
// every worker. A block job now finds the intents, records their lifecycle rows and HANDS each to the intent workers (kept in
// the retry journal first, so a hand-off outlives the process); it ends when they are handed off, not when they are done.

// startIntentWorkers starts the intent workers the way StartMonitoring does, and stops them with the test.
func startIntentWorkers(t *testing.T, id *IntentDiscovery, n int) {
	t.Helper()
	id.intentCh = make(chan *intentRetryJob, intentQueueDepth)
	for i := 0; i < n; i++ {
		go id.intentWorker(fmt.Sprintf("test-intent-worker-%d", i+1))
	}
	t.Cleanup(func() { close(id.stopCh) })
}

func waitUntil(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type doneLog struct {
	mu sync.Mutex
	at map[string]time.Time
}

func (d *doneLog) mark(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.at == nil {
		d.at = map[string]time.Time{}
	}
	d.at[id] = time.Now()
}

func (d *doneLog) has(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.at[id]
	return ok
}

// The D4 shape: two later intents share a block with a first one that takes "minutes". The block job must end without
// waiting for the first, and the later intents must be processed while the first is still running - on time, not behind it.
func TestASlowFirstIntentDoesNotHoldTheBlockWorkerNorDelayTheLaterOnes(t *testing.T) {
	first := blockTx("a1a1", "slow-first", 700)
	second := blockTx("b2b2", "later-second", 700)
	third := blockTx("c3c3", "later-third", 700)
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{first, second, third}},
		openJournal(t, filepath.Join(t.TempDir(), "r.json")), &failureLog{}, 4)
	id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
	startIntentWorkers(t, id, 4)

	release := make(chan struct{})
	var done doneLog
	id.blockProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		if ci.TransactionHash == first.Hash {
			<-release // minutes, in production
		}
		done.mark(ci.IntentID)
		return consensus.TargetChainPending, nil
	}

	returned := make(chan error, 1)
	go func() { returned <- id.processBlock(&BlockProcessJob{BlockHeight: 700}, "test") }()
	select {
	case err := <-returned:
		if err != nil {
			t.Fatalf("processBlock: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the block job is still holding its worker while the first intent runs: the watermark cannot pass the block and the intents behind it wait")
	}

	secondID, thirdID, firstID := convertedIntent(t, second).IntentID, convertedIntent(t, third).IntentID, convertedIntent(t, first).IntentID
	waitUntil(t, "the later intents were processed while the first was still running", 5*time.Second, func() bool {
		return done.has(secondID) && done.has(thirdID)
	})
	if done.has(firstID) {
		t.Fatal("the slow first intent finished before it was released: the test does not hold what it claims to")
	}

	close(release)
	waitUntil(t, "the first intent finished once released", 5*time.Second, func() bool { return done.has(firstID) })
	waitUntil(t, "every handed-off intent ended its journal entry", 5*time.Second, func() bool {
		return len(kept(t, id.retries)) == 0
	})
	for _, intentID := range []string{firstID, secondID, thirdID} {
		if got := id.getIntentStatus(intentID); got != IntentStatusCompleted {
			t.Fatalf("intent %s is %s, want completed", intentID, got.String())
		}
	}
}

// A hand-off is kept before it is queued, survives the process, and is resumed to the intent workers (not behind a retry's
// backoff) with the intent rebuilt from its block. A search of the same block again hands nothing off twice.
func TestAHandOffOutlivesTheProcessAndIsResumedToTheIntentWorkers(t *testing.T) {
	tx := blockTx("d4d4", "handed-off-1", 701)
	path := filepath.Join(t.TempDir(), "r.json")
	client := &blockClient{txs: []*accumulate.CertenTransaction{tx}}

	before := retryDiscovery(client, openJournal(t, path), &failureLog{}, 4)
	before.lifecycleRows, before.lifecyclePolicy = &rowLog{}, fastPolicy()
	before.intentCh = make(chan *intentRetryJob, 8) // nobody consumes: the process ends with the intent queued
	if err := before.processBlock(&BlockProcessJob{BlockHeight: 701}, "test"); err != nil {
		t.Fatalf("processBlock: %v", err)
	}
	intentID := convertedIntent(t, tx).IntentID
	got := kept(t, before.retries)
	if len(got) != 1 || got[0].IntentID != intentID || got[0].BlockHeight != 701 || got[0].Attempts != 0 || got[0].LastError != "" {
		t.Fatalf("a hand-off must be kept with its block, as one that never ran; kept %+v", got)
	}
	if err := before.processBlock(&BlockProcessJob{BlockHeight: 701}, "test"); err != nil {
		t.Fatal(err)
	}
	if n := len(before.intentCh); n != 1 {
		t.Fatalf("searching the block again handed the intent off a second time (%d queued)", n)
	}

	failures := &failureLog{}
	after := retryDiscovery(client, openJournal(t, path), failures, 4)
	after.intentCh = make(chan *intentRetryJob, 8)
	if !after.resumeRetriesOnce(map[string]bool{}) {
		t.Fatal("a kept hand-off whose block can be searched must be resumed")
	}
	if len(after.retryCh) != 0 || len(after.intentCh) != 1 {
		t.Fatalf("a hand-off that never ran belongs to the intent workers: %d on the retry queue, %d on the intent queue", len(after.retryCh), len(after.intentCh))
	}
	job := <-after.intentCh
	if job.intent.IntentID != intentID || job.intent.AccountURL != "acc://harbor.acme/data" || job.blockHeight != 701 {
		t.Fatalf("the resumed intent was not rebuilt from its block: %+v", job.intent)
	}
	ran := 0
	after.blockProcess = func(*CertenIntent, uint64) (consensus.TargetChainOutcome, error) {
		ran++
		return consensus.TargetChainPending, nil
	}
	after.runHandedOffIntent(job, "test")
	if ran != 1 {
		t.Fatalf("the resumed hand-off ran %d times", ran)
	}
	if left := kept(t, after.retries); len(left) != 0 {
		t.Fatalf("an ended hand-off must leave the journal, kept %+v", left)
	}
	if after.getIntentStatus(intentID) != IntentStatusCompleted {
		t.Fatalf("the intent is %s, want completed", after.getIntentStatus(intentID).String())
	}
	if after.resumeRetriesOnce(map[string]bool{}); len(after.intentCh) != 0 || len(after.retryCh) != 0 {
		t.Fatal("a second resume queued an ended hand-off again")
	}
}

// Every way processing a handed-off intent ends is the way a block job ended it: failed and recorded, queued for another
// attempt at its proof, or - if the failure could not be recorded - kept for the next start.
func TestAHandedOffIntentEndsAsABlockJobEndedIt(t *testing.T) {
	const height = 702
	run := func(t *testing.T, runErr error, failures *failureLog) (*IntentDiscovery, string) {
		t.Helper()
		tx := blockTx("e5e5", "handed-off-ends", height)
		id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{tx}},
			openJournal(t, filepath.Join(t.TempDir(), "r.json")), failures, 4)
		id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
		id.intentCh = make(chan *intentRetryJob, 4)
		id.blockProcess = func(*CertenIntent, uint64) (consensus.TargetChainOutcome, error) {
			if runErr != nil {
				return consensus.TargetChainFailed, runErr
			}
			return consensus.TargetChainPending, nil
		}
		if err := id.processBlock(&BlockProcessJob{BlockHeight: height}, "test"); err != nil {
			t.Fatal(err)
		}
		id.runHandedOffIntent(<-id.intentCh, "test")
		return id, convertedIntent(t, tx).IntentID
	}

	t.Run("a refusal is recorded failed and leaves the journal", func(t *testing.T) {
		failures := &failureLog{}
		id, intentID := run(t, fmt.Errorf("intent declined: %w", consensus.ErrNotEntitled), failures)
		if s, ok := failures.status(intentID); !ok || s != database.IntentLifecycleFailed {
			t.Fatalf("the refusal was not recorded failed (written: %v %q)", ok, s)
		}
		if left := kept(t, id.retries); len(left) != 0 {
			t.Fatalf("a recorded failure must leave the journal, kept %+v", left)
		}
	})
	t.Run("a failure that cannot be recorded keeps the intent for the next start", func(t *testing.T) {
		failures := &failureLog{fail: errors.New("database unavailable")}
		id, _ := run(t, errors.New("consensus refused"), failures)
		if left := kept(t, id.retries); len(left) != 1 {
			t.Fatalf("a failure that was not recorded must stay kept, kept %+v", left)
		}
	})
	t.Run("an unavailable proof is queued for another attempt, kept with its cause", func(t *testing.T) {
		failures := &failureLog{}
		id, intentID := run(t, unavailable("handed-off-ends"), failures)
		if len(id.retryCh) != 1 {
			t.Fatalf("the intent was not queued for another attempt (%d queued)", len(id.retryCh))
		}
		if _, ok := failures.status(intentID); ok {
			t.Fatal("a retryable failure was recorded terminal")
		}
		if left := kept(t, id.retries); len(left) != 1 || left[0].LastError == "" {
			t.Fatalf("the retry must stay kept with its cause, kept %+v", left)
		}
	})
}

// A panic while processing an intent is that intent failing, not one intent worker fewer.
func TestAPanickingIntentIsAFailureAndTheWorkerGoesOn(t *testing.T) {
	bad := blockTx("f6f6", "panics", 703)
	good := blockTx("a7a7", "after-the-panic", 703)
	failures := &failureLog{}
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{bad, good}},
		openJournal(t, filepath.Join(t.TempDir(), "r.json")), failures, 4)
	id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
	startIntentWorkers(t, id, 1) // one worker: it must survive the first intent to process the second
	var done doneLog
	id.blockProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		if ci.TransactionHash == bad.Hash {
			panic("boom")
		}
		done.mark(ci.IntentID)
		return consensus.TargetChainPending, nil
	}
	if err := id.processBlock(&BlockProcessJob{BlockHeight: 703}, "test"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the intent after the panic was processed by the same worker", 5*time.Second, func() bool {
		return done.has(convertedIntent(t, good).IntentID)
	})
	waitUntil(t, "the panicking intent was recorded failed", 5*time.Second, func() bool {
		s, ok := failures.status(convertedIntent(t, bad).IntentID)
		return ok && s == database.IntentLifecycleFailed
	})
}

// An intent that cannot be handed off is not processed inline and not lost: the block is not passed, and the intent is free to
// be handed off by the next search.
func TestABlockWhoseIntentCannotBeHandedOffIsNotPassed(t *testing.T) {
	cases := map[string]func(t *testing.T, client *blockClient) *IntentDiscovery{
		"no intent workers": func(t *testing.T, c *blockClient) *IntentDiscovery {
			return retryDiscovery(c, openJournal(t, filepath.Join(t.TempDir(), "r.json")), &failureLog{}, 4)
		},
		"no journal to keep the hand-off in": func(t *testing.T, c *blockClient) *IntentDiscovery {
			id := retryDiscovery(c, nil, &failureLog{}, 4)
			id.intentCh = make(chan *intentRetryJob, 4)
			return id
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			tx := blockTx("b8b8", "unhanded", 704)
			id := build(t, &blockClient{txs: []*accumulate.CertenTransaction{tx}})
			id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
			ran := false
			id.blockProcess = func(*CertenIntent, uint64) (consensus.TargetChainOutcome, error) {
				ran = true
				return consensus.TargetChainPending, nil
			}
			if err := id.processBlock(&BlockProcessJob{BlockHeight: 704}, "test"); err == nil {
				t.Fatal("a block whose intent could not be handed off was passed")
			}
			if ran {
				t.Fatal("the intent was processed inline instead of handed off")
			}
			if !id.markInProgress(convertedIntent(t, tx).IntentID) {
				t.Fatal("the intent is stuck in_progress: the next search of the block would skip it")
			}
		})
	}
}

// A full intent queue makes the block job wait for room - the hold is then the queue's, never one intent's - and a stop while
// it waits drops nothing: every hand-off stays kept for the next start.
func TestAFullIntentQueueMakesTheBlockJobWaitAndAStopLosesNothing(t *testing.T) {
	one := blockTx("c9c9", "queued-one", 705)
	two := blockTx("d0d0", "queued-two", 705)
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{one, two}},
		openJournal(t, filepath.Join(t.TempDir(), "r.json")), &failureLog{}, 4)
	id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
	id.intentCh = make(chan *intentRetryJob, 1) // room for one, no consumer

	returned := make(chan error, 1)
	go func() { returned <- id.processBlock(&BlockProcessJob{BlockHeight: 705}, "test") }()
	waitUntil(t, "the first hand-off was queued", 5*time.Second, func() bool { return len(id.intentCh) == 1 })
	select {
	case err := <-returned:
		t.Fatalf("the block job ended with a full queue (%v): the second intent was dropped or processed inline", err)
	case <-time.After(150 * time.Millisecond):
	}

	close(id.stopCh)
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("a stop while waiting for room passed the block")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the block job did not end on a stop")
	}
	if left := kept(t, id.retries); len(left) != 2 {
		t.Fatalf("both hand-offs must stay kept for the next start, kept %+v", left)
	}
}
