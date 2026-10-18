// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
)

// V-A defect 1: a hand-off that no worker has started is not "in progress". While the pause file exists a worker will not
// start it, and the maintenance procedure (docs/runbooks/bls-key-rotation.md 4.1; RB3-F8, "zero = nothing in flight") waits
// for discovery_intents_in_progress to reach zero, so counting a queued hand-off there made the wait impossible.
func TestAQueuedHandOffIsNotInProgressWhilePausedAndStartsWhenResumed(t *testing.T) {
	old := intakePausePoll
	intakePausePoll = 10 * time.Millisecond
	t.Cleanup(func() { intakePausePoll = old })

	tx := blockTx("1a1a", "queued-while-paused", 710)
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{tx}},
		openJournal(t, filepath.Join(t.TempDir(), "r.json")), &failureLog{}, 4)
	id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
	pause := filepath.Join(t.TempDir(), "intake.paused")
	id.pauseFile = pause
	if err := os.WriteFile(pause, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	intentID := convertedIntent(t, tx).IntentID

	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(1)
	var once sync.Once
	var done doneLog
	id.blockProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		once.Do(started.Done)
		<-release
		done.mark(ci.IntentID)
		return consensus.TargetChainPending, nil
	}
	startIntentWorkers(t, id, 1)
	t.Cleanup(func() { // runs before the helper's stop: a worker blocked in the fake must be let go
		select {
		case <-release:
		default:
			close(release)
		}
	})

	if err := id.processBlock(&BlockProcessJob{BlockHeight: 710}, "test"); err != nil {
		t.Fatalf("processBlock: %v", err)
	}
	// Paused: handed off, queued, and not one worker has started it.
	time.Sleep(150 * time.Millisecond)
	st := id.Status()
	if st.InProgress != 0 || st.Queued != 1 {
		t.Fatalf("paused with one queued hand-off and nothing running: InProgress=%d Queued=%d, want 0 and 1 "+
			"(the key-rotation wait for discovery_intents_in_progress 0 could never finish)", st.InProgress, st.Queued)
	}
	if got := id.getIntentStatus(intentID); got != IntentStatusQueued {
		t.Fatalf("intent is %s while paused and unstarted, want queued", got.String())
	}
	if !id.isIntentProcessed(intentID) || id.markQueued(intentID) || id.markInProgress(intentID) {
		t.Fatal("a queued hand-off must still hold the intent against being handed off or started a second time")
	}
	if err := id.ReprocessIntent(context.Background(), 710, tx.Hash, intentID); err == nil {
		t.Fatal("a queued intent was accepted for reprocessing: it would be processed twice")
	}

	// Resumed: a worker starts it, and only then is it in progress.
	if err := os.Remove(pause); err != nil {
		t.Fatal(err)
	}
	started.Wait()
	waitUntil(t, "the started intent counts as in progress and no longer as queued", 5*time.Second, func() bool {
		s := id.Status()
		return s.InProgress == 1 && s.Queued == 0
	})
	close(release)
	waitUntil(t, "the intent finished", 5*time.Second, func() bool { return done.has(intentID) })
	waitUntil(t, "nothing is queued or in progress once it ended", 5*time.Second, func() bool {
		s := id.Status()
		return s.InProgress == 0 && s.Queued == 0 && len(kept(t, id.retries)) == 0
	})
	if got := id.getIntentStatus(intentID); got != IntentStatusCompleted {
		t.Fatalf("intent is %s, want completed", got.String())
	}
}

// A kept hand-off a start resumes is queued too, not in progress, until a worker starts it.
func TestAResumedHandOffIsQueuedNotInProgressUntilAWorkerStartsIt(t *testing.T) {
	tx := blockTx("2b2b", "resumed-queued", 711)
	path := filepath.Join(t.TempDir(), "r.json")
	client := &blockClient{txs: []*accumulate.CertenTransaction{tx}}

	before := retryDiscovery(client, openJournal(t, path), &failureLog{}, 4)
	before.lifecycleRows, before.lifecyclePolicy = &rowLog{}, fastPolicy()
	before.intentCh = make(chan *intentRetryJob, 8) // nobody consumes
	if err := before.processBlock(&BlockProcessJob{BlockHeight: 711}, "test"); err != nil {
		t.Fatalf("processBlock: %v", err)
	}

	after := retryDiscovery(client, openJournal(t, path), &failureLog{}, 4)
	after.intentCh = make(chan *intentRetryJob, 8)
	if !after.resumeRetriesOnce(map[string]bool{}) {
		t.Fatal("the kept hand-off was not resumed")
	}
	st := after.Status()
	if st.InProgress != 0 || st.Queued != 1 || len(after.intentCh) != 1 {
		t.Fatalf("resumed hand-off with no worker started: InProgress=%d Queued=%d queue=%d, want 0, 1, 1", st.InProgress, st.Queued, len(after.intentCh))
	}
}

// panicOnceWriter is a lifecycle writer whose first write panics, as a bug in the step after processing would.
type panicOnceWriter struct {
	failureLog
	mu2   sync.Mutex
	fired bool
}

func (p *panicOnceWriter) UpdateStatus(ctx context.Context, intentID string, status database.IntentLifecycleStatus, opts ...database.UpdateOption) error {
	p.mu2.Lock()
	first := !p.fired
	p.fired = true
	p.mu2.Unlock()
	if first {
		panic("lifecycle writer exploded")
	}
	return p.failureLog.UpdateStatus(ctx, intentID, status, opts...)
}

// V-A defect 3: a panic AFTER the intent was processed (here in the lifecycle write that records its failure) is that intent
// failing and not one intent worker fewer; the one worker goes on to the intent queued behind it, and the first intent stays
// kept for the next start and free to be handed off again.
func TestAPanicAfterProcessingIsThatIntentFailingAndTheWorkerGoesOn(t *testing.T) {
	bad := blockTx("3c3c", "panics-after", 712)
	good := blockTx("4d4d", "behind-the-panic", 712)
	writer := &panicOnceWriter{}
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{bad, good}},
		openJournal(t, filepath.Join(t.TempDir(), "r.json")), nil, 4)
	id.failureWriter = writer
	id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
	startIntentWorkers(t, id, 1)
	var done doneLog
	id.blockProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		if ci.TransactionHash == bad.Hash {
			return consensus.TargetChainFailed, errors.New("intent declined: " + consensus.ErrNotEntitled.Error())
		}
		done.mark(ci.IntentID)
		return consensus.TargetChainPending, nil
	}
	if err := id.processBlock(&BlockProcessJob{BlockHeight: 712}, "test"); err != nil {
		t.Fatal(err)
	}
	goodID, badID := convertedIntent(t, good).IntentID, convertedIntent(t, bad).IntentID
	waitUntil(t, "the intent behind the panic was handled by the only worker", 5*time.Second, func() bool { return done.has(goodID) })
	waitUntil(t, "the good intent ended its journal entry", 5*time.Second, func() bool {
		for _, r := range kept(t, id.retries) {
			if r.IntentID == goodID {
				return false
			}
		}
		return true
	})
	if got := id.getIntentStatus(badID); got != IntentStatusFailed {
		t.Fatalf("the intent whose handling panicked is %s, want failed (free to be handed off again)", got.String())
	}
	left := kept(t, id.retries)
	if len(left) != 1 || left[0].IntentID != badID {
		t.Fatalf("the panicked intent must stay kept for the next start, kept %+v", left)
	}
	if id.queued() != 0 || id.inProgress() != 0 {
		t.Fatalf("after both ended: queued=%d in progress=%d, want 0 and 0", id.queued(), id.inProgress())
	}
}

// panicDropJournal is a retry journal whose Drop panics, as a bug in the step after a successful processing would.
type panicDropJournal struct{ RetryJournal }

func (panicDropJournal) Drop(string) error { panic("journal drop exploded") }

// V-G D2: the per-job recover marks the intent failed only if it is still queued or in progress. A panic AFTER the intent was
// processed and marked completed (here in the journal write that ends its retry) must leave it completed, not hand a done
// intent back to `acquire` as re-acquirable.
func TestAPanicAfterSuccessLeavesTheIntentCompleted(t *testing.T) {
	tx := blockTx("5e5e", "panics-after-success", 713)
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{tx}},
		panicDropJournal{openJournal(t, filepath.Join(t.TempDir(), "r.json"))}, nil, 4)
	id.lifecycleRows, id.lifecyclePolicy = &rowLog{}, fastPolicy()
	startIntentWorkers(t, id, 1)
	var done doneLog
	id.blockProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		done.mark(ci.IntentID)
		return consensus.TargetChainPending, nil
	}
	if err := id.processBlock(&BlockProcessJob{BlockHeight: 713}, "test"); err != nil {
		t.Fatal(err)
	}
	intentID := convertedIntent(t, tx).IntentID
	waitUntil(t, "the intent was processed", 5*time.Second, func() bool { return done.has(intentID) })
	waitUntil(t, "the worker is idle again", 5*time.Second, func() bool { return id.queued() == 0 && id.inProgress() == 0 })
	// let the recover run to its end before reading the status
	time.Sleep(100 * time.Millisecond)
	if got := id.getIntentStatus(intentID); got != IntentStatusCompleted {
		t.Fatalf("an intent processed successfully whose handling then panicked is %s, want completed", got.String())
	}
}
