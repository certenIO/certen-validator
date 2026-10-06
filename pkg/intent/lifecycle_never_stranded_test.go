// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/entitlement"
)

// RB6-F12: 108 intents sat in intent_lifecycle as `authorized` for days to months. Discovery writes that row before
// it processes an intent; every way processing ends must then move it on - through consensus to a member outcome,
// or to a recorded failure. These pin the paths in discovery that ended an intent and wrote nothing.

// failureLog records the terminal-failure writes discovery makes.
type failureLog struct {
	mu     sync.Mutex
	writes map[string]database.IntentLifecycleStatus
	fail   error
}

func (f *failureLog) UpdateStatus(_ context.Context, intentID string, status database.IntentLifecycleStatus, _ ...database.UpdateOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if f.writes == nil {
		f.writes = map[string]database.IntentLifecycleStatus{}
	}
	f.writes[intentID] = status
	return nil
}

func (f *failureLog) status(intentID string) (database.IntentLifecycleStatus, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.writes[intentID]
	return s, ok
}

func openJournal(t *testing.T, path string) *FileRetryJournal {
	t.Helper()
	j, err := OpenFileRetryJournal(path)
	if err != nil {
		t.Fatalf("open retry journal: %v", err)
	}
	return j
}

func kept(t *testing.T, j RetryJournal) []PendingRetry {
	t.Helper()
	list, err := j.List()
	if err != nil {
		t.Fatalf("list retry journal: %v", err)
	}
	return list
}

// failingSearchClient serves blocks like blockClient and fails the search of one height.
type failingSearchClient struct {
	blockClient
	failOn int64
}

func (c *failingSearchClient) SearchCertenTransactions(ctx context.Context, h int64) ([]*accumulate.CertenTransaction, error) {
	if h == c.failOn {
		return nil, errors.New("accumulate: 503 service unavailable")
	}
	return c.blockClient.SearchCertenTransactions(ctx, h)
}

func retryDiscovery(client accumulate.Client, journal RetryJournal, failures *failureLog, queue int) *IntentDiscovery {
	cfg := DefaultIntentDiscoveryConfig()
	cfg.ChainedProofRequeueBackoff = time.Millisecond
	id := &IntentDiscovery{client: client, config: cfg, logger: log.New(io.Discard, "", 0),
		intentStatus: map[string]IntentStatus{}, stopCh: make(chan struct{}), retries: journal}
	if failures != nil {
		id.failureWriter = failures
	}
	if queue > 0 {
		id.retryCh = make(chan *intentRetryJob, queue)
	}
	return id
}

func unavailable(intentID string) error {
	return fmt.Errorf("intent %s (proofClass=on_demand): %w", intentID, errChainedProofUnavailable)
}

// The entitlement pre-screen declined an intent by returning no error and no outcome; discovery logged "declined
// before execution" and wrote nothing, so the intent stayed `authorized` for good. A decline is the not-entitled
// refusal Phase 3 would make, returned as one.
func TestADeclinedIntentIsRefusedByNameNotDroppedSilently(t *testing.T) {
	store := screenStore(t, []entitlement.Leaf{activeLeaf("acc://other.acme/data")}, time.Now().Add(time.Hour))
	id := discoveryWithScreen(t, store, true)

	_, err := id.processIntent(&CertenIntent{IntentID: "declined-1", AccountURL: screenPrincipal}, 7)
	if err == nil {
		t.Fatal("a declined intent was returned as processed: nothing records it, and it stays authorized for good")
	}
	if !errors.Is(err, consensus.ErrNotEntitled) || failureClassOf(err) != database.FailureNotEntitled {
		t.Fatalf("a decline must be the not-entitled refusal, got %v (class %s)", err, failureClassOf(err))
	}
}

// End to end through the block: the declined intent is recorded failed.
func TestADeclinedIntentIsRecordedFailed(t *testing.T) {
	const intentID = "declined-in-block"
	store := screenStore(t, []entitlement.Leaf{activeLeaf("acc://other.acme/data")}, time.Now().Add(time.Hour))
	failures := &failureLog{}
	id := retryDiscovery(&blockClient{txs: []*accumulate.CertenTransaction{blockTx("aa01", intentID, 41)}}, nil, failures, 0)
	id.SetEntitlementScreen(store, func() bool { return true })

	if err := id.processBlock(&BlockProcessJob{BlockHeight: 41}, "test"); err != nil {
		t.Fatalf("processBlock: %v", err)
	}
	if s, ok := failures.status(intentID); !ok || s != database.IntentLifecycleFailed {
		t.Fatalf("the declined intent's lifecycle was not recorded failed (written: %v %q)", ok, s)
	}
}

// A retry is kept from the moment it is queued, survives the process, is resumed with the intent rebuilt from its
// block, and leaves the journal when it ends. It used to live only in memory: a restart lost it, the block had
// been passed as searched, and the intent stayed `authorized`.
func TestARetryOutlivesTheProcessAndEndsOnce(t *testing.T) {
	const intentID = "retried-1"
	path := filepath.Join(t.TempDir(), "intent_retries.json")
	client := &blockClient{txs: []*accumulate.CertenTransaction{blockTx("bb02", intentID, 42)}}

	before := retryDiscovery(client, openJournal(t, path), &failureLog{}, 4)
	ci, err := before.intentInBlock(42, intentID)
	if err != nil {
		t.Fatalf("intentInBlock: %v", err)
	}
	before.enqueueRetry(&intentRetryJob{intent: ci, blockHeight: 42, lastErr: unavailable(intentID)})
	if got := kept(t, before.retries); len(got) != 1 || got[0].IntentID != intentID || got[0].BlockHeight != 42 || got[0].LastError == "" {
		t.Fatalf("a queued retry must be kept with its block and cause, kept %+v", got)
	}

	// The process ends; a new one starts on the same journal.
	failures := &failureLog{}
	after := retryDiscovery(client, openJournal(t, path), failures, 4)
	if !after.resumeRetriesOnce(map[string]bool{}) {
		t.Fatal("a kept retry whose block can be searched must be resumed")
	}
	if len(after.retryCh) != 1 {
		t.Fatalf("the kept retry was not put back on the queue (%d queued)", len(after.retryCh))
	}
	job := <-after.retryCh
	if job.intent.IntentID != intentID || job.intent.AccountURL != "acc://harbor.acme/data" || job.blockHeight != 42 {
		t.Fatalf("the resumed intent was not rebuilt from its block: %+v", job.intent)
	}

	var ran int
	after.retryProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
		ran++
		return consensus.TargetChainPending, nil
	}
	after.handleRetryJob(job)
	if ran != 1 {
		t.Fatalf("the resumed retry ran %d times", ran)
	}
	if got := kept(t, after.retries); len(got) != 0 {
		t.Fatalf("an ended retry must leave the journal, kept %+v", got)
	}
	if _, ok := failures.status(intentID); ok {
		t.Fatal("a retry that succeeded was recorded failed")
	}
}

// A retry the stop interrupts is not ended: it stays kept for the next start.
func TestARetryInterruptedByAStopStaysKept(t *testing.T) {
	const intentID = "interrupted-1"
	failures := &failureLog{}
	id := retryDiscovery(&blockClient{}, openJournal(t, filepath.Join(t.TempDir(), "r.json")), failures, 4)
	id.config.ChainedProofRequeueBackoff = time.Hour
	job := &intentRetryJob{intent: &CertenIntent{IntentID: intentID}, blockHeight: 9, lastErr: unavailable(intentID)}
	id.enqueueRetry(job)
	close(id.stopCh)
	id.handleRetryJob(<-id.retryCh)
	if got := kept(t, id.retries); len(got) != 1 {
		t.Fatalf("an interrupted retry must stay kept for the next start, kept %+v", got)
	}
	if _, ok := failures.status(intentID); ok {
		t.Fatal("an interrupted retry is not a failure")
	}
}

// A retry that cannot be kept and queued is not dropped: its intent is recorded failed. The queue-full branch used
// to log that the intent "remains failed" - nothing had recorded it failed.
func TestARetryThatCannotBeQueuedIsRecordedFailed(t *testing.T) {
	cases := map[string]func(t *testing.T, failures *failureLog) *IntentDiscovery{
		"no retry worker": func(t *testing.T, f *failureLog) *IntentDiscovery {
			return retryDiscovery(&blockClient{}, openJournal(t, filepath.Join(t.TempDir(), "r.json")), f, 0)
		},
		"no journal": func(t *testing.T, f *failureLog) *IntentDiscovery {
			return retryDiscovery(&blockClient{}, nil, f, 4)
		},
		"full queue": func(t *testing.T, f *failureLog) *IntentDiscovery {
			id := retryDiscovery(&blockClient{}, openJournal(t, filepath.Join(t.TempDir(), "r.json")), f, 1)
			id.retryCh <- &intentRetryJob{intent: &CertenIntent{IntentID: "occupies-the-slot"}}
			return id
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			failures := &failureLog{}
			id := build(t, failures)
			const intentID = "unqueued-1"
			done := make(chan struct{})
			go func() {
				id.enqueueRetry(&intentRetryJob{intent: &CertenIntent{IntentID: intentID}, blockHeight: 5, lastErr: unavailable(intentID)})
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("enqueueRetry blocked")
			}
			if s, ok := failures.status(intentID); !ok || s != database.IntentLifecycleFailed {
				t.Fatalf("a retry that could not be queued left the intent unrecorded (written: %v %q)", ok, s)
			}
			if id.retries != nil {
				if got := kept(t, id.retries); len(got) != 0 {
					t.Fatalf("a retry recorded failed must not stay kept, kept %+v", got)
				}
			}
		})
	}
}

// An exhausted retry is recorded failed and leaves the journal; a failure that could not be recorded keeps it, so
// the next start resumes the intent instead of leaving it `authorized`.
func TestAnExhaustedRetryIsRecordedOrKept(t *testing.T) {
	for _, writeFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("record fails=%v", writeFails), func(t *testing.T) {
			const intentID = "exhausted-1"
			failures := &failureLog{}
			if writeFails {
				failures.fail = errors.New("database unavailable")
			}
			id := retryDiscovery(&blockClient{}, openJournal(t, filepath.Join(t.TempDir(), "r.json")), failures, 4)
			id.retryProcess = func(ci *CertenIntent, _ uint64) (consensus.TargetChainOutcome, error) {
				return consensus.TargetChainFailed, unavailable(ci.IntentID)
			}
			job := &intentRetryJob{intent: &CertenIntent{IntentID: intentID}, blockHeight: 6,
				attempts: id.config.ChainedProofRequeueAttempts - 1, lastErr: unavailable(intentID)}
			if err := id.keepRetry(job); err != nil {
				t.Fatal(err)
			}
			id.handleRetryJob(job)
			got := kept(t, id.retries)
			if writeFails {
				if len(got) != 1 {
					t.Fatalf("a failure that was not recorded must keep the retry for the next start, kept %+v", got)
				}
				return
			}
			if s, ok := failures.status(intentID); !ok || s != database.IntentLifecycleFailed {
				t.Fatalf("an exhausted retry was not recorded failed (written: %v %q)", ok, s)
			}
			if len(got) != 0 {
				t.Fatalf("a recorded failure must end the retry, kept %+v", got)
			}
		})
	}
}

// A kept retry whose block no longer carries its intent cannot be resumed and is recorded failed; one whose block
// cannot be searched now is left kept and tried again.
func TestAKeptRetryThatCannotBeRebuilt(t *testing.T) {
	failures := &failureLog{}
	journal := openJournal(t, filepath.Join(t.TempDir(), "r.json"))
	for _, r := range []PendingRetry{{IntentID: "gone-1", BlockHeight: 50, LastError: "x"}, {IntentID: "later-1", BlockHeight: 51, LastError: "y"}} {
		if err := journal.Keep(r); err != nil {
			t.Fatal(err)
		}
	}
	id := retryDiscovery(&failingSearchClient{blockClient: blockClient{txs: []*accumulate.CertenTransaction{blockTx("cc03", "someone-else", 50)}}, failOn: 51}, journal, failures, 4)
	if id.resumeRetriesOnce(map[string]bool{}) {
		t.Fatal("a kept retry whose block could not be searched was reported resumed")
	}
	if s, ok := failures.status("gone-1"); !ok || s != database.IntentLifecycleFailed {
		t.Fatalf("a retry whose intent its block does not carry must be recorded failed (written: %v %q)", ok, s)
	}
	if got := kept(t, journal); len(got) != 1 || got[0].IntentID != "later-1" {
		t.Fatalf("only the retry whose block could not be searched stays kept, kept %+v", got)
	}
}

func TestTheRetryJournalKeepsFirstSeenAndRefusesAnUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	j := openJournal(t, path)
	if err := j.Keep(PendingRetry{IntentID: "a", BlockHeight: 1}); err != nil {
		t.Fatal(err)
	}
	first := kept(t, j)[0].FirstSeen
	if err := j.Keep(PendingRetry{IntentID: "a", BlockHeight: 1, Attempts: 3}); err != nil {
		t.Fatal(err)
	}
	if got := kept(t, j)[0]; !got.FirstSeen.Equal(first) || got.Attempts != 3 {
		t.Fatalf("re-keeping must update attempts and keep when it was first seen: %+v (first %s)", got, first)
	}
	if err := j.Keep(PendingRetry{IntentID: "", BlockHeight: 1}); err == nil {
		t.Fatal("a retry with no intent was kept")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileRetryJournal(path); err == nil {
		t.Fatal("an unreadable journal was opened as empty: the retries it held would be lost")
	}
}
