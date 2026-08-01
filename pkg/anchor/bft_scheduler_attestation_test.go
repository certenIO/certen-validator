package anchor

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/verification"
)

// fakeExecutor lets a test script per-attempt outcomes for the target chain.
type fakeExecutor struct {
	mu       sync.Mutex
	calls    int
	outcomes []error // one entry per expected call; nil == success
}

func (f *fakeExecutor) SubmitAnchorFromValidatorBlock(
	_ context.Context,
	_ *verification.ValidatorBlockMetadata,
	_ *verification.BFTExecutionMetadata,
) (*verification.AnchorExecutionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	idx := f.calls
	f.calls++
	if idx < len(f.outcomes) && f.outcomes[idx] != nil {
		return nil, f.outcomes[idx]
	}
	return &verification.AnchorExecutionResult{
		AnchorTxID:               "0xanchor",
		Network:                  "sepolia",
		CreateTxHash:             "0xcreate",
		VerifyTxHash:             "0xverify",
		GovernanceTxHash:         "0xgov",
		AllTransactionsConfirmed: true,
	}, nil
}

func (f *fakeExecutor) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func newTestAdapter(exec verification.TargetChainExecutor) *BFTSchedulerAdapter {
	return NewBFTSchedulerAdapter(nil, exec, &BFTSchedulerConfig{
		BatchInterval: time.Hour,
		MinBatchSize:  1,
		MaxBatchSize:  100,
	}, quietLogger())
}

func testQueuedIntent(id string) *QueuedIntent {
	return &QueuedIntent{
		IntentID:    id,
		VBMeta:      &verification.ValidatorBlockMetadata{},
		BFTMeta:     &verification.BFTExecutionMetadata{},
		QueuedAt:    time.Now(),
		ScheduledAt: time.Now(),
		Attestation: "snapshot-" + id,
	}
}

// THE core regression: before this wiring, on_cadence intents executed on-chain and their
// proof cycle never closed. processBatch must now attest every settled intent.
func TestProcessBatch_AttestsSettledIntents(t *testing.T) {
	exec := &fakeExecutor{}
	a := newTestAdapter(exec)

	var mu sync.Mutex
	var attested []string
	a.SetAttestationRunner(func(_ context.Context, payload interface{}, res *verification.AnchorExecutionResult) {
		mu.Lock()
		defer mu.Unlock()
		if res == nil || !res.AllTransactionsConfirmed {
			t.Errorf("attestation received an unconfirmed result")
		}
		attested = append(attested, payload.(string))
	})

	batch := []*QueuedIntent{testQueuedIntent("i1"), testQueuedIntent("i2")}
	a.processBatch(context.Background(), batch)

	mu.Lock()
	defer mu.Unlock()
	if len(attested) != 2 {
		t.Fatalf("expected 2 attestations, got %d — cadence intents settled without closing their proof cycle", len(attested))
	}
	if attested[0] != "snapshot-i1" || attested[1] != "snapshot-i2" {
		t.Fatalf("wrong snapshots replayed: %v", attested)
	}
}

// Each intent must attest with its OWN snapshot even though they share one batch tx.
func TestProcessBatch_PerIntentAttestationSharesBatchTx(t *testing.T) {
	exec := &fakeExecutor{}
	a := newTestAdapter(exec)

	var mu sync.Mutex
	seen := map[string]string{}
	a.SetAttestationRunner(func(_ context.Context, payload interface{}, res *verification.AnchorExecutionResult) {
		mu.Lock()
		defer mu.Unlock()
		seen[payload.(string)] = res.GovernanceTxHash
	})

	a.processBatch(context.Background(), []*QueuedIntent{testQueuedIntent("a"), testQueuedIntent("b")})

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected per-intent attestation, got %d", len(seen))
	}
	if seen["snapshot-a"] != "0xgov" || seen["snapshot-b"] != "0xgov" {
		t.Fatalf("both intents should reference the shared batch tx: %v", seen)
	}
}

// A failed batch does not consume its anchor, so retry-once is safe and required.
func TestProcessBatch_RetriesOnceThenDeadLetters(t *testing.T) {
	exec := &fakeExecutor{outcomes: []error{fmt.Errorf("rpc down"), fmt.Errorf("still down")}}
	a := newTestAdapter(exec)

	var attestCount int
	var mu sync.Mutex
	a.SetAttestationRunner(func(_ context.Context, _ interface{}, _ *verification.AnchorExecutionResult) {
		mu.Lock()
		attestCount++
		mu.Unlock()
	})

	qi := testQueuedIntent("flaky")

	// Attempt 1 fails -> requeued, not dead-lettered.
	a.processBatch(context.Background(), []*QueuedIntent{qi})
	if got := len(a.DeadLetteredIntents()); got != 0 {
		t.Fatalf("must not dead-letter after one failure, got %d", got)
	}
	if a.GetQueuedCount() != 1 {
		t.Fatalf("failed intent must be requeued for retry, queue=%d", a.GetQueuedCount())
	}

	// Attempt 2 fails -> dead-lettered.
	a.processBatch(context.Background(), []*QueuedIntent{qi})
	dl := a.DeadLetteredIntents()
	if len(dl) != 1 {
		t.Fatalf("expected 1 dead-lettered intent, got %d", len(dl))
	}
	if dl[0].IntentID != "flaky" || dl[0].Attempts != 2 {
		t.Fatalf("dead-letter record wrong: %+v", dl[0])
	}
	if exec.callCount() != 2 {
		t.Fatalf("expected exactly 2 execution attempts, got %d", exec.callCount())
	}
}

// A successful retry must attest, not dead-letter.
func TestProcessBatch_SucceedsOnRetry(t *testing.T) {
	exec := &fakeExecutor{outcomes: []error{fmt.Errorf("transient")}}
	a := newTestAdapter(exec)

	var mu sync.Mutex
	attested := 0
	a.SetAttestationRunner(func(_ context.Context, _ interface{}, res *verification.AnchorExecutionResult) {
		mu.Lock()
		defer mu.Unlock()
		if res != nil && res.AllTransactionsConfirmed {
			attested++
		}
	})

	qi := testQueuedIntent("recovers")
	a.processBatch(context.Background(), []*QueuedIntent{qi}) // fails, requeues
	a.processBatch(context.Background(), []*QueuedIntent{qi}) // succeeds

	mu.Lock()
	defer mu.Unlock()
	if attested != 1 {
		t.Fatalf("expected 1 successful attestation after retry, got %d", attested)
	}
	if len(a.DeadLetteredIntents()) != 0 {
		t.Fatal("a recovered intent must not be dead-lettered")
	}
}

// An unconfirmed result is a failure even when err is nil — otherwise a half-executed
// batch would attest as success.
func TestProcessBatch_UnconfirmedResultCountsAsFailure(t *testing.T) {
	a := newTestAdapter(&unconfirmedExecutor{})

	var mu sync.Mutex
	successAttestations := 0
	a.SetAttestationRunner(func(_ context.Context, _ interface{}, res *verification.AnchorExecutionResult) {
		mu.Lock()
		defer mu.Unlock()
		if res != nil && res.AllTransactionsConfirmed {
			successAttestations++
		}
	})

	qi := testQueuedIntent("unconfirmed")
	a.processBatch(context.Background(), []*QueuedIntent{qi})
	a.processBatch(context.Background(), []*QueuedIntent{qi})

	mu.Lock()
	defer mu.Unlock()
	if successAttestations != 0 {
		t.Fatal("an unconfirmed execution must never attest as success")
	}
	if len(a.DeadLetteredIntents()) != 1 {
		t.Fatalf("unconfirmed execution must dead-letter after retries, got %d", len(a.DeadLetteredIntents()))
	}
}

type unconfirmedExecutor struct{}

func (unconfirmedExecutor) SubmitAnchorFromValidatorBlock(
	_ context.Context, _ *verification.ValidatorBlockMetadata, _ *verification.BFTExecutionMetadata,
) (*verification.AnchorExecutionResult, error) {
	return &verification.AnchorExecutionResult{
		AnchorTxID:               "0xanchor",
		AllTransactionsConfirmed: false, // reverted / partial
	}, nil
}

// Missing runner must be loud, never silent — this is the failure mode that hid the
// original defect.
func TestProcessBatch_MissingRunnerDoesNotPanic(t *testing.T) {
	a := newTestAdapter(&fakeExecutor{})
	// No SetAttestationRunner call.
	a.processBatch(context.Background(), []*QueuedIntent{testQueuedIntent("orphan")})
	// Reaching here without a panic is the assertion; the adapter logs the warning.
}

func TestQueueForCadenceWithAttestation_StoresSnapshot(t *testing.T) {
	a := newTestAdapter(&fakeExecutor{})

	_, err := a.QueueForCadenceWithAttestation(
		context.Background(), "i1",
		&verification.ValidatorBlockMetadata{}, &verification.BFTExecutionMetadata{},
		"my-snapshot",
	)
	if err != nil {
		t.Fatalf("queue failed: %v", err)
	}

	queued := a.GetQueuedIntents()
	if len(queued) != 1 {
		t.Fatalf("expected 1 queued intent, got %d", len(queued))
	}
	if queued[0].Attestation != "my-snapshot" {
		t.Fatalf("snapshot not stored: %v", queued[0].Attestation)
	}
}

// An intent queued WITHOUT a snapshot executes but cannot attest; it must not panic and
// must not be reported as attested.
func TestProcessBatch_NoSnapshotDoesNotAttest(t *testing.T) {
	a := newTestAdapter(&fakeExecutor{})

	called := false
	a.SetAttestationRunner(func(_ context.Context, _ interface{}, _ *verification.AnchorExecutionResult) {
		called = true
	})

	qi := testQueuedIntent("nosnap")
	qi.Attestation = nil
	a.processBatch(context.Background(), []*QueuedIntent{qi})

	if called {
		t.Fatal("must not invoke the runner without a snapshot")
	}
}
