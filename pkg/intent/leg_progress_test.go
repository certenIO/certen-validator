package intent

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Leg progress must reach the DURABLE record, not just the handler's memory.
//
// intent_lifecycle.legs_completed / legs_failed are written by exactly one function,
// UpdateLegProgress, and it had no caller — because SetLegCompletionHandler had no caller
// either, so multiLegEnabled was permanently false. All 542 lifecycle rows sat at 0 completed
// legs, including 238 whose status was 'complete'.
//
// Those columns are the first thing any analysis of multi-leg behaviour reads, and reading them
// is what led three separate reviews to conclude multi-leg had never run. It had: 34 intents
// across 613 legs, every one with an on-chain transaction. The work happened; the record of it
// did not.

// progressRecorder captures OnProgress callbacks. They fire on their own goroutine, so it
// synchronises rather than assuming ordering.
type progressRecorder struct {
	mu    sync.Mutex
	calls []progressCall
	fired chan struct{}
}

type progressCall struct {
	intentID  string
	completed int
	failed    int
}

func newProgressRecorder() *progressRecorder {
	return &progressRecorder{fired: make(chan struct{}, 16)}
}

func (p *progressRecorder) record(_ context.Context, intentID string, completed, failed int) {
	p.mu.Lock()
	p.calls = append(p.calls, progressCall{intentID, completed, failed})
	p.mu.Unlock()
	p.fired <- struct{}{}
}

func (p *progressRecorder) await(t *testing.T) {
	t.Helper()
	select {
	case <-p.fired:
	case <-time.After(2 * time.Second):
		t.Fatal("OnProgress never fired; leg progress would never reach intent_lifecycle")
	}
}

func (p *progressRecorder) last() progressCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return progressCall{}
	}
	return p.calls[len(p.calls)-1]
}

// seedIntent installs a two-leg intent directly into the handler. RegisterIntent needs a full
// cross-chain envelope; this test is about what happens AFTER registration, so it seeds the
// state that registration would have produced.
func seedIntent(h *LegCompletionHandler, intentID string, legIDs ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.intents[intentID] = &MultiLegIntentRecord{
		IntentID:    intentID,
		LegCount:    len(legIDs),
		LegsPending: len(legIDs),
		Status:      MultiLegStatusProcessing,
		Legs:        map[string]*LegRecord{},
	}
	for i, id := range legIDs {
		leg := &LegRecord{
			IntentID:      intentID,
			LegIndex:      i,
			LegExternalID: id,
			Status:        LegStatusProcessing,
		}
		h.legs[id] = leg
		h.legsByIntent[intentID] = append(h.legsByIntent[intentID], id)
		h.intents[intentID].Legs[id] = leg
	}
}

func TestLegCompletionPersistsProgress(t *testing.T) {
	rec := newProgressRecorder()
	h := NewLegCompletionHandler(&LegCompletionHandlerConfig{OnProgress: rec.record})
	seedIntent(h, "intent-1", "leg-a", "leg-b")

	if err := h.OnLegCompleted(context.Background(), "leg-a", "0xaaa", 100); err != nil {
		t.Fatalf("OnLegCompleted: %v", err)
	}
	rec.await(t)

	got := rec.last()
	if got.intentID != "intent-1" || got.completed != 1 || got.failed != 0 {
		t.Fatalf("progress = %+v, want intent-1 with 1 completed, 0 failed", got)
	}
}

// Progress must persist on INTERMEDIATE transitions too, not only when the last leg lands.
// Persisting only at the end means a crash mid-intent leaves the durable record claiming no
// legs were done, when some already cost real gas.
func TestProgressPersistsBeforeTheIntentFinishes(t *testing.T) {
	rec := newProgressRecorder()
	h := NewLegCompletionHandler(&LegCompletionHandlerConfig{OnProgress: rec.record})
	seedIntent(h, "intent-1", "leg-a", "leg-b")

	if err := h.OnLegCompleted(context.Background(), "leg-a", "0xaaa", 100); err != nil {
		t.Fatalf("OnLegCompleted: %v", err)
	}
	rec.await(t)

	// One of two legs done: the intent is still in flight, and the record must already say so.
	if got := rec.last(); got.completed != 1 {
		t.Fatalf("intermediate progress not persisted: %+v", got)
	}
}

// A failed leg is also progress. legs_failed exists so a partially-executed intent can be told
// apart from one that never started — they have very different billing consequences.
func TestLegFailurePersistsProgress(t *testing.T) {
	rec := newProgressRecorder()
	h := NewLegCompletionHandler(&LegCompletionHandlerConfig{OnProgress: rec.record})
	seedIntent(h, "intent-1", "leg-a", "leg-b")

	if err := h.OnLegFailed(context.Background(), "leg-a", "reverted"); err != nil {
		t.Fatalf("OnLegFailed: %v", err)
	}
	rec.await(t)

	if got := rec.last(); got.failed != 1 {
		t.Fatalf("failure progress = %+v, want 1 failed", got)
	}
}

// Both legs done must report the full count — this is the value that makes
// `status='complete' AND legs_completed=0` impossible going forward.
func TestAllLegsCompletedReportsFullCount(t *testing.T) {
	rec := newProgressRecorder()
	h := NewLegCompletionHandler(&LegCompletionHandlerConfig{OnProgress: rec.record})
	seedIntent(h, "intent-1", "leg-a", "leg-b")

	for _, leg := range []string{"leg-a", "leg-b"} {
		if err := h.OnLegCompleted(context.Background(), leg, "0x"+leg, 100); err != nil {
			t.Fatalf("OnLegCompleted(%s): %v", leg, err)
		}
		rec.await(t)
	}

	if got := rec.last(); got.completed != 2 {
		t.Fatalf("final progress = %+v, want 2 completed", got)
	}
}

// A handler with no OnProgress must still work. The callback is optional wiring, and a
// validator started without repositories must not panic on every leg.
func TestProgressCallbackIsOptional(t *testing.T) {
	h := NewLegCompletionHandler(&LegCompletionHandlerConfig{})
	seedIntent(h, "intent-1", "leg-a")

	if err := h.OnLegCompleted(context.Background(), "leg-a", "0xaaa", 100); err != nil {
		t.Fatalf("OnLegCompleted without OnProgress: %v", err)
	}
}
