package intent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

type recordingLifecycle struct {
	ctxErr      error
	hasDeadline bool
	remaining   time.Duration
	intentID    string
	status      database.IntentLifecycleStatus
	calls       int
}

func (r *recordingLifecycle) UpdateStatus(ctx context.Context, intentID string,
	newStatus database.IntentLifecycleStatus, _ ...database.UpdateOption) error {
	r.calls++
	r.ctxErr = ctx.Err()
	dl, ok := ctx.Deadline()
	r.hasDeadline = ok
	r.remaining = time.Until(dl)
	r.intentID, r.status = intentID, newStatus
	return r.ctxErr
}

// Observed live 2026-09-26 on every validator: processBlock's 30s context had expired by the time
// processIntent (bounded by the minutes-long BFT timeout) returned, so the terminal-failure write
// failed with "context deadline exceeded" and the intent was never recorded as failed. The write
// must run on a live context of its own, whatever happened to the block's.
func TestRecordLifecycleFailed_WritesOnItsOwnLiveBoundedContext(t *testing.T) {
	blockCtx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-blockCtx.Done() // the block's context is gone, as it is after a long processIntent

	w := &recordingLifecycle{}
	if err := recordLifecycleFailed(w, "31e958a1-40f5-4308-9133-3fe00046309d", errors.New("G1 governance proof failed")); err != nil {
		t.Fatalf("write must succeed on its own context, got %v", err)
	}
	if w.calls != 1 || w.ctxErr != nil {
		t.Fatalf("calls=%d ctxErr=%v: the write ran on a dead context", w.calls, w.ctxErr)
	}
	if !w.hasDeadline || w.remaining <= 0 || w.remaining > lifecycleWriteTimeout {
		t.Fatalf("the write must be bounded by lifecycleWriteTimeout, remaining=%s deadline=%v", w.remaining, w.hasDeadline)
	}
	if w.intentID != "31e958a1-40f5-4308-9133-3fe00046309d" || w.status != database.IntentLifecycleFailed {
		t.Fatalf("wrote %q/%q", w.intentID, w.status)
	}
}
