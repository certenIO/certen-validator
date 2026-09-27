// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// =============================================================================
// Proof-cycle completions the store could not take yet (RB3-F123)
// =============================================================================
//
// A cycle's level records are closed once, after its write-back: the four level hashes and the write-back
// transaction are bound into the cycle hash. The pass ran exactly once, so one failed read or write left a
// proof whose four levels were all complete marked incomplete for good. What the pass needs from the cycle
// - the write-back transaction and whether the quorum bound the levels - now goes to this outbox when the
// store fails, and the reconciler closes the record from it once the store answers. A record that cannot be
// closed (missing, or missing a level) is quarantined with its reason: a retry cannot fix it.

// ProofCompletion is what closing one level record needs besides the record itself.
type ProofCompletion struct {
	CompletionID  uuid.UUID `json:"completion_id"`
	CycleID       string    `json:"cycle_id"`
	WriteBackTx   string    `json:"write_back_tx"`
	BindingsValid bool      `json:"bindings_valid"`
}

// ProofCompletionOutbox holds completions not yet recorded.
type ProofCompletionOutbox interface {
	Put(c ProofCompletion) error
	List() ([]ProofCompletionOutboxEntry, error)
	Remove(id string) error
	Quarantine(id, reason string) error
	Depth() (int, error)
}

// ProofCompletionOutboxEntry is one pending completion (nil when its file does not decode).
type ProofCompletionOutboxEntry struct {
	ID         string
	Completion *ProofCompletion
}

// FileProofCompletionOutbox is the on-disk outbox: one JSON file per completion.
type FileProofCompletionOutbox struct {
	store *jsonFileOutbox
}

// NewFileProofCompletionOutbox opens (creating if needed) the outbox directory.
func NewFileProofCompletionOutbox(dir string) (*FileProofCompletionOutbox, error) {
	store, err := newJSONFileOutbox("proof completion outbox", dir)
	if err != nil {
		return nil, err
	}
	return &FileProofCompletionOutbox{store: store}, nil
}

// Dir reports where entries are stored.
func (o *FileProofCompletionOutbox) Dir() string { return o.store.dir }

func (o *FileProofCompletionOutbox) Put(c ProofCompletion) error {
	if c.CompletionID == uuid.Nil || c.WriteBackTx == "" {
		return fmt.Errorf("proof completion outbox: a completion id and its write-back transaction are required")
	}
	return o.store.put(outboxID("completion/"+c.CompletionID.String()), c.CycleID, c)
}

func (o *FileProofCompletionOutbox) List() ([]ProofCompletionOutboxEntry, error) {
	raw, err := o.store.list()
	if err != nil {
		return nil, err
	}
	out := make([]ProofCompletionOutboxEntry, 0, len(raw))
	for _, e := range raw {
		c := &ProofCompletion{}
		if err := json.Unmarshal(e.Body, c); err != nil {
			out = append(out, ProofCompletionOutboxEntry{ID: e.ID})
			continue
		}
		out = append(out, ProofCompletionOutboxEntry{ID: e.ID, Completion: c})
	}
	return out, nil
}

func (o *FileProofCompletionOutbox) Remove(id string) error { return o.store.remove(id) }
func (o *FileProofCompletionOutbox) Quarantine(id, reason string) error {
	return o.store.quarantine(id, reason)
}
func (o *FileProofCompletionOutbox) Depth() (int, error) { return o.store.depth() }

// ProofCompletionStore is the store's side of a completion.
type ProofCompletionStore interface {
	GetProofCycleCompletionByID(ctx context.Context, completionID uuid.UUID) (*database.ProofCycleCompletionRecord, error)
	CompleteProofCycle(ctx context.Context, completionID uuid.UUID, bindingsValid bool, cycleHash []byte) error
}

// errCompletionUnclosable is a record that no retry can close: absent, or missing a level.
type errCompletionUnclosable struct{ reason string }

func (e *errCompletionUnclosable) Error() string { return e.reason }

// closeProofCompletion closes one level record: it must exist and hold all four levels.
func closeProofCompletion(ctx context.Context, store ProofCompletionStore, c ProofCompletion) error {
	record, err := store.GetProofCycleCompletionByID(ctx, c.CompletionID)
	if err != nil {
		return err
	}
	if record == nil {
		return &errCompletionUnclosable{fmt.Sprintf("level record %s does not exist", c.CompletionID)}
	}
	if missing := missingLevels(record); len(missing) > 0 {
		return &errCompletionUnclosable{fmt.Sprintf("level record %s (proof %s) lacks %v", c.CompletionID, record.ProofID, missing)}
	}
	return store.CompleteProofCycle(ctx, c.CompletionID, c.BindingsValid, proofCycleHash(record, c.WriteBackTx))
}

// missingLevels names the levels a record has not completed.
func missingLevels(record *database.ProofCycleCompletionRecord) []string {
	var missing []string
	for level, done := range []bool{record.Level1Complete, record.Level2Complete, record.Level3Complete, record.Level4Complete} {
		if !done {
			missing = append(missing, fmt.Sprintf("L%d", level+1))
		}
	}
	return missing
}

// ProofCompletionReconciler replays the outbox into the store: at start, then every Interval.
type ProofCompletionReconciler struct {
	Outbox   ProofCompletionOutbox
	Store    ProofCompletionStore
	Interval time.Duration // zero: one minute
	Logf     func(string, ...interface{})
}

// ProofCompletionReconcileReport is what one pass did.
type ProofCompletionReconcileReport struct {
	Pending, Completed, Quarantined, Deferred, Remaining int
}

// Start runs passes until ctx ends.
func (r *ProofCompletionReconciler) Start(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		r.passAndLog(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.passAndLog(ctx)
			}
		}
	}()
}

func (r *ProofCompletionReconciler) passAndLog(ctx context.Context) {
	rep, err := r.RunOnce(ctx)
	if err != nil {
		r.Logf("❌ [PROOF-LEVELS] completion outbox pass failed: %v", err)
		return
	}
	if rep.Pending > 0 {
		r.Logf("[PROOF-LEVELS] completion outbox pass: pending=%d completed=%d quarantined=%d deferred=%d remaining=%d",
			rep.Pending, rep.Completed, rep.Quarantined, rep.Deferred, rep.Remaining)
	}
}

// RunOnce replays every pending completion once.
func (r *ProofCompletionReconciler) RunOnce(ctx context.Context) (*ProofCompletionReconcileReport, error) {
	if r.Outbox == nil || r.Store == nil {
		return nil, fmt.Errorf("proof completion reconciler: outbox and store are required")
	}
	entries, err := r.Outbox.List()
	if err != nil {
		return nil, err
	}
	rep := &ProofCompletionReconcileReport{Pending: len(entries)}
	for _, e := range entries {
		if e.Completion == nil {
			if qErr := r.Outbox.Quarantine(e.ID, "entry could not be decoded"); qErr != nil {
				return nil, qErr
			}
			rep.Quarantined++
			continue
		}
		err := closeProofCompletion(ctx, r.Store, *e.Completion)
		var unclosable *errCompletionUnclosable
		switch {
		case err == nil:
			if rmErr := r.Outbox.Remove(e.ID); rmErr != nil {
				return nil, rmErr
			}
			rep.Completed++
			r.Logf("✅ [PROOF-LEVELS] cycle %s: level record %s completed from the outbox", e.Completion.CycleID, e.Completion.CompletionID)
		case asUnclosable(err, &unclosable):
			if qErr := r.Outbox.Quarantine(e.ID, unclosable.reason); qErr != nil {
				return nil, qErr
			}
			r.Logf("❌ [PROOF-LEVELS] quarantined: %s", unclosable.reason)
			rep.Quarantined++
		default:
			rep.Deferred++
		}
	}
	if rep.Remaining, err = r.Outbox.Depth(); err != nil {
		return nil, err
	}
	return rep, nil
}

func asUnclosable(err error, target **errCompletionUnclosable) bool {
	u, ok := err.(*errCompletionUnclosable)
	if ok {
		*target = u
	}
	return ok
}
