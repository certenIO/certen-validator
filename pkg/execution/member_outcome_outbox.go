// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// =============================================================================
// Member outcomes the lifecycle store could not take yet (RB3-F78)
// =============================================================================
//
// A member's outcome is its intent's status (RB3-F50): the intent is complete or failed when every
// member's outcome is recorded. It is recorded after the member's write-back, so a store that refused it
// used to leave the intent short of a terminal status for good - the cycle had nothing left to fail.
// The outcome now goes to this outbox when the store refuses it, and the reconciler replays it until
// the store takes it. One the store refuses as contradicting what it holds (ErrMemberOutcomeInvalid) is
// quarantined with its reason: a retry cannot fix it, and deleting it would lose the only record.

// MemberOutcomeOutbox holds member outcomes not yet recorded.
type MemberOutcomeOutbox interface {
	Put(out database.MemberOutcome) error
	List() ([]MemberOutcomeOutboxEntry, error)
	Remove(id string) error
	Quarantine(id, reason string) error
	Depth() (int, error)
}

// MemberOutcomeOutboxEntry is one pending outcome (nil when its file does not decode).
type MemberOutcomeOutboxEntry struct {
	ID      string
	Outcome *database.MemberOutcome
}

// FileMemberOutcomeOutbox is the on-disk outbox: one JSON file per member outcome.
type FileMemberOutcomeOutbox struct {
	store *jsonFileOutbox
}

// NewFileMemberOutcomeOutbox opens (creating if needed) the outbox directory.
func NewFileMemberOutcomeOutbox(dir string) (*FileMemberOutcomeOutbox, error) {
	store, err := newJSONFileOutbox("member outcome outbox", dir)
	if err != nil {
		return nil, err
	}
	return &FileMemberOutcomeOutbox{store: store}, nil
}

// Dir reports where entries are stored.
func (o *FileMemberOutcomeOutbox) Dir() string { return o.store.dir }

// MemberOutcomeOutboxID is one report's entry id: the intent, the member's chain and the cycle that
// reported it - a later report of the same member from another cycle is its own entry.
func MemberOutcomeOutboxID(out database.MemberOutcome) string {
	return outboxID(fmt.Sprintf("%s/%d/%s", out.IntentID, out.ChainID, out.CycleID))
}

func (o *FileMemberOutcomeOutbox) Put(out database.MemberOutcome) error {
	if out.IntentID == "" || out.ChainID == 0 {
		return fmt.Errorf("member outcome outbox: intent id and chain id are required")
	}
	return o.store.put(MemberOutcomeOutboxID(out), out.IntentID, out)
}

func (o *FileMemberOutcomeOutbox) List() ([]MemberOutcomeOutboxEntry, error) {
	raw, err := o.store.list()
	if err != nil {
		return nil, err
	}
	out := make([]MemberOutcomeOutboxEntry, 0, len(raw))
	for _, e := range raw {
		rec := &database.MemberOutcome{}
		if err := json.Unmarshal(e.Body, rec); err != nil {
			out = append(out, MemberOutcomeOutboxEntry{ID: e.ID})
			continue
		}
		out = append(out, MemberOutcomeOutboxEntry{ID: e.ID, Outcome: rec})
	}
	return out, nil
}

func (o *FileMemberOutcomeOutbox) Remove(id string) error { return o.store.remove(id) }
func (o *FileMemberOutcomeOutbox) Quarantine(id, reason string) error {
	return o.store.quarantine(id, reason)
}
func (o *FileMemberOutcomeOutbox) Depth() (int, error) { return o.store.depth() }

// MemberOutcomeRecorder is the lifecycle store's side of an outcome.
type MemberOutcomeRecorder interface {
	RecordMemberOutcome(ctx context.Context, out database.MemberOutcome) (database.DerivedIntentStatus, error)
}

// MemberOutcomeReconciler replays the outbox into the lifecycle store: at start, then every Interval.
type MemberOutcomeReconciler struct {
	Outbox   MemberOutcomeOutbox
	Store    MemberOutcomeRecorder
	Interval time.Duration // zero: one minute
	Logf     func(string, ...interface{})
}

// MemberOutcomeReconcileReport is what one pass did.
type MemberOutcomeReconcileReport struct {
	Pending, Recorded, Quarantined, Deferred, Remaining int
}

// Start runs passes until ctx ends.
func (r *MemberOutcomeReconciler) Start(ctx context.Context) {
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

func (r *MemberOutcomeReconciler) passAndLog(ctx context.Context) {
	rep, err := r.RunOnce(ctx)
	if err != nil {
		r.Logf("❌ [MEMBER-OUTCOME] outbox pass failed: %v", err)
		return
	}
	if rep.Pending > 0 {
		r.Logf("[MEMBER-OUTCOME] outbox pass: pending=%d recorded=%d quarantined=%d deferred=%d remaining=%d",
			rep.Pending, rep.Recorded, rep.Quarantined, rep.Deferred, rep.Remaining)
	}
}

// RunOnce replays every pending outcome once.
func (r *MemberOutcomeReconciler) RunOnce(ctx context.Context) (*MemberOutcomeReconcileReport, error) {
	if r.Outbox == nil || r.Store == nil {
		return nil, fmt.Errorf("member outcome reconciler: outbox and store are required")
	}
	entries, err := r.Outbox.List()
	if err != nil {
		return nil, err
	}
	rep := &MemberOutcomeReconcileReport{Pending: len(entries)}
	for _, e := range entries {
		if e.Outcome == nil {
			if qErr := r.Outbox.Quarantine(e.ID, "entry could not be decoded"); qErr != nil {
				return nil, qErr
			}
			rep.Quarantined++
			continue
		}
		derived, err := r.Store.RecordMemberOutcome(ctx, *e.Outcome)
		switch {
		case err == nil:
			if rmErr := r.Outbox.Remove(e.ID); rmErr != nil {
				return nil, rmErr
			}
			rep.Recorded++
			if derived.Terminal {
				r.Logf("[LIFECYCLE] intent %s is %s: %s (outcome recorded from the outbox)", e.Outcome.IntentID, derived.Status, derived.Summary)
			}
		case errors.Is(err, database.ErrMemberOutcomeInvalid):
			reason := fmt.Sprintf("the lifecycle store refused intent %s member %d: %v", e.Outcome.IntentID, e.Outcome.ChainID, err)
			if qErr := r.Outbox.Quarantine(e.ID, reason); qErr != nil {
				return nil, qErr
			}
			r.Logf("❌ [MEMBER-OUTCOME] quarantined: %s", reason)
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
