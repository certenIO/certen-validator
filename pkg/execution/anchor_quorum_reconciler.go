// Copyright 2026 Certen Protocol
//
// Replays the anchor quorum outbox into the database.

package execution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/metrics"
)

// AnchorQuorumReconciler drains the outbox back into the database.
//
// The writer's job is to record evidence while the database is healthy. This is the other half: everything
// the writer had to set aside — a saturated queue, a database that was down, a process that shut down with
// records still in flight — is replayed here, on a timer, until it lands.
//
// It is deliberately dumb. It re-offers each stored record to the same RecordAnchorQuorum the live path
// uses, which is write-once and conflict-refusing, so replaying an anchor another validator already
// recorded is a no-op rather than a second opinion. Nothing here reconstructs, infers or repairs evidence:
// an entry either records as it stands or is set aside for a human.
type AnchorQuorumReconciler struct {
	Outbox AnchorQuorumOutbox
	Store  AnchorQuorumStore
	// Interval between passes. Zero means five minutes.
	Interval time.Duration
	// CallTimeout bounds one database write. Zero means sixty seconds.
	CallTimeout time.Duration
	Logf        func(string, ...interface{})

	cancel context.CancelFunc
	done   chan struct{}
}

// AnchorQuorumReconcileReport is what one pass did.
type AnchorQuorumReconcileReport struct {
	Pending     int // entries seen at the start of the pass
	Recorded    int // written by this pass
	AlreadyHeld int // the database already had the row; entry retired
	Quarantined int // conflicting or unparseable; set aside, never overwritten
	Deferred    int // still failing; left for the next pass
	Remaining   int // depth after the pass
}

const (
	anchorQuorumReconcileInterval = 5 * time.Minute
	anchorQuorumReconcileTimeout  = 60 * time.Second
)

// Start runs passes until ctx ends. Safe to call once.
func (r *AnchorQuorumReconciler) Start(ctx context.Context) {
	if r.Outbox == nil || r.Store == nil {
		return
	}
	interval := r.Interval
	if interval <= 0 {
		interval = anchorQuorumReconcileInterval
	}
	rctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.done = make(chan struct{})

	go func() {
		defer close(r.done)
		// A pass at startup, before the first tick: the commonest reason for a non-empty outbox is the
		// shutdown that just ended, and making an operator wait an interval to find out whether the
		// evidence survived defeats the point of persisting it.
		r.passAndLog(rctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-rctx.Done():
				return
			case <-t.C:
				r.passAndLog(rctx)
			}
		}
	}()
}

// Stop ends the loop and waits for the current pass.
func (r *AnchorQuorumReconciler) Stop() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	<-r.done
}

func (r *AnchorQuorumReconciler) logf(format string, args ...interface{}) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *AnchorQuorumReconciler) passAndLog(ctx context.Context) {
	rep, err := r.RunOnce(ctx)
	if err != nil {
		r.logf("⚠️ [ANCHOR-QUORUM] outbox pass failed: %v", err)
		return
	}
	if rep.Pending == 0 {
		return // silence is the normal case; an empty outbox is not news
	}
	r.logf("[ANCHOR-QUORUM] outbox pass: pending=%d recorded=%d already-held=%d quarantined=%d deferred=%d remaining=%d",
		rep.Pending, rep.Recorded, rep.AlreadyHeld, rep.Quarantined, rep.Deferred, rep.Remaining)
}

// RunOnce replays every pending entry once.
//
// A transient failure leaves the entry in place: the next pass retries it, and the entry outlives the
// process, so there is no window in which giving up loses evidence. Only two outcomes retire an entry
// without recording it, and both are reported loudly: the database disagrees about this anchor, or the
// file does not parse.
func (r *AnchorQuorumReconciler) RunOnce(ctx context.Context) (*AnchorQuorumReconcileReport, error) {
	if r.Outbox == nil || r.Store == nil {
		return nil, fmt.Errorf("anchor quorum reconciler: outbox and store are required")
	}
	entries, err := r.Outbox.List()
	if err != nil {
		return nil, err
	}
	timeout := r.CallTimeout
	if timeout <= 0 {
		timeout = anchorQuorumReconcileTimeout
	}

	rep := &AnchorQuorumReconcileReport{Pending: len(entries)}
	for _, entry := range entries {
		if ctx.Err() != nil {
			rep.Deferred++
			continue
		}
		if entry.Record == nil {
			// Unparseable. Never silently deleted — it is the only local copy of whatever it was.
			if qErr := r.Outbox.Quarantine(entry.ID, "entry could not be decoded"); qErr != nil {
				r.logf("⚠️ [ANCHOR-QUORUM] could not quarantine unreadable outbox entry %s: %v", entry.ID, qErr)
				rep.Deferred++
				continue
			}
			rep.Quarantined++
			metrics.RecordAnchorQuorumOutboxQuarantined()
			r.logf("❌ [ANCHOR-QUORUM] outbox entry %s does not decode; moved to quarantine", entry.ID)
			continue
		}

		cctx, cancel := context.WithTimeout(ctx, timeout)
		written, wErr := r.Store.RecordAnchorQuorum(cctx, entry.Record)
		cancel()

		var conflict *database.AnchorQuorumConflict
		switch {
		case errors.As(wErr, &conflict):
			if qErr := r.Outbox.Quarantine(entry.ID, conflict.Error()); qErr != nil {
				r.logf("⚠️ [ANCHOR-QUORUM] could not quarantine conflicting entry %s: %v", entry.ID, qErr)
				rep.Deferred++
				continue
			}
			rep.Quarantined++
			metrics.RecordAnchorQuorumConflict()
			metrics.RecordAnchorQuorumOutboxQuarantined()
			r.logf("❌ [ANCHOR-QUORUM] CONFLICT replaying outbox entry: %v — the stored row was NOT changed; "+
				"evidence kept in quarantine", conflict)
		case wErr != nil:
			// Transient as far as this pass can tell. Keep the entry and try again next time.
			rep.Deferred++
			r.logf("⚠️ [ANCHOR-QUORUM] outbox replay deferred for chain=%d bundle=%s: %v",
				entry.Record.ChainID, entry.Record.BundleID, wErr)
		default:
			if rmErr := r.Outbox.Remove(entry.ID); rmErr != nil {
				// The row IS recorded; failing to clear the entry only means it is replayed once more,
				// which is a no-op. Report it and carry on.
				r.logf("⚠️ [ANCHOR-QUORUM] recorded chain=%d bundle=%s but could not clear its outbox entry: %v",
					entry.Record.ChainID, entry.Record.BundleID, rmErr)
			}
			if written {
				rep.Recorded++
				metrics.RecordAnchorQuorumWritten()
				metrics.RecordAnchorQuorumOutboxReplayed()
				r.logf("✅ [ANCHOR-QUORUM] recovered from outbox: chain=%d bundle=%s (%d member(s), %d signer(s))",
					entry.Record.ChainID, entry.Record.BundleID,
					len(entry.Record.Members), len(entry.Record.Signers))
			} else {
				rep.AlreadyHeld++
			}
		}
	}

	if depth, dErr := r.Outbox.Depth(); dErr == nil {
		rep.Remaining = depth
		metrics.SetAnchorQuorumOutboxDepth(depth)
	}
	return rep, nil
}
