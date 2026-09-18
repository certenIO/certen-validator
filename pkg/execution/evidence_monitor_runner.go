// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"database/sql"
	"time"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/metrics"
)

// EvidenceMonitor runs the standing evidence checks on a timer and publishes them as gauges.
//
// # WHY A TIMER AND NOT AN ASSERTION
//
// Each thing it checks was introduced by code that believed it was correct. An assertion placed in that
// code would have shared its assumption and agreed with it — the layer-5 writer was perfectly happy
// publishing a root no transaction contained. Asking the whole database "is anything inconsistent right
// now", from outside the write path, on a schedule, is a different question, and it is the one that
// would have caught every defect in the 2026-09 anchor-quorum work within the hour instead of over weeks.
//
// It is read-only and it is allowed to fail: a check that errors increments a counter rather than
// pretending the answer is zero.
type EvidenceMonitor struct {
	DB *sql.DB
	// Interval between passes. Zero means five minutes.
	Interval time.Duration
	// Window for the settled-without-canonical check. Zero means one hour.
	Window time.Duration
	Logf   func(string, ...interface{})
}

// Start runs passes until ctx is cancelled. It returns immediately.
func (m *EvidenceMonitor) Start(ctx context.Context) {
	if m == nil || m.DB == nil {
		return
	}
	interval := m.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	logf := m.Logf
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}

	go func() {
		// One pass immediately: a validator that has just restarted is exactly when the schema check
		// matters, and waiting a full interval to discover the database is behind wastes the restart.
		m.runOnce(ctx, logf)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.runOnce(ctx, logf)
			}
		}
	}()
}

func (m *EvidenceMonitor) runOnce(ctx context.Context, logf func(string, ...interface{})) {
	passCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// The schema check first. When it trips, a restart of this binary FAILS — Verify is fatal at
	// startup — so it is the one an operator must see before they roll anything, not after.
	required, err := schema.LatestVersion()
	if err != nil {
		metrics.IncEvidenceCheckError()
		logf("[EVIDENCE] cannot read the migration catalog: %v", err)
	} else {
		runner := schema.Runner{DB: m.DB}
		if vErr := runner.Verify(passCtx, required); vErr != nil {
			metrics.SetSchemaBehindBinary(true)
			logf("[EVIDENCE] SCHEMA BEHIND BINARY: this database does not satisfy catalog %s (%v). "+
				"A restart of this binary will fail on startup. Migrate before rolling: "+
				"cmd/schemamigrate, or MIGRATE_ON_START=true.", required, vErr)
		} else {
			metrics.SetSchemaBehindBinary(false)
		}
	}

	rep, err := (database.EvidenceQueries{DB: m.DB, Window: m.Window}).Run(passCtx)
	if err != nil {
		// Leave the gauges at their previous values rather than zeroing them. Zero means "checked and
		// clean"; a failed check has not established that.
		metrics.IncEvidenceCheckError()
		logf("[EVIDENCE] checks could not run: %v", err)
		return
	}

	metrics.SetSettledWithoutCanonicalRow(rep.SettledWithoutCanonicalRow)
	metrics.SetContradictedLayer5Rows(rep.ContradictedLayer5Rows)

	if rep.SettledWithoutCanonicalRow > 0 {
		logf("[EVIDENCE] %d intent(s) settled with no canonical anchor row. Their quorum was proven and "+
			"the evidence did not land; recover with cmd/anchorquorumbackfill.",
			rep.SettledWithoutCanonicalRow)
	}
	if rep.ContradictedLayer5Rows > 0 {
		logf("[EVIDENCE] %d standing layer-5 row(s) name a root other than the canonical anchor their "+
			"intent was published in. These are published claims the chain does not support.",
			rep.ContradictedLayer5Rows)
	}
}
