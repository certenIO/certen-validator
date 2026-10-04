// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Automatic recovery of an executed action's owed proof bundle (RB6, DESIGN_RB6_execution_outcome_states.md §3).
//
// A member recorded proof_pending EXECUTED on its chain; only its proof bundle is missing - its block could not be proven
// yet, the quorum was not met, the write-back did not land. The validator that reported it re-drives it through the
// member repair (the RB4-F55 runner: every precondition checked, the member's round re-derived from its Directory block,
// its proof cycle run on the named settlement), on a backoff, until its bundle is written. Nothing is assumed: each
// attempt is a full proof cycle, and a member that cannot be recovered stays proof_pending, visible in the metrics and
// alerted on, never failed.

// Backoff of a proof_pending member's recovery: first at once, then doubling from proofRecoveryFirst, capped.
const (
	proofRecoveryFirst = time.Minute
	proofRecoveryMax   = time.Hour
	proofRecoveryBatch = 5
)

var (
	proofPendingMembers = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "proof_recovery",
		Name: "pending_members", Help: "Members this validator reported whose action executed with its proof bundle owed (proof_pending)"})
	proofPendingOldest = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "certen", Subsystem: "proof_recovery",
		Name: "oldest_pending_seconds", Help: "Age of this validator's oldest proof_pending member (0 when none)"})
	proofRecoveryAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "certen", Subsystem: "proof_recovery",
		Name: "attempts_total", Help: "Automatic recovery attempts of proof_pending members, by outcome"}, []string{"outcome"})
)

func init() {
	prometheus.MustRegister(proofPendingMembers, proofPendingOldest, proofRecoveryAttempts)
}

// ProofRecovery re-drives this validator's proof_pending members.
type ProofRecovery struct {
	DB          *sql.DB
	ValidatorID string
	// Repair runs one member repair: MemberRepairRunner.Serve.
	Repair func(ctx context.Context, req MemberRepairRequest) *MemberRepairResult
	Every  time.Duration
	Logf   func(format string, args ...interface{})
}

// proofRecoveryBackoff is the wait after the n-th failed attempt (n >= 1).
func proofRecoveryBackoff(n int) time.Duration {
	d := proofRecoveryFirst
	for i := 1; i < n && d < proofRecoveryMax; i++ {
		d *= 2
	}
	if d > proofRecoveryMax {
		d = proofRecoveryMax
	}
	return d
}

// Run recovers due members every Every until ctx ends.
func (p *ProofRecovery) Run(ctx context.Context) {
	every := p.Every
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := p.RunOnce(ctx); err != nil {
			p.Logf("⚠️ [PROOF-RECOVERY] %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type pendingMember struct {
	intentID     string
	chainID      int64
	settlementTx string
	attempts     int
}

// RunOnce re-drives the due proof_pending members this validator reported, and returns how many it attempted.
func (p *ProofRecovery) RunOnce(ctx context.Context) (int, error) {
	var count int
	var oldest sql.NullFloat64
	if err := p.DB.QueryRowContext(ctx, `SELECT count(*), EXTRACT(EPOCH FROM now() - min(recorded_at)) FROM intent_member_outcomes
		WHERE proof_cycle = 'proof_pending' AND reported_by = $1`, p.ValidatorID).Scan(&count, &oldest); err != nil {
		return 0, fmt.Errorf("read proof_pending members: %w", err)
	}
	proofPendingMembers.Set(float64(count))
	proofPendingOldest.Set(oldest.Float64)

	rows, err := p.DB.QueryContext(ctx, `SELECT intent_id, chain_id, COALESCE(settlement_tx, ''), proof_attempts FROM intent_member_outcomes
		WHERE proof_cycle = 'proof_pending' AND reported_by = $1 AND (next_proof_attempt_at IS NULL OR next_proof_attempt_at <= now())
		ORDER BY next_proof_attempt_at NULLS FIRST LIMIT $2`, p.ValidatorID, proofRecoveryBatch)
	if err != nil {
		return 0, fmt.Errorf("read due proof_pending members: %w", err)
	}
	var due []pendingMember
	for rows.Next() {
		var m pendingMember
		if err := rows.Scan(&m.intentID, &m.chainID, &m.settlementTx, &m.attempts); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan proof_pending member: %w", err)
		}
		due = append(due, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, m := range due {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if m.settlementTx == "" {
			// The store refuses an executed member without its transaction; a row like this was written by hand.
			p.Logf("❌ [PROOF-RECOVERY] intent %s member %d is proof_pending with no settlement transaction; it cannot be re-driven",
				m.intentID, m.chainID)
			proofRecoveryAttempts.WithLabelValues("unrecoverable").Inc()
			p.schedule(ctx, m, proofRecoveryMax)
			continue
		}
		req := MemberRepairRequest{ID: fmt.Sprintf("recovery-%s-%d-%d", m.intentID, m.chainID, m.attempts+1), IntentID: m.intentID,
			ChainID: m.chainID, SettlementTx: m.settlementTx, Apply: true, RequestedAt: time.Now().UTC()}
		res := p.Repair(ctx, req)
		outcome := "failed"
		if res != nil {
			outcome = res.Outcome
		}
		proofRecoveryAttempts.WithLabelValues(outcome).Inc()
		if res != nil && res.Outcome == MemberRepairRepaired {
			p.Logf("✅ [PROOF-RECOVERY] intent %s member %d: its proof bundle is written (attempt %d)", m.intentID, m.chainID, m.attempts+1)
			continue
		}
		reason := "no result"
		if res != nil {
			reason = res.Outcome + ": " + res.Reason
		}
		wait := proofRecoveryBackoff(m.attempts + 1)
		p.Logf("⏳ [PROOF-RECOVERY] intent %s member %d: attempt %d did not produce its bundle (%s); next in %s",
			m.intentID, m.chainID, m.attempts+1, reason, wait)
		p.schedule(ctx, m, wait)
	}
	return len(due), nil
}

// schedule counts the attempt and sets the next one, only while the member is still proof_pending.
func (p *ProofRecovery) schedule(ctx context.Context, m pendingMember, wait time.Duration) {
	if _, err := p.DB.ExecContext(ctx, `UPDATE intent_member_outcomes SET proof_attempts = proof_attempts + 1,
		next_proof_attempt_at = now() + make_interval(secs => $3) WHERE intent_id = $1 AND chain_id = $2 AND proof_cycle = 'proof_pending'`,
		m.intentID, m.chainID, wait.Seconds()); err != nil {
		p.Logf("❌ [PROOF-RECOVERY] intent %s member %d: the next attempt could not be scheduled: %v", m.intentID, m.chainID, err)
	}
}
