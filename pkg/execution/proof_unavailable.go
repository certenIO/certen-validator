// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/certen/independant-validator/pkg/database"
)

// Declaring an executed action's proof unavailable (RB6 state 3; owner decision 2026-10-04: declared only by an operator,
// with the evidence, never inferred).
//
// "Never" cannot be observed, so the declaration is a recorded judgement with its evidence: the member has been
// proof_pending - recovered automatically, and failing - for at least ProofUnavailableMinPending, and a fresh probe of every
// configured provider finds its block's bodies unprovable now. If the block CAN be proven now, the declaration is refused:
// the automatic recovery is the path. The member's prior proof_pending outcome is kept as a correction (the store records
// every replaced outcome).

// ProofUnavailableMinPending is how long a member must have been proof_pending before its proof may be declared unavailable.
const ProofUnavailableMinPending = 7 * 24 * time.Hour

// ProofProbe probes a settlement's provability now: proven is true when its block can be proven through the chain's
// agreeing providers; findings states, per provider, what it served for the transaction and its block.
type ProofProbe func(ctx context.Context, chainID int64, settlementTx string) (proven bool, findings []string, err error)

// ProofUnavailableRequest is one declaration.
type ProofUnavailableRequest struct {
	IntentID     string
	ChainID      int64
	SettlementTx string
	Operator     string
	Evidence     string
	Apply        bool
}

// ProofUnavailableResult is what a declaration came to.
type ProofUnavailableResult struct {
	Declared bool
	Refused  string
	Findings []string
	Reason   string
}

// DeclareProofUnavailable checks and, with Apply, records a member's proof as unavailable.
func DeclareProofUnavailable(ctx context.Context, db *sql.DB, lifecycle *database.IntentLifecycleRepository, probe ProofProbe,
	req ProofUnavailableRequest, now time.Time) (*ProofUnavailableResult, error) {
	res := &ProofUnavailableResult{}
	refuse := func(format string, args ...interface{}) (*ProofUnavailableResult, error) {
		res.Refused = fmt.Sprintf(format, args...)
		return res, nil
	}
	if req.IntentID == "" || req.ChainID == 0 || req.SettlementTx == "" || strings.TrimSpace(req.Operator) == "" ||
		strings.TrimSpace(req.Evidence) == "" {
		return nil, errors.New("intent, chain, settlement transaction, operator and evidence are all required")
	}

	var settlement, proofCycle, settlementTx string
	var legs int
	var members pq.Int64Array
	err := db.QueryRowContext(ctx, `SELECT m.settlement, m.proof_cycle, COALESCE(m.settlement_tx, ''), m.legs, l.member_chains
		FROM intent_member_outcomes m JOIN intent_lifecycle l USING (intent_id) WHERE m.intent_id = $1 AND m.chain_id = $2`,
		req.IntentID, req.ChainID).Scan(&settlement, &proofCycle, &settlementTx, &legs, &members)
	if errors.Is(err, sql.ErrNoRows) {
		return refuse("intent %s has no recorded outcome for member %d", req.IntentID, req.ChainID)
	}
	if err != nil {
		return nil, fmt.Errorf("read member %s/%d: %w", req.IntentID, req.ChainID, err)
	}
	if proofCycle != string(database.MemberProofCyclePending) {
		return refuse("member %d of %s is %s / %s: only an executed member whose proof is pending can have it declared unavailable",
			req.ChainID, req.IntentID, settlement, proofCycle)
	}
	if !strings.EqualFold(settlementTx, req.SettlementTx) {
		return refuse("member %d of %s records settlement %s, not %s", req.ChainID, req.IntentID, settlementTx, req.SettlementTx)
	}
	// How long the action has been owed its proof: proof_owed_since is set when it first became owed and kept while it is.
	var firstOwed sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT proof_owed_since FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = $2`,
		req.IntentID, req.ChainID).Scan(&firstOwed); err != nil {
		return nil, fmt.Errorf("read when member %s/%d was first owed its proof: %w", req.IntentID, req.ChainID, err)
	}
	if !firstOwed.Valid {
		return refuse("member %d of %s records no time it became owed its proof", req.ChainID, req.IntentID)
	}
	if pending := now.Sub(firstOwed.Time); pending < ProofUnavailableMinPending {
		return refuse("member %d of %s has been owed its proof for %s; it may be declared unavailable after %s of automatic recovery",
			req.ChainID, req.IntentID, pending.Round(time.Minute), ProofUnavailableMinPending)
	}

	proven, findings, err := probe(ctx, req.ChainID, req.SettlementTx)
	res.Findings = findings
	if err != nil {
		return nil, fmt.Errorf("probe the providers for %s: %w", req.SettlementTx, err)
	}
	if proven {
		return refuse("the block of %s CAN be proven now; let the automatic recovery write its bundle", req.SettlementTx)
	}

	res.Reason = fmt.Sprintf("proof_unavailable declared by %s at %s after %s owed: %s; providers now: %s", req.Operator,
		now.UTC().Format(time.RFC3339), now.Sub(firstOwed.Time).Round(time.Hour), req.Evidence, strings.Join(findings, "; "))
	if !req.Apply {
		return res, nil
	}
	if _, err := lifecycle.RecordMemberOutcome(ctx, database.MemberOutcome{IntentID: req.IntentID, ChainID: req.ChainID,
		MemberChains: members, Legs: legs, Settlement: database.MemberSettlement(settlement), ProofCycle: database.MemberProofCycleUnavailable,
		SettlementTx: settlementTx, CycleID: "declared-unavailable-" + now.UTC().Format("20060102T150405Z"), Reason: res.Reason,
		ReportedBy: req.Operator}); err != nil {
		return nil, fmt.Errorf("record member %s/%d proof_unavailable: %w", req.IntentID, req.ChainID, err)
	}
	res.Declared = true
	return res, nil
}
