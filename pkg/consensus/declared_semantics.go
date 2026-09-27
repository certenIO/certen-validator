package consensus

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// =============================================================================
// An intent is executed as it declares, or refused by name
// =============================================================================
//
// The signed crossChainData declares HOW its legs are to be executed, not only what they do:
// execution_mode ("sequential" when unset), atomicity, rollback_policy, leg dependencies, a
// per-leg deadline, conditional execution. The batch path splits a multi-chain intent into one
// member per chain and settles the members independently and concurrently; within one chain a
// member's legs run in one account transaction, in listing order, all-or-nothing by revert.
//
// So a declaration the batch path does not implement was simply not honoured - a "sequential"
// or "atomic" cross-chain intent could settle on one chain and fail on the other, in any order,
// and a leg could execute after the deadline its signer set (RB3-F52, RB3-F53). Until each is
// implemented, an intent declaring it is refused here, before anything is queued or signed,
// with the declaration it made - never executed against it (owner decision 2026-09-27).
//
// The raw signed JSON is read, not the CrossChainEnvelope structs: those drop fields the intent
// builder actually sends (rollback_policy.mode, timeout_policy.total_timeout_seconds), and a
// declaration that is dropped on decoding is still a declaration the signer made.

// ErrUnimplementedSemantics is an intent that declares execution semantics CERTEN does not
// implement.
var ErrUnimplementedSemantics = errors.New("intent declares execution semantics CERTEN does not implement")

// ErrPastDeadline is a leg whose signed deadline had passed when the intent was written.
var ErrPastDeadline = errors.New("leg deadline passed")

// ErrDeadlineTooSoon is a leg whose signed deadline leaves less time after the intent was written
// than CERTEN needs to settle it.
var ErrDeadlineTooSoon = errors.New("leg deadline too soon to settle")

// MinSettlementLead is the least time between an intent's consensus block and a leg's deadline that
// CERTEN can settle within: a batch period closing (100 Accumulate blocks, ~2.4 min), the settle
// grace for peers to finish processing (4 min), then anchor, quorum attestation and settlement
// (~2 min measured) - with a margin. A deadline inside it is a declaration CERTEN cannot honour, so
// the intent is refused rather than accepted and failed (RB3-F53).
const MinSettlementLead = 10 * time.Minute

type rawLeg struct {
	LegID                string   `json:"legId"`
	ChainID              int64    `json:"chainId"`
	SequenceOrder        *int     `json:"sequence_order"`
	DependsOnLegs        []string `json:"depends_on_legs"`
	DeadlineTimestamp    int64    `json:"deadline_timestamp"`
	ConditionalExecution *bool    `json:"conditional_execution"`
}

type rawDeclarations struct {
	Legs                 []rawLeg        `json:"legs"`
	ExecutionMode        string          `json:"execution_mode"`
	ExecutionConstraints map[string]any  `json:"execution_constraints"`
	Atomicity            map[string]any  `json:"atomicity"`
	RollbackPolicy       map[string]any  `json:"rollback_policy"`
	LegDependencies      []rawDependency `json:"leg_dependencies"`
}

type rawDependency struct {
	LegID          string `json:"leg_id"`
	DependsOnLegID string `json:"depends_on_leg_id"`
}

// CheckDeclaredSemantics refuses an intent whose declared execution semantics the batch path does
// not implement. writtenAt is the intent's consensus block time (the same on every validator); a
// zero writtenAt skips only the deadline check, which cannot be made without it.
func CheckDeclaredSemantics(ci *CertenIntent, writtenAt time.Time) error {
	if ci == nil {
		return fmt.Errorf("%w: no intent", ErrUnimplementedSemantics)
	}
	var d rawDeclarations
	if err := json.Unmarshal(ci.CrossChainData, &d); err != nil {
		return fmt.Errorf("%w: crossChainData cannot be read: %v", ErrUnimplementedSemantics, err)
	}

	chains := map[int64]bool{}
	index := map[string]int{}
	for i, l := range d.Legs {
		chains[l.ChainID] = true
		if l.LegID != "" {
			index[l.LegID] = i
		}
	}
	crossChain := len(chains) > 1

	// ---- Cross-chain ordering and atomicity -----------------------------------------------
	if crossChain {
		mode := strings.ToLower(strings.TrimSpace(d.ExecutionMode))
		if mode == "" {
			if m, ok := d.ExecutionConstraints["mode"].(string); ok {
				mode = strings.ToLower(strings.TrimSpace(m))
			}
		}
		if mode == "" {
			mode = "sequential" // the schema's default (CertenIntent.GetExecutionMode)
		}
		if mode != "parallel" {
			return fmt.Errorf("%w: a cross-chain intent declaring execution_mode %q - CERTEN settles each chain independently and implements only \"parallel\" across chains",
				ErrUnimplementedSemantics, mode)
		}
		if pe, ok := d.ExecutionConstraints["parallel_execution"].(bool); ok && !pe {
			return fmt.Errorf("%w: execution_mode \"parallel\" contradicts execution_constraints.parallel_execution=false", ErrUnimplementedSemantics)
		}
		if allOrNothing(d.Atomicity) {
			return fmt.Errorf("%w: a cross-chain intent declaring all-or-nothing atomicity %v - a chain that settled is not undone when another fails",
				ErrUnimplementedSemantics, d.Atomicity)
		}
		if rollsBack(d.RollbackPolicy) {
			return fmt.Errorf("%w: a cross-chain intent declaring rollback_policy %v - a settled chain is not rolled back",
				ErrUnimplementedSemantics, d.RollbackPolicy)
		}
	}

	// ---- Dependencies: only on an earlier leg of the same chain ------------------------------
	deps := make([]rawDependency, 0, len(d.LegDependencies))
	deps = append(deps, d.LegDependencies...)
	for _, l := range d.Legs {
		for _, on := range l.DependsOnLegs {
			deps = append(deps, rawDependency{LegID: l.LegID, DependsOnLegID: on})
		}
	}
	for _, dep := range deps {
		i, ok1 := index[dep.LegID]
		j, ok2 := index[dep.DependsOnLegID]
		if !ok1 || !ok2 {
			return fmt.Errorf("%w: leg dependency %q -> %q names a leg the intent does not have", ErrUnimplementedSemantics, dep.LegID, dep.DependsOnLegID)
		}
		if d.Legs[i].ChainID != d.Legs[j].ChainID {
			return fmt.Errorf("%w: leg %q depends on leg %q on another chain - cross-chain dependencies are not implemented",
				ErrUnimplementedSemantics, dep.LegID, dep.DependsOnLegID)
		}
		if j >= i {
			return fmt.Errorf("%w: leg %q depends on leg %q, which executes after it in the same transaction",
				ErrUnimplementedSemantics, dep.LegID, dep.DependsOnLegID)
		}
	}

	// ---- Order within a chain: listing order is execution order --------------------------------
	lastSeq := map[int64]int{}
	for _, l := range d.Legs {
		if l.SequenceOrder == nil {
			continue
		}
		if prev, ok := lastSeq[l.ChainID]; ok && *l.SequenceOrder < prev {
			return fmt.Errorf("%w: leg %q declares sequence_order %d after a leg with %d on the same chain - legs on one chain execute in listing order",
				ErrUnimplementedSemantics, l.LegID, *l.SequenceOrder, prev)
		}
		lastSeq[l.ChainID] = *l.SequenceOrder
	}

	// ---- Conditional execution and deadlines --------------------------------------------------
	for _, l := range d.Legs {
		if l.ConditionalExecution != nil && *l.ConditionalExecution {
			return fmt.Errorf("%w: leg %q declares conditional_execution, which has no defined condition to evaluate",
				ErrUnimplementedSemantics, l.LegID)
		}
		if l.DeadlineTimestamp > 0 && !writtenAt.IsZero() {
			deadline := time.Unix(l.DeadlineTimestamp, 0).UTC()
			if writtenAt.After(deadline) {
				return fmt.Errorf("%w: leg %q was written at %s, after its deadline %s",
					ErrPastDeadline, l.LegID, writtenAt.UTC().Format(time.RFC3339), deadline.Format(time.RFC3339))
			}
			if deadline.Sub(writtenAt) < MinSettlementLead {
				return fmt.Errorf("%w: leg %q was written at %s with deadline %s; CERTEN needs at least %s to settle",
					ErrDeadlineTooSoon, l.LegID, writtenAt.UTC().Format(time.RFC3339), deadline.Format(time.RFC3339), MinSettlementLead)
			}
		}
	}
	return nil
}

// allOrNothing reports whether an atomicity declaration asks for all-or-nothing execution.
// "best_effort" with partial execution allowed is what the batch path does.
func allOrNothing(a map[string]any) bool {
	if len(a) == 0 {
		return false
	}
	if p, ok := a["partial_execution_allowed"].(bool); ok && !p {
		return true
	}
	if m, ok := a["mode"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "", "best_effort":
		default:
			return true
		}
	}
	if s, ok := a["rollback_strategy"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "", "partial_allowed", "none":
		default:
			return true
		}
	}
	return false
}

// rollsBack reports whether a rollback policy asks for settled legs to be undone.
func rollsBack(r map[string]any) bool {
	if len(r) == 0 {
		return false
	}
	for _, k := range []string{"enabled", "rollback_on_failure", "rollback_on_timeout"} {
		if v, ok := r[k].(bool); ok && v {
			return true
		}
	}
	if p, ok := r["partial_execution_allowed"].(bool); ok && !p {
		return true
	}
	if m, ok := r["mode"].(string); ok {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "", "continue_on_failure", "none":
		default:
			return true
		}
	}
	return false
}
