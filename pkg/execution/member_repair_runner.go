// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/lib/pq"
)

// Re-driving one chain member's proof cycle, on request (RB4-F55 repair; DESIGN_RB4_F55_repair_000ac79a.md).
//
// `validator repair member-proof-cycle` writes a request into this validator's data directory; the running
// validator - which holds the orchestrator, its keys, its peers and the committed-operation index - picks it up.
// Every precondition is checked first and each failure refused by name. Then the repair is armed
// (consensus.ArmMemberRepair) and the member's intent re-processed from its Directory Network block exactly as
// discovery processes it (IntentDiscovery.ReprocessIntent), so the member's round is re-derived and checked
// against the committed block. Where that round reaches the member, its proof cycle is run on the named settlement
// (Apply) or its snapshot reported (dry run). The outcome is read back from what the proof cycle recorded. Requests
// are moved to done/ and results written to results/; nothing is deleted.

// MemberRepairRequest is one request, as the repair command writes it.
type MemberRepairRequest struct {
	ID           string    `json:"id"`
	IntentID     string    `json:"intent_id"`
	ChainID      int64     `json:"chain_id"`
	SettlementTx string    `json:"settlement_tx"`
	Apply        bool      `json:"apply"`
	RequestedAt  time.Time `json:"requested_at"`
}

// MemberRepairCheck is one precondition and whether it held.
type MemberRepairCheck struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Outcomes of a repair request.
const (
	MemberRepairRefused  = "refused"  // a precondition did not hold; nothing ran
	MemberRepairReached  = "reached"  // dry run: the re-derived round reached the member; its snapshot is reported
	MemberRepairRepaired = "repaired" // the member's proof cycle ran and recorded it settled and written back
	MemberRepairFailed   = "failed"   // the round did not reach the member, or its proof cycle did not write it back
)

// MemberRepairResult is what a request came to.
type MemberRepairResult struct {
	Request    MemberRepairRequest             `json:"request"`
	Validator  string                          `json:"validator"`
	Outcome    string                          `json:"outcome"`
	Reason     string                          `json:"reason,omitempty"`
	Checks     []MemberRepairCheck             `json:"checks"`
	DNBlock    uint64                          `json:"dn_block,omitempty"`
	Snapshot   *consensus.MemberRepairSnapshot `json:"snapshot,omitempty"`
	Before     map[string]any                  `json:"member_before,omitempty"`
	After      map[string]any                  `json:"member_after,omitempty"`
	Intent     map[string]any                  `json:"intent_after,omitempty"`
	WriteBack  *database.MemberWriteBack       `json:"write_back,omitempty"`
	ProofIDs   []string                        `json:"proof_ids,omitempty"`
	Correction []string                        `json:"corrections,omitempty"`
	StartedAt  time.Time                       `json:"started_at"`
	FinishedAt time.Time                       `json:"finished_at"`
}

// MemberRepairRunner serves repair requests inside the running validator.
type MemberRepairRunner struct {
	Dir         string // <data dir>/member_repairs
	ValidatorID string
	DB          *sql.DB
	Lifecycle   *database.IntentLifecycleRepository
	Outbox      MemberOutcomeOutbox
	// Observe reads the settlement from its chain, as Phase 7 does.
	Observe func(ctx context.Context, chainID int64, tx string) (*chain.ObservationResult, error)
	// Arm names the member for its round (consensus.BFTValidator.ArmMemberRepair).
	Arm func(consensus.MemberRepair) (<-chan consensus.MemberRepairReach, func())
	// Reprocess re-runs the intent's round (intent.IntentDiscovery.ReprocessIntent).
	Reprocess func(ctx context.Context, dnBlock uint64, accumTxHash, intentID string) error
	Interval  time.Duration // zero: ten seconds
	// OutcomeWait bounds the wait for the proof cycle's recorded outcome; zero: twelve minutes (a cycle runs
	// under a ten-minute limit).
	OutcomeWait time.Duration
	Logf        func(string, ...interface{})

	// serving serializes repairs: a requested repair and the automatic proof recovery (ProofRecovery) each arm one
	// member's round at a time.
	serving sync.Mutex
}

// MemberRepairDir is where a validator's repair requests and results live.
func MemberRepairDir(dataDir string) string { return filepath.Join(dataDir, "member_repairs") }

func (r *MemberRepairRunner) logf(format string, args ...interface{}) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

func (r *MemberRepairRunner) ready() error {
	var missing []string
	for _, m := range []struct {
		absent bool
		name   string
	}{
		{r.Dir == "", "directory"}, {r.ValidatorID == "", "validator id"}, {r.DB == nil, "database"},
		{r.Lifecycle == nil, "lifecycle repository"}, {r.Outbox == nil, "member outcome outbox"}, {r.Observe == nil, "chain observer"},
		{r.Arm == nil, "consensus"}, {r.Reprocess == nil, "discovery"},
	} {
		if m.absent {
			missing = append(missing, m.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("member repair runner: missing %s", strings.Join(missing, ", "))
	}
	for _, d := range []string{"requests", "done", "results"} {
		if err := os.MkdirAll(filepath.Join(r.Dir, d), 0o700); err != nil {
			return fmt.Errorf("member repair runner: %w", err)
		}
	}
	return nil
}

// Start serves requests until ctx ends. A runner that is not fully wired refuses to start, by name.
func (r *MemberRepairRunner) Start(ctx context.Context) error {
	if err := r.ready(); err != nil {
		return err
	}
	interval := r.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			if err := r.RunOnce(ctx); err != nil {
				r.logf("❌ [MEMBER-REPAIR] %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// RunOnce serves every pending request, oldest first.
func (r *MemberRepairRunner) RunOnce(ctx context.Context) error {
	if err := r.ready(); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(r.Dir, "requests"))
	if err != nil {
		return fmt.Errorf("list repair requests: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		src := filepath.Join(r.Dir, "requests", name)
		raw, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read repair request %s: %w", name, err)
		}
		var req MemberRepairRequest
		if err := json.Unmarshal(raw, &req); err != nil || req.ID == "" || req.ID+".json" != name {
			res := &MemberRepairResult{Request: req, Validator: r.ValidatorID, Outcome: MemberRepairRefused,
				Reason:    fmt.Sprintf("the request %s cannot be read as a repair request named by its id (%v)", name, err),
				StartedAt: time.Now().UTC()}
			req.ID = strings.TrimSuffix(name, ".json")
			res.Request.ID = req.ID
			if err := r.finish(name, res); err != nil {
				return err
			}
			continue
		}
		res := r.Serve(ctx, req)
		if err := r.finish(name, res); err != nil {
			return err
		}
	}
	return nil
}

// finish writes the result and moves the request to done/.
func (r *MemberRepairRunner) finish(name string, res *MemberRepairResult) error {
	res.FinishedAt = time.Now().UTC()
	blob, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("encode repair result %s: %w", res.Request.ID, err)
	}
	dst := filepath.Join(r.Dir, "results", res.Request.ID+".json")
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("write repair result %s: %w", res.Request.ID, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("write repair result %s: %w", res.Request.ID, err)
	}
	if err := os.Rename(filepath.Join(r.Dir, "requests", name), filepath.Join(r.Dir, "done", name)); err != nil {
		return fmt.Errorf("move repair request %s to done: %w", name, err)
	}
	r.logf("🔧 [MEMBER-REPAIR] request %s (intent %s member %d, apply %v): %s %s",
		res.Request.ID, res.Request.IntentID, res.Request.ChainID, res.Request.Apply, res.Outcome, res.Reason)
	return nil
}

type repairFacts struct {
	dnBlock     uint64
	accumTxHash string
	before      map[string]any
	cycleBefore string
	// dbStart is the database clock when the repair began: what it produced is read back against the clock that
	// stamped it, never this host's.
	dbStart time.Time
}

// Serve runs one request.
func (r *MemberRepairRunner) Serve(ctx context.Context, req MemberRepairRequest) *MemberRepairResult {
	r.serving.Lock()
	defer r.serving.Unlock()
	res := &MemberRepairResult{Request: req, Validator: r.ValidatorID, StartedAt: time.Now().UTC()}
	facts, ok := r.preconditions(ctx, req, res)
	if !ok {
		res.Outcome = MemberRepairRefused
		var failed []string
		for _, c := range res.Checks {
			if !c.Passed {
				failed = append(failed, c.Name+": "+c.Detail)
			}
		}
		res.Reason = strings.Join(failed, "; ")
		return res
	}
	res.DNBlock, res.Before = facts.dnBlock, facts.before
	if err := r.DB.QueryRowContext(ctx, `SELECT now()`).Scan(&facts.dbStart); err != nil {
		res.Outcome, res.Reason = MemberRepairRefused, "the database clock could not be read: "+err.Error()
		return res
	}

	reach, disarm := r.Arm(consensus.MemberRepair{IntentID: req.IntentID, ChainID: req.ChainID, SettlementTx: req.SettlementTx, Apply: req.Apply})
	defer disarm()
	reprocessErr := r.Reprocess(ctx, facts.dnBlock, facts.accumTxHash, req.IntentID)
	var reached consensus.MemberRepairReach
	select {
	case reached = <-reach:
	default:
		res.Outcome = MemberRepairFailed
		res.Reason = fmt.Sprintf("the re-derived round of intent %s did not reach member %d", req.IntentID, req.ChainID)
		if reprocessErr != nil {
			res.Reason += ": " + reprocessErr.Error()
		}
		return res
	}
	res.Snapshot = &reached.Snapshot
	if reached.Err != nil {
		res.Outcome, res.Reason = MemberRepairFailed, reached.Err.Error()
		return res
	}
	if !req.Apply {
		res.Outcome = MemberRepairReached
		return res
	}
	r.readOutcome(ctx, req, facts, res)
	return res
}

func (r *MemberRepairRunner) check(res *MemberRepairResult, name string, passed bool, detail string) bool {
	res.Checks = append(res.Checks, MemberRepairCheck{Name: name, Passed: passed, Detail: detail})
	return passed
}

// preconditions checks everything the repair relies on, in order, and stops at the first that does not hold.
func (r *MemberRepairRunner) preconditions(ctx context.Context, req MemberRepairRequest, res *MemberRepairResult) (*repairFacts, bool) {
	if !r.check(res, "request", req.IntentID != "" && req.ChainID != 0 && req.SettlementTx != "",
		"intent, chain and settlement transaction are required") {
		return nil, false
	}

	// 1. The intent exists and this chain is one of its members.
	var blockHeight sql.NullInt64
	var accum sql.NullString
	var members pq.Int64Array
	err := r.DB.QueryRowContext(ctx, `SELECT block_height, accum_tx_hash, member_chains FROM intent_lifecycle WHERE intent_id = $1`,
		req.IntentID).Scan(&blockHeight, &accum, &members)
	if errors.Is(err, sql.ErrNoRows) {
		r.check(res, "intent", false, fmt.Sprintf("intent %s has no lifecycle record", req.IntentID))
		return nil, false
	}
	if err != nil {
		r.check(res, "intent", false, fmt.Sprintf("the lifecycle record of %s could not be read: %v", req.IntentID, err))
		return nil, false
	}
	inSet := false
	for _, c := range members {
		inSet = inSet || c == req.ChainID
	}
	if !r.check(res, "intent", blockHeight.Valid && blockHeight.Int64 > 0 && accum.String != "" && inSet,
		fmt.Sprintf("DN block %d, Accumulate transaction %s, members %v", blockHeight.Int64, accum.String, []int64(members))) {
		return nil, false
	}
	facts := &repairFacts{dnBlock: uint64(blockHeight.Int64), accumTxHash: accum.String}

	// 2. The member's proof cycle is recorded failed: a member written back is never re-driven.
	var settlement, proofCycle string
	var settlementTx, writeBackTx, cycleID, reason sql.NullString
	var recordedAt time.Time
	err = r.DB.QueryRowContext(ctx, `SELECT settlement, proof_cycle, settlement_tx, write_back_tx, cycle_id, reason, recorded_at
		FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = $2`, req.IntentID, req.ChainID).
		Scan(&settlement, &proofCycle, &settlementTx, &writeBackTx, &cycleID, &reason, &recordedAt)
	if err != nil {
		r.check(res, "member outcome", false, fmt.Sprintf("no recorded outcome for member %d could be read: %v", req.ChainID, err))
		return nil, false
	}
	facts.before = map[string]any{"settlement": settlement, "proof_cycle": proofCycle, "settlement_tx": settlementTx.String,
		"write_back_tx": writeBackTx.String, "cycle_id": cycleID.String, "reason": reason.String, "recorded_at": recordedAt.UTC()}
	facts.cycleBefore = cycleID.String
	// 2. … failed, or its action executed with its proof bundle owed (proof_pending, RB6) - the member the automatic
	// recovery re-drives.
	if !r.check(res, "member outcome", proofCycle == string(database.MemberProofCycleFailed) || proofCycle == string(database.MemberProofCyclePending),
		fmt.Sprintf("recorded %s / %s by cycle %s", settlement, proofCycle, cycleID.String)) {
		return nil, false
	}

	// 3. No write-back of the member is registered, or may be on Accumulate.
	if err := r.Lifecycle.MemberWriteBackAllowed(ctx, req.IntentID, req.ChainID); !r.check(res, "write-back register", err == nil, errText(err, "none registered")) {
		return nil, false
	}

	// 4. No report of this member waits in the outbox: replayed after the repair it would contradict it.
	entries, err := r.Outbox.List()
	pending := 0
	for _, e := range entries {
		if e.Outcome != nil && e.Outcome.IntentID == req.IntentID && e.Outcome.ChainID == req.ChainID {
			pending++
		}
	}
	if !r.check(res, "member outcome outbox", err == nil && pending == 0, fmt.Sprintf("%d pending report(s) of this member (%v)", pending, err)) {
		return nil, false
	}

	// 5. This validator observed the settlement: its recorded observation is the one the proof cycle adopts (RB4-F55).
	var observer sql.NullString
	err = r.DB.QueryRowContext(ctx, `SELECT observer_validator_id FROM chain_execution_results WHERE chain_id = $1 AND lower(tx_hash) = lower($2)`,
		strconv.FormatInt(req.ChainID, 10), req.SettlementTx).Scan(&observer)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No validator recorded an observation of it. A settlement Phase 7 read final but could not prove in its block
		// (settled_unproven, RB6-F9) is recorded on the member - settled or reverted, with this settlement transaction -
		// and has no observation anywhere: this validator's proof cycle observes and proves it afresh (step 6 and the
		// cycle's own Phase 7), and its observation is the one recorded. Any other member with no observation is refused.
		named := strings.EqualFold(settlementTx.String, req.SettlementTx) &&
			(settlement == string(database.MemberSettlementSettled) || settlement == string(database.MemberSettlementReverted))
		if !r.check(res, "recorded observation", named, fmt.Sprintf("no observation of %s is recorded by any validator; the member "+
			"records settlement %s / %q; run the repair on the validator that settled it", req.SettlementTx, settlement, settlementTx.String)) {
			return nil, false
		}
		res.Checks[len(res.Checks)-1].Detail = fmt.Sprintf("no observation of %s is recorded by any validator, and the member records it %s "+
			"(settled_unproven): this validator's proof cycle observes and proves it", req.SettlementTx, settlement)
	case err != nil:
		r.check(res, "recorded observation", false, err.Error())
		return nil, false
	}
	if err == nil && !r.check(res, "recorded observation", observer.String == r.ValidatorID,
		fmt.Sprintf("observed by %s; this is %s", observer.String, r.ValidatorID)) {
		return nil, false
	}

	// 6. The settlement is final on its chain and executed.
	obs, err := r.Observe(ctx, req.ChainID, req.SettlementTx)
	if err != nil {
		r.check(res, "settlement on chain", false, err.Error())
		return nil, false
	}
	if !r.check(res, "settlement on chain", obs != nil && obs.IsFinalized && obs.Status == 1,
		fmt.Sprintf("finalized %v, status %d, block %d", obs != nil && obs.IsFinalized, statusOf(obs), blockOf(obs))) {
		return nil, false
	}
	return facts, true
}

func statusOf(o *chain.ObservationResult) uint8 {
	if o == nil {
		return 0
	}
	return o.Status
}

func blockOf(o *chain.ObservationResult) uint64 {
	if o == nil {
		return 0
	}
	return o.BlockNumber
}

func errText(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}

// readOutcome waits for the member's proof cycle to record its outcome, and reads back what it recorded.
func (r *MemberRepairRunner) readOutcome(ctx context.Context, req MemberRepairRequest, facts *repairFacts, res *MemberRepairResult) {
	wait := r.OutcomeWait
	if wait <= 0 {
		wait = 12 * time.Minute
	}
	deadline := time.Now().Add(wait)
	for {
		var settlement, proofCycle string
		var writeBackTx, cycleID, reason sql.NullString
		err := r.DB.QueryRowContext(ctx, `SELECT settlement, proof_cycle, write_back_tx, cycle_id, reason
			FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = $2`, req.IntentID, req.ChainID).
			Scan(&settlement, &proofCycle, &writeBackTx, &cycleID, &reason)
		if err == nil && cycleID.String != facts.cycleBefore {
			res.After = map[string]any{"settlement": settlement, "proof_cycle": proofCycle, "write_back_tx": writeBackTx.String,
				"cycle_id": cycleID.String, "reason": reason.String}
			r.collect(ctx, req, facts, res)
			if settlement == string(database.MemberSettlementSettled) && proofCycle == string(database.MemberProofCycleWritten) {
				res.Outcome = MemberRepairRepaired
			} else {
				res.Outcome = MemberRepairFailed
				res.Reason = fmt.Sprintf("the proof cycle recorded %s / %s: %s", settlement, proofCycle, reason.String)
			}
			return
		}
		if time.Now().After(deadline) {
			r.collect(ctx, req, facts, res)
			res.Outcome = MemberRepairFailed
			res.Reason = fmt.Sprintf("the member's proof cycle recorded no outcome within %s (last read: %v); see the validator log", wait, err)
			return
		}
		select {
		case <-ctx.Done():
			res.Outcome, res.Reason = MemberRepairFailed, "stopped before the proof cycle recorded its outcome: "+ctx.Err().Error()
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// collect reads back the intent, the write-back register, the proofs and the corrections the repair produced.
func (r *MemberRepairRunner) collect(ctx context.Context, req MemberRepairRequest, facts *repairFacts, res *MemberRepairResult) {
	var status string
	var errMsg, class sql.NullString
	if err := r.DB.QueryRowContext(ctx, `SELECT status, error_message, failure_class FROM intent_lifecycle WHERE intent_id = $1`, req.IntentID).
		Scan(&status, &errMsg, &class); err == nil {
		res.Intent = map[string]any{"status": status, "error_message": errMsg.String, "failure_class": class.String}
	}
	if w, err := r.Lifecycle.MemberWriteBackOf(ctx, req.IntentID, req.ChainID); err == nil {
		res.WriteBack = w
	}
	if rows, err := r.DB.QueryContext(ctx, `SELECT proof_id::text FROM proof_artifacts
		WHERE lower(accum_tx_hash) = lower($1) AND created_at >= $2 ORDER BY created_at`, facts.accumTxHash, facts.dbStart); err == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				res.ProofIDs = append(res.ProofIDs, id)
			}
		}
		rows.Close()
	}
	if rows, err := r.DB.QueryContext(ctx, `SELECT correction_id::text FROM evidence_corrections
		WHERE ((record_type = 'intent_member_outcome' AND record_id = $1) OR (record_type = 'intent_lifecycle' AND record_id = $2))
		  AND corrected_at >= $3 ORDER BY corrected_at`,
		fmt.Sprintf("%s/%d", req.IntentID, req.ChainID), req.IntentID, facts.dbStart); err == nil {
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				res.Correction = append(res.Correction, id)
			}
		}
		rows.Close()
	}
}
