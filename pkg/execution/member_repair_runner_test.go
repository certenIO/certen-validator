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
	"strings"
	"testing"
	"time"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
)

// RB4-F55 repair runner (DESIGN_RB4_F55_repair_000ac79a.md): a member's proof cycle is re-driven only when every
// precondition holds, each refused by name; a dry run reports the re-derived round's snapshot and runs nothing;
// an applied repair reads back what the proof cycle recorded; requests are kept in done/, results in results/.

type repairScene struct {
	db       *sql.DB
	repos    *database.Repositories
	intentID string
	accum    string
	tx       string
	outbox   *FileMemberOutcomeOutbox
	armed    []consensus.MemberRepair
	reproc   []string
	status   uint8
	// onReprocess plays the round (and, when it reaches the member, what its proof cycle records).
	onReprocess func(reach chan consensus.MemberRepairReach, apply bool) error
	reach       chan consensus.MemberRepairReach
}

func newRepairScene(t *testing.T) *repairScene {
	t.Helper()
	db := s1OpenDB(t)
	ctx := context.Background()
	repos := database.NewRepositories(database.NewClientFromDB(db))
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	s := &repairScene{db: db, repos: repos, intentID: "f55-repair-" + run, accum: fmt.Sprintf("%064s", run),
		tx: "0x" + fmt.Sprintf("%064s", "c409"+run), status: 1}
	if _, err := db.Exec(`INSERT INTO intent_lifecycle (intent_id, accum_tx_hash, status, block_height, created_at, updated_at)
		VALUES ($1, $2, 'settling', 10007772, now(), now())`, s.intentID, s.accum); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, s.intentID)
		db.Exec(`DELETE FROM member_write_backs WHERE intent_id = $1`, s.intentID)
		db.Exec(`DELETE FROM chain_execution_results WHERE tx_hash = $1`, s.tx)
		db.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, s.intentID)
	})
	members := []int64{84532, 421614}
	for _, o := range []database.MemberOutcome{
		{IntentID: s.intentID, ChainID: 421614, MemberChains: members, Legs: 1, Settlement: database.MemberSettlementSettled,
			ProofCycle: database.MemberProofCycleWritten, SettlementTx: "0xarb", WriteBackTx: "acc://wb-arb", CycleID: "cycle-arb", ReportedBy: "validator-1"},
		{IntentID: s.intentID, ChainID: 84532, MemberChains: members, Legs: 1, Settlement: database.MemberSettlementUnobserved,
			ProofCycle: database.MemberProofCycleFailed, CycleID: "cycle-broken", Reason: "phase 7 failed: duplicate key", ReportedBy: "validator-6"},
	} {
		if _, err := repos.IntentLifecycle.RecordMemberOutcome(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	bn := int64(47451715)
	now := time.Now().UTC()
	if _, err := repos.Unified.CreateChainExecutionResult(ctx, &database.NewChainExecutionResult{CycleID: "cycle-broken",
		ChainPlatform: "evm", ChainID: "84532", NetworkName: "base-sepolia", TxHash: s.tx, BlockNumber: &bn, BlockHash: "0xb33f",
		BlockTimestamp: &now, Status: 1, IsFinalized: true, RawReceipt: []byte("null"), Logs: []byte("[]"), PlatformData: []byte("{}"),
		ObserverValidatorID: "validator-6", SubmittedAt: &now}); err != nil {
		t.Fatal(err)
	}
	outbox, err := NewFileMemberOutcomeOutbox(filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	s.outbox = outbox
	return s
}

func (s *repairScene) runner(t *testing.T, validator string) *MemberRepairRunner {
	return &MemberRepairRunner{
		Dir: filepath.Join(t.TempDir(), "member_repairs"), ValidatorID: validator, DB: s.db, Lifecycle: s.repos.IntentLifecycle, Outbox: s.outbox,
		Observe: func(_ context.Context, chainID int64, tx string) (*chain.ObservationResult, error) {
			return &chain.ObservationResult{TxHash: tx, BlockNumber: 47451715, Status: s.status, IsFinalized: true}, nil
		},
		Arm: func(m consensus.MemberRepair) (<-chan consensus.MemberRepairReach, func()) {
			s.armed = append(s.armed, m)
			s.reach = make(chan consensus.MemberRepairReach, 1)
			return s.reach, func() {}
		},
		Reprocess: func(_ context.Context, dnBlock uint64, accum, intentID string) error {
			s.reproc = append(s.reproc, fmt.Sprintf("%d/%s/%s", dnBlock, accum, intentID))
			if s.onReprocess == nil {
				return nil
			}
			return s.onReprocess(s.reach, s.armed[len(s.armed)-1].Apply)
		},
		OutcomeWait: 5 * time.Second, Logf: t.Logf,
	}
}

func (s *repairScene) request(apply bool) MemberRepairRequest {
	return MemberRepairRequest{ID: "req-" + s.intentID, IntentID: s.intentID, ChainID: 84532, SettlementTx: s.tx, Apply: apply, RequestedAt: time.Now().UTC()}
}

var snapshot = consensus.MemberRepairSnapshot{BundleID: "0x0a", GovernanceRoot: "0x0c", OperationCommitment: "0x0b", Lane: "on_demand", GovernanceLevels: true}

func TestARepairIsRefusedUnlessEveryPreconditionHolds(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mutate    func(s *repairScene, req *MemberRepairRequest)
		validator string
		check     string
	}{
		"unknown intent":          {func(_ *repairScene, r *MemberRepairRequest) { r.IntentID = "no-such-intent" }, "validator-6", "intent"},
		"chain not a member":      {func(_ *repairScene, r *MemberRepairRequest) { r.ChainID = 11155111 }, "validator-6", "intent"},
		"member written back":     {func(_ *repairScene, r *MemberRepairRequest) { r.ChainID = 421614; r.SettlementTx = "0xarb" }, "validator-6", "member outcome"},
		"observed by another":     {func(*repairScene, *MemberRepairRequest) {}, "validator-3", "recorded observation"},
		"no recorded observation": {func(_ *repairScene, r *MemberRepairRequest) { r.SettlementTx = "0x" + strings.Repeat("99", 32) }, "validator-6", "recorded observation"},
		"settlement not executed": {func(s *repairScene, _ *MemberRepairRequest) { s.status = 2 }, "validator-6", "settlement on chain"},
		"a stale report waits": {func(s *repairScene, r *MemberRepairRequest) {
			if err := s.outbox.Put(database.MemberOutcome{IntentID: r.IntentID, ChainID: 84532, CycleID: "cycle-broken", MemberChains: []int64{84532, 421614}, Legs: 1}); err != nil {
				t.Fatal(err)
			}
		}, "validator-6", "member outcome outbox"},
		"a write-back registered": {func(s *repairScene, r *MemberRepairRequest) {
			if err := s.repos.IntentLifecycle.ClaimMemberWriteBack(ctx, r.IntentID, 84532, "cycle-x", "validator-6"); err != nil {
				t.Fatal(err)
			}
		}, "validator-6", "write-back register"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newRepairScene(t)
			req := s.request(true)
			tc.mutate(s, &req)
			res := s.runner(t, tc.validator).Serve(ctx, req)
			if res.Outcome != MemberRepairRefused || !strings.Contains(res.Reason, tc.check) {
				t.Fatalf("want refused on %q, got %s: %s", tc.check, res.Outcome, res.Reason)
			}
			if len(s.armed) != 0 || len(s.reproc) != 0 {
				t.Fatal("a refused repair armed or re-processed something")
			}
		})
	}
}

func TestADryRunRepairReachesTheMemberAndRunsNothing(t *testing.T) {
	s := newRepairScene(t)
	s.onReprocess = func(reach chan consensus.MemberRepairReach, apply bool) error {
		reach <- consensus.MemberRepairReach{Snapshot: snapshot}
		return nil
	}
	res := s.runner(t, "validator-6").Serve(context.Background(), s.request(false))
	if res.Outcome != MemberRepairReached || res.Snapshot == nil || res.Snapshot.BundleID != "0x0a" {
		t.Fatalf("a dry run: %s %s %+v", res.Outcome, res.Reason, res.Snapshot)
	}
	if len(s.armed) != 1 || s.armed[0].Apply || s.armed[0].SettlementTx != s.tx {
		t.Fatalf("armed %+v", s.armed)
	}
	if want := fmt.Sprintf("10007772/%s/%s", s.accum, s.intentID); len(s.reproc) != 1 || s.reproc[0] != want {
		t.Fatalf("re-processed %v, want %s (the intent's DN block and transaction)", s.reproc, want)
	}
	var cycle string
	s.db.QueryRow(`SELECT cycle_id FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = 84532`, s.intentID).Scan(&cycle)
	if cycle != "cycle-broken" {
		t.Fatalf("a dry run changed the member: %s", cycle)
	}
}

func TestAnAppliedRepairReadsBackWhatTheProofCycleRecorded(t *testing.T) {
	s := newRepairScene(t)
	ctx := context.Background()
	s.onReprocess = func(reach chan consensus.MemberRepairReach, apply bool) error {
		// What the member's proof cycle records when it runs: its write-back registered, its outcome settled and written.
		lc := s.repos.IntentLifecycle
		if err := lc.ClaimMemberWriteBack(ctx, s.intentID, 84532, "cycle-repair", "validator-6"); err != nil {
			return err
		}
		if err := lc.RecordMemberWriteBack(ctx, s.intentID, 84532, "cycle-repair", "acc://wb-base"); err != nil {
			return err
		}
		if _, err := lc.RecordMemberOutcome(ctx, database.MemberOutcome{IntentID: s.intentID, ChainID: 84532, MemberChains: []int64{84532, 421614},
			Legs: 1, Settlement: database.MemberSettlementSettled, ProofCycle: database.MemberProofCycleWritten, SettlementTx: s.tx,
			WriteBackTx: "acc://wb-base", CycleID: "cycle-repair", ReportedBy: "validator-6"}); err != nil {
			return err
		}
		reach <- consensus.MemberRepairReach{Snapshot: snapshot, Started: true}
		return nil
	}
	res := s.runner(t, "validator-6").Serve(ctx, s.request(true))
	if res.Outcome != MemberRepairRepaired {
		t.Fatalf("an applied repair: %s %s", res.Outcome, res.Reason)
	}
	if res.Before["proof_cycle"] != "failed" || res.After["proof_cycle"] != "written" || res.Intent["status"] != "complete" {
		t.Fatalf("before %v after %v intent %v", res.Before, res.After, res.Intent)
	}
	if res.WriteBack == nil || res.WriteBack.State != database.MemberWriteBackWritten || len(res.Correction) != 2 {
		t.Fatalf("write-back %+v, corrections %v; want the write-back registered and two corrections (member and intent)", res.WriteBack, res.Correction)
	}
}

func TestARoundThatNeverReachesTheMemberIsAFailureNamingWhy(t *testing.T) {
	s := newRepairScene(t)
	s.onReprocess = func(chan consensus.MemberRepairReach, bool) error { return errors.New("committed as another block") }
	res := s.runner(t, "validator-6").Serve(context.Background(), s.request(true))
	if res.Outcome != MemberRepairFailed || !strings.Contains(res.Reason, "did not reach") || !strings.Contains(res.Reason, "committed as another block") {
		t.Fatalf("got %s: %s", res.Outcome, res.Reason)
	}
}

func TestARepairRequestIsKeptAndAnswered(t *testing.T) {
	s := newRepairScene(t)
	s.onReprocess = func(reach chan consensus.MemberRepairReach, apply bool) error {
		reach <- consensus.MemberRepairReach{Snapshot: snapshot}
		return nil
	}
	r := s.runner(t, "validator-6")
	if err := r.ready(); err != nil {
		t.Fatal(err)
	}
	req := s.request(false)
	blob, _ := json.Marshal(req)
	if err := os.WriteFile(filepath.Join(r.Dir, "requests", req.ID+".json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.Dir, "done", req.ID+".json")); err != nil {
		t.Fatalf("the request was not kept in done/: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(r.Dir, "results", req.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var res MemberRepairResult
	if err := json.Unmarshal(raw, &res); err != nil || res.Outcome != MemberRepairReached || res.Request.ID != req.ID {
		t.Fatalf("result %+v (%v)", res, err)
	}
	if err := (&MemberRepairRunner{Dir: r.Dir}).Start(context.Background()); err == nil {
		t.Fatal("a runner that is not wired started")
	}
}

// RB6-F9: a member Phase 7 recorded settled_unproven - settled, with its settlement transaction, and no observation
// anywhere because its block could not be proven - can be repaired once it can be proven: the repair observes and proves
// it afresh (no other validator's observation exists to adopt). A member naming another transaction is still refused.
func TestASettledUnprovenMemberIsRepairable(t *testing.T) {
	for name, tc := range map[string]struct {
		memberTx string
		want     string
	}{
		"the member names this settlement":    {"", MemberRepairReached},
		"the member names another settlement": {"0x" + strings.Repeat("77", 32), MemberRepairRefused},
	} {
		t.Run(name, func(t *testing.T) {
			s := newRepairScene(t)
			memberTx := tc.memberTx
			if memberTx == "" {
				memberTx = s.tx
			}
			if _, err := s.db.Exec(`DELETE FROM chain_execution_results WHERE tx_hash = $1`, s.tx); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`UPDATE intent_member_outcomes SET settlement = 'settled', proof_cycle = 'proof_pending', settlement_tx = $3,
				reason = 'phase 7 failed: observe transaction 0: settled_unproven: no inclusion proof'
				WHERE intent_id = $1 AND chain_id = $2`, s.intentID, 84532, memberTx); err != nil {
				t.Fatal(err)
			}
			s.onReprocess = func(reach chan consensus.MemberRepairReach, apply bool) error {
				reach <- consensus.MemberRepairReach{Snapshot: snapshot}
				return nil
			}
			res := s.runner(t, "validator-3").Serve(context.Background(), s.request(false))
			if res.Outcome != tc.want {
				t.Fatalf("THE regression: %s: %s", res.Outcome, res.Reason)
			}
			if tc.want == MemberRepairRefused && !strings.Contains(res.Reason, "recorded observation") {
				t.Fatalf("refused, but not on the observation: %s", res.Reason)
			}
		})
	}
}
