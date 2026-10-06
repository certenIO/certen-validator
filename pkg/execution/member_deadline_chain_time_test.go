// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

// RB7 D7 (owner: the wall clock may never decide an outcome). A member that could not be settled - never certified, or
// held under the gas ceiling - used to be FAILED once memberPastDeadline said so: time.Since(origin) > its horizon, this
// machine's clock. Those failures are recorded (the drop handler's failed proof cycle, the on-demand dispose) and written
// back. They are now decided by the chain's finalized time past the member's deadline and the finality margin.

type failingClockSource struct{}

func (failingClockSource) HeaderByNumber(context.Context, *big.Int) (*types.Header, error) {
	return nil, errors.New("provider down")
}

// pastDeadlineOnChain: the chain decides; the wall clock only triggers the read.
func TestAMembersDeadlineIsJudgedOnChainTime(t *testing.T) {
	ctx := context.Background()
	deadline := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second) // long past by the wall clock
	m := odMember(1, 84532, 100)
	m.CommitTime = deadline.Add(-time.Hour) // commit + 1 h horizon = deadline
	if d, ok := memberChainDeadline(m); !ok || !d.Equal(deadline) {
		t.Fatalf("deadline %v %v", d, ok)
	}
	chain := newSimIdleChain(84532, uint64(deadline.Add(-3*time.Hour).Unix()))
	chain.mine(uint64(deadline.Add(nonSettlementFinality).Unix())) // exactly at the margin: not past
	o := &BatchOrchestrator{logf: t.Logf, clock: newChainClock(84532, chain)}
	if past, _, err := o.pastDeadlineOnChain(ctx, m); err != nil || past {
		t.Fatalf("THE regression: decided past=%v err=%v while the chain is not past the margin", past, err)
	}
	chain.mine(uint64(deadline.Add(nonSettlementFinality).Unix()) + 1)
	past, evidence, err := o.pastDeadlineOnChain(ctx, m)
	if err != nil || !past || !strings.Contains(evidence, "finalized block 2") {
		t.Fatalf("the chain past the margin: %v %q %v", past, evidence, err)
	}

	// Before the deadline by the wall clock the chain is not asked: the wall clock is only the trigger, and decides nothing.
	fresh := odMember(2, 84532, 100)
	fresh.CommitTime = time.Now()
	countingChain := &countingSource{src: chain}
	c := &BatchOrchestrator{logf: t.Logf, clock: newChainClock(84532, countingChain)}
	if past, _, err := c.pastDeadlineOnChain(ctx, fresh); past || err != nil || countingChain.n != 0 {
		t.Fatalf("a member in time: past=%v err=%v reads=%d", past, err, countingChain.n)
	}

	// An unreadable chain decides nothing.
	broken := &BatchOrchestrator{logf: t.Logf, clock: newChainClock(84532, failingClockSource{})}
	if past, _, err := broken.pastDeadlineOnChain(ctx, m); past || err == nil || !IsChainReadError(err) {
		t.Fatalf("unreadable: past=%v err=%v", past, err)
	}
	// A member with nothing to measure from is never past.
	if past, _, err := o.pastDeadlineOnChain(ctx, &PendingBatchIntent{IntentID: "none", ChainID: 84532}); past || err != nil {
		t.Fatalf("no deadline: past=%v err=%v", past, err)
	}
}

type countingSource struct {
	src chainClockSource
	n   int
}

func (c *countingSource) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	c.n++
	return c.src.HeaderByNumber(ctx, n)
}

// On an idle Adiri the deadline is decided by a heartbeat block: not past -> horizon armed -> heartbeat -> past.
func TestAnIdleChainsDeadlineIsDecidedByAHeartbeatBlock(t *testing.T) {
	deadline := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	var wall time.Time
	chain := idleAdiri(deadline.Add(-10*time.Minute), &wall)
	v := newSimValidator(t, chain, 1, &wall, false)
	m := adiriMember(t, 1, deadline.Add(-time.Hour))
	wall = deadline.Add(nonSettlementFinality + time.Minute)
	if past, _, err := v.orch.pastDeadlineOnChain(context.Background(), m); past || err != nil {
		t.Fatalf("idle: past=%v err=%v", past, err)
	}
	if v.beat.pending() != 1 {
		t.Fatalf("the deadline's horizon was not armed (%d)", v.beat.pending())
	}
	if o := v.tick(t); o != HeartbeatSent {
		t.Fatalf("heartbeat: %s", o)
	}
	if past, _, err := v.orch.pastDeadlineOnChain(context.Background(), m); !past || err != nil {
		t.Fatalf("after the heartbeat block: past=%v err=%v", past, err)
	}
}

// The on-demand gas ceiling: a member is deferred, however long ago it was committed by the wall clock, until its chain
// is past its deadline; then it fails, with the block that decided named in its cause.
func TestAGasCeilingMemberFailsOnlyWhenItsChainIsPastItsDeadline(t *testing.T) {
	f := &fakeODChain{attested: true, attester: odOwnAddr, settleErr: &ErrGasCeilingExceeded{ChainID: odChain, SuggestedGwei: 500, CeilingGwei: 100}}
	m := odMember(1, odChain, 100)
	m.CommitTime = time.Now().Add(-30 * 24 * time.Hour)
	out, err := odOrchestrator(f).SettleOnDemandMember(context.Background(), m, proveOK)
	if err != nil || out == nil || !out.Deferred || f.deadlineReads == 0 {
		t.Fatalf("THE regression (RB7 D7): the wall clock failed a gas-ceiling member: (%+v, %v)", out, err)
	}
	f.chainPast = true
	_, err = odOrchestrator(f).SettleOnDemandMember(context.Background(), m, proveOK)
	var gas *ErrGasCeilingExceeded
	if err == nil || !errors.As(err, &gas) || !strings.Contains(err.Error(), "finalized block") {
		t.Fatalf("past on chain: %v", err)
	}
	// An unreadable chain decides nothing.
	f.chainPast, f.chainPastErr = true, readErr(errors.New("provider down"))
	if out, err := odOrchestrator(f).SettleOnDemandMember(context.Background(), m, proveOK); err != nil || !out.Deferred {
		t.Fatalf("unreadable: (%+v, %v)", out, err)
	}
}

// The cadence lane's gas ceiling: the same rule, through gasCeilingFailure (FlushChain drops the member - a recorded
// failure - only when it says so).
func TestACadenceGasCeilingMemberFailsOnlyWhenItsChainIsPastItsDeadline(t *testing.T) {
	ctx := context.Background()
	deadline := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	m := odMember(1, 84532, 100)
	m.CommitTime = deadline.Add(-time.Hour)
	chain := newSimIdleChain(84532, uint64(deadline.Add(-3*time.Hour).Unix()))
	chain.mine(uint64(deadline.Unix()))
	o := &BatchOrchestrator{logf: t.Logf, clock: newChainClock(84532, chain)}
	gas := &ErrGasCeilingExceeded{ChainID: 84532, SuggestedGwei: 5, CeilingGwei: 1}
	if cause, failed := o.gasCeilingFailure(ctx, m, gas); failed {
		t.Fatalf("THE regression (RB7 D7): failed by the wall clock while the chain is not past its deadline: %s", cause)
	}
	chain.mine(uint64(deadline.Add(nonSettlementFinality).Unix()) + 1)
	cause, failed := o.gasCeilingFailure(ctx, m, gas)
	if !failed || !strings.Contains(cause, "stayed above the ceiling until chain 84532's finalized block 2") {
		t.Fatalf("past on chain: %v %q", failed, cause)
	}
	src := readSource(t, "batch_orchestrator.go")
	if !strings.Contains(src, "if cause, failed := o.gasCeilingFailure(ctx, p, serr); failed {") ||
		!strings.Contains(src, "res.drop(cause, p)") {
		t.Fatal("FlushChain does not decide its gas-ceiling failures through gasCeilingFailure")
	}
}

// The final sweep (RB7 D7): every read of this machine's clock in pkg/execution, classified. None may decide a recorded
// outcome - a drop, OnDropped, Attest, dispose, recordMemberOutcome, MemberDropped, a failed proof cycle, a write-back
// or an outcome leaf. A new read fails this test until it is classified here.
var wallClockReads = map[string]struct {
	n       int
	verdict string
}{
	"batch_orchestrator.go": {2, "trigger only: pastOnChain reads the chain only once the wall clock is past the bound; " +
		"memberPastDeadline releases another validator's member locally (MemberReleased: nothing recorded)"},
	"non_settlement_cycle.go": {3, "trigger only: nonSettlementWindowClosed reads the chain once the wall clock is past the " +
		"window; QueuedAt and StartedAt are timestamps"},
	"batch_ondemand_submitter.go": {9, "TTL is a trigger (settleOnDemandAtTTL decides on chain time); the quorum wait " +
		"bounds one pass and defers; RefuseOnDemand's time starts RefusedKeep (a trigger); failoverElapsed rotates who acts; " +
		"the commit-time retry is a local backoff"},
	"batch_assembly.go":  {1, "the flush loop's first pass time: the settle grace (when a leader forms its batch)"},
	"batch_mempool.go":   {1, "EnqueuedAt: a timestamp; the TTL it starts is a trigger"},
	"batch_execution.go": {3, "the cadence accumulator's flush timing: when legs are grouped, no outcome"},
	"batch_tx.go":        {2, "the genesis re-check cache (ethrpc.GenesisRecheck)"},
	"batch_proof_submitter.go": {1, "the attestation's ExpirationTime: a validity window the chain enforces on its own " +
		"block time; a late transaction reverts and is retried"},
	"batch_quorum_attestor.go": {1, "AttestedAt: a timestamp"},
	"tx_sender.go": {11, "sender liveness: stuck-replacement, waits, outbox retention; a wait that runs out is " +
		"ChainWaitError (outcome unknown), never a failure"},
	"nonce_tracker.go":         {7, "nonce bookkeeping timestamps and cache"},
	"ethereum_contracts.go":    {14, "the retired per-intent proof builders (no batch-lane caller) and the period lane's sequence wait"},
	"credit_checker.go":        {2, "a balance cache"},
	"layer5_validator_set.go":  {2, "a validator-set cache"},
	"accumulate_submitter.go":  {2, "Accumulate transaction timestamps"},
	"synthetic_transaction.go": {4, "timestamps"},
	"external_chain_observer.go": {2, "observation start time, and waitForReceipt (no caller; the observer waits through " +
		"ethrpc.SettledInFinalizedChain)"},
	"external_chain_result.go": {1, "FinalizedAt: a timestamp"},
	"g2_outcome_binding.go":    {3, "verification timestamps and duration"},
	"member_repair_runner.go": {5, "the operator repair's own report: how long it waits for the proof cycle; the member's " +
		"outcome is untouched"},
	"outcome_backfill.go":  {1, "RetainedAt: a timestamp"},
	"outcome_recorder.go":  {1, "the recorder's failover rotation: who records, measured from ResolvedAt (chain time)"},
	"outcome_retention.go": {1, "RetainedAt: a timestamp"},
	"proof_recovery.go":    {1, "RequestedAt: a timestamp"},
	"result_quorum.go":     {1, "CreatedAt: a timestamp"},
	"unified_adapter.go":   {2, "a duration for the log"},
	"unified_orchestrator.go": {18, "timestamps (CompletedAt, VerifiedAt, FinalizedAt, ConfirmedAt), Phase 8's peer rounds " +
		"and the message-freshness replay guard (a failed Phase 8 records proof_pending, re-driven by ProofRecovery), and " +
		"durations - see the RB7 Task 4 stream B report for the Phase 7 observation bound (escalated)"},
}

func TestEveryWallClockReadInTheExecutionPathIsClassified(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		for _, line := range strings.Split(readSource(t, name), "\n") {
			if strings.Contains(line, "time.Now()") || strings.Contains(line, "time.Since(") || strings.Contains(line, "time.Until(") {
				got[name]++
			}
		}
	}
	for file, n := range got {
		w, ok := wallClockReads[file]
		if !ok || w.n != n {
			t.Errorf("%s reads the wall clock %d time(s), classified %d: classify each read (it may never decide a recorded outcome)", file, n, w.n)
		}
	}
	for file, w := range wallClockReads {
		if got[file] != w.n {
			t.Errorf("%s: classified %d wall-clock read(s), found %d", file, w.n, got[file])
		}
	}
}

// The one remaining wall-clock judgment, memberPastDeadline, is local liveness: its only caller releases this node's copy
// of a member another validator attested (MemberReleased) and records nothing. Pinned at the source: no caller records,
// drops, attests or refuses on it, and the decisions that do record read the chain's clock.
func TestTheWallClockReleaseRecordsNothing(t *testing.T) {
	var callers []string
	for _, file := range []string{"batch_orchestrator.go", "batch_orchestrator_ondemand.go", "batch_ondemand_submitter.go",
		"batch_assembly.go", "non_settlement_cycle.go", "outcome_recorder.go"} {
		lines := strings.Split(readSource(t, file), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "memberPastDeadline(") || strings.HasPrefix(strings.TrimSpace(line), "//") ||
				strings.Contains(line, "func (o *BatchOrchestrator) memberPastDeadline(") {
				continue
			}
			callers = append(callers, file)
			end := i + 14
			if end > len(lines) {
				end = len(lines)
			}
			body := strings.Join(lines[i:end], "\n")
			for _, records := range []string{"res.drop(", "onDropped(", "OnDropped(", "Attest(", "dispose(", "MemberDropped",
				"recordMemberOutcome(", "return out, serr", "return nil, fmt.Errorf"} {
				if strings.Contains(body, records) {
					t.Fatalf("%s:%d: a wall-clock judgment leads to %s:\n%s", file, i+1, records, body)
				}
			}
			if !strings.Contains(body, "MarkOutcome(expired, MemberReleased)") {
				t.Fatalf("%s:%d: memberPastDeadline is used for something other than releasing this node's copy:\n%s", file, i+1, body)
			}
		}
	}
	if len(callers) != 1 || callers[0] != "batch_orchestrator.go" {
		t.Fatalf("memberPastDeadline callers %v: only the release of another validator's member may use it", callers)
	}
	// MemberReleased is local: the retention horizon decides only members still pending, and a released one is not.
	p := &PendingBatchIntent{Outcome: MemberReleased}
	if p.pending() {
		t.Fatal("a released member is still pending: the retention horizon would refuse it")
	}
	// The recording decisions read the chain's clock.
	for file, want := range map[string]int{"batch_orchestrator.go": 1, "batch_orchestrator_ondemand.go": 2,
		"batch_ondemand_submitter.go": 1, "batch_assembly.go": 1} {
		// pastDeadlineOnChain (and, in batch_assembly.go, pastAttestationWindowOnChain through pastAttestationWindow).
		if n := strings.Count(readSource(t, file), "astDeadlineOnChain(ctx, "); n != want {
			t.Fatalf("%s reads the chain's deadline %d times, want %d", file, n, want)
		}
	}
}
