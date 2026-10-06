// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"testing"
	"time"
)

// RB7 D7 (owner: the wall clock may never decide a recorded outcome), the attestation window. A non-settlement used to be
// recorded "could not be attested" once time.Since(deadline) passed 50 minutes on this machine's clock; every validator
// also dropped its own copy of a member - the copy a peer verifies a claim from - on its own clock. Both ends of the
// window are now judged on the member's chain: every copy is kept, and the requester keeps trying, until the chain's
// finalized time is past deadline + finality margin + nonSettlementGiveUp.

// windowMember is a member whose deadline is two hours ago by the wall clock.
func windowMember(t *testing.T) (*PendingBatchIntent, NonSettlementFacts) {
	t.Helper()
	own := odMember(1, odChain, 100)
	own.CommitTime = time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)
	own = certifiedForTest(own)
	f, err := memberFacts(own)
	if err != nil {
		t.Fatal(err)
	}
	return own, f
}

// No peers: every attempt fails, and the record is retried until the chain - not this machine's clock - closes the window.
func TestAnUnattestedNonSettlementIsGivenUpOnlyPastItsChainWindow(t *testing.T) {
	own, f := windowMember(t)
	end := nonSettlementWindowEnd(f.Deadline)
	// Attestable (past the deadline and margin) but inside the window, although the wall clock is an hour past its end.
	c := &fakeNSChain{finalized: 500, times: map[uint64]int64{500: f.Deadline.Add(nonSettlementFinality + 10*time.Minute).Unix()},
		consumed: map[uint64]bool{}}
	o := nsOrchestrator(t, own, c)
	if err := o.config.NonSettlements.Put(&NonSettlementRecord{Facts: f, Cause: "dropped", QueuedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	o.processNonSettlements(context.Background())
	if n := len(o.config.NonSettlements.All()); n != 1 {
		t.Fatalf("THE regression (RB7 D7): given up on the wall clock while the chain is inside the attestation window (%d left)", n)
	}
	// The chain at the window's end exactly: still inside.
	c.finalized, c.times[600] = 600, end.Unix()
	o.processNonSettlements(context.Background())
	if n := len(o.config.NonSettlements.All()); n != 1 {
		t.Fatalf("given up at the window's end, not past it (%d left)", n)
	}
	// Past it: recorded unattested, and the record leaves the queue.
	c.finalized, c.times[700] = 700, end.Unix()+1
	o.processNonSettlements(context.Background())
	if n := len(o.config.NonSettlements.All()); n != 0 {
		t.Fatalf("not given up once the chain is past the window (%d left)", n)
	}
}

// A chain that cannot be read decides nothing: the record stays.
func TestAnUnreadableChainNeverClosesTheWindow(t *testing.T) {
	own, f := windowMember(t)
	o := nsOrchestrator(t, own, &fakeNSChain{readErr: errors.New("provider down")})
	rec := &NonSettlementRecord{Facts: f, Cause: "dropped", QueuedAt: time.Now()}
	if err := o.config.NonSettlements.Put(rec); err != nil {
		t.Fatal(err)
	}
	o.retryNonSettlement(context.Background(), rec, errors.New("no quorum"))
	if n := len(o.config.NonSettlements.All()); n != 1 {
		t.Fatalf("an unreadable chain closed the window (%d left)", n)
	}
}

// On an idle Adiri the window's end is a horizon for the chain's heartbeat.
func TestAnIdleChainArmsTheAttestationWindow(t *testing.T) {
	commit := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)
	m := adiriMember(t, 1, commit)
	f, _ := memberFacts(m)
	wall := time.Now()
	chain := idleAdiri(commit, &wall)
	v := newSimValidator(t, chain, 1, &wall, true)
	o := nsOrchestrator(t, m, NonSettlementChainFromResolver(simResolver{adiriID: v.orch.ecm}))
	rec := &NonSettlementRecord{Facts: f, Cause: "dropped"}
	if closed, _, err := o.nonSettlementWindowClosed(context.Background(), rec); closed || err != nil {
		t.Fatalf("idle: closed=%v err=%v", closed, err)
	}
	if v.beat.pending() != 1 {
		t.Fatalf("the window's end was not armed (%d)", v.beat.pending())
	}
	wall = nonSettlementWindowEnd(f.Deadline).Add(time.Minute)
	if o := v.tick(t); o != HeartbeatSent {
		t.Fatalf("heartbeat: %s", o)
	}
	if closed, _, err := o.nonSettlementWindowClosed(context.Background(), rec); !closed || err != nil {
		t.Fatalf("after the heartbeat block: closed=%v err=%v", closed, err)
	}
}

// The refused set keeps a member past RefusedKeep (this machine's clock) until its chain is past its window.
func TestARefusedCopyIsKeptUntilItsChainIsPastTheWindow(t *testing.T) {
	m := newTestMempool(BatchMempoolConfig{MaxBatchSize: 10})
	p := horizonMember("refused", 5)
	p.CommitTime = time.Now().Add(-72 * time.Hour)
	if err := m.AddOnDemand(p); err != nil {
		t.Fatal(err)
	}
	refusedAt := time.Now().Add(-RefusedKeep - time.Hour)
	if !m.RefuseOnDemand(p.ChainID, p.OperationID, refusedAt) {
		t.Fatal("not refused")
	}
	chain := newSimIdleChain(p.ChainID, uint64(p.CommitTime.Add(-time.Hour).Unix()))
	chain.mine(uint64(p.CommitTime.Add(time.Hour).Unix()))
	s := &BatchStack{Mempool: m, MemberOutcomes: outcomeBook{},
		Orchestrators: map[int64]*BatchOrchestrator{p.ChainID: {logf: t.Logf, clock: newChainClock(p.ChainID, chain)}}}
	drops := &dropLog{dropped: map[string]string{}}
	s.settleOnDemandAtTTL(time.Hour, time.Now(), func(*PendingBatchIntent) bool { return true }, drops.fn, t.Logf)
	if _, ok := m.FindMember(p.ChainID, p.OperationID); !ok {
		t.Fatal("THE regression (RB7 D7): the refused copy was dropped on the wall clock inside the attestation window")
	}
	chain.mine(uint64(time.Now().Unix()))
	s.settleOnDemandAtTTL(time.Hour, time.Now(), func(*PendingBatchIntent) bool { return true }, drops.fn, t.Logf)
	if _, ok := m.FindMember(p.ChainID, p.OperationID); ok {
		t.Fatal("the refused copy was kept past its window")
	}
}

// The period pool below the retention horizon keeps a copy until its chain is past the window.
func TestAPeriodCopyIsKeptUntilItsChainIsPastTheWindow(t *testing.T) {
	m := newTestMempool(BatchMempoolConfig{MaxBatchSize: 10})
	p := horizonMember("elsewhere", 5)
	p.CommitTime = time.Now().Add(-72 * time.Hour)
	if err := m.Add(p); err != nil {
		t.Fatal(err)
	}
	chain := newSimIdleChain(p.ChainID, uint64(p.CommitTime.Add(-time.Hour).Unix()))
	chain.mine(uint64(p.CommitTime.Add(time.Hour).Unix()))
	s := &BatchStack{Mempool: m, MemberOutcomes: outcomeBook{"elsewhere": "settled"},
		Orchestrators: map[int64]*BatchOrchestrator{p.ChainID: {logf: t.Logf, clock: newChainClock(p.ChainID, chain)}}}
	leads := func(*PendingBatchIntent) bool { return true }
	if n := s.pruneAtRetentionHorizon(4, 100, leads, nil, t.Logf); n != 0 {
		t.Fatalf("THE regression (RB7 D7): pruned %d copy(ies) inside the attestation window", n)
	}
	chain.mine(uint64(time.Now().Unix()))
	if n := s.pruneAtRetentionHorizon(4, 100, leads, nil, t.Logf); n != 1 {
		t.Fatalf("pruned %d past the window, want 1", n)
	}
}

// A quorum that is not ready when this pass's wait runs out defers the member: peers that are behind decide nothing.
func TestAQuorumDeadlineDefersTheMember(t *testing.T) {
	s, calls := settlementSubmitter(t, &fakeODChain{})
	s.cfg.QuorumDeadline, s.cfg.RetryBackoff = 50*time.Millisecond, 10*time.Millisecond
	s.proveRoot = func(context.Context, *BatchTree, *PendingBatchIntent) error {
		return &QuorumNotReadyError{NotHeld: 3, Agreed: 1}
	}
	m := odMember(1, odChain, 100)
	orch, _ := s.cfg.Stack.OrchestratorFor(odChain)
	out, err := s.settleWithReadinessRetry(context.Background(), orch, m)
	if err != nil || out == nil || !out.Deferred {
		t.Fatalf("THE regression (RB7 D7): a wall-clock quorum wait decided the member: (%+v, %v)", out, err)
	}
	if len(*calls) != 0 {
		t.Fatalf("attested %+v", *calls)
	}
}
