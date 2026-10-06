// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// RB7 D7: Telcoin Adiri (2017) makes a block only when a transaction lands or its epoch closes, so its finalized time
// stops while it is idle. Every rule that waits for a finalized block past a horizon reads the chain's ONE clock, and on
// this chain - only on this chain - a rule blocked solely on its horizon arms the heartbeat: validator i sends one
// zero-value transfer to itself once its wall clock is 30 s + 15 s*(i-1) past the horizon. The block decides; the wall
// clock only triggers.

const adiriID = int64(2017)

// adiriMember is a member on Adiri committed at commit: its deadline is commit + 1 h, its v4 leaf window opens at commit.
func adiriMember(t *testing.T, id byte, commit time.Time) *PendingBatchIntent {
	t.Helper()
	withAccountLeafVersions(t, "2017=v4")
	p := odMember(id, adiriID, 100)
	p.CommitTime = commit
	return certifiedForTest(p)
}

// idleAdiri is an Adiri whose last block (traffic) is at lastTraffic; a block made later is committed at *wall.
func idleAdiri(lastTraffic time.Time, wall *time.Time) *simIdleChain {
	c := newSimIdleChain(adiriID, uint64(lastTraffic.Add(-time.Hour).Unix()))
	for i := 9; i >= 0; i-- { // ten blocks of traffic, the last at lastTraffic
		c.mine(uint64(lastTraffic.Add(-time.Duration(i) * 13 * time.Second).Unix()))
	}
	c.commitAt = func() uint64 { return uint64(wall.Unix()) }
	return c
}

// T-6, rule 10: a non-settlement on an idle chain becomes attestable after a heartbeat block - and only then.
func TestAnIdleChainsNonSettlementBecomesAttestableAfterAHeartbeat(t *testing.T) {
	commit := time.Unix(1_800_000_000, 0).UTC()
	m := adiriMember(t, 1, commit)
	facts, err := memberFacts(m)
	if err != nil {
		t.Fatal(err)
	}
	horizon := facts.Deadline.Add(nonSettlementFinality)
	var wall time.Time
	chain := idleAdiri(commit, &wall)
	v := newSimValidator(t, chain, 1, &wall, true)
	rd := NonSettlementChainFromResolver(simResolver{adiriID: v.orch.ecm})
	ctx := context.Background()

	wall = horizon.Add(10 * time.Second)
	if _, _, err := observeNonSettlementAt(ctx, rd, facts, "test", 0); !errors.Is(err, errNotYetAttestable) {
		t.Fatalf("an idle chain past the deadline by the wall clock: %v", err)
	}
	if v.beat.pending() != 1 {
		t.Fatalf("the non-settlement did not tell the clock its horizon (%d pending)", v.beat.pending())
	}
	if o := v.tick(t); o != HeartbeatWaiting || chain.sentCount() != 0 {
		t.Fatalf("validator 1 acted %s before 30 s past the horizon", o)
	}
	wall = horizon.Add(31 * time.Second)
	if o := v.tick(t); o != HeartbeatSent || chain.sentCount() != 1 {
		t.Fatalf("validator 1, 31 s past the horizon: %s (%d sent)", o, chain.sentCount())
	}
	hb := chain.sent[0]
	if hb.To() == nil || *hb.To() != v.orch.ownAddress() || hb.Value().Sign() != 0 || hb.Gas() != heartbeatGas {
		t.Fatalf("the heartbeat is not a zero-value transfer to itself: to %v value %v gas %d", hb.To(), hb.Value(), hb.Gas())
	}
	claim, obs, err := observeNonSettlementAt(ctx, rd, facts, "test", 0)
	if err != nil {
		t.Fatalf("THE regression (T-6): after the heartbeat block the non-settlement is still not attestable: %v", err)
	}
	if claim.Block != chain.head().Number.Uint64() || claim.BlockTime <= horizon.Unix() {
		t.Fatalf("claim at block %d (time %d); the heartbeat block is %d, the horizon %d", claim.Block, claim.BlockTime,
			chain.head().Number.Uint64(), horizon.Unix())
	}
	// A peer reproduces it from its own reads.
	msg := &attestation.AttestationMessage{IntentID: m.IntentID, ResultHash: obs.ResultHash, NonSettlement: claim}
	if err := verifyNonSettlementClaim(ctx, rd, m, msg); err != nil {
		t.Fatalf("a peer does not reproduce the claim: %v", err)
	}
	// The horizon is served: nothing more is sent.
	wall = wall.Add(time.Hour)
	if o := v.tick(t); o == HeartbeatSent || chain.sentCount() != 1 {
		t.Fatalf("a served horizon sent again: %s", o)
	}
}

// T-8: a successor behind a predecessor on an idle Adiri that did not settle is stopped once a heartbeat block passes
// the predecessor's deadline and margin.
func TestASuccessorBehindAFailedPredecessorOnAnIdleChainIsStopped(t *testing.T) {
	withAccountLeafVersions(t, "2017=v4")
	commit := time.Unix(1_800_000_000, 0).UTC()
	succ := successor(false)
	succ.CommitTime = commit
	succ.After.ChainID = adiriID
	succ.After.Deadline = commit.Add(time.Hour)
	horizon := succ.After.Deadline.Add(nonSettlementFinality)
	var wall time.Time
	chain := idleAdiri(commit, &wall)
	v := newSimValidator(t, chain, 1, &wall, true)
	rd := NonSettlementChainFromResolver(simResolver{adiriID: v.orch.ecm})
	ctx := context.Background()

	wall = horizon.Add(5 * time.Second)
	if st, cause, err := sequenceReadiness(ctx, rd, succ); err != nil || st != sequenceWaiting {
		t.Fatalf("before any block past the horizon: state %d (%q, %v)", st, cause, err)
	}
	wall = horizon.Add(31 * time.Second)
	if o := v.tick(t); o != HeartbeatSent {
		t.Fatalf("the heartbeat: %s", o)
	}
	st, cause, err := sequenceReadiness(ctx, rd, succ)
	if err != nil || st != sequenceStopped || !strings.Contains(cause, "2017") {
		t.Fatalf("THE regression (T-8): after the heartbeat block the successor is %d (%q, %v), not stopped", st, cause, err)
	}
}

// T-1: no settlement is sent before its leaf's notBefore - on an idle chain the head never reaches it, and only a send
// would make a block. The heartbeat makes the block; then the settlement is sent.
func TestANotBeforeSendOnAnIdleChainIsResolvedByAHeartbeat(t *testing.T) {
	commit := time.Unix(1_800_000_000, 0).UTC()
	m := adiriMember(t, 1, commit)
	in, err := m.LeafInput()
	if err != nil || in.NotBefore != uint64(commit.Unix()) {
		t.Fatalf("leaf input %+v, %v", in, err)
	}
	tree, err := BuildBatchTree(adiriID, []BatchLeafInput{in}, m.CommitHeight, testIncarnation)
	if err != nil {
		t.Fatal(err)
	}
	var wall time.Time
	chain := idleAdiri(commit.Add(-10*time.Minute), &wall)
	v := newSimValidator(t, chain, 1, &wall, true)
	ctx := context.Background()
	settle := func() (string, error) {
		if err := v.orch.ecm.beginNonceSequence(ctx); err != nil {
			t.Fatal(err)
		}
		defer v.orch.ecm.endNonceSequence()
		return v.orch.settleMember(ctx, m, tree, nil, time.Time{})
	}

	wall = commit.Add(10 * time.Second)
	if _, err := settle(); err == nil || !strings.Contains(err.Error(), "before its leaf's notBefore") || !IsChainReadError(err) {
		t.Fatalf("an idle head before notBefore: %v", err)
	}
	if chain.sentCount() != 0 || v.beat.pending() != 1 {
		t.Fatalf("%d sent, %d horizons", chain.sentCount(), v.beat.pending())
	}
	wall = commit.Add(31 * time.Second)
	if o := v.tick(t); o != HeartbeatSent {
		t.Fatalf("the heartbeat: %s", o)
	}
	tx, err := settle()
	if err != nil {
		t.Fatalf("THE regression (T-1): after the heartbeat block the settlement is still not sent: %v", err)
	}
	if chain.sentCount() != 2 || chain.sent[1].Hash().Hex() != tx || *chain.sent[1].To() != m.Account {
		t.Fatalf("sent %d; the settlement %s", chain.sentCount(), tx)
	}
}

// T-4: the settlement window hands over on an idle chain: the next window's settler tells the clock its horizon (window
// j's fence plus the reorg margin, where window j+1 begins), the heartbeat makes the block, and the taker acts.
func TestTheSettlementWindowHandsOverOnAnIdleChain(t *testing.T) {
	var wall time.Time
	chain := idleAdiri(odT0.Add(time.Minute), &wall) // the attestation's block is the last traffic
	v := newSimValidator(t, chain, 1, &wall, true)
	// Window 0 is the attester's (third); window 1 is this validator's (roster [own, other, third]).
	f := &fakeODChain{attested: true, attester: odThirdAddr, settleTx: odSettleTx, sim: chain,
		await: func(rule string, after time.Time) { v.clock.AwaitTime(rule, uint64(after.Unix())) }}
	m := odMember(1, odChain, 100)
	horizon := odT0.Add(SettlementWindow) // fence(0) + settlementReorgMargin
	ctx := context.Background()

	wall = horizon.Add(10 * time.Minute)
	if needed, err := odOrchestrator(f).OnDemandMemberNeedsThisValidator(ctx, m); err != nil || needed {
		t.Fatalf("before any block past window 0: needed=%v err=%v", needed, err)
	}
	if len(f.awaited) == 0 || !f.awaited[0].Equal(horizon) {
		t.Fatalf("the next settler did not tell the clock window 1's start: %v", f.awaited)
	}
	if out := settle(t, f, m); !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("window 0 is the attester's: %+v", out)
	}
	if o := v.tick(t); o != HeartbeatSent {
		t.Fatalf("the heartbeat: %s", o)
	}
	if needed, err := odOrchestrator(f).OnDemandMemberNeedsThisValidator(ctx, m); err != nil || !needed {
		t.Fatalf("THE regression (T-4): after the heartbeat block window 1 is not this validator's: needed=%v err=%v", needed, err)
	}
	out := settle(t, f, m)
	if !out.Settled || f.settleCalls != 1 {
		t.Fatalf("THE regression (T-4): the taker did not settle after the heartbeat block: %+v", out)
	}
	if want := odT0.Add(2*SettlementWindow - settlementFenceMargin); !f.lastFence.Equal(want) {
		t.Fatalf("the taker's fence %s, want window 1's %s", f.lastFence, want)
	}
}

// simOutcomeChain is the outcome reads of a simulated chain through its clock, as AgreedOutcomeChain reads them: the
// leaf is read unconsumed at the agreed block ethrpc.RecentStateDepth below the head.
type simOutcomeChain struct {
	sim   *simIdleChain
	clock *ChainClock
}

func (c simOutcomeChain) ChainID() int64 { return c.sim.chainID }
func (c simOutcomeChain) FinalizedHeader(ctx context.Context) (*types.Header, error) {
	return c.clock.Finalized(ctx)
}
func (c simOutcomeChain) HeaderAt(ctx context.Context, n uint64) (*types.Header, error) {
	return c.clock.HeaderAt(ctx, n)
}
func (c simOutcomeChain) LeafConsumption(context.Context, common.Address, [32]byte, time.Time) (*LeafConsumption, uint64, error) {
	n := c.sim.head().Number.Uint64()
	if n > 3 {
		n -= 3
	}
	return nil, n, nil
}
func (c simOutcomeChain) MemberExecution(context.Context, common.Hash, []CommittedLeg, [32]byte, common.Address) (*ExternalChainResult, []CommittedEffect, []CommittedEffect, error) {
	return nil, nil, nil, errors.New("no execution")
}
func (c simOutcomeChain) RevertedAttempt(context.Context, common.Hash, []CommittedLeg, [32]byte, common.Address) (*ExternalChainResult, error) {
	return nil, ErrNotAnAttempt
}
func (c simOutcomeChain) AwaitTime(rule string, after uint64) { c.clock.AwaitTime(rule, after) }
func (c simOutcomeChain) AwaitBlock(rule string, n uint64)    { c.clock.AwaitBlock(rule, n) }

// adiriKeptTree is a one-member kept tree on Adiri.
func adiriKeptTree(t *testing.T) *OutcomeTree {
	t.Helper()
	withAccountLeafVersions(t, "2017=v4")
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	a := outcomeTestMember(t, adiriID, "alpha", f77NativeLeg(adiriID, "7"))
	tree, byOp := outcomeTestTree(t, adiriID, a)
	kept, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	return kept
}

// T-9: an unconsumed member's status-3 outcome on an idle chain is derived at the first block past its deadline and
// margin - the heartbeat's - once the head is far enough past it to read the leaf there.
func TestAnIdleChainsStatusThreeOutcomeIsDerivedAtTheFirstHeartbeatBlock(t *testing.T) {
	kept := adiriKeptTree(t)
	deadline := time.Unix(kept.Members[0].Deadline, 0)
	horizon := deadline.Add(nonSettlementFinality)
	var wall time.Time
	chain := idleAdiri(deadline.Add(-10*time.Minute), &wall)
	v := newSimValidator(t, chain, 1, &wall, false)
	oc := simOutcomeChain{sim: chain, clock: v.clock}
	ctx := context.Background()

	wall = horizon.Add(10 * time.Second)
	if _, err := DeriveOutcome(ctx, oc, kept, nil); !errors.Is(err, ErrOutcomeNotYet) {
		t.Fatalf("before any block past the horizon: %v", err)
	}
	wall = horizon.Add(31 * time.Second)
	if o := v.tick(t); o != HeartbeatSent {
		t.Fatalf("the heartbeat: %s", o)
	}
	claimBlock := chain.head()
	// The leaf is read at the agreed block three below the head: three more heartbeats, one per minimum gap.
	for i := 0; i < 3; i++ {
		if _, err := DeriveOutcome(ctx, oc, kept, nil); !errors.Is(err, ErrOutcomeNotYet) {
			t.Fatalf("with the head %d blocks past the claim: %v", i, err)
		}
		wall = wall.Add(heartbeatMinGap + heartbeatDelay(1))
		if o := v.tick(t); o != HeartbeatSent {
			t.Fatalf("heartbeat %d for the block horizon: %s", i+2, o)
		}
	}
	out, err := DeriveOutcome(ctx, oc, kept, nil)
	if err != nil {
		t.Fatalf("THE regression (T-9): the status-3 outcome is not derivable on an idle chain: %v", err)
	}
	l := out.Leaves[0]
	if l.Status != OutcomeNotSettled || l.BlockNumber != claimBlock.Number.Uint64() || l.BlockHash != claimBlock.Hash() {
		t.Fatalf("leaf %+v; want status 3 at the first block past the horizon, %d", l, claimBlock.Number.Uint64())
	}
	if o := v.tick(t); o == HeartbeatSent {
		t.Fatal("a derived outcome kept the heartbeat going")
	}
}

// A heartbeat that lands too early - in a block whose time is not past the horizon (the chain's time trails the
// validator's clock) - decides nothing; the trigger re-arms and the next heartbeat's block decides.
func TestAnEarlyHeartbeatChangesNothing(t *testing.T) {
	commit := time.Unix(1_800_000_000, 0).UTC()
	m := adiriMember(t, 1, commit)
	facts, _ := memberFacts(m)
	horizon := facts.Deadline.Add(nonSettlementFinality)
	var wall time.Time
	chain := idleAdiri(commit, &wall)
	chain.commitAt = func() uint64 { return uint64(wall.Add(-40 * time.Second).Unix()) } // consensus time trails by 40 s
	v := newSimValidator(t, chain, 1, &wall, true)
	rd := NonSettlementChainFromResolver(simResolver{adiriID: v.orch.ecm})
	ctx := context.Background()

	wall = horizon.Add(10 * time.Second)
	_, _, _ = observeNonSettlementAt(ctx, rd, facts, "test", 0)
	wall = horizon.Add(31 * time.Second)
	if o := v.tick(t); o != HeartbeatSent || chain.head().Time > uint64(horizon.Unix()) {
		t.Fatalf("the early heartbeat: %s, block time %d, horizon %d", o, chain.head().Time, horizon.Unix())
	}
	if _, _, err := observeNonSettlementAt(ctx, rd, facts, "test", 0); !errors.Is(err, errNotYetAttestable) {
		t.Fatalf("THE regression: a block not past the horizon decided: %v", err)
	}
	if o := v.tick(t); o != HeartbeatWaiting {
		t.Fatalf("re-sent inside the minimum gap: %s", o)
	}
	wall = wall.Add(heartbeatMinGap + time.Second)
	if o := v.tick(t); o != HeartbeatSent {
		t.Fatalf("the trigger did not re-arm: %s", o)
	}
	if claim, _, err := observeNonSettlementAt(ctx, rd, facts, "test", 0); err != nil || claim.BlockTime <= horizon.Unix() {
		t.Fatalf("after the second heartbeat: %+v %v", claim, err)
	}
}

// Two validators racing: both are due, both read the head before either block lands, both send. Two blocks past the
// horizon exist - and every decision is the same on both, because each rule decides from the chain: the first block past
// the horizon, and a pinned claim each peer re-reads.
func TestTwoValidatorsRacingHeartbeatsYieldOneDecision(t *testing.T) {
	kept := adiriKeptTree(t)
	deadline := time.Unix(kept.Members[0].Deadline, 0)
	horizon := deadline.Add(nonSettlementFinality)
	var wall time.Time
	chain := idleAdiri(deadline.Add(-10*time.Minute), &wall)
	v1 := newSimValidator(t, chain, 1, &wall, false)
	v2 := newSimValidator(t, chain, 2, &wall, false)
	ctx := context.Background()
	wall = horizon.Add(time.Minute) // past both validators' delays (30 s, 45 s)
	for _, v := range []*simValidator{v1, v2} {
		v.clock.AwaitTime("the outcome", uint64(horizon.Unix()))
		send := v.beat.send
		var once sync.Once
		v.beat.send = func(ctx context.Context) (string, uint64, error) {
			once.Do(func() { raceBarrier.Done(); raceBarrier.Wait() }) // both have read the head before either sends
			return send(ctx)
		}
	}
	raceBarrier.Add(2)
	var wg sync.WaitGroup
	outs := make([]HeartbeatOutcome, 2)
	for i, v := range []*simValidator{v1, v2} {
		wg.Add(1)
		go func(i int, v *simValidator) { defer wg.Done(); outs[i], _ = v.beat.Tick(ctx) }(i, v)
	}
	wg.Wait()
	if outs[0] != HeartbeatSent || outs[1] != HeartbeatSent || chain.sentCount() != 2 {
		t.Fatalf("the race did not happen: %v, %d sent", outs, chain.sentCount())
	}
	first := chain.headers[len(chain.headers)-2]
	// Traffic carries the head far enough past both for the leaf read.
	for i := 0; i < 3; i++ {
		chain.mine(uint64(wall.Unix()))
	}
	var leaves []OutcomeLeaf
	for _, v := range []*simValidator{v1, v2} {
		out, err := DeriveOutcome(ctx, simOutcomeChain{sim: chain, clock: v.clock}, kept, nil)
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, out.Leaves[0])
	}
	if leaves[0] != leaves[1] || leaves[0].BlockNumber != first.Number.Uint64() || leaves[0].Status != OutcomeNotSettled {
		t.Fatalf("two decisions: %+v / %+v (the first block past the horizon is %d)", leaves[0], leaves[1], first.Number.Uint64())
	}
}

var raceBarrier sync.WaitGroup

// The wall clock decides nothing. With every heartbeat refused (the relayer is unfunded), a day past every horizon by the
// wall clock, no rule has decided anything; the refusal is named. Then the chain's own epoch-closing block arrives and
// every rule decides, by its own predicate, from that block.
func TestTheWallClockNeverDecides(t *testing.T) {
	commit := time.Unix(1_800_000_000, 0).UTC()
	m := adiriMember(t, 1, commit)
	facts, _ := memberFacts(m)
	horizon := facts.Deadline.Add(nonSettlementFinality)
	succ := successor(false)
	succ.CommitTime = commit
	succ.After.ChainID, succ.After.Deadline = adiriID, facts.Deadline
	var wall time.Time
	chain := idleAdiri(commit, &wall)
	chain.balance = new(big.Int)
	v := newSimValidator(t, chain, 1, &wall, true)
	rd := NonSettlementChainFromResolver(simResolver{adiriID: v.orch.ecm})
	ctx := context.Background()

	wall = horizon.Add(24 * time.Hour)
	if _, _, err := observeNonSettlementAt(ctx, rd, facts, "test", 0); !errors.Is(err, errNotYetAttestable) {
		t.Fatalf("THE regression: the wall clock decided a non-settlement: %v", err)
	}
	if st, _, err := sequenceReadiness(ctx, rd, succ); err != nil || st != sequenceWaiting {
		t.Fatalf("THE regression: the wall clock decided a successor: %d %v", st, err)
	}
	o, err := v.beat.Tick(ctx)
	if o != HeartbeatUnfunded || !errors.Is(err, ErrHeartbeatUnfunded) || chain.sentCount() != 0 {
		t.Fatalf("an unfunded relayer: %s %v", o, err)
	}
	if _, _, err := observeNonSettlementAt(ctx, rd, facts, "test", 0); !errors.Is(err, errNotYetAttestable) {
		t.Fatalf("after a refused heartbeat: %v", err)
	}
	// The epoch closes: an empty block, made by the chain, not by CERTEN.
	chain.mine(uint64(wall.Unix()))
	if _, _, err := observeNonSettlementAt(ctx, rd, facts, "test", 0); err != nil {
		t.Fatalf("the epoch-closing block: %v", err)
	}
	if st, _, err := sequenceReadiness(ctx, rd, succ); err != nil || st != sequenceStopped {
		t.Fatalf("the epoch-closing block, the successor: %d %v", st, err)
	}
}

// Every failure to send a heartbeat is named.
func TestHeartbeatFailuresAreNamed(t *testing.T) {
	commit := time.Unix(1_800_000_000, 0).UTC()
	for name, tc := range map[string]struct {
		set  func(c *simIdleChain, v *simValidator)
		want HeartbeatOutcome
	}{
		"gas ceiling": {func(c *simIdleChain, v *simValidator) {
			c.baseFee = big.NewInt(5e9)
			c.mine(uint64(commit.Unix()))
		}, HeartbeatGasCeiling},
		"key busy": {func(c *simIdleChain, v *simValidator) {
			if err := v.orch.ecm.beginNonceSequence(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(v.orch.ecm.endNonceSequence)
		}, HeartbeatKeyBusy},
		"unfunded": {func(c *simIdleChain, v *simValidator) { c.balance = big.NewInt(1) }, HeartbeatUnfunded},
		// RB7 D8: the chain the key would send to is not the pinned incarnation (a reset): refused by name, nothing sent.
		"another genesis": {func(c *simIdleChain, v *simValidator) {
			t.Setenv(supportedchains.GenesisEnvFor(adiriID), "0x"+strings.Repeat("ab", 32))
		}, HeartbeatRefused},
	} {
		t.Run(name, func(t *testing.T) {
			var wall time.Time
			chain := idleAdiri(commit, &wall)
			v := newSimValidator(t, chain, 1, &wall, false)
			tc.set(chain, v)
			wall = commit.Add(2 * time.Hour)
			v.clock.AwaitTime("test", uint64(commit.Add(time.Hour).Unix()))
			o, err := v.beat.Tick(context.Background())
			if o != tc.want || err == nil || chain.sentCount() != 0 {
				t.Fatalf("%s: %v (%d sent)", o, err, chain.sentCount())
			}
		})
	}
}

// The rules routed through the clock read no wall clock: the only time.Now in their bodies would be a decision taken on
// this machine's clock.
func TestTheClockRulesReadNoWallClock(t *testing.T) {
	for file, funcs := range map[string][]string{
		"non_settlement.go":          {"func observeNonSettlementAt(", "func verifyNonSettlementClaim("},
		"batch_sequence.go":          {"func sequenceReadiness("},
		"outcome_derivation.go":      {"func DeriveOutcome(", "func deriveMember("},
		"batch_settlement_window.go": {"func (o *BatchOrchestrator) decideSettlementWindow(", "func (o *BatchOrchestrator) OnDemandMemberNeedsThisValidator(", "func (o *BatchOrchestrator) headTime(", "func (o *BatchOrchestrator) finalizedTime("},
		"batch_orchestrator.go":      {"func (o *BatchOrchestrator) settleMember(", "func (o *BatchOrchestrator) allPendingPastDeadline(", "func settlementExpiry(", "func allPastDeadlineAt("},
		"batch_attribution.go":       {"func (o *BatchOrchestrator) blockAtOrBefore(", "func searchBlockAtOrBefore("},
		"chain_clock.go":             {"func (c *ChainClock) Head(", "func (c *ChainClock) Finalized(", "func (c *ChainClock) HeaderAt("},
	} {
		src := readSource(t, file)
		for _, fn := range funcs {
			body := funcBody(t, src, fn)
			for _, wallRead := range []string{"time.Now(", "time.Since(", "time.Until("} {
				if strings.Contains(body, wallRead) {
					t.Fatalf("%s %s reads the wall clock (%s)", file, fn, wallRead)
				}
			}
		}
	}
}

func readSource(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// funcBody is the top-level function starting with signature, through its closing brace.
func funcBody(t *testing.T, src, signature string) string {
	t.Helper()
	start := strings.Index(src, signature)
	if start < 0 {
		t.Fatalf("%s not found", signature)
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("%s has no end", signature)
	}
	return src[start : start+end]
}
