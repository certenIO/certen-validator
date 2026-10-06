// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB7 D7: Phase 7 ends only when the chain decides. It used to give up on this machine's clock (FinalityBound, the
// cycle's deadline) and record the member "unobserved" / "failed".

// observingChain is a chain strategy whose observation fails `fails` times (the chain has not finalized the
// transaction), then succeeds - or never, with fails < 0.
type observingChain struct {
	chain.ChainExecutionStrategy
	fails    int
	attempts int
}

func (c *observingChain) ChainID() string { return odChainStr }
func (c *observingChain) ObserveTransaction(ctx context.Context, tx string) (*chain.ObservationResult, error) {
	c.attempts++
	if c.fails < 0 || c.attempts <= c.fails {
		return nil, fmt.Errorf("observe %s in the finalized chain: %w", tx, ethrpc.ErrNotYetFinalized)
	}
	return &chain.ObservationResult{TxHash: tx, IsFinalized: true, Status: 1}, nil
}

// decidingChain is the chain Phase 7's decision reads.
type decidingChain struct {
	finTime   int64
	receipt   error // nil: the providers hold a receipt
	readFails bool
}

func (d decidingChain) Finalized(context.Context) (*types.Header, error) {
	if d.readFails {
		return nil, errors.New("provider down")
	}
	return &types.Header{Number: big.NewInt(900), Time: uint64(d.finTime), Difficulty: big.NewInt(0)}, nil
}
func (d decidingChain) SettlementReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	if d.receipt != nil {
		return nil, d.receipt
	}
	return &types.Receipt{}, nil
}

const phase7Tx = "0x00000000000000000000000000000000000000000000000000000000000057e1"

// phase7Fixture is an orchestrator holding the kept tree of a one-member anchor on odChain, and the cycle observing that
// member's settlement.
func phase7Fixture(t *testing.T, d decidingChain) (*UnifiedOrchestrator, *activeCycle, *OutcomeTreeMember) {
	t.Helper()
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	old := phase7RetriggerInForce
	phase7RetriggerInForce = time.Millisecond
	t.Cleanup(func() { phase7RetriggerInForce = old })
	m := outcomeTestMember(t, odChain, "p7", f77NativeLeg(odChain, "7"))
	tree, byOp := outcomeTestTree(t, odChain, m)
	kept, err := NewOutcomeTree(tree, byOp, OutcomeTreeSigned)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewOutcomeTreeStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Retain(kept); err != nil {
		t.Fatal(err)
	}
	o := nsOrchestrator(t, nil, &fakeNSChain{})
	o.config.OutcomeTrees = store
	o.config.ObservationTimeout = time.Second
	o.phase7DecisionChain = func(int64) phase7DecisionChain { return d }
	cycle := &activeCycle{CycleID: "c-p7", Request: &UnifiedProofCycleRequest{IntentID: "p7", CycleID: "c-p7", TargetChain: odChainStr,
		BundleID: kept.BundleID, TxHashes: []string{phase7Tx}, AccumulateAccountURL: "acc://p7.acme/data", AccumulateTxHash: "h",
		ProofClass: "on_demand", CommitmentData: map[string]interface{}{"memberChains": []int64{odChain}, "memberLegs": 1}}}
	return o, cycle, &kept.Members[0]
}

// The chain has not decided: Phase 7 observes again, however many times this machine's clock bounds an attempt, until
// the transaction is finalized - and records nothing on the way.
func TestPhase7KeepsObservingUntilTheChainDecides(t *testing.T) {
	o, cycle, m := phase7Fixture(t, decidingChain{})
	// The chain is finalized only to just before the member's deadline.
	o.phase7DecisionChain = func(int64) phase7DecisionChain { return decidingChain{finTime: m.Deadline - 1} }
	c := &observingChain{fails: 3}
	obs, err := o.observeUntilTheChainDecides(context.Background(), cycle, c, 0, phase7Tx)
	if err != nil || obs == nil || c.attempts != 4 {
		t.Fatalf("THE regression (RB7 D7): Phase 7 ended on a local timeout: (%v, %v) after %d attempt(s)", obs, err, c.attempts)
	}
	if n := len(o.config.NonSettlements.All()); n != 0 {
		t.Fatalf("an undecided observation queued %d non-settlement(s)", n)
	}
}

// (b): the chain is past the member's deadline and the margin, and no agreeing provider holds the transaction - it can
// never execute. The member goes to its non-settlement, from the kept tree; this cycle records nothing.
func TestPhase7HandsANeverExecutedSettlementToItsNonSettlement(t *testing.T) {
	o, cycle, m := phase7Fixture(t, decidingChain{})
	horizon := m.Deadline + int64(nonSettlementFinality/time.Second)
	o.phase7DecisionChain = func(int64) phase7DecisionChain {
		return decidingChain{finTime: horizon + 1, receipt: ethereum.NotFound}
	}
	_, err := o.observeUntilTheChainDecides(context.Background(), cycle, &observingChain{fails: -1}, 0, phase7Tx)
	if !errors.Is(err, errSettlementHandedToNonSettlement) || !phase7RecordsNothing(err) {
		t.Fatalf("the chain's decision was not taken: %v", err)
	}
	recs := o.config.NonSettlements.All()
	if len(recs) != 1 || recs[0].Facts.Leaf != m.Leaf || recs[0].Facts.Account != m.Account || recs[0].Facts.Deadline.Unix() != m.Deadline ||
		!strings.Contains(recs[0].Cause, phase7Tx) || recs[0].AccountURL != "acc://p7.acme/data" || recs[0].MemberLegs != 1 {
		t.Fatalf("queued %+v", recs)
	}
	// Exactly at the margin the chain has not decided.
	o2, cycle2, _ := phase7Fixture(t, decidingChain{})
	o2.phase7DecisionChain = func(int64) phase7DecisionChain { return decidingChain{finTime: horizon, receipt: ethereum.NotFound} }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := o2.observeUntilTheChainDecides(ctx, cycle2, &observingChain{fails: -1}, 0, phase7Tx); !errors.Is(err, errObservationUndecided) ||
		len(o2.config.NonSettlements.All()) != 0 {
		t.Fatalf("decided at the margin, not past it: %v", err)
	}
}

// Past the deadline, but the providers hold a receipt (or cannot be read): not decided - the observation goes on.
func TestPhase7DoesNotDecideWhileAReceiptExistsOrTheChainIsUnreadable(t *testing.T) {
	for name, d := range map[string]func(horizon int64) decidingChain{
		"a receipt exists": func(h int64) decidingChain { return decidingChain{finTime: h + 60} },
		"receipts unreadable": func(h int64) decidingChain {
			return decidingChain{finTime: h + 60, receipt: errors.New("too few providers")}
		},
		"finalized unreadable": func(h int64) decidingChain { return decidingChain{readFails: true} },
	} {
		t.Run(name, func(t *testing.T) {
			o, cycle, m := phase7Fixture(t, decidingChain{})
			dc := d(m.Deadline + int64(nonSettlementFinality/time.Second))
			o.phase7DecisionChain = func(int64) phase7DecisionChain { return dc }
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := o.observeUntilTheChainDecides(ctx, cycle, &observingChain{fails: -1}, 0, phase7Tx)
			if !errors.Is(err, errObservationUndecided) || len(o.config.NonSettlements.All()) != 0 {
				t.Fatalf("decided: %v", err)
			}
		})
	}
}

// A cycle stopped before the chain decided records nothing; a final receipt whose proof could not be built is still
// the existing settled_unproven path.
func TestAStoppedPhase7RecordsNothing(t *testing.T) {
	o, cycle, _ := phase7Fixture(t, decidingChain{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := o.observeUntilTheChainDecides(ctx, cycle, &observingChain{fails: -1}, 0, phase7Tx)
	if !errors.Is(err, errObservationUndecided) || !phase7RecordsNothing(err) {
		t.Fatalf("stopped: %v", err)
	}
	if phase7RecordsNothing(fmt.Errorf("x: %w", &chain.UnprovenSettlementError{})) || phase7RecordsNothing(errors.New("gate refused")) {
		t.Fatal("a chain verdict was classified as recording nothing")
	}
	// recordPhaseFailure returns before any member outcome for those two.
	body := funcBody(t, readSource(t, "unified_orchestrator.go"), "func (o *UnifiedOrchestrator) recordPhaseFailure(")
	if skip, rec := strings.Index(body, "phase7RecordsNothing(err)"), strings.Index(body, "o.recordMemberOutcome("); skip < 0 || rec < 0 || skip > rec {
		t.Fatal("recordPhaseFailure does not return before recording for an observation the chain has not decided")
	}
	// The cycle's observation has no wall-clock deadline: the adapter starts it with none.
	adapter := funcBody(t, readSource(t, "unified_adapter.go"), "func (a *UnifiedOrchestratorAdapter) StartProofCycleWithAccumulateRef(")
	if strings.Contains(adapter, "context.WithTimeout(context.Background()") {
		t.Fatal("the proof cycle is started under a wall-clock deadline")
	}
}

// A peer that no longer holds the member in its queues (its settlement was sent) verifies the non-settlement from the
// tree it kept and signed.
func TestAPeerVerifiesANonSettlementFromItsKeptTree(t *testing.T) {
	o, _, m := phase7Fixture(t, decidingChain{})
	facts, err := keptMemberFacts("p7", odChain, m)
	if err != nil {
		t.Fatal(err)
	}
	c := nsChainPast(facts.Deadline)
	o.config.NonSettlementChain = c
	claim, obs, err := observeNonSettlementAt(context.Background(), c, facts, "never reached the finalized chain", 0)
	if err != nil {
		t.Fatal(err)
	}
	msg := &attestation.AttestationMessage{IntentID: "p7", ResultHash: obs.ResultHash, TargetChain: odChainStr, ChainID: odChainStr,
		Timestamp: time.Now().Unix(), NonSettlement: claim}
	resp, err := o.HandlePeerAttestationRequest(context.Background(), &PeerAttestationRequest{CycleID: "c", Message: msg,
		Scheme: attestation.AttestationSchemeBLS12381, RequestingID: "validator-1"})
	if err != nil || !resp.Success {
		t.Fatalf("a peer holding the kept tree did not verify the claim: %+v %v", resp, err)
	}
	// Another intent's claim on that operation is refused.
	msg.IntentID = "someone-else"
	if resp, _ := o.HandlePeerAttestationRequest(context.Background(), &PeerAttestationRequest{CycleID: "c", Message: msg,
		Scheme: attestation.AttestationSchemeBLS12381, RequestingID: "validator-1"}); resp.Success {
		t.Fatal("a claim naming another intent was signed")
	}
}
