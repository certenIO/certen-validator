// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB8-F-F1: StartProofCycle recorded the member's outcome for every start failure except one. When the intent could not
// be moved to in_process - no lifecycle row, and none creatable from the request - it returned the error and recorded
// nothing, so the member had no outcome, `repair member-proof-cycle` refused it (precondition 2: no recorded outcome),
// and the intent stayed where it was with nothing to say why (the four D4 members of 2026-10-18).

// startChain is a chain strategy that gets a cycle as far as the in_process mark: it names its platform and chain, and
// nothing else (a call past that is the test's own failure).
type startChain struct{ chain.ChainExecutionStrategy }

func (startChain) Platform() chain.ChainPlatform { return chain.ChainPlatformEVM }
func (startChain) ChainID() string               { return "84532" }

// startableOrchestrator is an orchestrator on the real lifecycle repository and a registry that resolves chain 84532.
func startableOrchestrator(t *testing.T) (*UnifiedOrchestrator, func(intentID string) (settlement, proofCycle, reason string)) {
	t.Helper()
	db := s1OpenDB(t)
	o := s1Orchestrator(t, db)
	o.activeCycles = make(map[string]*activeCycle)
	reg := strategy.NewRegistry()
	bls, err := attestation.NewBLSStrategyWithNewKey("validator-test", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterAttestationStrategy(bls); err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterChainStrategy("84532", &chain.ChainConfig{Platform: chain.ChainPlatformEVM, ChainID: "84532"}, startChain{}); err != nil {
		t.Fatal(err)
	}
	o.config.Registry = reg
	outcome := func(intentID string) (settlement, proofCycle, reason string) {
		t.Helper()
		if err := db.QueryRow(`SELECT settlement, proof_cycle, COALESCE(reason, '') FROM intent_member_outcomes WHERE intent_id = $1`,
			intentID).Scan(&settlement, &proofCycle, &reason); err != nil {
			t.Fatalf("no member outcome was recorded for %s: %v", intentID, err)
		}
		return
	}
	return o, outcome
}

func TestAProofCycleThatCannotMarkItsIntentInProcessIsRecordedAsTheMembersOutcome(t *testing.T) {
	o, outcome := startableOrchestrator(t)
	ctx := context.Background()
	db := s1OpenDB(t)

	// The intent has no lifecycle row and the request names no Accumulate transaction, so the row cannot be created from it
	// either (RB8-G): the move to in_process fails with the not-found it started from.
	id := fmt.Sprintf("rb8f-f1-norow-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id)
		db.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, id)
	})
	req := memberCycle(id, "84532", []int64{84532}, 1, nil).Request
	req.ProofClass = string(LaneOnDemand)
	req.TxHashes = []string{"0x" + strings.Repeat("ab", 32)}
	req.AccumulateTxHash = ""

	res, err := o.StartProofCycle(ctx, req)
	if err == nil {
		t.Fatal("a cycle whose intent cannot be marked in_process started")
	}
	if !strings.Contains(err.Error(), "in_process") {
		t.Fatalf("the refusal does not say what failed: %v", err)
	}
	settlement, proofCycle, reason := outcome(id)
	if settlement != string(database.MemberSettlementUnobserved) || proofCycle != string(database.MemberProofCycleFailed) {
		t.Fatalf("recorded %s / %s; want unobserved / failed", settlement, proofCycle)
	}
	if !strings.Contains(reason, "not started") || !strings.Contains(reason, "in_process") {
		t.Fatalf("the recorded reason %q does not say the cycle did not start, nor why", reason)
	}

	if res == nil || res.Error == "" {
		t.Fatalf("the start failure did not come back on the result like every other start failure (%+v)", res)
	}

	// A refused cycle leaves nothing active behind it.
	o.mu.RLock()
	active := len(o.activeCycles)
	o.mu.RUnlock()
	if active != 0 {
		t.Fatalf("%d active cycle(s) left behind by a cycle that did not start", active)
	}
}
