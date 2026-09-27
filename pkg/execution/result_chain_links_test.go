// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F80: a non-settlement's result takes the next place in its chain's result hash chain, and its
// link is persisted, so the chain continues past it after a restart.
func TestANonSettlementsChainLinkIsPersistedAndContinued(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repos := database.NewRepositories(database.NewClientFromDB(db))
	validator := fmt.Sprintf("f80-validator-%d", time.Now().UnixNano())
	t.Cleanup(func() { db.Exec(`DELETE FROM result_hash_chain_links WHERE observer_validator_id=$1`, validator) })

	_, key, _ := ed25519.GenerateKey(nil)
	o := &UnifiedOrchestrator{
		config: &UnifiedOrchestratorConfig{ValidatorID: validator, UnifiedRepo: repos.Unified,
			ResultsPrincipal: "acc://results.acme/data", Ed25519Key: key, AccumulateClient: &recordingSubmitter{}},
		resultChains: map[string]*ResultHashChain{},
		txBuilder:    NewSyntheticTxBuilder("acc://results.acme/data", validator, key),
	}

	own := nsMember()
	f, _ := memberFacts(own)
	claim, obs, err := observeNonSettlement(ctx, nsChainPast(f.Deadline), f, "its batch quorum was never reached")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		rec := &NonSettlementRecord{Facts: f, Cause: claim.Cause, MemberChains: []int64{odChain}, MemberLegs: 1}
		cycle := nonSettlementCycle(rec, claim)
		cycle.CycleID = fmt.Sprintf("%s-%d", cycle.CycleID, i)
		cycle.Result.ObservationResults = []*chain.ObservationResult{obs}
		cycle.Result.ThresholdMet = true
		cycle.Result.AggregatedAttestation = &attestation.AggregatedAttestation{
			ThresholdMet: true, Verified: true, AchievedWeight: 700, TotalWeight: 700, ParticipantCount: 7}
		if err := o.executePhase9(ctx, cycle); err != nil {
			t.Fatalf("non-settlement %d: phase 9: %v", i, err)
		}
	}

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM result_hash_chain_links WHERE observer_validator_id=$1`, validator).Scan(&n); err != nil || n != 2 {
		t.Fatalf("persisted links: %d (%v); want 2", n, err)
	}
	if checked, err := repos.Unified.VerifyChainExecutionHashChain(ctx, validator, odChainStr); err != nil || checked != 2 {
		t.Fatalf("the persisted chain: %d links, %v", checked, err)
	}

	// A restart continues from the last non-settlement, not from sequence 0.
	restarted := map[string]*ResultHashChain{}
	if _, err := seedResultHashChains(ctx, repos.Unified, validator, restarted); err != nil {
		t.Fatal(err)
	}
	c := restarted[odChainStr]
	if c == nil || c.LatestSequence != 2 || c.LatestHash != o.resultChains[odChainStr].LatestHash {
		t.Fatalf("seeded chain %+v; want it to continue at sequence 2 from the last link", c)
	}
}
