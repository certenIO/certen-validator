// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F81: the written-back record states what was observed, not stand-ins for it.

func TestHashesAreTheChainsOwnOrRefused(t *testing.T) {
	full := "0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7"
	if h, err := hash32(full, false); err != nil || h != common.HexToHash(full) {
		t.Fatalf("a real hash: %v %v", h, err)
	}
	if h, err := hash32("", true); err != nil || h != (common.Hash{}) {
		t.Fatalf("a non-settlement's absent transaction is the zero hash: %v %v", h, err)
	}
	for _, bad := range []string{"", "0x", "0x1234", "not-hex", "8Zx1sfNEARbase58"} {
		if _, err := hash32(bad, false); err == nil {
			t.Fatalf("%q was accepted as a 32-byte hash", bad)
		}
	}
}

func TestTheAttestationMessageHashIsWhatStrategiesSign(t *testing.T) {
	msg := &attestation.AttestationMessage{IntentID: "i", ResultHash: [32]byte{1}, AnchorTxHash: "0xab", ChainID: "84532"}
	h, err := msg.Hash()
	if err != nil || h == ([32]byte{}) {
		t.Fatalf("hash %x %v", h, err)
	}
	b, _ := json.Marshal(msg)
	if h != sha256.Sum256(b) {
		t.Fatal("not SHA-256 of the message's JSON")
	}
	bls, _ := attestation.NewBLSStrategyWithNewKey("v", 1)
	if got, _ := bls.ComputeMessageHash(msg); got != h {
		t.Fatal("the BLS strategy signs another hash")
	}
}

func f81Orchestrator(repo *database.UnifiedRepository, validator string) *UnifiedOrchestrator {
	_, key, _ := ed25519.GenerateKey(nil)
	return &UnifiedOrchestrator{
		config: &UnifiedOrchestratorConfig{ValidatorID: validator, UnifiedRepo: repo,
			ResultsPrincipal: "acc://results.acme/data", Ed25519Key: key, AccumulateClient: &recordingSubmitter{}},
		resultChains: map[string]*ResultHashChain{},
		txBuilder:    NewSyntheticTxBuilder("acc://results.acme/data", validator, key),
	}
}

func f81NonSettlementCycle(t *testing.T) *activeCycle {
	t.Helper()
	own := nsMember()
	f, _ := memberFacts(own)
	claim, obs, err := observeNonSettlement(context.Background(), nsChainPast(f.Deadline), f, "its batch quorum was never reached")
	if err != nil {
		t.Fatal(err)
	}
	rec := &NonSettlementRecord{Facts: f, Cause: claim.Cause, MemberChains: []int64{odChain}, MemberLegs: 1}
	c := nonSettlementCycle(rec, claim)
	c.CycleID = fmt.Sprintf("%s-%d", c.CycleID, time.Now().UnixNano())
	c.Result.ObservationResults = []*chain.ObservationResult{obs}
	c.Result.ThresholdMet = true
	c.Result.AggregatedAttestation = &attestation.AggregatedAttestation{
		ThresholdMet: true, Verified: true, AchievedWeight: 500, TotalWeight: 700, ParticipantCount: 5}
	return c
}

func TestTheWrittenBackRecordStatesWhatWasObserved(t *testing.T) {
	o := f81Orchestrator(nil, "v")
	c := f81NonSettlementCycle(t)
	bundle, _, err := o.buildAttestationBundleFromCycle(c)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Result.TxHash != (common.Hash{}) {
		t.Fatalf("a non-settlement's transaction hash is %s; it has none (it used to be SHA-256 of the empty string)", bundle.Result.TxHash.Hex())
	}
	agg := bundle.Aggregated
	if agg.ValidatorCount != 5 || agg.SignedVotingPower.Int64() != 500 || agg.TotalVotingPower.Int64() != 700 {
		t.Fatalf("aggregate count %d signed %v total %v; want 5 validators, 500 of 700 voting power", agg.ValidatorCount, agg.SignedVotingPower, agg.TotalVotingPower)
	}
	c.Result.AggregatedAttestation.AchievedWeight = 0
	bundle, _, _ = o.buildAttestationBundleFromCycle(c)
	if bundle.Aggregated.SignedVotingPower.Sign() != 0 {
		t.Fatalf("no signed power is stated as %v", bundle.Aggregated.SignedVotingPower)
	}
}

// RB3-F82: a link that was not stored gives its sequence number back.
func TestAResultWhoseLinkIsNotStoredDoesNotConsumeASequenceNumber(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repos := database.NewRepositories(database.NewClientFromDB(db))
	validator := fmt.Sprintf("f82-validator-%d", time.Now().UnixNano())
	t.Cleanup(func() { db.Exec(`DELETE FROM result_hash_chain_links WHERE observer_validator_id=$1`, validator) })
	o := f81Orchestrator(repos.Unified, validator)

	if _, err := db.Exec(`CREATE OR REPLACE FUNCTION f82_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'f82: refused'; END $$;
		CREATE TRIGGER f82_refuse BEFORE INSERT ON result_hash_chain_links FOR EACH ROW EXECUTE FUNCTION f82_refuse();`); err != nil {
		t.Fatal(err)
	}
	dropped := false
	drop := func() {
		if !dropped {
			db.Exec(`DROP TRIGGER IF EXISTS f82_refuse ON result_hash_chain_links; DROP FUNCTION IF EXISTS f82_refuse();`)
			dropped = true
		}
	}
	t.Cleanup(drop)

	if err := o.executePhase9(ctx, f81NonSettlementCycle(t)); err == nil {
		t.Fatal("phase 9 succeeded with its link refused")
	}
	drop()
	if err := o.executePhase9(ctx, f81NonSettlementCycle(t)); err != nil {
		t.Fatal(err)
	}
	var seq int64
	if err := db.QueryRow(`SELECT sequence_number FROM result_hash_chain_links WHERE observer_validator_id=$1`, validator).Scan(&seq); err != nil || seq != 0 {
		t.Fatalf("the first stored link has sequence %d (%v): the refused link consumed a sequence number and left a gap", seq, err)
	}
	if n, err := repos.Unified.VerifyChainExecutionHashChain(ctx, validator, odChainStr); err != nil || n != 1 {
		t.Fatalf("the chain after a refused link then a stored one: %d links, %v", n, err)
	}
}
