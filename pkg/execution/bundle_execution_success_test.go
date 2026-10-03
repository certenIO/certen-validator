// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/certen/independant-validator/pkg/database"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB5-F18 (survey §5 item 8): the proof bundle's G1 execution_success. It was the write-back's success, read when the
// bundle is built - before Phase 9 runs - so every bundle stated false, and a write-back flag is not what G1's
// execution_success means anyway: G1 states that the governed Accumulate transaction executed. It is now the proven
// G1 result's own verdict.

func g1StatingExecution(executed bool) json.RawMessage {
	g1 := certenproof.G1Result{G1ProofComplete: true, ThresholdSatisfied: true, UniqueValidKeys: 1, ExecutionSuccess: executed}
	g1.G0ProofComplete = executed
	g1.AuthoritySnapshot.Page = "acc://harbor.acme/book/1"
	g1.AuthoritySnapshot.StateExec = certenproof.KeyPageState{Version: 3, Keys: []string{"aa"}, Threshold: 1}
	b, _ := json.Marshal(g1)
	return b
}

func TestTheBundleStatesTheGovernedExecutionTheG1ProofEstablishes(t *testing.T) {
	db := s1OpenDB(t)
	repos := database.NewRepositories(database.NewClientFromDB(db))
	g0, _ := json.Marshal(certenproof.G0Result{G0ProofComplete: true})

	for name, tc := range map[string]struct {
		g1        json.RawMessage
		writeBack bool
		want      bool
	}{
		"a G1 proving the governed transaction executed":   {g1StatingExecution(true), false, true},
		"a G1 that does not establish execution":           {g1StatingExecution(false), false, false},
		"no G1 at all, whatever the write-back says":       {nil, true, false},
		"a G1 that does not establish it, write-back done": {g1StatingExecution(false), true, false},
	} {
		c, intentID := f73Cycle(t, g0, tc.g1)
		t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })
		c.Result.WriteBackSuccess = tc.writeBack
		if err := f73Orchestrator(db).generateAndPersistBundle(context.Background(), c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		gov := storedBundle(t, db, repos, intentID).ProofComponents.GovernanceProof
		if gov == nil || gov.G1 == nil {
			t.Fatalf("%s: the bundle has no G1 component", name)
		}
		if gov.G1.ExecutionSuccess != tc.want {
			t.Errorf("%s: the bundle states execution_success=%v; the G1 proof establishes %v", name, gov.G1.ExecutionSuccess, tc.want)
		}
	}
}

// RB5-F18, the same defect in the records stored beside the bundle: the artifact and its G2 level stated the
// write-back's state as "" and its success as false, read before Phase 9 attempts it. They now state it is pending.
func TestRecordsStoredBeforePhase9StateTheWriteBackIsPending(t *testing.T) {
	db := s1OpenDB(t)
	g0, _ := json.Marshal(certenproof.G0Result{G0ProofComplete: true})
	c, intentID := f73Cycle(t, g0, g1StatingExecution(true))
	t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })
	if err := f73Orchestrator(db).generateAndPersistBundle(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	var artifactRaw, g2Raw []byte
	if err := db.QueryRow(`SELECT artifact_json FROM proof_artifacts WHERE intent_id=$1`, intentID).Scan(&artifactRaw); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT g.level_json FROM governance_proof_levels g JOIN proof_artifacts p ON p.proof_id = g.proof_id
		WHERE p.intent_id=$1 AND g.gov_level='G2'`, intentID).Scan(&g2Raw); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"artifact": artifactRaw, "G2 level": g2Raw} {
		var flags map[string]interface{}
		if err := json.Unmarshal(raw, &flags); err != nil {
			t.Fatal(err)
		}
		if flags["write_back_state"] != WriteBackPending || flags["write_back_success"] != false {
			t.Errorf("the %s, stored before Phase 9, states write_back_state=%q write_back_success=%v", name, flags["write_back_state"], flags["write_back_success"])
		}
	}
}
