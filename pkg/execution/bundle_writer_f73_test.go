// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB3-F73: the stored evidence of a proof cycle is the product. The bundle writer used to print
// "Warning:" and carry on past every row the database refused, and to mark levels verified by
// construction.

func f73Cycle(t *testing.T, g0, g1 json.RawMessage) (*activeCycle, string) {
	t.Helper()
	intentID := fmt.Sprintf("f73-%d", time.Now().UnixNano())
	accTx := fmt.Sprintf("%064x", time.Now().UnixNano())
	obs := &chain.ObservationResult{TxHash: "0x" + accTx, IsFinalized: true, Status: 1, BlockNumber: 100, Confirmations: 12, BlockTimestamp: time.Now()}
	c := memberCycle(intentID, "84532", []int64{84532}, 1, obs)
	c.Request.ProofClass = "on_demand"
	c.Request.AccumulateTxHash = accTx
	c.Request.AccumulateAccountURL = "acc://harbor.acme/data"
	c.Request.GovernanceRoot = [32]byte{1}
	c.Request.OperationCommitment = [32]byte{2}
	if g0 != nil {
		c.Request.CommitmentData[consensus.G0ProofCommitmentKey] = string(g0)
	}
	if g1 != nil {
		c.Request.CommitmentData[consensus.G1ProofCommitmentKey] = string(g1)
	}
	c.Result.Attestations = []*attestation.Attestation{{}}
	c.Result.ThresholdMet = true // the VALIDATOR quorum - not any governance level
	return c, intentID
}

func f73Orchestrator(db *sql.DB) *UnifiedOrchestrator {
	return &UnifiedOrchestrator{
		config: &UnifiedOrchestratorConfig{Repos: database.NewRepositories(database.NewClientFromDB(db)), ValidatorID: "validator-test",
			ProofGenerator: fixtureFileGenerator{name: "proof_bvn1.json"}},
		resultChains: map[string]*ResultHashChain{},
	}
}

func TestBundleWriterFailsWhenAnEvidenceRowIsRefused(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE OR REPLACE FUNCTION f73_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'f73: row refused'; END $$;
		CREATE TRIGGER f73_refuse BEFORE INSERT ON governance_proof_levels FOR EACH ROW EXECUTE FUNCTION f73_refuse();`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DROP TRIGGER IF EXISTS f73_refuse ON governance_proof_levels; DROP FUNCTION IF EXISTS f73_refuse();`)
	})
	c, intentID := f73Cycle(t, nil, provenG1("acc://harbor.acme/book/1", 1, []string{"aa"}, 1, true))
	t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })

	if err := f73Orchestrator(db).generateAndPersistBundle(ctx, c); err == nil {
		t.Fatal("the database refused the governance level rows, and the bundle writer reported success")
	}
}

func TestGovernanceLevelsSayOnlyWhatTheirProofsEstablish(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	g0, _ := json.Marshal(certenproof.G0Result{G0ProofComplete: true})

	for name, tc := range map[string]struct {
		g0, g1                   json.RawMessage
		wantG0, wantG1, wantIncl bool
	}{
		// The validator quorum was met and no governance proof established anything.
		"no governance proof": {nil, nil, false, false, false},
		// An incomplete G1 (the replay could not finish) is not a verified G1, whatever the quorum.
		"incomplete G1":      {g0, provenG1("acc://harbor.acme/book/1", 1, []string{"aa"}, 1, false), true, false, false},
		"complete G0 and G1": {g0, provenG1("acc://harbor.acme/book/1", 1, []string{"aa"}, 1, true), true, true, false},
	} {
		c, intentID := f73Cycle(t, tc.g0, tc.g1)
		t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })
		if err := f73Orchestrator(db).generateAndPersistBundle(ctx, c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rows, err := db.Query(`SELECT g.gov_level, g.verified, g.level_json FROM governance_proof_levels g
			JOIN proof_artifacts p ON p.proof_id = g.proof_id WHERE p.intent_id = $1`, intentID)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		var incl, outcomeBound interface{}
		for rows.Next() {
			var level string
			var verified sql.NullBool
			var raw []byte
			if err := rows.Scan(&level, &verified, &raw); err != nil {
				t.Fatal(err)
			}
			got[level] = verified.Valid && verified.Bool
			var flags map[string]interface{}
			_ = json.Unmarshal(raw, &flags)
			if level == "G0" {
				incl = flags["inclusion_verified"]
			}
			if level == "G2" {
				outcomeBound = flags["outcome_bound"]
			}
		}
		rows.Close()
		if got["G0"] != tc.wantG0 || got["G1"] != tc.wantG1 || got["G2"] {
			t.Errorf("%s: verified G0=%v G1=%v G2=%v; the proofs establish G0=%v G1=%v G2=false", name, got["G0"], got["G1"], got["G2"], tc.wantG0, tc.wantG1)
		}
		if incl != tc.wantIncl {
			t.Errorf("%s: inclusion_verified %v with no settlement inclusion proven", name, incl)
		}
		if outcomeBound != false {
			t.Errorf("%s: outcome_bound %v with no G2 proof", name, outcomeBound)
		}
	}
}

// fixtureFileGenerator serves a committed chained-proof fixture as every transaction's proof: the bundle
// writer refuses to store a bundle without one (RB3-F93).
type fixtureFileGenerator struct{ name string }

func (g fixtureFileGenerator) GenerateChainedProofForTx(context.Context, string, string, string) (*ChainedProofResult, error) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "accumulate-lite-client-2", "liteclient", "proof",
		"working-proof_do_not_edit", "testdata", g.name))
	if err != nil {
		return nil, err
	}
	cp := new(chained_proof.ChainedProof)
	if err := json.Unmarshal(raw, cp); err != nil {
		return nil, err
	}
	return &ChainedProofResult{CompleteProof: cp}, nil
}
