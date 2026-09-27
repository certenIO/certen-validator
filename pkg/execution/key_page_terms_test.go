// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB3-F69: the key page terms a governance level row states come from the proven G1 result.

func provenG1(page string, threshold uint64, keys []string, valid int, complete bool) json.RawMessage {
	g1 := certenproof.G1Result{UniqueValidKeys: valid, G1ProofComplete: complete, ThresholdSatisfied: complete}
	g1.AuthoritySnapshot.Page = page
	g1.AuthoritySnapshot.StateExec = certenproof.KeyPageState{Version: 3, Keys: keys, Threshold: threshold}
	b, _ := json.Marshal(g1)
	return b
}

func TestKeyPageTermsComeOnlyFromACompleteCoherentG1(t *testing.T) {
	terms := keyPageTermsFromG1(provenG1("acc://harbor.acme/book/1", 1, []string{"aa", "bb"}, 1, true))
	if terms.Threshold == nil || *terms.Threshold != 1 || terms.Keys == nil || *terms.Keys != 2 ||
		terms.Signatures == nil || *terms.Signatures != 1 || terms.Authority == nil || *terms.Authority != "acc://harbor.acme/book" {
		t.Fatalf("1-of-2 page: got %+v", terms)
	}
	for name, raw := range map[string]json.RawMessage{
		"no G1":             nil,
		"not JSON":          json.RawMessage("{"),
		"incomplete proof":  provenG1("acc://harbor.acme/book/1", 1, []string{"aa"}, 1, false),
		"page with no keys": provenG1("acc://harbor.acme/book/1", 1, nil, 1, true),
		"threshold of zero": provenG1("acc://harbor.acme/book/1", 0, []string{"aa"}, 1, true),
		"threshold > keys":  provenG1("acc://harbor.acme/book/1", 3, []string{"aa", "bb"}, 1, true),
	} {
		if got := keyPageTermsFromG1(raw); got.Threshold != nil || got.Keys != nil || got.Signatures != nil || got.Authority != nil {
			t.Fatalf("%s established terms: %+v", name, got)
		}
	}
	if got := keyPageTermsFromG1(provenG1("not-a-url", 1, []string{"aa"}, 1, true)); got.Authority != nil || got.Threshold == nil {
		t.Fatalf("a page URL that is not <book>/<index> names no book, and the proven M-of-N still stands: %+v", got)
	}
	for page, want := range map[string]string{"acc://a.acme/book/1": "acc://a.acme/book", "acc://a.acme/book/x": "", "acc://a.acme": "", "acc:///1": ""} {
		if got, _ := keyBookOf(page); got != want {
			t.Fatalf("keyBookOf(%q) = %q, want %q", page, got, want)
		}
	}
}

// The bundle writer, against a real schema: a proof cycle for an intent authorised by one of a 1-of-2
// key page's keys, attested by 7 validators. Every G-level row must say "1 of 2, 1 signature" - not
// the 1-of-1 guess, and not the 7 validator attestations as the page's signature count.
func TestGovernanceLevelRowsStateTheProvenKeyPageTerms(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := &UnifiedOrchestrator{
		config:       &UnifiedOrchestratorConfig{Repos: database.NewRepositories(database.NewClientFromDB(db)), ValidatorID: "validator-test"},
		resultChains: map[string]*ResultHashChain{},
	}
	intentID := fmt.Sprintf("f69-keypage-%d", time.Now().UnixNano())
	accTx := fmt.Sprintf("%064x", time.Now().UnixNano())
	t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })

	atts := make([]*attestation.Attestation, 7)
	for i := range atts {
		atts[i] = &attestation.Attestation{}
	}
	obs := &chain.ObservationResult{TxHash: "0x" + accTx, IsFinalized: true, Status: 1, BlockNumber: 100, Confirmations: 12, BlockTimestamp: time.Now()}
	c := memberCycle(intentID, "84532", []int64{84532}, 1, obs)
	c.Request.ProofClass = "on_demand"
	c.Request.AccumulateTxHash = accTx
	c.Request.AccumulateAccountURL = "acc://harbor.acme/data"
	c.Request.GovernanceRoot = [32]byte{1}
	c.Request.OperationCommitment = [32]byte{2}
	c.Request.CommitmentData[consensus.G1ProofCommitmentKey] = string(provenG1("acc://harbor.acme/book/1", 1, []string{"aa", "bb"}, 1, true))
	c.Result.Attestations = atts
	c.Result.ThresholdMet = true

	_ = o.generateAndPersistBundle(ctx, c)

	rows, err := db.Query(`SELECT g.gov_level, g.threshold_m, g.threshold_n, g.signature_count, g.authority_url
		FROM governance_proof_levels g JOIN proof_artifacts p ON p.proof_id = g.proof_id WHERE p.intent_id = $1 ORDER BY 1`, intentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var level string
		var m, keys, sigs sql.NullInt64
		var auth sql.NullString
		if err := rows.Scan(&level, &m, &keys, &sigs, &auth); err != nil {
			t.Fatal(err)
		}
		n++
		if m.Int64 != 1 || keys.Int64 != 2 || sigs.Int64 != 1 || auth.String != "acc://harbor.acme/book" {
			t.Errorf("%s states %d of %d with %d signature(s), authority %q; the proven page is 1 of 2 with 1 signature, book acc://harbor.acme/book",
				level, m.Int64, keys.Int64, sigs.Int64, auth.String)
		}
	}
	if n != 3 {
		t.Fatalf("%d governance level rows written, want G0, G1 and G2", n)
	}
}

func cleanupProofArtifacts(db *sql.DB, intentID string) {
	for _, table := range []string{"governance_proof_levels", "anchor_references", "chained_proof_layers", "chain_execution_results",
		"external_chain_results", "unified_attestations", "aggregated_attestations", "proof_requests", "custody_chain_events", "proof_bundles"} {
		db.Exec(`DELETE FROM `+table+` WHERE proof_id IN (SELECT proof_id FROM proof_artifacts WHERE intent_id = $1)`, intentID)
	}
	db.Exec(`DELETE FROM proof_artifacts WHERE intent_id = $1`, intentID)
}
