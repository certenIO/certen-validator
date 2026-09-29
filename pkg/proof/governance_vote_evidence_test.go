// Copyright 2026 Certen Protocol

package proof

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RB4-F66: the vote record is reached, offline, from the chain-bound evidence the CLI emitted beside it - live
// Kermit output for the RB4 Phase C intent and for a delegated decision (case C).

func voteEvidenceFixture(t *testing.T, name string) (*G0Result, *AuthorizationRecord, json.RawMessage) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var g0 G0Result
	if err := json.Unmarshal(raw, &g0); err != nil {
		t.Fatal(err)
	}
	rec, err := AuthorizationRecordFromRaw(raw)
	if err != nil || rec == nil {
		t.Fatalf("vote record: %v", err)
	}
	return &g0, rec, raw
}

var voteEvidenceFixtures = []string{"vote_evidence_g1_phasec_98e40472.json", "vote_evidence_g1_delegated_case_c.json"}

func TestVoteEvidenceReachesTheRecord(t *testing.T) {
	for _, name := range voteEvidenceFixtures {
		g0, rec, raw := voteEvidenceFixture(t, name)
		ev, err := VoteEvidenceFromRaw(raw)
		if err != nil || ev == nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := VerifyVoteEvidence(context.Background(), g0, ev, rec); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestVoteEvidenceIsBoundToTheExecutedTransactionAndItsRecord(t *testing.T) {
	g0, rec, raw := voteEvidenceFixture(t, "vote_evidence_g1_phasec_98e40472.json")
	ev, _ := VoteEvidenceFromRaw(raw)

	other := *g0
	other.TxHash = "00" + g0.TxHash[2:]
	if err := VerifyVoteEvidence(context.Background(), &other, ev, rec); err == nil {
		t.Fatal("evidence about another transaction was accepted")
	}

	_, caseC, rawC := voteEvidenceFixture(t, "vote_evidence_g1_delegated_case_c.json")
	if err := VerifyVoteEvidence(context.Background(), g0, ev, caseC); err == nil {
		t.Fatal("evidence reaching one vote was accepted for another record")
	}
	evC, _ := VoteEvidenceFromRaw(rawC)
	if err := VerifyVoteEvidence(context.Background(), g0, evC, rec); err == nil {
		t.Fatal("another transaction's evidence was accepted")
	}

	other = *g0
	other.ExecMBI++
	if err := VerifyVoteEvidence(context.Background(), &other, ev, rec); err == nil {
		t.Fatal("an authority set replayed at another block was accepted")
	}

	ev.Account = "acc://other.acme/data"
	if err := VerifyVoteEvidence(context.Background(), g0, ev, rec); err == nil {
		t.Fatal("evidence evaluating another account was accepted")
	}
	if err := VerifyVoteEvidence(context.Background(), g0, nil, rec); err == nil {
		t.Fatal("no evidence was accepted")
	}
}

func TestVoteEvidenceMalformedIsAnErrorNotAnAbsence(t *testing.T) {
	if ev, err := VoteEvidenceFromRaw(json.RawMessage(`{"authorization":null}`)); err != nil || ev != nil {
		t.Fatalf("an output without evidence: %v %v", ev, err)
	}
	if _, err := VoteEvidenceFromRaw(json.RawMessage(`{"voteEvidence":{"version":"x","extraField":1}}`)); err == nil {
		t.Fatal("malformed evidence read as valid")
	}
}

// The adapter keeps the evidence on the wrapper; G1Result - inside the govRoot and the ValidatorBlock's BundleID -
// never carries it.
func TestVoteEvidence_TheAdapterKeepsItOffG1Result(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "vote_evidence_g1_delegated_case_c.json"))
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	out := append([]byte("[G1] log line\n"), compact.Bytes()...)
	g := &CLIGovernanceProofGenerator{logger: log.New(io.Discard, "", 0)}
	gp, err := g.parseOutput(GovLevelG1, out, kermitRouter(t))
	if err != nil {
		t.Fatal(err)
	}
	if gp.VoteEvidence == nil || len(gp.VoteEvidence.Pages) != 2 || len(gp.VoteEvidence.Arrivals) != 1 {
		t.Fatalf("the vote evidence was not kept: %+v", gp.VoteEvidence)
	}
	g1json, _ := json.Marshal(gp.G1)
	if strings.Contains(string(g1json), "voteEvidence") || strings.Contains(string(g1json), "govvote-evidence") {
		t.Fatal("the vote evidence leaked into G1Result")
	}

	var bad map[string]json.RawMessage
	_ = json.Unmarshal(compact.Bytes(), &bad)
	bad["voteEvidence"] = json.RawMessage(`{"version": 7}`)
	broken, _ := json.Marshal(bad)
	if _, err := g.parseOutput(GovLevelG1, broken, kermitRouter(t)); err == nil {
		t.Fatal("malformed vote evidence was accepted")
	}
}
