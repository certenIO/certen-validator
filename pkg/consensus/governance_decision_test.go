package consensus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// RB4-F66: each validator derives, from its own proof, the record of who decided the transaction, and the batch
// commits to it. G2 runs G1 again; both runs must have recorded the same decision, or which one to commit to is not
// established.

func g1Wrapper(t *testing.T) (*proof.G0Result, *proof.GovernanceProof) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "proof", "testdata", "gdr_g1_phasec_98e40472.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g0 proof.G0Result
	if err := json.Unmarshal(raw, &g0); err != nil {
		t.Fatal(err)
	}
	rec, err := proof.AuthorizationRecordFromRaw(raw)
	if err != nil || rec == nil {
		t.Fatalf("record: %v", err)
	}
	return &g0, &proof.GovernanceProof{Level: proof.GovLevelG1, Authorization: rec}
}

func TestGovernanceDecisionIsDerivedFromG1AndConfirmedByG2(t *testing.T) {
	g0, g1 := g1Wrapper(t)
	_, g2 := g1Wrapper(t)
	gdr, rec, err := deriveGovernanceDecision(g0, g1, g2)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := proof.GovernanceDecisionRecord(g0, g1.Authorization)
	if string(gdr) != string(want) || rec != g1.Authorization {
		t.Fatal("the decision is not G1's")
	}
}

func TestGovernanceDecisionRefusesWhatItCannotEstablish(t *testing.T) {
	g0, g1 := g1Wrapper(t)
	_, g2 := g1Wrapper(t)
	g2.Authorization.Authorities[0].Vote.Pages[0].Counted[0].By += "-other"
	if _, _, err := deriveGovernanceDecision(g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("G1 and G2 recorded different decisions: %v", err)
	}

	_, g2 = g1Wrapper(t)
	g1.Authorization = nil
	if _, _, err := deriveGovernanceDecision(g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("no G1 vote record: %v", err)
	}

	g0, g1 = g1Wrapper(t)
	g2.Authorization = nil
	if _, _, err := deriveGovernanceDecision(g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("no G2 vote record: %v", err)
	}
}

// The round's snapshot carries the decision, and the proof cycle's commitment carries it to storage.
func TestGovernanceDecisionTravelsToTheProofCycle(t *testing.T) {
	g0, g1 := g1Wrapper(t)
	gdr, err := proof.GovernanceDecisionRecord(g0, g1.Authorization)
	if err != nil {
		t.Fatal(err)
	}
	bv := &BFTValidator{}
	att := bv.captureAttestation(nil, nil, &proof.CertenProof{GovDecision: gdr, GovAuthorization: g1.Authorization},
		1, g0, nil, nil, "", nil, "G2")
	if string(att.GovDecision) != string(gdr) || att.GovAuthorization != g1.Authorization {
		t.Fatal("the snapshot does not carry the decision")
	}
	cm := map[string]interface{}{}
	putProofEvidence(cm, att, func(string, error) {})
	if cm[GovDecisionCommitmentKey] != hex.EncodeToString(gdr) {
		t.Fatalf("the commitment carries decision %v", cm[GovDecisionCommitmentKey])
	}
	var rec proof.AuthorizationRecord
	if s, _ := cm[GovAuthorizationCommitmentKey].(string); json.Unmarshal([]byte(s), &rec) != nil || !rec.Satisfied {
		t.Fatal("the commitment does not carry the vote record")
	}
	if _, bad := cm[EvidenceErrorCommitmentKey]; bad {
		t.Fatal("an evidence error was recorded for evidence that marshals")
	}
}
