package execution

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB4-F66: the proof cycle stores who decided the transaction with the G1 level - the decision record, its
// commitment and the vote record - and stores only a decision that re-derives from what is stored with it.

func f66Commitment(t *testing.T) (map[string]interface{}, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "proof", "testdata", "gdr_g1_phasec_98e40472.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g0 certenproof.G0Result
	if err := json.Unmarshal(raw, &g0); err != nil {
		t.Fatal(err)
	}
	rec, err := certenproof.AuthorizationRecordFromRaw(raw)
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	gdr, err := certenproof.GovernanceDecisionRecord(&g0, rec)
	if err != nil {
		t.Fatal(err)
	}
	g0JSON, _ := json.Marshal(g0)
	recJSON, _ := json.Marshal(rec)
	return map[string]interface{}{
		consensus.G0ProofCommitmentKey:          string(g0JSON),
		consensus.GovDecisionCommitmentKey:      hex.EncodeToString(gdr),
		consensus.GovAuthorizationCommitmentKey: string(recJSON),
	}, gdr
}

func TestF66_TheDecisionIsStoredWithItsCommitment(t *testing.T) {
	cm, gdr := f66Commitment(t)
	in, err := GovernanceInputsFromCommitment(cm)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := in.DecisionEvidence()
	if err != nil {
		t.Fatal(err)
	}
	c := certenproof.GovernanceCommitment(gdr)
	if ev[GovLevelDecisionKey] != hex.EncodeToString(gdr) || ev[GovLevelCommitmentKey] != hex.EncodeToString(c[:]) {
		t.Fatalf("stored %+v", ev)
	}
	if hex.EncodeToString(c[:]) != "bf70dbca95fcf373511b454ad486f6c85396a5c2ff7119b55c7538be834c0d1f" {
		t.Fatal("the Phase C decision commitment moved")
	}
	out := mustLevelJSON(t, "G1", nil, nil, nil, ev)
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(out, &obj)
	for _, k := range []string{GovLevelDecisionKey, GovLevelCommitmentKey, GovLevelAuthorizationKey} {
		if _, ok := obj[k]; !ok {
			t.Errorf("level_json lacks %s", k)
		}
	}
}

func TestF66_ADecisionThatDoesNotReDeriveIsRefused(t *testing.T) {
	cm, gdr := f66Commitment(t)
	tampered := append([]byte(nil), gdr...)
	tampered[len(tampered)-1] ^= 1
	cm[consensus.GovDecisionCommitmentKey] = hex.EncodeToString(tampered)
	in, err := GovernanceInputsFromCommitment(cm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.DecisionEvidence(); err == nil {
		t.Fatal("a decision that does not re-derive from its vote record was stored")
	}
}

func TestF66_ADecisionWithoutItsVoteRecordIsRefused(t *testing.T) {
	cm, _ := f66Commitment(t)
	delete(cm, consensus.GovAuthorizationCommitmentKey)
	if _, err := GovernanceInputsFromCommitment(cm); err == nil {
		t.Fatal("a decision without its vote record was accepted")
	}
	cm, _ = f66Commitment(t)
	delete(cm, consensus.GovDecisionCommitmentKey)
	if _, err := GovernanceInputsFromCommitment(cm); err == nil {
		t.Fatal("a vote record without its decision was accepted")
	}
}
