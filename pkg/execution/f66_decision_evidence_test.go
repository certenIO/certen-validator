package execution

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
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

// A stored proof's decision is re-derived and checked against the batch its layer 5 names.
func f66StoredG1(t *testing.T) (certenproof.StoredGovernanceLevel, [32]byte) {
	t.Helper()
	cm, gdr := f66Commitment(t)
	in, err := GovernanceInputsFromCommitment(cm)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := in.DecisionEvidence()
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]json.RawMessage{}
	for k, v := range ev {
		b, _ := json.Marshal(v)
		flags[k] = b
	}
	raw, err := os.ReadFile(filepath.Join("..", "proof", "testdata", "gdr_g1_phasec_98e40472.json"))
	if err != nil {
		t.Fatal(err)
	}
	return certenproof.StoredGovernanceLevel{Level: "G1", Result: raw, Flags: flags}, certenproof.GovernanceCommitment(gdr)
}

func f66AnchoredLayer5(t *testing.T, member [32]byte, version string) *Layer5 {
	t.Helper()
	inputs := []BatchLeafInput{
		{ADIURL: "acc://other.acme", ExecutionCommitment: [32]byte{1}, OperationID: [32]byte{7}, GovernanceCommitment: [32]byte{0x0c}},
		{ADIURL: "acc://rb4-phase-c-09282125.acme", ExecutionCommitment: [32]byte{2}, OperationID: [32]byte{8}, GovernanceCommitment: member},
	}
	if version == BatchOperationIDV1 {
		for i := range inputs {
			inputs[i].GovernanceCommitment, inputs[i].LegacyNoGovernance = [32]byte{}, true
		}
	}
	tree, err := BuildBatchTree(84532, inputs, 100)
	if err != nil {
		t.Fatal(err)
	}
	g := &BatchGovernance{Version: tree.BatchOperationIDVersion, BatchOperationID: hexPrefixed(tree.BatchOperationID[:])}
	for _, in := range tree.Inputs {
		m := database.BatchMemberGovernance{OperationID: hexPrefixed(in.OperationID[:])}
		if !in.LegacyNoGovernance {
			m.GovernanceCommitment = hexPrefixed(in.GovernanceCommitment[:])
		}
		g.Members = append(g.Members, m)
	}
	g.OperationID, g.GovernanceCommitment = g.Members[1].OperationID, g.Members[1].GovernanceCommitment
	return &Layer5{Governance: g}
}

func TestF66_AStoredDecisionIsCheckedAgainstItsAnchoredBatch(t *testing.T) {
	g1, c := f66StoredG1(t)
	got, err := CheckGovernanceDecision([]certenproof.StoredGovernanceLevel{g1}, f66AnchoredLayer5(t, c, BatchOperationIDV2))
	if err != nil {
		t.Fatal(err)
	}
	if got.Commitment != hexPrefixed(c[:]) || got.BatchVersion != "v2" || got.Authorities != 1 {
		t.Fatalf("%+v", got)
	}

	// The batch lists another commitment for this member.
	if _, err := CheckGovernanceDecision([]certenproof.StoredGovernanceLevel{g1},
		f66AnchoredLayer5(t, [32]byte{0xdd}, BatchOperationIDV2)); err == nil || errors.Is(err, ErrGovernanceNotAnchored) {
		t.Fatalf("a batch committing to another decision: %v", err)
	}
	// A v1 batch: recorded, not anchored.
	if _, err := CheckGovernanceDecision([]certenproof.StoredGovernanceLevel{g1},
		f66AnchoredLayer5(t, c, BatchOperationIDV1)); !errors.Is(err, ErrGovernanceNotAnchored) {
		t.Fatalf("a v1 batch: %v", err)
	}
	// No layer 5 governance: recorded, not anchored.
	if _, err := CheckGovernanceDecision([]certenproof.StoredGovernanceLevel{g1}, nil); !errors.Is(err, ErrGovernanceNotAnchored) {
		t.Fatalf("no layer 5: %v", err)
	}
	// A proof from before decisions were stored.
	bare := certenproof.StoredGovernanceLevel{Level: "G1", Result: g1.Result, Flags: map[string]json.RawMessage{}}
	if _, err := CheckGovernanceDecision([]certenproof.StoredGovernanceLevel{bare}, nil); !errors.Is(err, ErrNoGovernanceDecision) {
		t.Fatalf("no decision stored: %v", err)
	}
	// A stored vote record altered after the fact no longer derives the stored decision.
	tampered := certenproof.StoredGovernanceLevel{Level: "G1", Result: g1.Result, Flags: map[string]json.RawMessage{}}
	for k, v := range g1.Flags {
		tampered.Flags[k] = v
	}
	tampered.Flags[GovLevelAuthorizationKey] = json.RawMessage(strings.Replace(string(g1.Flags[GovLevelAuthorizationKey]),
		`"version":2`, `"version":3`, 1))
	if string(tampered.Flags[GovLevelAuthorizationKey]) == string(g1.Flags[GovLevelAuthorizationKey]) {
		t.Fatal("the tamper did not change the stored vote record")
	}
	if _, err := CheckGovernanceDecision([]certenproof.StoredGovernanceLevel{tampered}, nil); err == nil ||
		errors.Is(err, ErrGovernanceNotAnchored) || errors.Is(err, ErrNoGovernanceDecision) {
		t.Fatalf("an altered vote record: %v", err)
	}
}
