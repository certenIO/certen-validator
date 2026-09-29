package consensus

import (
	"context"
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
	raw, err := os.ReadFile(filepath.Join("..", "proof", "testdata", "vote_evidence_g1_phasec_98e40472.json"))
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
	ev, err := proof.VoteEvidenceFromRaw(raw)
	if err != nil || ev == nil {
		t.Fatalf("vote evidence: %v", err)
	}
	return &g0, &proof.GovernanceProof{Level: proof.GovLevelG1, Authorization: rec, VoteEvidence: ev}
}

func TestGovernanceDecisionIsDerivedFromG1AndConfirmedByG2(t *testing.T) {
	g0, g1 := g1Wrapper(t)
	_, g2 := g1Wrapper(t)
	gdr, rec, err := deriveGovernanceDecision(context.Background(), g0, g1, g2)
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
	if _, _, err := deriveGovernanceDecision(context.Background(), g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("G1 and G2 recorded different decisions: %v", err)
	}

	_, g2 = g1Wrapper(t)
	g1.Authorization = nil
	if _, _, err := deriveGovernanceDecision(context.Background(), g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("no G1 vote record: %v", err)
	}

	g0, g1 = g1Wrapper(t)
	g2.Authorization = nil
	if _, _, err := deriveGovernanceDecision(context.Background(), g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("no G2 vote record: %v", err)
	}

	// The vote record must be reached, here, from its chain-bound evidence: without it, or from evidence that does
	// not reach it, the record is only the proof's word for who decided.
	g0, g1 = g1Wrapper(t)
	_, g2 = g1Wrapper(t)
	g1.VoteEvidence = nil
	if _, _, err := deriveGovernanceDecision(context.Background(), g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("no vote evidence: %v", err)
	}
	g0, g1 = g1Wrapper(t)
	g1.VoteEvidence.Signatures[0].Fact.Block++
	if _, _, err := deriveGovernanceDecision(context.Background(), g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("tampered vote evidence: %v", err)
	}
	g0, g1 = g1Wrapper(t)
	g1.Authorization.Authorities[0].Vote.Pages[0].Counted[0].By += "-other"
	g2.Authorization.Authorities[0].Vote.Pages[0].Counted[0].By += "-other"
	if _, _, err := deriveGovernanceDecision(context.Background(), g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("a vote record its evidence does not reach: %v", err)
	}
	g0, g1 = g1Wrapper(t)
	_, g2 = g1Wrapper(t)
	g0.TxHash = "00" + g0.TxHash[2:]
	if _, _, err := deriveGovernanceDecision(context.Background(), g0, g1, g2); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("evidence about another transaction: %v", err)
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

// Every chain member of an intent is queued committing to the round's governance decision.
func TestEveryMemberCommitsToTheRoundsDecision(t *testing.T) {
	f := newFakeEnqueuer()
	if err := enqueue(refusalValidator(f), batchableIntent(t, "i1", 84532, 421614)); err != nil {
		t.Fatal(err)
	}
	want := proof.GovernanceCommitment(testGovDecision)
	for _, c := range []int64{84532, 421614} {
		if f.governance[c] != want {
			t.Fatalf("chain %d was queued with governance %x, want %x", c, f.governance[c], want)
		}
	}
}

// A round that recorded no decision is not queued - and CERTEN not having established it is retried, not a
// refusal of the intent.
func TestARoundWithoutADecisionIsRetriedNotRefused(t *testing.T) {
	f := newFakeEnqueuer()
	err := refusalValidator(f).enqueueForBatch(batchableIntent(t, "i1", 84532), &proof.CertenProof{}, nil, 7,
		nil, nil, nil, "", nil, "", 7)
	var r *BatchRefusal
	if !errors.As(err, &r) || r.Permanent || !errors.Is(err, ErrNoGovernanceCommitment) {
		t.Fatalf("got %v", err)
	}
	if len(f.queued) != 0 {
		t.Fatal("a member was queued without a decision")
	}
}
