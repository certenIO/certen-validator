package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// RB5-F15: a recorded outcome's evidence is attached to the proofs its anchor's members carry - found by their standing
// layer 5 - once, and never overwritten.

func outcomeLayer5(t *testing.T, ctx context.Context, repo *ProofArtifactRepository, chainID int64, bundle, root, leaf string, withCommitment bool) uuid.UUID {
	t.Helper()
	a := newTestArtifact(t, ctx)
	l5 := map[string]interface{}{"chainId": chainID, "batchRoot": root, "leafHash": leaf, "leafIndex": 0, "anchorTx": "0x" + strings.Repeat("ab", 32),
		"blockNumber": 1}
	if withCommitment {
		l5["commitment"] = map[string]interface{}{"bundleId": bundle}
	}
	raw, _ := json.Marshal(l5)
	if _, err := repo.CreateChainedProofLayer(ctx, &NewChainedProofLayer{ProofID: a.ProofID, LayerNumber: 5, LayerName: "L5 - External Anchor",
		LayerJSON: raw}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testDB.ExecContext(context.Background(), `DELETE FROM chained_proof_layers WHERE proof_id = $1`, a.ProofID)
	})
	return a.ProofID
}

func TestTheProofsOfAnAnchorLeafAreFoundByTheirLayer5(t *testing.T) {
	ctx := context.Background()
	repo := NewProofArtifactRepository(testDB)
	tag := strings.ReplaceAll(uuid.NewString(), "-", "")
	h := func(s string) string { return fmt.Sprintf("%064s", tag+s)[:64] }
	bundle, root, leaf := "0x"+h("b1"), h("r1"), h("l1")
	withC := outcomeLayer5(t, ctx, repo, 84532, bundle, root, leaf, true)
	without := outcomeLayer5(t, ctx, repo, 84532, bundle, "0x"+root, "0X"+strings.ToUpper(leaf), false) // a pre-00018 layer 5, other spelling
	outcomeLayer5(t, ctx, repo, 84532, "0x"+h("b2"), root, leaf, true)                                  // the same leaf under another anchor
	outcomeLayer5(t, ctx, repo, 421614, bundle, root, leaf, true)                                       // and on another chain

	got, err := repo.ProofsOfAnchorLeaf(ctx, 84532, strings.ToUpper(bundle[2:]), "0x"+root, leaf)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]bool{withC: true, without: true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("found %v, want %v and %v", got, withC, without)
	}

	// A superseded layer 5 places nothing.
	if _, err := testDB.ExecContext(ctx, `UPDATE chained_proof_layers SET superseded_at = NOW(), superseded_reason = 'test'
		WHERE proof_id = $1 AND layer_number = 5`, without); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.ProofsOfAnchorLeaf(ctx, 84532, bundle, root, leaf); err != nil || len(got) != 1 || got[0] != withC {
		t.Fatalf("after superseding: %v %v", got, err)
	}
}

func TestAProofsOutcomeEvidenceIsAttachedOnceAndNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	repo := NewProofArtifactRepository(testDB)
	id := outcomeLayer5(t, ctx, repo, 84532, "0x"+strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), true)
	first := []byte(`{"version":"certen:outcome-evidence:v1","quorum":{"zkProof":"0x01"}}`)
	completed := []byte(`{"version":"certen:outcome-evidence:v1","quorum":{"zkProof":"0x01","aggregateSignature":"0xaa"}}`)
	keep := func([]byte) (OutcomeLayerDecision, string, error) { return OutcomeLayerKeep, "", nil }
	supersede := func([]byte) (OutcomeLayerDecision, string, error) { return OutcomeLayerSupersede, "completed", nil }
	refuse := func([]byte) (OutcomeLayerDecision, string, error) {
		return OutcomeLayerKeep, "", errors.New("another outcome")
	}

	if ok, err := repo.AttachOutcomeLayer(ctx, id, "L6 - Batch Outcome", first, refuse); err != nil || !ok {
		t.Fatalf("the first attachment: %v %v", ok, err)
	}
	if ok, err := repo.AttachOutcomeLayer(ctx, id, "L6 - Batch Outcome", first, keep); err != nil || ok {
		t.Fatalf("the same evidence again: %v %v", ok, err)
	}
	if _, err := repo.AttachOutcomeLayer(ctx, id, "L6 - Batch Outcome", completed, refuse); !errors.Is(err, ErrOutcomeLayerContradiction) {
		t.Fatalf("contradicting evidence: %v", err)
	}
	if ok, err := repo.AttachOutcomeLayer(ctx, id, "L6 - Batch Outcome", completed, supersede); err != nil || !ok {
		t.Fatalf("completing evidence: %v %v", ok, err)
	}
	var standing, superseded int
	var reason string
	if err := testDB.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE superseded_at IS NULL), count(*) FILTER (WHERE superseded_at IS NOT NULL),
		max(superseded_reason) FROM chained_proof_layers WHERE proof_id = $1 AND layer_number = 6`, id).Scan(&standing, &superseded, &reason); err != nil {
		t.Fatal(err)
	}
	if standing != 1 || superseded != 1 || reason != "completed" {
		t.Fatalf("%d standing, %d superseded (%q): the first row must be kept, marked, never deleted", standing, superseded, reason)
	}
	layers, err := repo.GetChainedProofLayers(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range layers {
		if l.LayerNumber == 6 && !strings.Contains(string(l.LayerJSON), "aggregateSignature") {
			t.Fatalf("the standing row is not the completed evidence: %s", l.LayerJSON)
		}
	}
}

// RB5-F15: a recorded anchor is listed as a hint while a member's proof lacks its outcome evidence, and no longer once
// every such proof carries it.
func TestRecordedAnchorsWithoutProofEvidenceAreListedAsHints(t *testing.T) {
	ctx := context.Background()
	repo := NewProofArtifactRepository(testDB)
	outcomes := outcomeRepoForTest(t)
	bundle := "0x" + strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")[:64]
	if err := outcomes.RecordBatchOutcome(ctx, outcomeRecordForTest(bundle, BatchOutcomeEvidenceChain)); err != nil {
		t.Fatal(err)
	}
	id := outcomeLayer5(t, ctx, repo, 84532, strings.ToUpper(bundle[2:]), strings.Repeat("4", 64), strings.Repeat("5", 64), true)
	listed := func() bool {
		got, err := outcomes.RecordedAnchorsWithoutProofEvidence(ctx, 84532, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range got {
			if b == bundle {
				return true
			}
		}
		return false
	}
	if !listed() {
		t.Fatal("a recorded anchor whose member's proof has no outcome evidence is not listed")
	}
	if _, err := repo.AttachOutcomeLayer(ctx, id, "L6 - Batch Outcome", []byte(`{"version":"x"}`),
		func([]byte) (OutcomeLayerDecision, string, error) { return OutcomeLayerKeep, "", nil }); err != nil {
		t.Fatal(err)
	}
	if listed() {
		t.Fatal("an anchor whose members' proofs all carry outcome evidence is still listed")
	}
}
