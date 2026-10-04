package database

import (
	"context"
	"strings"
	"testing"
)

// RB6 Phase A, migration 00022: the proof v2 shadow's store.

func shadowRepoForTest(t *testing.T) *ProofV2ShadowRepository {
	t.Helper()
	if testDB == nil {
		t.Fatal("CERTEN_TEST_DB is required: this test runs against PostgreSQL (a skipped gate is not a green gate)")
	}
	return NewProofV2ShadowRepository(NewClientFromDB(testDB))
}

// A retried intent is re-discovered after its block may have left retention. Its later, failed capture must not erase
// the pages read while they were servable.
func TestProofV2Shadow_AGoodCaptureIsNeverReplaced(t *testing.T) {
	r := shadowRepoForTest(t)
	ctx := context.Background()
	id := "rb6-shadow-capture-" + t.Name()
	if err := r.RecordCapture(ctx, id, "aa", "acc://x.acme/data", 7, []string{"page"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordCapture(ctx, id, "aa", "acc://x.acme/data", 0, nil, "no BPT history retained"); err != nil {
		t.Fatal(err)
	}
	raw, ok, err := r.Captured(ctx, id)
	if err != nil || !ok || !strings.Contains(string(raw), "page") {
		t.Fatalf("the captured pages were replaced: %s ok=%v err=%v", raw, ok, err)
	}

	// A capture that held nothing may be completed by a later one.
	id2 := id + "-empty"
	if err := r.RecordCapture(ctx, id2, "bb", "acc://x.acme/data", 0, nil, "not yet"); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordCapture(ctx, id2, "bb", "acc://x.acme/data", 9, []string{"later"}, ""); err != nil {
		t.Fatal(err)
	}
	raw, _, _ = r.Captured(ctx, id2)
	if !strings.Contains(string(raw), "later") {
		t.Fatalf("an empty capture was not completed: %s", raw)
	}
}

func TestProofV2Shadow_AFailedBuildNamesWhy(t *testing.T) {
	r := shadowRepoForTest(t)
	ctx := context.Background()
	if err := r.RecordBuild(ctx, ProofV2Result{IntentID: "rb6-shadow-fail", TxHash: "cc", Account: "acc://x.acme/data", Verdict: "failed"}); err == nil {
		t.Fatal("a failed build without a reason was stored")
	}
	// The table refuses it too, whatever writes it.
	if _, err := testDB.ExecContext(ctx, `INSERT INTO proof_v2_shadow (intent_id, accum_tx_hash, account_url, verdict) VALUES ('rb6-shadow-raw', 'dd', 'acc://x', 'failed')`); err == nil {
		t.Fatal("the table accepted a failed verdict without an error")
	}
	if err := r.RecordBuild(ctx, ProofV2Result{IntentID: "rb6-shadow-ok", TxHash: "ee", Account: "acc://x.acme/data", Verdict: "verified", Evidence: map[string]any{"version": "2.0"}, AnchorBlock: 5, CertifiedBlock: 6, Pages: 3}); err != nil {
		t.Fatal(err)
	}
}

func TestProofV2Shadow_AStoredSpineRecordNeverChanges(t *testing.T) {
	r := shadowRepoForTest(t)
	ctx := context.Background()
	if _, err := testDB.ExecContext(ctx, `DELETE FROM proof_v2_spine`); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveSpine(ctx, 1, [][]byte{{1}, {2}, {3}}); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveSpine(ctx, 2, [][]byte{{2}, {3}, {4}}); err != nil {
		t.Fatalf("re-saving the same records with one new one: %v", err)
	}
	if err := r.SaveSpine(ctx, 3, [][]byte{{9}}); err == nil {
		t.Fatal("a stored major record was replaced")
	}
	got, err := r.Spine(ctx)
	if err != nil || len(got) != 4 || got[3][0] != 4 {
		t.Fatalf("spine %v err %v", got, err)
	}
}
