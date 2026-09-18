// Copyright 2026 Certen Protocol
//
// The standing checks must DETECT, not merely return zero.

package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A check that cannot fail is decoration. Each test below plants exactly the condition the check exists
// for and requires it to be seen — then removes it and requires zero.

func evidenceQ(t *testing.T) EvidenceQueries {
	t.Helper()
	_ = anchorRepoForTest(t) // brings the schema up and skips when no database is configured
	return EvidenceQueries{DB: testDB, Window: time.Hour}
}

// Plant an intent whose only anchor row is a shadow row: settled, but no canonical evidence.
func TestEvidenceChecksSeeASettledIntentWithNoCanonicalRow(t *testing.T) {
	q := evidenceQ(t)
	ctx := context.Background()

	before, err := q.Run(ctx)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	intentID := "intent-uncovered-" + uuid.NewString()
	shadow := uuid.New()
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count, created_at, updated_at)
		VALUES ($1,'on_demand','pending',$2,1,1,NOW(),NOW())`, shadow, []byte{0xaa}); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, intent_id, created_at)
		VALUES ($1,'','acc://x.acme',0,$2,NOW())`, shadow, intentID); err != nil {
		t.Fatal(err)
	}

	after, err := q.Run(ctx)
	if err != nil {
		t.Fatalf("after planting: %v", err)
	}
	if after.SettledWithoutCanonicalRow != before.SettledWithoutCanonicalRow+1 {
		t.Fatalf("settled-without-canonical = %d, want %d — the check did not see an intent that settled "+
			"with no canonical anchor", after.SettledWithoutCanonicalRow, before.SettledWithoutCanonicalRow+1)
	}

	// Give the same intent a canonical row and it must stop counting.
	canonical := uuid.New()
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count,
		                            chain_id, bundle_id, created_at, updated_at)
		VALUES ($1,'on_demand','confirmed',$2,1,1,84532,$3,NOW(),NOW())`,
		canonical, []byte{0xbb}, "0x"+strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, intent_id, created_at)
		VALUES ($1,'','acc://x.acme',0,$2,NOW())`, canonical, intentID); err != nil {
		t.Fatal(err)
	}

	covered, err := q.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if covered.SettledWithoutCanonicalRow != before.SettledWithoutCanonicalRow {
		t.Fatalf("an intent WITH a canonical row is still counted as uncovered (%d, want %d)",
			covered.SettledWithoutCanonicalRow, before.SettledWithoutCanonicalRow)
	}
}

// Plant a standing layer-5 row whose root disagrees with its intent's canonical anchor.
func TestEvidenceChecksSeeAContradictedLayer5Row(t *testing.T) {
	q := evidenceQ(t)
	ctx := context.Background()

	before, err := q.Run(ctx)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}

	intentID := "intent-contradicted-" + uuid.NewString()
	proofID := uuid.New()
	batchID := uuid.New()
	anchorRoot := make([]byte, 32)
	for i := range anchorRoot {
		anchorRoot[i] = 0xda
	}
	otherRoot := make([]byte, 32)
	for i := range otherRoot {
		otherRoot[i] = 0x1d
	}

	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count,
		                            chain_id, bundle_id, created_at, updated_at)
		VALUES ($1,'on_demand','confirmed',$2,1,1,84532,$3,NOW(),NOW())`,
		batchID, anchorRoot, "0x"+strings.ReplaceAll(uuid.NewString(), "-", "")+strings.Repeat("0", 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, intent_id, created_at)
		VALUES ($1,'','acc://x.acme',0,$2,NOW())`, batchID, intentID); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO proof_artifacts (proof_id, intent_id, proof_type, accum_tx_hash, account_url,
		                             proof_class, validator_id, artifact_json, artifact_hash, created_at)
		VALUES ($1,$2,'certen_anchor',$3,'acc://x.acme','on_demand','v-fictional','{}'::jsonb,'\x00',NOW())`,
		proofID, intentID, strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	layer, _ := json.Marshal(map[string]interface{}{
		"batchRoot": hex.EncodeToString(otherRoot), "anchorTx": "0x" + strings.Repeat("ee", 32),
		"leafHash": strings.Repeat("11", 32), "leafIndex": 0, "path": []interface{}{},
	})
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO chained_proof_layers (layer_id, proof_id, layer_number, layer_name, layer_json, verified)
		VALUES ($1,$2,5,'external_anchor',$3::jsonb,TRUE)`, uuid.New(), proofID, string(layer)); err != nil {
		t.Fatal(err)
	}

	after, err := q.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.ContradictedLayer5Rows != before.ContradictedLayer5Rows+1 {
		t.Fatalf("contradicted-layer5 = %d, want %d — the check did not see a published claim its own "+
			"canonical anchor contradicts", after.ContradictedLayer5Rows, before.ContradictedLayer5Rows+1)
	}

	// Withdrawing it must clear the count: a withdrawn claim is no longer being made.
	if _, err := testDB.ExecContext(ctx,
		`UPDATE chained_proof_layers SET superseded_at = NOW() WHERE proof_id = $1`, proofID); err != nil {
		t.Fatal(err)
	}
	cleared, err := q.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.ContradictedLayer5Rows != before.ContradictedLayer5Rows {
		t.Fatalf("a withdrawn row is still counted (%d, want %d)",
			cleared.ContradictedLayer5Rows, before.ContradictedLayer5Rows)
	}
}

// A check that cannot reach the database must report an error, never a clean zero.
func TestEvidenceChecksRefuseToReportZeroWithoutADatabase(t *testing.T) {
	if _, err := (EvidenceQueries{}).Run(context.Background()); err == nil {
		t.Fatal("a check with no database returned a report; a zero that was never measured reads as health")
	}
}
