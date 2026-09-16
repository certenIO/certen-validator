// Copyright 2025 Certen Protocol
//
// Migration 020 withdraws layer-5 rows the canonical anchor rows contradict.

package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func migration020SQL(t *testing.T) string {
	t.Helper()
	ms, err := NewClientFromDB(testDB).getMigrations()
	if err != nil {
		t.Fatalf("loading migrations: %v", err)
	}
	for _, m := range ms {
		if strings.HasPrefix(m.Version, "020_") {
			return m.SQL
		}
	}
	t.Fatal("migration 020 is not embedded")
	return ""
}

// l5Case builds one intent's worth of rows: an anchor row carrying anchorRoot, a member row linking the
// intent to it, a proof artifact, and a layer-5 row claiming l5Root.
func l5Case(t *testing.T, canonical bool, anchorRoot, l5Root []byte) (layerID uuid.UUID, intentID string) {
	t.Helper()
	ctx := context.Background()
	intentID = "intent-" + uuid.NewString()
	batchID := uuid.New()
	proofID := uuid.New()

	var bundleID, chainID interface{}
	if canonical {
		bundleID = "0x" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("0", 32)
		chainID = int64(84532)
	}
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count,
		                            chain_id, bundle_id, created_at, updated_at)
		VALUES ($1,'on_demand','confirmed',$2,1,1,$3,$4,NOW(),NOW())`,
		batchID, anchorRoot, chainID, bundleID); err != nil {
		t.Fatalf("anchor row: %v", err)
	}
	// accumulate_tx_hash is NOT NULL, and a canonical member row does not know the intent's Accumulate
	// transaction — the batch path never sees it. Empty is what "not known here" looks like, and it is
	// precisely why the layer-5 binding is keyed on intent_id instead.
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, intent_id, created_at)
		VALUES ($1,'','acc://fictional-payer.acme',0,$2,NOW())`, batchID, intentID); err != nil {
		t.Fatalf("member row: %v", err)
	}
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO proof_artifacts (proof_id, intent_id, proof_type, accum_tx_hash, account_url,
		                             proof_class, validator_id, artifact_json, artifact_hash, created_at)
		VALUES ($1,$2,'certen_anchor',$3,'acc://fictional-payer.acme',
		        'on_demand','validator-fictional','{}'::jsonb,'\x00',NOW())`,
		proofID, intentID, strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("proof artifact: %v", err)
	}

	layer, err := json.Marshal(map[string]interface{}{
		"chainId": 84532, "network": "base-sepolia",
		"anchorTx":  "0x" + strings.Repeat("ee", 32),
		"batchRoot": hex.EncodeToString(l5Root),
		"leafHash":  strings.Repeat("11", 32),
		"leafIndex": 0, "path": []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	layerID = uuid.New()
	if _, err := testDB.ExecContext(ctx, `
		INSERT INTO chained_proof_layers (layer_id, proof_id, layer_number, layer_name, layer_json, verified)
		VALUES ($1,$2,5,'external_anchor',$3::jsonb,TRUE)`, layerID, proofID, string(layer)); err != nil {
		t.Fatalf("layer row: %v", err)
	}
	return layerID, intentID
}

func rootOf(b byte) []byte {
	r := make([]byte, 32)
	for i := range r {
		r[i] = b
	}
	return r
}

// THE LIVE CASE: intent 7758cbed. A canonical anchor row exists for the intent, and layer 5 names a
// different root — one that appears on no anchor row at all, so 019 could never reach it.
func TestMigration020WithdrawsALayerContradictedByItsCanonicalAnchor(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql := migration020SQL(t)

	layerID, _ := l5Case(t, true, rootOf(0xda), rootOf(0x1d))
	if _, err := testDB.Exec(sql); err != nil {
		t.Fatalf("migration 020: %v", err)
	}

	superseded, reason, verified := supersededState(t, layerID)
	if !superseded {
		t.Fatal("a layer contradicted by its own canonical anchor still stands")
	}
	if verified {
		t.Fatal("a withdrawn claim is still marked verified")
	}
	if !strings.Contains(reason, "is not the root this intent was anchored under") {
		t.Fatalf("reason does not name the contradiction: %q", reason)
	}
	// The claim itself is kept, as evidence of what was published.
	var js string
	if err := testDB.QueryRow(`SELECT layer_json::text FROM chained_proof_layers WHERE layer_id=$1`,
		layerID).Scan(&js); err != nil {
		t.Fatalf("the row was deleted rather than withdrawn: %v", err)
	}
	if !strings.Contains(js, hex.EncodeToString(rootOf(0x1d))) {
		t.Fatal("the withdrawn row's claim was rewritten")
	}
}

// A layer that AGREES with its canonical anchor must be left alone — the second live intent's shape.
func TestMigration020LeavesAnAgreeingLayerStanding(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql := migration020SQL(t)

	root := rootOf(0x2a)
	layerID, _ := l5Case(t, true, root, root)
	if _, err := testDB.Exec(sql); err != nil {
		t.Fatal(err)
	}
	if superseded, reason, _ := supersededState(t, layerID); superseded {
		t.Fatalf("a layer matching its canonical anchor was withdrawn: %s", reason)
	}
}

// THE GUARD THAT MATTERS. An intent with no canonical row yet — every historical row until the chain
// backfill reaches it — must NOT be withdrawn. Silence is not evidence against a claim.
func TestMigration020DoesNotWithdrawWhenNoCanonicalAnchorExists(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql := migration020SQL(t)

	// Shadow-only anchor row, and a layer naming some other root entirely.
	layerID, _ := l5Case(t, false, rootOf(0xc3), rootOf(0x99))
	if _, err := testDB.Exec(sql); err != nil {
		t.Fatal(err)
	}
	if superseded, reason, _ := supersededState(t, layerID); superseded {
		t.Fatalf("a not-yet-backfilled layer was withdrawn: %s", reason)
	}
}

// Re-running must not re-stamp an existing withdrawal.
func TestMigration020IsIdempotent(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql := migration020SQL(t)

	layerID, _ := l5Case(t, true, rootOf(0xab), rootOf(0xcd))
	if _, err := testDB.Exec(sql); err != nil {
		t.Fatal(err)
	}
	var first string
	if err := testDB.QueryRow(`SELECT superseded_at::text FROM chained_proof_layers WHERE layer_id=$1`,
		layerID).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if _, err := testDB.Exec(sql); err != nil {
		t.Fatalf("second run: %v", err)
	}
	var second string
	if err := testDB.QueryRow(`SELECT superseded_at::text FROM chained_proof_layers WHERE layer_id=$1`,
		layerID).Scan(&second); err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("re-running re-stamped the withdrawal: %s then %s", first, second)
	}
}

// Seven validators upgrade at once.
func TestMigration020IsSafeUnderConcurrentMigrators(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql := migration020SQL(t)

	errs := make(chan error, 7)
	for i := 0; i < 7; i++ {
		go func() { _, err := testDB.Exec(sql); errs <- err }()
	}
	for i := 0; i < 7; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent migrator: %v", err)
		}
	}
	var n int
	if err := testDB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=$1`,
		"020_supersede_layer5_contradicted_by_canonical").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("recorded %d times", n)
	}
}
