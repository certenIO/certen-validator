// Copyright 2025 Certen Protocol
//
// Migration 019 withdraws layer-5 rows that bind a root no anchor ever held.

package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// migration019SQL returns the migration's own text, so the test runs exactly what production runs.
func migration019SQL(t *testing.T) string {
	t.Helper()
	client := NewClientFromDB(testDB)
	ms, err := client.getMigrations()
	if err != nil {
		t.Fatalf("loading migrations: %v", err)
	}
	for _, m := range ms {
		if strings.HasPrefix(m.Version, "019_") {
			return m.SQL
		}
	}
	t.Fatal("migration 019 is not embedded")
	return ""
}

// insertAnchorRootForTest adds an anchor row carrying a root, canonical or shadow.
func insertAnchorRootForTest(t *testing.T, root []byte, canonical bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var bundleID interface{}
	var chainID interface{}
	if canonical {
		bundleID = "0x" + strings.ReplaceAll(uuid.NewString(), "-", "") + strings.Repeat("0", 32)
		chainID = int64(84532)
	}
	if _, err := testDB.ExecContext(context.Background(), `
		INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count,
		                            chain_id, bundle_id, created_at, updated_at)
		VALUES ($1, 'on_demand', 'confirmed', $2, 1, 1, $3, $4, NOW(), NOW())`,
		id, root, chainID, bundleID); err != nil {
		t.Fatalf("inserting anchor row: %v", err)
	}
	return id
}

// insertLayer5ForTest adds a layer-5 row claiming a leaf is under a root, published in a transaction.
func insertLayer5ForTest(t *testing.T, root []byte, anchorTx string) uuid.UUID {
	t.Helper()
	layer, err := json.Marshal(map[string]interface{}{
		"chainId":     84532,
		"network":     "base-sepolia",
		"anchorTx":    anchorTx,
		"blockNumber": 45943270,
		"batchRoot":   hex.EncodeToString(root),
		"leafHash":    strings.Repeat("11", 32),
		"leafIndex":   0,
		"path":        []interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if _, err := testDB.ExecContext(context.Background(), `
		INSERT INTO chained_proof_layers (layer_id, proof_id, layer_number, layer_name, layer_json, verified)
		VALUES ($1, NULL, 5, 'external_anchor', $2::jsonb, TRUE)`, id, string(layer)); err != nil {
		t.Fatalf("inserting layer 5 row: %v", err)
	}
	return id
}

func supersededState(t *testing.T, layerID uuid.UUID) (superseded bool, reason string, verified bool) {
	t.Helper()
	var reasonNull *string
	var at *string
	if err := testDB.QueryRowContext(context.Background(),
		`SELECT superseded_at::text, superseded_reason, verified FROM chained_proof_layers WHERE layer_id = $1`,
		layerID).Scan(&at, &reasonNull, &verified); err != nil {
		t.Fatalf("reading layer row: %v", err)
	}
	if reasonNull != nil {
		reason = *reasonNull
	}
	return at != nil, reason, verified
}

// The incident: a layer-5 row bound to a root that exists only on a shadow anchor row.
func TestMigration019WithdrawsAShadowOnlyBinding(t *testing.T) {
	_ = consensusRepoForTest(t) // brings the schema up, 019 included
	sql019 := migration019SQL(t)

	// A root nobody published, held only by a per-validator shadow row — the d2d24ab3 shape.
	shadowRoot := make([]byte, 32)
	for i := range shadowRoot {
		shadowRoot[i] = byte(0xd0 + (i % 7))
	}
	insertAnchorRootForTest(t, shadowRoot, false)
	// The settlement transaction, which published a different root entirely.
	layerID := insertLayer5ForTest(t, shadowRoot, "0x9e4ff6ab"+strings.Repeat("0", 56))

	if _, err := testDB.Exec(sql019); err != nil {
		t.Fatalf("re-running migration 019: %v", err)
	}

	superseded, reason, verified := supersededState(t, layerID)
	if !superseded {
		t.Fatal("a binding to a root that was never published still stands")
	}
	if verified {
		t.Fatal("a withdrawn claim is still marked verified")
	}
	if !strings.Contains(reason, "never published") {
		t.Fatalf("reason does not say what is wrong: %q", reason)
	}

	// The evidence itself is kept: the claim must remain readable after being withdrawn.
	var layerJSON string
	if err := testDB.QueryRow(`SELECT layer_json::text FROM chained_proof_layers WHERE layer_id = $1`,
		layerID).Scan(&layerJSON); err != nil {
		t.Fatalf("the withdrawn row was deleted rather than marked: %v", err)
	}
	if !strings.Contains(layerJSON, hex.EncodeToString(shadowRoot)) {
		t.Fatal("the withdrawn row's claim was rewritten")
	}
}

// A binding to a root an anchor genuinely holds must be left alone.
func TestMigration019LeavesACanonicalBindingStanding(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql019 := migration019SQL(t)

	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(0x2f + (i % 5))
	}
	insertAnchorRootForTest(t, root, true)
	layerID := insertLayer5ForTest(t, root, "0x51a1c0de"+strings.Repeat("0", 56))

	if _, err := testDB.Exec(sql019); err != nil {
		t.Fatalf("re-running migration 019: %v", err)
	}
	if superseded, reason, _ := supersededState(t, layerID); superseded {
		t.Fatalf("a canonical binding was withdrawn: %s", reason)
	}
}

// The same root on BOTH a shadow row and a canonical one is a published root: the shadow row is a
// duplicate of it, not evidence against it.
func TestMigration019KeepsARootThatIsAlsoCanonical(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql019 := migration019SQL(t)

	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(0x7a + (i % 3))
	}
	insertAnchorRootForTest(t, root, false)
	insertAnchorRootForTest(t, root, true)
	layerID := insertLayer5ForTest(t, root, "0x51a1c0de"+strings.Repeat("1", 56))

	if _, err := testDB.Exec(sql019); err != nil {
		t.Fatalf("re-running migration 019: %v", err)
	}
	if superseded, reason, _ := supersededState(t, layerID); superseded {
		t.Fatalf("a root that IS canonical was withdrawn: %s", reason)
	}
}

// A root this database has no anchor row for at all is NOT withdrawn: canonical rows begin at migration
// 018 and the backfill fills the history afterwards. Withdrawing everything not yet backfilled would
// replace one wrong claim with thousands.
func TestMigration019DoesNotWithdrawRootsItSimplyHasNoRowFor(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql019 := migration019SQL(t)

	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(0x40 + (i % 11))
	}
	layerID := insertLayer5ForTest(t, root, "0xabcdef"+strings.Repeat("2", 58))

	if _, err := testDB.Exec(sql019); err != nil {
		t.Fatalf("re-running migration 019: %v", err)
	}
	if superseded, reason, _ := supersededState(t, layerID); superseded {
		t.Fatalf("a not-yet-backfilled binding was withdrawn: %s", reason)
	}
}

// Re-running the migration must not re-stamp rows it already withdrew, or withdraw anything new.
func TestMigration019IsIdempotent(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql019 := migration019SQL(t)

	shadowRoot := make([]byte, 32)
	for i := range shadowRoot {
		shadowRoot[i] = byte(0x90 + (i % 13))
	}
	insertAnchorRootForTest(t, shadowRoot, false)
	layerID := insertLayer5ForTest(t, shadowRoot, "0x9e4ff6ab"+strings.Repeat("3", 56))

	if _, err := testDB.Exec(sql019); err != nil {
		t.Fatal(err)
	}
	_, firstReason, _ := supersededState(t, layerID)
	var firstAt string
	if err := testDB.QueryRow(`SELECT superseded_at::text FROM chained_proof_layers WHERE layer_id=$1`,
		layerID).Scan(&firstAt); err != nil {
		t.Fatal(err)
	}

	if _, err := testDB.Exec(sql019); err != nil {
		t.Fatalf("second run: %v", err)
	}
	var secondAt string
	if err := testDB.QueryRow(`SELECT superseded_at::text FROM chained_proof_layers WHERE layer_id=$1`,
		layerID).Scan(&secondAt); err != nil {
		t.Fatal(err)
	}
	if secondAt != firstAt {
		t.Fatalf("re-running re-stamped the withdrawal: %s then %s", firstAt, secondAt)
	}
	if _, reason, _ := supersededState(t, layerID); reason != firstReason {
		t.Fatal("the recorded reason changed on a second run")
	}
}

// Seven validators upgrade at once; the migration must serialise rather than collide.
func TestMigration019IsSafeUnderConcurrentMigrators(t *testing.T) {
	_ = consensusRepoForTest(t)
	sql019 := migration019SQL(t)

	errs := make(chan error, 7)
	for i := 0; i < 7; i++ {
		go func() {
			_, err := testDB.Exec(sql019)
			errs <- err
		}()
	}
	for i := 0; i < 7; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent migrator %d: %v", i, err)
		}
	}

	var recorded int
	if err := testDB.QueryRow(
		`SELECT count(*) FROM schema_migrations WHERE version = $1`,
		"019_supersede_false_layer5_bindings").Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Fatalf("migration recorded %d times", recorded)
	}
}
