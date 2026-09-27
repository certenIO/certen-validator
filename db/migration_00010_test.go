package schema

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
)

// RB3-F130: 00003 removed the 'already-exists' sentinel from anchor_create_tx but left the copy the quorum
// writer had put in anchor_tx_hash, and left that column unconstrained. Production held two such rows.
func TestMigration00010WithdrawsAndForbidsASentinelAnchorTx(t *testing.T) {
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		t.Fatal("CERTEN_TEST_DB is required: a skipped gate is not a green gate")
	}
	withThrowawayDatabase(t, conn, func(db *sql.DB) {
		ctx := context.Background()
		all, err := Migrations()
		if err != nil {
			t.Fatal(err)
		}
		var before []Migration
		for _, m := range all {
			if m.Version < "00010" {
				before = append(before, m)
			}
		}
		if err := (Runner{DB: db, catalog: before}).Up(ctx, "before-00010"); err != nil {
			t.Fatalf("migrate to 00009: %v", err)
		}
		const sentinel, real = "b0000000-0000-0000-0000-000000000001", "b0000000-0000-0000-0000-000000000002"
		realTx := "0x" + strings.Repeat("ab", 32)
		if _, err := db.ExecContext(ctx, `
			INSERT INTO anchor_batches (id, batch_type, status, merkle_root, chain_id, bundle_id, anchor_tx_hash)
			VALUES ($1, 'on_demand', 'confirmed', '\x01', 84532, '0x01', 'already-exists'),
			       ($2, 'on_demand', 'confirmed', '\x02', 84532, '0x02', $3)`, sentinel, real, realTx); err != nil {
			t.Fatalf("the production shape could not be planted: %v", err)
		}

		if err := (Runner{DB: db}).Up(ctx, "00010"); err != nil {
			t.Fatalf("migrate 00010: %v", err)
		}
		var stored sql.NullString
		if err := db.QueryRow(`SELECT anchor_tx_hash FROM anchor_batches WHERE id = $1`, sentinel).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored.Valid {
			t.Fatalf("the sentinel is still stored as the publishing transaction: %q", stored.String)
		}
		var previous, by string
		if err := db.QueryRow(`SELECT previous->>'anchor_tx_hash', corrected_by FROM evidence_corrections
			WHERE record_type = 'anchor_batch' AND record_id = $1`, sentinel).Scan(&previous, &by); err != nil {
			t.Fatalf("the withdrawn value has no correction record: %v", err)
		}
		if previous != "already-exists" || by != "migration 00010" {
			t.Fatalf("correction record previous=%q by=%q", previous, by)
		}
		if err := db.QueryRow(`SELECT anchor_tx_hash FROM anchor_batches WHERE id = $1`, real).Scan(&stored); err != nil || stored.String != realTx {
			t.Fatalf("a real transaction was changed: %q (%v)", stored.String, err)
		}
		var others int
		if err := db.QueryRow(`SELECT COUNT(*) FROM evidence_corrections WHERE record_id = $1`, real).Scan(&others); err != nil || others != 0 {
			t.Fatalf("a real transaction got a correction record: %d (%v)", others, err)
		}

		// And no writer can store one again.
		if _, err := db.ExecContext(ctx, `UPDATE anchor_batches SET anchor_tx_hash = 'already-exists' WHERE id = $1`, sentinel); err == nil {
			t.Fatal("a status word was accepted as the publishing transaction")
		}
	})
}
