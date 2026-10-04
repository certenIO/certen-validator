package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// RB6-F12: an intent left `authorized` with nothing executed is resolved to a named state - failed, processing_failed -
// only on facts the database holds at that moment (no member outcome, no anchored batch, no chain execution), and the
// state it replaces is kept as a correction. Anything that may have executed is never touched.
func TestAStaleAuthorizedIntentIsResolvedOnlyWhenNothingExecuted(t *testing.T) {
	if testDB == nil {
		t.Fatal("test database not configured")
	}
	ctx := context.Background()
	repo := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	old := time.Now().Add(-72 * time.Hour)
	intent := func(at time.Time) string {
		id := "rb6-f12-" + uuid.NewString()
		if _, err := testDB.ExecContext(ctx, `INSERT INTO intent_lifecycle (intent_id, accum_tx_hash, status, authorized_at, created_at, updated_at)
			VALUES ($1, $2, 'authorized', $3, $3, $3)`, id, uuid.NewString()[:16], at); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			testDB.Exec(`DELETE FROM evidence_corrections WHERE record_id = $1`, id)
			testDB.Exec(`DELETE FROM batch_transactions WHERE intent_id = $1`, id)
			testDB.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id)
			testDB.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, id)
		})
		return id
	}
	batch := func(intentID string, anchored bool) {
		id := uuid.New()
		var anchorTx *string
		if anchored {
			s := "0x" + strings.Repeat("ab", 32)
			anchorTx = &s
		}
		if _, err := testDB.ExecContext(ctx, `INSERT INTO anchor_batches (id, batch_type, status, merkle_root, transaction_count, tx_count, anchor_tx_hash,
			created_at, updated_at) VALUES ($1, 'on_demand', 'closed', $2, 1, 1, $3, NOW(), NOW())`, id, []byte{1}, anchorTx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { testDB.Exec(`DELETE FROM anchor_batches WHERE id = $1`, id) })
		if _, err := testDB.ExecContext(ctx, `INSERT INTO batch_transactions (batch_id, accumulate_tx_hash, account_url, tree_index, intent_id, created_at)
			VALUES ($1, $2, 'acc://x.acme', 0, $3, NOW())`, id, uuid.NewString()[:16], intentID); err != nil {
			t.Fatal(err)
		}
	}
	unbatched := intent(old)
	unanchored := intent(old)
	batch(unanchored, false)
	anchored := intent(old)
	batch(anchored, true)
	recent := intent(time.Now())
	withOutcome := intent(old)
	if _, err := repo.RecordMemberOutcome(ctx, MemberOutcome{IntentID: withOutcome, ReportedBy: "validator-3", ChainID: 84532, MemberChains: []int64{84532},
		Settlement: MemberSettlementNone, ProofCycle: MemberProofCycleFailed, Legs: 1}); err != nil {
		t.Fatal(err)
	}

	horizon := time.Now().Add(-24 * time.Hour)
	stale, err := repo.StaleIntents(ctx, horizon)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]StaleIntent{}
	for _, s := range stale {
		found[s.IntentID] = s
	}
	for _, id := range []string{recent, withOutcome} {
		if _, ok := found[id]; ok {
			t.Fatalf("%s listed: it is recent or has an outcome", id)
		}
	}
	status := func(id string) (st, class string) {
		var c *string
		testDB.QueryRow(`SELECT status, failure_class FROM intent_lifecycle WHERE intent_id = $1`, id).Scan(&st, &c)
		if c != nil {
			class = *c
		}
		return
	}
	for _, id := range []string{unbatched, unanchored, anchored} {
		s, ok := found[id]
		if !ok {
			t.Fatalf("%s not listed", id)
		}
		resolved, err := repo.ResolveStaleIntent(ctx, s, horizon, "operator-test")
		if err != nil {
			t.Fatal(err)
		}
		st, class := status(id)
		switch id {
		case anchored:
			if resolved || st != "authorized" {
				t.Fatalf("THE regression: an intent with an anchored batch was resolved (%v, %s)", resolved, st)
			}
		default:
			if !resolved || st != "failed" || class != "processing_failed" {
				t.Fatalf("a stale intent with nothing executed: resolved=%v %s / %s", resolved, st, class)
			}
			var kept int
			testDB.QueryRow(`SELECT count(*) FROM evidence_corrections WHERE record_type = 'intent_lifecycle' AND record_id = $1
				AND previous->>'status' = 'authorized'`, id).Scan(&kept)
			if kept != 1 {
				t.Fatalf("the replaced state of %s was not kept (%d)", id, kept)
			}
		}
	}
	// An intent anchored after it was listed is re-checked under its lock and left alone.
	late := intent(old)
	stale, _ = repo.StaleIntents(ctx, horizon)
	var listed StaleIntent
	for _, s := range stale {
		if s.IntentID == late {
			listed = s
		}
	}
	batch(late, true)
	if resolved, err := repo.ResolveStaleIntent(ctx, listed, horizon, "operator-test"); err != nil || resolved {
		t.Fatalf("an intent anchored since it was listed was resolved (%v, %v)", resolved, err)
	}
}
