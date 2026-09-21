// The lifecycle an ADI's intent ends in when its settlement REVERTED - against a real PostgreSQL
// through the production repository, addressed by CERTEN_TEST_DB exactly as Gate 1c is.
//
//	go test ./pkg/execution/ -run 'TestS1_FailedReverted' -count=1 -v
package execution

import (
	"context"
	"strings"
	"testing"
)

// A cycle that proved and wrote back a reverted settlement ends the intent FAILED, carrying the
// reverted transaction and the write-back that recorded it - not "complete".
func TestS1_FailedRevertedSettlementIsNotComplete(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	const intentID = "s1-reverted"
	s1Seed(ctx, t, db, intentID)

	o.updateLifecycleReverted(ctx, intentID, "cycle-1",
		"0x54562d54d6c38a858fda1bdd9cffb95cffb688b2f2f685468ba4752ddd3c8b0b", "writeback-tx")
	status, _, _, completed, failed := s1Status(t, db, intentID)
	if status != "failed" || failed == nil || completed != nil {
		t.Fatalf("status %q completed %v failed %v; want failed, never completed", status, completed, failed)
	}
	var msg, wb string
	if err := db.QueryRow(`SELECT error_message, write_back_tx FROM intent_lifecycle WHERE intent_id=$1`, intentID).Scan(&msg, &wb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "0x54562d54") || wb != "writeback-tx" {
		t.Fatalf("error_message %q write_back_tx %q", msg, wb)
	}
}
