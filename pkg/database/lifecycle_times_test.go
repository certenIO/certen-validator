package database

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// RB4-F73: the lifecycle's submitted_at and authorized_at are stated facts about the intent - when it was submitted, and
// when Accumulate executed it. Discovery wrote the validator's own clock into both. Now authorized_at is the time of the
// partition block the intent executed in (RB4-F74), and submitted_at - on no chain, known to no validator - is not stated.
func TestLifecycleTimesAreNotTheValidatorsClock(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	lifecycle := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	run := time.Now().UnixNano()
	single, multiID := fmt.Sprintf("f73-intent-%d", run), fmt.Sprintf("f73-multi-%d", run)
	executed := time.Date(2026, 9, 28, 21, 25, 3, 0, time.UTC)
	if err := lifecycle.UpsertOnDiscovery(ctx, single, single+"-tx", 7, executed, "", "on_demand", "base-sepolia"); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.UpsertOnDiscoveryMultiLeg(ctx, multiID, multiID+"-tx", 7, time.Time{}, "", "on_demand",
		"base-sepolia", []string{"84532", "421614"}, 2, "sequential"); err != nil {
		t.Fatal(err)
	}
	lc, err := lifecycle.GetByIntentID(ctx, single)
	if err != nil {
		t.Fatal(err)
	}
	if lc.SubmittedAt != nil {
		t.Errorf("submitted_at is %v: a validator cannot know when the intent was submitted", lc.SubmittedAt)
	}
	if lc.AuthorizedAt == nil || !lc.AuthorizedAt.Equal(executed) {
		t.Errorf("authorized_at is %v, not the time of the block it executed in %v", lc.AuthorizedAt, executed)
	}
	multi, err := lifecycle.GetByIntentID(ctx, multiID)
	if err != nil {
		t.Fatal(err)
	}
	if multi.SubmittedAt != nil || multi.AuthorizedAt != nil {
		t.Errorf("an unknown block time is stated as %v / %v, not left unstated", multi.SubmittedAt, multi.AuthorizedAt)
	}
}
