package execution

import (
	"context"
	"os"
	"strings"
	"testing"
)

// =============================================================================
// A dropped member is recorded as failed WITH the reason it was dropped
// =============================================================================
//
// A member leaves the batch path for good when its account cannot participate, when the anchor
// mines but rejects the leaves, or when quorum over the root is never reached. There is no other
// path to settle it: it is attested as FAILED (owner decision 2026-09-26). The comments used to say
// such members "go to the per-intent path" - they never did - and the failure record always gave
// the same reason whatever the cause (RB3-F37). Each drop now carries its own cause to the caller.

func TestBatchFlushResult_DropRecordsTheCausePerMember(t *testing.T) {
	a := &PendingBatchIntent{IntentID: "a", ChainID: 84532}
	b := &PendingBatchIntent{IntentID: "b", ChainID: 84532}
	res := &BatchFlushResult{}
	res.drop("account 0xabc is not a CertenAccountV7", a)
	res.drop("quorum over root not reached after 5 attempts", b)
	if len(res.Dropped) != 2 {
		t.Fatalf("dropped=%d want 2", len(res.Dropped))
	}
	if got := res.DropCauseOf(a); got != "account 0xabc is not a CertenAccountV7" {
		t.Fatalf("cause of a = %q", got)
	}
	if got := res.DropCauseOf(b); got != "quorum over root not reached after 5 attempts" {
		t.Fatalf("cause of b = %q", got)
	}
}

func TestRouteDropped_HandsEachMemberItsOwnCause(t *testing.T) {
	a := &PendingBatchIntent{IntentID: "a", ChainID: 84532}
	b := &PendingBatchIntent{IntentID: "b", ChainID: 84532}
	res := &BatchFlushResult{}
	res.drop("cause-a", a)
	res.drop("cause-b", b)
	got := map[string]string{}
	routeDropped(context.Background(), 84532, res, func(_ context.Context, m *PendingBatchIntent, cause string) {
		got[m.IntentID] = cause
	}, func(string, ...interface{}) {})
	if got["a"] != "cause-a" || got["b"] != "cause-b" {
		t.Fatalf("causes routed = %v", got)
	}
}

// A drop with nowhere to go is a wiring defect, and it must say so rather than pass silently.
func TestRouteDropped_WithNoHandlerSaysTheMembersAreStranded(t *testing.T) {
	res := &BatchFlushResult{}
	res.drop("cause", &PendingBatchIntent{IntentID: "a", ChainID: 84532})
	var logged string
	routeDropped(context.Background(), 84532, res, nil, func(f string, a ...interface{}) { logged += f })
	if !strings.Contains(logged, "never be recorded") {
		t.Fatalf("an unwired drop handler must be reported loudly, got %q", logged)
	}
}

// Every drop site must go through res.drop, so no drop can lose its cause.
func TestEveryDropSiteRecordsItsCause(t *testing.T) {
	raw, err := os.ReadFile("batch_orchestrator.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, forbidden := range []string{"res.Dropped = ", "res.Dropped=", "res.Dropped = append("} {
		if strings.Contains(src, forbidden) {
			t.Errorf("batch_orchestrator.go assigns Dropped directly (%q); use res.drop(cause, ...)", forbidden)
		}
	}
	// The one append to Dropped is drop's own, which records the cause beside it.
	if n := strings.Count(src, "Dropped = append("); n != 1 {
		t.Errorf("Dropped is appended to in %d places; only drop may add to it", n)
	}
	if strings.Count(src, "res.drop(") < 3 {
		t.Errorf("expected the three drop sites (screening, leaf verification, quorum) to use res.drop")
	}
}
