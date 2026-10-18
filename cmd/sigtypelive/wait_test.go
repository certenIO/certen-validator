package main

import (
	"testing"
	"time"
)

// RB8-E finding: a rerun waited too short for the lifecycle to be complete (6 minutes for the Accumulate certificate,
// about 20 for finality). Its default is 60 minutes; an explicit -wait is honoured; the other commands keep 5.
func TestRerunWaitsSixtyMinutesByDefault(t *testing.T) {
	if got := resolveWait("rerun", 0); got != 60*time.Minute {
		t.Fatalf("rerun default wait %s, want 60m", got)
	}
	if got := resolveWait("submit", 0); got != 5*time.Minute {
		t.Fatalf("submit default wait %s, want 5m", got)
	}
	if got := resolveWait("rerun", 90*time.Minute); got != 90*time.Minute {
		t.Fatalf("an explicit -wait was overridden: %s", got)
	}
}

// The whole rerun is bounded by its cases' waits, not by the 60 minutes that would cut the second case short.
func TestRerunsOverallTimeoutCoversEveryCasesWait(t *testing.T) {
	if got := overallTimeout("rerun", 60*time.Minute, "ed25519,rcd1,rsaSha256,ecdsaSha256"); got < 4*60*time.Minute {
		t.Fatalf("four cases at 60m each are cut off after %s", got)
	}
	if got := overallTimeout("submit", 5*time.Minute, ""); got != 60*time.Minute {
		t.Fatalf("submit overall %s", got)
	}
}
