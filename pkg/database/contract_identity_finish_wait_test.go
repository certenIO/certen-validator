package database

import (
	"testing"
	"time"
)

// Measured on the live system (2026-10-26): the proof row appeared 26 minutes after the settlement, so a finisher that waits 15 minutes gives up
// (no_proof) on every leg. The default must cover the measured delay with room to spare.
func TestDefaultFinishWaitCoversTheMeasuredProofRowDelay(t *testing.T) {
	if DefaultFinishWait < 45*time.Minute {
		t.Fatalf("DefaultFinishWait = %v, want at least 45m (the proof row took 26m after settlement on the live system)", DefaultFinishWait)
	}
}
