package execution

import (
	"context"
	"testing"
)

// =============================================================================
// Phase 9 says whether the result was WRITTEN - never "success" for a write that did not happen
// =============================================================================
//
// WriteBackSuccess was set true when write-back was disabled by configuration, and when a
// multi-leg chain group only deferred its write-back to the aggregator - even with no aggregator
// to defer to, and even when the aggregator returned an error. It feeds the governance flags
// ("write_back_success"), so each of those recorded a write-back that never happened. (The multi-leg
// hand-off state went with the multi-leg aggregator: every cycle is one chain member's, RB3-F45.)

func phase9Cycle() *activeCycle {
	return &activeCycle{
		CycleID: "cycle-1",
		Request: &UnifiedProofCycleRequest{IntentID: "i1", Metadata: map[string]string{}},
		Result:  &UnifiedProofCycleResult{ThresholdMet: true},
	}
}

func TestPhase9_DisabledWriteBackIsNotRecordedAsWritten(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{EnableWriteBack: false}}
	c := phase9Cycle()
	if err := o.executePhase9(context.Background(), c); err != nil {
		t.Fatalf("disabled write-back is a stated mode, not a failure: %v", err)
	}
	if c.Result.WriteBackSuccess {
		t.Fatal("write-back disabled by configuration was recorded as a successful write-back")
	}
	if c.Result.WriteBackState != WriteBackDisabledByConfiguration {
		t.Fatalf("write-back state = %q, want %q", c.Result.WriteBackState, WriteBackDisabledByConfiguration)
	}
}

func TestPhase9_QuorumNotMetRecordsTheRefusal(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{EnableWriteBack: true}}
	c := phase9Cycle()
	c.Result.ThresholdMet = false
	if err := o.executePhase9(context.Background(), c); err == nil {
		t.Fatal("write-back without quorum must be refused")
	}
	if c.Result.WriteBackSuccess || c.Result.WriteBackState != WriteBackRefusedQuorumNotMet {
		t.Fatalf("state = %q success = %v", c.Result.WriteBackState, c.Result.WriteBackSuccess)
	}
}
