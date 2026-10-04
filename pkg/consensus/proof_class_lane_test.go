// Copyright 2026 Certen Protocol

package consensus

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// RB3-F74: a member's proof class is the lane that settled - or dropped - it, and the signed intent's
// declared class is never guessed.

func TestProofCycle_CarriesTheLaneThatSettledIt(t *testing.T) {
	for _, lane := range []string{"on_cadence", "on_demand"} {
		orch := &routeOrchestrator{}
		bv := failureTestValidator(orch)
		att := &PendingAttestation{IntentID: "i1", Replayed: true,
			CertenIntent: memberIntent(t, leg("base-sepolia", 84532, "0x"))}
		bv.RunBatchMemberAttestation(context.Background(), att, settledTx, 84532, true, lane)
		if got := orch.commitment["proofClass"]; got != lane {
			t.Fatalf("settled in the %s lane, the cycle states proofClass %v", lane, got)
		}

		orch = &routeOrchestrator{}
		bv = failureTestValidator(orch)
		att = &PendingAttestation{IntentID: "i1", Replayed: true,
			CertenIntent: memberIntent(t, leg("base-sepolia", 84532, "0x"))}
		bv.RunBatchMemberRefusal(context.Background(), att, 84532, "dropped", "", lane)
		if got := orch.commitment["proofClass"]; got != lane {
			t.Fatalf("dropped from the %s lane, the failure record states proofClass %v", lane, got)
		}
	}
}

func TestAnUndeclaredProofClassIsRefusedNotGuessed(t *testing.T) {
	for _, priority := range []string{"high", "normal", ""} {
		body, _ := json.Marshal(map[string]interface{}{"intent_id": "i1", "priority": priority})
		ci := &CertenIntent{IntentID: "i1", IntentData: body}
		if err := ci.ExtractAndSetProofClass(); err == nil || !strings.Contains(err.Error(), "declares no proof_class") {
			t.Fatalf("priority %q: an intent declaring no proof class was given %q (%v)", priority, ci.ProofClass, err)
		}
	}
	body, _ := json.Marshal(map[string]interface{}{"intent_id": "i1", "proof_class": "on_cadence", "priority": "high"})
	ci := &CertenIntent{IntentID: "i1", IntentData: body}
	if err := ci.ExtractAndSetProofClass(); err != nil || ci.ProofClass != "on_cadence" {
		t.Fatalf("the declared class: %q %v", ci.ProofClass, err)
	}
}
