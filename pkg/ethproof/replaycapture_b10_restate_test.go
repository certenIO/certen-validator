// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// RB10-B10 (V-R10B3 note): evidence that carries both a proof and a named state is refused by the verifier ("exactly one
// of"); holding it to the settlement must return it as it is and let the verifier refuse it by name, never convert it
// into a state-only evidence that verifies with the proof dropped.
func TestCapturer_EvidenceWithBothAProofAndAStateIsRefusedNotRestated(t *testing.T) {
	w := replayworld.New(t, replayworld.Opts{After: 1})
	store := ethproof.NewReplayGuardStore(16)
	cp := ethproof.NewReplayGuardCapturer(ethproof.ReplayCaptureConfig{ChainID: replayworld.ChainID, Budget: 50 * time.Millisecond, Poll: time.Millisecond}, store)
	both := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: w.Proof, State: &ethproof.ReplayNamedState{
		State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: replayworld.ChainID, TxHash: w.Tx.Hash(),
		Detail: "a capture that stated no block and no contract"}}
	store.Put(replayworld.ChainID, w.Tx.Hash(), both, false)
	out := cp.Resolve(w.Settlement)
	if out == nil || out.State == nil || out.Proof != nil || out.State.State != ethproof.ReplayUnproven || out.State.Reason != ethproof.ReasonEmptyEvidence ||
		!strings.Contains(out.State.Detail, "exactly one of") {
		t.Fatalf("evidence with a proof and a state is not refused by name: %+v", out)
	}
	cp.Bind(w.Settlement)
	if ev := waitStored(t, store, replayworld.ChainID, w.Tx.Hash(), true); ev.State == nil || ev.State.Reason != ethproof.ReasonEmptyEvidence {
		t.Fatalf("Bind kept evidence of a proof and a state: %+v", ev)
	}
}
