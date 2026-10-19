// Copyright 2026 Certen Protocol

package ethproof

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// The emission guard (RB10-B13)
// =============================================================================
//
// The producer never emits S6 evidence its own verifier refuses. DecodeReplayGuardEvidence refuses a document longer than
// MaxReplayEvidenceBytes (and so does the layer-6 member decoder, which reads the replayGuard member through it), so
// evidence the capture stored at that length would turn a disclosed named state into a refusal of the member's whole
// layer 6. Free text a provider served is bounded where it is built (BoundProviderText) and the providers listed are
// bounded; this is the last guard for what is still longer - a provider padding its eth_getProof answer with nodes the
// walk ignores, say - and for evidence that cannot be encoded at all.

// replayEmitProblem is why ev cannot be emitted as JSON within the bound, or "" when it can.
func replayEmitProblem(ev *ReplayGuardEvidence) string {
	if ev == nil {
		return ""
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return "the evidence cannot be encoded: " + BoundProviderText(err.Error())
	}
	if len(raw) > MaxReplayEvidenceBytes {
		return fmt.Sprintf("the evidence would be %d bytes, more than the %d the format allows", len(raw), MaxReplayEvidenceBytes)
	}
	return ""
}

// BoundReplayEvidence is ev when its wire form (the JSON a stored layer-6 member and a proof file carry) is at most
// MaxReplayEvidenceBytes, and otherwise the named state s6_replay_unproven{state_unavailable} saying why, built from what ev
// itself states of the settlement block and contract (chainID and tx are the settlement's). ev is never changed. Nil
// evidence (no S6 claim) stays nil.
func BoundReplayEvidence(ev *ReplayGuardEvidence, chainID int64, tx common.Hash) *ReplayGuardEvidence {
	why := replayEmitProblem(ev)
	if why == "" {
		return ev
	}
	return UnemittableReplayEvidence(ev, chainID, tx, why)
}

// UnemittableReplayEvidence is the named state that stands for evidence that cannot be emitted for the reason why, in the
// form the emitter writes it (an indented proof file is longer than the compact form BoundReplayEvidence measures, so its
// writer states its own reason). The block and contract are those ev states.
func UnemittableReplayEvidence(ev *ReplayGuardEvidence, chainID int64, tx common.Hash, why string) *ReplayGuardEvidence {
	st := &ReplayNamedState{State: ReplayUnproven, Reason: ReasonStateUnavailable, ChainID: chainID, TxHash: tx}
	switch {
	case ev != nil && ev.Proof != nil:
		st.BlockNumber, st.BlockHash, st.Contract = ev.Proof.SettlementBlock.Number, ev.Proof.SettlementBlock.Hash, ev.Proof.Contract
	case ev != nil && ev.State != nil:
		st.BlockNumber, st.BlockHash, st.Contract = ev.State.BlockNumber, ev.State.BlockHash, ev.State.Contract
		why += fmt.Sprintf(" (it was %s{reason=%s})", ev.State.State, BoundProviderText(ev.State.Reason))
	}
	st.Detail = BoundProviderText(why)
	return &ReplayGuardEvidence{Version: ReplayGuardDomain, State: st}
}
