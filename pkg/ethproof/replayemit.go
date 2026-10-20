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

// storedFormLen is the length of the text form PostgreSQL's jsonb writes for the compact JSON raw: the form
// chained_proof_layers.layer_json is read back in, and so the form a layer-6 member's replayGuard document reaches
// DecodeReplayGuardEvidence in. jsonb prints one space after every ':' and every ',' that is outside a string; that is all
// it adds. It also SHORTENS some text inside strings, which storedFormLen does not measure: the Go encoder writes < > & and
// U+2028/U+2029 as six-byte escapes and an invalid UTF-8 byte as the six-byte escape of U+FFFD, and PostgreSQL writes the
// characters themselves (one byte for each of < > &, three for the others). So for the documents this type marshals (it has no
// float or number that jsonb rewrites) the stored form is never longer than
// storedFormLen says: the guard over-measures, the safe direction (measured by V-R10B8 on PostgreSQL 16: a text with 50 < and
// 50 & is 1707 bytes measured and 707 stored, U+2028 549 and 537, invalid UTF-8 569 and 551). For text without those
// characters the length is exact. A NUL byte in a string is refused by PostgreSQL altogether (BoundProviderText removes
// them). It is computed by expanding raw outside its strings, one byte at a time, without building the expanded document.
func storedFormLen(raw []byte) int {
	n, inString, escaped := len(raw), false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case inString:
			if c == '\x5c' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
		case c == ':' || c == ',':
			n++
		}
	}
	return n
}

// replayEmitProblem is why ev cannot be emitted as JSON within the bound, or "" when it can. The bound is measured on the form
// the evidence is stored and read back in (storedFormLen), which is longer than the compact form it is marshalled in.
func replayEmitProblem(ev *ReplayGuardEvidence) string {
	if ev == nil {
		return ""
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return "the evidence cannot be encoded: " + BoundProviderText(err.Error())
	}
	if stored := storedFormLen(raw); stored > MaxReplayEvidenceBytes {
		return fmt.Sprintf("the evidence would be %d bytes, more than the %d the format allows", stored, MaxReplayEvidenceBytes)
	}
	return ""
}

// BoundReplayEvidence is ev when its stored form (the jsonb text a layer-6 member is read back in: the compact JSON with a
// space after every ':' and ',' outside a string, see storedFormLen) is at most
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
// form the emitter writes it (an indented proof file is longer than the stored form BoundReplayEvidence measures, so its
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
