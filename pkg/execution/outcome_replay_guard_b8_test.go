// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// V-R10B2 D1: the capture itself names s6_replay_unproven{receipt_unavailable} with no contract when no provider served the
// settlement transaction, and the S6 verifier accepts that zero contract for exactly that reason (s6replay3 SPEC section 3
// step 4, vector 004). Layer 6 must state it as not established - a named state - and must not refuse the member's whole
// evidence for it, nor rank it "does not verify".
func TestACarriedReceiptUnavailableStateWithoutAContractIsStatedNotRefused(t *testing.T) {
	m := newS6Member(t)
	rg := m.named()
	rg.State.Reason = ethproof.ReasonReceiptUnavailable
	rg.State.Contract = common.Address{}
	rg.State.Providers = nil
	rg.State.Detail = "no provider served the settlement transaction (rpc.example: not found)"
	m.ev.ReplayGuard = rg

	// The S6 verifier's own verdict, which layer 6 must agree with.
	if _, err := rg.VerifyAgainst(m.header, m.tx, true, nil); err != nil {
		t.Fatalf("the S6 verifier refuses the named state the capture produces: %v", err)
	}

	chk, err := m.check(t)
	if err != nil {
		t.Fatalf("the member's evidence is refused for a named state the capture produced: %v", err)
	}
	not := joined(chk.NotEstablished)
	if !strings.Contains(not, "S6:") || !strings.Contains(not, ethproof.ReasonReceiptUnavailable) || !strings.Contains(not, "block 100") {
		t.Fatalf("the named state is not stated as not established, with its reason and block:\n%s", not)
	}
	if est := joined(chk.Established); strings.Contains(est, "S6") {
		t.Fatalf("a named state is stated as established:\n%s", est)
	}
	if got := s6Outcome(t, m, rg, "").replayGuardStanding(); got != replayGuardNamed {
		t.Fatalf("the standing of the named state is %q, want %q", got, replayGuardNamed)
	}
}

// The exemption is the S6 verifier's own and no wider: the zero contract only for receipt_unavailable; another reason,
// another contract, another chain, or a proof still has to be the member's account on the outcome's chain.
func TestTheZeroContractExemptionIsReceiptUnavailableAndNothingWider(t *testing.T) {
	account := common.HexToAddress("0x1019dbd5b0fcd9e6e9b0000000000000000021ac")
	const chain = int64(84532)
	leaf := [32]byte{0x01}
	check := func(state, reason string, contract common.Address, chainID int64) error {
		return bindReplayGuard(&ethproof.ReplayGuardCheck{State: state, Reason: reason, ChainID: chainID, Contract: contract}, chain, account, leaf)
	}
	zero := common.Address{}
	other := common.HexToAddress("0x00000000000000000000000000000000000000cc")
	if err := check(ethproof.ReplayUnproven, ethproof.ReasonReceiptUnavailable, zero, chain); err != nil {
		t.Fatalf("receipt_unavailable with no contract is refused: %v", err)
	}
	if err := check(ethproof.ReplayUnproven, ethproof.ReasonReceiptUnavailable, account, chain); err != nil {
		t.Fatalf("receipt_unavailable with the member's account is refused: %v", err)
	}
	for _, c := range []struct {
		name            string
		state, reason   string
		contract        common.Address
		chainID         int64
		wantInTheReason string
	}{
		{"receipt_unavailable of another contract", ethproof.ReplayUnproven, ethproof.ReasonReceiptUnavailable, other, chain, "contract"},
		{"receipt_unavailable of another chain", ethproof.ReplayUnproven, ethproof.ReasonReceiptUnavailable, zero, chain + 1, "chain"},
		{"state_unavailable without a contract", ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, zero, chain, "contract"},
		{"capture_not_attempted_in_window without a contract", ethproof.ReplayUnproven, ethproof.ReasonCaptureNotAttempted, zero, chain, "contract"},
		{"settlement_block_mismatch without a contract", ethproof.ReplayUnproven, ethproof.ReasonBlockMismatch, zero, chain, "contract"},
		{"a refutation without a contract", ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent, zero, chain, "contract"},
		{"a missing event without a contract", ethproof.ReplayEventMissing, ethproof.ReasonNoEvent, zero, chain, "contract"},
		{"a proof without a contract", ethproof.ReplayProven, "", zero, chain, "contract"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := check(c.state, c.reason, c.contract, c.chainID)
			if err == nil || !strings.Contains(err.Error(), c.wantInTheReason) {
				t.Fatalf("want a refusal naming the %s, got %v", c.wantInTheReason, err)
			}
		})
	}
}

// V-R10B2 D3: the layer-6 document's own `member` key is read by its exact key, once. A case variant or a duplicate - which
// encoding/json would let silently replace the member and drop a proven guard - is refused by name; unrelated keys, and a
// `Member` nested in another object, are not.
func TestTheOutcomeEvidenceMemberKeyIsReadStrictly(t *testing.T) {
	m := newS6Member(t)
	m.ev.ReplayGuard = m.proven()
	honest := s6OutcomeDoc(t, m)
	raw, err := json.Marshal(honest)
	if err != nil {
		t.Fatal(err)
	}
	var back OutcomeEvidence
	if err := json.Unmarshal(raw, &back); err != nil || back.Member.ReplayGuard == nil || back.replayGuardStanding() != replayGuardProven {
		t.Fatalf("the honest document: %v guard=%v", err, back.Member.ReplayGuard != nil)
	}

	bare := honest.Member
	bare.ReplayGuard = nil
	bareJSON, err := json.Marshal(bare)
	if err != nil {
		t.Fatal(err)
	}
	with := func(extra string) []byte {
		return append(append(append([]byte(nil), raw[:len(raw)-1]...), ","+extra...), '}')
	}
	refused := []struct{ name, extra string }{
		{"reviewer: Member without a replay guard after the honest member", `"Member":` + string(bareJSON)},
		{"a second member without a replay guard", `"member":` + string(bareJSON)},
		{"MEMBER", `"MEMBER":` + string(bareJSON)},
		{"mEmBeR null", `"mEmBeR":null`},
		{"an escaped duplicate", `"m\u0065mber":` + string(bareJSON)},
		{"an escaped case variant", `"\u004dember":` + string(bareJSON)},
		{"the honest member twice", `"member":` + string(raw[bytes.Index(raw, []byte(`"member":`))+len(`"member":`):len(raw)-1])},
	}
	// The escaped cases are escaped (V-R10B3 D3): the text of the key is not "member"/"Member", and the decoder reads it as such.
	for name, want := range map[string]string{"an escaped duplicate": "member", "an escaped case variant": "Member"} {
		for _, c := range refused {
			if c.name != name {
				continue
			}
			if !strings.Contains(c.extra, `\u00`) {
				t.Fatalf("%s: the key is not escaped: %s", name, c.extra[:20])
			}
			var keys map[string]json.RawMessage
			if err := json.Unmarshal([]byte("{"+c.extra+"}"), &keys); err != nil || keys[want] == nil {
				t.Fatalf("%s: the escaped key does not decode to %q (err=%v, keys=%v)", name, want, err, len(keys))
			}
		}
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			var got OutcomeEvidence
			err := json.Unmarshal(with(c.extra), &got)
			if !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "member") {
				t.Fatalf("decoded (err=%v, guard=%v); want the document refused by name for its member key", err, got.Member.ReplayGuard != nil)
			}
		})
	}

	// Unrelated keys are not over-refused: a key the format does not know, a duplicate of another key (as encoding/json
	// always read it), the word member inside another value, and a nested Member under another object.
	accepted := []struct{ name, extra string }{
		{"an unknown top-level key", `"extra":1`},
		{"members, a different key", `"members":[1,2]`},
		{"a nested Member under another object", `"note":{"Member":{"x":1},"member":2}`},
		{"the word member in a string value", `"note":"the Member of the member"`},
	}
	for _, c := range accepted {
		t.Run(c.name, func(t *testing.T) {
			var got OutcomeEvidence
			if err := json.Unmarshal(with(c.extra), &got); err != nil {
				t.Fatalf("an unrelated key is refused: %v", err)
			}
			if got.Member.ReplayGuard == nil || got.replayGuardStanding() != replayGuardProven {
				t.Fatalf("the honest member's guard was lost")
			}
		})
	}
	var null OutcomeEvidence
	if err := json.Unmarshal([]byte(`{"version":"`+OutcomeEvidenceVersion+`"}`), &null); err != nil {
		t.Fatalf("a document without a member key is refused at decode, not by its verification: %v", err)
	}
}
