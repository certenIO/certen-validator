// Copyright 2026 Certen Protocol

package execution

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// V-R10B D1: whatever arrives, the row that ends up attached holds the better of the two BLS aggregates and the better of
// the two replay guards (invalid < none < named < proven: a guard that does not verify refuses the whole layer, so it is
// worse than none). Every rank pair x aggregate up / same / down.
func TestTheAttachedOutcomeRowKeepsTheBetterGuardAndTheAggregate(t *testing.T) {
	m := newS6Member(t)
	rank := map[replayGuardRank]int{replayGuardInvalid: 0, replayGuardAbsent: 1, replayGuardNamed: 2, replayGuardProven: 3}
	guards := []struct {
		name string
		of   func() *ethproof.ReplayGuardEvidence
	}{
		{"invalid", m.notVerifying},
		{"none", func() *ethproof.ReplayGuardEvidence { return nil }},
		{"named", m.named},
		{"proven", m.proven},
	}
	aggs := []struct{ name, standing, fresh string }{
		{"aggregate up", "", "0xaa"},
		{"aggregate same (none)", "", ""},
		{"aggregate same (held)", "0xaa", "0xaa"},
		{"aggregate down", "0xaa", ""},
	}
	for _, sg := range guards {
		for _, fg := range guards {
			for _, ag := range aggs {
				t.Run(fmt.Sprintf("%s then %s, %s", sg.name, fg.name, ag.name), func(t *testing.T) {
					standing := s6Outcome(t, m, sg.of(), ag.standing)
					fresh := s6Outcome(t, m, fg.of(), ag.fresh)
					raw, _ := jsonMarshal(t, standing)
					d, reason, merged, err := decideOutcomeLayerMerge(raw, fresh)
					if err != nil {
						t.Fatalf("judged a contradiction: %v", err)
					}
					attached := standing
					switch {
					case d == database.OutcomeLayerSupersede && merged == nil:
						attached = fresh
					case d == database.OutcomeLayerKeep && merged != nil:
						attached = merged
					case d == database.OutcomeLayerKeep:
					default:
						t.Fatalf("decision %v with merged=%v", d, merged != nil)
					}
					if (d == database.OutcomeLayerSupersede) != (reason != "") {
						t.Fatalf("decision %v gives reason %q", d, reason)
					}
					sr, fr, ar := standing.replayGuardStanding(), fresh.replayGuardStanding(), attached.replayGuardStanding()
					best := sr
					if rank[fr] > rank[sr] {
						best = fr
					}
					if ar != best {
						t.Fatalf("the attached row's guard is %q; the standing was %q and the fresh %q (decision %v, merged=%v)", ar, sr, fr, d, merged != nil)
					}
					wantAgg := ag.standing
					if wantAgg == "" {
						wantAgg = ag.fresh
					}
					if attached.Quorum.AggregateSignature != wantAgg {
						t.Fatalf("the attached row's aggregate is %q, want %q", attached.Quorum.AggregateSignature, wantAgg)
					}
					// Nothing better is ever replaced by the same or worse.
					if d == database.OutcomeLayerSupersede && rank[fr] < rank[sr] {
						t.Fatalf("a %q guard superseded a %q one", fr, sr)
					}
					if merged != nil {
						// the union is attached by a second decide, which must supersede the standing row
						if d2, _, m2, err := decideOutcomeLayerMerge(raw, merged); err != nil || d2 != database.OutcomeLayerSupersede || m2 != nil {
							t.Fatalf("the union does not supersede the standing row: %v %v merged=%v", d2, err, m2 != nil)
						}
					}
				})
			}
		}
	}
}

// V-R10B D3: member.replayGuard is read by its exact key, once; a duplicate or a case variant is refused by name.
func TestTheMembersReplayGuardKeyIsReadStrictly(t *testing.T) {
	m := newS6Member(t)
	valid, err := json.Marshal(m.proven())
	if err != nil {
		t.Fatal(err)
	}
	base, err := json.Marshal(s6Outcome(t, m, nil, "").Member)
	if err != nil {
		t.Fatal(err)
	}
	with := func(extra string) []byte {
		return append(append(append([]byte(nil), base[:len(base)-1]...), ","+extra...), '}')
	}
	refused := []struct{ name, extra string }{
		{"reviewer: replayGuard bogus then replayguard null", `"replayGuard":{"version":"bogus","proof":7},"replayguard":null`},
		{"reviewer: replayGuard bogus then replayGuard null", `"replayGuard":{"version":"bogus"},"replayGuard":null`},
		{"reviewer: replayGuard garbage then ReplayGuard valid", `"replayGuard":"garbage","ReplayGuard":` + string(valid)},
		{"ReplayGuard alone", `"ReplayGuard":` + string(valid)},
		{"replayguard alone", `"replayguard":` + string(valid)},
		{"REPLAYGUARD null", `"REPLAYGUARD":null`},
		{"valid twice", `"replayGuard":` + string(valid) + `,"replayGuard":` + string(valid)},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			var got OutcomeMemberEvidence
			err := json.Unmarshal(with(c.extra), &got)
			if err == nil || !strings.Contains(err.Error(), "replayGuard") {
				t.Fatalf("decoded (err=%v, guard=%v); want a refusal naming member.replayGuard", err, got.ReplayGuard != nil)
			}
		})
	}
	var ok OutcomeMemberEvidence
	if err := json.Unmarshal(with(`"replayGuard":`+string(valid)), &ok); err != nil || ok.ReplayGuard == nil || ok.ReplayGuard.Proof == nil {
		t.Fatalf("the exact key once is refused: %v", err)
	}
	var none OutcomeMemberEvidence
	if err := json.Unmarshal(base, &none); err != nil || none.ReplayGuard != nil {
		t.Fatalf("no key: %v", err)
	}
	var null OutcomeMemberEvidence
	if err := json.Unmarshal(with(`"replayGuard":null`), &null); err != nil || null.ReplayGuard != nil {
		t.Fatalf("the exact key, null: %v", err)
	}
}

// V-R10B D5: layer 6 holds the S6 key to the member's own leaf and the proof to the member's own account. A receipt in
// which the account emits LeafConsumed for another leaf too does not let that leaf's slot stand for the member's.
func TestTheReplayGuardIsBoundToTheMembersLeafAndAccount(t *testing.T) {
	other := common.Hash{0x0b, 0x0e, 0xef}
	t.Run("the proof of another leaf's slot from the same receipt is refused", func(t *testing.T) {
		m := newS6MemberProving(t, &other)
		m.ev.ReplayGuard = m.proven()
		_, err := m.check(t)
		if !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "the member's leaf") {
			t.Fatalf("want the evidence refused for a key that is not the member's leaf, got %v", err)
		}
	})
	t.Run("the member's own slot from the same receipt is proven", func(t *testing.T) {
		m := newS6MemberProving(t, nil)
		m.ev.ReplayGuard = m.proven()
		if _, err := m.check(t); err != nil {
			t.Fatalf("the member's own slot refused: %v", err)
		}
	})
	t.Run("a named state of another contract is refused", func(t *testing.T) {
		m := newS6Member(t)
		ev := m.named()
		ev.State.Contract = common.HexToAddress("0x00000000000000000000000000000000000000cc")
		m.ev.ReplayGuard = ev
		// RB10-B7: ethproof now holds a named state to the transaction's target itself (s6replay3 SPEC §3), so the
		// refusal comes before layer 6's account binding, as contract_mismatch.
		if _, err := m.check(t); !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "contract_mismatch") ||
			!strings.Contains(err.Error(), "0x00000000000000000000000000000000000000cc") {
			t.Fatalf("want a refusal contract_mismatch naming the stated contract, got %v", err)
		}
	})
	t.Run("a named state of another chain is refused", func(t *testing.T) {
		m := newS6Member(t)
		ev := m.named()
		ev.State.ChainID = m.chainID + 1
		m.ev.ReplayGuard = ev
		if _, err := m.check(t); !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "chain") {
			t.Fatalf("want a refusal naming the chain, got %v", err)
		}
	})
}

// V-R10B D5, build side: the capture is keyed by the settlement transaction. When the guard it holds proves another
// leaf's slot of that transaction, the member's evidence carries the named state slot_mismatch for its own leaf - never
// the other leaf's proof, which layer 6 refuses.
func TestTheBuiltEvidenceCarriesOnlyAGuardOfTheMembersOwnLeaf(t *testing.T) {
	other := common.Hash{0x0b, 0x0e, 0xef}
	m := newS6MemberProving(t, &other)
	m.ev.ReplayGuard = replayGuardForLeaf(m.proven(), m.leaf)
	if m.ev.ReplayGuard == nil || m.ev.ReplayGuard.State == nil || m.ev.ReplayGuard.State.Reason != ethproof.ReasonSlotMismatch ||
		m.ev.ReplayGuard.State.State != ethproof.ReplayUnproven {
		t.Fatalf("another leaf's proof was not replaced by the named state slot_mismatch: %+v", m.ev.ReplayGuard)
	}
	chk, err := m.check(t)
	if err != nil {
		t.Fatalf("the member's evidence with the named state is refused: %v", err)
	}
	if not := joined(chk.NotEstablished); !strings.Contains(not, "slot_mismatch") {
		t.Fatalf("the named state is not stated as not established:\n%s", not)
	}
	own := newS6Member(t)
	if rg := replayGuardForLeaf(own.proven(), own.leaf); rg == nil || rg.Proof == nil {
		t.Fatalf("the member's own proof was not kept: %+v", rg)
	}
	if rg := replayGuardForLeaf(nil, own.leaf); rg != nil {
		t.Fatalf("no guard became %+v", rg)
	}
}
