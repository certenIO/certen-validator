// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// Deliverable 3 (RB10-F2 = PV2-F4): the L5 note names the generation of the account the evidence proves, never a fixed one.
func TestTheL5NoteNamesTheMembersAccountGeneration(t *testing.T) {
	v4 := newS6Member(t)
	chk, err := v4.check(t)
	if err != nil {
		t.Fatal(err)
	}
	not := joined(chk.NotEstablished)
	if !strings.Contains(not, "runs CertenAccountV7_3 code") || strings.Contains(not, "V7_2") {
		t.Fatalf("a v4 member's note does not name CertenAccountV7_3 (alone):\n%s", not)
	}

	v3 := newSynthMember(t, nil)
	v3.settle(synthSettlement(t, v3.chainID, 100, 1000, common.Hash{}, common.HexToAddress(v3.ev.Account), 1,
		[]*types.Log{v3.consumedLog(v3.anchor.bundleID)}), OutcomeExecuted, CommittedEffectsHash(nil, nil))
	if err := v3.verify(); err != nil {
		t.Fatal(err)
	}
	root, _ := v3.leaf.Hash()
	chk3 := &OutcomeEvidenceCheck{}
	if err := v3.ev.verify(v3.chainID, v3.anchor, root, chk3); err != nil {
		t.Fatal(err)
	}
	if not := joined(chk3.NotEstablished); !strings.Contains(not, "runs CertenAccountV7_2 code") || strings.Contains(not, "V7_3") {
		t.Fatalf("a v3 member's note does not name CertenAccountV7_2 (alone):\n%s", not)
	}

	// consumed under another anchor (status 4), v4
	el := newSynthMember(t, nil).asV4(t)
	el.settle(synthSettlement(t, el.chainID, 100, 1000, common.Hash{}, common.HexToAddress(el.ev.Account), 1,
		[]*types.Log{el.consumedLog([32]byte{0xee})}), OutcomeConsumedElsewhere, [32]byte{})
	if err := el.verify(); err != nil {
		t.Fatal(err)
	}
	root, _ = el.leaf.Hash()
	chk4 := &OutcomeEvidenceCheck{}
	if err := el.ev.verify(el.chainID, el.anchor, root, chk4); err != nil {
		t.Fatal(err)
	}
	if not := joined(chk4.NotEstablished); !strings.Contains(not, "runs CertenAccountV7_3 code") || strings.Contains(not, "V7_2") {
		t.Fatalf("a v4 member consumed elsewhere is not noted as CertenAccountV7_3 (alone):\n%s", not)
	}

	// The wording rule the TS port copies.
	for v, want := range map[AccountLeafVersion]string{AccountLeafV3: "CertenAccountV7_2", AccountLeafV4: "CertenAccountV7_3", "v9": "an unknown account generation"} {
		if got := v.AccountGeneration(); got != want {
			t.Fatalf("%q.AccountGeneration() = %q, want %q", v, got, want)
		}
	}
}

// s6Outcome wraps the member as the outcome evidence a proof's layer 6 holds.
func s6Outcome(t *testing.T, m *s6Member, rg *ethproof.ReplayGuardEvidence, agg string) *OutcomeEvidence {
	t.Helper()
	if err := m.verify(); err != nil {
		t.Fatal(err)
	}
	member := m.ev
	member.ReplayGuard = rg
	ev := &OutcomeEvidence{Version: OutcomeEvidenceVersion, ChainID: m.chainID,
		Anchor: OutcomeAnchorEvidence{BundleID: common.Hash(m.anchor.bundleID).Hex()}, Member: member}
	if agg != "" {
		ev.Quorum.AggregateSignature, ev.Quorum.AggregatePublicKey = agg, agg+"pk"
	}
	return ev
}

// Deliverable 2 (RB10-F1): two honest validators' evidence that differs only in the replay guard is one outcome.
func TestOutcomeEvidenceThatDiffersOnlyInTheReplayGuardIsOneOutcome(t *testing.T) {
	m := newS6Member(t)
	type rgOf func() *ethproof.ReplayGuardEvidence
	none := func() *ethproof.ReplayGuardEvidence { return nil }
	cases := []struct {
		name            string
		standing, fresh rgOf
		want            database.OutcomeLayerDecision
	}{
		{"none, then proven: supersedes", none, m.proven, database.OutcomeLayerSupersede},
		{"named, then proven: supersedes", m.named, m.proven, database.OutcomeLayerSupersede},
		{"not verifying, then proven: supersedes", m.notVerifying, m.proven, database.OutcomeLayerSupersede},
		{"proven, then none: kept", m.proven, none, database.OutcomeLayerKeep},
		{"proven, then named: kept", m.proven, m.named, database.OutcomeLayerKeep},
		{"proven, then proven otherwise (Before undisclosed vs proven): kept", m.proven, func() *ethproof.ReplayGuardEvidence {
			ev := m.proven()
			ev.Proof.Before, ev.Proof.BeforeUnavailable = nil, &ethproof.ReplayBeforeUnavailable{Reason: "state_unavailable"}
			return ev
		}, database.OutcomeLayerKeep},
		{"none, then not verifying: never supersedes", none, m.notVerifying, database.OutcomeLayerKeep},
		{"named, then not verifying: never supersedes", m.named, m.notVerifying, database.OutcomeLayerKeep},
		{"none, then named: kept", none, m.named, database.OutcomeLayerKeep},
		{"named, then none: kept", m.named, none, database.OutcomeLayerKeep},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			standing, _ := jsonMarshal(t, s6Outcome(t, m, c.standing(), ""))
			d, reason, err := decideOutcomeLayer(standing, s6Outcome(t, m, c.fresh(), ""))
			if err != nil {
				t.Fatalf("judged a contradiction: %v", err)
			}
			if d != c.want || (d == database.OutcomeLayerSupersede) != (reason != "") {
				t.Fatalf("decision %v (%q), want %v", d, reason, c.want)
			}
		})
	}

	t.Run("a pre-RB10 standing row without replayGuard is not a contradiction", func(t *testing.T) {
		ev := loadOutcomeFixture(t, 11155111)
		plain, _ := jsonMarshal(t, ev)
		if bytes.Contains(plain, []byte("eplay")) {
			t.Fatal("the pre-RB10 fixture carries a replay guard")
		}
		withRG := *ev
		leaf, err := ev.Member.Leaf.decode(ev.ChainID, mustEvHash(t, ev.Anchor.BundleID))
		if err != nil {
			t.Fatal(err)
		}
		withRG.Member.ReplayGuard = &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{
			State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: ev.ChainID, TxHash: leaf.Tx,
			BlockNumber: leaf.BlockNumber, BlockHash: leaf.BlockHash}}
		if d, _, err := decideOutcomeLayer(plain, &withRG); err != nil || d != database.OutcomeLayerKeep {
			t.Fatalf("a named state beside a pre-RB10 row: %v %v", d, err)
		}
		withRG.Member.ReplayGuard.State.TxHash = common.Hash{0x01} // does not verify against the settlement
		if d, _, err := decideOutcomeLayer(plain, &withRG); err != nil || d != database.OutcomeLayerKeep {
			t.Fatalf("a non-verifying replay guard beside a pre-RB10 row: %v %v", d, err)
		}
		other := withRG
		other.Member.Leaf.BlockNumber++
		if _, _, err := decideOutcomeLayer(plain, &other); err == nil {
			t.Fatal("another outcome, carrying a replay guard, was not a contradiction")
		}
	})

	t.Run("the aggregate and a proven replay guard held by different rows are merged, never one dropped", func(t *testing.T) {
		guardOnly, _ := jsonMarshal(t, s6Outcome(t, m, m.proven(), ""))
		aggOnly := s6Outcome(t, m, nil, "0xaa")
		d, _, merged, err := decideOutcomeLayerMerge(guardOnly, aggOnly)
		if err != nil || d != database.OutcomeLayerKeep || merged == nil || merged.Quorum.AggregateSignature != "0xaa" ||
			merged.replayGuardStanding() != replayGuardProven {
			t.Fatalf("guard standing, aggregate fresh: %v %v merged=%v", d, err, merged != nil)
		}
		if d, _, _, err := decideOutcomeLayerMerge(guardOnly, merged); err != nil || d != database.OutcomeLayerSupersede {
			t.Fatalf("the union does not supersede the guard-only row: %v %v", d, err)
		}
		aggRow, _ := jsonMarshal(t, aggOnly)
		d, _, merged, err = decideOutcomeLayerMerge(aggRow, s6Outcome(t, m, m.proven(), ""))
		if err != nil || d != database.OutcomeLayerKeep || merged == nil || merged.Quorum.AggregateSignature != "0xaa" ||
			merged.replayGuardStanding() != replayGuardProven {
			t.Fatalf("aggregate standing, guard fresh: %v %v", d, err)
		}
		if d, _, _, err := decideOutcomeLayerMerge(aggRow, merged); err != nil || d != database.OutcomeLayerSupersede {
			t.Fatalf("the union does not supersede the aggregate-only row: %v %v", d, err)
		}
		both := s6Outcome(t, m, m.proven(), "0xaa")
		if d, _, _, err := decideOutcomeLayerMerge(guardOnly, both); err != nil || d != database.OutcomeLayerSupersede {
			t.Fatalf("aggregate and guard over guard-only: %v %v", d, err)
		}
	})
}

func jsonMarshal(t *testing.T, v interface{}) ([]byte, error) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b, nil
}

func mustEvHash(t *testing.T, s string) [32]byte {
	t.Helper()
	h, err := evHash(s, "test")
	if err != nil {
		t.Fatal(err)
	}
	return h
}
