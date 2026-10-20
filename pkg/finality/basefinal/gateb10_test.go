// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// Both provers present: ignoring the failed read of one of the two keys would leave the other, and the game would be accepted.
func TestEverySlotTheJudgeReadsRefusesAValueThatIsNotAWordWhenBothProversAreSet(t *testing.T) {
	p := loadPins(t)
	base := SynthSpec{K: 3, Depth: 4, TEE: bl(true), ZK: bl(true)}
	if _, err := judgeSpec(t, p, base); err != nil {
		t.Fatalf("the base world must be accepted: %v", err)
	}
	refs, _ := worldRefs(t, p, base)
	for _, r := range refs {
		for name, leaf := range map[string][]byte{"33 bytes": rlpBytes(make([]byte, 33)), "empty string": {0x80}, "a list": {0xc0}} {
			r, leaf := r, leaf
			spec := base
			spec.Tweak = func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetRaw(r.addr, r.slot, leaf) }
			_, err := judgeSpec(t, p, spec)
			if got := canonOf(t, err); got != `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}` {
				t.Errorf("slot %x of %x as %s: %s", r.slot, r.addr, name, got)
			}
		}
	}
}

// A slot of an account that is proven absent is the refusal of the account, not of the slot.
func TestASlotOfAProvenAbsentAccountIsTheRefusalOfTheAccount(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetAbsent(SynthAddrs.SUP) }})
	if err != nil {
		t.Fatal(err)
	}
	rd := newStateReader(o.Body.Nodes, o.A.StateRoot)
	_, err = rd.slot(SynthAddrs.SUP, mapSlot(be32(0), 0))
	if got := canonOf(t, err); got != `{"code":"l1_state_proof_invalid","fields":{"which":"account"}}` {
		t.Errorf("%s", got)
	}
}

// A game_impl row that does not carry everything the predicates need is no row: the builder does not choose it.
func TestTheBuilderDoesNotChooseAnIncompleteGameImplementationRow(t *testing.T) {
	w := loadLive(t)
	m := baseSection(t)
	for _, v := range m["impl_pins"].(map[string]any) {
		row := v.(map[string]any)
		if row["role"] == RoleGameImpl {
			row["slow_finalization_delay"] = 0
		}
	}
	// an empty store: a row chosen by the builder would go on to a capture (a wait), the refusal must come before
	b := w.builder(t, &MemStore{})
	b.Pins = pinsWith(t, m)
	_, p, err := w.built(t, b)
	if p != nil {
		t.Errorf("an incomplete row was chosen: %+v", p)
	}
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != RoleGameImpl {
		t.Errorf("%v", err)
	}
}

// The factory scan starts at the estimate and walks; where it starts and where it gives up are observable.
func TestTheFactoryScanStartsAtTheEstimateAndNamesAGapBetweenGames(t *testing.T) {
	lay := loadLive(t).bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	x := binary.BigEndian.Uint64(loadLive(t).body.GameCode[tl+84+24 : tl+84+32])
	// the estimate equals the index: the scan starts at the newest game and needs five loads to reach the oldest; two are allowed
	w := loadLive(t)
	b := w.builder(t, w.store(t))
	b.Games = w.factory(5, 0, 600)
	b.MaxScan = 2
	_, p, err := w.built(t, b)
	if err == nil || !strings.Contains(err.Error(), "did not reach the covering game") || p != nil {
		t.Errorf("%v %v", p, err)
	}
	// a block between two games is covered by neither: the scan flips between them until its bound, it does not claim there is no
	// game above
	w2 := loadLive(t)
	b2 := w2.builder(t, w2.store(t))
	b2.Games = w2.factory(30, 28, 700)
	gap := w2.leg
	gap.Number = x + 50
	_, p, err = b2.buildLeg(context.Background(), gap, haveIncluded)
	if err == nil || !strings.Contains(err.Error(), "did not reach the covering game") || p != nil {
		t.Errorf("%v %v", p, err)
	}
}
