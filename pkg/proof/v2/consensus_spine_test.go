// Copyright 2026 Certen Protocol

package proofv2

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The spine as CERTEN's consensus state holds it: a genesis accepted only under the registry's incarnation, extended
// a chunk at a time, ends exactly where one walk from genesis over the same records ends.
func TestConsensusSpineMatchesTheWalk(t *testing.T) {
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}

	// A genesis under another incarnation is refused.
	other := fx.pin
	other[0] ^= 1
	if _, _, err := AcceptSpineGenesis(ir.Inputs, other, 1); err == nil || !strings.Contains(err.Error(), "not the registry's") {
		t.Fatalf("a genesis under another incarnation: %v", err)
	}

	gen, set, err := AcceptSpineGenesis(ir.Inputs, fx.pin, 10)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}

	// Extend in uneven chunks, as validators would submit them over time.
	for start := 0; start < len(fx.ar.Majors); {
		end := min(start+97, len(fx.ar.Majors))
		cps, sets, err := ExtendSpine(l, fx.ar.Majors[start:end], int64(100+start))
		if err != nil {
			t.Fatalf("extend %d..%d: %v", start+1, end, err)
		}
		l.Checkpoints = append(l.Checkpoints, cps...)
		l.Sets = append(l.Sets, sets...)
		start = end
	}

	// One walk from genesis over the same records.
	g, err := genesisValues(ir.Inputs.NetworkRecord, ir.Inputs.GlobalsRecord)
	if err != nil {
		t.Fatal(err)
	}
	walk, err := NewSpine(g, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range fx.ar.Majors {
		if err := walk.Advance(r); err != nil {
			t.Fatal(err)
		}
	}
	restored, err := SpineAt(l, uint64(len(fx.ar.Majors)))
	if err != nil {
		t.Fatal(err)
	}
	if restored.LastMinorBlock != walk.LastMinorBlock || restored.RootChainAnchor != walk.RootChainAnchor ||
		restored.StateTreeAnchor != walk.StateTreeAnchor || restored.NextMajor != walk.NextMajor ||
		restored.NetworkUpdates() != walk.NetworkUpdates() {
		t.Fatalf("restored %+v, walked %+v", restored, walk)
	}
	if len(l.Sets) != 1 {
		t.Fatalf("Kermit's set never changed, but the spine holds %d sets", len(l.Sets))
	}

	// The next extension must start at the next major block: replaying one already verified is refused.
	if _, _, err := ExtendSpine(l, fx.ar.Majors[len(fx.ar.Majors)-1:], 999); err == nil || !strings.Contains(err.Error(), "expected major block") {
		t.Fatalf("a replayed major block: %v", err)
	}
	// So is an extension that skips one.
	half := &ledger.AccumulateSpineLog{Genesis: gen, Sets: l.Sets, Checkpoints: l.Checkpoints[:100]}
	if _, _, err := ExtendSpine(half, fx.ar.Majors[101:110], 999); err == nil || !strings.Contains(err.Error(), "expected major block") {
		t.Fatalf("a skipped major block: %v", err)
	}
}
