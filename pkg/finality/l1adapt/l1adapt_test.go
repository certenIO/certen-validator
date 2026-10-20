// Copyright 2026 Certen Protocol

package l1adapt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func TestPinsCarryEveryEmbeddedSepoliaPinIntoTheL1HeadVerifier(t *testing.T) {
	fp, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	e, err := fp.Sepolia()
	if err != nil {
		t.Fatal(err)
	}
	got, err := PinsOf(fp)
	if err != nil {
		t.Fatal(err)
	}
	if got.Network.ChainID != e.ChainID || len(got.Network.Forks) != len(e.Forks) || len(got.Anchors) != len(e.Anchors) {
		t.Fatalf("chain %d forks %d anchors %d, pins have %d %d %d", got.Network.ChainID, len(got.Network.Forks), len(got.Anchors), e.ChainID, len(e.Forks), len(e.Anchors))
	}
	if got.MinParticipants != e.MinParticipants || got.MaxLinks != e.MaxLinks || got.MaxSpineHeaders != e.MaxSpineHeaders {
		t.Fatalf("bounds %d %d %d, pins have %d %d %d", got.MinParticipants, got.MaxLinks, got.MaxSpineHeaders, e.MinParticipants, e.MaxLinks, e.MaxSpineHeaders)
	}
	if got.Network.GenesisValidatorsRoot == ([32]byte{}) {
		t.Fatal("the genesis validators root was dropped")
	}
	for i, f := range e.Forks {
		g := got.Network.Forks[i]
		v, _ := hex.DecodeString(strings.TrimPrefix(f.Version, "0x"))
		want := ethl1.LayoutNone
		if f.Layout != nil {
			switch *f.Layout {
			case "electra":
				want = ethl1.LayoutElectra
			case "gloas":
				want = ethl1.LayoutGloas
			}
		}
		if g.Name != f.Name || g.Epoch != f.Epoch || !bytes.Equal(g.Version[:], v) || g.Layout != want {
			t.Fatalf("fork %d: %+v from %+v", i, g, f)
		}
	}
	for i, a := range e.Anchors {
		g := got.Anchors[i]
		if g.Period != a.Period || g.WSPEpochs != a.WspEpochs || g.CommitteeRoot == ([32]byte{}) {
			t.Fatalf("anchor %d: %+v from %+v", i, g, a)
		}
		if (a.BlockRoot != "") != (g.BlockRoot != nil) {
			t.Fatalf("anchor %d: block root presence differs", i)
		}
	}
}

func TestPinsOfWithoutTheSepoliaSectionIsPinUnknownNotAZeroPins(t *testing.T) {
	_, err := PinsOf(&finality.Pins{})
	s, ok := finality.AsNamed(err)
	if !ok || s.Code != finality.CodePinUnknown {
		t.Fatalf("%v", err)
	}
	if _, err := PinsOf(nil); err == nil {
		t.Fatal("nil pins were converted")
	}
}

func TestPinsLeaveAMalformedHexFieldZeroInsteadOfDecodingItLoosely(t *testing.T) {
	e := &finality.EthSepoliaPins{ChainID: 11155111, GenesisValidatorsRoot: "0X" + "ab"}
	if got := Pins(e); got.Network.GenesisValidatorsRoot != ([32]byte{}) {
		t.Fatalf("a malformed root decoded to %x", got.Network.GenesisValidatorsRoot)
	}
}

func TestFaultStateKeepsTheCodeAndEveryFieldAndStateLeavesOtherErrorsAlone(t *testing.T) {
	f := ethl1.HeaderChainBroken("l2", 7, [32]byte{1}, [32]byte{2}, "hash")
	s := FaultState(f)
	if s.Code != f.Code || len(s.Fields) != len(f.Fields) {
		t.Fatalf("%v from %v", s, f)
	}
	for k, v := range f.Fields {
		if s.Fields[k] != v {
			t.Fatalf("field %s: %v, want %v", k, s.Fields[k], v)
		}
	}
	if st, ok := State(f).(*finality.StateError); !ok || st.Code != f.Code {
		t.Fatalf("State(fault) = %v", State(f))
	}
	other := errors.New("not a fault")
	if State(other) != other {
		t.Fatal("a non-fault error was rewritten")
	}
	if State(nil) != nil {
		t.Fatal("nil became an error")
	}
	named := finality.NewState(finality.CodePinUnknown)
	if State(named) != error(named) {
		t.Fatal("a named state was rewritten")
	}
}
