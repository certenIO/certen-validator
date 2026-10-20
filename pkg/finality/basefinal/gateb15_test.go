// Copyright 2026 Certen Protocol

package basefinal

import (
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// The pinned build of the game implementation is made for one AnchorStateRegistry (and, when pinned, one factory).
func TestTheGameImplementationPinNamesTheASRAndTheFactoryTheGraphProves(t *testing.T) {
	p := loadPins(t)
	// the pin carries no ASR: the row is incomplete, treated as absent
	q := clonePinsAll(p)
	var hash [32]byte
	for h, r := range q.Impl {
		if r.Role == RoleGameImpl && r.Version == "0.2.0" {
			hash = h
		}
	}
	o, err := BuildSynth(p, SynthSpec{})
	if err != nil {
		t.Fatal(err)
	}
	r := q.Impl[hash]
	r.ASR = [20]byte{}
	q.Impl[hash] = r
	_, err = Judge(q, o.A, o.Body, o.Leg, ethl1.FinalizedHead{})
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != RoleGameImpl {
		t.Errorf("no ASR pinned: %v", err)
	}
	// a pinned factory that is not the proven one (0.3.0 pins one), and the right one
	o3, err := BuildSynth(p, SynthSpec{Version: "0.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Judge(p, o3.A, o3.Body, o3.Leg, ethl1.FinalizedHead{}); err != nil {
		t.Fatalf("0.3.0 with its own ASR and factory: %v", err)
	}
	q = clonePinsAll(p)
	for h, r := range q.Impl {
		if r.Role == RoleGameImpl && r.Version == "0.3.0" {
			if r.DGF == ([20]byte{}) {
				t.Fatal("test assumption: the 0.3.0 row pins its factory")
			}
			r.DGF = [20]byte{0x55}
			q.Impl[h] = r
		}
	}
	_, err = Judge(q, o3.A, o3.Body, o3.Leg, ethl1.FinalizedHead{})
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != RoleGameImpl {
		t.Errorf("another factory: %v", err)
	}
	// the pins file: asr and dgf are read, an unreadable asr leaves the row incomplete
	m := baseSection(t)
	for _, v := range m["impl_pins"].(map[string]any) {
		row := v.(map[string]any)
		if row["role"] == RoleGameImpl && row["version"] == "0.3.0" {
			row["asr"] = "garbage"
		}
	}
	bp, err := ParsePins(pinsWith(t, m))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range bp.Impl {
		if r.Role == RoleGameImpl && r.Version == "0.3.0" && (r.ASR != [20]byte{} || r.Complete(bp.Layouts)) {
			t.Errorf("an unreadable asr must leave the row incomplete: %+v", r)
		}
	}
	good, err := ParsePins(pinsWith(t, baseSection(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range good.Impl {
		if r.Role == RoleGameImpl && (hexOf(r.ASR) != "0x2ff5cc82dbf333ea30d8ee462178ab1707315355" || r.Version == "0.3.0" && hexOf(r.DGF) != "0xd6e6dbf4f7ea0ac412fd8b65ed297e64bb7a06e1") {
			t.Errorf("%+v", r)
		}
	}
}
