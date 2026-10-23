// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-DBFIX (Addendum C item 7): the capture loops' status rows name the pins the builder runs under, like the upgrader's.
func TestRTBaseLoopStatusRowsRecordThePinsHash(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := pins.Identity()
	l1 := &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	st := &rtStatus{}
	loop, _, _ := rtBaseLoop(t, l1, st)
	loop.Pins = pins
	if err := loop.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	row, ok := st.row(CaptureStatusProofID(finality.ChainBaseSepolia), finality.LevelL1Posted)
	if !ok || row.PinsSHA256 != want {
		t.Fatalf("row %+v (found %v): want pins %s recorded", row, ok, want)
	}
	// a loop that holds no pins records no identity rather than a wrong one
	l2 := &rtBaseL1{head: 100, failing: map[uint64]bool{99: true}}
	st2 := &rtStatus{}
	loop2, _, _ := rtBaseLoop(t, l2, st2)
	if err := loop2.Tick(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if row, _ := st2.row(CaptureStatusProofID(finality.ChainBaseSepolia), finality.LevelL1Posted); row.PinsSHA256 != "" {
		t.Fatalf("a loop with no pins recorded %q", row.PinsSHA256)
	}
}

// Wire hands the loops the pins it resolved: the loops it registers record the hash of exactly those pins.
func TestRTWireGivesTheCaptureLoopsThePinsItResolved(t *testing.T) {
	rtProviderEnv(t)
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	reg := finality.NewRegistry()
	st := &rtStatus{}
	w, err := Wire(cfg, Deps{Registry: reg, Store: finality.NewMemCaptureStore(), Status: st})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range reg.Capturers() {
		switch l := c.(type) {
		case *BasePostedLoop:
			n++
			if l.Pins != w.Pins {
				t.Errorf("Base capture loop pins %p, wiring pins %p", l.Pins, w.Pins)
			}
		case *ArbPostedLoop:
			n++
			if l.Pins != w.Pins {
				t.Errorf("Arbitrum capture loop pins %p, wiring pins %p", l.Pins, w.Pins)
			}
		}
	}
	if n != 2 {
		t.Fatalf("%d capture loops registered, want the Base and the Arbitrum one", n)
	}
}
