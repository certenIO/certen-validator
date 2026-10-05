// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/json"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// The portable form round-trips: exporting the live Kermit proof and verifying what is read back gives the same
// report as verifying the evidence itself.
func TestPortableRoundTrip(t *testing.T) {
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	want, err := Verify(fx.ev, fx.ar, fx.inc, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Export(fx.ev, fx.ar, ir.Inputs, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	back := new(Portable)
	if err := json.Unmarshal(j, back); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyPortable(back)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertifiedBlock != want.CertifiedBlock || got.CertifiedRoot != want.CertifiedRoot || got.AnchorBlock != want.AnchorBlock ||
		len(got.Pages) != len(want.Pages) || got.SetVerdict != want.SetVerdict || got.CheckBlock != want.CheckBlock {
		t.Fatalf("portable %+v\nevidence %+v", got, want)
	}
	if got.SetVerdict != proof.VerdictVerified {
		t.Fatalf("set verdict %s", got.SetVerdict)
	}
}
