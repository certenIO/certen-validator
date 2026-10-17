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

// ExportDocument carries everything but the major blocks, and adding the first MajorsNeeded records of the shared spine to it is
// exactly Export: the split a store relies on to keep the spine once and a document per proof.
func TestExportDocumentPlusSpineIsExport(t *testing.T) {
	fx := load(t)
	ir, err := fx.inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	whole, err := Export(fx.ev, fx.ar, ir.Inputs, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ExportDocument(fx.ev, ir.Inputs, fx.pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Majors) != 0 {
		t.Fatalf("the document carries %d major blocks; the spine is stored once, elsewhere", len(doc.Majors))
	}
	for _, m := range fx.ar.Majors[:MajorsNeeded(fx.ev)] {
		j, err := MajorJSON(m)
		if err != nil {
			t.Fatal(err)
		}
		doc.Majors = append(doc.Majors, j)
	}
	a, _ := json.Marshal(whole)
	b, _ := json.Marshal(doc)
	if string(a) != string(b) {
		t.Fatal("the document with the spine added is not what Export writes")
	}
	back := new(Portable)
	if err := json.Unmarshal(b, back); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPortable(back); err != nil {
		t.Fatalf("the assembled document does not verify: %v", err)
	}
	// a short archive is a named error, not a slice panic
	if _, err := Export(fx.ev, &Archive{Majors: fx.ar.Majors[:1]}, ir.Inputs, fx.pin); err == nil {
		t.Fatal("an archive shorter than the evidence needs was accepted")
	}
}
