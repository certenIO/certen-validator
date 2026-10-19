// Copyright 2026 Certen Protocol

package proofv2

import (
	"errors"
	"testing"
)

// RB9-F6 on real data: the evidence 2.1 document captured live from Kermit (testdata/xpartition3/real-bvn1-billing-receipts) is in the
// continuous form. Offline AND by the spine-log entry point consensus calls it is refused certify_link_missing{genesis} until it carries the
// receipt from the pinned genesis root chain anchor to its certified root; Kermit's recorded answer to exactly that question verifies it by
// both, with one and the same report.
func TestRealContinuousEvidence21NeedsItsGenesisLink(t *testing.T) {
	r := loadReal21(t)
	if len(r.ev.Links) != 0 {
		t.Fatalf("the fixture is not in the continuous form: %d links", len(r.ev.Links))
	}
	with, err := Verify21FromGenesis(r.ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatalf("with Kermit's recorded genesis answer: %v", err)
	}
	l := spineOf(t, r)
	got, err := VerifyEvidence21FromSpine(r.ev, l, r.pin)
	if err != nil {
		t.Fatalf("the spine entry point with the genesis link: %v", err)
	}
	if reportJSON(t, got) != reportJSON(t, with) {
		t.Fatal("the spine entry point's report differs from the offline walk's")
	}

	bare := r.clone(t)
	bare.GenesisLink = ""
	for name, verify := range map[string]func() error{
		"offline": func() error { _, err := Verify21FromGenesis(bare, r.ar, r.in, r.pin); return err },
		"spine":   func() error { _, err := VerifyEvidence21FromSpine(bare, l, r.pin); return err },
	} {
		var cs *CertifyState
		if err := verify(); !errors.As(err, &cs) || cs.Code != StateCertifyLinkMissing || len(cs.Fields) != 1 || cs.Fields[0] != "genesis" {
			t.Fatalf("%s: the real continuous document without a genesis link: %v, want certify_link_missing{genesis}", name, err)
		}
	}
}
