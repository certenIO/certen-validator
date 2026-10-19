// Copyright 2026 Certen Protocol

package proofv2

import (
	"errors"
	"testing"
)

// RB9-F6 on real data: the evidence 2.1 document captured live from Kermit (testdata/xpartition3/real-bvn1-billing-receipts) is in the
// continuous form. Offline it is refused certify_link_missing{genesis} until it carries the receipt from the pinned genesis root chain anchor
// to its certified root - Kermit's recorded answer to exactly that question verifies it, and gives the report it always had - while the
// spine-log entry point, which takes its starting points from the chain's own log, judges the document without the link as it always did.
func TestRealContinuousEvidence21NeedsItsGenesisLinkOffline(t *testing.T) {
	r := loadReal21(t)
	if len(r.ev.Links) != 0 {
		t.Fatalf("the fixture is not in the continuous form: %d links", len(r.ev.Links))
	}
	with, err := Verify21FromGenesis(r.ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatalf("with Kermit's recorded genesis answer: %v", err)
	}

	bare := r.clone(t)
	bare.GenesisLink = ""
	_, err = Verify21FromGenesis(bare, r.ar, r.in, r.pin)
	var cs *CertifyState
	if !errors.As(err, &cs) || cs.Code != StateCertifyLinkMissing || len(cs.Fields) != 1 || cs.Fields[0] != "genesis" {
		t.Fatalf("the real continuous document without a genesis link: %v, want certify_link_missing{genesis}", err)
	}

	got, err := VerifyEvidence21FromSpine(bare, spineOf(t, r), r.pin)
	if err != nil {
		t.Fatalf("the spine entry point refused the real continuous document without the link: %v", err)
	}
	if reportJSON(t, got) != reportJSON(t, with) {
		t.Fatal("the spine entry point's report for the document without the link differs from the offline report of the document with it")
	}
}
