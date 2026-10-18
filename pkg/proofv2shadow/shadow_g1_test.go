// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"testing"
)

// RB9-I item 4: once the rules v15 activation is in force consensus refuses a 2.0 certificate (ErrIntentProofV21Missing), so the proof for an
// intent's certificate is evidence 2.1 for EVERY capture - the governing pages on one partition or several - and exactly then. Before the
// activation nothing changes: own-partition captures are 2.0, foreign ones are g1_evidence_21_not_in_force for a certificate.
func TestPlanBuildFromTheActivationEveryCertificateProofIsEvidence21(t *testing.T) {
	// A capture whose governing pages are all on the transaction's partition.
	w := world{}
	w.adi("cust.acme", 1)
	w.add(data("cust.acme", "pay", "acc://cust.acme/book"))
	g := newFakeNet(t, w)
	g.facts = facts("acc://cust.acme/pay")
	own, err := g.collect()
	if err != nil {
		t.Fatal(err)
	}
	if own.HasForeignPages() {
		t.Fatal("the own-partition capture reports a foreign page")
	}

	// Before the activation: a 2.0 document, unchanged.
	pl, err := planBuild(own, true, false)
	if err != nil || pl.is21 || len(pl.pages) != 3 {
		t.Fatalf("own-partition capture, activation not in force: %+v, %v", pl, err)
	}
	// In force: a certificate proof is 2.1 although every page is on one partition.
	pl, err = planBuild(own, true, true)
	if err != nil || !pl.is21 || len(pl.pages) != 0 {
		t.Fatalf("own-partition capture, activation in force: %+v, %v", pl, err)
	}
	// The background shadow build (not a certificate) is not changed by the activation: own-partition captures stay 2.0.
	pl, err = planBuild(own, false, true)
	if err != nil || pl.is21 || len(pl.pages) != 3 {
		t.Fatalf("own-partition shadow build, activation in force: %+v, %v", pl, err)
	}

	// A cross-partition capture: held by name before the activation, 2.1 from it.
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	foreign, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planBuild(foreign, true, false); err == nil {
		t.Fatal("a cross-partition certificate proof was planned before the activation")
	}
	if pl, err = planBuild(foreign, true, true); err != nil || !pl.is21 {
		t.Fatalf("cross-partition capture, activation in force: %+v, %v", pl, err)
	}
}
