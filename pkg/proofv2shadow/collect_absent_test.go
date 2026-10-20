// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-C2-F1: an authority the principal lists that does not exist at the capture block (the executor allows a DISABLED one: it can
// neither be required nor vote) is a book no receipt of the evidence can prove absent, while the verifier and BindProofV21 require every
// listed authority to be a proven book. A capture that noted it and went on built a 2.1 document the binding then refused, late and
// without saying where. The capture records it as a proven-absent fact (partition and block it was judged at) and a 2.1 build is
// refused by name at once; a 2.0 build (own-partition pages, rules before the activation) is exactly what it was.

// absentWorld: cust.acme/pay lists bank.acme/book (BVN2) and its own book, and ghost.acme/book - which does not exist - on ghostOn.
func absentWorld(t *testing.T, ghostOn string, ghostDisabled bool) *fakeNet {
	t.Helper()
	w := world{}
	w.adi("cust.acme", 1).adi("bank.acme", 2)
	pay := data("cust.acme", "pay", "acc://bank.acme/book", "acc://ghost.acme/book", "acc://cust.acme/book")
	pay.Authorities[1].Disabled = ghostDisabled
	if ghostOn == "BVN1" { // an intent whose pages are all on the transaction's own partition: no bank
		pay = data("cust.acme", "pay", "acc://ghost.acme/book", "acc://cust.acme/book")
		pay.Authorities[0].Disabled = ghostDisabled
	}
	w.add(pay)
	f := newFakeNet(t, w)
	f.part["ghost.acme"] = ghostOn
	f.facts = facts("acc://cust.acme/pay")
	return f
}

func asState(t *testing.T, what string, err error) *proofv2.NamedState {
	t.Helper()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) {
		t.Fatalf("%s: %v is not a named state", what, err)
	}
	return ns
}

// A capture that holds pages on another partition is a 2.1 document: the missing disabled authority is refused by name, with the
// partition and block the absence was judged at and the authority's URL.
func TestCaptureOfForeignPagesRefusesAMissingDisabledAuthorityByName(t *testing.T) {
	f := absentWorld(t, "BVN2", true)
	c, err := f.collect()
	if err == nil {
		t.Fatal("the capture noted a nonexistent disabled authority and went on")
	}
	ns := asState(t, "capture", err)
	if ns.Code != proofv2.StateAuthorityMissing || ns.Partition != "BVN2" || ns.Block != c.Partitions["BVN2"].Block || ns.Block == 0 {
		t.Fatalf("not named where it was judged: %+v (BVN2 captured at %d)", ns, c.Partitions["BVN2"].Block)
	}
	if !strings.Contains(ns.Detail, "acc://ghost.acme/book") {
		t.Fatalf("the authority is not named: %q", ns.Detail)
	}
	if !c.HasForeignPages() || len(c.Absent) != 1 || c.Absent[0].Code != proofv2.StateAuthorityMissing {
		t.Fatalf("the proven-absent fact is not carried by the capture: %+v", c.Absent)
	}
	// The 2.1 assembly never starts from such a capture.
	_, aerr := c.Assembly(context.Background(), fakeLog{f}, nil)
	if as := asState(t, "assembly", aerr); as.Code != proofv2.StateAuthorityMissing || as.Partition != "BVN2" || as.Block != ns.Block {
		t.Fatalf("assembly gave %+v", as)
	}
}

// An own-partition capture is a 2.0 document until the activation: the capture succeeds exactly as before (the stored 2.0 verdict of
// such an intent does not change), carries the fact, and the 2.1 assembly - the only path after the activation - refuses it by name.
func TestOwnPartitionCaptureKeepsItsTwoZeroPlanButNo21AssemblyForAMissingDisabledAuthority(t *testing.T) {
	f := absentWorld(t, "BVN1", true)
	c, err := f.collect()
	if err != nil {
		t.Fatalf("the 2.0 capture of an intent with a nonexistent disabled authority changed: %v", err)
	}
	if c.HasForeignPages() {
		t.Fatal("the own-partition world captured a foreign page")
	}
	if len(c.Absent) != 1 || c.Absent[0].Partition != "BVN1" || c.Absent[0].Block != f.block {
		t.Fatalf("the fact is not carried where it was judged: %+v", c.Absent)
	}
	if len(c.Notes) == 0 {
		t.Fatal("the note a 2.0 capture always carried is gone")
	}
	pl, err := planBuild(c, true, false)
	if err != nil || pl.is21 || len(pl.pages) == 0 {
		t.Fatalf("the 2.0 plan changed: %+v, %v", pl, err)
	}
	_, aerr := c.Assembly(context.Background(), fakeLog{f}, nil)
	if as := asState(t, "assembly", aerr); as.Code != proofv2.StateAuthorityMissing || as.Partition != "BVN1" || as.Block != f.block ||
		!strings.Contains(as.Detail, "acc://ghost.acme/book") {
		t.Fatalf("assembly gave %+v", as)
	}
}

// An ENABLED authority that does not exist stays what it was - the capture stops with the same named state - and now says where.
func TestCaptureOfAMissingEnabledAuthorityIsTheSameNamedStateWithWhereItWasJudged(t *testing.T) {
	f := absentWorld(t, "BVN2", false)
	_, err := f.collect()
	ns := asState(t, "capture", err)
	if ns.Code != proofv2.StateAuthorityMissing || !strings.Contains(ns.Detail, "acc://ghost.acme/book") {
		t.Fatalf("the enabled case changed: %+v", ns)
	}
	if ns.Partition != "BVN2" || ns.Block == 0 {
		t.Fatalf("not named where it was judged: %+v", ns)
	}
}

// A capture of intents with no missing authority carries no such fact: its stored form (omitempty) is unchanged.
func TestCaptureWithEveryAuthorityPresentCarriesNoAbsentFact(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	c, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Absent) != 0 {
		t.Fatalf("%+v", c.Absent)
	}
}
