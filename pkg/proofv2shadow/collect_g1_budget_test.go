// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"context"
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9-F6, B1 (V-J, owner-decided 2026-10-19): after the rules v15 activation a one-partition capture is built as evidence 2.1 (planBuild with
// prove and allow21), so its capture-time closure budget is judged for evidence 2.1, the form the build and the signing produce - not for
// evidence 2.0, whose threshold is stricter. Before the activation the capture is judged exactly as before. The signal is the one planBuild
// takes (Collector.G1InForce, fed by intent.ProofV2G1Gate); a capture with pages on other partitions is evidence 2.1 either way.

// oneDataWorld is a customer's data account on BVN1 under its own book, with a latest entry of n bytes: a one-partition closure whose pages
// are about 2n bytes of hex.
func oneDataWorld(n int) world {
	w := world{}
	w.adi("cust.acme", 1)
	a := data("cust.acme", "pay", "acc://cust.acme/book")
	if n > 0 {
		a.Entry = &protocol.DoubleHashDataEntry{Data: [][]byte{make([]byte, n)}}
	}
	w.add(a)
	return w
}

func collectWith(t *testing.T, w world, g1 func() (bool, error)) (*Capture, error) {
	t.Helper()
	f := newFakeNet(t, w)
	f.facts = facts("acc://cust.acme/pay")
	c := f.collector()
	c.G1InForce = g1
	return c.Collect(context.Background(), f.facts.Principal.String(), strings.Repeat("ab", 32))
}

func inForce(v bool) func() (bool, error) { return func() (bool, error) { return v, nil } }

func wantClosureLimit(t *testing.T, err error, limit string) {
	t.Helper()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateClosureExceedsBudget || !strings.Contains(ns.Detail, "limit="+limit) {
		t.Fatalf("got %v, want g1_closure_exceeds_budget{limit=%s}", err, limit)
	}
}

// A one-partition capture of ~400,000 bytes (in the gap between the evidence 2.0 threshold, 190,272, and the evidence 2.1 one, 680,896): refused
// as 2.0 before the activation exactly as before, admitted as 2.1 after it. One that fits neither is refused by the named closure state of the
// form it will be built in.
func TestCaptureClosureBudgetFollowsTheActivation(t *testing.T) {
	gap := oneDataWorld(200_000)

	cp, err := collectWith(t, gap, nil)
	wantClosureLimit(t, err, "950272")
	if cp == nil || len(cp.Pages) == 0 || cp.HasForeignPages() {
		t.Fatalf("the capture is not kept, or is not a one-partition capture: %v", cp)
	}
	if _, err := collectWith(t, gap, inForce(false)); err == nil {
		t.Fatal("before the activation a closure in the gap was admitted")
	} else {
		wantClosureLimit(t, err, "950272")
	}
	if cp, err := collectWith(t, gap, inForce(true)); err != nil || cp == nil || cp.BudgetVersionFor(true) != proofv2.Version21 {
		t.Fatalf("after the activation a one-partition closure that fits evidence 2.1 was refused: %v", err)
	}

	huge := oneDataWorld(400_000) // ~800,000 bytes of pages: over both thresholds
	_, err = collectWith(t, huge, inForce(false))
	wantClosureLimit(t, err, "950272")
	_, err = collectWith(t, huge, inForce(true))
	wantClosureLimit(t, err, "720896")

	// An activation that cannot be read is the capture's soft error, by name; the capture is kept and no form is assumed.
	cp, err = collectWith(t, gap, func() (bool, error) { return false, errors.New("the committed state is unreadable") })
	if err == nil || !strings.Contains(err.Error(), "not judged") || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("an unreadable activation: %v", err)
	}
	if cp == nil || len(cp.Pages) == 0 {
		t.Fatal("the capture was not kept")
	}
}

// The whole-certificate check is the evidence 2.1 one and now applies at capture to a one-partition closure after the activation: pages that fit
// the evidence cap but whose certificate (evidence + R scaled by the pages) does not fit the transaction path are certificate_budget.
func TestCaptureWholeCertificateIsJudgedForAOnePartitionClosureAfterTheActivation(t *testing.T) {
	cp, err := collectWith(t, oneDataWorld(0), nil)
	if err != nil {
		t.Fatal(err)
	}
	page := cp.Pages[0]
	page.State = strings.Repeat("a", 650_000/16)
	cp.Pages = nil
	for i := 0; i < 16; i++ {
		cp.Pages = append(cp.Pages, page)
	}
	if err := cp.checkClosureBudgetFor(false); err == nil {
		t.Fatal("a one-partition closure of ~650,000 bytes is inside the evidence 2.0 threshold")
	} else {
		wantClosureLimit(t, err, "950272")
	}
	err = cp.checkClosureBudgetFor(true)
	var cs *proofv2.CertifyState
	if !errors.As(err, &cs) || cs.Code != proofv2.StateCertificateBudget {
		t.Fatalf("got %v, want certificate_budget{size,limit}", err)
	}
}

// BudgetVersionFor is planBuild's form: for a certificate's proof (prove) the same combination of capture and activation gives the same version.
func TestBudgetVersionForIsPlanBuildsForm(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	foreign, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	own, err := collectWith(t, oneDataWorld(0), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, cp := range map[string]*Capture{"own": own, "foreign": foreign} {
		for _, allow21 := range []bool{false, true} {
			plan, perr := planBuild(cp, true, allow21)
			is21 := perr != nil || plan.is21 // the refusal g1_evidence_21_not_in_force is a 2.1 document that may not be certified yet
			want := proofv2.Version
			if is21 {
				want = proofv2.Version21
			}
			if got := cp.BudgetVersionFor(allow21); got != want {
				t.Errorf("%s capture, activation %v: the budget is judged as %s, planBuild builds %s", name, allow21, got, want)
			}
		}
		// the shadow (not a certificate) builds 2.1 for a foreign capture only, whatever the activation
		plan, _ := planBuild(cp, false, false)
		if got, want := cp.BudgetVersion() == proofv2.Version21, plan.is21; got != want {
			t.Errorf("%s capture, no certificate: BudgetVersion %s, planBuild is21 %v", name, cp.BudgetVersion(), plan.is21)
		}
	}
}
