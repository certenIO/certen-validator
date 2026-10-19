// Copyright 2026 Certen Protocol

package proofv2shadow

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-F5 package F5-4b (V-I D2, RB9-F5 invariant 2): the capture's closure budget is judged for the document form the capture becomes. A capture
// of one partition's pages is evidence 2.0, whose threshold on pages + votes is the one it always had (950,272 - 760,000 = 190,272 bytes); a
// capture with pages on other partitions is evidence 2.1, whose threshold is 720,896 - 40,000 = 680,896. A one-partition closure in the gap
// is refused g1_closure_exceeds_budget at capture exactly as before.
func TestCaptureClosureBudgetIsJudgedForTheDocumentForm(t *testing.T) {
	f := newFakeNet(t, tclWorld())
	f.facts = facts("acc://cust.acme/pay")
	foreign, err := f.collect()
	if err != nil {
		t.Fatal(err)
	}
	if !foreign.HasForeignPages() || foreign.BudgetVersion() != proofv2.Version21 {
		t.Fatalf("a capture with foreign pages is evidence 2.1, got %q", foreign.BudgetVersion())
	}

	w := world{}
	w.adi("cust.acme", 1)
	w.add(data("cust.acme", "pay", "acc://cust.acme/book"))
	g := newFakeNet(t, w)
	g.facts = facts("acc://cust.acme/pay")
	own, err := g.collect()
	if err != nil {
		t.Fatal(err)
	}
	if own.HasForeignPages() || own.BudgetVersion() != proofv2.Version {
		t.Fatalf("a one-partition capture is evidence 2.0, got %q", own.BudgetVersion())
	}

	// Pad the first page so that pages + votes are 400,000 bytes: in the gap 190,272..680,896.
	pad := func(c *Capture) {
		pages := make([]proofv2.PageState, len(c.Pages))
		for i := range c.Pages {
			pages[i] = c.Pages[i].PageState
		}
		n := 0
		for i := range pages {
			n += len(mustJSON(t, &pages[i]))
		}
		n += len(mustJSON(t, c.Votes))
		c.Pages[0].State += strings.Repeat("a", 400_000-n)
	}
	pad(own)
	err = own.checkClosureBudget()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateClosureExceedsBudget || !strings.Contains(ns.Detail, "limit=950272") {
		t.Fatalf("a one-partition closure of 400,000 bytes (evidence 2.0): %v, want g1_closure_exceeds_budget{limit=950272}", err)
	}
	pad(foreign)
	if err := foreign.checkClosureBudget(); err != nil {
		t.Fatalf("a cross-partition closure of 400,000 bytes (evidence 2.1, inside its 680,896 threshold and its whole-certificate estimate): %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
