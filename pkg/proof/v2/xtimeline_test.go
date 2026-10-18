// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// RB9 Phase C1b-1: the certified timeline. Every case is a whole document of the timeline world (xworld.Timeline): a real
// transaction, BankPage1 with a scripted history folded into its proven main chain, a signature chain whose index chain places the
// key signature in its arrival block.

func tl(t *testing.T, s xworld.Timeline, mut func(*proofv2.Evidence)) (*proofv2.Report, error) {
	t.Helper()
	return runX(t, xworld.Options{Timeline: &s}, mut)
}

func codes(rep *proofv2.Report) []string {
	var out []string
	for _, u := range rep.Unproven {
		out = append(out, u.Code)
	}
	return out
}

// The valid timeline document: the history folds, the replay ends in the proven page, the arrival block is DERIVED from the
// signature-index chain, the vote model reproduces the recorded vote and the authority is ready. Nothing but the production of the
// vote (a HoldUntil release could have produced it later) is left unproven.
func TestTimelineValidDocumentVerifiesAndDerivesTheArrival(t *testing.T) {
	rep, err := tl(t, xworld.Timeline{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(rep); strings.Join(got, ",") != proofv2.StateVoteHeld {
		t.Fatalf("unproven %v, want only %s", got, proofv2.StateVoteHeld)
	}
	if rep.AuthorizationMode != proofv2.ModeAuthoritiesRequired {
		t.Fatalf("mode %q", rep.AuthorizationMode)
	}
	if len(rep.Arrivals) != 1 || rep.Arrivals[0].Block != xworld.HopBlock || rep.Arrivals[0].Account != xworld.BankPage1 {
		t.Fatalf("arrivals %+v, want the key signature on %s derived at block %d", rep.Arrivals, xworld.BankPage1, xworld.HopBlock)
	}
}
