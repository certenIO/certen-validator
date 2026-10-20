// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

func refusedReport(st *finality.StateError) finality.Report {
	return finality.Report{
		Block:    finality.BlockRef{Chain: finality.ChainSepolia, Number: 1},
		Levels:   map[finality.Level]finality.LevelStatus{finality.LevelIncluded: {Status: finality.StatusVerified}, finality.LevelFinalized: {Status: finality.StatusRefused, State: st}},
		Headline: finality.LevelIncluded,
	}
}

// Evidence anchored beyond the pins' ledger is not judged wrong, only not covered by the pins: the same summary-only class (exit 3) as a
// period the pins hold no entry for; evidence that fails any check, and a wrapped pin_unknown (unchanged by this change), stay FAILED.
func TestALedgerBehindRefusalIsSummaryOnlyLikePinUnknown(t *testing.T) {
	for name, tc := range map[string]struct {
		st   *finality.StateError
		want int
	}{
		"ledger behind":            {finality.NewState("finality_ledger_behind", "needed_period", uint64(1391), "ledger_head_period", uint64(1378)), exitSummaryOnly},
		"pin unknown":              {finality.NewState(finality.CodePinUnknown, "period", uint64(1300)), exitSummaryOnly},
		"unrecognised kind":        {finality.NewState(finality.CodeEvidenceUnrecognised, "kind", "x/y/v9", "version", "v9"), exitSummaryOnly},
		"wrapped ledger behind":    {finality.NewState("l1_finality_unproven", "reason", "lc_refused", "inner", "finality_ledger_behind"), exitSummaryOnly},
		"wrapped pin unknown":      {finality.NewState("l1_finality_unproven", "reason", "lc_refused", "inner", "finality_pin_unknown"), exitFailed},
		"wrapped signature":        {finality.NewState("l1_finality_unproven", "reason", "lc_refused", "inner", "finality_signature_invalid"), exitFailed},
		"signature invalid":        {finality.NewState("finality_signature_invalid", "index", 0), exitFailed},
		"pin mismatch":             {finality.NewState("finality_pin_mismatch", "period", uint64(1378)), exitFailed},
		"no state at all":          {nil, exitFailed},
		"wrapper without an inner": {finality.NewState("l1_finality_unproven", "reason", "lc_refused"), exitFailed},
	} {
		var out bytes.Buffer
		if got := printReport(&out, refusedReport(tc.st), "leg"); got != tc.want {
			t.Errorf("%s: exit %d, want %d\n%s", name, got, tc.want, out.String())
		}
		if tc.want == exitSummaryOnly && !strings.Contains(out.String(), "SUMMARY-ONLY") {
			t.Errorf("%s: %s", name, out.String())
		}
	}
}
