// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/execution"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// The recorded ON-CHAIN OUTCOME of the batch a proof settled in (RB5-F15): the member's outcome leaf, the root the
// quorum certified and CertenOutcomeRegistryV1 recorded, the quorum itself, and the chain evidence the member's status
// rests on - checked OFFLINE from the proof's stored evidence (its layer 6), or from an exported evidence file with no
// database at all. The same three-way verdict as the rest of this tool:
//
//	0  verified        every check passed
//	3  named weaker    the outcome is not recorded yet, or the proof predates outcome evidence; or the outcome was
//	                   certified by a CERTEN set other than the anchor's; or (online) a member recorded NOT SETTLED has
//	                   since been consumed
//	1  FAILED          the evidence is present and does not check out

// reportOutcome checks a stored proof's recorded outcome, bound to the proof's own layer 5.
func reportOutcome(ctx context.Context, w io.Writer, store certenproof.ProofStorageReader, id uuid.UUID, onlineRPC string) int {
	ev, chk, err := execution.VerifyStoredOutcome(ctx, store, id)
	return reportOutcomeResult(ctx, w, id.String(), ev, chk, err, onlineRPC)
}

// reportOutcomeFile checks an exported outcome evidence file (the JSON of a proof's layer 6) on its own: no proof, no
// database. What binds it to a particular proof is that proof's layer 5, which --outcome checks.
func reportOutcomeFile(ctx context.Context, w io.Writer, path, onlineRPC string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "FAILED (outcome)  %s\n  %v\n", path, err)
		return exitFailed
	}
	ev := new(execution.OutcomeEvidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		fmt.Fprintf(w, "FAILED (outcome)  %s\n  the evidence does not decode: %v\n", path, err)
		return exitFailed
	}
	chk, err := ev.VerifyOffline()
	code := reportOutcomeResult(ctx, w, path, ev, chk, err, onlineRPC)
	if code == exitVerified {
		fmt.Fprintf(w, "  NOT checked here: which proof this outcome is of - its layer 5 binds it (--proof-id with --outcome)\n")
	}
	return code
}

func reportOutcomeResult(ctx context.Context, w io.Writer, subject string, ev *execution.OutcomeEvidence, chk *execution.OutcomeEvidenceCheck,
	err error, onlineRPC string) int {
	switch {
	case errors.Is(err, execution.ErrNoOutcomeEvidence):
		fmt.Fprintf(w, "OUTCOME NOT RECORDED  %s\n  %v\n", subject, err)
		fmt.Fprintf(w, "  The batch this proof settled in has no recorded outcome evidence on this proof: its outcome is not\n")
		fmt.Fprintf(w, "  recorded yet, or the proof predates outcome evidence. Nothing is known to be wrong; nothing about\n")
		fmt.Fprintf(w, "  what its members did on chain is verified either.\n")
		return exitSummaryOnly
	case errors.Is(err, execution.ErrOutcomeSetRotated):
		printOutcomeCheck(w, chk)
		fmt.Fprintf(w, "SUMMARY-ONLY (outcome)  %s\n  %v\n", subject, err)
		fmt.Fprintf(w, "  The outcome verifies under the set that certified it; that this set succeeded the one that signed\n")
		fmt.Fprintf(w, "  the anchor is not established offline.\n")
		return exitSummaryOnly
	case err != nil:
		fmt.Fprintf(w, "FAILED (outcome)  %s\n  %v\n", subject, err)
		fmt.Fprintf(w, "  The outcome evidence IS present and does not check out.\n")
		return exitFailed
	}
	fmt.Fprintf(w, "  OUTCOME verified OFFLINE (%s): chain %d anchor %s…, member %d status %d (%s)\n", ev.Version, ev.ChainID,
		ev.Anchor.BundleID[:18], chk.Leaf.LeafIndex, chk.Leaf.Status, outcomeStatusName(chk.Leaf.Status))
	printOutcomeCheck(w, chk)
	if onlineRPC == "" {
		return exitVerified
	}
	online, err := execution.VerifyOutcomeEvidenceOnline(ctx, onlineRPC, ev)
	if err != nil {
		fmt.Fprintf(w, "FAILED (outcome online)  %s\n  %v\n", subject, err)
		return exitFailed
	}
	for _, s := range online.Established {
		fmt.Fprintf(w, "      ONLINE ✓ %s\n", s)
	}
	code := exitVerified
	if online.SetRotated {
		fmt.Fprintf(w, "SUMMARY-ONLY (outcome online)  %s\n  the anchor's CERTEN validator set has changed since it certified this outcome; the\n", subject)
		fmt.Fprintf(w, "  stated keys were compared only where the current registry still holds them\n")
		code = exitSummaryOnly
	}
	if online.ConsumedAfterClaim {
		fmt.Fprintf(w, "SUMMARY-ONLY (outcome online)  %s\n  the member was recorded NOT SETTLED and its leaf has since been consumed: the\n", subject)
		fmt.Fprintf(w, "  record states a true historical fact that no longer describes the leaf (the deadline is not enforced on\n")
		fmt.Fprintf(w, "  chain, RB5-F57)\n")
		code = exitSummaryOnly
	}
	return code
}

func printOutcomeCheck(w io.Writer, chk *execution.OutcomeEvidenceCheck) {
	if chk == nil {
		return
	}
	for _, s := range chk.Established {
		fmt.Fprintf(w, "      ✓ %s\n", s)
	}
	for _, s := range chk.NotEstablished {
		fmt.Fprintf(w, "      NOT established offline: %s\n", s)
	}
}

func outcomeStatusName(s execution.OutcomeStatus) string {
	switch s {
	case execution.OutcomeExecuted:
		return "executed, every committed effect proven"
	case execution.OutcomeEffectsNotProven:
		return "executed, a committed effect proven absent"
	case execution.OutcomeNotSettled:
		return "not settled by its deadline"
	case execution.OutcomeConsumedElsewhere:
		return "consumed under another anchor"
	}
	return strings.TrimSpace(fmt.Sprintf("unknown %d", s))
}
