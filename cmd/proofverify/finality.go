// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/finality"
)

// S7: staged finality (PROOF_V2 section 7, pkg/finality, domain tag certen:finality:v1).
//
// A proof's finality addenda are append-only evidence beside the proof. They are verified here offline: the chain of
// addenda (sequence, previous-hash links, own hashes against the proof's original digest, levels strictly rising, one
// settlement), then each addendum's evidence by its registered verifier. The report names every level - verified, pending
// or not applicable - and the level reached. Exit codes are the tool's own:
//
//	0  verified     the chain verifies and every addendum verifies to exactly its level (a level not yet reached is
//	                reported as finality_pending with the level reached, never as a failure)
//	3  summary-only an addendum's kind or pins are not known to this verifier (nothing is known to be wrong), or the
//	                proof carries no settlement evidence to attach finality to
//	1  FAILED       the chain or some evidence is present and does not check out

// reportFinality verifies a stored proof's finality (S7): its bundle's L6 settlement (level 1, derived, never stored), the
// addenda stored for the leg, and each stored level's evidence, judged by the registered Kinds against the pins. D0 is
// recomputed from the verified Settlement's block; the stored addenda never supply it.
func reportFinality(ctx context.Context, w io.Writer, db *sql.DB, id uuid.UUID, reg *finality.Registry, pins *finality.Pins) int {
	repo := database.NewFinalityAddendaRepository(database.NewClientFromDB(db))
	ref, err := repo.LegRef(ctx, id.String())
	if err != nil {
		if n, ok := finality.AsNamed(err); ok {
			fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  %v\n  The proof carries no settlement evidence, so there is nothing for finality to attach to.\n", id, n)
			return exitSummaryOnly
		}
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", id, err)
		return exitFailed
	}
	settlement, err := repo.LegSettlement(ctx, ref)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the bundle's L6 settlement evidence does not verify: %v\n", id, err)
		return exitFailed
	}
	chain, err := repo.Chain(ctx, id.String())
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  reading the stored addenda: %v\n", id, err)
		return exitFailed
	}
	// The stored chain belongs to the leg this proof's bundle proves: its carried block is that block.
	rep := reg.Verify(ref.Chain, settlement.Included, settlement.Block(), chain, pins)
	return printReport(w, rep, id.String())
}

// reportFinalityFile reads the `finality` member (certen-finality-addenda/1) of a portable proof v2 document file with no
// database. A verifier needs the leg's Settlement to recompute D0 (V2_SPEC_S7 2.6), and the portable document does not carry
// one: until the Settlement source is wired (RB11-B2B) no level is judged and none is claimed, and the report says so by name.
func reportFinalityFile(w io.Writer, path string, reg *finality.Registry, pins *finality.Pins) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", path, err)
		return exitFailed
	}
	var doc struct {
		Finality json.RawMessage `json:"finality"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  not a portable document: %v\n", path, err)
		return exitFailed
	}
	if len(doc.Finality) == 0 || string(doc.Finality) == "null" {
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  the document carries no finality section: no level beyond the proof itself is evidenced.\n", path)
		return exitSummaryOnly
	}
	section, err := finality.ParseSection(doc.Finality)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", path, err)
		return exitFailed
	}
	st := finality.NewState(finality.CodeIncludedUnavailable, "chain", section.Leg.Chain, "reason",
		"this verifier holds no Settlement for the leg, so D0 cannot be recomputed and no level is judged")
	fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  %v\n  S7  carried leg: chain %d block %d %s; %d addenda are not judged\n", path, st, section.Leg.Chain,
		section.Leg.BlockNumber, section.Leg.BlockHash, len(section.Addenda))
	return exitSummaryOnly
}

// printReport writes one leg's per-statement S7 verdicts and returns the leg's exit code.
func printReport(w io.Writer, rep finality.Report, subject string) int {
	if rep.Unsupported != nil {
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  %v\n", subject, rep.Unsupported)
		return exitSummaryOnly
	}
	if st := rep.Levels[finality.LevelIncluded]; st.Status == finality.StatusRefused {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the leg's Settlement does not verify as the included level: %v\n", subject, st.State)
		return exitFailed
	}
	fmt.Fprintf(w, "  S7  chain %d  block %d  %x…  pins %s (%s)\n", rep.Block.Chain, rep.Block.Number, rep.Block.Hash[:6], rep.PinsSHA256, rep.PinsSource)
	for _, l := range finality.Levels {
		st := rep.Levels[l]
		line := fmt.Sprintf("  S7    %-9s  %s", l, st.Status)
		if st.State != nil {
			line += "  " + st.State.Error()
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "  S7  level reached: %s\n", rep.Headline)
	if rep.FinalizedBlock != nil {
		fmt.Fprintf(w, "  S7  finalized_block: number %d hash %x stateRoot %x\n", rep.FinalizedBlock.Number, rep.FinalizedBlock.Hash, rep.FinalizedBlock.StateRoot)
	}
	if rep.Broken != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the addendum chain does not verify: %v\n", subject, rep.Broken)
		return exitFailed
	}
	code := exitVerified
	for _, l := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
		switch st := rep.Levels[l]; st.Status {
		case finality.StatusRefused:
			if st.State != nil && (st.State.Code == finality.CodeEvidenceUnrecognised || st.State.Code == finality.CodePinUnknown) {
				code = worseExit(code, exitSummaryOnly)
			} else {
				code = exitFailed
			}
		}
	}
	switch code {
	case exitFailed:
		fmt.Fprintf(w, "FAILED (finality)  %s\n  an addendum's evidence is present and does not check out\n", subject)
	case exitSummaryOnly:
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  an addendum's kind or pins are not known to this verifier; nothing is known to be wrong, and the levels above\n  %s are not judged here.\n", subject, rep.Headline)
	default:
		fmt.Fprintf(w, "VERIFIED (finality)  %s  level %s\n", subject, rep.Headline)
	}
	return code
}
