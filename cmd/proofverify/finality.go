// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"database/sql"
	"encoding/hex"
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

// reportFinality verifies a stored proof's finality: its bundle's L6 settlement, and the addenda stored for it.
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
	if len(chain) == 0 {
		// Nothing has been appended yet. The bundle's own L6 evidence is level 1, verified directly.
		prover := finality.IncludedProver{ChainID: ref.Chain}
		ev, _, err := prover.Build(ctx, settlement)
		var rep finality.LegReport
		if err == nil {
			a, aerr := finality.NewAddendum(ref.Digest, id.String(), nil, ref.Chain, finality.LevelIncluded, ev)
			if aerr != nil {
				fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", id, aerr)
				return exitFailed
			}
			rep = reg.VerifyLeg(ref.Digest, []finality.Addendum{a}, pins)
		} else {
			fmt.Fprintf(w, "FAILED (finality)  %s\n  the bundle's L6 evidence does not verify as the included level: %v\n", id, err)
			return exitFailed
		}
		fmt.Fprintf(w, "  S7  no finality addendum is stored for this proof yet; its bundle's own L6 evidence is judged as level 1\n")
		return printLegReport(w, rep, id.String())
	}
	// A stored chain must be about the settlement the proof's own bundle proves.
	rep := reg.VerifyLeg(ref.Digest, chain, pins)
	if rep.ChainErr == nil && rep.Subject != settlement.Subject {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  the stored addenda are about block %d tx %x, the proof's bundle proves block %d tx %x\n",
			id, rep.Subject.BlockNumber, rep.Subject.TxHash[:6], settlement.Subject.BlockNumber, settlement.Subject.TxHash[:6])
		return exitFailed
	}
	return printLegReport(w, rep, id.String())
}

// reportFinalityFile verifies the `finality` section of a portable proof v2 document file (or a bare JSON array of
// addenda) with no database: each leg's chain against the original digest its addenda carry, and every addendum's evidence.
func reportFinalityFile(w io.Writer, path string, reg *finality.Registry, pins *finality.Pins) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", path, err)
		return exitFailed
	}
	var doc struct {
		Finality []json.RawMessage `json:"finality"`
	}
	section := []json.RawMessage(nil)
	if err := json.Unmarshal(raw, &doc); err == nil {
		section = doc.Finality
	} else if err := json.Unmarshal(raw, &section); err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  neither a portable document nor a list of addenda: %v\n", path, err)
		return exitFailed
	}
	if len(section) == 0 {
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s\n  the document carries no finality section: no level beyond the proof itself is evidenced.\n", path)
		return exitSummaryOnly
	}
	reports, err := reg.VerifyDocumentSection(section, pins)
	if err != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s\n  %v\n", path, err)
		return exitFailed
	}
	code := exitVerified
	for _, rep := range reports {
		code = worseExit(code, printLegReport(w, rep, path))
	}
	return code
}

// printLegReport writes one leg's per-statement S7 verdicts and returns the leg's exit code.
func printLegReport(w io.Writer, rep finality.LegReport, subject string) int {
	if rep.ChainErr != nil {
		fmt.Fprintf(w, "FAILED (finality)  %s  leg %s\n  the addendum chain does not verify: %v\n", subject, rep.ProofID, rep.ChainErr)
		fmt.Fprintf(w, "  S7  level reached: none (a broken chain evidences nothing)\n")
		return exitFailed
	}
	fmt.Fprintf(w, "  S7  chain %d  block %d  tx %s…  original digest %s…\n", rep.Chain, rep.Subject.BlockNumber,
		hex.EncodeToString(rep.Subject.TxHash[:6]), hex.EncodeToString(rep.Digest[:6]))
	byLevel := map[finality.Level]finality.AddendumVerdict{}
	for _, a := range rep.Addenda {
		byLevel[a.Level] = a
		status := "verified"
		switch {
		case !a.Verified && a.Unjudged:
			status = "UNJUDGED"
		case !a.Verified:
			status = "FAILED"
		}
		line := fmt.Sprintf("  S7    addendum %d  %-9s  %-9s  %s", a.Seq, a.Level, status, a.Kind)
		if a.Err != nil {
			line += "  " + a.Err.Error()
		}
		fmt.Fprintln(w, line)
	}
	for _, l := range finality.Levels {
		if _, done := byLevel[l]; done {
			continue
		}
		var na *finality.NotApplicable
		for _, n := range rep.NotApplicable {
			if n.Level == l {
				na = n
			}
		}
		switch {
		case na != nil:
			fmt.Fprintf(w, "  S7    %-9s  %s\n", l, na.Error())
		case l > rep.Top:
			// above the chain's top: not a level of this chain
		case l <= rep.Reached:
			// reached through a higher addendum
		default:
			fmt.Fprintf(w, "  S7    %-9s  not evidenced yet\n", l)
		}
	}
	fmt.Fprintf(w, "  S7  level reached: %s (of %s)\n", rep.Reached, rep.Top)
	if p := rep.PendingState(); p != nil {
		fmt.Fprintf(w, "  S7  %s\n", p.Error())
	}
	switch rep.Verdict {
	case finality.VerdictFailed:
		fmt.Fprintf(w, "FAILED (finality)  %s  leg %s\n  an addendum's evidence is present and does not check out\n", subject, rep.ProofID)
		return exitFailed
	case finality.VerdictSummaryOnly:
		fmt.Fprintf(w, "SUMMARY-ONLY (finality)  %s  leg %s\n  an addendum's kind or pins are not known to this verifier; nothing is known to be wrong, and the levels above\n", subject, rep.ProofID)
		fmt.Fprintf(w, "  %s are not judged here.\n", rep.Reached)
		return exitSummaryOnly
	}
	fmt.Fprintf(w, "VERIFIED (finality)  %s  leg %s  level %s\n", subject, rep.ProofID, rep.Reached)
	return exitVerified
}
