// Copyright 2026 Certen Protocol

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/finality"
	finruntime "github.com/certen/independant-validator/pkg/finality/runtime"
)

const finalityIndexSelfCheckUsage = "usage: certen-validator finality-index-selfcheck [--sample N]   (N in 1..1024, default 16)"

// parseFinalityIndexSelfCheckArgs reads the arguments of `validator finality-index-selfcheck`.
func parseFinalityIndexSelfCheckArgs(args []string) (sample int, ok bool) {
	sample = 16
	for i := 0; i < len(args); i++ {
		if args[i] != "--sample" || i+1 >= len(args) {
			return 0, false
		}
		n, err := strconv.Atoi(args[i+1])
		if err != nil || n < 1 || n > 1024 {
			return 0, false
		}
		sample = n
		i++
	}
	return sample, true
}

// runFinalityIndexSelfCheck is `validator finality-index-selfcheck [--sample N]` (RB12-INDEX-FIX D3): it recomputes N stored Base capture
// index entries and N block digests from the captured rows by the reference path and compares bytes, under the process memory budget. It
// prints one named result line and exits 0 (ok), 1 (a mismatch: the channel is quarantined by name for every validator), 2 (the index is off),
// 3 (some checks were skipped: incomplete), 4 (the check could not run) or 5 (the arguments are wrong: usage, nothing was started). It reads the capture table and writes only the quarantine record of
// a mismatched entry (insert-only); it needs the database settings of the validator and nothing else.
func runFinalityIndexSelfCheck(args []string, out, errw io.Writer) int {
	sample, ok := parseFinalityIndexSelfCheckArgs(args)
	if !ok {
		fmt.Fprintln(errw, finalityIndexSelfCheckUsage)
		return finruntime.IndexSelfCheckUsage
	}
	fcfg, err := finruntime.ConfigFromEnv()
	if err != nil {
		fmt.Fprintf(out, "finality-index-selfcheck: FAILED: the finality configuration is refused: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	pins, _, _, err := finruntime.LoadPins(fcfg.PinsFile)
	if err != nil {
		fmt.Fprintf(out, "finality-index-selfcheck: FAILED: the pins cannot be loaded: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(out, "finality-index-selfcheck: FAILED: configuration: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	client, err := database.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(out, "finality-index-selfcheck: FAILED: database: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	defer client.Close()
	budget, err := finality.MemoryBudgetFromEnv()
	if err != nil {
		fmt.Fprintf(out, "finality-index-selfcheck: FAILED: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	ix, err := finruntime.NewIndexSelfChecker(fcfg, database.NewFinalityCaptureStore(client), pins, log.Printf)
	if err != nil {
		fmt.Fprintf(out, "finality-index-selfcheck: FAILED: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ctx = finality.WithMemoryBudget(ctx, finality.NewMemoryBudget(budget))
	return finruntime.RunIndexSelfCheck(ctx, out, fcfg, ix, sample)
}

const finalityArbIndexSelfCheckUsage = "usage: certen-validator finality-arb-index-selfcheck [--sample N]   (N in 1..1024, default 16)"

// runFinalityArbIndexSelfCheck is `validator finality-arb-index-selfcheck [--sample N]` (RB12-INDEX-B): it recomputes N stored Arbitrum batch-index
// entries and N block digests from the captured rows and compares bytes, under the process memory budget. It prints one named result line and exits
// 0 (ok), 1 (a mismatch: the entry is quarantined by name for every validator), 2 (the index is off), 3 (some checks were skipped: incomplete), 4 (the
// check could not run) or 5 (the arguments are wrong: usage, nothing was started). It writes only the quarantine record of a mismatched entry.
func runFinalityArbIndexSelfCheck(args []string, out, errw io.Writer) int {
	sample, ok := parseFinalityIndexSelfCheckArgs(args)
	if !ok {
		fmt.Fprintln(errw, finalityArbIndexSelfCheckUsage)
		return finruntime.IndexSelfCheckUsage
	}
	fcfg, err := finruntime.ConfigFromEnv()
	if err != nil {
		fmt.Fprintf(out, "finality-arb-index-selfcheck: FAILED: the finality configuration is refused: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	pins, _, _, err := finruntime.LoadPins(fcfg.PinsFile)
	if err != nil {
		fmt.Fprintf(out, "finality-arb-index-selfcheck: FAILED: the pins cannot be loaded: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(out, "finality-arb-index-selfcheck: FAILED: configuration: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	client, err := database.NewClient(cfg)
	if err != nil {
		fmt.Fprintf(out, "finality-arb-index-selfcheck: FAILED: database: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	defer client.Close()
	budget, err := finality.MemoryBudgetFromEnv()
	if err != nil {
		fmt.Fprintf(out, "finality-arb-index-selfcheck: FAILED: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	ix, err := finruntime.NewArbIndexSelfChecker(fcfg, database.NewFinalityCaptureStore(client), pins, log.Printf)
	if err != nil {
		fmt.Fprintf(out, "finality-arb-index-selfcheck: FAILED: %v\n", err)
		return finruntime.IndexSelfCheckFailed
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ctx = finality.WithMemoryBudget(ctx, finality.NewMemoryBudget(budget))
	return finruntime.RunArbIndexSelfCheck(ctx, out, fcfg, ix, sample)
}
