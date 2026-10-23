// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"fmt"
	"io"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// RB12-INDEX-FIX D3: the on-demand self-check of the Base capture index (`validator finality-index-selfcheck`). The indexer runs the same
// check every 256 steps; this is the operator's way to run it now, with a larger sample, after a deploy or a database incident.

// Exit codes of RunIndexSelfCheck.
const (
	IndexSelfCheckOK         = 0
	IndexSelfCheckMismatch   = 1 // at least one stored row differs from what the captured rows give: the channel is quarantined by name
	IndexSelfCheckNotRunning = 2 // the index is switched off (or a bad setting switched it off): there is nothing to check
	IndexSelfCheckIncomplete = 3 // some checks were skipped (the memory budget refused their rows): nothing was judged for those
	IndexSelfCheckFailed     = 4 // the check could not run (the store failed)
	IndexSelfCheckUsage      = 5 // the arguments are wrong: no check was started (never confused with a mismatch)
)

// IndexSelfChecker is the indexer as the on-demand caller sees it.
type IndexSelfChecker interface {
	SelfCheckReport(ctx context.Context, sample int) (baseposted.SelfCheckResult, error)
}

// NewIndexSelfChecker builds the Base indexer a process would run (generation and limits of cfg) over store, for the on-demand check.
func NewIndexSelfChecker(cfg Config, store finality.CaptureStore, pins *finality.Pins, logf func(string, ...any)) (IndexSelfChecker, error) {
	bp, err := baseposted.ParsePins(pins)
	if err != nil {
		return nil, err
	}
	return baseposted.NewIndexer(store, bp, cfg.IndexGeneration, baseposted.IndexConfig{BlocksPerStep: cfg.IndexBlocks, StepBudget: cfg.IndexStep, Logf: logf}), nil
}

// RunIndexSelfCheck runs the self-check with the given sample and writes ONE named result line (and the named state of a mismatch) to w. It
// returns the exit code. A mismatch writes the shared quarantine record of the channel (builds of every validator refuse it by name until
// a new generation); a skipped check is reported, never counted as passed.
func RunIndexSelfCheck(ctx context.Context, w io.Writer, cfg Config, ix IndexSelfChecker, sample int) int {
	if cfg.IndexDisabled != nil {
		fmt.Fprintf(w, "finality-index-selfcheck: not running: %s\n", cfg.IndexDisabled.Error())
		return IndexSelfCheckNotRunning
	}
	if !cfg.BaseIndex || ix == nil {
		fmt.Fprintf(w, "finality-index-selfcheck: not running: the Base capture index is switched off (%s)\n", EnvBaseIndex)
		return IndexSelfCheckNotRunning
	}
	res, err := ix.SelfCheckReport(ctx, sample)
	line := fmt.Sprintf("generation=%d around_l1_block=%d entries=%d digests=%d skipped=%d mismatches=%d", res.Generation, res.Around, res.Entries, res.Digests, res.Skipped, res.Mismatches)
	if err != nil {
		if st, named := finality.AsNamed(err); named {
			fmt.Fprintf(w, "finality-index-selfcheck: MISMATCH %s\n%s\n", line, st.Error())
			return IndexSelfCheckMismatch
		}
		fmt.Fprintf(w, "finality-index-selfcheck: FAILED %s: %v\n", line, err)
		return IndexSelfCheckFailed
	}
	if res.Mismatches > 0 {
		fmt.Fprintf(w, "finality-index-selfcheck: MISMATCH %s\n", line)
		return IndexSelfCheckMismatch
	}
	if res.Skipped > 0 {
		fmt.Fprintf(w, "finality-index-selfcheck: INCOMPLETE %s (the memory budget refused the rows of the skipped checks; nothing was judged for them)\n", line)
		return IndexSelfCheckIncomplete
	}
	fmt.Fprintf(w, "finality-index-selfcheck: ok %s\n", line)
	return IndexSelfCheckOK
}
