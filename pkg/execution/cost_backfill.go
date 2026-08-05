package execution

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/billing"
)

// =============================================================================
// Historical cost backfill
// =============================================================================
//
// # WHAT THIS RECOVERS
//
// The validator has recorded tx_hash, chain and cycle for every on-chain execution since
// 2026-01-26, but nothing shipped those to the gateway until the batch settle path began
// reporting on 2026-08-05. The gateway therefore holds 197 events from a single chain while the
// validator holds ~1000 executions across 22. Every chain-keyed consumer — the pricing gate,
// the gas estimator, the margin report — reads that near-empty set.
//
// The measurements are recoverable because tx_hash was always stored: the cost can be re-probed
// from the chain itself. That is what this does.
//
// # WHY ONLY PART OF THE HISTORY IS BACKFILLED
//
// A cost event is only useful if BOTH its leg and its intent are known, and neither is universal:
//
//   - LEG. chain_execution_results.workflow_step is NOT a stable leg identifier. On cycles with
//     three rows it is (1,2,3) = (anchor, verify, vault_execute), confirmed across 209 EVM
//     samples whose gas profile matches — anchor ~290k, verify ~446k (the largest, consistent
//     with executeComprehensiveProof), vault_execute ~132k. But cycles with ONE row also use
//     step 1, and there it is the SETTLEMENT: verified against intent 719b0e95 on 2026-08-05,
//     whose single row was step 1 carrying the vault_execute transaction. Backfilling those as
//     "anchor" would mislabel real money, and a wrong leg is worse than a missing one — it
//     silently skews the per-leg medians the estimator prices from.
//
//   - INTENT. NewCostEvent requires an intent id, and accum_tx_hash is the only key the gateway
//     can join on. Both come from intent_lifecycle via cycle_id, and only 552 of the 840
//     three-row records resolve.
//
// So the backfill takes the intersection: three-row cycles that resolve to an intent. Everything
// else is reported as skipped rather than guessed.
//
// # WHY IT RE-PROBES RATHER THAN USING THE STORED GAS
//
// chain_execution_results.gas_used exists but gas_cost is an empty string on every row, so the
// PRICE was never recorded — and price is half of the cost. gas_used is also overloaded: it
// holds native units on non-EVM chains, which is why its average across chains reads in the
// trillions. Re-probing by tx_hash gets the real price, the OP-stack L1 fee, and the correct
// denomination per chain, through exactly the same code production uses.
//
// Re-running is safe. The reporter keys on (chain, tx, leg), so an event already delivered
// collapses to the existing row at the gateway.

// CostBackfillOptions tunes one run.
type CostBackfillOptions struct {
	// DryRun reports what would be sent without probing or delivering anything.
	DryRun bool
	// Limit caps the rows processed; zero means all.
	Limit int
	// Pause between rows, to avoid hammering a shared RPC endpoint. Probing is I/O bound and
	// these are historical transactions — there is no reason to rush and every reason not to
	// trip a provider's rate limit mid-run.
	Pause time.Duration
	// Logf receives progress.
	Logf func(string, ...interface{})
}

// CostBackfillReport summarises a run.
type CostBackfillReport struct {
	Candidates   int
	Reported     int
	SkippedChain int // no canonical slug or no RPC endpoint configured
	SkippedNoTx  int
	Errors       int
	ByChain      map[string]int
	ByLeg        map[string]int
}

// backfillLegForStep maps a three-row cycle's workflow_step to its leg.
//
// ONLY valid for cycles with exactly three rows — see the note above. Returns "" otherwise so
// the caller skips rather than guesses.
func backfillLegForStep(step int, rowsInCycle int) string {
	if rowsInCycle != 3 {
		return ""
	}
	switch step {
	case 1:
		return billing.LegAnchor
	case 2:
		return billing.LegVerify
	case 3:
		return billing.LegVaultExecute
	}
	return ""
}

// RunCostBackfill re-probes historical executions and reports their cost to the gateway.
//
// The query deliberately restricts to three-row cycles joined to an intent; anything outside
// that is not a candidate and is not counted as an error.
func RunCostBackfill(ctx context.Context, db *sql.DB, opts CostBackfillOptions) (*CostBackfillReport, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	if opts.Pause <= 0 {
		opts.Pause = 250 * time.Millisecond
	}
	rep := &CostBackfillReport{ByChain: map[string]int{}, ByLeg: map[string]int{}}

	reporter := CostReporter()
	if reporter == nil && !opts.DryRun {
		return nil, fmt.Errorf("cost reporting is not configured (CERTEN_GATEWAY_URL / " +
			"VALIDATOR_SERVICE_TOKEN_SECRET); nothing could be delivered")
	}

	const q = `
		WITH sized AS (
		  SELECT cycle_id, count(*) AS n
		  FROM chain_execution_results
		  WHERE cycle_id IS NOT NULL
		  GROUP BY cycle_id
		)
		SELECT cer.workflow_step, s.n, cer.tx_hash, cer.network_name, cer.chain_id,
		       il.intent_id, il.accum_tx_hash, il.user_id
		FROM chain_execution_results cer
		JOIN sized s            ON s.cycle_id = cer.cycle_id
		JOIN intent_lifecycle il ON il.cycle_id = cer.cycle_id
		WHERE s.n = 3
		  AND cer.tx_hash IS NOT NULL AND cer.tx_hash <> ''
		  AND il.intent_id IS NOT NULL
		ORDER BY cer.created_at`

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("querying backfill candidates: %w", err)
	}
	defer rows.Close()

	type candidate struct {
		step        int
		rowsInCycle int
		txHash      string
		network     string
		chainID     sql.NullInt64
		intentID    string
		accumTx     sql.NullString
		adiURL      sql.NullString
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.step, &c.rowsInCycle, &c.txHash, &c.network,
			&c.chainID, &c.intentID, &c.accumTx, &c.adiURL); err != nil {
			return nil, fmt.Errorf("scanning candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating candidates: %w", err)
	}
	rep.Candidates = len(candidates)
	logf("[BACKFILL] %d candidate execution(s) from three-row cycles resolvable to an intent",
		rep.Candidates)

	for i, c := range candidates {
		if opts.Limit > 0 && rep.Reported >= opts.Limit {
			logf("[BACKFILL] stopping at limit %d", opts.Limit)
			break
		}
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}

		leg := backfillLegForStep(c.step, c.rowsInCycle)
		if leg == "" {
			// Unreachable given the WHERE clause, but a guard beats a mislabelled cost.
			rep.SkippedNoTx++
			continue
		}

		// Canonicalise through the SAME function production uses, so a backfilled row is
		// indistinguishable in shape from a live one. This also folds the historical "sepolia"
		// spelling into "ethereum-sepolia" rather than creating a second chain.
		chain, chainID := canonicalChainSlug(c.network)
		if chain == "" {
			rep.SkippedChain++
			continue
		}
		if c.chainID.Valid && c.chainID.Int64 != 0 {
			chainID = c.chainID.Int64
		}
		rpcURL, apiKey := costEndpointForChain(chain)
		if rpcURL == "" {
			// No endpoint configured for this chain in THIS process's environment. Not an
			// error: a validator is not required to hold RPC credentials for every chain it has
			// ever touched.
			rep.SkippedChain++
			continue
		}

		rep.ByChain[chain]++
		rep.ByLeg[leg]++
		rep.Reported++

		if opts.DryRun {
			if i < 5 || i%100 == 0 {
				logf("[BACKFILL] (dry-run) %s leg=%s tx=%s intent=%s",
					chain, leg, shortHex(c.txHash), c.intentID)
			}
			continue
		}

		reporter.ObserveAndReport(ctx, billing.ProbeConfig{
			Chain:   chain,
			ChainID: chainID,
			RPCURL:  rpcURL,
			APIKey:  apiKey,
			Leg:     leg,
		}, c.intentID, c.adiURL.String, c.accumTx.String, c.txHash, nil)

		if rep.Reported%50 == 0 {
			logf("[BACKFILL] queued %d/%d", rep.Reported, rep.Candidates)
		}
		select {
		case <-ctx.Done():
			return rep, ctx.Err()
		case <-time.After(opts.Pause):
		}
	}

	logf("[BACKFILL] queued=%d skipped_chain=%d errors=%d (of %d candidates)",
		rep.Reported, rep.SkippedChain, rep.Errors, rep.Candidates)
	for chain, n := range rep.ByChain {
		logf("[BACKFILL]   %-24s %d", chain, n)
	}
	return rep, nil
}
