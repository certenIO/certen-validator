package billing

import (
	"context"
	"fmt"
	"time"
)

// =============================================================================
// Shared-cost attribution: one anchor, many intents
// =============================================================================
//
// # WHY THIS EXISTS
//
// CertenAnchorV8_1.createBatchAnchor puts N intents under ONE anchor, and one
// executeComprehensiveProof verifies the whole batch. Measured on live Sepolia those two
// transactions are 802,128 of the 987,644 gas an intent costs — 81.2% — and amortising them
// across the batch is the entire economic point of batching.
//
// Reporting that shared transaction once per member with its FULL cost would bill each of N
// intents for gas that was paid once, inflating recorded cost by a factor of N on the dominant
// component. Reporting it once for a single member would leave the other N-1 looking free.
// Neither is recoverable after the fact, because nothing in cost_events records that the
// transaction was shared.
//
// So a shared leg is measured ONCE and divided, and each member's share carries the divisor and
// the anchor tx in its breakdown so the split is auditable rather than asserted.
//
// # WHY THE IDEMPOTENCY KEY MUST CHANGE
//
// NewCostEvent keys on (chain, tx, leg), which is exactly right for a per-intent transaction:
// a WAL replay, a retry and a duplicated call all collapse to one row. For a SHARED leg that
// same key would collapse all N member shares into one row — silently discarding N-1 of them
// and under-reporting the anchor by (N-1)/N. Shared events therefore key on
// (chain, tx, leg, intent), which still dedupes replays of the SAME member's share.

// CostMember is one intent's claim on a shared transaction.
type CostMember struct {
	// IntentID is the validator's identifier, used for attribution.
	IntentID string
	// ADIURL is the authorising Accumulate identity. The gateway resolves the org from it.
	ADIURL string
	// AccumTxHash is the Accumulate transaction that carried the intent — the ONLY identifier
	// the gateway and the validator both hold. Without it the gateway can store the cost but
	// never join it to an intent.
	AccumTxHash string
}

// splitGas divides a shared gas figure across n members.
//
// The remainder goes to the FIRST member rather than being dropped, so the shares sum to
// exactly the gas that was paid. Dropping it would leak a few units per batch, which is
// invisible per transaction and wrong in aggregate — and "billing that does not reconcile to
// the penny" is a much harder problem to explain than an uneven first share.
func splitGas(total uint64, n int) []uint64 {
	if n <= 0 {
		return nil
	}
	if n == 1 {
		return []uint64{total}
	}
	share := total / uint64(n)
	rem := total % uint64(n)
	out := make([]uint64, n)
	for i := range out {
		out[i] = share
	}
	out[0] += rem
	return out
}

// ObserveAndReportShared measures ONE transaction and attributes it across N members.
//
// Use for the anchor and verify legs, which are paid once for the whole batch. Per-member
// transactions (the vault execute) go through ObserveAndReport unchanged.
//
// N=1 is not a special case: a solo intent is a one-member batch and gets the whole cost, with
// the breakdown recording shared_with=1 so the on-demand and batched paths produce
// structurally identical rows.
func (r *Reporter) ObserveAndReportShared(
	ctx context.Context,
	probeCfg ProbeConfig,
	members []CostMember,
	txHash string,
	inclusionProof interface{},
) {
	if r == nil || len(members) == 0 {
		return
	}
	go func() {
		// Detached, like ObserveAndReport: settlement finishes long before some chains index.
		bg, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		probe, err := NewProbe(probeCfg)
		if err != nil {
			r.logger.Printf("⚠️ No fee model for %s: %v", probeCfg.Chain, err)
			return
		}

		var cost *ChainCost
		delay := 2 * time.Second
		for attempt := 1; attempt <= 8; attempt++ {
			cost, err = probe.ObservedCost(bg, txHash)
			if err == nil {
				break
			}
			select {
			case <-bg.Done():
				r.logger.Printf("⚠️ Shared cost probe for %s/%s timed out: %v", probeCfg.Chain, txHash, err)
				return
			case <-time.After(delay):
			}
			if delay < 30*time.Second {
				delay *= 2
			}
		}
		if cost == nil {
			r.logger.Printf("❌ Could not measure shared cost for %s/%s after retries: %v",
				probeCfg.Chain, txHash, err)
			return
		}

		shares := splitGas(cost.GasUsed, len(members))
		r.logger.Printf("💰 %s leg=%s tx=%s gas=%d shared across %d intent(s)",
			probeCfg.Chain, cost.Leg, txHash, cost.GasUsed, len(members))

		for i, m := range members {
			// Copy per member: the shared ChainCost must not be mutated in place, or every
			// share after the first would inherit the previous one's gas.
			share := *cost
			share.GasUsed = shares[i]
			share.Breakdown = mergeBreakdown(cost.Breakdown, map[string]string{
				"shared_tx":        txHash,
				"shared_with":      fmt.Sprintf("%d", len(members)),
				"shared_total_gas": fmt.Sprintf("%d", cost.GasUsed),
			})

			event, err := NewCostEvent(m.IntentID, m.ADIURL, m.AccumTxHash, &share, inclusionProof)
			if err != nil {
				r.logger.Printf("❌ Rejecting malformed shared cost event for %s/%s intent %s: %v",
					probeCfg.Chain, txHash, m.IntentID, err)
				continue
			}
			// Per-intent key. The default (chain, tx, leg) would collapse every share into one
			// row and silently discard the rest — see the note at the top of this file.
			event.IdempotencyKey = fmt.Sprintf("cost:%s:%s:%s:%s",
				share.Chain, share.TxHash, share.Leg, m.IntentID)
			r.Report(event)
		}
	}()
}

// mergeBreakdown returns base plus extra, without mutating base.
func mergeBreakdown(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
