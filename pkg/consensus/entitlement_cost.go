package consensus

import (
	"fmt"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// Worst-case cost of a ValidatorBlock, for the entitlement ceiling.
//
// # WHY A BOUND AND NOT AN ESTIMATE
//
// This number decides whether work is refused. An estimate that lands low
// refuses intents that would have been affordable — dropping a paying customer's
// work, which nothing downstream catches. So every step rounds AGAINST refusing:
// the figure is an upper bound on what CERTEN can spend, and an intent is
// refused only when even that bound exceeds the ceiling.
//
// # WHY THE INPUTS ARE WHAT THEY ARE
//
// Two candidate inputs were rejected as unsound, and the reasons are worth
// keeping because both look plausible:
//
//   - The intent's own `gasPolicy`. Submitter-controlled, and as of 2026-08-08
//     parsed but never honoured — execution gas comes from validator constants
//     (400000 + legs*250000). Bounding against a number the submitter writes and
//     the executor ignores is enforcement in appearance only: declare
//     gasLimit:1 and every ceiling passes.
//
//   - MaxGasPriceGwei. Genuinely binding at execution, but sourced from per-node
//     YAML/env — 100 gwei on sepolia, 1 on arbitrum, 100 by default. Two nodes
//     configured differently compute different bounds and reach different
//     verdicts on the same block, which is a fork.
//
// What remains is the published cost basis in the signed epoch header: measured
// by the gateway, signed with a key every validator pins, identical on every
// node, and controlled by no submitter.
//
// # DETERMINISM
//
// Integer arithmetic only, on int64, with an explicit overflow guard. Every
// validator must produce the identical number from the identical block: a
// divergence here is not a mispricing, it is a fork.

// legsPerChain counts a block's chain targets by chain id.
//
// ChainTargets is the block's own record of what will execute, derived from the
// intent's legs at build time. It is inside the OperationCommitment, so a
// proposer cannot understate it to shrink the bound without invalidating the
// block.
func legsPerChain(vb *ValidatorBlock) map[int64]int64 {
	out := make(map[int64]int64)
	if vb == nil {
		return out
	}
	for _, t := range vb.CrossChainProof.ChainTargets {
		out[t.ChainID]++
	}
	return out
}

// maxInt64 guards the multiplications below.
const maxInt64 = int64(^uint64(0) >> 1)

// WorstCaseCostMicroUSD bounds what executing this block can cost, in micro-USD.
//
// Returns ok=false when no basis was published for a chain the block touches. The
// caller must then SKIP the cost ceiling rather than treat the intent as free:
// an unpriced chain is one we cannot bound, and refusing on a missing bound would
// turn a gateway configuration gap into a refusal of legitimate work, while
// admitting it as zero would let an unpriced chain bypass the ceiling entirely.
// Neither is acceptable, so the ceiling simply does not apply and the status gate
// still does.
func WorstCaseCostMicroUSD(vb *ValidatorBlock, h entitlement.Header) (total int64, ok bool, err error) {
	perChain := legsPerChain(vb)
	if len(perChain) == 0 {
		// No chain targets: nothing will execute on any chain, so the bound is
		// zero and it is a genuine bound, not a missing one.
		return 0, true, nil
	}

	for chainID, legs := range perChain {
		basis, found := h.CostBasisFor(chainID)
		if !found {
			return 0, false, nil
		}
		if basis.BaseMicroUSD < 0 || basis.PerLegMicroUSD < 0 {
			return 0, false, fmt.Errorf("negative cost basis for chain %d", chainID)
		}

		// base + perLeg * (legs - 1). Legs beyond the first cost their MARGINAL
		// share because they ride in the same settlement transaction — measured
		// on base-sepolia 2026-08-07: 5 legs settled in one transaction of
		// 423,519 gas against 156,318 for one leg.
		chainTotal := basis.BaseMicroUSD
		if legs > 1 {
			extra := legs - 1
			if basis.PerLegMicroUSD != 0 && extra > maxInt64/basis.PerLegMicroUSD {
				return 0, false, fmt.Errorf("cost basis overflow for chain %d with %d legs", chainID, legs)
			}
			marginal := basis.PerLegMicroUSD * extra
			if chainTotal > maxInt64-marginal {
				return 0, false, fmt.Errorf("cost basis overflow for chain %d with %d legs", chainID, legs)
			}
			chainTotal += marginal
		}

		if total > maxInt64-chainTotal {
			return 0, false, fmt.Errorf("cost basis overflow summing chains")
		}
		total += chainTotal
	}
	return total, true, nil
}
