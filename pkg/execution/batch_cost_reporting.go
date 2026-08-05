package execution

import (
	"context"

	"github.com/certen/independant-validator/pkg/billing"
)

// =============================================================================
// Cost reporting for the BATCH settlement path
// =============================================================================
//
// # THE GAP THIS CLOSES
//
// reportExecutionCosts (cost_reporting.go) has exactly one caller, inside
// BFTTargetChainExecutor. The batch and on-demand settle paths never reached it, so from the
// moment batching became the settlement path NOTHING reported cost at all — the newest row in
// the gateway's cost_events was 2026-08-02 while intents kept settling daily.
//
// That was invisible because it fails silently in both directions: the validator logs nothing
// when it does not report, and the gateway cannot distinguish "no cost events for this chain"
// from "this chain has no traffic". The pricing gate reads zero events and the gas estimator
// takes a median over an empty set, producing a zero estimate rather than an error.
//
// # PER-ANCHOR, THEN DIVIDED — NOT PER-INTENT
//
// The anchor is paid ONCE for N members. Attributing it per-intent would bill each of N intents
// for the same 81.2% of gas. So the anchor leg is measured once and split across the members
// that actually shared it (billing.ObserveAndReportShared), while each member's own settlement
// transaction is reported per-intent (billing.ObserveAndReport).
//
// This is the only place both facts are known at the same time: the anchor transaction hash and
// the member set it covered.

// costMember is one settled member and the identifiers cost attribution needs.
type costMember struct {
	IntentID    string
	AccumTxHash string
	// ADIURL is the authorising Accumulate identity. NOT an org id — the validator cannot know
	// the gateway's org UUID, and supplying anything else fails the uuid cast at insert.
	ADIURL   string
	SettleTx string // this member's own transaction; empty if it never reached the chain
}

// reportBatchCosts attributes one settled batch.
//
// anchorTx is shared across every member; each member's SettleTx is its own. Safe to call with
// a single member — a solo intent is a one-member batch and the shared split degenerates to the
// whole cost, so the on-demand and batched paths produce structurally identical rows.
//
// Never blocks: every reporter call is asynchronous and WAL-backed, so a slow or unreachable
// gateway cannot delay settlement.
func (o *BatchOrchestrator) reportBatchCosts(
	ctx context.Context,
	chainID int64,
	anchorTx string,
	verifyTx string,
	members []costMember,
) {
	reporter := CostReporter()
	if reporter == nil || len(members) == 0 {
		return
	}

	chain, resolvedChainID := canonicalChainSlugForChainID(chainID)
	if chain == "" {
		o.logf("[COST] chain %d has no canonical slug; cost for this batch will be unattributable "+
			"at the gateway, which keys everything by slug", chainID)
		return
	}
	rpcURL, apiKey := costEndpointForChain(chain)
	if rpcURL == "" {
		o.logf("[COST] no RPC endpoint for %s; this batch will be unmeasured and the chain will "+
			"stay unpriceable", chain)
		return
	}

	// ---- Shared: the anchor, paid once for the whole batch --------------------
	if anchorTx != "" {
		shared := make([]billing.CostMember, 0, len(members))
		for _, m := range members {
			shared = append(shared, billing.CostMember{
				IntentID:    m.IntentID,
				ADIURL:      m.ADIURL,
				AccumTxHash: m.AccumTxHash,
			})
		}
		reporter.ObserveAndReportShared(ctx, billing.ProbeConfig{
			Chain:   chain,
			ChainID: resolvedChainID,
			RPCURL:  rpcURL,
			APIKey:  apiKey,
			Leg:     billing.LegAnchor,
		}, shared, anchorTx, nil)
	}

	// ---- Shared: the verify, also paid once for the whole batch ---------------
	//
	// executeComprehensiveProof verifies the WHOLE batch root in one transaction, so it is
	// shared on exactly the same terms as the anchor. Its hash used to be discarded by
	// SubmitBatchQuorumProof, which left every batch-settled chain stuck at 2 of 3 measured
	// legs — and the pricing gate treats partial leg coverage as unpriceable, so no chain
	// settled by the batch path could ever become quotable.
	if verifyTx != "" {
		shared := make([]billing.CostMember, 0, len(members))
		for _, m := range members {
			shared = append(shared, billing.CostMember{
				IntentID:    m.IntentID,
				ADIURL:      m.ADIURL,
				AccumTxHash: m.AccumTxHash,
			})
		}
		reporter.ObserveAndReportShared(ctx, billing.ProbeConfig{
			Chain:   chain,
			ChainID: resolvedChainID,
			RPCURL:  rpcURL,
			APIKey:  apiKey,
			Leg:     billing.LegVerify,
		}, shared, verifyTx, nil)
	}

	// ---- Per member: its own settlement transaction --------------------------
	for _, m := range members {
		if m.SettleTx == "" {
			// A member with no transaction never reached the chain, so there is no cost to
			// measure. Not an error — a dropped or deferred member legitimately has none.
			continue
		}
		reporter.ObserveAndReport(ctx, billing.ProbeConfig{
			Chain:   chain,
			ChainID: resolvedChainID,
			RPCURL:  rpcURL,
			APIKey:  apiKey,
			Leg:     billing.LegVaultExecute,
		}, m.IntentID, m.ADIURL, m.AccumTxHash, m.SettleTx, nil)
	}

	o.logf("[COST] chain=%s reported anchor+verify(shared across %d) + %d member settlement(s)",
		chain, len(members), countSettled(members))
}

func countSettled(members []costMember) int {
	n := 0
	for _, m := range members {
		if m.SettleTx != "" {
			n++
		}
	}
	return n
}

// canonicalChainSlugForChainID resolves a numeric chain id to the gateway's slug.
//
// The batch path knows the chain by NUMBER (it is keyed on chainID throughout), whereas the
// executor path knows it by name. Both must produce the same spelling or cost_events splits
// into two chains that are one — the failure canonicalChainSlug was written to close.
func canonicalChainSlugForChainID(chainID int64) (string, int64) {
	if slug, ok := evmCanonicalSlugForChainID(chainID); ok {
		return slug, chainID
	}
	return "", 0
}

// costEndpointForChain resolves the RPC to probe for a chain's fee data. Shared with the
// executor path so both probe the endpoint that actually executed the transaction.
func costEndpointForChain(chain string) (string, string) {
	return resolveCostEndpointForChain(chain)
}

// lastVerifyTx returns the executeComprehensiveProof transaction from the prover that just ran,
// consuming it so it cannot be attributed to a later batch.
//
// Returns empty when the prover is not a *BatchQuorumAttestor (tests use stubs) or when the
// attestation did not reach a mined transaction. Reporting nothing is correct there: a verify
// leg that never landed has no cost to measure.
func (o *BatchOrchestrator) lastVerifyTx() string {
	if a, ok := o.prover.(interface{ TakeLastVerifyTx() string }); ok {
		return a.TakeLastVerifyTx()
	}
	return ""
}
