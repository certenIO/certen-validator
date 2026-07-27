package consensus

import (
	abcitypes "github.com/cometbft/cometbft/abci/types"
)

// The ABCI side of policy updates. Both functions run inside FinalizeBlock and
// are therefore consensus-affecting, so both are pure functions of committed
// state and the block being executed. Neither reads the environment or a clock.

// activatePolicyForHeight sets the rule in force for the block about to be
// executed.
//
// It DERIVES the rule from the append-only schedule rather than mutating a
// stored "current mode". That distinction is the entire correctness argument:
// a mutated value reflects how far the chain has progressed, so replaying block
// 10 after the chain reached block 210 would judge block 10 by the rule active
// at 210 — the 2026-07-27 divergence, merely relocated. A derived value depends
// only on (schedule, height), so block 10 is judged identically however many
// times it is executed and in whatever order.
//
// Nothing is persisted here, which is what makes it safe to call on every
// block, including replayed ones.
func (app *ValidatorApp) activatePolicyForBlock(height int64, blockTimeUnix int64) {
	if app.ledgerStore == nil {
		return
	}
	state, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil || state == nil {
		return
	}

	active := ActivePolicyAt(state, blockTimeUnix)
	cfg, err := policyStateTo(active)
	if err != nil {
		// An unusable policy activating here would halt the fleet at this exact
		// height on every node. VerifyPolicyUpdate refuses unusable policies at
		// acceptance time precisely so this cannot happen.
		app.logger.Fatalf("❌ [POLICY] the rule active at height %d (block time %d) is unusable: %v",
			height, blockTimeUnix, err)
	}

	if cfg.Mode != app.entitlement.Mode {
		app.logger.Printf("🔐 [POLICY] rule at height %d: mode=%s (was %s) keys=%d fingerprint=%s",
			height, cfg.Mode, app.entitlement.Mode, len(cfg.Keys), PolicyFingerprint(active))
	}
	app.entitlement = cfg
}

// processPolicyUpdate validates and schedules a policy-update transaction.
//
// Accepting one does NOT change the rule in force; it appends to the schedule.
// The rule only ever changes by derivation at the activation height.
func (app *ValidatorApp) processPolicyUpdate(pu *PolicyUpdateTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: 5, Log: "policy updates require a ledger store"}
	}

	current, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		return abcitypes.ExecTxResult{Code: 5, Log: "could not load the committed policy: " + err.Error()}
	}

	// REPLAY. On re-execution the schedule already contains this update, so
	// verification would refuse it as stale — and a refusal would withhold its
	// id from the app hash, producing exactly the divergence this design
	// prevents. An already-scheduled update is therefore an accepted no-op.
	if IsPolicyUpdateScheduled(current, pu.Version) {
		app.blockBundles = append(app.blockBundles, pu.PolicyUpdateID())
		return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
	}

	if err := VerifyPolicyUpdate(pu, current, app.currentBlockTime.UTC().Unix()); err != nil {
		app.logger.Printf("🚫 [POLICY] rejected update at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: 5, Log: "policy update rejected: " + err.Error()}
	}

	next := ApplyPolicyUpdate(pu, current, height)
	if err := app.ledgerStore.SaveEntitlementPolicy(next); err != nil {
		// Persisting failed here but may have succeeded elsewhere, so the fleet
		// would disagree about the schedule. Stop rather than drift.
		app.logger.Fatalf("❌ [POLICY] could not persist an accepted update at height %d: %v", height, err)
	}

	// Contribute to the app hash, so nodes commit to the update having been
	// INCLUDED — not merely to its effect at the activation height.
	app.blockBundles = append(app.blockBundles, pu.PolicyUpdateID())

	app.logger.Printf("📜 [POLICY] scheduled at height %d: mode=%s activates at unix %d (version %d)",
		height, pu.Mode, pu.ActivationUnix, pu.Version)

	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}
