package consensus

import (
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/metrics"
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
	if err != nil {
		// RB3-F116: keeping the previous rule because the committed one could not be read would
		// judge this block by a rule the fleet may not be applying. Stop rather than drift.
		app.logger.Fatalf("❌ [POLICY] the committed policy could not be read at height %d: %v", height, err)
	}
	if state == nil {
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
		// The gauge states the mode the chain enforces, so it moves when the rule does (RB4-F37a).
		metrics.SetEntitlementMode(string(cfg.Mode))
	}
	app.entitlement = cfg
}

// processPolicyUpdate validates and schedules a policy-update transaction.
//
// Accepting one does NOT change the rule in force; it appends to the schedule.
// The rule only ever changes by derivation at the activation height.
//
// It is judged against the schedule as it stood before this block - the entries
// proposed below this height - plus the updates this execution of the block
// accepted (blockPolicyChanges), never against an entry an earlier execution of
// the same block wrote. So executing the block again (a crash between
// FinalizeBlock and Commit, or a handshake replay) decides every transaction of
// it exactly as the first execution did, a refused one included; an acceptance
// an earlier execution already scheduled is not scheduled twice.
func (app *ValidatorApp) processPolicyUpdate(pu *PolicyUpdateTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: 5, Log: "policy updates require a ledger store"}
	}

	current, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		// RB3-F116: refusing here withholds the update's id from this node's app hash while the
		// nodes that could read their ledger include it - a fork. Stop rather than drift, as a
		// failed persist below does.
		app.logger.Fatalf("❌ [POLICY] the committed policy could not be read at height %d: %v", height, err)
	}
	var before *ledger.EntitlementPolicyState
	if current != nil {
		b := *current // copy; never mutate committed state in place
		b.Schedule = nil
		for _, e := range current.Schedule {
			if e.ProposedAtHeight < height {
				b.Schedule = append(b.Schedule, e)
			}
		}
		for _, e := range app.blockPolicyChanges {
			if e.ProposedAtHeight == height {
				b.Schedule = append(b.Schedule, e)
			}
		}
		before = &b
	}

	// An update whose version is already scheduled. Scheduled earlier in THIS block, the same version again is the
	// accepted no-op it always was. Scheduled in an earlier block, it is a replay: rules v11 accepted it as a no-op too -
	// whatever it carried, signed or not - which made "an update cannot be replayed" untrue; v12 refuses it by name, a
	// verdict v11 does not reach (committedRulesVersion).
	if before != nil {
		for _, e := range before.Schedule {
			if e.Version != pu.Version {
				continue
			}
			if e.ProposedAtHeight < height {
				app.blockRulesV12Verdict = true
				app.logger.Printf("🚫 [POLICY] rejected update at height %d: version %d was scheduled at height %d", height, pu.Version, e.ProposedAtHeight)
				return abcitypes.ExecTxResult{Code: 5, Log: fmt.Sprintf("policy update rejected: version %d was scheduled at "+
					"height %d; an update cannot be replayed", pu.Version, e.ProposedAtHeight)}
			}
			app.blockBundles = append(app.blockBundles, pu.PolicyUpdateID())
			return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
		}
	}

	// Judged by the admin set in force for this block (AdminSetAt, rules v11); the update is applied to the committed
	// state itself, whose genesis seal and re-seal record it leaves untouched.
	if err := VerifyPolicyUpdateOnChain(pu, withAdminSetAt(before, height), app.currentBlockTime.UTC().Unix(), app.cometChainID); err != nil {
		app.logger.Printf("🚫 [POLICY] rejected update at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: 5, Log: "policy update rejected: " + err.Error()}
	}

	accepted := ApplyPolicyUpdate(pu, before, height).Schedule
	entry := accepted[len(accepted)-1]
	if IsPolicyUpdateScheduled(current, pu.Version) {
		// An earlier execution of this block scheduled it; anything else under this version is a contradiction.
		for _, e := range current.Schedule {
			if e.Version == pu.Version && !sameScheduledChange(e, entry) {
				app.logger.Fatalf("❌ [POLICY] version %d is already scheduled at height %d, but this execution of block %d "+
					"accepts another update under it: the committed schedule and this block disagree", pu.Version, e.ProposedAtHeight, height)
			}
		}
	} else {
		next := ApplyPolicyUpdate(pu, current, height)
		if err := app.ledgerStore.SaveEntitlementPolicy(next); err != nil {
			// Persisting failed here but may have succeeded elsewhere, so the fleet
			// would disagree about the schedule. Stop rather than drift.
			app.logger.Fatalf("❌ [POLICY] could not persist an accepted update at height %d: %v", height, err)
		}
		app.logger.Printf("📜 [POLICY] scheduled at height %d: mode=%s activates at unix %d (version %d)",
			height, pu.Mode, pu.ActivationUnix, pu.Version)
	}
	app.blockPolicyChanges = append(app.blockPolicyChanges, entry)

	// Contribute to the app hash, so nodes commit to the update having been
	// INCLUDED — not merely to its effect at the activation height.
	app.blockBundles = append(app.blockBundles, pu.PolicyUpdateID())

	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}

// sameScheduledChange reports whether two schedule entries are the same accepted update.
func sameScheduledChange(a, b ledger.ScheduledPolicyChange) bool {
	if a.Mode != b.Mode || a.ActivationUnix != b.ActivationUnix || a.Version != b.Version ||
		a.ProposedAtHeight != b.ProposedAtHeight || len(a.Keys) != len(b.Keys) {
		return false
	}
	for id, k := range a.Keys {
		if b.Keys[id] != k {
			return false
		}
	}
	return true
}
