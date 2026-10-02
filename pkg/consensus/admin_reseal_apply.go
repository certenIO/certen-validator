package consensus

import (
	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// processAdminReseal validates and records an admin re-seal carried by block height (rules v11, admin_reseal.go). It is
// written during FinalizeBlock and takes effect from height+1 (AdminSetAt); replay of the block that accepted it is
// recognised by its height and id, as a rotation's or a registry's is.
func (app *ValidatorApp) processAdminReseal(rt *AdminResealTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: codeAdminResealRefused, Log: "admin re-seal requires a ledger store"}
	}
	state, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		// Refusing here would withhold the re-seal's id from this node's app hash while nodes that could read their
		// ledger include it: a fork. Stop.
		app.logger.Fatalf("❌ [ADMIN-RESEAL] the committed policy could not be read at height %d: %v", height, err)
	}

	// REPLAY: this block already accepted this re-seal.
	if state != nil {
		for _, r := range state.AdminReseals {
			if r.Height == height && r.ID == rt.ResealID() {
				app.blockBundles = append(app.blockBundles, r.ID)
				return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
			}
		}
	}

	if err := verifyAdminReseal(rt, app.cometChainID, state, height, lostAdminSet, resealedAdminSet); err != nil {
		app.logger.Printf("🚫 [ADMIN-RESEAL] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: codeAdminResealRefused, Log: "admin re-seal refused: " + err.Error()}
	}

	next := *state // copy; never mutate committed state in place
	next.AdminReseals = append(append([]ledger.AdminReseal(nil), state.AdminReseals...), ledger.AdminReseal{
		Height: height, ID: rt.ResealID(), Keys: rt.AdminKeys, Threshold: rt.AdminThreshold,
	})
	if err := app.ledgerStore.SaveEntitlementPolicy(&next); err != nil {
		// Persisting failed here but may have succeeded elsewhere: the fleet would disagree about its admins. Stop.
		app.logger.Fatalf("❌ [ADMIN-RESEAL] could not persist an accepted re-seal at height %d: %v", height, err)
	}
	app.logger.Printf("🔐 [ADMIN-RESEAL] accepted at height %d: the admin set is now %d keys, threshold %d, from height %d",
		height, len(rt.AdminKeys), rt.AdminThreshold, height+1)
	app.blockBundles = append(app.blockBundles, rt.ResealID())
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}
