package consensus

import (
	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// processAdminRotate validates and records an admin rotation carried by block height (rules v12, admin_rotate.go). It is
// written during FinalizeBlock and takes effect from height+1 (AdminSetAt).
//
// The verdict is a function of the changes recorded BELOW this height and of this execution of the block alone - never
// of a record this block wrote in an earlier execution. So executing the block again (a handshake replay, or
// FinalizeBlock without Commit) decides every transaction of it exactly as the first execution did: the same refusals
// with the same reasons, the same acceptance. An acceptance whose record an earlier execution already wrote is not
// written twice. At most one admin-set change lands per block (blockAdminSetChanged).
func (app *ValidatorApp) processAdminRotate(rt *AdminRotateTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: codeAdminRotateRefused, Log: "admin rotation requires a ledger store"}
	}
	state, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		// Refusing here would withhold the rotation's id from this node's app hash while nodes that could read their
		// ledger include it: a fork. Stop.
		app.logger.Fatalf("❌ [ADMIN-ROTATE] the committed policy could not be read at height %d: %v", height, err)
	}

	if app.blockAdminSetChanged {
		app.logger.Printf("🚫 [ADMIN-ROTATE] refused at height %d: this block already changed the admin set", height)
		return abcitypes.ExecTxResult{Code: codeAdminRotateRefused,
			Log: "admin rotation refused: this block already changed the admin set; one admin-set change per block"}
	}
	if err := VerifyAdminRotate(rt, app.cometChainID, state, height); err != nil {
		app.logger.Printf("🚫 [ADMIN-ROTATE] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: codeAdminRotateRefused, Log: "admin rotation refused: " + err.Error()}
	}

	// An earlier execution of this block may already have recorded this acceptance; any other record at this height is
	// a contradiction - this block's changes are decided by this function alone - and judging on would fork.
	written := false
	for _, r := range state.AdminReseals {
		if r.Height != height {
			continue
		}
		if r.ID != rt.RotationID() {
			app.logger.Fatalf("❌ [ADMIN-ROTATE] height %d already records admin-set change %s, but this execution of the "+
				"block accepts %s: the committed record and this block disagree", height, r.ID, rt.RotationID())
		}
		written = true
	}
	if !written {
		keys := make(map[string]string, len(rt.NewAdminKeys))
		for id, k := range rt.NewAdminKeys {
			keys[id] = k
		}
		next := *state // copy; never mutate committed state in place
		next.AdminReseals = append(append([]ledger.AdminReseal(nil), state.AdminReseals...), ledger.AdminReseal{
			Height: height, ID: rt.RotationID(), Keys: keys, Threshold: rt.NewThreshold, Kind: AdminRotateKind, Sequence: rt.Sequence,
		})
		if err := app.ledgerStore.SaveEntitlementPolicy(&next); err != nil {
			// Persisting failed here but may have succeeded elsewhere: the fleet would disagree about its admins. Stop.
			app.logger.Fatalf("❌ [ADMIN-ROTATE] could not persist an accepted rotation at height %d: %v", height, err)
		}
		app.logger.Printf("🔐 [ADMIN-ROTATE] sequence %d accepted at height %d: the admin set is now %d keys, threshold %d "+
			"(set %s…), from height %d", rt.Sequence, height, len(keys), rt.NewThreshold, rt.NewSetID()[:16], height+1)
	}
	app.blockAdminSetChanged = true
	app.blockBundles = append(app.blockBundles, rt.RotationID())
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}
