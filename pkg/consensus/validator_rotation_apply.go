package consensus

import (
	"strings"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// processValidatorRotation judges a rotation carried by block `height` and, when it is accepted, records it
// and stages the ValidatorUpdates this block returns (RB3-F95).
//
// Like a policy update, the rotation is persisted here, in FinalizeBlock, and a replay of the block that
// accepted it is an accepted no-op that returns the same updates - so a crash between FinalizeBlock and
// Commit, or a handshake replay, reproduces the block's result exactly.
func (app *ValidatorApp) processValidatorRotation(vr *ValidatorRotationTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: 6, Log: "validator rotation requires a ledger store"}
	}
	log, err := app.ledgerStore.LoadValidatorRotations()
	if err != nil {
		// A refusal here would withhold the rotation's id from this node's app hash while nodes that could
		// read their ledger include it, and would return different validator updates: a fork. Stop.
		app.logger.Fatalf("❌ [ROTATION] the validator rotation log could not be read at height %d: %v", height, err)
	}

	// REPLAY: this block already accepted this rotation.
	for i := range log.Rotations {
		r := &log.Rotations[i]
		if r.Version != vr.Version {
			continue
		}
		if r.Height == height && r.ID == vr.RotationID() {
			return app.stageRotation(r)
		}
		return abcitypes.ExecTxResult{Code: 6, Log: "validator rotation refused: version already used"}
	}

	if app.blockRotations > 0 {
		return abcitypes.ExecTxResult{Code: 6, Log: "validator rotation refused: one rotation per block"}
	}

	policy, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		app.logger.Fatalf("❌ [ROTATION] the committed policy (admin quorum) could not be read at height %d: %v", height, err)
	}
	power, err := VerifyValidatorRotation(vr, app.cometChainID, policy, app.genesisValidators, log, height)
	if err != nil {
		app.logger.Printf("🚫 [ROTATION] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: 6, Log: "validator rotation refused: " + err.Error()}
	}

	log.Rotations = append(log.Rotations, ledger.ValidatorRotationRecord{
		Version:   vr.Version,
		Height:    height,
		OldPubKey: strings.ToLower(strings.TrimPrefix(vr.OldPubKey, "0x")),
		NewPubKey: strings.ToLower(strings.TrimPrefix(vr.NewPubKey, "0x")),
		Power:     power,
		ID:        vr.RotationID(),
	})
	if err := app.ledgerStore.SaveValidatorRotations(log); err != nil {
		// Persisting failed here but may have succeeded elsewhere: the fleet would disagree about the set.
		app.logger.Fatalf("❌ [ROTATION] could not persist an accepted rotation at height %d: %v", height, err)
	}
	app.logger.Printf("🔑 [ROTATION] accepted at height %d: version %d, %s... -> %s... (power %d), effective at height %d",
		height, vr.Version, vr.OldPubKey[:min(12, len(vr.OldPubKey))], vr.NewPubKey[:min(12, len(vr.NewPubKey))],
		power, height+2)
	return app.stageRotation(&log.Rotations[len(log.Rotations)-1])
}

// stageRotation returns the rotation's updates to CometBFT and folds its id into this block's app hash.
func (app *ValidatorApp) stageRotation(r *ledger.ValidatorRotationRecord) abcitypes.ExecTxResult {
	updates, err := rotationUpdates(r)
	if err != nil {
		app.logger.Fatalf("❌ [ROTATION] an accepted rotation's keys do not decode: %v", err)
	}
	app.blockValidatorUpdates = append(app.blockValidatorUpdates, updates...)
	app.blockRotations++
	app.rotationAccepted = true
	app.blockBundles = append(app.blockBundles, r.ID)
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}

// recordRotationAdoption marks the pending rotation adopted when its new key signed the commit this block
// carries. Idempotent: an adopted rotation is not re-marked, so replay changes nothing.
func (app *ValidatorApp) recordRotationAdoption(height int64, commit abcitypes.CommitInfo) {
	if app.ledgerStore == nil {
		return
	}
	log, err := app.ledgerStore.LoadValidatorRotations()
	if err != nil {
		app.logger.Fatalf("❌ [ROTATION] the validator rotation log could not be read at height %d: %v", height, err)
	}
	if !markRotationAdopted(log, height, commit) {
		return
	}
	if err := app.ledgerStore.SaveValidatorRotations(log); err != nil {
		app.logger.Fatalf("❌ [ROTATION] could not persist a rotation's adoption at height %d: %v", height, err)
	}
	app.logger.Printf("✅ [ROTATION] the rotated validator is signing with its new key (adopted at height %d)", height)
}
