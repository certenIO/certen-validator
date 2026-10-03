package consensus

import (
	"strings"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// processValidatorRotation judges a rotation carried by block `height` and, when it is accepted, records it
// and stages the ValidatorUpdates this block returns (RB3-F95).
//
// Like a policy update, the rotation is persisted here, in FinalizeBlock. It is judged against the rotations
// accepted below this height and those this execution of the block accepted (blockRotationRecords) - never
// against a rotation an earlier execution of the same block wrote - so executing the block again (a crash
// between FinalizeBlock and Commit, or a handshake replay) decides every transaction of it exactly as the first
// execution did, a refused one included, and returns the same updates. An acceptance whose record an earlier
// execution already wrote is not written twice.
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
	before := &ledger.ValidatorRotationLog{}
	for _, r := range log.Rotations {
		if r.Height < height {
			before.Rotations = append(before.Rotations, r)
		}
	}
	for _, r := range app.blockRotationRecords {
		if r.Height == height {
			before.Rotations = append(before.Rotations, r)
		}
	}

	// A version already used - below this block, or earlier in it.
	for i := range before.Rotations {
		r := &before.Rotations[i]
		if r.Version != vr.Version {
			continue
		}
		if r.Height == height && r.ID == vr.RotationID() {
			// The rotation this block already accepted, again (in other bytes). Rules v11 accepted it a second time
			// and returned its validator updates twice, which CometBFT refuses as a duplicate entry: every node would
			// fail to apply the block. v12 refuses the copy - a verdict v11 does not reach (committedRulesVersion).
			app.blockRulesV12Verdict = true
			return abcitypes.ExecTxResult{Code: 6, Log: "validator rotation refused: this block already accepted this rotation; one rotation per block"}
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
	// Judged by the admin set in force for this block (AdminSetAt, rules v11).
	power, err := VerifyValidatorRotation(vr, app.cometChainID, withAdminSetAt(policy, height), app.genesisValidators, before, height)
	if err != nil {
		app.logger.Printf("🚫 [ROTATION] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: 6, Log: "validator rotation refused: " + err.Error()}
	}

	rec := ledger.ValidatorRotationRecord{
		Version:   vr.Version,
		Height:    height,
		OldPubKey: strings.ToLower(strings.TrimPrefix(vr.OldPubKey, "0x")),
		NewPubKey: strings.ToLower(strings.TrimPrefix(vr.NewPubKey, "0x")),
		Power:     power,
		ID:        vr.RotationID(),
	}
	written := false
	for _, r := range log.Rotations {
		if r.Height == height && r.Version == rec.Version {
			if r.ID != rec.ID || r.OldPubKey != rec.OldPubKey || r.NewPubKey != rec.NewPubKey || r.Power != rec.Power {
				app.logger.Fatalf("❌ [ROTATION] height %d already records rotation version %d as %s, but this execution of "+
					"the block accepts %s: the committed record and this block disagree", height, rec.Version, r.ID, rec.ID)
			}
			written = true
		}
	}
	if !written {
		log.Rotations = append(log.Rotations, rec)
		if err := app.ledgerStore.SaveValidatorRotations(log); err != nil {
			// Persisting failed here but may have succeeded elsewhere: the fleet would disagree about the set.
			app.logger.Fatalf("❌ [ROTATION] could not persist an accepted rotation at height %d: %v", height, err)
		}
		app.logger.Printf("🔑 [ROTATION] accepted at height %d: version %d, %s... -> %s... (power %d), effective at height %d",
			height, vr.Version, vr.OldPubKey[:min(12, len(vr.OldPubKey))], vr.NewPubKey[:min(12, len(vr.NewPubKey))],
			power, height+2)
	}
	app.blockRotationRecords = append(app.blockRotationRecords, rec)
	return app.stageRotation(&rec)
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
