package consensus

import (
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// processG1Activation validates and records a cross-partition activation carried by block height. Like the anchor set it
// is written during FinalizeBlock and is in force from the next height (G1ActivationAt: accepted below the height).
//
// It is judged against the activations accepted below this height and those this execution of the block accepted
// (blockG1ActivationRecords) - never against a record an earlier execution of the same block wrote - so executing the
// block again decides every transaction of it exactly as the first execution did, a refused one included. An acceptance
// whose record an earlier execution already wrote is not written twice.
func (app *ValidatorApp) processG1Activation(ga *G1ActivationTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: codeG1ActivationRefused, Log: "cross-partition activation requires a ledger store"}
	}
	log, err := app.ledgerStore.LoadG1Activation()
	if err != nil {
		// Refusing here would withhold the activation's id from this node's app hash while nodes that could read their
		// ledger include it: a fork. Stop.
		app.logger.Fatalf("❌ [G1-ACTIVATION] the activation log could not be read at height %d: %v", height, err)
	}
	before := &ledger.G1ActivationLog{}
	for _, r := range log.Activations {
		if r.Height < height {
			before.Activations = append(before.Activations, r)
		}
	}
	for _, r := range app.blockG1ActivationRecords {
		if r.Height == height {
			before.Activations = append(before.Activations, r)
		}
	}

	// The same activation accepted earlier in this block: the same bytes again are accepted and change nothing; anything
	// else after an accepted activation is refused (there is one activation per chain).
	if len(before.Activations) > 0 {
		r := before.Activations[0]
		if r.Height == height && r.ID == ga.ActivationID() {
			app.blockBundles = append(app.blockBundles, r.ID)
			return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
		}
		return abcitypes.ExecTxResult{Code: codeG1ActivationRefused, Log: "cross-partition activation refused: the chain is already activated"}
	}

	policy, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		app.logger.Fatalf("❌ [G1-ACTIVATION] the committed policy (admin quorum) could not be read at height %d: %v", height, err)
	}
	// Judged by the admin set in force for this block (AdminSetAt, applied by VerifyG1Activation).
	rec, err := VerifyG1Activation(ga, app.cometChainID, policy, before, height)
	if err != nil {
		app.logger.Printf("🚫 [G1-ACTIVATION] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: codeG1ActivationRefused, Log: "cross-partition activation refused: " + err.Error()}
	}
	written := false
	for _, r := range log.Activations {
		if r.Height == height {
			if r.ID != rec.ID {
				app.logger.Fatalf("❌ [G1-ACTIVATION] height %d already records activation %s, but this execution of the block "+
					"accepts %s: the committed record and this block disagree", height, r.ID, rec.ID)
			}
			written = true
		}
	}
	if !written {
		log.Activations = append(log.Activations, *rec)
		if err := app.ledgerStore.SaveG1Activation(log); err != nil {
			app.logger.Fatalf("❌ [G1-ACTIVATION] could not persist an accepted activation at height %d: %v", height, err)
		}
		app.logger.Printf("🧭 [G1-ACTIVATION] accepted at height %d; evidence 2.1 is required from height %d (rules v15 active)",
			height, height+1)
	}
	app.blockG1ActivationRecords = append(app.blockG1ActivationRecords, *rec)
	app.blockBundles = append(app.blockBundles, rec.ID)
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}

// g1ActivationInForce is the activation in force for a block at height h - nil before the v15 activation. A log this node
// cannot read stops it: judging without it would decide blocks the v14 way where every peer decides them the v15 way.
func (app *ValidatorApp) g1ActivationInForce(h int64) *ledger.G1ActivationRecord {
	if app.ledgerStore == nil {
		return nil
	}
	log, err := app.ledgerStore.LoadG1Activation()
	if err != nil {
		app.logger.Fatalf("❌ [G1-ACTIVATION] the activation log could not be read at height %d: %v", h, err)
	}
	return G1ActivationAt(log, h)
}

// G1CrossPartitionRequired implements intent.ProofV2G1Gate: whether the next block requires evidence 2.1 in every v3 certificate, read
// from the same committed state as G1ActivationContext. The intent discovery asks it per intent, so it builds 2.1 exactly when the
// activation is in force and otherwise behaves as before.
func (app *ValidatorApp) G1CrossPartitionRequired() (bool, error) {
	g, err := app.G1ActivationContext()
	if err != nil {
		return false, err
	}
	return G1CrossPartitionRequired(g), nil
}

// G1ActivationContext is the activation in force for the next block, nil when none is recorded - read from the same
// committed state FinalizeBlock judges by. A proposer builds intent certificates against it (BuildIntentCertificate).
func (app *ValidatorApp) G1ActivationContext() (*ledger.G1ActivationRecord, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.ledgerStore == nil {
		return nil, fmt.Errorf("the validator app has no ledger store")
	}
	log, err := app.ledgerStore.LoadG1Activation()
	if err != nil {
		return nil, fmt.Errorf("the cross-partition activation could not be read: %w", err)
	}
	return G1ActivationAt(log, app.latestHeight+1), nil
}
