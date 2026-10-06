package consensus

import (
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// processAnchorSet validates and records an anchor-set transaction carried by block height. Like the BLS registry it is
// written during FinalizeBlock and is in force from the next height.
//
// It is judged against the versions accepted below this height and those this execution of the block accepted
// (blockAnchorSetRecords) - never against a version an earlier execution of the same block wrote - so executing the
// block again decides every transaction of it exactly as the first execution did, a refused one included. An acceptance
// whose record an earlier execution already wrote is not written twice.
func (app *ValidatorApp) processAnchorSet(at *AnchorSetTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: codeAnchorSetRefused, Log: "anchor set requires a ledger store"}
	}
	log, err := app.ledgerStore.LoadAnchorSet()
	if err != nil {
		// Refusing here would withhold the set's id from this node's app hash while nodes that could read their ledger
		// include it: a fork. Stop.
		app.logger.Fatalf("❌ [ANCHOR-SET] the anchor set log could not be read at height %d: %v", height, err)
	}
	before := &ledger.AnchorSetLog{}
	for _, r := range log.Versions {
		if r.Height < height {
			before.Versions = append(before.Versions, r)
		}
	}
	for _, r := range app.blockAnchorSetRecords {
		if r.Height == height {
			before.Versions = append(before.Versions, r)
		}
	}

	// The same version accepted earlier in this block: the same set again is accepted and changes nothing.
	for i := range before.Versions {
		r := &before.Versions[i]
		if r.Version != at.Version {
			continue
		}
		if r.Height == height && r.ID == at.AnchorSetID() {
			app.blockBundles = append(app.blockBundles, r.ID)
			return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
		}
		return abcitypes.ExecTxResult{Code: codeAnchorSetRefused, Log: "anchor set refused: version already used"}
	}

	policy, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		app.logger.Fatalf("❌ [ANCHOR-SET] the committed policy (admin quorum) could not be read at height %d: %v", height, err)
	}
	// Judged by the admin set in force for this block (AdminSetAt, applied by VerifyAnchorSet).
	rec, err := VerifyAnchorSet(at, app.cometChainID, policy, before, height)
	if err != nil {
		app.logger.Printf("🚫 [ANCHOR-SET] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: codeAnchorSetRefused, Log: "anchor set refused: " + err.Error()}
	}
	written := false
	for _, r := range log.Versions {
		if r.Height == height && r.Version == rec.Version {
			if r.ID != rec.ID {
				app.logger.Fatalf("❌ [ANCHOR-SET] height %d already records anchor set version %d as %s, but this execution "+
					"of the block accepts %s: the committed record and this block disagree", height, rec.Version, r.ID, rec.ID)
			}
			written = true
		}
	}
	if !written {
		log.Versions = append(log.Versions, *rec)
		if err := app.ledgerStore.SaveAnchorSet(log); err != nil {
			app.logger.Fatalf("❌ [ANCHOR-SET] could not persist an accepted anchor set at height %d: %v", height, err)
		}
		app.logger.Printf("⚓ [ANCHOR-SET] version %d accepted at height %d: %v; in force from height %d (rules v14 active)",
			rec.Version, height, rec.Anchors, height+1)
	}
	app.blockAnchorSetRecords = append(app.blockAnchorSetRecords, *rec)
	app.blockBundles = append(app.blockBundles, rec.ID)
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}

// anchorSetInForce is the anchor set in force for a block at height h - nil before the v14 activation. A log this node
// cannot read stops it: judging without it would decide blocks the v13 way where every peer decides them the v14 way.
func (app *ValidatorApp) anchorSetInForce(h int64) *ledger.AnchorSetRecord {
	if app.ledgerStore == nil {
		return nil
	}
	log, err := app.ledgerStore.LoadAnchorSet()
	if err != nil {
		app.logger.Fatalf("❌ [ANCHOR-SET] the anchor set log could not be read at height %d: %v", h, err)
	}
	return AnchorSetAt(log, h)
}

// judgeAnchors applies the v14 anchor rule to a ValidatorBlock of the block being finalized: once an anchor set is in
// force, every chain target names its chain's committed anchor. Before it, nothing changes (v13's verdict). Every
// refusal is a v14 verdict.
func (app *ValidatorApp) judgeAnchors(vb *ValidatorBlock, set *ledger.AnchorSetRecord) *abcitypes.ExecTxResult {
	if set == nil {
		return nil
	}
	if err := CheckChainTargetAnchors(vb, set); err != nil {
		app.blockRulesV14Verdict = true
		app.logger.Printf("🚫 [ANCHOR-SET] REJECTED bundle=%s validator=%q height=%d: %v", vb.BundleID, vb.ValidatorID,
			app.currentBlockHeight, err)
		return &abcitypes.ExecTxResult{Code: codeAnchorNotCommitted, Log: "anchor refused: " + err.Error()}
	}
	return nil
}

// AnchorSetContext is the anchor set in force for the next block, nil when none is recorded - read from the same
// committed state FinalizeBlock judges by. A proposer admits intents against it (CheckAnchorSetAdmission).
func (app *ValidatorApp) AnchorSetContext() (*ledger.AnchorSetRecord, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.ledgerStore == nil {
		return nil, fmt.Errorf("the validator app has no ledger store")
	}
	log, err := app.ledgerStore.LoadAnchorSet()
	if err != nil {
		return nil, fmt.Errorf("the anchor set could not be read: %w", err)
	}
	return AnchorSetAt(log, app.latestHeight+1), nil
}
