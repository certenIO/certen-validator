package consensus

import (
	abcitypes "github.com/cometbft/cometbft/abci/types"
)

// processBLSRegistry validates and records a BLS registry transaction carried by block height. Like a
// rotation it is written during FinalizeBlock, so the next transaction of the same block - and every later
// block - is judged against it; replay of the block that accepted it is recognised by version, height and id.
func (app *ValidatorApp) processBLSRegistry(rt *BLSRegistryTx, height int64) abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return abcitypes.ExecTxResult{Code: codeBLSRegistryRefused, Log: "BLS registry requires a ledger store"}
	}
	log, err := app.ledgerStore.LoadBLSRegistry()
	if err != nil {
		// Refusing here would withhold the registry's id from this node's app hash while nodes that could read
		// their ledger include it: a fork. Stop.
		app.logger.Fatalf("❌ [BLS-REGISTRY] the registry log could not be read at height %d: %v", height, err)
	}

	// REPLAY: this block already accepted this version.
	for i := range log.Versions {
		r := &log.Versions[i]
		if r.Version != rt.Version {
			continue
		}
		if r.Height == height && r.ID == rt.RegistryID() {
			app.blockBundles = append(app.blockBundles, r.ID)
			return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
		}
		return abcitypes.ExecTxResult{Code: codeBLSRegistryRefused, Log: "BLS registry refused: version already used"}
	}

	policy, err := app.ledgerStore.LoadEntitlementPolicy()
	if err != nil {
		app.logger.Fatalf("❌ [BLS-REGISTRY] the committed policy (admin quorum) could not be read at height %d: %v", height, err)
	}
	rec, err := VerifyBLSRegistry(rt, app.cometChainID, policy, log, height)
	if err != nil {
		app.logger.Printf("🚫 [BLS-REGISTRY] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: codeBLSRegistryRefused, Log: "BLS registry refused: " + err.Error()}
	}
	log.Versions = append(log.Versions, *rec)
	if err := app.ledgerStore.SaveBLSRegistry(log); err != nil {
		app.logger.Fatalf("❌ [BLS-REGISTRY] could not persist an accepted registry at height %d: %v", height, err)
	}
	app.logger.Printf("🔐 [BLS-REGISTRY] version %d accepted at height %d: %d members, threshold %d/%d, CERTEN set root %s, "+
		"incarnation %s; in force from height %d", rec.Version, height, len(rec.Members), rec.ThresholdNumerator,
		rec.ThresholdDenominator, rec.CertenSetRoot, rec.AccumulateIncarnation, height+1)
	app.blockBundles = append(app.blockBundles, rec.ID)
	return abcitypes.ExecTxResult{Code: 0, GasWanted: 1, GasUsed: 1}
}

// codeIntentCertificateRefused is the result code of a ValidatorBlock whose intent certificate is refused.
const codeIntentCertificateRefused uint32 = 10

// judgeIntentCertificate applies the intent rule to a ValidatorBlock of the block being finalized. Before any
// registry is in force nothing changes, except that a block claiming a certificate nothing could verify is
// refused. Once one is, every block must carry a certificate that verifies. Each outcome here is one v9 does not
// reach (v9 accepted every such block that passed its invariants), so each refusal is a v10 verdict.
func (app *ValidatorApp) judgeIntentCertificate(vb *ValidatorBlock) *abcitypes.ExecTxResult {
	if app.ledgerStore == nil {
		return &abcitypes.ExecTxResult{Code: codeIntentCertificateRefused, Log: "intent certificate: no ledger store"}
	}
	log, err := app.ledgerStore.LoadBLSRegistry()
	if err != nil {
		// Judging without the registry would accept here what nodes that can read it refuse: a fork. Stop.
		app.logger.Fatalf("❌ [INTENT-CERT] the BLS registry could not be read at height %d: %v", app.currentBlockHeight, err)
	}
	reg := RegistryAt(log, int64(app.currentBlockHeight))
	refuse := func(why string) *abcitypes.ExecTxResult {
		app.blockRulesV10Verdict = true
		app.logger.Printf("🚫 [INTENT-CERT] REJECTED bundle=%s validator=%q height=%d: %s", vb.BundleID, vb.ValidatorID,
			app.currentBlockHeight, why)
		return &abcitypes.ExecTxResult{Code: codeIntentCertificateRefused, Log: "intent certificate refused: " + why}
	}
	switch {
	case reg == nil && vb.IntentCertificate == nil:
		return nil
	case reg == nil:
		return refuse("the block carries an intent certificate, but no BLS registry is in force to verify it")
	}
	if _, err := VerifyIntentCertificate(vb, app.cometChainID, reg); err != nil {
		return refuse(err.Error())
	}
	return nil
}
