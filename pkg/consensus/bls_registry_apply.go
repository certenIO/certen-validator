package consensus

import (
	"errors"
	"fmt"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// processBLSRegistry validates and records a BLS registry transaction carried by block height. Like a
// rotation it is written during FinalizeBlock, so the next transaction of the same block - and every later
// block - is judged against it.
//
// It is judged against the versions accepted below this height and those this execution of the block accepted
// (blockRegistryRecords) - never against a version an earlier execution of the same block wrote - so executing the
// block again decides every transaction of it exactly as the first execution did, a refused one included. An
// acceptance whose record an earlier execution already wrote is not written twice.
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
	before := &ledger.BLSRegistryLog{}
	for _, r := range log.Versions {
		if r.Height < height {
			before.Versions = append(before.Versions, r)
		}
	}
	for _, r := range app.blockRegistryRecords {
		if r.Height == height {
			before.Versions = append(before.Versions, r)
		}
	}

	// The same version accepted earlier in this block: the same registry again is accepted and changes nothing.
	for i := range before.Versions {
		r := &before.Versions[i]
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
	// Judged by the admin set in force for this block (AdminSetAt, rules v11).
	rec, err := VerifyBLSRegistry(rt, app.cometChainID, withAdminSetAt(policy, height), before, height)
	if err != nil {
		app.logger.Printf("🚫 [BLS-REGISTRY] refused at height %d: %v", height, err)
		return abcitypes.ExecTxResult{Code: codeBLSRegistryRefused, Log: "BLS registry refused: " + err.Error()}
	}
	written := false
	for _, r := range log.Versions {
		if r.Height == height && r.Version == rec.Version {
			if r.ID != rec.ID {
				app.logger.Fatalf("❌ [BLS-REGISTRY] height %d already records registry version %d as %s, but this execution "+
					"of the block accepts %s: the committed record and this block disagree", height, rec.Version, r.ID, rec.ID)
			}
			written = true
		}
	}
	if !written {
		log.Versions = append(log.Versions, *rec)
		if err := app.ledgerStore.SaveBLSRegistry(log); err != nil {
			app.logger.Fatalf("❌ [BLS-REGISTRY] could not persist an accepted registry at height %d: %v", height, err)
		}
		app.logger.Printf("🔐 [BLS-REGISTRY] version %d accepted at height %d: %d members, threshold %d/%d, CERTEN set root %s, "+
			"incarnation %s; in force from height %d", rec.Version, height, len(rec.Members), rec.ThresholdNumerator,
			rec.ThresholdDenominator, rec.CertenSetRoot, rec.AccumulateIncarnation, height+1)
	}
	app.blockRegistryRecords = append(app.blockRegistryRecords, *rec)
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
	// Judged with the spine as this block sees it: committed below it and accepted earlier in it. No spine of the
	// registry's incarnation means v3 is not required (ProofV3Required); an unreadable one would judge differently
	// here than on nodes that can read it, so the node stops.
	spine, err := app.accumulateSpineAt(int64(app.currentBlockHeight))
	if errors.Is(err, ErrSpineNotRegistryIncarnation) {
		spine, err = nil, nil
	}
	if err != nil {
		app.logger.Fatalf("❌ [INTENT-CERT] the Accumulate spine could not be read at height %d: %v", app.currentBlockHeight, err)
	}
	if _, err := VerifyIntentCertificate(vb, app.cometChainID, reg, spine); err != nil {
		return refuse(err.Error())
	}
	return nil
}

// IntentCertificateContext is what a proposer builds an intent certificate against: the CERTEN chain id this
// chain judges certificates under (its genesis, never configuration) and the BLS registry in force for the next
// block, nil when none is recorded. Read from the same committed state FinalizeBlock judges by.
func (app *ValidatorApp) IntentCertificateContext() (string, *ledger.BLSRegistryRecord, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.ledgerStore == nil {
		return "", nil, fmt.Errorf("the validator app has no ledger store")
	}
	if app.cometChainID == "" {
		return "", nil, fmt.Errorf("the validator app has no genesis chain id")
	}
	log, err := app.ledgerStore.LoadBLSRegistry()
	if err != nil {
		return "", nil, fmt.Errorf("the BLS registry could not be read: %w", err)
	}
	return app.cometChainID, RegistryAt(log, app.latestHeight+1), nil
}

// CommittedAccumulateSpine is the Accumulate spine as committed: what a proposer builds a v3 intent certificate
// against (ProofV3Required, and the checkpoints its proof v2 may start from). An unreadable spine is an error, never
// an empty one, which would build a v2 certificate the chain refuses.
func (app *ValidatorApp) CommittedAccumulateSpine() (*ledger.AccumulateSpineLog, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.ledgerStore == nil {
		return nil, fmt.Errorf("the validator app has no ledger store")
	}
	spine, err := app.ledgerStore.LoadAccumulateSpine()
	if err != nil {
		return nil, fmt.Errorf("the Accumulate spine could not be read: %w", err)
	}
	return spine, nil
}

// ProofV2Bound implements intent.ProofV2Gate from committed state: whether the next block requires the v3 intent
// certificate, and how many major blocks the chain has verified.
func (app *ValidatorApp) ProofV2Bound() (bool, uint64, error) {
	_, reg, err := app.IntentCertificateContext()
	if err != nil {
		return false, 0, err
	}
	spine, err := app.CommittedAccumulateSpine()
	if err != nil {
		return false, 0, err
	}
	return ProofV3Required(spine, reg), uint64(len(spine.Checkpoints)), nil
}
