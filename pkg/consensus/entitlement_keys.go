package consensus

import (
	"fmt"
	"log"
	"time"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// One source for the entitlement key set.
//
// Consensus verifies an epoch's signature against the key set of the rule in force for the block - the policy sealed at
// genesis as changed by every policy update activated since (activatePolicyForBlock). The proposer's entitlement store
// verified the epochs it fetched against CERTEN_ENTITLEMENT_KEYS from the environment, read once at start: the genesis
// SEED, which a sealed chain ignores. After a key rotation in policy state the two disagreed - the store refused every
// epoch signed by the new key, so no evidence could be built for blocks consensus would accept, and it kept building
// evidence under the retired key, which consensus refuses. The store now reads its keys here, from the same committed
// state and the same derivation consensus uses.

// EntitlementConfigAt is the entitlement rule consensus applies to a block whose time is blockTimeUnix: the committed
// policy, derived by ActivePolicyAt exactly as FinalizeBlock derives it. A chain with no ledger has no committed policy,
// and its rule is the one the app was built with.
func (app *ValidatorApp) EntitlementConfigAt(blockTimeUnix int64) (EntitlementConfig, error) {
	app.mu.RLock()
	store, built := app.ledgerStore, app.entitlement
	app.mu.RUnlock()
	if store == nil {
		return built, nil
	}
	state, err := store.LoadEntitlementPolicy()
	if err != nil {
		return EntitlementConfig{}, fmt.Errorf("the committed entitlement policy could not be read: %w", err)
	}
	if state == nil {
		return EntitlementConfig{}, fmt.Errorf("this chain has sealed no entitlement policy")
	}
	return policyStateTo(ActivePolicyAt(state, blockTimeUnix))
}

// NewEntitlementStore is the proposer's entitlement store for this chain: it fetches epochs as cfg says and holds only
// those signed by a key consensus applies (EntitlementKeys) - the one source. It does not fetch; call Start.
func (app *ValidatorApp) NewEntitlementStore(cfg entitlement.StoreConfig, logger *log.Logger) *entitlement.Store {
	return entitlement.NewStoreWithKeySource(cfg, app.EntitlementKeys, logger)
}

// EntitlementKeys is the entitlement key set consensus applies to the next block, whose time is taken to be now - the
// entitlement.KeySource a validator's store verifies epochs against.
func (app *ValidatorApp) EntitlementKeys() (entitlement.KeySet, error) {
	cfg, err := app.EntitlementConfigAt(time.Now().UTC().Unix())
	if err != nil {
		return nil, err
	}
	return cfg.Keys, nil
}
