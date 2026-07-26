package intent

import (
	"strings"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// Entitlement pre-screen: decline obviously-unpayable work before spending CPU
// on it.
//
// WHAT THIS IS NOT
//
// It is not the enforcement point. The authority is VerifyEntitlement inside
// CheckTx/FinalizeBlock, which every validator runs on every ValidatorBlock and
// which no single node can skip. This pre-screen reads THIS node's cached
// snapshot, which may lag the fleet, so it must only ever decline work this node
// would otherwise perform — it can never admit anything, and nothing downstream
// may treat passing it as authorization.
//
// WHY IT EXISTS ANYWAY
//
// Building an L1-L4 chained proof is real CPU, and for on_demand intents it
// retries against Accumulate. Doing that for an intent that provably cannot
// execute is free denial-of-service: an attacker with a wallet and the public
// CERTEN_INTENT memo could keep the fleet busy at no cost to themselves.
// Declining early makes that attack cost them Accumulate fees for nothing.

// SetEntitlementScreen wires the snapshot and mode used by the pre-screen.
// Leaving it unset disables screening entirely, which is correct for a
// deployment not running the entitlement gate.
func (id *IntentDiscovery) SetEntitlementScreen(store *entitlement.Store, enforce bool) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.entitlementStore = store
	id.entitlementEnforce = enforce
}

// entitlementPreScreen reports whether this intent is worth working on.
//
// Returns true (proceed) in every ambiguous case. The bar for declining is
// deliberately high: a false decline silently drops a paying customer's intent,
// which is far worse than the wasted CPU of a false accept — the consensus gate
// will catch the latter, and nothing catches the former.
func (id *IntentDiscovery) entitlementPreScreen(intent *CertenIntent) bool {
	id.mu.RLock()
	store, enforce := id.entitlementStore, id.entitlementEnforce
	id.mu.RUnlock()

	if store == nil || !store.Enabled() {
		return true // not configured — screening is off
	}

	principal := strings.TrimSpace(intent.AccountURL)
	if principal == "" {
		// No principal to judge. Proceed and let the consensus gate decide:
		// declining here on incomplete information could drop a legitimate
		// intent whose account URL is populated later in the pipeline.
		return true
	}

	// A store with no usable snapshot cannot distinguish "not entitled" from
	// "I don't know yet". Proceed — the consensus gate still refuses, so no
	// money is at risk, and we avoid dropping every intent during a refresh
	// outage on this one node.
	health := store.Health()
	if health.Accounts == 0 || health.Stale {
		return true
	}

	leaf, found := store.Lookup(principal)
	if !found {
		if enforce {
			id.logger.Printf("🚫 [ENTITLEMENT-PRESCREEN] declining intent %s: principal %q is not in entitlement epoch %d (no proof work will be done)",
				intent.IntentID, principal, health.Epoch)
			return false
		}
		id.logger.Printf("👁️ [ENTITLEMENT-PRESCREEN] OBSERVE would decline intent %s: principal %q absent from epoch %d",
			intent.IntentID, principal, health.Epoch)
		return true
	}

	if !leaf.Entitled() {
		if enforce {
			id.logger.Printf("🚫 [ENTITLEMENT-PRESCREEN] declining intent %s: principal %q is %s with ceiling %d",
				intent.IntentID, principal, leaf.Status, leaf.IntentCeilingMicroUSD)
			return false
		}
		id.logger.Printf("👁️ [ENTITLEMENT-PRESCREEN] OBSERVE would decline intent %s: principal %q is %s",
			intent.IntentID, principal, leaf.Status)
		return true
	}

	return true
}
