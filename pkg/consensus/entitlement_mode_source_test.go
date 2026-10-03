package consensus

import (
	"encoding/hex"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
)

// RB4-F37a: the proposer (Phase 3 refusal) and the discovery pre-screen act on the mode the CHAIN enforces. main
// wired them with EntitlementConfigFromEnv().Mode - the environment's genesis seed - while the consensus gate judges
// by the sealed policy and the updates activated since. On a chain sealed observe, a node whose env said enforce
// refused intents as not_entitled (a terminal verdict) that the fleet would have admitted; after a policy update to
// enforce, a node still on observe built blocks the fleet refuses.

func sealPolicy(t *testing.T, mode EntitlementMode) (*ledger.LedgerStore, string) {
	t.Helper()
	store := newInMemLedger()
	keys := testKeySet(t, 1)
	if _, err := ResolveEntitlementPolicy(store, EntitlementConfig{Mode: mode, Keys: keys}, quietLogger()); err != nil {
		t.Fatalf("seal %s: %v", mode, err)
	}
	return store, "a:" + hex.EncodeToString(keys["a"])
}

func TestEntitlementModeIsTheChainsNotTheEnvironments(t *testing.T) {
	store, keys := sealPolicy(t, EntitlementObserve)
	// The operator's environment says enforce; the chain was sealed observe.
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "enforce")
	t.Setenv("CERTEN_ENTITLEMENT_KEYS", keys)

	app := NewValidatorApp(store, "entitlement-mode-test")
	if got := app.EntitlementMode(); got != EntitlementObserve {
		t.Fatalf("EntitlementMode() = %q: the producers would act on the environment, the chain enforces observe", got)
	}
}

func TestEntitlementModeFollowsAnActivatedPolicyUpdate(t *testing.T) {
	store, keys := sealPolicy(t, EntitlementObserve)
	t.Setenv("CERTEN_ENTITLEMENT_MODE", "observe")
	t.Setenv("CERTEN_ENTITLEMENT_KEYS", keys)
	app := NewValidatorApp(store, "entitlement-mode-test")

	state, err := store.LoadEntitlementPolicy()
	if err != nil || state == nil {
		t.Fatalf("load sealed policy: %v", err)
	}
	state.Schedule = append(state.Schedule, ledger.ScheduledPolicyChange{Mode: string(EntitlementEnforce), Keys: state.Keys, ActivationUnix: 1_000})
	if err := store.SaveEntitlementPolicy(state); err != nil {
		t.Fatal(err)
	}

	app.activatePolicyForBlock(5, 999)
	if got := app.EntitlementMode(); got != EntitlementObserve {
		t.Fatalf("before activation EntitlementMode() = %q, want observe", got)
	}
	app.activatePolicyForBlock(6, 1_000)
	if got := app.EntitlementMode(); got != EntitlementEnforce {
		t.Fatalf("after the update activated EntitlementMode() = %q, want enforce", got)
	}
}

// The proposer reads the mode at each intent, not once at wiring.
func TestProposerEntitlementModeIsReadAtEachUse(t *testing.T) {
	mode := EntitlementObserve
	bv := &BFTValidator{}
	bv.SetEntitlementStore(nil, func() EntitlementMode { return mode })
	if got := bv.enforcedEntitlementMode(); got != EntitlementObserve {
		t.Fatalf("got %q, want observe", got)
	}
	mode = EntitlementEnforce
	if got := bv.enforcedEntitlementMode(); got != EntitlementEnforce {
		t.Fatalf("after the chain's mode changed got %q, want enforce", got)
	}
	if got := (&BFTValidator{}).enforcedEntitlementMode(); got != EntitlementOff {
		t.Fatalf("unwired: got %q, want off", got)
	}
}
