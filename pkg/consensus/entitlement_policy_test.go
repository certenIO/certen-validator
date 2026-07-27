package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/certen/independant-validator/pkg/ledger"
)

// Sealing the entitlement policy is the fix for the 2026-07-27 outage: an
// operator edited CERTEN_ENTITLEMENT_MODE, restarted, and every validator
// replayed its own history under a rule that had not committed it. The
// recomputed app hash diverged and the fleet died at handshake.
//
// The property under test is narrow and absolute: once a chain has sealed a
// policy, NOTHING in the environment can change it.

// Reuses memKV from abci_info_recovery_test.go. Holding the same KV across two
// ResolveEntitlementPolicy calls IS the restart being simulated.
func policyTestStore(t *testing.T) *ledger.LedgerStore {
	t.Helper()
	return ledger.NewLedgerStore(newMemKV())
}

func testKeySet(t *testing.T, n int) entitlement.KeySet {
	t.Helper()
	ks := entitlement.KeySet{}
	for i := 0; i < n; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ks[string(rune('a'+i))] = pub
	}
	return ks
}

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// THE REGRESSION. Seal observe, then restart with enforce in the environment.
// The sealed value must win.
func TestEnvCannotChangeTheRuleOnASealedChain(t *testing.T) {
	store := policyTestStore(t)
	keys := testKeySet(t, 1)

	sealed, err := ResolveEntitlementPolicy(store,
		EntitlementConfig{Mode: EntitlementObserve, Keys: keys}, quietLogger())
	if err != nil {
		t.Fatalf("genesis seal failed: %v", err)
	}
	if sealed.Mode != EntitlementObserve {
		t.Fatalf("genesis mode = %s, want observe", sealed.Mode)
	}

	// The operator edits .env.shared and restarts. This is the exact action
	// that bricked the fleet.
	after, err := ResolveEntitlementPolicy(store,
		EntitlementConfig{Mode: EntitlementEnforce, Keys: keys}, quietLogger())
	if err != nil {
		t.Fatalf("resolve after restart failed: %v", err)
	}
	if after.Mode != EntitlementObserve {
		t.Fatalf("env changed a sealed consensus rule: mode = %s, want observe", after.Mode)
	}
}

// Swapping the trusted keys is the same divergence by another route: a node
// verifying with different keys reaches a different verdict.
func TestEnvCannotChangeTheSealedKeys(t *testing.T) {
	store := policyTestStore(t)
	original := testKeySet(t, 2)

	if _, err := ResolveEntitlementPolicy(store,
		EntitlementConfig{Mode: EntitlementObserve, Keys: original}, quietLogger()); err != nil {
		t.Fatal(err)
	}

	after, err := ResolveEntitlementPolicy(store,
		EntitlementConfig{Mode: EntitlementObserve, Keys: testKeySet(t, 2)}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range original {
		got, ok := after.Keys[id]
		if !ok {
			t.Fatalf("sealed key %q disappeared", id)
		}
		if !want.Equal(got) {
			t.Fatalf("sealed key %q was replaced from the environment", id)
		}
	}
}

// The seal must survive a full round-trip through storage, including the mode
// and every key — otherwise the rule silently changes on the next boot.
func TestSealedPolicyRoundTripsExactly(t *testing.T) {
	for _, mode := range []EntitlementMode{EntitlementOff, EntitlementObserve, EntitlementEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			store := policyTestStore(t)
			keys := testKeySet(t, 3)

			if _, err := ResolveEntitlementPolicy(store,
				EntitlementConfig{Mode: mode, Keys: keys}, quietLogger()); err != nil {
				t.Fatal(err)
			}
			// A different env on the way back proves the values came from state.
			got, err := ResolveEntitlementPolicy(store,
				EntitlementConfig{Mode: EntitlementOff, Keys: entitlement.KeySet{}}, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			if got.Mode != mode {
				t.Fatalf("mode = %s, want %s", got.Mode, mode)
			}
			if len(got.Keys) != len(keys) {
				t.Fatalf("keys = %d, want %d", len(got.Keys), len(keys))
			}
			for id, want := range keys {
				if !want.Equal(got.Keys[id]) {
					t.Fatalf("key %q did not survive the round trip", id)
				}
			}
		})
	}
}

// A sealed policy of enforce-with-no-keys would reject every block on the
// fleet. Refusing to start beats discovering it one block later.
func TestSealedEnforceWithoutKeysIsRejected(t *testing.T) {
	_, err := policyStateTo(&ledger.EntitlementPolicyState{Mode: "enforce"})
	if err == nil {
		t.Fatal("enforce with no keys must be refused")
	}
	if !strings.Contains(err.Error(), "every block would be rejected") {
		t.Errorf("message should say what would happen; got: %v", err)
	}
}

func TestSealedUnknownModeIsRejected(t *testing.T) {
	if _, err := policyStateTo(&ledger.EntitlementPolicyState{Mode: "enfrce"}); err == nil {
		t.Fatal("a typo'd mode must not be silently accepted")
	}
}

// The fingerprint is how a mismatched fleet is spotted before it forks, so it
// must actually distinguish policies — and must not leak key material.
func TestFingerprintDistinguishesPoliciesWithoutLeakingKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	keyHex := hex.EncodeToString(pub)

	a := &ledger.EntitlementPolicyState{Mode: "observe", Keys: map[string]string{"k1": keyHex}}
	b := &ledger.EntitlementPolicyState{Mode: "enforce", Keys: map[string]string{"k1": keyHex}}

	if PolicyFingerprint(a) == PolicyFingerprint(b) {
		t.Fatal("fingerprint does not distinguish observe from enforce")
	}
	if PolicyFingerprint(a) != PolicyFingerprint(a) {
		t.Fatal("fingerprint is not stable")
	}
	if strings.Contains(PolicyFingerprint(a), keyHex[:16]) {
		t.Fatal("fingerprint leaks key material")
	}
	if PolicyFingerprint(nil) != "none" {
		t.Fatal("nil policy should fingerprint as none")
	}
}

// Without a ledger there is no committed state to disagree with, so the
// environment is the only source. Tooling and tests rely on this.
func TestNoLedgerFallsBackToEnv(t *testing.T) {
	env := EntitlementConfig{Mode: EntitlementEnforce, Keys: testKeySet(t, 1)}
	got, err := ResolveEntitlementPolicy(nil, env, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != EntitlementEnforce {
		t.Fatalf("mode = %s, want enforce", got.Mode)
	}
}

// Drift detection drives the warning an operator sees when their edit is
// ignored. Silence there would be worse than the old behaviour: the change
// would appear to have taken effect.
func TestDriftIsDescribedForModeAndKeys(t *testing.T) {
	keys := testKeySet(t, 1)
	same := EntitlementConfig{Mode: EntitlementObserve, Keys: keys}

	if d := describePolicyDrift(same, same); d != "" {
		t.Fatalf("identical configs reported drift: %s", d)
	}
	if d := describePolicyDrift(
		EntitlementConfig{Mode: EntitlementEnforce, Keys: keys}, same); !strings.Contains(d, "mode") {
		t.Fatalf("mode drift not described: %q", d)
	}
	if d := describePolicyDrift(
		EntitlementConfig{Mode: EntitlementObserve, Keys: testKeySet(t, 2)}, same); d == "" {
		t.Fatal("key-count drift not described")
	}
}
