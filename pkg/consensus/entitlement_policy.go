package consensus

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sort"

	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/certen/independant-validator/pkg/ledger"
)

// Where the entitlement rule comes from.
//
// # THE RULE MUST NOT LIVE IN THE ENVIRONMENT
//
// The gate's verdict decides whether a ValidatorBlock is accepted, and the app
// hash is a chain over the bundle-ids of ACCEPTED blocks. So the rule is a
// consensus input. An environment variable is not: it can differ between two
// nodes, and — the failure that actually happened — between one node and its
// own committed past.
//
// On 2026-07-27 the mode was changed from observe to enforce and the fleet
// restarted. CometBFT replayed history, the new rule rejected blocks the old
// rule had accepted, the recomputed app hash no longer matched what CometBFT
// had recorded, and all seven validators panicked at handshake with no path to
// recovery. Two hours down, chain history lost.
//
// # SEALED AT GENESIS
//
// The policy is therefore read from the environment exactly once — on a chain
// with no policy recorded — and sealed into committed state. Every later boot
// reads the sealed value and IGNORES the environment. Editing .env.shared on a
// running chain can no longer change a consensus rule; it can only produce a
// warning.
//
// This deliberately makes the mode immutable for the life of the chain. That is
// the correct default: the only safe way to change a consensus rule is at an
// agreed activation height, which is Layer 2 (PolicyUpdate transactions). Until
// that exists, changing the rule means starting a new chain — explicit and
// survivable, rather than implicit and fatal.
//
// # WHAT THIS DOES NOT FIX
//
// Sealing happens per node at its own genesis, so two nodes started with
// different environments still seal different policies and will disagree. That
// is a one-time setup concern rather than the recurring hazard, and it is what
// Layer 2 closes by carrying the policy in a block. Until then, `PolicyFingerprint`
// is logged at startup so a mismatched fleet is visible in seconds rather than
// after a fork.

// ResolveEntitlementPolicy returns the policy this node must apply, sealing the
// environment's value if the chain has none yet.
//
// envCfg is the parsed environment configuration, used ONLY as the genesis seed.
func ResolveEntitlementPolicy(
	store *ledger.LedgerStore,
	envCfg EntitlementConfig,
	logger *log.Logger,
) (EntitlementConfig, error) {
	if store == nil {
		// No ledger (tests, tooling): fall back to the environment. There is no
		// committed state to disagree with.
		return envCfg, nil
	}

	sealed, err := store.LoadEntitlementPolicy()
	if err != nil {
		return EntitlementConfig{}, fmt.Errorf("load entitlement policy: %w", err)
	}

	if sealed == nil {
		admin, err := AdminSeedFromEnv()
		if err != nil {
			return EntitlementConfig{}, fmt.Errorf("admin key seed: %w", err)
		}
		state := policyStateFrom(envCfg)
		state.AdminKeys = admin.Keys
		state.AdminThreshold = admin.Threshold
		if err := store.SaveEntitlementPolicy(state); err != nil {
			return EntitlementConfig{}, fmt.Errorf("seal entitlement policy: %w", err)
		}
		mutability := fmt.Sprintf("%d admin keys, threshold %d", len(admin.Keys), admin.Threshold)
		if len(admin.Keys) == 0 {
			mutability = "NO admin keys — this chain's rule is immutable for its whole life"
		}
		logger.Printf("🔏 [ENTITLEMENT] policy SEALED at genesis: mode=%s keys=%d fingerprint=%s (%s). "+
			"The environment is not consulted again on this chain.",
			envCfg.Mode, len(envCfg.Keys), PolicyFingerprint(state), mutability)
		return envCfg, nil
	}

	cfg, err := policyStateTo(sealed)
	if err != nil {
		return EntitlementConfig{}, fmt.Errorf("sealed entitlement policy is unusable: %w", err)
	}

	// A disagreement is not an error — the sealed value wins — but it is worth
	// saying loudly, because the operator plainly expected the edit to take.
	if drift := describePolicyDrift(envCfg, cfg); drift != "" {
		logger.Printf("⚠️ [ENTITLEMENT] the environment disagrees with this chain's sealed policy "+
			"and is being IGNORED: %s. Changing a consensus rule on a running chain is what "+
			"bricked the fleet on 2026-07-27; use a PolicyUpdate at an activation height, or "+
			"start a new chain.", drift)
	}

	logger.Printf("🔏 [ENTITLEMENT] policy from committed state: mode=%s keys=%d fingerprint=%s",
		cfg.Mode, len(cfg.Keys), PolicyFingerprint(sealed))
	return cfg, nil
}

func policyStateFrom(cfg EntitlementConfig) *ledger.EntitlementPolicyState {
	keys := make(map[string]string, len(cfg.Keys))
	for id, pub := range cfg.Keys {
		keys[id] = hex.EncodeToString(pub)
	}
	return &ledger.EntitlementPolicyState{
		Mode:           string(cfg.Mode),
		Keys:           keys,
		SealedAtHeight: 0,
		Version:        1,
	}
}

func policyStateTo(s *ledger.EntitlementPolicyState) (EntitlementConfig, error) {
	cfg := EntitlementConfig{Keys: entitlement.KeySet{}}

	switch EntitlementMode(s.Mode) {
	case EntitlementOff, EntitlementObserve, EntitlementEnforce:
		cfg.Mode = EntitlementMode(s.Mode)
	default:
		return cfg, fmt.Errorf("mode %q is not one of off|observe|enforce", s.Mode)
	}

	for id, hexKey := range s.Keys {
		b, err := hex.DecodeString(hexKey)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return cfg, fmt.Errorf("key %q is not %d hex-encoded bytes", id, ed25519.PublicKeySize)
		}
		cfg.Keys[id] = ed25519.PublicKey(b)
	}

	// Enforcing with no keys would reject every block on the fleet. A sealed
	// policy in that shape is unusable, and failing here is far better than
	// discovering it one block later.
	if cfg.Mode == EntitlementEnforce && len(cfg.Keys) == 0 {
		return cfg, fmt.Errorf("mode is enforce but no trusted keys are sealed; every block would be rejected")
	}
	return cfg, nil
}

// PolicyFingerprint is a short, stable digest of a sealed policy, so two nodes
// can be compared at a glance. Full keys are not logged.
func PolicyFingerprint(s *ledger.EntitlementPolicyState) string {
	if s == nil {
		return "none"
	}
	ids := make([]string, 0, len(s.Keys))
	for id := range s.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	h := sha256.Sum256([]byte(s.Mode + "|" + joinKeyed(ids, s.Keys)))
	return hex.EncodeToString(h[:6])
}

func joinKeyed(ids []string, keys map[string]string) string {
	out := ""
	for _, id := range ids {
		out += id + "=" + keys[id] + ";"
	}
	return out
}

// describePolicyDrift reports how the environment differs from the sealed
// policy, or "" when they agree.
func describePolicyDrift(env, sealed EntitlementConfig) string {
	var parts []string
	if env.Mode != sealed.Mode {
		parts = append(parts, fmt.Sprintf("env mode=%s but sealed mode=%s", env.Mode, sealed.Mode))
	}
	if len(env.Keys) != len(sealed.Keys) {
		parts = append(parts, fmt.Sprintf("env has %d keys, sealed has %d", len(env.Keys), len(sealed.Keys)))
	} else {
		for id, pub := range env.Keys {
			s, ok := sealed.Keys[id]
			if !ok {
				parts = append(parts, fmt.Sprintf("env key %q is not in the sealed set", id))
			} else if !pub.Equal(s) {
				parts = append(parts, fmt.Sprintf("env key %q differs from the sealed one", id))
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "; " + p
	}
	return out
}
