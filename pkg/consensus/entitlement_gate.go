package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// The entitlement gate: the point at which CERTEN decides whether to spend its
// own money on an intent.
//
// WHERE THIS RUNS, and why it is here rather than at the BLS signing site
//
// Tracing the Phase 3 path showed the pre-execution BLS signature is produced by
// ONE validator acting alone (bft_integration.go, signV6_1PreExecBLS), not by a
// 7-way threshold round. So refusing to sign is a local decision that a single
// modified node could skip. It is worth doing — it saves that node's work — but
// it is not enforcement.
//
// The only fleet-wide, non-bypassable point is VerifyValidatorBlockInvariants,
// which every validator runs on every ValidatorBlock via both CheckTx and
// FinalizeBlock. Rejecting there means the block cannot commit anywhere.
//
// FinalizeBlock is consensus. CheckTx is not — it is a mempool filter. That
// distinction matters: the FinalizeBlock check MUST be deterministic (it uses
// the ABCI block time, which is identical on every node), while CheckTx may use
// an approximate clock because a disagreement there costs a wasted gossip round,
// not a halted chain.

// EntitlementMode controls what the gate does.
type EntitlementMode string

const (
	// EntitlementOff disables the gate entirely. Evidence is ignored.
	EntitlementOff EntitlementMode = "off"

	// EntitlementObserve evaluates and logs, but never rejects. This is the
	// stage that finds ADI-to-account mapping bugs at zero risk, and it is
	// where the CARP demo is run before anything is enforced.
	EntitlementObserve EntitlementMode = "observe"

	// EntitlementEnforce rejects ValidatorBlocks lacking valid entitlement.
	EntitlementEnforce EntitlementMode = "enforce"
)

// AdminKeys and AdminThreshold seed who may later change this chain's policy.
//
//	CERTEN_ENTITLEMENT_ADMIN_KEYS      = <keyID>:<hex pubkey>[,...]
//	CERTEN_ENTITLEMENT_ADMIN_THRESHOLD = <n>   (default: all sealed admin keys)
//
// Read ONLY at genesis, like the rest of the policy. A chain sealed with no
// admin keys has an immutable rule for its whole life — which is a legitimate
// posture, and the safe default, since it makes the outage of 2026-07-27
// impossible by construction rather than by discipline.
type adminSeed struct {
	Keys      map[string]string
	Threshold int
}

// AdminSeedFromEnv parses the admin key set. An unparseable entry is fatal
// rather than skipped: silently sealing a smaller admin set than the operator
// intended would lower the bar for changing a consensus rule.
func AdminSeedFromEnv() (adminSeed, error) {
	seed := adminSeed{Keys: map[string]string{}}

	raw := strings.TrimSpace(os.Getenv("CERTEN_ENTITLEMENT_ADMIN_KEYS"))
	if raw != "" {
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			id, hexKey, ok := strings.Cut(entry, ":")
			id, hexKey = strings.TrimSpace(id), strings.TrimSpace(hexKey)
			if !ok || id == "" || hexKey == "" {
				return seed, fmt.Errorf("CERTEN_ENTITLEMENT_ADMIN_KEYS entry %q is not <keyID>:<hexPubKey>", entry)
			}
			b, err := hex.DecodeString(hexKey)
			if err != nil || len(b) != ed25519.PublicKeySize {
				return seed, fmt.Errorf(
					"CERTEN_ENTITLEMENT_ADMIN_KEYS entry %q: public key must be %d hex-encoded bytes",
					id, ed25519.PublicKeySize)
			}
			seed.Keys[id] = hexKey
		}
	}

	// Default to unanimity. A threshold is a security control, so the default
	// is the strict end; an operator who wants m-of-n states it.
	seed.Threshold = len(seed.Keys)
	if v := strings.TrimSpace(os.Getenv("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return seed, fmt.Errorf("CERTEN_ENTITLEMENT_ADMIN_THRESHOLD=%q must be a positive integer", v)
		}
		if n > len(seed.Keys) {
			return seed, fmt.Errorf(
				"CERTEN_ENTITLEMENT_ADMIN_THRESHOLD=%d exceeds the %d admin keys configured; "+
					"the policy could never be updated", n, len(seed.Keys))
		}
		seed.Threshold = n
	}
	return seed, nil
}

// EntitlementConfig is the pinned, node-local configuration for the gate.
//
// Keys are PINNED here rather than fetched. A key set that could be fetched is a
// key set an attacker could substitute, and it would also be per-node mutable
// state inside a consensus rule.
type EntitlementConfig struct {
	Mode EntitlementMode
	Keys entitlement.KeySet
}

// EntitlementConfigFromEnv reads the gate configuration.
//
//	CERTEN_ENTITLEMENT_MODE = off | observe | enforce   (default: off)
//	CERTEN_ENTITLEMENT_KEYS = <keyID>:<hex pubkey>[,<keyID>:<hex pubkey>...]
//
// Defaults to OFF. This is a consensus-affecting rule: it must not switch itself
// on during an upgrade, because a fleet where some nodes enforce and others do
// not is a fleet that disagrees about block validity. Enabling it is a
// deliberate, coordinated operator action.
//
// Note the asymmetry with the gas/cost ceiling, which defaults ON: that one is a
// local spending decision with no consensus consequence, so the safe default
// there is to protect the treasury. Here the safe default is to not fork.
func EntitlementConfigFromEnv() (EntitlementConfig, error) {
	cfg := EntitlementConfig{Mode: EntitlementOff, Keys: entitlement.KeySet{}}

	switch strings.ToLower(strings.TrimSpace(os.Getenv("CERTEN_ENTITLEMENT_MODE"))) {
	case "enforce":
		cfg.Mode = EntitlementEnforce
	case "observe":
		cfg.Mode = EntitlementObserve
	case "", "off":
		cfg.Mode = EntitlementOff
	default:
		return cfg, fmt.Errorf(
			"CERTEN_ENTITLEMENT_MODE=%q is not one of off|observe|enforce; refusing to guess",
			os.Getenv("CERTEN_ENTITLEMENT_MODE"))
	}

	raw := strings.TrimSpace(os.Getenv("CERTEN_ENTITLEMENT_KEYS"))
	if raw != "" {
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			id, hexKey, ok := strings.Cut(entry, ":")
			id, hexKey = strings.TrimSpace(id), strings.TrimSpace(hexKey)
			if !ok || id == "" || hexKey == "" {
				return cfg, fmt.Errorf("CERTEN_ENTITLEMENT_KEYS entry %q is not <keyID>:<hexPubKey>", entry)
			}
			b, err := hex.DecodeString(hexKey)
			if err != nil || len(b) != ed25519.PublicKeySize {
				return cfg, fmt.Errorf(
					"CERTEN_ENTITLEMENT_KEYS entry %q: public key must be %d hex-encoded bytes",
					id, ed25519.PublicKeySize)
			}
			cfg.Keys[id] = ed25519.PublicKey(b)
		}
	}

	// Enforcing with no keys would reject every block on the fleet. Refuse to
	// start rather than take the network down on a configuration slip.
	if cfg.Mode == EntitlementEnforce && len(cfg.Keys) == 0 {
		return cfg, fmt.Errorf(
			"CERTEN_ENTITLEMENT_MODE=enforce requires CERTEN_ENTITLEMENT_KEYS; " +
				"enforcing with no trusted keys would reject every ValidatorBlock")
	}

	return cfg, nil
}

// executionValidationEnabled reports whether ValidateForExecution runs before
// an intent is worked on.
//
// Defaults ON. It enforces expiry, structural completeness and — the part that
// has never actually run — nonce replay protection, and every one of those is a
// correctness property rather than a policy choice.
//
// The escape hatch exists because turning on a check that has been dead since it
// was written can surface pre-existing malformed intents. Set
// CERTEN_EXEC_VALIDATION=false to restore the old behaviour without redeploying
// a binary; expect replayed and expired intents to execute again if you do.
func executionValidationEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CERTEN_EXEC_VALIDATION"))) {
	case "false", "0", "no":
		return false
	default:
		return true
	}
}

// VerifyEntitlement is the gate.
//
// nowUnix MUST be the ABCI block time when called from FinalizeBlock. Passing
// wall-clock time there would make validators disagree about expiry and halt the
// chain.
//
// Returns nil when the block may proceed. In observe mode it always returns nil
// and the caller is expected to log the reported reason.
func VerifyEntitlement(
	vb *ValidatorBlock,
	principal string,
	nowUnix int64,
	cfg EntitlementConfig,
) (reason string, err error) {
	if cfg.Mode == EntitlementOff {
		return "", nil
	}

	verr := entitlement.Verify(vb.EntitlementEvidence, principal, nowUnix, cfg.Keys)
	if verr == nil {
		// Standing is established. Now the SPEND gate.
		//
		// These are different questions and both must be asked: Verify answers
		// "may this account spend at all", the ceiling answers "may it spend
		// this much". Until 2026-08-08 only the first was enforced — the
		// ceilings were published and read as a boolean, so an entitled account
		// could execute an intent of any size.
		if reason, cerr := verifyCostCeiling(vb, nowUnix); cerr != nil {
			if cfg.Mode == EntitlementObserve {
				return reason, nil
			}
			return reason, cerr
		}
		return "", nil
	}

	reason = entitlement.ReasonNotEntitled
	var ve *entitlement.VerifyError
	if ok := asVerifyError(verr, &ve); ok {
		reason = ve.Reason
	}

	if cfg.Mode == EntitlementObserve {
		// Observe: report, decide nothing.
		return reason, nil
	}
	return reason, verr
}

// verifyCostCeiling checks the block's worst-case cost against the leaf ceiling.
//
// Called only after entitlement.Verify has passed, so the evidence, its
// signature, its freshness and the leaf's binding to this principal are already
// established — the ceiling read here is one this epoch's signer published for
// this account, not an attacker's number.
//
// Returns ("", nil) — the intent is affordable, or cannot be bounded — in three
// distinct cases, and the distinction matters:
//
//   - No cost basis was published for a chain the block touches. The bound is
//     unknown. Refusing would turn a gateway configuration gap into refusal of
//     legitimate work; admitting it as zero would let an unpriced chain bypass
//     the ceiling entirely. Neither is acceptable, so the COST gate does not
//     apply and the STATUS gate still does. Visible as a distinct metric so an
//     unpriced chain is a reported gap rather than a silent hole.
//
//   - The leaf publishes a zero ceiling. Entitled() has already refused that
//     case as NOT_ENTITLED; re-refusing here would relabel the same decision.
//
//   - The arithmetic could not be completed. Fails OPEN on purpose: a bound we
//     could not compute is not evidence of unaffordability, and there is no
//     safe way to refuse on a number that does not exist.
func verifyCostCeiling(vb *ValidatorBlock, _ int64) (string, error) {
	ev := vb.EntitlementEvidence
	if ev == nil {
		return "", nil // unreachable: Verify already refused a nil evidence
	}

	ceiling := ev.Leaf.IntentCeilingMicroUSD
	if ceiling <= 0 {
		return "", nil
	}

	worst, ok, err := WorstCaseCostMicroUSD(vb, ev.Header)
	if err != nil || !ok {
		return "", nil
	}
	if worst <= ceiling {
		return "", nil
	}

	return entitlement.ReasonCeiling, &entitlement.VerifyError{
		Reason: entitlement.ReasonCeiling,
		Detail: fmt.Sprintf(
			"worst-case cost %d microUSD exceeds intent ceiling %d microUSD for %s",
			worst, ceiling, ev.Leaf.ADIURL),
	}
}

// asVerifyError is errors.As specialised, kept local so this file has no
// dependency beyond the entitlement package.
func asVerifyError(err error, target **entitlement.VerifyError) bool {
	if ve, ok := err.(*entitlement.VerifyError); ok {
		*target = ve
		return true
	}
	return false
}

// PrincipalOf extracts the account URL an intent was actually written under.
//
// This is the ONLY field in the whole pipeline that a submitter cannot forge:
// Accumulate's own consensus verified they can sign for it. Everything else the
// intent carries — created_by, intent_id, organizationAdi — is attacker
// controlled, and intent discovery deliberately OVERWRITES the self-declared
// organizationAdi with this value.
//
// Returns "" when there is nothing trustworthy to key on, which fails closed
// downstream.
func PrincipalOf(vb *ValidatorBlock) string {
	if vb == nil {
		return ""
	}
	if u := strings.TrimSpace(vb.AccumulateAnchorReference.AccountURL); u != "" {
		return u
	}
	return ""
}
