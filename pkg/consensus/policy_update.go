package consensus

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/certen/independant-validator/pkg/ledger"
)

// Changing the entitlement rule safely.
//
// # WHY A TRANSACTION AND NOT A SETTING
//
// The gate's verdict decides whether a ValidatorBlock is accepted, and the app
// hash is a chain over accepted bundle-ids. So the rule is a consensus input.
// Layer 1 sealed it in committed state, which stopped an environment edit from
// changing it — at the cost of making it immutable for the life of the chain.
//
// This is the way to change it: a transaction, committed like any other, that
// takes effect at a HEIGHT rather than at a restart. Two properties follow, and
// both are exactly what the 2026-07-27 outage lacked:
//
//   - Replay is deterministic. The rule in force at height H is derivable from
//     committed state at H-1, so re-executing history applies the rule that
//     committed it, not the one an operator happens to have configured today.
//   - Activation is simultaneous. Every node switches at the same height
//     because they all read the same committed schedule, rather than at
//     whatever moment each was restarted.
//
// # WHY AN ACTIVATION DELAY
//
// An update that took effect immediately would apply to the very block that
// carried it, and a node that had not yet seen that block would disagree. The
// delay guarantees every node has the change committed well before anyone acts
// on it.

// PolicyUpdateKind identifies a policy-update transaction on the wire. It is a
// versioned string so a future format cannot be mistaken for this one.
const PolicyUpdateKind = "certen.policy.update/v1"

// MinActivationDelay is the FLOOR on how far ahead an update may activate.
//
// Correctness does not depend on its size. Activation is derived from committed
// state, so a node executing block H has already executed any update that
// committed before H — true even at a delay of one. What the delay buys is
// OPERATIONAL: a window in which a scheduled change is visible and can be
// superseded before it takes effect.
//
// The value is 10, not the 200 first chosen by analogy with Ethereum fork
// blocks and the Cosmos upgrade module. Those chains produce blocks every few
// seconds, so 200 blocks is minutes. THIS chain runs with empty-block
// production disabled and advances only on real ValidatorBlock transactions —
// it reached height 7 in a full day of operation. At that rate 200 blocks is
// weeks, or never if traffic stops, and an update scheduled that far out would
// simply never activate.
//
// A block count is a poor proxy for elapsed time on an event-driven chain.
// Treat this as a floor and choose an activation height with real headroom for
// the traffic the chain is actually seeing.
const MinActivationDelay = 10

// PolicySignature is one operator's endorsement of an update.
type PolicySignature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // hex ed25519 over SigningBytes
}

// PolicyUpdateTx schedules a change to the entitlement rule.
type PolicyUpdateTx struct {
	Kind             string            `json:"kind"`
	Mode             string            `json:"mode"`
	Keys             map[string]string `json:"keys,omitempty"`
	ActivationHeight int64             `json:"activation_height"`
	Version          uint64            `json:"version"`
	Signatures       []PolicySignature `json:"signatures,omitempty"`
}

// SigningBytes is what admins sign: every field that changes behaviour, and
// nothing else.
//
// Signatures are excluded (they cannot sign themselves) and the encoding is
// deterministic — sorted keys, no map iteration order — so two nodes computing
// the digest of the same update always agree.
func (t *PolicyUpdateTx) SigningBytes() []byte {
	ids := make([]string, 0, len(t.Keys))
	for id := range t.Keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	payload := t.Kind + "\n" + t.Mode + "\n"
	for _, id := range ids {
		payload += id + "=" + t.Keys[id] + ";"
	}
	payload += fmt.Sprintf("\n%d\n%d", t.ActivationHeight, t.Version)

	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

// PolicyUpdateID is the identifier this transaction contributes to the app
// hash, so nodes commit to the fact that the update was included — not merely
// to its effect later.
func (t *PolicyUpdateTx) PolicyUpdateID() string {
	return "policy-update:" + hex.EncodeToString(t.SigningBytes())
}

// DecodePolicyUpdate returns the transaction if these bytes are one, and false
// otherwise, so the caller can fall through to ValidatorBlock handling.
//
// The discriminator is an explicit `kind`, never a guess at shape: a
// misclassified transaction would be judged by the wrong rules entirely.
func DecodePolicyUpdate(tx []byte) (*PolicyUpdateTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != PolicyUpdateKind {
		return nil, false
	}
	var out PolicyUpdateTx
	if err := json.Unmarshal(tx, &out); err != nil {
		return nil, false
	}
	return &out, true
}

// VerifyPolicyUpdate checks an update against the currently committed policy.
//
// currentHeight is the height of the block carrying the update. Every input is
// committed state or the block itself, so the verdict is identical on every
// node and reproducible on replay.
func VerifyPolicyUpdate(t *PolicyUpdateTx, current *ledger.EntitlementPolicyState, currentHeight int64) error {
	if current == nil {
		return fmt.Errorf("no sealed policy exists to update")
	}
	if t.Kind != PolicyUpdateKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, PolicyUpdateKind)
	}

	// The proposed rule must itself be usable. Scheduling enforce with no keys
	// would halt the fleet at the activation height — a delayed outage is worse
	// than an immediate refusal, because nothing connects it to this action.
	proposed := &ledger.EntitlementPolicyState{Mode: t.Mode, Keys: t.Keys}
	if _, err := policyStateTo(proposed); err != nil {
		return fmt.Errorf("proposed policy is unusable: %w", err)
	}

	if t.Version <= HighestPolicyVersion(current) {
		return fmt.Errorf("version %d is not newer than the highest committed version %d "+
			"(an update cannot be replayed or reordered)", t.Version, HighestPolicyVersion(current))
	}

	minHeight := currentHeight + MinActivationDelay
	if t.ActivationHeight < minHeight {
		return fmt.Errorf("activation height %d is too soon: must be at least %d "+
			"(current %d + %d), so every node commits the change before any node acts on it",
			t.ActivationHeight, minHeight, currentHeight, MinActivationDelay)
	}

	if err := verifyPolicyQuorum(t, current); err != nil {
		return err
	}
	return nil
}

// verifyPolicyQuorum requires AdminThreshold distinct, valid admin signatures.
func verifyPolicyQuorum(t *PolicyUpdateTx, current *ledger.EntitlementPolicyState) error {
	threshold := current.AdminThreshold
	if threshold <= 0 {
		return fmt.Errorf("this chain sealed no admin threshold, so the policy cannot be updated; " +
			"it is immutable for the life of the chain")
	}
	if len(current.AdminKeys) == 0 {
		return fmt.Errorf("this chain sealed no admin keys, so the policy cannot be updated")
	}

	digest := t.SigningBytes()
	seen := make(map[string]struct{}, len(t.Signatures))
	valid := 0

	for _, s := range t.Signatures {
		// Distinct signers only: the same key repeated must not reach the
		// threshold on its own.
		if _, dup := seen[s.KeyID]; dup {
			continue
		}
		hexPub, ok := current.AdminKeys[s.KeyID]
		if !ok {
			continue // not an admin on this chain
		}
		pub, err := hex.DecodeString(hexPub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		sig, err := hex.DecodeString(s.Signature)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), digest, sig) {
			continue
		}
		seen[s.KeyID] = struct{}{}
		valid++
	}

	if valid < threshold {
		return fmt.Errorf("policy update has %d valid admin signatures, needs %d", valid, threshold)
	}
	return nil
}

// HighestPolicyVersion is the newest version in the schedule, or the genesis
// version when the schedule is empty.
func HighestPolicyVersion(s *ledger.EntitlementPolicyState) uint64 {
	if s == nil {
		return 0
	}
	highest := s.Version
	for _, e := range s.Schedule {
		if e.Version > highest {
			highest = e.Version
		}
	}
	return highest
}

// ApplyPolicyUpdate appends an accepted update to the schedule.
//
// IDEMPOTENT: an update whose version is already scheduled changes nothing.
// Replay depends on this — CometBFT re-executes the block carrying the update
// after the schedule already contains it, and a second append would both
// corrupt the schedule and change the app hash.
//
// It does NOT change the rule in force. The rule is derived from the schedule
// by ActivePolicyAt, so it changes at the activation height on every node at
// once, whenever that block is executed.
func ApplyPolicyUpdate(t *PolicyUpdateTx, current *ledger.EntitlementPolicyState, atHeight int64) *ledger.EntitlementPolicyState {
	for _, e := range current.Schedule {
		if e.Version == t.Version {
			return current // already scheduled; nothing to do
		}
	}
	next := *current // copy; never mutate committed state in place
	next.Schedule = append(append([]ledger.ScheduledPolicyChange(nil), current.Schedule...),
		ledger.ScheduledPolicyChange{
			Mode:             t.Mode,
			Keys:             t.Keys,
			ActivationHeight: t.ActivationHeight,
			Version:          t.Version,
			ProposedAtHeight: atHeight,
		})
	return &next
}

// IsPolicyUpdateScheduled reports whether this exact version is already in the
// schedule, so a replayed update can be accepted as a no-op rather than
// rejected — a rejection would withhold its id from the app hash and diverge.
func IsPolicyUpdateScheduled(s *ledger.EntitlementPolicyState, version uint64) bool {
	if s == nil {
		return false
	}
	for _, e := range s.Schedule {
		if e.Version == version {
			return true
		}
	}
	return false
}

// ActivePolicyAt returns the rule in force at a given height: the latest
// scheduled change whose activation height has been reached, else genesis.
//
// PURE in (schedule, height). This is what makes replay safe — executing block
// H yields the same rule regardless of how far the chain has since progressed.
func ActivePolicyAt(s *ledger.EntitlementPolicyState, height int64) *ledger.EntitlementPolicyState {
	if s == nil {
		return nil
	}
	active := *s
	best := int64(-1)
	for _, e := range s.Schedule {
		if e.ActivationHeight <= height && e.ActivationHeight > best {
			best = e.ActivationHeight
			active.Mode = e.Mode
			active.Keys = e.Keys
			active.SealedAtHeight = e.ActivationHeight
		}
	}
	return &active
}
