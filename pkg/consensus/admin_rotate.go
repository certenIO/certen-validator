package consensus

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/ledger"
)

// Rotating CERTEN's admin set (rules v12, RB5-F37).
//
// # WHY A TRANSACTION
//
// The admin quorum is the chain's one authority for policy updates, validator key rotations and the BLS registry. It
// was sealed at genesis and no transaction could change it, so when certen-testnet's sealed admin secrets were lost
// the only way out was a rules upgrade written for that one repair (v11's re-seal). v12 makes changing the admin set an
// ordinary act of the chain: the admin quorum IN FORCE authorises a new set - replacing, adding or removing keys and
// changing the threshold - by a transaction committed at a height, like any other state change. A lost or compromised
// admin key is then replaced by the keys that remain, without another rules upgrade.
//
// # WHAT MAKES IT SAFE
//
//   - Authority: at least the threshold of DISTINCT keys of the admin set in force for the block (AdminSetAt) sign it.
//     Distinct means distinct public keys - one key named under two ids is one signer.
//   - Binding: the signatures cover the chain id, the rotation's sequence, the id of the set in force (a hash of its
//     keys and threshold) and the id of the new set, under a length-prefixed encoding nothing else shares. A rotation
//     signed for one chain is nothing on another; one signed against a set that has since changed is refused.
//   - Ordering: the sequence is one more than the number of admin-set changes recorded (the v11 re-seal included), so
//     a rotation cannot be replayed, skipped or reordered, and at most one admin-set change lands per block.
//   - Possession: every key of the new set signs the rotation under its own domain, so nobody installs a key they do
//     not hold - a typo, a key whose secret was never kept (how certen-testnet lost its admins), or someone else's key.
//   - Shape: key ids are plain names, keys are canonical lowercase hex, no key appears twice, and the threshold is
//     reachable and never a single point of failure unless the set is explicitly a single key (minimumAdminThreshold).
//   - No return: a key that has left the admin set can never be brought back; it is presumed compromised or lost.
//   - Effect: recorded APPEND-ONLY in the same record the v11 re-seal writes (EntitlementPolicyState.AdminReseals), and
//     in force from the next height - every admin-signed transaction of a block, this one's included, is judged by
//     the set in force for that block, however many times the block is executed.

// AdminRotateKind identifies an admin rotation on the wire.
const AdminRotateKind = "certen.admin.rotate/v1"

// codeAdminRotateRefused is the result code of a refused admin rotation.
const codeAdminRotateRefused uint32 = 12

// maxAdminKeys bounds an admin set: the possession proofs of every key are verified in FinalizeBlock, and admin keys
// are people's offline keys, not a validator set.
const maxAdminKeys = 32

// The domains of the three things this file hashes. Each is the first field of its encoding, so none can be mistaken
// for another, or for any other signed message of the chain.
const (
	adminSetIDDomain            = "certen:admin-set:v1"
	adminRotatePossessionDomain = "certen:admin-rotate-possession:v1"
)

// adminKeyIDPattern is what an admin key id may be: a plain name, so ids print unambiguously in logs and tools.
var adminKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// AdminRotateTx replaces the admin set.
type AdminRotateTx struct {
	Kind    string `json:"kind"`
	ChainID string `json:"chain_id"`
	// Sequence is this rotation's ordinal: 1 + the number of admin-set changes already recorded.
	Sequence uint64 `json:"sequence"`
	// CurrentSetID is AdminSetID of the set in force the rotation is made against (lowercase hex).
	CurrentSetID string `json:"current_set_id"`
	// NewAdminKeys and NewThreshold are the set from the next height: key id -> lowercase hex ed25519 public key.
	NewAdminKeys map[string]string `json:"new_admin_keys"`
	NewThreshold int               `json:"new_threshold"`
	// Signatures are the current admins' signatures over SigningBytes.
	Signatures []PolicySignature `json:"signatures,omitempty"`
	// Possession is every new key's signature over PossessionBytes, by the key's id in NewAdminKeys.
	Possession []PolicySignature `json:"possession,omitempty"`
}

// lengthPrefixed is the encoding of every hash below: each field as its 4-byte big-endian length then its bytes. It is
// injective - no two field lists encode alike, whatever the fields contain - so what is signed is exactly one thing.
func lengthPrefixed(fields ...string) []byte {
	var b []byte
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

// sortedAdminIDs is a set's key ids in ascending order.
func sortedAdminIDs(keys map[string]string) []string {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// AdminSetID identifies an admin set: sha256 over the domain, the threshold, the number of keys and each key id with
// its lowercase hex key in id order. Hex.
func AdminSetID(keys map[string]string, threshold int) string {
	fields := []string{adminSetIDDomain, strconv.Itoa(threshold), strconv.Itoa(len(keys))}
	for _, id := range sortedAdminIDs(keys) {
		fields = append(fields, id, strings.ToLower(keys[id]))
	}
	sum := sha256.Sum256(lengthPrefixed(fields...))
	return hex.EncodeToString(sum[:])
}

// NewSetID is AdminSetID of the set the rotation installs.
func (t *AdminRotateTx) NewSetID() string { return AdminSetID(t.NewAdminKeys, t.NewThreshold) }

func (t *AdminRotateTx) canonical(domain string) []byte {
	sum := sha256.Sum256(lengthPrefixed(domain, t.ChainID, strconv.FormatUint(t.Sequence, 10),
		strings.ToLower(t.CurrentSetID), t.NewSetID()))
	return sum[:]
}

// SigningBytes is what the current admins sign: the chain, the sequence, the set in force and the new set.
func (t *AdminRotateTx) SigningBytes() []byte { return t.canonical(AdminRotateKind) }

// PossessionBytes is what every new key signs: the same fields under its own domain, so a possession proof is never an
// admin's approval (a key kept from the current set signs both, each meaning what it says) and neither can stand in
// for the other.
func (t *AdminRotateTx) PossessionBytes() []byte { return t.canonical(adminRotatePossessionDomain) }

// RotationID is what an accepted rotation contributes to the app hash and records.
func (t *AdminRotateTx) RotationID() string {
	return "admin-rotation:" + hex.EncodeToString(t.SigningBytes())
}

// DecodeAdminRotate returns the transaction if these bytes are one. The discriminator is the explicit kind; bytes of
// the kind that do not decode are still the kind, refused by CheckShape, never judged as a ValidatorBlock.
func DecodeAdminRotate(tx []byte) (*AdminRotateTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != AdminRotateKind {
		return nil, false
	}
	var t AdminRotateTx
	if err := json.Unmarshal(tx, &t); err != nil {
		return &AdminRotateTx{Kind: AdminRotateKind}, true
	}
	return &t, true
}

// minimumAdminThreshold is the least threshold a set of n keys may have: 1 for a single key, 2 for any more.
//
// A set of two or more keys at threshold 1 lets any ONE of them act alone - one lost laptop is the whole chain's
// governance - while looking like a quorum. A single-key set is a single point of failure too, but an explicit one:
// it is exactly what it says. So the rule refuses the disguised case and allows the explicit one.
func minimumAdminThreshold(n int) int {
	if n <= 1 {
		return 1
	}
	return 2
}

// isCanonicalEd25519Hex reports whether s is a 32-byte key in lowercase hex, the one spelling the chain records.
func isCanonicalEd25519Hex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == ed25519.PublicKeySize && s == strings.ToLower(s)
}

// CheckShape is the stateless part of verification, used by CheckTx as a mempool filter: everything except the chain,
// the sequence, the set in force and the current admins' signatures. It includes every new key's proof of possession.
func (t *AdminRotateTx) CheckShape() error {
	if t.Kind != AdminRotateKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, AdminRotateKind)
	}
	if strings.TrimSpace(t.ChainID) == "" || t.Sequence == 0 {
		return fmt.Errorf("an admin rotation names its chain and a sequence above zero")
	}
	if b, err := hex.DecodeString(t.CurrentSetID); err != nil || len(b) != sha256.Size || t.CurrentSetID != strings.ToLower(t.CurrentSetID) {
		return fmt.Errorf("current_set_id is not a lowercase hex sha256")
	}
	n := len(t.NewAdminKeys)
	if n == 0 || n > maxAdminKeys {
		return fmt.Errorf("the new admin set has %d keys; it needs 1 to %d", n, maxAdminKeys)
	}
	seen := make(map[string]string, n)
	for _, id := range sortedAdminIDs(t.NewAdminKeys) {
		k := t.NewAdminKeys[id]
		if !adminKeyIDPattern.MatchString(id) {
			return fmt.Errorf("admin key id %q is not a plain name (letters, digits, '.', '_', '-'; at most 64)", id)
		}
		if !isCanonicalEd25519Hex(k) {
			return fmt.Errorf("admin key %q is not an ed25519 public key in lowercase hex", id)
		}
		if other, dup := seen[k]; dup {
			return fmt.Errorf("admin keys %q and %q are the same key: one key is one signer", other, id)
		}
		seen[k] = id
	}
	if min := minimumAdminThreshold(n); t.NewThreshold < min || t.NewThreshold > n {
		return fmt.Errorf("threshold %d is not allowed for %d keys: it must be %d to %d (a set of two or more keys "+
			"never lets one key act alone)", t.NewThreshold, n, min, n)
	}
	proved := make(map[string]bool, n)
	for _, p := range t.Possession {
		pub, ok := t.NewAdminKeys[p.KeyID]
		if !ok {
			return fmt.Errorf("a proof of possession names %q, which is not in the new admin set", p.KeyID)
		}
		if proved[p.KeyID] {
			return fmt.Errorf("admin key %q proves possession twice", p.KeyID)
		}
		raw, _ := hex.DecodeString(pub)
		sig, err := hex.DecodeString(p.Signature)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(raw), t.PossessionBytes(), sig) {
			return fmt.Errorf("admin key %q's proof of possession does not verify", p.KeyID)
		}
		proved[p.KeyID] = true
	}
	for _, id := range sortedAdminIDs(t.NewAdminKeys) {
		if !proved[id] {
			return fmt.Errorf("admin key %q has no proof of possession: every key of the new set signs the rotation", id)
		}
	}
	return nil
}

// adminChangesBefore is the admin-set changes recorded at heights below h - those a block at h is judged after.
func adminChangesBefore(state *ledger.EntitlementPolicyState, h int64) []ledger.AdminReseal {
	if state == nil {
		return nil
	}
	var out []ledger.AdminReseal
	for _, r := range state.AdminReseals {
		if r.Height < h {
			out = append(out, r)
		}
	}
	return out
}

// NextAdminSequence is the sequence the next admin rotation in a block at h must carry.
func NextAdminSequence(state *ledger.EntitlementPolicyState, h int64) uint64 {
	return uint64(len(adminChangesBefore(state, h))) + 1
}

// sameKeysAndThreshold reports whether two sets are the same set (ids, keys and threshold).
func sameKeysAndThreshold(a map[string]string, at int, b map[string]string, bt int) bool {
	return AdminSetID(a, at) == AdminSetID(b, bt)
}

// VerifyAdminRotate is the v12 rule for an admin rotation carried by a block at height h on chainID, against the
// committed policy. Every input is committed state or the block, so every node reaches the same verdict and replay
// reproduces it.
func VerifyAdminRotate(t *AdminRotateTx, chainID string, state *ledger.EntitlementPolicyState, h int64) error {
	if err := t.CheckShape(); err != nil {
		return err
	}
	if t.ChainID != chainID {
		return fmt.Errorf("the rotation is for chain %q, this is %q", t.ChainID, chainID)
	}
	if state == nil {
		return fmt.Errorf("no sealed policy exists, so there is no admin set to rotate")
	}
	if want := NextAdminSequence(state, h); t.Sequence != want {
		return fmt.Errorf("sequence %d is not the next admin-set change %d (a rotation cannot be replayed, skipped "+
			"or reordered)", t.Sequence, want)
	}
	keys, threshold := AdminSetAt(state, h)
	if cur := AdminSetID(keys, threshold); t.CurrentSetID != cur {
		return fmt.Errorf("the rotation was made against admin set %s, but the set in force is %s: it is stale",
			t.CurrentSetID, cur)
	}
	if sameKeysAndThreshold(t.NewAdminKeys, t.NewThreshold, keys, threshold) {
		return fmt.Errorf("the new admin set is the set in force: the rotation changes nothing")
	}
	// A key that has left the admin set never comes back: every set ever in force before this block, less the one in
	// force now.
	inForce := make(map[string]bool, len(keys))
	for _, k := range keys {
		inForce[strings.ToLower(k)] = true
	}
	retired := map[string]bool{}
	for _, k := range state.AdminKeys {
		retired[strings.ToLower(k)] = true
	}
	for _, r := range adminChangesBefore(state, h) {
		for _, k := range r.Keys {
			retired[strings.ToLower(k)] = true
		}
	}
	for _, id := range sortedAdminIDs(t.NewAdminKeys) {
		if k := t.NewAdminKeys[id]; retired[k] && !inForce[k] {
			return fmt.Errorf("admin key %q left the admin set earlier and cannot come back", id)
		}
	}
	return verifyAdminQuorum(t.SigningBytes(), t.Signatures, &ledger.EntitlementPolicyState{AdminKeys: keys, AdminThreshold: threshold},
		"admin rotation", "the admin set cannot be rotated")
}
