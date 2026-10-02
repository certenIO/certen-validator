package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/ledger"
)

// The admin re-seal (rules v11).
//
// CERTEN's admin quorum - the one authority for policy updates, validator key rotations and the BLS registry - is
// sealed at genesis and could not be changed by any transaction. On certen-testnet the secrets of both sealed admin
// keys (ops-1, ops-2, threshold 2) were never kept: `policy-update keygen` printed them once and no copy survived
// (RUNLOG_RB5, 2026-10-02). With them lost the chain could never take a BLS registry (so no intent could be certified),
// a policy update, or a rotation of its publicly derivable consensus keys (RB3-F95) - for its whole life.
//
// v11 replaces that admin set ONCE, with a set written into this rule: three keys, any two of which authorise, so the
// loss of one can never lock the chain again. The transaction carries no signature because no surviving key could
// sign it; its authority is the rule itself, which every validator of the chain adopts by running this binary. It is
// accepted only
//
//   - on certen-testnet (adminResealChainID),
//   - while the admin set in force is exactly the lost set (lostAdminSet), and never once the chain has re-sealed,
//   - naming exactly the set below (resealedAdminSet) - nothing else can be installed this way.
//
// Accepted, it is recorded APPEND-ONLY in the committed policy (EntitlementPolicyState.AdminReseals) and takes effect
// from the next height. The admin set in force at a height is DERIVED from that record (AdminSetAt), never a mutated
// field: every admin-signed transaction of a block - before or after the re-seal in it - is judged by the set in force
// for that block, however many times the block is executed.

// AdminResealKind identifies an admin re-seal on the wire.
const AdminResealKind = "certen.admin.reseal/v1"

// codeAdminResealRefused is the result code of a refused re-seal.
const codeAdminResealRefused uint32 = 11

// adminResealChainID is the only chain the re-seal applies to.
const adminResealChainID = "certen-testnet"

// adminSet is an admin quorum: key id -> hex ed25519 public key, and how many distinct signatures it takes.
type adminSet struct {
	Keys      map[string]string
	Threshold int
}

// lostAdminSet is the set sealed at certen-testnet's genesis whose secrets were lost.
var lostAdminSet = adminSet{
	Keys: map[string]string{
		"ops-1": "2074b00450f5dbfd9d084423b5232e3732ef5db108f8b6fb5d4c96b73d5effd6",
		"ops-2": "4572d81eeb0b2f72347f987a1a2ba75f4d5b475da14bbda9e0b585d1d50bc2f8",
	},
	Threshold: 2,
}

// resealedAdminSet is the set v11 installs: three keys generated 2026-10-02 (their secrets written straight to the
// owner's files, never printed), any two of which authorise.
var resealedAdminSet = adminSet{
	Keys: map[string]string{
		"admin-a": "92d403978891216dac310c053c18d048d783d0311e8558e68b26f7fc101e004a",
		"admin-b": "df2b05997cf690ef04279cc71be4f51e1ea1328d06eebf33902763c8c8586696",
		"admin-c": "dc7c9f6202c3285abe476b4160026ae31ef988354818d74adc61d41db5f5f029",
	},
	Threshold: 2,
}

// AdminResealTx is the re-seal transaction.
type AdminResealTx struct {
	Kind           string            `json:"kind"`
	ChainID        string            `json:"chain_id"`
	AdminKeys      map[string]string `json:"admin_keys"`
	AdminThreshold int               `json:"admin_threshold"`
}

// NewAdminResealTx is the one re-seal this rule accepts, for chainID.
func NewAdminResealTx(chainID string) *AdminResealTx {
	keys := make(map[string]string, len(resealedAdminSet.Keys))
	for id, k := range resealedAdminSet.Keys {
		keys[id] = k
	}
	return &AdminResealTx{Kind: AdminResealKind, ChainID: chainID, AdminKeys: keys, AdminThreshold: resealedAdminSet.Threshold}
}

// DecodeAdminReseal returns the transaction if these bytes are one. The discriminator is the explicit kind.
func DecodeAdminReseal(tx []byte) (*AdminResealTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != AdminResealKind {
		return nil, false
	}
	var t AdminResealTx
	if err := json.Unmarshal(tx, &t); err != nil {
		return &AdminResealTx{Kind: AdminResealKind}, true // the kind, malformed: refused by CheckShape
	}
	return &t, true
}

// CheckShape is the stateless check: a chain, at least one well-formed ed25519 key, a reachable threshold of 1 or more.
func (t *AdminResealTx) CheckShape() error {
	if t.Kind != AdminResealKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, AdminResealKind)
	}
	if strings.TrimSpace(t.ChainID) == "" {
		return fmt.Errorf("no chain id")
	}
	if len(t.AdminKeys) == 0 {
		return fmt.Errorf("no admin keys")
	}
	for id, k := range t.AdminKeys {
		b, err := hex.DecodeString(k)
		if strings.TrimSpace(id) == "" || err != nil || len(b) != 32 {
			return fmt.Errorf("admin key %q is not a hex ed25519 public key", id)
		}
	}
	if t.AdminThreshold < 1 || t.AdminThreshold > len(t.AdminKeys) {
		return fmt.Errorf("threshold %d is not reachable with %d keys", t.AdminThreshold, len(t.AdminKeys))
	}
	return nil
}

// canonical is the re-seal's deterministic encoding: kind, chain, threshold and the sorted keys.
func (t *AdminResealTx) canonical() []byte {
	ids := make([]string, 0, len(t.AdminKeys))
	for id := range t.AdminKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n%d\n", AdminResealKind, t.ChainID, t.AdminThreshold)
	for _, id := range ids {
		fmt.Fprintf(&b, "%s=%s\n", id, strings.ToLower(t.AdminKeys[id]))
	}
	return []byte(b.String())
}

// ResealID identifies the re-seal in the app hash and its record.
func (t *AdminResealTx) ResealID() string {
	h := sha256.Sum256(t.canonical())
	return hex.EncodeToString(h[:])
}

// sameAdminSet reports whether keys/threshold are exactly s (key ids and keys, case-insensitively for the hex).
func sameAdminSet(keys map[string]string, threshold int, s adminSet) bool {
	if threshold != s.Threshold || len(keys) != len(s.Keys) {
		return false
	}
	for id, k := range s.Keys {
		if !strings.EqualFold(keys[id], k) {
			return false
		}
	}
	return true
}

// AdminSetAt is the admin set in force for the block at height: the newest re-seal recorded at a height below it, or
// the set sealed at genesis. Derived from the append-only record, so it is the same however often a block is executed.
func AdminSetAt(state *ledger.EntitlementPolicyState, height int64) (map[string]string, int) {
	if state == nil {
		return nil, 0
	}
	keys, threshold := state.AdminKeys, state.AdminThreshold
	for _, r := range state.AdminReseals {
		if r.Height < height {
			keys, threshold = r.Keys, r.Threshold
		}
	}
	return keys, threshold
}

// withAdminSetAt is state with its admin quorum replaced by the set in force at height - what every admin-signed
// transaction of that block is judged against. A shallow copy: never saved, never mutating committed state.
func withAdminSetAt(state *ledger.EntitlementPolicyState, height int64) *ledger.EntitlementPolicyState {
	if state == nil {
		return nil
	}
	eff := *state
	eff.AdminKeys, eff.AdminThreshold = AdminSetAt(state, height)
	return &eff
}

// verifyAdminReseal is the v11 rule for a re-seal at height on chainID, against the committed policy: the one re-seal
// from the lost set to the set this rule installs, on the one chain it applies to, once.
func verifyAdminReseal(t *AdminResealTx, chainID string, state *ledger.EntitlementPolicyState, height int64,
	from, to adminSet) error {
	if err := t.CheckShape(); err != nil {
		return err
	}
	if chainID != adminResealChainID || t.ChainID != chainID {
		return fmt.Errorf("the re-seal applies to chain %q only; this is %q and the transaction names %q",
			adminResealChainID, chainID, t.ChainID)
	}
	if state == nil {
		return fmt.Errorf("no sealed policy exists to re-seal")
	}
	if len(state.AdminReseals) > 0 {
		return fmt.Errorf("this chain already re-sealed its admin set at height %d", state.AdminReseals[0].Height)
	}
	keys, threshold := AdminSetAt(state, height)
	if !sameAdminSet(keys, threshold, from) {
		return fmt.Errorf("the admin set in force is not the lost set this rule replaces; nothing is re-sealed")
	}
	if !sameAdminSet(t.AdminKeys, t.AdminThreshold, to) {
		return fmt.Errorf("the transaction does not name the admin set this rule installs")
	}
	return nil
}
