package consensus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/certen/independant-validator/pkg/ledger"
)

// Rotating a validator's CometBFT consensus key on a running chain (RB3-F95).
//
// # WHY A TRANSACTION
//
// The validator set is consensus state: CometBFT takes it from the genesis and changes it only by the
// ValidatorUpdates an application returns from FinalizeBlock. Replacing a key file on a node does not
// change the set - the node simply stops being able to sign for its slot - and replacing it on every node
// at once is a new chain. A key can only be rotated by the chain agreeing to it, at a height, like any
// other state change.
//
// # WHAT MAKES IT SAFE
//
//   - The sealed admin quorum authorises it (the same keys and threshold that govern the entitlement
//     rule), over the chain id, so a rotation for one chain is nothing on another.
//   - The new key proves possession: it signs the rotation itself, so a key nobody holds - a typo, a
//     key whose seed was lost before submission - is refused before it can take a slot.
//   - Versions are strictly sequential, so a rotation cannot be replayed or reordered.
//   - At most one rotation per block, and none while an earlier one is not ADOPTED - its new key has not
//     yet signed a committed block. A rotated validator whose operator has not switched it to its new key
//     is one slot offline; refusing a second rotation until the first is signing means rotations can
//     never take more than one validator offline at a time, however they are submitted. The one
//     exception is re-rotating that same pending slot, which is how a new key that turned out to be
//     unusable is replaced.
//   - A key that ever left the set cannot come back, and a key already in the set cannot take a second
//     slot (which would silently merge two validators' power into one).
//   - Every input is committed state or the block itself, so every node reaches the same verdict and
//     replay reproduces it.

// ValidatorRotationKind identifies a rotation transaction on the wire.
const ValidatorRotationKind = "certen.validator.rotate/v1"

// ValidatorRotationTx replaces one validator's consensus key.
type ValidatorRotationTx struct {
	Kind      string `json:"kind"`
	ChainID   string `json:"chain_id"`
	Version   uint64 `json:"version"`
	OldPubKey string `json:"old_pub_key"` // hex ed25519, the key leaving the set
	NewPubKey string `json:"new_pub_key"` // hex ed25519, the key taking its power
	// Possession is the NEW key's signature over PossessionBytes: whoever submits this holds the key.
	Possession string            `json:"possession"`
	Signatures []PolicySignature `json:"signatures,omitempty"` // admin signatures over SigningBytes
}

func (t *ValidatorRotationTx) canonical(domain string) []byte {
	payload := fmt.Sprintf("%s\n%s\n%d\n%s\n%s", domain, t.ChainID, t.Version,
		strings.ToLower(t.OldPubKey), strings.ToLower(t.NewPubKey))
	sum := sha256.Sum256([]byte(payload))
	return sum[:]
}

// SigningBytes is what the admins sign: the chain, the version and both keys.
func (t *ValidatorRotationTx) SigningBytes() []byte { return t.canonical(ValidatorRotationKind) }

// PossessionBytes is what the new key signs. A different domain from SigningBytes, so neither signature
// can stand in for the other.
func (t *ValidatorRotationTx) PossessionBytes() []byte {
	return t.canonical("certen:validator-rotate-possession:v1")
}

// RotationID is what an accepted rotation contributes to the app hash.
func (t *ValidatorRotationTx) RotationID() string {
	return "validator-rotation:" + hex.EncodeToString(t.SigningBytes())
}

// DecodeValidatorRotation returns the transaction if these bytes are one. The discriminator is the explicit
// kind, never a guess at shape.
func DecodeValidatorRotation(tx []byte) (*ValidatorRotationTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != ValidatorRotationKind {
		return nil, false
	}
	var out ValidatorRotationTx
	if err := json.Unmarshal(tx, &out); err != nil {
		return nil, false
	}
	return &out, true
}

// decodeEd25519Hex decodes a hex ed25519 public key.
func decodeEd25519Hex(what, s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not a hex ed25519 public key", what)
	}
	return b, nil
}

// CheckShape is the stateless part of verification, used by CheckTx as a mempool filter.
func (t *ValidatorRotationTx) CheckShape() error {
	if t.Kind != ValidatorRotationKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, ValidatorRotationKind)
	}
	if t.ChainID == "" || t.Version == 0 {
		return fmt.Errorf("a rotation names its chain and a version above zero")
	}
	oldKey, err := decodeEd25519Hex("old_pub_key", t.OldPubKey)
	if err != nil {
		return err
	}
	newKey, err := decodeEd25519Hex("new_pub_key", t.NewPubKey)
	if err != nil {
		return err
	}
	if bytes.Equal(oldKey, newKey) {
		return fmt.Errorf("the new key is the old key")
	}
	sig, err := hex.DecodeString(t.Possession)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(newKey), t.PossessionBytes(), sig) {
		return fmt.Errorf("the new key's proof of possession does not verify")
	}
	return nil
}

// GenesisValidator is one validator of the chain's genesis set.
type GenesisValidator struct {
	PubKey []byte
	Power  int64
}

// GenesisValidatorsFrom reads the genesis set. Only ed25519 keys are supported: that is what CometBFT's
// default consensus params accept and what every Certen validator runs.
func GenesisValidatorsFrom(doc *cmttypes.GenesisDoc) ([]GenesisValidator, error) {
	if doc == nil || len(doc.Validators) == 0 {
		return nil, fmt.Errorf("the genesis names no validators")
	}
	out := make([]GenesisValidator, 0, len(doc.Validators))
	for i, v := range doc.Validators {
		pk, ok := v.PubKey.(cmted25519.PubKey)
		if !ok || len(pk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("genesis validator %d (%s) is not an ed25519 key", i, v.Name)
		}
		if v.Power <= 0 {
			return nil, fmt.Errorf("genesis validator %d (%s) has no power", i, v.Name)
		}
		out = append(out, GenesisValidator{PubKey: append([]byte(nil), pk...), Power: v.Power})
	}
	return out, nil
}

// validatorSetAt is the set in force for transactions in block h: the genesis set with every rotation
// accepted below h applied. Keys are lower-case hex.
func validatorSetAt(genesis []GenesisValidator, log *ledger.ValidatorRotationLog, h int64) map[string]int64 {
	set := make(map[string]int64, len(genesis))
	for _, v := range genesis {
		set[hex.EncodeToString(v.PubKey)] = v.Power
	}
	if log == nil {
		return set
	}
	for _, r := range log.Rotations {
		if r.Height >= h {
			continue
		}
		delete(set, strings.ToLower(r.OldPubKey))
		set[strings.ToLower(r.NewPubKey)] = r.Power
	}
	return set
}

// pendingRotationAt is the rotation accepted below h whose new key had not signed a committed block as of
// h, if any.
func pendingRotationAt(log *ledger.ValidatorRotationLog, h int64) *ledger.ValidatorRotationRecord {
	if log == nil {
		return nil
	}
	for i := len(log.Rotations) - 1; i >= 0; i-- {
		r := &log.Rotations[i]
		if r.Height >= h {
			continue
		}
		if r.AdoptedHeight == 0 || r.AdoptedHeight > h {
			return r
		}
		return nil // the latest accepted rotation is adopted; earlier ones were adopted before it was accepted
	}
	return nil
}

// highestRotationVersion is the newest accepted version (zero before any).
func highestRotationVersion(log *ledger.ValidatorRotationLog) uint64 {
	var v uint64
	if log == nil {
		return 0
	}
	for _, r := range log.Rotations {
		if r.Version > v {
			v = r.Version
		}
	}
	return v
}

// VerifyValidatorRotation judges a rotation carried by block h against committed state. It returns the power
// the new key takes.
func VerifyValidatorRotation(
	t *ValidatorRotationTx,
	chainID string,
	policy *ledger.EntitlementPolicyState,
	genesis []GenesisValidator,
	log *ledger.ValidatorRotationLog,
	h int64,
) (int64, error) {
	if len(genesis) == 0 {
		return 0, fmt.Errorf("this node has no genesis validator set to rotate against")
	}
	if err := t.CheckShape(); err != nil {
		return 0, err
	}
	if t.ChainID != chainID {
		return 0, fmt.Errorf("the rotation is for chain %q, this is %q", t.ChainID, chainID)
	}
	if want := highestRotationVersion(log) + 1; t.Version != want {
		return 0, fmt.Errorf("version %d is not the next rotation version %d (a rotation cannot be replayed, "+
			"skipped or reordered)", t.Version, want)
	}
	if err := verifyAdminQuorum(t.SigningBytes(), t.Signatures, policy, "validator rotation",
		"no validator key can be rotated"); err != nil {
		return 0, err
	}

	oldKey, newKey := strings.ToLower(strings.TrimPrefix(t.OldPubKey, "0x")), strings.ToLower(strings.TrimPrefix(t.NewPubKey, "0x"))
	set := validatorSetAt(genesis, log, h)
	power, ok := set[oldKey]
	if !ok {
		return 0, fmt.Errorf("the old key is not in the validator set")
	}
	if _, taken := set[newKey]; taken {
		return 0, fmt.Errorf("the new key already holds a slot in the validator set")
	}
	if log != nil {
		for _, r := range log.Rotations {
			if r.Height < h && strings.EqualFold(r.OldPubKey, newKey) {
				return 0, fmt.Errorf("the new key was rotated out at height %d and cannot come back", r.Height)
			}
		}
	}
	if pending := pendingRotationAt(log, h); pending != nil && !strings.EqualFold(pending.NewPubKey, oldKey) {
		return 0, fmt.Errorf("rotation %d (accepted at height %d) has not been adopted: its new key has not "+
			"signed a committed block yet. One rotation at a time - switch that validator to its new key "+
			"first, or re-rotate that same slot", pending.Version, pending.Height)
	}
	return power, nil
}

// rotationUpdates is what CometBFT applies: the old key leaves, the new key takes its power.
func rotationUpdates(r *ledger.ValidatorRotationRecord) ([]abcitypes.ValidatorUpdate, error) {
	oldKey, err := decodeEd25519Hex("old_pub_key", r.OldPubKey)
	if err != nil {
		return nil, err
	}
	newKey, err := decodeEd25519Hex("new_pub_key", r.NewPubKey)
	if err != nil {
		return nil, err
	}
	return []abcitypes.ValidatorUpdate{
		abcitypes.Ed25519ValidatorUpdate(oldKey, 0),
		abcitypes.Ed25519ValidatorUpdate(newKey, r.Power),
	}, nil
}

// markRotationAdopted records, for the rotation pending at h, that its new key signed the commit block h
// carries. Returns whether the log changed.
func markRotationAdopted(log *ledger.ValidatorRotationLog, h int64, commit abcitypes.CommitInfo) bool {
	pending := pendingRotationAt(log, h)
	if pending == nil || pending.AdoptedHeight != 0 {
		return false
	}
	newKey, err := decodeEd25519Hex("new_pub_key", pending.NewPubKey)
	if err != nil {
		return false
	}
	addr := cmted25519.PubKey(newKey).Address()
	for _, v := range commit.Votes {
		if v.BlockIdFlag == cmtproto.BlockIDFlagCommit && bytes.Equal(v.Validator.Address, addr) {
			pending.AdoptedHeight = h
			return true
		}
	}
	return false
}

// ValidatorSetSummary lists a set's keys and powers in a stable order, for logs and tools.
func ValidatorSetSummary(set map[string]int64) []string {
	out := make([]string, 0, len(set))
	for k, p := range set {
		out = append(out, fmt.Sprintf("%s:%d", k, p))
	}
	sort.Strings(out)
	return out
}
