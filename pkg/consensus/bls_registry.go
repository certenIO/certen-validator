package consensus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/ledger"
)

// CERTEN's BLS registry as consensus state (RB5 D3).
//
// # WHY A TRANSACTION
//
// A ValidatorBlock's intent signature must be verified in FinalizeBlock against the signer's BLS key, and
// FinalizeBlock may read only committed state and the block: never an RPC, never a node's environment. Until
// now no such key existed in consensus - the only BLS registry was the anchor contract's, read over RPC - so a
// ValidatorBlock was authenticated by nothing (its validator_id is self-declared, RB5-F25). The registry is
// recorded by the chain, like a rotation, so every node verifies against the same keys at every height and
// replay reproduces each verdict.
//
// # WHAT MAKES IT SAFE
//
//   - The sealed admin quorum authorises it over the chain id, so a registry for one chain is nothing on another.
//   - Every member's BLS key proves possession: it signs a domain-tagged statement of its own membership (chain,
//     validator id, address, key) under the same hash-to-G1 its intent signatures use. A key nobody holds, or a
//     key copied from another validator to claim its signatures (a rogue-key aggregate), cannot enter.
//   - Keys are subgroup-checked; validator ids, addresses and keys are each unique.
//   - Versions are strictly sequential, so a registry cannot be replayed or reordered.
//   - It records the Accumulate incarnation the quorum attests under, and the CERTEN set root - derived here
//     from the members exactly as the anchor contract derives currentValidatorSetRoot - so both are chain state
//     rather than each node's environment.

// BLSRegistryKind identifies a registry transaction on the wire.
const BLSRegistryKind = "certen.blsregistry.set/v1"

// codeBLSRegistryRefused is the result code of a refused registry transaction.
const codeBLSRegistryRefused uint32 = 9

// BLSRegistryEntry is one member as submitted: the recorded member plus its proof of possession.
type BLSRegistryEntry struct {
	ledger.BLSRegistryMember
	// Possession is the member's BLS signature (hex G1, compressed) over PossessionMessage.
	Possession string `json:"possession"`
}

// BLSRegistryTx sets CERTEN's BLS registry.
type BLSRegistryTx struct {
	Kind                  string             `json:"kind"`
	ChainID               string             `json:"chain_id"`
	Version               uint64             `json:"version"`
	Members               []BLSRegistryEntry `json:"members"`
	ThresholdNumerator    uint64             `json:"threshold_numerator"`
	ThresholdDenominator  uint64             `json:"threshold_denominator"`
	AccumulateIncarnation string             `json:"accumulate_incarnation"`
	Signatures            []PolicySignature  `json:"signatures,omitempty"` // admin signatures over SigningBytes
}

// sortedMembers is the members in validator-id order, with canonical lowercase encodings.
func (t *BLSRegistryTx) sortedMembers() []ledger.BLSRegistryMember {
	out := make([]ledger.BLSRegistryMember, len(t.Members))
	for i, m := range t.Members {
		out[i] = ledger.BLSRegistryMember{
			ValidatorID: m.ValidatorID,
			EVMAddress:  strings.ToLower(m.EVMAddress),
			BLSPubKey:   strings.ToLower(strings.TrimPrefix(m.BLSPubKey, "0x")),
			Power:       m.Power,
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ValidatorID < out[j].ValidatorID })
	return out
}

// SigningBytes is what the admins sign: the chain, the version, the threshold, the incarnation and every member.
func (t *BLSRegistryTx) SigningBytes() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n%d\n%d/%d\n%s\n", BLSRegistryKind, t.ChainID, t.Version,
		t.ThresholdNumerator, t.ThresholdDenominator, strings.ToLower(strings.TrimPrefix(t.AccumulateIncarnation, "0x")))
	for _, m := range t.sortedMembers() {
		fmt.Fprintf(&b, "%s|%s|%s|%d\n", m.ValidatorID, m.EVMAddress, m.BLSPubKey, m.Power)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return sum[:]
}

// RegistryID is what an accepted registry contributes to the app hash.
func (t *BLSRegistryTx) RegistryID() string {
	return "bls-registry:" + hex.EncodeToString(t.SigningBytes())
}

// PossessionMessage is what a member's BLS key signs to prove it holds it: its own membership on this chain.
// sha256 under its own domain, so it is no intent, anchor or batch message (those are keccak over ABI encodings
// with their own domains).
func PossessionMessage(chainID string, m ledger.BLSRegistryMember) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("certen:blsregistry-possession:v1\n%s\n%s\n%s\n%s",
		chainID, m.ValidatorID, strings.ToLower(m.EVMAddress), strings.ToLower(strings.TrimPrefix(m.BLSPubKey, "0x")))))
}

// SignPossession produces a member's proof of possession.
func SignPossession(sk *bls.PrivateKey, chainID string, m ledger.BLSRegistryMember) string {
	return hex.EncodeToString(bls_zkp.SignV6_1PreExec(sk, PossessionMessage(chainID, m)).Bytes())
}

// DecodeBLSRegistry returns the transaction if these bytes are one. The discriminator is the explicit kind.
func DecodeBLSRegistry(tx []byte) (*BLSRegistryTx, bool) {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(tx, &probe); err != nil || probe.Kind != BLSRegistryKind {
		return nil, false
	}
	var out BLSRegistryTx
	if err := json.Unmarshal(tx, &out); err != nil {
		return nil, false
	}
	return &out, true
}

// CheckShape is the stateless part of verification, used by CheckTx as a mempool filter: everything except
// the chain, the version and the admin quorum.
func (t *BLSRegistryTx) CheckShape() error {
	if t.Kind != BLSRegistryKind {
		return fmt.Errorf("kind %q is not %q", t.Kind, BLSRegistryKind)
	}
	if t.ChainID == "" || t.Version == 0 {
		return fmt.Errorf("a registry names its chain and a version above zero")
	}
	if len(t.Members) == 0 {
		return fmt.Errorf("a registry has members")
	}
	if t.ThresholdDenominator == 0 || t.ThresholdNumerator == 0 || t.ThresholdNumerator > t.ThresholdDenominator {
		return fmt.Errorf("threshold %d/%d is not in (0, 1]", t.ThresholdNumerator, t.ThresholdDenominator)
	}
	inc, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(t.AccumulateIncarnation), "0x"))
	if err != nil || len(inc) != 32 || bytes.Equal(inc, make([]byte, 32)) {
		return fmt.Errorf("accumulate_incarnation is not a non-zero hex32")
	}
	ids, addrs, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range t.Members {
		m := e.BLSRegistryMember
		if m.ValidatorID == "" {
			return fmt.Errorf("a member has no validator id")
		}
		if !common.IsHexAddress(m.EVMAddress) || common.HexToAddress(m.EVMAddress) == (common.Address{}) {
			return fmt.Errorf("member %s: %q is not a non-zero EVM address", m.ValidatorID, m.EVMAddress)
		}
		if m.Power == 0 {
			return fmt.Errorf("member %s has no power", m.ValidatorID)
		}
		key := strings.ToLower(strings.TrimPrefix(m.BLSPubKey, "0x"))
		raw, err := hex.DecodeString(key)
		if err != nil {
			return fmt.Errorf("member %s: the BLS key is not hex", m.ValidatorID)
		}
		if err := bls.ValidateBLSPublicKeySubgroup(raw); err != nil {
			return fmt.Errorf("member %s: %w", m.ValidatorID, err)
		}
		addr := strings.ToLower(m.EVMAddress)
		if ids[m.ValidatorID] || addrs[addr] || keys[key] {
			return fmt.Errorf("member %s repeats a validator id, address or BLS key", m.ValidatorID)
		}
		ids[m.ValidatorID], addrs[addr], keys[key] = true, true, true
		if err := verifyPossession(t.ChainID, e); err != nil {
			return fmt.Errorf("member %s: %w", m.ValidatorID, err)
		}
	}
	return nil
}

func verifyPossession(chainID string, e BLSRegistryEntry) error {
	raw, _ := hex.DecodeString(strings.ToLower(strings.TrimPrefix(e.BLSPubKey, "0x")))
	pub, err := bls.PublicKeyFromBytes(raw)
	if err != nil {
		return err
	}
	sigRaw, err := hex.DecodeString(strings.TrimPrefix(e.Possession, "0x"))
	if err != nil {
		return fmt.Errorf("the proof of possession is not hex")
	}
	if err := bls.ValidateBLSSignatureSubgroup(sigRaw); err != nil {
		return fmt.Errorf("the proof of possession: %w", err)
	}
	sig, err := bls.SignatureFromBytes(sigRaw)
	if err != nil {
		return err
	}
	if !pub.VerifyG1(sig, bls_zkp.HashMessageToG1V2(PossessionMessage(chainID, e.BLSRegistryMember))) {
		return fmt.Errorf("the BLS key's proof of possession does not verify")
	}
	return nil
}

// RegistryCertenSetRoot is the anchor contract's currentValidatorSetRoot for these members and threshold:
// keccak256(abi.encode(address[] ascending, uint256[] powers, num, den)).
func RegistryCertenSetRoot(members []ledger.BLSRegistryMember, num, den uint64) ([32]byte, error) {
	addrs := make([]common.Address, len(members))
	powers := make([]*big.Int, len(members))
	for i, m := range members {
		addrs[i] = common.HexToAddress(m.EVMAddress)
		powers[i] = new(big.Int).SetUint64(m.Power)
	}
	sa, sp := contracts.SortValidatorsForSetRoot(addrs, powers)
	return contracts.ComputeValidatorSetRootV6_1(sa, sp, new(big.Int).SetUint64(num), new(big.Int).SetUint64(den))
}

// highestRegistryVersion is the newest accepted version (zero before any).
func highestRegistryVersion(log *ledger.BLSRegistryLog) uint64 {
	if log == nil || len(log.Versions) == 0 {
		return 0
	}
	return log.Versions[len(log.Versions)-1].Version
}

// RegistryAt is the registry in force for a block at height h: the newest version accepted below h. Nil when
// none was.
func RegistryAt(log *ledger.BLSRegistryLog, h int64) *ledger.BLSRegistryRecord {
	if log == nil {
		return nil
	}
	for i := len(log.Versions) - 1; i >= 0; i-- {
		if log.Versions[i].Height < h {
			return &log.Versions[i]
		}
	}
	return nil
}

// VerifyBLSRegistry judges a registry transaction against committed state and returns the record it sets.
func VerifyBLSRegistry(t *BLSRegistryTx, chainID string, policy *ledger.EntitlementPolicyState,
	log *ledger.BLSRegistryLog, h int64) (*ledger.BLSRegistryRecord, error) {
	if err := t.CheckShape(); err != nil {
		return nil, err
	}
	if t.ChainID != chainID {
		return nil, fmt.Errorf("the registry is for chain %q, this is %q", t.ChainID, chainID)
	}
	if want := highestRegistryVersion(log) + 1; t.Version != want {
		return nil, fmt.Errorf("version %d is not the next registry version %d (a registry cannot be replayed, "+
			"skipped or reordered)", t.Version, want)
	}
	if err := verifyAdminQuorum(t.SigningBytes(), t.Signatures, policy, "BLS registry",
		"no BLS registry can be set"); err != nil {
		return nil, err
	}
	members := t.sortedMembers()
	root, err := RegistryCertenSetRoot(members, t.ThresholdNumerator, t.ThresholdDenominator)
	if err != nil {
		return nil, err
	}
	return &ledger.BLSRegistryRecord{
		Version:               t.Version,
		Height:                h,
		Members:               members,
		ThresholdNumerator:    t.ThresholdNumerator,
		ThresholdDenominator:  t.ThresholdDenominator,
		AccumulateIncarnation: "0x" + strings.ToLower(strings.TrimPrefix(t.AccumulateIncarnation, "0x")),
		CertenSetRoot:         "0x" + hex.EncodeToString(root[:]),
		ID:                    t.RegistryID(),
	}, nil
}
