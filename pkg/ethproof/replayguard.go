// Copyright 2026 Certen Protocol

package ethproof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// =============================================================================
// S6 - the replay guard was consumed by this transaction (PROOF_V2 section 3, RB10)
// =============================================================================
//
// A member is settled through its own account (CertenAccountV7_3.executeGovernanceProofDirect /
// batchExecuteGovernanceProofDirect), and the account's replay guard is `_consumedLeaf[leaf]` (storage slot 4,
// `mapping(bytes32 => bool)`): a leaf is one authorized effect, consumable exactly once, and a second consumption reverts
// (CertenAccountV7_3.sol _authorizeLeaf). The account announces the consumption in the receipt:
// LeafConsumed(anchorId indexed, leaf indexed, operationID), topics[2] being the very key of the mapping.
//
// ReplayGuardProof carries what a verifier needs to check, offline and trusting no provider, that the slot of THIS
// transaction's leaf is 1 in the account's state at a block no earlier than the settlement block (After, mandatory - it is
// the claim "replay-nonce slot consumed (storage proof)"), and, whenever a provider served it, that it was 0 in the state
// of the settlement block's parent (Before - the transition). Monotonicity - a consumed leaf is never cleared - is the
// contract code's, which S8 proves; the proven receipt and its LeafConsumed event tie the consumption to this transaction.
//
// The object sits BESIDE the settlement. It is never an input of the observation's result hash, the attestation message,
// ExternalChainResult.ComputeResultHash or an outcome leaf: its bytes exist only if the capturing validator's provider
// still served that state, which differs by provider and time (R10 Q5).

// ReplayGuardDomain is the domain tag of the evidence.
const ReplayGuardDomain = "certen:s6-replay:v1"

// MaxReplayHeaderChain is the longest header chain From the settlement block to the block After is proven at.
const MaxReplayHeaderChain = 512

// ReplayDerivation names how the slot is derived from the key and the declared base.
const ReplayDerivation = "keccak256(abi.encode(bytes32 key, uint256 base))"

// AccountGenerationV7_3 is the account generation whose `_consumedLeaf` layout is pinned: the compiler's storage layout of
// CertenAccountV7_3 at certen-contracts 57153e5 (solc 0.8.24, via_ir) puts `_consumedLeaf` at slot 4, and the deployed
// code of the four live chains is that source (R10 Q1a, Q2).
const AccountGenerationV7_3 = "CertenAccountV7_3"

// replayLayout is a generation's pinned layout: the base slot of its replay guard, and the selectors of the settlement
// entry points that consume it.
type replayLayout struct {
	base      uint64
	selectors [][4]byte
}

// replayLayouts: selectors from `forge inspect CertenAccountV7_3 methodIdentifiers` (R10 M4): executeGovernanceProofDirect
// 0x606f2c8d and batchExecuteGovernanceProofDirect 0x329fe012. pkg/execution pins them to the ABI it sends with.
var replayLayouts = map[string]replayLayout{
	AccountGenerationV7_3: {base: 4, selectors: [][4]byte{{0x60, 0x6f, 0x2c, 0x8d}, {0x32, 0x9f, 0xe0, 0x12}}},
}

// AccountGenerationV7_2 is the older account generation (leaf v3, factory V10) and the settlements made before each
// chain's v4 cutover. Its layout is not pinned here: its settlements are the named state s6_replay_unproven
// {account_generation}, never omitted and never answered with the V7_3 layout.
const AccountGenerationV7_2 = "CertenAccountV7_2"

// settlementSelectors are the settlement entry points of every account generation, to tell an account settlement of
// either generation from any other transaction. V7_3's are replayLayouts'; V7_2's are the selectors of its ABI
// (pkg/execution pins both to the ABIs it sends with).
var settlementSelectors = map[string][][4]byte{
	AccountGenerationV7_3: replayLayouts[AccountGenerationV7_3].selectors,
	AccountGenerationV7_2: {{0x57, 0xf8, 0x56, 0x7d}, {0xb7, 0xda, 0xa9, 0x01}},
}

// SettlementCallGeneration is the account generation whose settlement entry point calldata calls, and false when the
// calldata is no account settlement at all.
func SettlementCallGeneration(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	for gen, sels := range settlementSelectors {
		for _, sel := range sels {
			if bytes.Equal(sel[:], data[:4]) {
				return gen, true
			}
		}
	}
	return "", false
}

// ReplayLayoutBase is the pinned base slot of a generation's replay guard.
func ReplayLayoutBase(generation string) (uint64, bool) {
	l, ok := replayLayouts[generation]
	return l.base, ok
}

// ReplaySettlementSelectors are the settlement entry points of a generation.
func ReplaySettlementSelectors(generation string) [][4]byte {
	return append([][4]byte(nil), replayLayouts[generation].selectors...)
}

// LeafConsumedTopic is keccak256("LeafConsumed(bytes32,bytes32,bytes32)"), the account's record of a consumption.
var LeafConsumedTopic = crypto.Keccak256Hash([]byte("LeafConsumed(bytes32,bytes32,bytes32)"))

// ReplaySlotFor is the storage slot of mapping(bytes32 => bool) at base for key: keccak256(abi.encode(key, base)).
func ReplaySlotFor(key common.Hash, base uint64) common.Hash {
	var buf [64]byte
	copy(buf[:32], key[:])
	binary.BigEndian.PutUint64(buf[56:], base)
	return crypto.Keccak256Hash(buf[:])
}

// The named states of the S6 replay-guard evidence. Nothing is judged without one: what cannot be established is stated
// with the block it was judged at, never answered with something weaker.
const (
	// ReplayProven: the slot was proven consumed.
	ReplayProven = "proven"
	// ReplayUnproven: the replay guard could not be proven; Reason says why.
	ReplayUnproven = "s6_replay_unproven"
	// ReplayEventMissing: the proven status-1 receipt holds no LeafConsumed event of the transaction's target account.
	ReplayEventMissing = "s6_event_missing"
	// ReplayRefuted: the proof contradicts the settlement.
	ReplayRefuted = "s6_replay_refuted"
)

// Reasons of the named states.
const (
	ReasonStateUnavailable      = "state_unavailable"
	ReasonProofDoesNotVerify    = "proof_does_not_verify"
	ReasonParentHeaderUnproven  = "parent_header_unproven"
	ReasonHeaderChainBroken     = "header_chain_broken"
	ReasonHeaderChainTooLong    = "header_chain_too_long"
	ReasonAccountGeneration     = "account_generation"
	ReasonSlotMismatch          = "slot_mismatch"
	ReasonContractMismatch      = "contract_mismatch"
	ReasonSettlementUnproven    = "settlement_unproven"
	ReasonSettlementNotExecuted = "settlement_not_executed"
	ReasonBlockMismatch         = "settlement_block_mismatch"
	ReasonBeforeUndisclosed     = "before_neither_proven_nor_disclosed"
	ReasonNoEvent               = "no_leaf_consumed_event"
	ReasonReceiptUnavailable    = "receipt_unavailable"
	ReasonSlotSetAtParent       = "slot_set_at_parent"
	ReasonSlotUnsetAtBlock      = "slot_unset_at_block"
	ReasonVersion               = "unknown_version"
	ReasonEmptyEvidence         = "no_evidence_or_state"
)

// ErrReplayGuard is the class of every refusal of a replay-guard proof.
var ErrReplayGuard = errors.New("replay guard proof refused")

// ReplayError is a refusal by named state: the state, the reason, and what was judged.
type ReplayError struct {
	State  string
	Reason string
	Detail string
}

func (e *ReplayError) Error() string {
	return fmt.Sprintf("%v: %s{reason=%s}: %s", ErrReplayGuard, e.State, e.Reason, e.Detail)
}

// Is makes every ReplayError an ErrReplayGuard.
func (e *ReplayError) Is(target error) bool { return target == ErrReplayGuard }

func replayRefusal(state, reason, format string, args ...interface{}) error {
	return &ReplayError{State: state, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

func unproven(reason, format string, args ...interface{}) error {
	return replayRefusal(ReplayUnproven, reason, format, args...)
}

// BlockRef names a block.
type BlockRef struct {
	Number uint64      `json:"number"`
	Hash   common.Hash `json:"hash"`
}

// ReplaySlot is the storage slot the proof is about: the key (the leaf the account's LeafConsumed event names), the base
// slot of the pinned layout, how the slot derives from them, and the slot.
type ReplaySlot struct {
	Key        common.Hash `json:"key"`
	Base       uint64      `json:"base"`
	Derivation string      `json:"derivation"`
	Slot       common.Hash `json:"slot"`
}

// SlotProof is an account proof and a storage proof, as eth_getProof serves them, at one block's state root.
type SlotProof struct {
	// AccountAbsent: the account proof is a verified exclusion proof (the contract is not in that state).
	AccountAbsent bool            `json:"account_absent,omitempty"`
	AccountProof  []hexutil.Bytes `json:"account_proof"`
	StorageHash   common.Hash     `json:"storage_hash"`
	CodeHash      common.Hash     `json:"code_hash"`
	StorageProof  []hexutil.Bytes `json:"storage_proof"`
	// Value is the slot's value as the proof states it; verification recomputes it.
	Value common.Hash `json:"value"`
}

// ReplayProviderFailure is why one provider did not serve a proof.
type ReplayProviderFailure struct {
	Host  string `json:"host"`
	Error string `json:"error"`
}

// ReplayBefore is the optional transition half: the settlement block's parent (header, which must be the block's
// parentHash) and the slot proven 0 in its state.
type ReplayBefore struct {
	ParentHeader hexutil.Bytes `json:"parent_header_rlp"`
	Proof        SlotProof     `json:"proof"`
}

// ReplayBeforeUnavailable is the disclosure that the parent-state half was not served. It is not a failure: the claim
// is After; the disclosure says what was tried.
type ReplayBeforeUnavailable struct {
	Reason    string                  `json:"reason"`
	Providers []ReplayProviderFailure `json:"providers,omitempty"`
}

// ReplayGuardProof is the S6 storage evidence of one settlement (domain tag certen:s6-replay:v1).
type ReplayGuardProof struct {
	Version    string         `json:"version"`
	ChainID    int64          `json:"chain_id"`
	Generation string         `json:"generation"`
	Contract   common.Address `json:"contract"`
	Slot       ReplaySlot     `json:"slot"`
	// SettlementBlock is the block the settlement is proven in; ProvenAt the block After is proven at (not before it, at
	// most MaxReplayHeaderChain after it).
	SettlementBlock BlockRef `json:"settlement_block"`
	ProvenAt        BlockRef `json:"proven_at"`
	// Headers are the RLP headers of the blocks after the settlement block up to ProvenAt, each linked by parentHash to
	// the one before; empty when ProvenAt is the settlement block.
	Headers []hexutil.Bytes `json:"headers"`
	// After: the slot is 1 in the contract's state at ProvenAt's state root. Mandatory.
	After SlotProof `json:"after"`
	// Before: the slot is 0 in the state of the settlement block's parent, or BeforeUnavailable says it was not served.
	Before            *ReplayBefore            `json:"before,omitempty"`
	BeforeUnavailable *ReplayBeforeUnavailable `json:"s6_before_unavailable,omitempty"`
}

// ReplayNamedState is a replay guard that is not proven (or is refuted), stated with what it was judged at.
type ReplayNamedState struct {
	State       string                  `json:"state"`
	Reason      string                  `json:"reason"`
	ChainID     int64                   `json:"chain_id"`
	TxHash      common.Hash             `json:"tx_hash"`
	BlockNumber uint64                  `json:"block_number"`
	BlockHash   common.Hash             `json:"block_hash"`
	Contract    common.Address          `json:"contract"`
	Providers   []ReplayProviderFailure `json:"providers,omitempty"`
	Detail      string                  `json:"detail,omitempty"`
	// Before carries the proof that refutes, for ReplayRefuted / slot_set_at_parent.
	Before *ReplayBefore `json:"before,omitempty"`
}

// ReplayGuardEvidence is what is stored beside a settlement: exactly one of a proof or a named state.
type ReplayGuardEvidence struct {
	Version string            `json:"version"`
	Proof   *ReplayGuardProof `json:"proof,omitempty"`
	State   *ReplayNamedState `json:"state,omitempty"`
}

// ReplayGuardCheck is what verifying the evidence against its settlement established.
type ReplayGuardCheck struct {
	// State is ReplayProven, or the named state the evidence states.
	State           string
	Reason          string
	ChainID         int64
	Contract        common.Address
	Generation      string
	Slot            ReplaySlot
	SettlementBlock BlockRef
	ProvenAt        BlockRef
	CodeHash        common.Hash
	// BeforeVerified: the parent-state half was proven (the slot was 0 at the settlement block's parent).
	BeforeVerified    bool
	BeforeUnavailable *ReplayBeforeUnavailable
	Named             *ReplayNamedState
	Established       []string
}

func hexNodeList(in []hexutil.Bytes) [][]byte {
	out := make([][]byte, len(in))
	for i, n := range in {
		out[i] = n
	}
	return out
}

func decodeReplayHeader(raw []byte, what string) (*types.Header, error) {
	var h types.Header
	if err := rlp.DecodeBytes(raw, &h); err != nil {
		return nil, unproven(ReasonProofDoesNotVerify, "%s does not decode: %v", what, err)
	}
	if h.Number == nil {
		return nil, unproven(ReasonProofDoesNotVerify, "%s has no number", what)
	}
	return &h, nil
}

// Verify is VerifyAgainst over the facts of a settlement s proves.
func (p *ReplayGuardProof) Verify(s *Settlement) (*ReplayGuardCheck, error) {
	if s == nil {
		return nil, unproven(ReasonSettlementUnproven, "no settlement to hold the proof to")
	}
	header, receipt, err := s.Verify()
	if err != nil {
		return nil, unproven(ReasonSettlementUnproven, "the settlement does not verify: %v", err)
	}
	if s.Tx == nil {
		return nil, unproven(ReasonSettlementUnproven, "no transaction proof")
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(s.Tx.LeafValue); err != nil {
		return nil, unproven(ReasonSettlementUnproven, "the proven transaction does not decode: %v", err)
	}
	return p.VerifyAgainst(header, &tx, receipt.Succeeded(), receipt.Logs)
}

// VerifyAgainst verifies the proof against a settlement already proven in its block: header is the settlement block's
// header, tx its proven transaction, success and logs its proven receipt's status and logs.
//
//  1. the contract is the transaction's target, and the logs' emitter of LeafConsumed (S5); the calldata is a settlement
//     call of the pinned generation, whose layout puts the guard at the declared base;
//  2. the key is topics[2] of that LeafConsumed, and the slot is recomputed from it - never read from the proof;
//  3. the header chain from the settlement block to ProvenAt links by parentHash, within MaxReplayHeaderChain;
//  4. After proves, at ProvenAt's state root, the slot is 1;
//  5. Before, when carried, proves at the parent's state root (the header the settlement block names) the slot is 0; when
//     not carried, the disclosure must be.
func (p *ReplayGuardProof) VerifyAgainst(header *types.Header, tx *types.Transaction, success bool, logs []*types.Log) (*ReplayGuardCheck, error) {
	if p == nil {
		return nil, unproven(ReasonEmptyEvidence, "no replay guard proof")
	}
	if p.Version != ReplayGuardDomain {
		return nil, unproven(ReasonVersion, "version %q is not %s", p.Version, ReplayGuardDomain)
	}
	if header == nil || header.Number == nil || tx == nil {
		return nil, unproven(ReasonSettlementUnproven, "no settlement header or transaction")
	}
	if !success {
		return nil, unproven(ReasonSettlementNotExecuted, "the proven receipt is not status 1: no consumption happened")
	}
	nBlock := BlockRef{Number: header.Number.Uint64(), Hash: header.Hash()}
	if p.SettlementBlock != nBlock {
		return nil, unproven(ReasonBlockMismatch, "the proof is about block %d (%s), the settlement is in block %d (%s)",
			p.SettlementBlock.Number, p.SettlementBlock.Hash.Hex(), nBlock.Number, nBlock.Hash.Hex())
	}

	// (1) the target and the pinned generation.
	layout, ok := replayLayouts[p.Generation]
	if !ok {
		return nil, unproven(ReasonAccountGeneration, "generation %q has no pinned replay-guard layout", p.Generation)
	}
	if to := tx.To(); to == nil || *to != p.Contract {
		return nil, unproven(ReasonContractMismatch, "the transaction's target is %v, the proof is of contract %s", tx.To(), p.Contract.Hex())
	}
	if id := tx.ChainId(); id != nil && id.Sign() > 0 && (!id.IsInt64() || id.Int64() != p.ChainID) {
		return nil, unproven(ReasonContractMismatch, "the transaction is of chain %s, the proof of chain %d", id, p.ChainID)
	}
	data := tx.Data()
	if len(data) < 4 {
		return nil, unproven(ReasonAccountGeneration, "the transaction carries no settlement call")
	}
	isSettlement := false
	for _, sel := range layout.selectors {
		if bytes.Equal(sel[:], data[:4]) {
			isSettlement = true
		}
	}
	if !isSettlement {
		return nil, unproven(ReasonAccountGeneration, "calldata selector 0x%x is not a %s settlement call", data[:4], p.Generation)
	}

	// (2) the event, and the slot recomputed from it.
	var event *types.Log
	for _, lg := range logs {
		if lg != nil && lg.Address == p.Contract && len(lg.Topics) == 3 && lg.Topics[0] == LeafConsumedTopic && lg.Topics[2] == p.Slot.Key {
			event = lg
			break
		}
	}
	if event == nil {
		for _, lg := range logs {
			if lg != nil && lg.Address == p.Contract && len(lg.Topics) == 3 && lg.Topics[0] == LeafConsumedTopic {
				return nil, unproven(ReasonSlotMismatch, "the key %s is not the leaf %s that %s's LeafConsumed in this receipt names",
					p.Slot.Key.Hex(), lg.Topics[2].Hex(), p.Contract.Hex())
			}
		}
		return nil, replayRefusal(ReplayEventMissing, ReasonNoEvent, "the status-1 receipt of a call to %s holds no LeafConsumed it emitted", p.Contract.Hex())
	}
	if p.Slot.Base != layout.base || p.Slot.Derivation != ReplayDerivation {
		return nil, unproven(ReasonSlotMismatch, "base %d (%q) is not %s's pinned base %d (%q)", p.Slot.Base, p.Slot.Derivation,
			p.Generation, layout.base, ReplayDerivation)
	}
	if want := ReplaySlotFor(p.Slot.Key, layout.base); p.Slot.Slot != want {
		return nil, unproven(ReasonSlotMismatch, "slot %s is not keccak256(key || base) = %s", p.Slot.Slot.Hex(), want.Hex())
	}

	// (3) the header chain, settlement block to ProvenAt.
	if len(p.Headers) > MaxReplayHeaderChain {
		return nil, unproven(ReasonHeaderChainTooLong, "%d headers after the settlement block, at most %d", len(p.Headers), MaxReplayHeaderChain)
	}
	at := header
	for i, raw := range p.Headers {
		next, err := decodeReplayHeader(raw, fmt.Sprintf("header %d of the chain", i))
		if err != nil {
			return nil, err
		}
		if next.ParentHash != at.Hash() || next.Number.Uint64() != at.Number.Uint64()+1 {
			return nil, unproven(ReasonHeaderChainBroken, "header %d (block %d, parent %s) does not follow block %d (%s)", i,
				next.Number.Uint64(), next.ParentHash.Hex(), at.Number.Uint64(), at.Hash().Hex())
		}
		at = next
	}
	if got := (BlockRef{Number: at.Number.Uint64(), Hash: at.Hash()}); p.ProvenAt != got {
		return nil, unproven(ReasonHeaderChainBroken, "the chain ends at block %d (%s), the proof says it is proven at block %d (%s)",
			got.Number, got.Hash.Hex(), p.ProvenAt.Number, p.ProvenAt.Hash.Hex())
	}

	// (4) After: the slot is 1 at ProvenAt.
	afterRes, err := p.After.verify(at.Root, p.Contract, p.Slot.Slot)
	if err != nil {
		return nil, unproven(ReasonProofDoesNotVerify, "After at block %d: %v", at.Number.Uint64(), err)
	}
	if !afterRes.Account.HasCode() {
		return nil, unproven(ReasonContractMismatch, "%s holds no code at block %d", p.Contract.Hex(), at.Number.Uint64())
	}
	switch afterRes.Value {
	case common.BigToHash(big.NewInt(1)):
	case (common.Hash{}):
		return nil, replayRefusal(ReplayRefuted, ReasonSlotUnsetAtBlock, "slot %s of %s is 0 at block %d although the status-1 receipt of block %d holds its LeafConsumed",
			p.Slot.Slot.Hex(), p.Contract.Hex(), at.Number.Uint64(), nBlock.Number)
	default:
		return nil, unproven(ReasonProofDoesNotVerify, "After proves %s, not the bool true of a consumed leaf", afterRes.Value.Hex())
	}

	check := &ReplayGuardCheck{State: ReplayProven, ChainID: p.ChainID, Contract: p.Contract, Generation: p.Generation, Slot: p.Slot,
		SettlementBlock: nBlock, ProvenAt: p.ProvenAt, CodeHash: afterRes.Account.CodeHash}
	check.Established = append(check.Established, fmt.Sprintf("S6: %s's replay-guard slot %s (%s _consumedLeaf[leaf], leaf %s from this receipt's LeafConsumed) is 1 in the state of block %d (%s), %d block(s) after the settlement block %d, the chain of headers linked by parentHash",
		p.Contract.Hex(), p.Slot.Slot.Hex(), p.Generation, p.Slot.Key.Hex(), p.ProvenAt.Number, p.ProvenAt.Hash.Hex(), len(p.Headers), nBlock.Number))

	// (5) Before, or its disclosure.
	switch {
	case p.Before != nil && p.BeforeUnavailable != nil:
		return nil, unproven(ReasonBeforeUndisclosed, "both a Before proof and a disclosure that it is unavailable are carried")
	case p.Before != nil:
		parent, err := decodeReplayHeader(p.Before.ParentHeader, "the parent header")
		if err != nil {
			return nil, unproven(ReasonParentHeaderUnproven, "%v", err)
		}
		if parent.Hash() != header.ParentHash || parent.Number.Uint64()+1 != nBlock.Number {
			return nil, unproven(ReasonParentHeaderUnproven, "the parent header is block %d (%s), the settlement block names its parent %s",
				parent.Number.Uint64(), parent.Hash().Hex(), header.ParentHash.Hex())
		}
		beforeRes, err := p.Before.Proof.verify(parent.Root, p.Contract, p.Slot.Slot)
		if err != nil {
			return nil, unproven(ReasonProofDoesNotVerify, "Before at block %d: %v", parent.Number.Uint64(), err)
		}
		if beforeRes.Account.Exists && beforeRes.Account.CodeHash != afterRes.Account.CodeHash {
			return nil, unproven(ReasonContractMismatch, "the code of %s changed between block %d and block %d", p.Contract.Hex(), parent.Number.Uint64(), at.Number.Uint64())
		}
		switch beforeRes.Value {
		case common.Hash{}:
		case common.BigToHash(big.NewInt(1)):
			return nil, replayRefusal(ReplayRefuted, ReasonSlotSetAtParent, "slot %s of %s is already 1 at block %d, the parent of the settlement block %d: this transaction cannot have consumed it",
				p.Slot.Slot.Hex(), p.Contract.Hex(), parent.Number.Uint64(), nBlock.Number)
		default:
			return nil, unproven(ReasonProofDoesNotVerify, "Before proves %s, not the bool false of an unconsumed leaf", beforeRes.Value.Hex())
		}
		check.BeforeVerified = true
		check.Established = append(check.Established, fmt.Sprintf("S6: the same slot is 0 in the state of block %d (%s), the settlement block's parent: the transition happened in block %d",
			parent.Number.Uint64(), parent.Hash().Hex(), nBlock.Number))
	case p.BeforeUnavailable != nil:
		if p.BeforeUnavailable.Reason == "" {
			return nil, unproven(ReasonBeforeUndisclosed, "the disclosure that Before is unavailable gives no reason")
		}
		check.BeforeUnavailable = p.BeforeUnavailable
	default:
		return nil, unproven(ReasonBeforeUndisclosed, "the parent-state half is neither proven nor disclosed as unavailable")
	}
	return check, nil
}

// verify checks the slot proof at stateRoot for account and slot and that what the proof declares is what it proves.
func (sp *SlotProof) verify(stateRoot common.Hash, account common.Address, slot common.Hash) (*StorageResult, error) {
	res, err := VerifyStorage(stateRoot, account, hexNodeList(sp.AccountProof), slot, hexNodeList(sp.StorageProof))
	if err != nil {
		return nil, err
	}
	if res.Account.Exists == sp.AccountAbsent {
		return nil, storageInvalid("the proof declares the account absent=%v and proves it present=%v", sp.AccountAbsent, res.Account.Exists)
	}
	if res.Account.Exists && (res.Account.StorageRoot != sp.StorageHash || res.Account.CodeHash != sp.CodeHash) {
		return nil, storageInvalid("the declared storage hash %s / code hash %s are not the account's %s / %s", sp.StorageHash.Hex(),
			sp.CodeHash.Hex(), res.Account.StorageRoot.Hex(), res.Account.CodeHash.Hex())
	}
	if res.Value != sp.Value {
		return nil, storageInvalid("the declared value %s is not the proven %s", sp.Value.Hex(), res.Value.Hex())
	}
	return res, nil
}

// Verify verifies the evidence against the settlement s proves: see VerifyAgainst.
func (e *ReplayGuardEvidence) Verify(s *Settlement) (*ReplayGuardCheck, error) {
	if s == nil {
		return nil, unproven(ReasonSettlementUnproven, "no settlement to hold the evidence to")
	}
	header, receipt, err := s.Verify()
	if err != nil {
		return nil, unproven(ReasonSettlementUnproven, "the settlement does not verify: %v", err)
	}
	if s.Tx == nil {
		return nil, unproven(ReasonSettlementUnproven, "no transaction proof")
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(s.Tx.LeafValue); err != nil {
		return nil, unproven(ReasonSettlementUnproven, "the proven transaction does not decode: %v", err)
	}
	return e.VerifyAgainst(header, &tx, receipt.Succeeded(), receipt.Logs)
}

// VerifyAgainst verifies the evidence against a settlement already proven in its block: a proof as
// ReplayGuardProof.VerifyAgainst; a named state is checked to be about this transaction and block and is reported as the
// state it names (not a failure: it says what could not be established, where).
func (e *ReplayGuardEvidence) VerifyAgainst(header *types.Header, tx *types.Transaction, success bool, logs []*types.Log) (*ReplayGuardCheck, error) {
	if e == nil || (e.Proof == nil) == (e.State == nil) {
		return nil, unproven(ReasonEmptyEvidence, "the evidence carries exactly one of a proof and a named state")
	}
	if e.Version != ReplayGuardDomain {
		return nil, unproven(ReasonVersion, "version %q is not %s", e.Version, ReplayGuardDomain)
	}
	if e.Proof != nil {
		return e.Proof.VerifyAgainst(header, tx, success, logs)
	}
	st := e.State
	if st.State != ReplayUnproven && st.State != ReplayEventMissing && st.State != ReplayRefuted {
		return nil, unproven(ReasonEmptyEvidence, "%q is not a named state of the replay guard", st.State)
	}
	if st.Reason == "" {
		return nil, unproven(ReasonEmptyEvidence, "a named state carries its reason")
	}
	if header == nil || header.Number == nil || tx == nil {
		return nil, unproven(ReasonSettlementUnproven, "no settlement header or transaction to hold the named state to")
	}
	if st.TxHash != tx.Hash() || st.BlockHash != header.Hash() || st.BlockNumber != header.Number.Uint64() {
		return nil, unproven(ReasonBlockMismatch, "the named state is about tx %s in block %d (%s), the settlement is %s in block %d (%s)",
			st.TxHash.Hex(), st.BlockNumber, st.BlockHash.Hex(), tx.Hash().Hex(), header.Number.Uint64(), header.Hash().Hex())
	}
	return &ReplayGuardCheck{State: st.State, Reason: st.Reason, ChainID: st.ChainID, Contract: st.Contract,
		SettlementBlock: BlockRef{Number: st.BlockNumber, Hash: st.BlockHash}, Named: st}, nil
}
