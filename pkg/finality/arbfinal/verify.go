// Copyright 2026 Certen Protocol

package arbfinal

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Kind is the verifier of arb-sepolia/finalized/v1 (spec 5.7). It is pure: no I/O, no clock, no randomness.
type Kind struct{}

// New returns the verifier.
func New() *Kind { return &Kind{} }

var _ finality.Kind = (*Kind)(nil)

// Name, Chain and Level implement finality.Kind.
func (*Kind) Name() string          { return KindName }
func (*Kind) Chain() uint64         { return finality.ChainArbitrumSepolia }
func (*Kind) Level() finality.Level { return finality.LevelFinalized }

// Register adds the verifier of arb-sepolia/finalized/v1 to a registry. There is no init(): the process (or a test) calls it
// explicitly, and a second registration of the kind is refused by the registry.
func Register(reg *finality.Registry) error { return reg.RegisterKind(New()) }

func boundsFor(l1p ethl1.Pins, a *Pins) Bounds {
	return Bounds{Limits: finality.DefaultLimits(), MaxLinks: l1p.MaxLinks, MaxSpineHeaders: l1p.MaxSpineHeaders, MaxHeaderChain: a.MaxHeaderChain}
}

func w32(v uint64) common.Hash {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], v)
	return h
}

// AfterStateHash is keccak256(abi.encode(AssertionState)): six 32-byte words (annex A2).
func AfterStateHash(a AfterState) [32]byte {
	var b []byte
	b = append(b, a.BlockHash[:]...)
	b = append(b, a.SendRoot[:]...)
	b = append(b, w32(a.InboxPosition).Bytes()...)
	b = append(b, w32(a.PositionInMessage).Bytes()...)
	b = append(b, w32(uint64(a.MachineStatus)).Bytes()...)
	b = append(b, a.EndHistoryRoot[:]...)
	return crypto.Keccak256Hash(b)
}

// AssertionHash is keccak256(abi.encodePacked(parentAssertionHash, afterStateHash, sequencerBatchAcc)) (annex A2).
func AssertionHash(parent [32]byte, a AfterState, sequencerBatchAcc [32]byte) [32]byte {
	h := AfterStateHash(a)
	return crypto.Keccak256Hash(parent[:], h[:], sequencerBatchAcc[:])
}

// ConfigHash is keccak256(abi.encodePacked(wasmModuleRoot, requiredStake, challengeManager, confirmPeriodBlocks,
// nextInboxPosition)) (annex A2): 32 + 32 + 20 + 8 + 8 bytes.
func ConfigHash(c ParentConfig) [32]byte {
	var b []byte
	b = append(b, c.WasmModuleRoot[:]...)
	b = append(b, c.RequiredStake[:]...)
	b = append(b, c.ChallengeManager[:]...)
	b = binary.BigEndian.AppendUint64(b, c.ConfirmPeriodBlocks)
	b = binary.BigEndian.AppendUint64(b, c.NextInboxPosition)
	return crypto.Keccak256Hash(b)
}

// NodeSlot is the storage slot of word 0 of the assertion node: keccak256(abi.encode(assertionHash, assertionsSlot)).
func NodeSlot(assertion [32]byte, assertionsSlot uint64) common.Hash {
	return crypto.Keccak256Hash(assertion[:], w32(assertionsSlot).Bytes())
}

// ConfigSlot is the storage slot of the node's configHash word: the node slot plus the layout's offset (1).
func ConfigSlot(assertion [32]byte, assertionsSlot, offset uint64) common.Hash {
	b := new(big.Int).SetBytes(NodeSlot(assertion, assertionsSlot).Bytes())
	b.Add(b, new(big.Int).SetUint64(offset))
	return common.BigToHash(b)
}

// StatusOf is (word >> shift) & 0xff of a node word.
func StatusOf(word common.Hash, shift uint64) uint64 {
	v := new(big.Int).SetBytes(word[:])
	v.Rsh(v, uint(shift))
	return v.Uint64() & 0xff
}

// Verify judges the whole CFE1 container of one leg block (spec 5.7). The order of the checks is the order of annex "Offline
// verification algorithm / finalized" with the r2 additions: pins and pre-BoLD, L1 finality (head, spine, S and K on it),
// the logic identity under S and under K, the assertion under S, the L2 spine, the confirmation path under K.
func (k *Kind) Verify(p *finality.Pins, b finality.BlockRef, evidence []byte) (finality.Verdict, error) {
	c, err := finality.DecodeContainer(evidence, finality.DefaultLimits())
	if err != nil {
		return finality.Verdict{}, err
	}
	if c.Header.Kind != KindName {
		return finality.Verdict{}, finality.EvidenceUnrecognised(c.Header.Kind, "")
	}
	if c.Header.Chain != finality.ChainArbitrumSepolia {
		return finality.Verdict{}, PinMismatch("chain_id")
	}
	if c.Header.Level != finality.LevelFinalized {
		return finality.Verdict{}, finality.Malformed("header.level", finality.ReasonLevelNotFinalized, int(c.Header.Level), 3)
	}
	if c.Header.BlockNumber != b.Number {
		return finality.Verdict{}, finality.BlockMismatch("blockNumber", b.Number, c.Header.BlockNumber)
	}
	if c.Header.BlockHash != b.Hash {
		return finality.Verdict{}, finality.BlockMismatch("blockHash", b.Hash, c.Header.BlockHash)
	}
	arb, err := LoadPins(p)
	if err != nil {
		return finality.Verdict{}, err
	}
	l1p, err := ethl1Pins(p)
	if err != nil {
		return finality.Verdict{}, err
	}
	e, err := Decode(c.Body, boundsFor(l1p, arb))
	if err != nil {
		return finality.Verdict{}, err
	}
	hdr, err := finality.ReadHeader(b.HeaderRLP)
	if err != nil {
		return finality.Verdict{}, err
	}
	if hdr.Hash != b.Hash {
		return finality.Verdict{}, finality.BlockMismatch("settlementHeaderHash", b.Hash, hdr.Hash)
	}
	if hdr.Number != b.Number {
		return finality.Verdict{}, finality.BlockMismatch("settlementHeaderNumber", b.Number, hdr.Number)
	}
	if hdr.Number <= arb.BoldGenesisL2Block {
		return finality.Verdict{}, finality.NewState(CodePreBold, "n", hdr.Number, "bold_genesis_l2_block", arb.BoldGenesisL2Block)
	}
	// 5.2 / 5.7 O1: the L1 finalized head, S and K on the covered spine.
	head, err := ethl1.VerifyFinalizedHead(l1p, e.LC)
	if err != nil {
		return finality.Verdict{}, L1FinalityUnproven(L1FinalityLCRefused, innerCode(err))
	}
	covered, err := head.Covers(e.L1Spine, l1p.MaxSpineHeaders)
	if err != nil {
		return finality.Verdict{}, L1FinalityUnproven(L1FinalitySpineRefused, innerCode(err))
	}
	s, err := ethl1.BlockAt(covered, e.StateBlock)
	if err != nil {
		return finality.Verdict{}, asState(err)
	}
	kb, err := ethl1.BlockAt(covered, e.ConfBlock)
	if err != nil {
		return finality.Verdict{}, asState(err)
	}
	if kb.Number > s.Number {
		return finality.Verdict{}, finality.BlockMismatch("confBlockAboveStateBlock", e.StateBlock, e.ConfBlock)
	}
	kHeader, found := headerNumbered(e.L1Spine, kb.Number)
	if !found {
		return finality.Verdict{}, asState(ethl1.BlockNotCovered(kb.Number, covered[0].Number))
	}
	return k.verifyState(arb, s, kb, kHeader, b, e)
}

// headerNumbered returns the fields of the spine header with this number. Covers has already read and walked every header of the
// spine and BlockAt found the number on it, so the header is there; found is false only for a caller whose spine lacks it.
func headerNumbered(spine [][]byte, number uint64) (finality.HeaderFields, bool) {
	for _, raw := range spine {
		h, err := finality.ReadHeader(raw)
		if err != nil {
			continue
		}
		if h.Number == number {
			return h, true
		}
	}
	return finality.HeaderFields{}, false
}

// verifyState is the part of the judgement that runs under the state roots of the covered L1 blocks S and K; it is separate
// so that tests can hand it a state built in memory.
func (k *Kind) verifyState(arb *Pins, s, kb ethl1.L1Block, kHeader finality.HeaderFields, b finality.BlockRef, e Evidence) (finality.Verdict, error) {
	// 5.7 O2: logic identity under stateRoot_S and also under stateRoot_K (r2 C1).
	acctS, err := identityAt(arb, s, e.Nodes)
	if err != nil {
		return finality.Verdict{}, err
	}
	var acctK *ethproof.AccountState
	if kb.Number == s.Number {
		acctK = acctS
	} else if acctK, err = identityAt(arb, kb, e.Nodes); err != nil {
		return finality.Verdict{}, err
	}
	// 5.7 O3: the assertion under S.
	if e.After.MachineStatus != 1 {
		return finality.Verdict{}, finality.NewState(CodeMachineNotFinished, "machine_status", e.After.MachineStatus)
	}
	assertion := AssertionHash(e.ParentAssertionHash, e.After, e.SequencerBatchAcc)
	word, err := ethproof.VerifySlot(acctS.StorageRoot, NodeSlot(assertion, arb.Layout.AssertionsSlot), e.Nodes)
	if err != nil {
		return finality.Verdict{}, StateProofInvalid("slot")
	}
	switch status := StatusOf(word, arb.Layout.StatusShiftBits); status {
	case 2:
	case 0:
		return finality.Verdict{}, finality.NewState(CodeAssertionUnknown)
	default:
		return finality.Verdict{}, finality.NewState(CodeNotConfirmed, "status", status)
	}
	cfgWord, err := ethproof.VerifySlot(acctS.StorageRoot, ConfigSlot(e.ParentAssertionHash, arb.Layout.AssertionsSlot, arb.Layout.ConfigSlotOffset), e.Nodes)
	if err != nil {
		return finality.Verdict{}, StateProofInvalid("slot")
	}
	if ConfigHash(e.Parent) != [32]byte(cfgWord) {
		return finality.Verdict{}, PreimageMismatch(PreimageParentConfig)
	}
	// 5.7 O3 / O3b: the L2 spine from the assertion's block down to the leg, ending byte-identical at Settlement.Header.
	m, err := verifyL2Spine(e, b)
	if err != nil {
		return finality.Verdict{}, err
	}
	// 5.7 O4: the confirmation path under K.
	conf, err := classifyConfirmation(arb, kb, kHeader, acctK, assertion, e)
	if err != nil {
		return finality.Verdict{}, err
	}
	fields := map[string]any{
		"assertion":             assertion,
		"m":                     m,
		"s_number":              s.Number,
		"s_hash":                s.Hash,
		"k_number":              kb.Number,
		"k_hash":                kb.Hash,
		"confirm_period_blocks": e.Parent.ConfirmPeriodBlocks,
		"confirmation_path":     "honest",
		"confirmation_route":    conf.Route,
		"confirmation_tx":       conf.TxHash,
	}
	return finality.Verdict{Level: finality.LevelFinalized, Kind: KindName, Fields: fields}, nil
}

// identityAt is O2 for one covered L1 block X: the Rollup account is proven under stateRoot_X, both EIP-1967 slots (admin
// logic, secondary user logic) are read from its storage and both logic accounts are proven under stateRoot_X; each code hash
// must be pinned with its role, else contract_identity_unproven{role, address, code_hash, judged_at = X}.
func identityAt(arb *Pins, x ethl1.L1Block, nodes [][]byte) (*ethproof.AccountState, error) {
	root := common.Hash(x.StateRoot)
	acct, err := ethproof.VerifyAccount(root, arb.Rollup, nodes)
	if err != nil {
		return nil, StateProofInvalid("account")
	}
	if !acct.Exists {
		return nil, ContractIdentity(roleRollup, arb.Rollup[:], make([]byte, 32), x.Number)
	}
	for _, r := range []struct {
		slot common.Hash
		role string
	}{{arb.AdminSlot, RoleAdminLogic}, {arb.UserSlot, RoleUserLogic}} {
		word, err := ethproof.VerifySlot(acct.StorageRoot, r.slot, nodes)
		if err != nil {
			return nil, StateProofInvalid("slot")
		}
		impl := common.BytesToAddress(word[12:])
		logic, err := ethproof.VerifyAccount(root, impl, nodes)
		if err != nil {
			return nil, StateProofInvalid("account")
		}
		codeHash := logic.CodeHash
		if !logic.Exists {
			codeHash = common.Hash{}
		}
		if !bytes.Equal(word[:12], make([]byte, 12)) || !logic.Exists || arb.roleOf(codeHash) != r.role {
			return nil, ContractIdentity(r.role, impl[:], codeHash[:], x.Number)
		}
	}
	return acct, nil
}

// verifyL2Spine is the §0 spine rule for the L2 chain: keccak256(h_0) = afterState.blockHash, each further header is the
// parent of the one before it (hash and number), and h_k is byte-identical to Settlement.Header. It returns m = number(h_0).
func verifyL2Spine(e Evidence, leg finality.BlockRef) (uint64, error) {
	if len(e.L2Spine) == 0 {
		return 0, finality.Malformed("l2Spine", finality.ReasonSpineEmpty, 0, 1)
	}
	var prev finality.HeaderFields
	var m uint64
	for i, raw := range e.L2Spine {
		h, err := finality.ReadHeader(raw)
		if err != nil {
			return 0, err
		}
		if i == 0 {
			if h.Hash != e.After.BlockHash {
				return 0, HeaderChainBroken(h.Number, e.After.BlockHash, h.Hash, ReasonParentHash)
			}
			m = h.Number
		} else {
			if h.Hash != prev.ParentHash {
				return 0, HeaderChainBroken(prev.Number-1, prev.ParentHash, h.Hash, ReasonParentHash)
			}
			if h.Number+blockStep != prev.Number {
				return 0, HeaderChainBroken(prev.Number-1, prev.ParentHash, h.Hash, ReasonNumberGap)
			}
		}
		prev = h
	}
	last := e.L2Spine[len(e.L2Spine)-1]
	if prev.Number != leg.Number {
		return 0, finality.BlockMismatch("spineLastNumber", leg.Number, prev.Number)
	}
	if prev.Hash != leg.Hash {
		return 0, finality.BlockMismatch("spineLastHash", leg.Hash, prev.Hash)
	}
	if leg.HeaderRLP != nil && !bytes.Equal(last, leg.HeaderRLP) {
		return 0, finality.BlockMismatch("spineLastHeader", crypto.Keccak256Hash(leg.HeaderRLP), crypto.Keccak256Hash(last))
	}
	return m, nil
}
