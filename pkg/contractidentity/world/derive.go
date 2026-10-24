// Copyright 2026 Certen Protocol

package world

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// World is a derived world: everything a verifier reads, plus the roots and hashes it was derived from.
type World struct {
	Spec           *Spec
	Manifest       *ci.Manifest
	Ctx            ci.LegContext
	Container      *ci.Container
	ContainerBytes []byte
	StateRoots     map[string]common.Hash // by station
	BlockHashes    map[string]common.Hash // by block name: attest_parent, attest, between.<i>, settle
	HeaderRLP      map[string][]byte
	d              *derived
	// Planned is the number of nodes the read plan collected (= len(Container.Nodes)).
	Planned int
	// PlanErr is the first read the build pass could not make (a hostile world: the capture carried what it could reach). CheckErr is the
	// first failure of the strict re-read of the container nodes by the contractidentity reads, including nodes no read visited (step 22b).
	// Both are nil for H0 and every semantic mutation that leaves the evidence consistent.
	PlanErr, CheckErr error
}

type builtAcct struct {
	spec     *AcctSpec
	nonce    uint64
	balance  *big.Int
	code     []byte
	codeHash common.Hash
	storage  map[common.Hash]common.Hash
	sto      *trie.Trie
	root     common.Hash
}

type builtState struct {
	accts map[common.Address]*builtAcct
	tr    *trie.Trie
	root  common.Hash
}

type leafAcct struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash common.Hash
}

type collector struct{ nodes [][]byte }

func (c *collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collector) Delete([]byte) error { return nil }

func trimmedRLP(v common.Hash) []byte {
	enc, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(v[:]))
	return enc
}

func resolveCode(m *ci.Manifest, cs *CodeSpec) (code []byte, hash common.Hash, err error) {
	switch {
	case cs == nil:
		return nil, types.EmptyCodeHash, nil
	case cs.Hex != "":
		b, err := parseHex(cs.Hex)
		if err != nil {
			return nil, common.Hash{}, err
		}
		return b, common.BytesToHash(crypto.Keccak256(b)), nil
	case cs.CodeHash != "":
		h, err := parseHash(cs.CodeHash)
		return nil, h, err
	case cs.Build != "":
		b, ok := m.Build(cs.Build)
		if !ok {
			return nil, common.Hash{}, fmt.Errorf("the manifest has no build %s", cs.Build)
		}
		tpl, err := Template(cs.Build)
		if err != nil {
			return nil, common.Hash{}, err
		}
		vals := map[string]common.Hash{}
		for k, v := range cs.Immutables {
			h, err := parseHash(v)
			if err != nil {
				return nil, common.Hash{}, fmt.Errorf("immutable %s: %w", k, err)
			}
			vals[k] = h
		}
		code, err := Fill(tpl, b, vals)
		if err != nil {
			return nil, common.Hash{}, err
		}
		return code, common.BytesToHash(crypto.Keccak256(code)), nil
	}
	return nil, common.Hash{}, errors.New("an empty code spec")
}

func buildState(m *ci.Manifest, accounts map[string]*AcctSpec) (*builtState, error) {
	bs := &builtState{accts: map[common.Address]*builtAcct{}, tr: trie.NewEmpty(nil)}
	keys := make([]string, 0, len(accounts))
	for k := range accounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		as := accounts[k]
		addr, err := parseAddr(k)
		if err != nil {
			return nil, fmt.Errorf("account %q: %w", k, err)
		}
		ba := &builtAcct{spec: as, nonce: as.Nonce, storage: map[common.Hash]common.Hash{}, sto: trie.NewEmpty(nil)}
		if ba.balance, err = parseDec(as.Balance); err != nil {
			return nil, fmt.Errorf("account %s balance: %w", k, err)
		}
		if ba.code, ba.codeHash, err = resolveCode(m, as.Code); err != nil {
			return nil, fmt.Errorf("account %s code: %w", k, err)
		}
		for sk, sv := range as.Storage {
			slot, err := parseHash(sk)
			if err != nil {
				return nil, fmt.Errorf("account %s storage slot: %w", k, err)
			}
			val, err := parseHash(sv)
			if err != nil {
				return nil, fmt.Errorf("account %s storage value: %w", k, err)
			}
			if val == (common.Hash{}) {
				continue // a zero is absent
			}
			ba.storage[slot] = val
			if err := ba.sto.Update(crypto.Keccak256(slot[:]), trimmedRLP(val)); err != nil {
				return nil, err
			}
		}
		ba.root = ba.sto.Hash()
		enc, err := rlp.EncodeToBytes(&leafAcct{Nonce: ba.nonce, Balance: ba.balance, Root: ba.root, CodeHash: ba.codeHash})
		if err != nil {
			return nil, err
		}
		if err := bs.tr.Update(crypto.Keccak256(addr[:]), enc); err != nil {
			return nil, err
		}
		bs.accts[addr] = ba
	}
	bs.root = bs.tr.Hash()
	return bs, nil
}

// ---- transactions, receipts, headers ----

type block struct {
	name     string
	spec     *BlockSpec
	header   *types.Header
	rlp      []byte
	hash     common.Hash
	wires    [][]byte
	receipts [][]byte
	txTrie   *trie.Trie
	rcTrie   *trie.Trie
	txIndex  map[string]int // role -> index
	bloom    types.Bloom
}

func (b *block) listTrie(vals [][]byte) *trie.Trie {
	t := trie.NewEmpty(nil)
	for i, v := range vals {
		k, _ := rlp.EncodeToBytes(uint64(i))
		_ = t.Update(k, v)
	}
	t.Hash()
	return t
}

func signerKey(seed, label string) *ecdsa.PrivateKey {
	k, err := crypto.ToECDSA(seeded(seed, "key", label).Bytes())
	if err != nil {
		panic(err) // keccak output is below the curve order but for a 2^-128 case
	}
	return k
}

type tupGov struct {
	KeyBookURL         string
	KeyBookRoot        [32]byte
	KeyPageProofs      [][32]byte
	AuthorityAddress   common.Address
	AuthorityLevel     uint8
	Nonce              *big.Int
	RequiredSignatures *big.Int
	ProvidedSignatures *big.Int
	ThresholdMet       bool
}
type tupBLS struct {
	AggregateSignature []byte
	ValidatorAddresses []common.Address
	VotingPowers       []*big.Int
	TotalVotingPower   *big.Int
	SignedVotingPower  *big.Int
	ThresholdMet       bool
	MessageHash        [32]byte
}
type tupCommit struct {
	OperationCommitment  [32]byte
	CrossChainCommitment [32]byte
	GovernanceRoot       [32]byte
	ExecutionCommitment  [32]byte
	SourceChain          string
	SourceBlockHeight    *big.Int
	SourceTxHash         [32]byte
	TargetChain          string
	TargetAddress        common.Address
}
type tupProof struct {
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte
	GovernanceProof tupGov
	BlsProof        tupBLS
	Commitments     tupCommit
	ExpirationTime  *big.Int
	Metadata        []byte
}
type tupADI struct {
	AdiURL              string
	AnchorId            [32]byte
	MerkleProof         [][32]byte
	OperationID         [32]byte
	KeyBookProof        []byte
	RoleProof           []byte
	ThresholdProof      []byte
	Timestamp           *big.Int
	ExpiresAt           *big.Int
	ValidatorSignatures []byte
	Nonce               *big.Int
	AuthorityBook       [32]byte
	AuthorityPage       uint64
	NotBefore           uint64
	NotAfter            uint64
}

func am(name, typ string, comps ...abi.ArgumentMarshaling) abi.ArgumentMarshaling {
	return abi.ArgumentMarshaling{Name: name, Type: typ, Components: comps}
}

func proofType() (abi.Type, error) {
	return abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		am("transactionHash", "bytes32"), am("merkleRoot", "bytes32"), am("proofHashes", "bytes32[]"), am("leafHash", "bytes32"),
		am("governanceProof", "tuple", am("keyBookURL", "string"), am("keyBookRoot", "bytes32"), am("keyPageProofs", "bytes32[]"), am("authorityAddress", "address"),
			am("authorityLevel", "uint8"), am("nonce", "uint256"), am("requiredSignatures", "uint256"), am("providedSignatures", "uint256"), am("thresholdMet", "bool")),
		am("blsProof", "tuple", am("aggregateSignature", "bytes"), am("validatorAddresses", "address[]"), am("votingPowers", "uint256[]"),
			am("totalVotingPower", "uint256"), am("signedVotingPower", "uint256"), am("thresholdMet", "bool"), am("messageHash", "bytes32")),
		am("commitments", "tuple", am("operationCommitment", "bytes32"), am("crossChainCommitment", "bytes32"), am("governanceRoot", "bytes32"), am("executionCommitment", "bytes32"),
			am("sourceChain", "string"), am("sourceBlockHeight", "uint256"), am("sourceTxHash", "bytes32"), am("targetChain", "string"), am("targetAddress", "address")),
		am("expirationTime", "uint256"), am("metadata", "bytes"),
	})
}

func adiType() (abi.Type, error) {
	return abi.NewType("tuple", "", []abi.ArgumentMarshaling{am("adiURL", "string"), am("anchorId", "bytes32"), am("merkleProof", "bytes32[]"), am("operationID", "bytes32"),
		am("keyBookProof", "bytes"), am("roleProof", "bytes"), am("thresholdProof", "bytes"), am("timestamp", "uint256"), am("expiresAt", "uint256"),
		am("validatorSignatures", "bytes"), am("nonce", "uint256"), am("authorityBook", "bytes32"), am("authorityPage", "uint64"), am("notBefore", "uint64"), am("notAfter", "uint64")})
}

func h32(s string) ([32]byte, error) {
	h, err := parseHash(s)
	return [32]byte(h), err
}

// attestCalldata is executeComprehensiveProof(anchorId, proof) from the Attestation spec.
func attestCalldata(sp *Spec) ([]byte, error) {
	at := sp.Attestation
	var pr tupProof
	var err error
	anchor, err := h32(at.AnchorID)
	if err != nil {
		return nil, err
	}
	pr.TransactionHash, _ = h32(at.TransactionHash)
	pr.MerkleRoot, _ = h32(at.MerkleRoot)
	pr.LeafHash, _ = h32(at.LeafHash)
	seed := sp.Seed
	pr.ProofHashes = [][32]byte{seeded(seed, "ph", 0), seeded(seed, "ph", 1)}
	pr.GovernanceProof = tupGov{KeyBookURL: sp.Context.ADIURL + "/book", KeyBookRoot: seeded(seed, "kbroot"), KeyPageProofs: [][32]byte{seeded(seed, "kp", 0)},
		AuthorityAddress: common.HexToAddress(sp.Roles.Owner), AuthorityLevel: at.AuthorityLevel, Nonce: big.NewInt(1), RequiredSignatures: big.NewInt(2),
		ProvidedSignatures: big.NewInt(3), ThresholdMet: true}
	var blob []byte
	for _, w := range at.Blob {
		b, err := parseHex(w)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("blob word %q", w)
		}
		blob = append(blob, b...)
	}
	pr.BlsProof = tupBLS{AggregateSignature: blob, TotalVotingPower: new(big.Int).SetUint64(at.OuterTotal), SignedVotingPower: new(big.Int).SetUint64(at.OuterSigned), ThresholdMet: true}
	pr.BlsProof.MessageHash, _ = h32(at.MessageHash)
	for i, v := range at.Validators {
		a, err := parseAddr(v)
		if err != nil {
			return nil, err
		}
		pr.BlsProof.ValidatorAddresses = append(pr.BlsProof.ValidatorAddresses, a)
		pr.BlsProof.VotingPowers = append(pr.BlsProof.VotingPowers, new(big.Int).SetUint64(at.Powers[i]))
	}
	pr.Commitments = tupCommit{SourceChain: "accumulate", SourceBlockHeight: big.NewInt(7_000_000), TargetChain: "ethereum-sepolia", TargetAddress: common.HexToAddress(sp.Roles.Account)}
	pr.Commitments.OperationCommitment, _ = h32(at.OperationCommitment)
	pr.Commitments.ExecutionCommitment, _ = h32(at.ExecutionCommitment)
	pr.Commitments.CrossChainCommitment = seeded(seed, "crosschain")
	pr.Commitments.GovernanceRoot = seeded(seed, "govroot")
	pr.Commitments.SourceTxHash = seeded(seed, "srctx")
	pr.ExpirationTime, pr.Metadata = big.NewInt(2_000_000_000), []byte("certen")
	pt, err := proofType()
	if err != nil {
		return nil, err
	}
	b32, _ := abi.NewType("bytes32", "", nil)
	enc, err := abi.Arguments{{Type: b32}, {Type: pt}}.Pack(anchor, pr)
	if err != nil {
		return nil, err
	}
	sel := ci.Selector4(ci.SigExecuteComprehensiveProof)
	return append(sel[:], enc...), nil
}

// settleCalldata is the account's executeGovernanceProofDirect / batchExecuteGovernanceProofDirect call from the Settlement spec.
func settleCalldata(sp *Spec) ([]byte, error) {
	st := sp.Settlement
	var p tupADI
	var err error
	p.AdiURL = sp.Context.ADIURL
	p.AnchorId, _ = h32(st.AnchorID)
	p.OperationID, _ = h32(st.OperationID)
	p.AuthorityBook, _ = h32(st.AuthorityBook)
	p.MerkleProof = [][32]byte{seeded(sp.Seed, "mp", 0), seeded(sp.Seed, "mp", 1)}
	p.KeyBookProof, p.RoleProof, p.ThresholdProof = []byte("kbp"), []byte{}, bytes.Repeat([]byte{9}, 40)
	p.Timestamp, p.ExpiresAt, p.Nonce = big.NewInt(1_790_000_000), big.NewInt(2_000_000_000), big.NewInt(1)
	p.ValidatorSignatures = bytes.Repeat([]byte{7}, 65)
	p.AuthorityPage, p.NotBefore, p.NotAfter = st.AuthorityPage, 1_790_000_000, 2_000_000_000
	at, err := adiType()
	if err != nil {
		return nil, err
	}
	var targets []common.Address
	var values []*big.Int
	var datas [][]byte
	for _, l := range st.Legs {
		a, err := parseAddr(l.Target)
		if err != nil {
			return nil, err
		}
		v, err := parseDec(l.Value)
		if err != nil {
			return nil, err
		}
		d, err := parseHex(l.Data)
		if err != nil {
			return nil, err
		}
		targets, values, datas = append(targets, a), append(values, v), append(datas, d)
	}
	ty := func(s string) abi.Type { t, _ := abi.NewType(s, "", nil); return t }
	if !st.Batch {
		if len(targets) != 1 {
			return nil, fmt.Errorf("a single-leg settlement needs exactly one leg, has %d", len(targets))
		}
		enc, err := abi.Arguments{{Type: ty("address")}, {Type: ty("uint256")}, {Type: ty("bytes")}, {Type: at}}.Pack(targets[0], values[0], datas[0], p)
		if err != nil {
			return nil, err
		}
		sel := ci.Selector4(ci.SigExecuteGovernanceDirect)
		return append(sel[:], enc...), nil
	}
	enc, err := abi.Arguments{{Type: ty("address[]")}, {Type: ty("uint256[]")}, {Type: ty("bytes[]")}, {Type: at}}.Pack(targets, values, datas, p)
	if err != nil {
		return nil, err
	}
	sel := ci.Selector4(ci.SigBatchGovernanceDirect)
	return append(sel[:], enc...), nil
}

func logsOf(ls []LogSpec) ([]*types.Log, error) {
	var out []*types.Log
	for _, l := range ls {
		a, err := parseAddr(l.Address)
		if err != nil {
			return nil, err
		}
		lg := &types.Log{Address: a}
		for _, t := range l.Topics {
			h, err := parseHash(t)
			if err != nil {
				return nil, err
			}
			lg.Topics = append(lg.Topics, h)
		}
		if lg.Data, err = parseHex(l.Data); err != nil {
			return nil, err
		}
		out = append(out, lg)
	}
	return out, nil
}

// buildTx returns the wire encoding of one transaction and its logs.
func buildTx(sp *Spec, chain uint64, blk *block, i int, t TxSpec) (wire []byte, logs []*types.Log, err error) {
	if t.Wire != "" {
		wire, err = parseHex(t.Wire)
	}
	switch t.Role {
	case "attestation", "settlement":
		var data []byte
		var to common.Address
		var key *ecdsa.PrivateKey
		if t.Role == "attestation" {
			data, err = attestCalldata(sp)
			to, _ = parseAddr(sp.Roles.Anchor)
			key = signerKey(sp.Seed, "validator")
			if err == nil {
				logs, err = logsOf(sp.Attestation.Logs)
			}
		} else {
			data, err = settleCalldata(sp)
			to, _ = parseAddr(sp.Roles.Account)
			key = signerKey(sp.Seed, "relayer")
			if err == nil {
				logs, err = logsOf(sp.Settlement.Logs)
			}
		}
		if err != nil {
			return nil, nil, err
		}
		if t.Wire == "" {
			tx, err := types.SignNewTx(key, types.LatestSignerForChainID(new(big.Int).SetUint64(chain)), &types.DynamicFeeTx{ChainID: new(big.Int).SetUint64(chain),
				Nonce: uint64(7 + i), GasTipCap: big.NewInt(1_000_000_000), GasFeeCap: big.NewInt(30_000_000_000), Gas: 3_000_000, To: &to, Value: big.NewInt(0), Data: data})
			if err != nil {
				return nil, nil, err
			}
			wire, err = tx.MarshalBinary()
			if err != nil {
				return nil, nil, err
			}
		}
		return wire, logs, nil
	}
	if t.Wire != "" {
		return wire, nil, err
	}
	// a filler of type t.Type
	to := common.BytesToAddress(seeded(sp.Seed, "to", t.Seed).Bytes()[12:])
	cid := new(big.Int).SetUint64(chain)
	key := signerKey(sp.Seed, "filler")
	switch t.Type {
	case 0, 1, 2:
		var inner types.TxData
		switch t.Type {
		case 0:
			inner = &types.LegacyTx{Nonce: t.Seed, GasPrice: big.NewInt(2_000_000_000), Gas: 21000, To: &to, Value: new(big.Int).SetUint64(t.Seed + 1)}
		case 1:
			inner = &types.AccessListTx{ChainID: cid, Nonce: t.Seed, GasPrice: big.NewInt(2_000_000_000), Gas: 30000, To: &to, Value: big.NewInt(1)}
		default:
			inner = &types.DynamicFeeTx{ChainID: cid, Nonce: t.Seed, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(3_000_000_000), Gas: 50000, To: &to, Value: big.NewInt(1), Data: []byte{byte(t.Seed)}}
		}
		tx, err := types.SignNewTx(key, types.LatestSignerForChainID(cid), inner)
		if err != nil {
			return nil, nil, err
		}
		wire, err = tx.MarshalBinary()
		return wire, nil, err
	case 3, 4:
		body, err := rlp.EncodeToBytes([]any{cid, t.Seed, to.Bytes(), []byte{byte(t.Seed)}})
		return append([]byte{t.Type}, body...), nil, err
	}
	// an L2 or unknown type: an opaque payload, not necessarily RLP
	return append([]byte{t.Type}, byte(t.Seed), byte(t.Seed>>8), 0x99), nil, nil
}

func receiptWire(t TxSpec, wire []byte, logs []*types.Log, cum uint64) ([]byte, error) {
	if t.Receipt != "" {
		return parseHex(t.Receipt)
	}
	ty := uint8(0)
	if len(wire) > 0 && wire[0] < 0x80 {
		ty = wire[0]
	}
	r := &types.Receipt{Type: ty, Status: types.ReceiptStatusSuccessful, CumulativeGasUsed: cum, Logs: logs}
	r.Bloom = types.CreateBloom(r)
	return r.MarshalBinary()
}

func (b *block) buildTxs(sp *Spec, chain uint64) error {
	var cum uint64
	var allLogs []*types.Log
	for i, t := range b.spec.Txs {
		wire, logs, err := buildTx(sp, chain, b, i, t)
		if err != nil {
			return fmt.Errorf("%s tx %d: %w", b.name, i, err)
		}
		cum += 50_000
		rc, err := receiptWire(t, wire, logs, cum)
		if err != nil {
			return fmt.Errorf("%s receipt %d: %w", b.name, i, err)
		}
		allLogs = append(allLogs, logs...)
		b.wires, b.receipts = append(b.wires, wire), append(b.receipts, rc)
		if t.Role != "" {
			b.txIndex[t.Role] = i
		}
	}
	b.txTrie, b.rcTrie = b.listTrie(b.wires), b.listTrie(b.receipts)
	b.bloom = types.CreateBloom(&types.Receipt{Logs: allLogs})
	return nil
}

func uintField(fields map[string]string, key string, def uint64) (uint64, error) {
	s, ok := fields[key]
	if !ok {
		return def, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func (b *block) buildHeader(sp *Spec, parent common.Hash, adjacent bool, stateRoot common.Hash) error {
	f := b.spec.Fields
	num := b.spec.Number
	ph := parent
	if !adjacent {
		ph = seeded(sp.Seed, "parent", num)
	}
	h := &types.Header{
		ParentHash: ph, UncleHash: types.EmptyUncleHash, Coinbase: common.BytesToAddress(seeded(sp.Seed, "coinbase").Bytes()[12:]), Root: stateRoot,
		TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Difficulty: new(big.Int), Number: new(big.Int).SetUint64(num),
		GasLimit: 30_000_000, Time: 1_790_000_000 + num*12, Extra: []byte("certen-h0"), MixDigest: seeded(sp.Seed, "mix"), BaseFee: big.NewInt(1_000_000_000),
		WithdrawalsHash: &types.EmptyWithdrawalsHash, BlobGasUsed: new(uint64), ExcessBlobGas: new(uint64), ParentBeaconRoot: &common.Hash{}, RequestsHash: &types.EmptyRequestsHash,
	}
	if b.txTrie != nil && len(b.wires) > 0 {
		h.Bloom = b.bloom
		h.TxHash, h.ReceiptHash = b.txTrie.Hash(), b.rcTrie.Hash()
		h.GasUsed = uint64(50_000 * len(b.wires))
	}
	var err error
	hashField := func(key string, dst *common.Hash) {
		if s, ok := f[key]; ok && err == nil {
			*dst, err = parseHash(s)
		}
	}
	hashField("parentHash", &h.ParentHash)
	hashField("stateRoot", &h.Root)
	hashField("transactionsRoot", &h.TxHash)
	hashField("receiptsRoot", &h.ReceiptHash)
	if err != nil {
		return err
	}
	if h.Time, err = uintField(f, "timestamp", h.Time); err != nil {
		return err
	}
	if h.GasLimit, err = uintField(f, "gasLimit", h.GasLimit); err != nil {
		return err
	}
	if h.GasUsed, err = uintField(f, "gasUsed", h.GasUsed); err != nil {
		return err
	}
	if s, ok := f["coinbase"]; ok {
		if h.Coinbase, err = parseAddr(s); err != nil {
			return err
		}
	}
	if s, ok := f["extraData"]; ok {
		if h.Extra, err = parseHex(s); err != nil {
			return err
		}
	}
	if s, ok := f["baseFee"]; ok {
		if h.BaseFee, err = parseDec(s); err != nil {
			return err
		}
	}
	if s, ok := f["logsBloom"]; ok {
		bb, err := parseHex(s)
		if err != nil || len(bb) != 256 {
			return fmt.Errorf("logsBloom %q", s)
		}
		h.Bloom = types.BytesToBloom(bb)
	}
	b.header = h
	if b.rlp, err = rlp.EncodeToBytes(h); err != nil {
		return err
	}
	b.hash = h.Hash()
	return nil
}

// historyAccount makes sure the EIP-2935 account exists in the accounts of a station and holds the ring slot of the previous block unless
// the Spec states that slot (an override, a zero value deleting the slot).
func historyAccount(m *ci.Manifest, sp *Spec, accounts map[string]*AcctSpec, prevNumber uint64, prevHash common.Hash) (map[string]*AcctSpec, error) {
	e, ok := m.EIP2935(sp.Chain)
	if !ok {
		return nil, fmt.Errorf("chain %d has no eip2935 row", sp.Chain)
	}
	out := map[string]*AcctSpec{}
	for k, v := range accounts {
		out[k] = v
	}
	key := sp.Roles.History
	a := &AcctSpec{Nonce: 1, Code: &CodeSpec{CodeHash: e.CodeHash}, Storage: map[string]string{}}
	if old, has := out[key]; has && old != nil {
		cp := *old
		cp.Storage = map[string]string{}
		for k, v := range old.Storage {
			cp.Storage[k] = v
		}
		if cp.Code == nil {
			cp.Code = a.Code
		}
		if cp.Nonce == 0 {
			cp.Nonce = 1
		}
		a = &cp
	}
	slot := hh(wordU(prevNumber % e.Window))
	if _, over := a.Storage[slot]; !over {
		a.Storage[slot] = hh(prevHash)
	}
	out[key] = a
	return out, nil
}

// Derive turns a Spec into a World. m is the manifest the chain profile and the pins come from.
func Derive(m *ci.Manifest, sp *Spec) (*World, error) {
	if sp.Format != Format {
		return nil, fmt.Errorf("world format %q is not %q", sp.Format, Format)
	}
	if sp.Link != "spine" && sp.Link != "hops" {
		return nil, fmt.Errorf("world link %q is neither spine nor hops", sp.Link)
	}
	st := func(name string) map[string]*AcctSpec {
		if s := sp.Stations[name]; s != nil && s.Accounts != nil {
			return s.Accounts
		}
		return map[string]*AcctSpec{}
	}
	w := &World{Spec: sp, Manifest: m, StateRoots: map[string]common.Hash{}, BlockHashes: map[string]common.Hash{}, HeaderRLP: map[string][]byte{}}
	states := map[string]*builtState{}
	setState := func(name string, accts map[string]*AcctSpec) error {
		bs, err := buildState(m, accts)
		if err != nil {
			return fmt.Errorf("station %s: %w", name, err)
		}
		states[name] = bs
		w.StateRoots[name] = bs.root
		return nil
	}

	// blocks in chain order
	blocks := []*block{}
	mk := func(name string, bs *BlockSpec) *block {
		b := &block{name: name, spec: bs, txIndex: map[string]int{}}
		blocks = append(blocks, b)
		return b
	}
	bParent := mk(BlockAttestParent, &sp.Blocks.AttestParent)
	bAtt := mk(BlockAttest, &sp.Blocks.Attest)
	var between []*block
	for i := range sp.Blocks.Between {
		between = append(between, mk(fmt.Sprintf("between.%d", i), &sp.Blocks.Between[i]))
	}
	bSet := mk(BlockSettle, &sp.Blocks.Settle)
	for _, b := range blocks {
		if err := b.buildTxs(sp, sp.Chain); err != nil {
			return nil, err
		}
	}
	if err := setState(StationPre, st(StationPre)); err != nil {
		return nil, err
	}
	if err := setState(StationPost, st(StationPost)); err != nil {
		return nil, err
	}
	var prev *block
	for _, b := range blocks {
		var root common.Hash
		var accts map[string]*AcctSpec
		var needState bool
		switch {
		case b == bParent:
			root = states[StationPre].root
		case b == bAtt:
			root = states[StationPost].root
		case b == bSet:
			accts, needState = st(StationSettle), true
		case sp.Link == "hops":
			accts, needState = st(HopStation(indexOf(between, b)+1)), true
		default:
			root = seeded(sp.Seed, "spinestate", b.spec.Number)
		}
		if needState {
			if sp.Link == "hops" && prev != nil {
				var err error
				if accts, err = historyAccount(m, sp, accts, prev.spec.Number, prev.hash); err != nil {
					return nil, err
				}
			}
			name := StationSettle
			if b != bSet {
				name = HopStation(indexOf(between, b) + 1)
			}
			if err := setState(name, accts); err != nil {
				return nil, err
			}
			root = states[name].root
		}
		adjacent := prev != nil && b.spec.Number == prev.spec.Number+1
		var pHash common.Hash
		if prev != nil {
			pHash = prev.hash
		}
		if err := b.buildHeader(sp, pHash, adjacent, root); err != nil {
			return nil, fmt.Errorf("block %s: %w", b.name, err)
		}
		w.BlockHashes[b.name], w.HeaderRLP[b.name] = b.hash, b.rlp
		prev = b
	}
	if sp.Link == "spine" {
		if _, ok := states[StationSettle]; !ok {
			return nil, errors.New("internal: no settle state")
		}
	}

	dv := &derived{w: w, sp: sp, m: m, states: states, bAtt: bAtt, bSet: bSet, between: between, bParent: bParent}
	w.d = dv
	if err := dv.assemble(); err != nil {
		return nil, err
	}
	return w, nil
}

func mustIndexKey(idx int) []byte { k, _ := rlp.EncodeToBytes(uint64(idx)); return k }

func indexOf(bs []*block, b *block) int {
	for i, x := range bs {
		if x == b {
			return i
		}
	}
	return -1
}

type derived struct {
	w       *World
	sp      *Spec
	m       *ci.Manifest
	states  map[string]*builtState
	bParent *block
	bAtt    *block
	bSet    *block
	between []*block
}

func (d *derived) assemble() error {
	sp := d.sp
	// ---- nodes: run the read plan against the tries, then re-run it strictly against the container's nodes ----
	br := &buildReader{d: d, seen: map[common.Hash][]byte{}}
	d.w.PlanErr = d.runPlan(br)
	nodes := make([][]byte, 0, len(br.seen))
	for _, n := range br.seen {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return bytes.Compare(crypto.Keccak256(nodes[i]), crypto.Keccak256(nodes[j])) < 0 })
	d.w.Planned = len(nodes)

	// ---- codes ----
	settle := d.states[StationSettle]
	var codes []ci.Code
	for _, s := range sp.Carry {
		a, err := parseAddr(s)
		if err != nil {
			return err
		}
		ba := settle.accts[a]
		if ba == nil || ba.code == nil {
			// a capture carries only code it can read: the container then lacks it (the verifier names code_not_carried)
			if d.w.PlanErr == nil {
				d.w.PlanErr = fmt.Errorf("carry %s: no materialised code at the settle station", s)
			}
			continue
		}
		codes = append(codes, ci.Code{Address: a, Runtime: ba.code})
	}
	sort.Slice(codes, func(i, j int) bool { return bytes.Compare(codes[i].Address[:], codes[j].Address[:]) < 0 })

	// ---- container ----
	ai := d.bAtt.txIndex["attestation"]
	proof := &ci.AttestProof{TxIndex: uint32(ai), HeaderV: d.bAtt.rlp, HeaderVParent: d.bParent.rlp, BlockTxs: d.bAtt.wires}
	proof.TxLeaf, proof.ReceiptLeaf = d.bAtt.wires[ai], d.bAtt.receipts[ai]
	if sp.Link == "hops" {
		proof.Link = ci.LinkHops
		for _, b := range d.between {
			proof.HopHeaders = append(proof.HopHeaders, b.rlp)
		}
	} else {
		proof.Link = ci.LinkSpine
		for i := len(d.between) - 1; i >= 0; i-- {
			proof.Spine = append(proof.Spine, d.between[i].rlp)
		}
		proof.Spine = append(proof.Spine, d.bAtt.rlp)
	}
	c := &ci.Container{Chain: sp.Chain, Leg: ci.BlockRef{Number: d.bSet.spec.Number, Hash: d.bSet.hash}, Codes: codes,
		Settle: ci.Part{Tag: ci.TagCaptured}, Attest: ci.Part{Tag: ci.TagCaptured, Attest: proof}, Nodes: nodes}
	raw, err := ci.Encode(c, ci.DefaultLimits())
	if err != nil {
		return fmt.Errorf("encode container: %w", err)
	}
	d.w.Container, d.w.ContainerBytes = c, raw
	d.w.CheckErr = d.w.Recheck(raw)
	return d.context()
}

func inclusion(tr *trie.Trie, root common.Hash, idx int, wires [][]byte) (*ethproof.InclusionProof, error) {
	key, _ := rlp.EncodeToBytes(uint64(idx))
	var col collector
	if err := tr.Prove(key, &col); err != nil {
		return nil, err
	}
	p := &ethproof.InclusionProof{LeafIndex: uint64(idx), ExpectedRoot: root, ProofNodes: col.nodes, LeafValue: wires[idx]}
	p.LeafHash = [32]byte(crypto.Keccak256Hash(wires[idx]))
	for _, n := range col.nodes {
		p.ProofHashes = append(p.ProofHashes, [32]byte(crypto.Keccak256Hash(n)))
	}
	return p, nil
}

func (d *derived) context() error {
	sp, c := d.sp, d.sp.Context
	b := d.bSet
	si := b.txIndex["settlement"]
	txp, err := inclusion(b.txTrie, b.txTrie.Hash(), si, b.wires)
	if err != nil {
		return err
	}
	rcp, err := inclusion(b.rcTrie, b.rcTrie.Hash(), si, b.receipts)
	if err != nil {
		return err
	}
	settlement := &ethproof.Settlement{BlockHash: b.hash, Header: b.rlp, Tx: txp, Receipt: rcp}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(b.wires[si]); err != nil {
		return fmt.Errorf("settlement transaction: %w", err)
	}
	settlement.TxHash = tx.Hash()
	rl, err := ethproof.DecodeReceiptLeaf(b.receipts[si])
	if err != nil {
		return fmt.Errorf("settlement receipt: %w", err)
	}
	ctx := ci.LegContext{Chain: sp.Chain, Settlement: settlement, Tx: &tx, Receipt: rl, ADIURL: c.ADIURL, S6Status: ci.S6Status(c.S6Status), S6Reason: c.S6Reason, S6State: c.S6State}
	if c.S6 != nil {
		contract, err := parseAddr(c.S6.Contract)
		if err != nil {
			return err
		}
		leaf, err := h32(c.S6.LeafKey)
		if err != nil {
			return err
		}
		ref := ci.BlockRef{Number: b.spec.Number, Hash: b.hash}
		link := &ci.S6Link{Contract: contract, LeafKey: leaf, SettlementBlock: ref, ProvenAt: ref}
		if ba := d.states[StationSettle].accts[contract]; ba != nil {
			link.CodeHash = ba.codeHash
		}
		ctx.S6 = link
	}
	for _, f := range []struct {
		src string
		dst *[32]byte
	}{{c.Batch.BatchRoot, &ctx.Batch.BatchRoot}, {c.Batch.OperationID, &ctx.Batch.OperationID}, {c.Batch.AccSetRoot, &ctx.Batch.AccSetRoot}, {c.Batch.Incarnation, &ctx.Batch.Incarnation}} {
		if *f.dst, err = h32(f.src); err != nil {
			return err
		}
	}
	if r := c.Registry9; r != nil {
		reg := &ci.Registry9{Num: r.Num, Den: r.Den}
		for _, mem := range r.Members {
			a, err := parseAddr(mem.Address)
			if err != nil {
				return err
			}
			reg.Members = append(reg.Members, ci.RegistryMember{Address: a, Power: mem.Power, BLSKey: mem.BLSKey})
		}
		if reg.CertenSetRoot, err = h32(r.CertenSetRoot); err != nil {
			return err
		}
		if reg.SignerCommitment, err = h32(r.SignerCommitment); err != nil {
			return err
		}
		ctx.Registry9 = reg
	}
	// the S7 report of the world: included and finalized verified at the settlement block (constructed, not judged: S7's own vectors judge S7)
	ref := finality.BlockRef{Chain: sp.Chain, Number: b.spec.Number, Hash: b.hash, HeaderRLP: b.rlp}
	ctx.S7 = &finality.Report{Block: ref, Headline: finality.LevelFinalized,
		Levels:         map[finality.Level]finality.LevelStatus{finality.LevelIncluded: {Status: finality.StatusVerified}, finality.LevelFinalized: {Status: finality.StatusVerified}},
		FinalizedBlock: &finality.FinalizedBlock{Number: b.spec.Number, Hash: b.hash, StateRoot: d.states[StationSettle].root}}
	d.w.Ctx = ctx
	return nil
}

// headerStateRoot is the state root of the header the station belongs to (what a verifier reads the station under).
func (d *derived) headerStateRoot(station string) (common.Hash, error) {
	var b *block
	switch {
	case station == StationPre:
		b = d.bParent
	case station == StationPost:
		b = d.bAtt
	case station == StationSettle:
		b = d.bSet
	case strings.HasPrefix(station, "hop."):
		i, err := strconv.Atoi(strings.TrimPrefix(station, "hop."))
		if err != nil || i < 1 || i > len(d.between) {
			return common.Hash{}, fmt.Errorf("station %q", station)
		}
		b = d.between[i-1]
	default:
		return common.Hash{}, fmt.Errorf("station %q", station)
	}
	return b.header.Root, nil
}

// Recheck re-runs the read plan with the strict reads of the contractidentity package over the nodes of the given container bytes (the
// world's own container or a mutated one), under the roots of the headers. It returns the first read that does not verify, or the
// nodes_unreferenced refusal of step 22b when a node is carried that no read visits; nil means the container carries exactly what the
// plan reads.
func (w *World) Recheck(container []byte) error {
	c, err := ci.Decode(container, ci.DefaultLimits())
	if err != nil {
		return err
	}
	ns, err := ci.NewNodeSet(c.Nodes)
	if err != nil {
		return err
	}
	if err := w.d.runPlan(&checkReader{d: w.d, ns: ns, accts: map[string]ci.AccountState{}}); err != nil {
		return err
	}
	if un := ns.Unvisited(); len(un) != 0 {
		return fmt.Errorf("nodes_unreferenced: node %d of %d is carried and no read visits it", un[0], len(c.Nodes))
	}
	return nil
}
