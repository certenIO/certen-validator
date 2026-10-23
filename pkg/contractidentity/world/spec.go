// Copyright 2026 Certen Protocol

// Package world builds the honest synthetic world H0 of the S8 contract-identity verifier (Freeze inventory item 5) and applies the
// mutations of the published vector format to it.
//
// A world is described by a Spec (the JSON of a vector set's world.json): every account of every station with its storage, the headers, the
// transactions, the calls the attestation and the settlement made, and the LegContext members. Generate expands a chain profile of the
// manifest into the Spec of H0; Derive turns a Spec into everything a verifier reads - real go-ethereum tries, real RLP headers linked by
// hash, the receipts and transactions of the two blocks, the CIE1 container and the LegContext - and shares ONE read plan with its own
// self-check, so that the container carries exactly the nodes the plan visits (step 22b). A semantic mutation edits the Spec and Derive
// re-derives every root, hash and container; a raw mutation edits the derived container or context and re-derives nothing.
package world

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// Format is the format string of a world.json.
const Format = "certen-contract-identity-world/1"

// Variants (the named base worlds of the vector rows).
const (
	VariantH0       = "h0"       // S6 proven, Registry9 present, the attestation linked to the settlement by a spine of three headers
	VariantS6Silent = "s6silent" // H0 with S6 silent (no claim): the settlement was made by a call generation S6 does not pin
	VariantHops     = "hops"     // H0 with the attestation linked by EIP-2935 hop headers (link 1, k = 3 hops across gaps W, W/2, 7)
)

// Stations: the states the verifier reads.
const (
	StationSettle = "settle"      // stateRoot(N)
	StationPre    = "attest_pre"  // stateRoot(headerVParent)
	StationPost   = "attest_post" // stateRoot(headerV)
)

// HopStation is the station of the i-th hop header (1-based).
func HopStation(i int) string { return fmt.Sprintf("hop.%d", i) }

// Block names of Blocks.
const (
	BlockAttestParent = "attest_parent"
	BlockAttest       = "attest"
	BlockSettle       = "settle"
)

// SeedLabel is the fixed seed of every derived pseudo-random value: the same manifest, chain and variant give byte-identical output.
const SeedLabel = "certen:contract-identity:world:h0:v1"

// EntryPoint is the canonical ERC-4337 v0.7 EntryPoint (the manifest rule "constant" of the factory and the account; step 7).
var EntryPoint = common.HexToAddress("0x0000000071727De22E5E9d8BAf0edAc6f37da032")

// Spec is the JSON of world.json.
type Spec struct {
	Format         string              `json:"format"`
	Chain          uint64              `json:"chain"`
	Variant        string              `json:"variant"`
	Seed           string              `json:"seed"`
	ManifestSHA256 string              `json:"manifest_sha256"`
	Link           string              `json:"link"` // spine | hops
	Roles          Roles               `json:"roles"`
	Blocks         Blocks              `json:"blocks"`
	Stations       map[string]*Station `json:"stations"`
	Carry          []string            `json:"carry"` // addresses whose code the container carries
	Attestation    AttestSpec          `json:"attestation"`
	Settlement     SettleSpec          `json:"settlement"`
	Context        CtxSpec             `json:"context"`
}

// Roles are the addresses the read plan and the transactions use.
type Roles struct {
	Anchor   string `json:"anchor"`
	Verifier string `json:"verifier"`
	Groth16  string `json:"groth16"`
	Factory  string `json:"factory"`
	Account  string `json:"account"`
	Owner    string `json:"owner"`
	History  string `json:"history"` // the EIP-2935 history contract
}

// Blocks are the headers of the world. Between holds the blocks strictly between the attestation block and the settlement block in
// ascending order: the spine (link 2, consecutive) or the hop headers (link 1).
type Blocks struct {
	AttestParent BlockSpec   `json:"attest_parent"`
	Attest       BlockSpec   `json:"attest"`
	Between      []BlockSpec `json:"between"`
	Settle       BlockSpec   `json:"settle"`
}

// BlockSpec is one header: its number, the header fields that override the derived ones (parentHash, stateRoot, transactionsRoot,
// receiptsRoot, logsBloom, timestamp, gasLimit, gasUsed, coinbase, extraData, baseFee), and its transactions in index order.
type BlockSpec struct {
	Number uint64            `json:"number"`
	Fields map[string]string `json:"fields,omitempty"`
	Txs    []TxSpec          `json:"txs,omitempty"`
}

// TxSpec is one transaction of a block. Role "attestation" and "settlement" are built from the Attestation and Settlement specs; any other
// transaction is a filler of the given type. Wire replaces the encoding, Receipt the receipt, when set (raw forgeries).
type TxSpec struct {
	Role    string `json:"role,omitempty"`
	Type    uint8  `json:"type"`
	Seed    uint64 `json:"seed,omitempty"`
	Wire    string `json:"wire,omitempty"`
	Receipt string `json:"receipt,omitempty"`
}

// Station is the state at one station: every account with its storage. For a hop station only the overrides of the EIP-2935 account are
// listed; Derive adds the computed ring slot unless the Spec states that slot.
type Station struct {
	Accounts map[string]*AcctSpec `json:"accounts"`
}

// AcctSpec is one account. Storage maps 32-byte slot to 32-byte value (a zero value is absent).
type AcctSpec struct {
	Nonce   uint64            `json:"nonce,omitempty"`
	Balance string            `json:"balance,omitempty"` // decimal
	Code    *CodeSpec         `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

// CodeSpec describes the code of an account: a pinned build with the values of its immutables, explicit bytes, or only a code hash (the
// code is then not materialised and cannot be carried).
type CodeSpec struct {
	Build      string            `json:"build,omitempty"`
	Immutables map[string]string `json:"immutables,omitempty"`
	Hex        string            `json:"hex,omitempty"`
	CodeHash   string            `json:"code_hash,omitempty"`
}

// LogSpec is one log of a receipt.
type LogSpec struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// AttestSpec is executeComprehensiveProof(anchorId, proof) as made in the attestation block, and its receipt.
type AttestSpec struct {
	AnchorID            string    `json:"anchor_id"`
	TransactionHash     string    `json:"transaction_hash"`
	MerkleRoot          string    `json:"merkle_root"`
	LeafHash            string    `json:"leaf_hash"`
	OperationCommitment string    `json:"operation_commitment"`
	ExecutionCommitment string    `json:"execution_commitment"`
	Validators          []string  `json:"validators"` // the listed signers
	Powers              []uint64  `json:"powers"`
	OuterSigned         uint64    `json:"outer_signed"`
	OuterTotal          uint64    `json:"outer_total"`
	AuthorityLevel      uint8     `json:"authority_level"`
	MessageHash         string    `json:"message_hash"` // blsProof.messageHash
	Blob                []string  `json:"blob"`         // the 18 words of the aggregate signature
	Logs                []LogSpec `json:"logs"`
}

// SettleSpec is executeGovernanceProofDirect (one leg) or batchExecuteGovernanceProofDirect (Legs) as made in the settlement block.
type SettleSpec struct {
	Batch         bool      `json:"batch"`
	Legs          []LegSpec `json:"legs"`
	AnchorID      string    `json:"anchor_id"`
	OperationID   string    `json:"operation_id"`
	AuthorityBook string    `json:"authority_book"`
	AuthorityPage uint64    `json:"authority_page"`
	Leaf          string    `json:"leaf"`
	Logs          []LogSpec `json:"logs"`
}

// LegSpec is one (target, value, data) call.
type LegSpec struct {
	Target string `json:"target"`
	Value  string `json:"value"` // decimal
	Data   string `json:"data"`
}

// CtxSpec are the LegContext members that are not derived from the blocks.
type CtxSpec struct {
	ADIURL    string         `json:"adi_url"`
	S6Status  string         `json:"s6_status"`
	S6Reason  string         `json:"s6_reason,omitempty"`
	S6State   string         `json:"s6_state,omitempty"`
	S6        *S6Spec        `json:"s6,omitempty"`
	Batch     BatchSpec      `json:"batch"`
	Registry9 *Registry9Spec `json:"registry9,omitempty"`
}

// S6Spec is the S6 link; the settlement block and the proof block are the settlement block of the world, the code hash the account's.
type S6Spec struct {
	Contract string `json:"contract"`
	LeafKey  string `json:"leaf_key"`
}

// BatchSpec are the four batch facts of the proof file.
type BatchSpec struct {
	BatchRoot   string `json:"batch_root"`
	OperationID string `json:"batch_operation_id"`
	AccSetRoot  string `json:"acc_set_root"`
	Incarnation string `json:"incarnation"`
}

// Registry9Spec is the S9 validator registry.
type Registry9Spec struct {
	Members          []MemberSpec `json:"members"`
	Num              uint64       `json:"num"`
	Den              uint64       `json:"den"`
	CertenSetRoot    string       `json:"certen_set_root"`
	SignerCommitment string       `json:"signer_commitment"`
}

// MemberSpec is one registry member; BLSKey is lowercase hex without 0x.
type MemberSpec struct {
	Address string `json:"address"`
	Power   uint64 `json:"power"`
	BLSKey  string `json:"bls_key"`
}

// ---- encoding helpers ----

func hx(b []byte) string            { return "0x" + hex.EncodeToString(b) }
func hh(h common.Hash) string       { return hx(h[:]) }
func addrS(a common.Address) string { return strings.ToLower(a.Hex()) }

func parseHex(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("%q is not 0x-prefixed hex", s)
	}
	return hex.DecodeString(s[2:])
}

func parseHash(s string) (common.Hash, error) {
	b, err := parseHex(s)
	if err != nil || len(b) != 32 {
		return common.Hash{}, fmt.Errorf("%q is not a 32-byte hex value", s)
	}
	return common.BytesToHash(b), nil
}

func parseAddr(s string) (common.Address, error) {
	b, err := parseHex(s)
	if err != nil || len(b) != 20 {
		return common.Address{}, fmt.Errorf("%q is not a 20-byte hex address", s)
	}
	return common.BytesToAddress(b), nil
}

func parseDec(s string) (*big.Int, error) {
	if s == "" {
		return new(big.Int), nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return nil, fmt.Errorf("%q is not a decimal number", s)
	}
	return v, nil
}

// seeded returns keccak256(seed || label parts): the single source of every pseudo-random value.
func seeded(seed string, parts ...any) common.Hash {
	var b []byte
	b = append(b, seed...)
	for _, p := range parts {
		b = append(b, '|')
		b = append(b, fmt.Sprint(p)...)
	}
	return common.BytesToHash(crypto.Keccak256(b))
}

func setSlot(m map[string]string, slot, val common.Hash) {
	if val == (common.Hash{}) {
		delete(m, hh(slot))
		return
	}
	m[hh(slot)] = hh(val)
}

func wordU(v uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(v)) }

func wordAddr(a common.Address) common.Hash { return common.BytesToHash(a[:]) }

// putDyn writes a bytes/string value at slot in the short/long layout of step 6.
func putDyn(m map[string]string, slot common.Hash, data []byte) {
	if len(data) < 32 {
		var w common.Hash
		copy(w[:], data)
		w[31] = byte(2 * len(data))
		setSlot(m, slot, w)
		return
	}
	setSlot(m, slot, wordU(uint64(2*len(data)+1)))
	for i := 0; i*32 < len(data); i++ {
		var w common.Hash
		copy(w[:], data[i*32:])
		setSlot(m, ci.DynDataSlot(slot, uint64(i)), w)
	}
}

func abiPack(types []string, vals ...any) ([]byte, error) {
	var args abi.Arguments
	for _, t := range types {
		ty, err := abi.NewType(t, "", nil)
		if err != nil {
			return nil, err
		}
		args = append(args, abi.Argument{Type: ty})
	}
	return args.Pack(vals...)
}

// ---- Generate ----

// Generate expands the chain profile of the manifest into the Spec of the named base world. Every address, window, code pin and transaction
// type list comes from the manifest; every other value is derived from the fixed seed.
func Generate(m *ci.Manifest, chain uint64, variant string) (*Spec, error) {
	if variant != VariantH0 && variant != VariantS6Silent && variant != VariantHops {
		return nil, fmt.Errorf("unknown world variant %q", variant)
	}
	ce, err := m.Chain(chain)
	if err != nil {
		return nil, err
	}
	dep := func(role string) (common.Address, error) {
		d, ok := m.Deployment(chain, role)
		if !ok {
			return common.Address{}, fmt.Errorf("chain %d has no %s deployment in the manifest", chain, role)
		}
		return parseAddr(strings.ToLower(d.Address))
	}
	var roles Roles
	var A, V, G, F common.Address
	for _, r := range []struct {
		role string
		dst  *common.Address
		out  *string
	}{{"anchor", &A, &roles.Anchor}, {"blsZkVerifier", &V, &roles.Verifier}, {"groth16Verifier", &G, &roles.Groth16}, {"accountFactory", &F, &roles.Factory}} {
		a, err := dep(r.role)
		if err != nil {
			return nil, err
		}
		*r.dst, *r.out = a, addrS(a)
	}
	rows := m.Accounts(chain)
	if len(rows) == 0 {
		return nil, fmt.Errorf("chain %d has no account row in the manifest", chain)
	}
	row := rows[0]
	acct, err := parseAddr(strings.ToLower(row.Address))
	if err != nil {
		return nil, err
	}
	owners := m.OwnerRows(chain, "anchor")
	if len(owners) == 0 {
		return nil, fmt.Errorf("chain %d has no anchor owner row in the manifest", chain)
	}
	O, err := parseAddr(strings.ToLower(owners[0].Address))
	if err != nil {
		return nil, err
	}
	e29, ok := m.EIP2935(chain)
	if !ok {
		return nil, fmt.Errorf("chain %d has no eip2935 row in the manifest", chain)
	}
	hist, err := parseAddr(strings.ToLower(e29.Address))
	if err != nil {
		return nil, err
	}
	roles.Account, roles.Owner, roles.History = addrS(acct), addrS(O), addrS(hist)
	seed := fmt.Sprintf("%s|%d", SeedLabel, chain)
	sd := func(parts ...any) common.Hash { return seeded(seed, parts...) }
	adiURL, book := row.ADIURL, row.GoverningBook

	// ---- validators, authorized commitments, set root ----
	const nVal, nPKC = 7, 29
	type val struct {
		addr  common.Address
		power uint64
		key   []byte
	}
	vals := make([]val, nVal)
	for i := range vals {
		k := append(append(sd("key", i, 0).Bytes(), sd("key", i, 1).Bytes()...), sd("key", i, 2).Bytes()...)
		vals[i] = val{addr: common.BytesToAddress(sd("validator", i).Bytes()[12:]), power: 10, key: k}
	}
	sorted := append([]val{}, vals...)
	sort.Slice(sorted, func(a, b int) bool {
		return new(big.Int).SetBytes(sorted[a].addr[:]).Cmp(new(big.Int).SetBytes(sorted[b].addr[:])) < 0
	})
	var sAddrs []common.Address
	var sPowers []*big.Int
	var total uint64
	for _, v := range sorted {
		sAddrs, sPowers = append(sAddrs, v.addr), append(sPowers, new(big.Int).SetUint64(v.power))
	}
	for _, v := range vals {
		total += v.power
	}
	rootEnc, err := abiPack([]string{"address[]", "uint256[]", "uint256", "uint256"}, sAddrs, sPowers, big.NewInt(2), big.NewInt(3))
	if err != nil {
		return nil, err
	}
	setRoot := common.BytesToHash(crypto.Keccak256(rootEnc))
	pkcs := make([]common.Hash, nPKC)
	for j := range pkcs {
		pkcs[j] = sd("pkc", j)
	}

	// ---- the batch and the anchor record ----
	batch := ci.BatchFacts{BatchRoot: sd("merkleroot"), OperationID: sd("operationid"), AccSetRoot: sd("accsetroot"), Incarnation: sd("incarnation")}
	const leafCount, accHeight = 3, 7_000_000
	packed := append([]byte("certen:batchbundle:v2"), common.BigToHash(new(big.Int).SetUint64(chain)).Bytes()...)
	packed = append(packed, batch.BatchRoot[:]...)
	packed = append(packed, wordU(leafCount).Bytes()...)
	packed = append(packed, batch.OperationID[:]...)
	packed = append(packed, wordU(accHeight).Bytes()...)
	packed = append(packed, batch.AccSetRoot[:]...)
	packed = append(packed, batch.Incarnation[:]...)
	anchorID := common.BytesToHash(crypto.Keccak256(packed))
	execCommit := sd("executioncommitment")
	msgEnc, err := abiPack([]string{"bytes32", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"},
		[32]byte(common.RightPadBytes([]byte("certen:bls:v2:pre"), 32)), new(big.Int).SetUint64(chain), [32]byte(anchorID), [32]byte(execCommit),
		[32]byte(batch.OperationID), [32]byte(setRoot), [32]byte(batch.AccSetRoot), [32]byte(batch.Incarnation))
	if err != nil {
		return nil, err
	}
	msgHash := common.BytesToHash(crypto.Keccak256(msgEnc))
	const authLevel = 3

	recWords := func(proofExecuted bool, level uint8) [13]common.Hash {
		var w [13]common.Hash
		w[0], w[1] = anchorID, batch.BatchRoot
		w[2] = common.BytesToHash(crypto.Keccak256([]byte(adiURL)))
		w[3], w[4], w[5], w[6] = common.Hash{}, sd("crosschain"), sd("govroot"), execCommit
		w[7], w[8], w[9] = batch.OperationID, wordU(accHeight), wordU(1_790_000_000)
		var p common.Hash
		copy(p[12:], vals[0].addr[:]) // validator b0-b19
		p[11] = 1                     // valid b20
		if proofExecuted {
			p[10] = 1 // proofExecuted b21
		}
		p[8] = level // governanceLevel b23
		w[10], w[11], w[12] = p, batch.AccSetRoot, batch.Incarnation
		return w
	}

	// ---- storage of the anchor, the verifier, the account and the factory ----
	anchorStore := func(station string) map[string]string {
		s := map[string]string{}
		pre, post := station == StationPre, station != StationPre
		w := recWords(post, 0)
		if post {
			w = recWords(true, authLevel)
		}
		rec := ci.MappingSlotAt(ci.KeyBytes32(anchorID), 1)
		for k := range w {
			setSlot(s, ci.MemberSlot(rec, uint64(k)), w[k])
		}
		_ = pre
		setSlot(s, ci.MappingSlotAt(ci.KeyBytes32(anchorID), 2), wordU(1))
		setSlot(s, ci.MappingSlotAt(ci.KeyBytes32(anchorID), 3), wordU(leafCount))
		for _, p := range pkcs {
			setSlot(s, ci.MappingSlotAt(ci.KeyBytes32(p), 4), wordU(1))
		}
		setSlot(s, ci.SlotIndex(5), wordU(nPKC))
		setSlot(s, ci.SlotIndex(6), wordU(1))
		for _, v := range vals {
			base := ci.MappingSlotAt(ci.KeyAddress(v.addr), 12)
			setSlot(s, base, wordU(1))
			setSlot(s, ci.MemberSlot(base, 1), wordU(v.power))
			putDyn(s, ci.MemberSlot(base, 2), v.key)
			setSlot(s, ci.MemberSlot(base, 3), wordU(1_700_000_000))
		}
		setSlot(s, ci.SlotIndex(13), wordU(nVal))
		for i, v := range vals {
			el, _, _ := ci.ArrayElementSlot(13, uint64(i), 20)
			setSlot(s, el, wordAddr(v.addr))
		}
		setSlot(s, ci.SlotIndex(14), wordU(total))
		setSlot(s, ci.SlotIndex(15), wordU(2))
		setSlot(s, ci.SlotIndex(16), wordU(3))
		setSlot(s, ci.SlotIndex(17), setRoot)
		if post {
			setSlot(s, ci.MappingSlotAt(ci.KeyBytes32(batch.OperationID), 18), wordU(1))
		}
		setSlot(s, ci.SlotIndex(27), wordAddr(O))
		var s30 common.Hash
		copy(s30[12:], V[:])
		s30[11], s30[10], s30[9] = 1, 1, 1 // enabled b20, minimumGovernanceLevel b21, ...ForValueOps b22
		setSlot(s, ci.SlotIndex(30), s30)
		return s
	}
	verifierStore := func() map[string]string {
		s := map[string]string{}
		setSlot(s, ci.SlotIndex(0), wordU(2))
		setSlot(s, ci.SlotIndex(1), wordU(3))
		setSlot(s, ci.SlotIndex(2), wordAddr(O))
		return s
	}
	leaf := sd("leaf")
	regKey, err := abiPack([]string{"string", "string"}, adiURL, book)
	if err != nil {
		return nil, err
	}
	registrationKey := common.BytesToHash(crypto.Keccak256(regKey))
	acctStore := func() map[string]string {
		s := map[string]string{}
		putDyn(s, ci.SlotIndex(0), []byte(adiURL))
		setSlot(s, ci.SlotIndex(1), wordAddr(vals[0].addr))
		setSlot(s, ci.SlotIndex(2), wordAddr(A))
		setSlot(s, ci.MappingSlotAt(ci.KeyBytes32(leaf), 4), wordU(1))
		putDyn(s, ci.SlotIndex(11), []byte(book))
		return s
	}
	factStore := func() map[string]string {
		s := map[string]string{}
		setSlot(s, ci.SlotIndex(1), wordAddr(A))
		setSlot(s, ci.MappingSlotAt(ci.KeyAddress(acct), 2), wordU(1))
		setSlot(s, ci.MappingSlotAt(ci.KeyBytes32(registrationKey), 3), wordAddr(acct))
		return s
	}
	ownerOf := func(adi string) common.Hash {
		h := crypto.Keccak256([]byte(adi))
		return common.BytesToHash(h[12:])
	}
	bookHash := common.BytesToHash(crypto.Keccak256([]byte(book)))
	code := func(build string, imm map[string]common.Hash) *CodeSpec {
		cs := &CodeSpec{Build: build, Immutables: map[string]string{}}
		for k, v := range imm {
			cs.Immutables[k] = hh(v)
		}
		return cs
	}
	gBuild := ""
	if d, ok := m.Deployment(chain, "groth16Verifier"); ok {
		gBuild = d.Build
	}
	codes := map[common.Address]*CodeSpec{
		A:    code("CertenAnchorV8_2/r5", map[string]common.Hash{"DEPLOYMENT_CHAIN_ID": wordU(chain)}),
		V:    code("BLSZKVerifierV2_1/r5", map[string]common.Hash{"groth16Verifier": wordAddr(G)}),
		G:    code(gBuild, nil),
		F:    code("CertenAccountFactoryV11/r5", map[string]common.Hash{"entryPoint": wordAddr(EntryPoint)}),
		acct: code(row.Build, map[string]common.Hash{"_entryPoint": wordAddr(EntryPoint), "owner": ownerOf(adiURL), "governingBookHash": bookHash}),
	}
	// ---- stations: the contracts, the owner EOA and sixteen unrelated accounts that give the tries their depth ----
	mkStation := func(name string) *Station {
		st := &Station{Accounts: map[string]*AcctSpec{}}
		st.Accounts[addrS(A)] = &AcctSpec{Nonce: 1, Code: codes[A], Storage: anchorStore(name)}
		st.Accounts[addrS(V)] = &AcctSpec{Nonce: 1, Code: codes[V], Storage: verifierStore()}
		st.Accounts[addrS(G)] = &AcctSpec{Nonce: 1, Code: codes[G]}
		st.Accounts[addrS(O)] = &AcctSpec{Nonce: 45, Balance: "1000000000000000000"}
		for i := 0; i < 16; i++ {
			a := common.BytesToAddress(sd("filler", i).Bytes()[12:])
			fa := &AcctSpec{Nonce: uint64(i + 1), Balance: fmt.Sprint(1000 * (i + 1))}
			if i%4 == 0 {
				fa.Code = &CodeSpec{Hex: hx([]byte{0x60, byte(i), 0x60, 0x00, 0x52, 0x00})}
				fa.Storage = map[string]string{}
				setSlot(fa.Storage, ci.SlotIndex(uint64(i)), sd("fillerslot", i))
			}
			st.Accounts[addrS(a)] = fa
		}
		if name == StationSettle {
			st.Accounts[addrS(acct)] = &AcctSpec{Nonce: 1, Code: codes[acct], Storage: acctStore()}
			st.Accounts[addrS(F)] = &AcctSpec{Nonce: 1, Code: codes[F], Storage: factStore()}
		}
		return st
	}
	spec := &Spec{Format: Format, Chain: chain, Variant: variant, Seed: seed, ManifestSHA256: fmt.Sprintf("%x", m.SHA256), Roles: roles,
		Stations: map[string]*Station{StationSettle: mkStation(StationSettle), StationPre: mkStation(StationPre), StationPost: mkStation(StationPost)}}
	spec.Carry = []string{addrS(A), addrS(V), addrS(G), addrS(F), addrS(acct)}
	sort.Strings(spec.Carry)

	// ---- the blocks ----
	N := ce.SnapshotBlock - 100
	W := e29.Window
	var Bv uint64
	var between []uint64
	if variant == VariantHops {
		gaps := []uint64{W, W / 2, 7}
		Bv = N - gaps[0] - gaps[1] - gaps[2]
		between = []uint64{Bv + gaps[0], Bv + gaps[0] + gaps[1]}
		spec.Link = "hops"
	} else {
		Bv = N - 3
		between = []uint64{Bv + 1, Bv + 2}
		spec.Link = "spine"
	}
	ts, _ := m.TxScan(chain)
	var types []int
	types = append(types, ts.CoveredTypes...)
	types = append(types, ts.SystemTypes...)
	fillers := func(seed0 uint64) []TxSpec {
		var out []TxSpec
		for i, t := range types {
			out = append(out, TxSpec{Type: uint8(t), Seed: seed0 + uint64(i)})
		}
		return out
	}
	attTxs := append(fillers(100), TxSpec{Role: "attestation", Type: 2})
	attTxs = append(attTxs, TxSpec{Type: 2, Seed: 900})
	spec.Blocks = Blocks{
		AttestParent: BlockSpec{Number: Bv - 1},
		Attest:       BlockSpec{Number: Bv, Txs: attTxs},
		Settle:       BlockSpec{Number: N, Txs: append(fillers(300)[:2], TxSpec{Role: "settlement", Type: 2})},
	}
	for _, n := range between {
		spec.Blocks.Between = append(spec.Blocks.Between, BlockSpec{Number: n})
	}
	if variant == VariantHops {
		for i := range between {
			spec.Stations[HopStation(i+1)] = &Station{Accounts: map[string]*AcctSpec{}}
		}
	}

	// ---- the attestation call ----
	att := AttestSpec{AnchorID: hh(anchorID), TransactionHash: hh(sd("txhash")), MerkleRoot: hh(batch.BatchRoot), LeafHash: hh(sd("leafhash")),
		OperationCommitment: hh(batch.OperationID), ExecutionCommitment: hh(execCommit), AuthorityLevel: authLevel, MessageHash: hh(msgHash)}
	for _, v := range vals[:5] {
		att.Validators, att.Powers = append(att.Validators, addrS(v.addr)), append(att.Powers, v.power)
		att.OuterSigned += v.power
	}
	att.OuterTotal = total
	for i := 0; i < 18; i++ {
		var w common.Hash
		switch i {
		case 12:
			w = msgHash
		case 13:
			w = pkcs[0]
		case 14:
			w = wordU(att.OuterSigned)
		case 15:
			w = wordU(att.OuterTotal)
		case 16:
			w = wordU(2)
		case 17:
			w = wordU(3)
		default:
			w = sd("blob", i)
		}
		att.Blob = append(att.Blob, hh(w))
	}
	peData, err := abiPack([]string{"bytes32", "bool", "bool", "bool", "uint256"}, [32]byte(common.HexToHash(att.TransactionHash)), true, true, true, big.NewInt(1_790_000_000))
	if err != nil {
		return nil, err
	}
	att.Logs = []LogSpec{{Address: addrS(A), Topics: []string{hh(ci.TopicOf(ci.SigProofExecuted)), hh(anchorID)}, Data: hx(peData)}}
	spec.Attestation = att

	// ---- the settlement call ----
	target := common.BytesToAddress(sd("target").Bytes()[12:])
	callData := append([]byte{0xa9, 0x05, 0x9c, 0xbb}, append(wordAddr(common.BytesToAddress(sd("recipient").Bytes()[12:])).Bytes(), wordU(5).Bytes()...)...)
	setl := SettleSpec{AnchorID: hh(anchorID), OperationID: hh(batch.OperationID), AuthorityBook: hh(bookHash), AuthorityPage: 1, Leaf: hh(leaf),
		Legs: []LegSpec{{Target: addrS(target), Value: "0", Data: hx(callData)}}}
	goData, err := abiPack([]string{"uint256", "bytes", "uint8"}, big.NewInt(0), callData, uint8(4))
	if err != nil {
		return nil, err
	}
	setl.Logs = []LogSpec{
		{Address: addrS(acct), Topics: []string{hh(ci.TopicOf(ci.SigGovernanceOperation)), hh(common.BytesToHash(crypto.Keccak256([]byte(adiURL)))), hh(wordAddr(target))}, Data: hx(goData)},
		{Address: addrS(acct), Topics: []string{hh(ci.TopicOf(ci.SigLeafConsumed)), hh(anchorID), hh(leaf)}, Data: hh(batch.OperationID)},
	}
	spec.Settlement = setl

	// ---- the context ----
	ctx := CtxSpec{ADIURL: adiURL, S6Status: string(ci.S6Proven), S6: &S6Spec{Contract: addrS(acct), LeafKey: hh(leaf)},
		Batch: BatchSpec{BatchRoot: hh(batch.BatchRoot), OperationID: hh(batch.OperationID), AccSetRoot: hh(batch.AccSetRoot), Incarnation: hh(batch.Incarnation)}}
	if variant == VariantS6Silent {
		ctx.S6Status, ctx.S6Reason, ctx.S6 = string(ci.S6Silent), "unsupported_generation", nil
	}
	reg := &Registry9Spec{Num: 2, Den: 3, CertenSetRoot: hh(setRoot), SignerCommitment: hh(pkcs[0])}
	for _, v := range sorted {
		reg.Members = append(reg.Members, MemberSpec{Address: addrS(v.addr), Power: v.power, BLSKey: hex.EncodeToString(v.key)})
	}
	ctx.Registry9 = reg
	spec.Context = ctx
	return spec, nil
}

// MarshalIndent is the canonical text of a Spec (sorted map keys, two-space indent): the content of world.json.
func (s *Spec) MarshalIndent() ([]byte, error) { return json.MarshalIndent(s, "", " ") }
