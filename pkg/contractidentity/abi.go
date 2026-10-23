// Copyright 2026 Certen Protocol

package contractidentity

// Strict ABI decoding of the exact tuple shapes S8 reads (steps 14 and 17): the calldata of executeComprehensiveProof, the calldata of the
// account's executeGovernanceProofDirect / batchExecuteGovernanceProofDirect, the aggregate-signature blob, and the data of the
// ProofExecuted, LeafConsumed, GovernanceOperationExecuted and GovernanceBatchExecuted logs.
//
// The decoder accepts exactly the canonical encoding a Solidity abi.encode (and every common client) produces, and nothing else:
//
//   - every offset must point to where the previous tail ended (the first tail starts right after the head), so tails are contiguous, in
//     head order, never overlapping and never out of order; an offset that is out of range, a gap, a back-reference and an offset shared by
//     two fields are all the same refusal (ABIOffset);
//   - every length is bounded by the bytes that remain AND by its cap BEFORE anything is allocated (an array of n elements needs n times the
//     element head in bytes; bytes and strings need ceil(len/32) words); the caps of Freeze item 1c are ABILimits.MaxLegs (64) and
//     ABILimits.MaxValidators (64); no input makes the decoder allocate more than a small multiple of its length;
//   - padding is canonical: bytes/string padding is zero, an address has its upper 12 bytes zero, a bool is 0 or 1, a uintN has no bits above
//     N, an enum is within its members;
//   - the selector is checked, and no byte may follow the padded tail (ABITrailing).
//
// A canonical-looking but malleable encoding (a gap, shared or reordered tails) that a chain would nevertheless accept is therefore
// undecodable here: the verifier states it as the named unproven reason (calldata_undecodable{field}), never as a weaker pass.

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ABIKind names why a decode refused.
type ABIKind string

// ABI refusal kinds.
const (
	ABISelector  ABIKind = "selector"
	ABITruncated ABIKind = "truncated"
	ABIOffset    ABIKind = "offset"
	ABILength    ABIKind = "length"
	ABICap       ABIKind = "cap"
	ABIPadding   ABIKind = "padding"
	ABIWord      ABIKind = "word"
	ABITrailing  ABIKind = "trailing"
	ABIShape     ABIKind = "shape"
)

// ABIError is a named decode refusal; Field is the path of the field (proof.keyBookProof, datas[3], ...).
type ABIError struct {
	Kind   ABIKind
	Field  string
	Offset int
	// Got and Limit carry the numbers of a cap or length refusal (a count against its bound).
	Got, Limit uint64
	Detail     string
}

func (e *ABIError) Error() string {
	s := fmt.Sprintf("abi %s at %q (byte %d)", e.Kind, e.Field, e.Offset)
	if e.Kind == ABICap || e.Kind == ABILength {
		s += fmt.Sprintf(": %d against %d", e.Got, e.Limit)
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// ABILimits are the bounds of the decoders besides the remaining input: Freeze item 1c max_batch_legs and max_validators.
type ABILimits struct {
	MaxLegs       int
	MaxValidators int
}

// DefaultABILimits are the item 1c values.
func DefaultABILimits() ABILimits {
	l := DefaultLimits()
	return ABILimits{MaxLegs: l.MaxBatchLegs, MaxValidators: l.MaxValidators}
}

// ---- the schema ----

type abiT struct {
	k       byte // u uint, a address, b bool, w bytes32, e enum(uint8, max), y bytes, s string, d dynamic array, f fixed array, t tuple
	bits    int
	max     uint64 // enum: highest member
	n       int    // fixed array length
	elem    *abiT
	fields  []abiF
	cap     int // dynamic array / bytes / string length bound (0: the remaining input only)
	capName string
}

type abiF struct {
	name string
	t    *abiT
}

type abiV struct {
	w     [32]byte
	b     []byte
	items []abiV
}

func tU(bits int) *abiT            { return &abiT{k: 'u', bits: bits} }
func tAddr() *abiT                 { return &abiT{k: 'a'} }
func tBool() *abiT                 { return &abiT{k: 'b'} }
func tB32() *abiT                  { return &abiT{k: 'w'} }
func tEnum(max uint64) *abiT       { return &abiT{k: 'e', max: max} }
func tBytes() *abiT                { return &abiT{k: 'y'} }
func tString() *abiT               { return &abiT{k: 's'} }
func tArr(e *abiT, cap int) *abiT  { return &abiT{k: 'd', elem: e, cap: cap} }
func tFix(e *abiT, n int) *abiT    { return &abiT{k: 'f', elem: e, n: n} }
func tTup(f ...abiF) *abiT         { return &abiT{k: 't', fields: f} }
func fd(name string, t *abiT) abiF { return abiF{name, t} }

func (t *abiT) dynamic() bool {
	switch t.k {
	case 'y', 's', 'd':
		return true
	case 'f':
		return t.elem.dynamic()
	case 't':
		for _, f := range t.fields {
			if f.t.dynamic() {
				return true
			}
		}
	}
	return false
}

// headSize is the bytes the value occupies in a head: 32 for a dynamic type (its offset), the whole encoding for a static one.
func (t *abiT) headSize() int {
	if t.dynamic() {
		return 32
	}
	switch t.k {
	case 'f':
		return t.n * t.elem.headSize()
	case 't':
		n := 0
		for _, f := range t.fields {
			n += f.t.headSize()
		}
		return n
	}
	return 32
}

type abiDec struct {
	buf []byte
}

func (d *abiDec) fail(kind ABIKind, field string, off int, detail string, args ...any) *ABIError {
	return &ABIError{Kind: kind, Field: field, Offset: off, Detail: fmt.Sprintf(detail, args...)}
}

func (d *abiDec) word(off int, field string) ([32]byte, *ABIError) {
	var w [32]byte
	if off < 0 || off+32 > len(d.buf) {
		return w, d.fail(ABITruncated, field, off, "need 32 bytes, %d remain", max(len(d.buf)-off, 0))
	}
	copy(w[:], d.buf[off:off+32])
	return w, nil
}

// length reads a length or count word that must fit the remaining input arithmetic.
func (d *abiDec) length(off int, field string) (uint64, *ABIError) {
	w, err := d.word(off, field)
	if err != nil {
		return 0, err
	}
	for _, c := range w[:24] {
		if c != 0 {
			return 0, &ABIError{Kind: ABILength, Field: field, Offset: off, Got: ^uint64(0), Limit: uint64(len(d.buf)), Detail: "length does not fit 64 bits"}
		}
	}
	return binary.BigEndian.Uint64(w[24:]), nil
}

func (d *abiDec) scalar(t *abiT, off int, field string) (abiV, *ABIError) {
	w, err := d.word(off, field)
	if err != nil {
		return abiV{}, err
	}
	zeroAbove := func(n int) bool { // the first n bytes of the word are zero
		for _, c := range w[:n] {
			if c != 0 {
				return false
			}
		}
		return true
	}
	switch t.k {
	case 'u':
		if t.bits < 256 && !zeroAbove(32-t.bits/8) {
			return abiV{}, d.fail(ABIWord, field, off, "value does not fit uint%d", t.bits)
		}
	case 'a':
		if !zeroAbove(12) {
			return abiV{}, d.fail(ABIWord, field, off, "address with non-zero high bytes")
		}
	case 'b':
		if !zeroAbove(31) || w[31] > 1 {
			return abiV{}, d.fail(ABIWord, field, off, "bool is neither 0 nor 1")
		}
	case 'e':
		if !zeroAbove(31) || uint64(w[31]) > t.max {
			return abiV{}, d.fail(ABIWord, field, off, "enum value outside 0..%d", t.max)
		}
	}
	return abiV{w: w}, nil
}

// decode decodes the value of type t whose encoding starts at off (the position of its head for a static type, of its tail data for a
// dynamic one) and returns it with the offset after its encoding.
func (d *abiDec) decode(t *abiT, off int, field string, lim ABILimits) (abiV, int, *ABIError) {
	switch t.k {
	case 'u', 'a', 'b', 'w', 'e':
		v, err := d.scalar(t, off, field)
		return v, off + 32, err
	case 'y', 's':
		n, err := d.length(off, field)
		if err != nil {
			return abiV{}, 0, err
		}
		rem := uint64(len(d.buf) - off - 32)
		if t.cap > 0 && n > uint64(t.cap) {
			return abiV{}, 0, &ABIError{Kind: ABICap, Field: field, Offset: off, Got: n, Limit: uint64(t.cap)}
		}
		padded := (n + 31) / 32 * 32
		if n > rem || padded > rem {
			return abiV{}, 0, &ABIError{Kind: ABILength, Field: field, Offset: off, Got: n, Limit: rem}
		}
		start := off + 32
		for _, c := range d.buf[start+int(n) : start+int(padded)] {
			if c != 0 {
				return abiV{}, 0, d.fail(ABIPadding, field, start+int(n), "non-zero padding after %d bytes", n)
			}
		}
		return abiV{b: append([]byte{}, d.buf[start:start+int(n)]...)}, start + int(padded), nil
	case 'd':
		n, err := d.length(off, field)
		if err != nil {
			return abiV{}, 0, err
		}
		if t.cap > 0 && n > uint64(t.cap) {
			return abiV{}, 0, &ABIError{Kind: ABICap, Field: field, Offset: off, Got: n, Limit: uint64(t.cap)}
		}
		rem := uint64(len(d.buf) - off - 32)
		per := uint64(t.elem.headSize())
		if n > rem/per { // each element needs at least its head
			return abiV{}, 0, &ABIError{Kind: ABILength, Field: field, Offset: off, Got: n, Limit: rem / per}
		}
		types := make([]*abiT, n)
		names := make([]string, n)
		for i := range types {
			types[i], names[i] = t.elem, fmt.Sprintf("%s[%d]", field, i)
		}
		items, end, err := d.seq(types, names, off+32, lim)
		return abiV{items: items}, end, err
	case 'f':
		types := make([]*abiT, t.n)
		names := make([]string, t.n)
		for i := range types {
			types[i], names[i] = t.elem, fmt.Sprintf("%s[%d]", field, i)
		}
		items, end, err := d.seq(types, names, off, lim)
		return abiV{items: items}, end, err
	default: // tuple
		types := make([]*abiT, len(t.fields))
		names := make([]string, len(t.fields))
		for i, f := range t.fields {
			types[i] = f.t
			if field == "" {
				names[i] = f.name
			} else {
				names[i] = field + "." + f.name
			}
		}
		items, end, err := d.seq(types, names, off, lim)
		return abiV{items: items}, end, err
	}
}

// seq decodes a head/tail sequence that starts at base (tuple members, array elements): static members inline in the head, dynamic ones
// through an offset relative to base that must be exactly where the previous tail ended.
func (d *abiDec) seq(types []*abiT, names []string, base int, lim ABILimits) ([]abiV, int, *ABIError) {
	head := 0
	for _, t := range types {
		head += t.headSize()
	}
	if base+head > len(d.buf) {
		return nil, 0, d.fail(ABITruncated, names0(names), base, "head of %d bytes, %d remain", head, len(d.buf)-base)
	}
	pos := base + head
	hp := base
	out := make([]abiV, len(types))
	for i, t := range types {
		if !t.dynamic() {
			v, _, err := d.decode(t, hp, names[i], lim)
			if err != nil {
				return nil, 0, err
			}
			out[i] = v
			hp += t.headSize()
			continue
		}
		o, err := d.length(hp, names[i])
		if err != nil {
			if err.Kind == ABILength { // a word that does not fit 64 bits is an impossible offset
				err.Kind = ABIOffset
			}
			return nil, 0, err
		}
		if o > uint64(len(d.buf)) || base+int(o) != pos {
			return nil, 0, d.fail(ABIOffset, names[i], hp, "offset %d points to byte %d, the previous tail ends at %d", o, base+int(min(o, uint64(len(d.buf)))), pos)
		}
		v, end, err := d.decode(t, pos, names[i], lim)
		if err != nil {
			return nil, 0, err
		}
		out[i] = v
		pos = end
		hp += 32
	}
	return out, pos, nil
}

func names0(n []string) string {
	if len(n) == 0 {
		return ""
	}
	return n[0]
}

// decodeArgs decodes args (calldata after the selector, or log data) as the tuple of types, with no byte left over.
func decodeArgs(args []byte, fields []abiF, lim ABILimits) ([]abiV, *ABIError) {
	d := &abiDec{buf: args}
	types := make([]*abiT, len(fields))
	names := make([]string, len(fields))
	for i, f := range fields {
		types[i], names[i] = f.t, f.name
	}
	items, end, err := d.seq(types, names, 0, lim)
	if err != nil {
		return nil, err
	}
	if end != len(args) {
		return nil, d.fail(ABITrailing, "", end, "%d bytes after the encoding", len(args)-end)
	}
	return items, nil
}

func splitSelector(calldata []byte, want [4]byte) ([]byte, *ABIError) {
	if len(calldata) < 4 {
		return nil, &ABIError{Kind: ABITruncated, Field: "selector", Detail: fmt.Sprintf("%d bytes", len(calldata))}
	}
	if [4]byte(calldata[:4]) != want {
		return nil, &ABIError{Kind: ABISelector, Field: "selector", Detail: fmt.Sprintf("got 0x%x, want 0x%x", calldata[:4], want[:])}
	}
	return calldata[4:], nil
}

// Selector4 is the 4-byte function selector of a canonical signature.
func Selector4(signature string) [4]byte { return [4]byte(crypto.Keccak256([]byte(signature))[:4]) }

// TopicOf is the event topic0 of a canonical signature.
func TopicOf(signature string) common.Hash {
	return common.BytesToHash(crypto.Keccak256([]byte(signature)))
}

// ---- value accessors ----

func (v abiV) big() *big.Int        { return new(big.Int).SetBytes(v.w[:]) }
func (v abiV) b32() [32]byte        { return v.w }
func (v abiV) addr() common.Address { return common.BytesToAddress(v.w[12:]) }
func (v abiV) boolean() bool        { return v.w[31] == 1 }
func (v abiV) u64() uint64          { return binary.BigEndian.Uint64(v.w[24:]) }
func (v abiV) u8() uint8            { return v.w[31] }
func (v abiV) b32s() [][32]byte {
	out := make([][32]byte, len(v.items))
	for i, it := range v.items {
		out[i] = it.w
	}
	return out
}

// ---- executeComprehensiveProof ----

// Signatures of the pinned generation (they equal the manifest selectors rows; TestABISelectorsEqualManifest).
const (
	SigExecuteComprehensiveProof = "executeComprehensiveProof(bytes32,(bytes32,bytes32,bytes32[],bytes32,(string,bytes32,bytes32[],address,uint8,uint256,uint256,uint256,bool),(bytes,address[],uint256[],uint256,uint256,bool,bytes32),(bytes32,bytes32,bytes32,bytes32,string,uint256,bytes32,string,address),uint256,bytes))"
	adiGovTuple                  = "(string,bytes32,bytes32[],bytes32,bytes,bytes,bytes,uint256,uint256,bytes,uint256,bytes32,uint64,uint64,uint64)"
	SigExecuteGovernanceDirect   = "executeGovernanceProofDirect(address,uint256,bytes," + adiGovTuple + ")"
	SigBatchGovernanceDirect     = "batchExecuteGovernanceProofDirect(address[],uint256[],bytes[]," + adiGovTuple + ")"
	SigProofExecuted             = "ProofExecuted(bytes32,bytes32,bool,bool,bool,uint256)"
	SigLeafConsumed              = "LeafConsumed(bytes32,bytes32,bytes32)"
	SigGovernanceOperation       = "GovernanceOperationExecuted(string,address,uint256,bytes,uint8)"
	SigGovernanceBatch           = "GovernanceBatchExecuted(string,bytes32,uint256,uint8)"
)

// AuthorityLevelMax is the highest member of the account's AuthorityLevel enum (NONE 0, OPERATOR 1, MANAGER 2, ADMIN 3, ROOT 4).
const AuthorityLevelMax = 4

func certenProofType(lim ABILimits) *abiT {
	return tTup(
		fd("transactionHash", tB32()), fd("merkleRoot", tB32()), fd("proofHashes", tArr(tB32(), 0)), fd("leafHash", tB32()),
		fd("governanceProof", tTup(
			fd("keyBookURL", tString()), fd("keyBookRoot", tB32()), fd("keyPageProofs", tArr(tB32(), 0)), fd("authorityAddress", tAddr()),
			fd("authorityLevel", tU(8)), fd("nonce", tU(256)), fd("requiredSignatures", tU(256)), fd("providedSignatures", tU(256)), fd("thresholdMet", tBool()))),
		fd("blsProof", tTup(
			fd("aggregateSignature", tBytes()), fd("validatorAddresses", &abiT{k: 'd', elem: tAddr(), cap: lim.MaxValidators, capName: "validators"}),
			fd("votingPowers", &abiT{k: 'd', elem: tU(256), cap: lim.MaxValidators, capName: "validators"}),
			fd("totalVotingPower", tU(256)), fd("signedVotingPower", tU(256)), fd("thresholdMet", tBool()), fd("messageHash", tB32()))),
		fd("commitments", tTup(
			fd("operationCommitment", tB32()), fd("crossChainCommitment", tB32()), fd("governanceRoot", tB32()), fd("executionCommitment", tB32()),
			fd("sourceChain", tString()), fd("sourceBlockHeight", tU(256)), fd("sourceTxHash", tB32()), fd("targetChain", tString()), fd("targetAddress", tAddr()))),
		fd("expirationTime", tU(256)), fd("metadata", tBytes()),
	)
}

// ComprehensiveProofCall is a decoded executeComprehensiveProof(anchorId, proof) transaction input.
type ComprehensiveProofCall struct {
	AnchorID        [32]byte
	TransactionHash [32]byte
	MerkleRoot      [32]byte
	ProofHashes     [][32]byte
	LeafHash        [32]byte
	Governance      struct {
		KeyBookURL                                    string
		KeyBookRoot                                   [32]byte
		KeyPageProofs                                 [][32]byte
		AuthorityAddress                              common.Address
		AuthorityLevel                                uint8
		Nonce, RequiredSignatures, ProvidedSignatures *big.Int
		ThresholdMet                                  bool
	}
	BLS struct {
		AggregateSignature                  []byte
		ValidatorAddresses                  []common.Address
		VotingPowers                        []*big.Int
		TotalVotingPower, SignedVotingPower *big.Int
		ThresholdMet                        bool
		MessageHash                         [32]byte
	}
	Commitments struct {
		OperationCommitment, CrossChainCommitment, GovernanceRoot, ExecutionCommitment [32]byte
		SourceChain                                                                    string
		SourceBlockHeight                                                              *big.Int
		SourceTxHash                                                                   [32]byte
		TargetChain                                                                    string
		TargetAddress                                                                  common.Address
	}
	ExpirationTime *big.Int
	Metadata       []byte
}

// DecodeComprehensiveProofCall decodes calldata of executeComprehensiveProof strictly (selector 0x4ca9d0c8, canonical encoding, caps,
// no trailing byte). validatorAddresses and votingPowers are bounded by lim.MaxValidators before allocation and must have equal length.
func DecodeComprehensiveProofCall(calldata []byte, lim ABILimits) (*ComprehensiveProofCall, error) {
	args, aerr := splitSelector(calldata, Selector4(SigExecuteComprehensiveProof))
	if aerr != nil {
		return nil, aerr
	}
	items, aerr := decodeArgs(args, []abiF{fd("anchorId", tB32()), fd("proof", certenProofType(lim))}, lim)
	if aerr != nil {
		return nil, aerr
	}
	p := items[1].items
	gov, bls, com := p[4].items, p[5].items, p[6].items
	var c ComprehensiveProofCall
	c.AnchorID = items[0].b32()
	c.TransactionHash, c.MerkleRoot, c.ProofHashes, c.LeafHash = p[0].b32(), p[1].b32(), p[2].b32s(), p[3].b32()
	c.Governance.KeyBookURL, c.Governance.KeyBookRoot, c.Governance.KeyPageProofs = string(gov[0].b), gov[1].b32(), gov[2].b32s()
	c.Governance.AuthorityAddress, c.Governance.AuthorityLevel = gov[3].addr(), gov[4].u8()
	c.Governance.Nonce, c.Governance.RequiredSignatures, c.Governance.ProvidedSignatures = gov[5].big(), gov[6].big(), gov[7].big()
	c.Governance.ThresholdMet = gov[8].boolean()
	c.BLS.AggregateSignature = bls[0].b
	if len(bls[1].items) != len(bls[2].items) {
		return nil, &ABIError{Kind: ABIShape, Field: "proof.blsProof.votingPowers", Got: uint64(len(bls[2].items)), Limit: uint64(len(bls[1].items)),
			Detail: "validatorAddresses and votingPowers differ in length"}
	}
	for i := range bls[1].items {
		c.BLS.ValidatorAddresses = append(c.BLS.ValidatorAddresses, bls[1].items[i].addr())
		c.BLS.VotingPowers = append(c.BLS.VotingPowers, bls[2].items[i].big())
	}
	c.BLS.TotalVotingPower, c.BLS.SignedVotingPower, c.BLS.ThresholdMet, c.BLS.MessageHash = bls[3].big(), bls[4].big(), bls[5].boolean(), bls[6].b32()
	c.Commitments.OperationCommitment, c.Commitments.CrossChainCommitment = com[0].b32(), com[1].b32()
	c.Commitments.GovernanceRoot, c.Commitments.ExecutionCommitment = com[2].b32(), com[3].b32()
	c.Commitments.SourceChain, c.Commitments.SourceBlockHeight, c.Commitments.SourceTxHash = string(com[4].b), com[5].big(), com[6].b32()
	c.Commitments.TargetChain, c.Commitments.TargetAddress = string(com[7].b), com[8].addr()
	c.ExpirationTime, c.Metadata = p[7].big(), p[8].b
	return &c, nil
}

// ZKBlob is the static ZKBLSSignatureProof of 18 words that blsProof.aggregateSignature carries (CertenAnchorV8_2.sol:575-585,
// BLSZKVerifierV2_1.sol:95-108): words 0-11 the Groth16 proof and commitments, 12 messageHash, 13 pubkeyCommitment, 14 and 15 the inner
// signed and total voting power, 16 and 17 the thresholds (ignored by the verifier).
type ZKBlob struct {
	Words                                    [18][32]byte
	MessageHash, PubkeyCommitment            [32]byte
	SignedVotingPower, TotalVotingPower      *big.Int
	ThresholdNumerator, ThresholdDenominator *big.Int
	// Length is the blob length; the anchor's abi.decode ignores bytes after the 18 words, so a longer blob is accepted (step 17: >= 576).
	Length int
}

// ZKBlobWords is the number of words the static proof occupies.
const ZKBlobWords = 18

// DecodeZKBlob reads the words of the aggregate-signature blob. A blob shorter than 18 words is ABITruncated.
func DecodeZKBlob(blob []byte) (*ZKBlob, error) {
	if len(blob) < ZKBlobWords*32 {
		return nil, &ABIError{Kind: ABITruncated, Field: "aggregateSignature", Got: uint64(len(blob)), Limit: ZKBlobWords * 32, Detail: "blob shorter than 18 words"}
	}
	z := &ZKBlob{Length: len(blob)}
	for i := 0; i < ZKBlobWords; i++ {
		copy(z.Words[i][:], blob[i*32:(i+1)*32])
	}
	z.MessageHash, z.PubkeyCommitment = z.Words[12], z.Words[13]
	z.SignedVotingPower, z.TotalVotingPower = new(big.Int).SetBytes(z.Words[14][:]), new(big.Int).SetBytes(z.Words[15][:])
	z.ThresholdNumerator, z.ThresholdDenominator = new(big.Int).SetBytes(z.Words[16][:]), new(big.Int).SetBytes(z.Words[17][:])
	return z, nil
}

// ---- the account settlement calls ----

// GovernanceProof is the ADIGovernanceProof tuple of the account's settlement calls (CertenAccountV7_3.sol:176-193), 15 head words.
type GovernanceProof struct {
	ADIURL              string
	AnchorID            [32]byte
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

// Leg is one (target, value, data) call of a settlement. Selector is bytes4(data[:4]), zero when len(data) < 4 (step 14).
type Leg struct {
	Target   common.Address
	Value    *big.Int
	Data     []byte
	Selector [4]byte
}

// SettlementCall is a decoded executeGovernanceProofDirect (one leg) or batchExecuteGovernanceProofDirect (1..max_batch_legs legs).
type SettlementCall struct {
	Selector [4]byte
	Batch    bool
	Legs     []Leg
	Proof    GovernanceProof
}

func adiGovType() *abiT {
	return tTup(fd("adiURL", tString()), fd("anchorId", tB32()), fd("merkleProof", tArr(tB32(), 0)), fd("operationID", tB32()),
		fd("keyBookProof", tBytes()), fd("roleProof", tBytes()), fd("thresholdProof", tBytes()), fd("timestamp", tU(256)), fd("expiresAt", tU(256)),
		fd("validatorSignatures", tBytes()), fd("nonce", tU(256)), fd("authorityBook", tB32()), fd("authorityPage", tU(64)),
		fd("notBefore", tU(64)), fd("notAfter", tU(64)))
}

func govProofOf(v abiV) GovernanceProof {
	p := v.items
	return GovernanceProof{ADIURL: string(p[0].b), AnchorID: p[1].b32(), MerkleProof: p[2].b32s(), OperationID: p[3].b32(),
		KeyBookProof: p[4].b, RoleProof: p[5].b, ThresholdProof: p[6].b, Timestamp: p[7].big(), ExpiresAt: p[8].big(),
		ValidatorSignatures: p[9].b, Nonce: p[10].big(), AuthorityBook: p[11].b32(), AuthorityPage: p[12].u64(), NotBefore: p[13].u64(), NotAfter: p[14].u64()}
}

func legSelector(data []byte) (s [4]byte) {
	if len(data) >= 4 {
		copy(s[:], data[:4])
	}
	return s
}

// DecodeSettlementCall decodes the calldata of the pinned account generation's two settlement functions (selectors 0x606f2c8d and 0x329fe012).
// A batch above lim.MaxLegs is ABICap{legs}; arrays of different lengths and an empty batch are ABIShape. Any other selector is ABISelector.
func DecodeSettlementCall(calldata []byte, lim ABILimits) (*SettlementCall, error) {
	if len(calldata) < 4 {
		return nil, &ABIError{Kind: ABITruncated, Field: "selector", Detail: fmt.Sprintf("%d bytes", len(calldata))}
	}
	sel := [4]byte(calldata[:4])
	switch sel {
	case Selector4(SigExecuteGovernanceDirect):
		items, err := decodeArgs(calldata[4:], []abiF{fd("target", tAddr()), fd("value", tU(256)), fd("data", tBytes()), fd("proof", adiGovType())}, lim)
		if err != nil {
			return nil, err
		}
		return &SettlementCall{Selector: sel, Legs: []Leg{{Target: items[0].addr(), Value: items[1].big(), Data: items[2].b, Selector: legSelector(items[2].b)}}, Proof: govProofOf(items[3])}, nil
	case Selector4(SigBatchGovernanceDirect):
		legs := func(name string, e *abiT) abiF {
			return fd(name, &abiT{k: 'd', elem: e, cap: lim.MaxLegs, capName: "legs"})
		}
		items, err := decodeArgs(calldata[4:], []abiF{legs("targets", tAddr()), legs("values", tU(256)), legs("datas", tBytes()), fd("proof", adiGovType())}, lim)
		if err != nil {
			return nil, err
		}
		n := len(items[0].items)
		if n == 0 {
			return nil, &ABIError{Kind: ABIShape, Field: "targets", Detail: "empty batch"}
		}
		if len(items[1].items) != n || len(items[2].items) != n {
			return nil, &ABIError{Kind: ABIShape, Field: "values", Got: uint64(len(items[1].items)), Limit: uint64(n), Detail: "targets, values and datas differ in length"}
		}
		c := &SettlementCall{Selector: sel, Batch: true, Proof: govProofOf(items[3])}
		for i := 0; i < n; i++ {
			c.Legs = append(c.Legs, Leg{Target: items[0].items[i].addr(), Value: items[1].items[i].big(), Data: items[2].items[i].b, Selector: legSelector(items[2].items[i].b)})
		}
		return c, nil
	}
	return nil, &ABIError{Kind: ABISelector, Field: "selector", Detail: fmt.Sprintf("0x%x is not a pinned settlement selector", sel[:])}
}

// ---- log data ----

// ProofExecutedLog is the data of ProofExecuted(bytes32 indexed anchorId, bytes32 transactionHash, bool merkleVerified, bool blsVerified,
// bool governanceVerified, uint256 timestamp).
type ProofExecutedLog struct {
	TransactionHash                                 [32]byte
	MerkleVerified, BLSVerified, GovernanceVerified bool
	Timestamp                                       *big.Int
}

// DecodeProofExecutedData decodes the 5-word data of a ProofExecuted log.
func DecodeProofExecutedData(data []byte) (*ProofExecutedLog, error) {
	it, err := decodeArgs(data, []abiF{fd("transactionHash", tB32()), fd("merkleVerified", tBool()), fd("blsVerified", tBool()), fd("governanceVerified", tBool()), fd("timestamp", tU(256))}, ABILimits{})
	if err != nil {
		return nil, err
	}
	return &ProofExecutedLog{it[0].b32(), it[1].boolean(), it[2].boolean(), it[3].boolean(), it[4].big()}, nil
}

// DecodeLeafConsumedData decodes the one-word data (operationID) of LeafConsumed(bytes32 indexed anchorId, bytes32 indexed leaf, bytes32 operationID).
func DecodeLeafConsumedData(data []byte) ([32]byte, error) {
	it, err := decodeArgs(data, []abiF{fd("operationID", tB32())}, ABILimits{})
	if err != nil {
		return [32]byte{}, err
	}
	return it[0].b32(), nil
}

// GovernanceOperationLog is the data of GovernanceOperationExecuted(string indexed adiURL, address indexed target, uint256 value, bytes data,
// AuthorityLevel requiredLevel): head word 2 is the level (step 14).
type GovernanceOperationLog struct {
	Value *big.Int
	Data  []byte
	Level uint8
}

// DecodeGovernanceOperationData decodes the data of GovernanceOperationExecuted; the level must be a member of the enum (0..4).
func DecodeGovernanceOperationData(data []byte) (*GovernanceOperationLog, error) {
	it, err := decodeArgs(data, []abiF{fd("value", tU(256)), fd("data", tBytes()), fd("requiredLevel", tEnum(AuthorityLevelMax))}, ABILimits{})
	if err != nil {
		return nil, err
	}
	return &GovernanceOperationLog{Value: it[0].big(), Data: it[1].b, Level: it[2].u8()}, nil
}

// GovernanceBatchLog is the data of GovernanceBatchExecuted(string indexed adiURL, bytes32 indexed anchorId, uint256 callCount,
// AuthorityLevel requiredLevel): head word 1 is the level.
type GovernanceBatchLog struct {
	CallCount *big.Int
	Level     uint8
}

// DecodeGovernanceBatchData decodes the 2-word data of GovernanceBatchExecuted; the level must be a member of the enum (0..4).
func DecodeGovernanceBatchData(data []byte) (*GovernanceBatchLog, error) {
	it, err := decodeArgs(data, []abiF{fd("callCount", tU(256)), fd("requiredLevel", tEnum(AuthorityLevelMax))}, ABILimits{})
	if err != nil {
		return nil, err
	}
	return &GovernanceBatchLog{CallCount: it[0].big(), Level: it[1].u8()}, nil
}
