// Copyright 2026 Certen Protocol

package adiri

import (
	"bytes"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// Link kinds of the body (V2_SPEC_S7 3.3).
const (
	LinkSpine = 1 // LIST<LP> spine: h_0 = F ... h_k = the leg block
	LinkSlot  = 2 // LP finalHeader || NODES: EIP-2935 account and slot N mod 8191 under stateRoot_F
)

// EIP2935Window is the ring size of the EIP-2935 history contract: under stateRoot_F the account holds the hashes of blocks
// F-1 down to F-8191, in slot (block number mod 8191).
const EIP2935Window = 8191

// MaxSlotDistance is the greatest F.number - N a linkKind 2 proof binds: 8190, one block inside the ring, the bound at which the
// spec's prover emits the form (V2_SPEC_S7 3.3 and annex A9: F.number - N <= 8190). A slot proves the hash of block N only for
// distances inside the ring; further back the same slot holds the hash of a later block with the same residue (block 9000 and block
// 809 share slot 809), so the distance is part of the claim and is judged here.
const MaxSlotDistance = EIP2935Window - 1

// Body is the adiri/finalized/v1 body after the CFE1 header: LP cfa1 || u8 linkKind || (1: LIST<LP> spine | 2: LP finalHeader
// || NODES).
type Body struct {
	CFA1        []byte
	LinkKind    uint8
	Spine       [][]byte // linkKind 1, descending from F to the leg block
	FinalHeader []byte   // linkKind 2
	Nodes       [][]byte // linkKind 2, strictly ascending by keccak256
}

// Encode is the canonical body.
func (b Body) Encode() []byte {
	var w finality.Writer
	w.LP(b.CFA1)
	w.U8(b.LinkKind)
	switch b.LinkKind {
	case LinkSpine:
		w.LPList(b.Spine)
	case LinkSlot:
		w.LP(b.FinalHeader)
		w.Nodes(finality.EncodeNodes(b.Nodes))
	}
	return w.Bytes()
}

// DecodeBody decodes strictly. The spine is bounded by min(maxHeaders, Limits.MaxSpineHeaders).
func DecodeBody(body []byte, lim finality.Limits, maxHeaders int) (*Body, error) {
	r := finality.NewReader(body, lim)
	var b Body
	var err error
	if b.CFA1, err = r.LP("cfa1", lim.MaxEvidenceBytes); err != nil {
		return nil, err
	}
	if b.LinkKind, err = r.U8("linkKind"); err != nil {
		return nil, err
	}
	switch b.LinkKind {
	case LinkSpine:
		limit := lim.MaxSpineHeaders
		if maxHeaders > 0 && maxHeaders < limit {
			limit = maxHeaders
		}
		if b.Spine, err = r.LPList("spine", limit, lim.MaxNodeBytes); err != nil {
			return nil, err
		}
		if len(b.Spine) == 0 {
			return nil, finality.Malformed("spine", finality.ReasonSpineEmpty, 0, 1)
		}
	case LinkSlot:
		if b.FinalHeader, err = r.LP("finalHeader", lim.MaxNodeBytes); err != nil {
			return nil, err
		}
		if b.Nodes, err = r.Nodes("nodes", lim.MaxNodeBytes); err != nil {
			return nil, err
		}
	default:
		return nil, finality.Malformed("linkKind", finality.ReasonLinkKindUnknown, int(b.LinkKind), 1)
	}
	if err := r.End("body"); err != nil {
		return nil, err
	}
	return &b, nil
}

// BuildContainer wraps a body in the CFE1 container for the leg block.
func BuildContainer(leg finality.BlockRef, b Body) ([]byte, error) {
	return finality.Container{
		Header: finality.ContainerHeader{Kind: Name, Chain: finality.ChainAdiri, Level: finality.LevelFinalized, BlockNumber: leg.Number, BlockHash: leg.Hash},
		Body:   b.Encode(),
	}.Encode()
}

// Verifier is the adiri/finalized/v1 Kind. Mode and Rand choose the signature strategy; the zero value verifies batched with
// crypto/rand, the form the TypeScript port uses.
type Verifier struct {
	Mode Mode
	Rand io.Reader
	Lim  *finality.Limits
}

// NewVerifier returns the production verifier: batched random linear combination.
func NewVerifier() *Verifier { return &Verifier{Mode: ModeBatched} }

func (v *Verifier) limits() finality.Limits {
	if v.Lim != nil {
		return *v.Lim
	}
	return finality.DefaultLimits()
}

var (
	_ finality.Kind      = (*Verifier)(nil)
	_ finality.Prover    = (*Prover)(nil)
	_ finality.Ceilinged = (*Prover)(nil)
)

// Name, Chain and Level implement finality.Kind.
func (v *Verifier) Name() string          { return Name }
func (v *Verifier) Chain() uint64         { return finality.ChainAdiri }
func (v *Verifier) Level() finality.Level { return finality.LevelFinalized }

// Register adds the Adiri Kind to reg. It is explicit: the package has no init(), and wiring into finality.Default is the
// integration package's job.
func Register(reg *finality.Registry) error { return reg.RegisterKind(NewVerifier()) }

// Verify judges the whole container (implements finality.Kind).
func (v *Verifier) Verify(p *finality.Pins, leg finality.BlockRef, evidence []byte) (finality.Verdict, error) {
	lim := v.limits()
	par, err := ParsePins(p)
	if err != nil {
		return finality.Verdict{}, err
	}
	if par.ChainID != finality.ChainAdiri {
		return finality.Verdict{}, PinMismatch("chain_id", finality.ChainAdiri, par.ChainID)
	}
	c, err := finality.DecodeContainer(evidence, lim)
	if err != nil {
		return finality.Verdict{}, err
	}
	h := c.Header
	if h.Kind != Name {
		return finality.Verdict{}, finality.EvidenceUnrecognised(h.Kind, "")
	}
	if h.Chain != finality.ChainAdiri {
		return finality.Verdict{}, PinMismatch("chain_id", par.ChainID, h.Chain)
	}
	if h.Level != finality.LevelFinalized {
		return finality.Verdict{}, finality.Malformed("header.level", finality.ReasonLevelNotFinalized, int(h.Level), 3)
	}
	if h.BlockNumber != leg.Number {
		return finality.Verdict{}, finality.BlockMismatch("blockNumber", leg.Number, h.BlockNumber)
	}
	if h.BlockHash != leg.Hash {
		return finality.Verdict{}, finality.BlockMismatch("blockHash", leg.Hash, h.BlockHash)
	}
	body, err := DecodeBody(c.Body, lim, par.MaxHeaders)
	if err != nil {
		return finality.Verdict{}, err
	}
	chain, err := DecodeCFA1(body.CFA1, lim)
	if err != nil {
		return finality.Verdict{}, err
	}
	res, err := VerifyCommitteeChain(par, chain, v.Mode, v.Rand)
	if err != nil {
		return finality.Verdict{}, err
	}
	link, err := verifyLink(par, res, body, leg)
	if err != nil {
		return finality.Verdict{}, err
	}
	shrunk := make([]string, len(res.Shrunk))
	for i, s := range res.Shrunk {
		shrunk[i] = string(s.Canonical())
	}
	fields := map[string]any{
		"epoch":                  res.Epoch,
		"chain_len":              res.Epoch + 1,
		"committee_size":         uint64(res.CommitteeSize),
		"signers":                uint64(res.Signers),
		"final_number":           res.Final.Number,
		"final_hash":             res.Final.Hash,
		"distance":               res.Final.Number - leg.Number,
		"link_kind":              uint64(body.LinkKind),
		"consensus_root_matches": link.consensusRootMatches,
		"committee_shrunk":       shrunk,
	}
	return finality.Verdict{Level: finality.LevelFinalized, Kind: Name, Fields: fields}, nil
}

type linkResult struct{ consensusRootMatches bool }

// verifyLink is O4: the seal R = record E with N <= F.number, and the link from F to the leg block.
func verifyLink(par *Params, res *ChainResult, body *Body, leg finality.BlockRef) (linkResult, error) {
	var out linkResult
	F := res.Final
	if leg.Number > F.Number {
		return out, LinkBroken(LinkBlockAfterSeal, F.Number, leg.Number, leg.Number)
	}
	switch body.LinkKind {
	case LinkSpine:
		return verifySpine(res, body.Spine, leg)
	default:
		return verifySlot(par, res, body, leg)
	}
}

// verifySpine: keccak256(h_0) = F.hash and number(h_0) = F.number; for i >= 1 keccak256(h_i) = parentHash(h_{i-1}) and
// number(h_i) = number(h_{i-1}) - 1; h_k is the leg's own header (byte-identical to Settlement.Header when the caller holds
// it, else equal by hash and number).
func verifySpine(res *ChainResult, spine [][]byte, leg finality.BlockRef) (linkResult, error) {
	var out linkResult
	if len(spine) == 0 { // DecodeBody refuses an empty spine; this function indexes the last header, so it states the same refusal itself
		return out, finality.Malformed("spine", finality.ReasonSpineEmpty, 0, 1)
	}
	F := res.Final
	var prev finality.HeaderFields
	for i, raw := range spine {
		h, err := finality.ReadHeader(raw)
		if err != nil {
			return out, LinkBroken(LinkHeaderDecode, F.Number, leg.Number, numberAt(F.Number, i), "index", uint64(i))
		}
		if i == 0 {
			if h.Hash != F.Hash || h.Number != F.Number {
				return out, LinkBroken(LinkTipNotFinalState, F.Number, leg.Number, h.Number, "want_hash", F.Hash, "got_hash", h.Hash)
			}
			out.consensusRootMatches = consensusRootOf(raw) == res.FinalConsensus.Hash
		} else {
			if h.Hash != prev.ParentHash {
				return out, HeaderChainBroken(numberBelow(prev.Number), prev.ParentHash, h.Hash, ReasonParentHash)
			}
			// wrap-free: a header after number 0 has no number below it, and h.Number+1 must not wrap to prev.Number
			if prev.Number == 0 || h.Number != prev.Number-1 {
				return out, HeaderChainBroken(numberBelow(prev.Number), prev.ParentHash, h.Hash, ReasonNumberGap)
			}
		}
		prev = h
	}
	last := spine[len(spine)-1]
	lastH, _ := finality.ReadHeader(last)
	if lastH.Number != leg.Number {
		return out, finality.BlockMismatch("spineLastNumber", leg.Number, lastH.Number)
	}
	if lastH.Hash != leg.Hash {
		return out, finality.BlockMismatch("spineLastHash", leg.Hash, lastH.Hash)
	}
	if leg.HeaderRLP != nil && !bytes.Equal(last, leg.HeaderRLP) {
		return out, finality.BlockMismatch("spineLastHeader", common.Bytes2Hex(crypto.Keccak256(leg.HeaderRLP)), common.Bytes2Hex(crypto.Keccak256(last)))
	}
	return out, nil
}

// numberAt is top - i, saturating at 0 (it only labels a refusal and must not wrap); numberBelow is n - 1, saturating at 0.
func numberAt(top uint64, i int) uint64 {
	if uint64(i) > top {
		return 0
	}
	return top - uint64(i)
}

func numberBelow(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return n - 1
}

// verifySlot: linkKind 2, only when N < F.number. The leg is bound first (F.number - N <= MaxSlotDistance; a non-zero hash, since
// a proven-absent slot reads as zero; and, when the caller holds the leg's header, keccak256(header) = the leg hash and the header
// carries the leg number), then keccak256(finalHeader) = F.hash and the EIP-2935 account (codeHash = pin) and storage slot
// N mod 8191 hold the leg block's hash under stateRoot_F. A zero proven slot value cannot equal the (non-zero) leg hash, so it is
// refused as slot_value_mismatch.
func verifySlot(par *Params, res *ChainResult, body *Body, leg finality.BlockRef) (linkResult, error) {
	var out linkResult
	F := res.Final
	if leg.Number == F.Number {
		return out, finality.Malformed("linkKind", finality.ReasonLinkKind2AtSeal, int(body.LinkKind), 1)
	}
	// verifyLink has refused N > F and the line above N = F, so this difference does not wrap
	if d := F.Number - leg.Number; d > MaxSlotDistance {
		return out, finality.BlockMismatch("slotDistance", uint64(MaxSlotDistance), d)
	}
	if leg.Hash == ([32]byte{}) {
		return out, finality.BlockMismatch("legHash", "nonzero", leg.Hash)
	}
	if leg.HeaderRLP != nil {
		lh, err := finality.ReadHeader(leg.HeaderRLP)
		if err != nil {
			return out, LinkBroken(LinkHeaderDecode, F.Number, leg.Number, leg.Number)
		}
		if lh.Hash != leg.Hash {
			return out, finality.BlockMismatch("legHeaderHash", leg.Hash, lh.Hash)
		}
		if lh.Number != leg.Number {
			return out, finality.BlockMismatch("legHeaderNumber", leg.Number, lh.Number)
		}
	}
	h, err := finality.ReadHeader(body.FinalHeader)
	if err != nil {
		return out, LinkBroken(LinkHeaderDecode, F.Number, leg.Number, F.Number)
	}
	if h.Hash != F.Hash || h.Number != F.Number {
		return out, LinkBroken(LinkTipNotFinalState, F.Number, leg.Number, h.Number, "want_hash", F.Hash, "got_hash", h.Hash)
	}
	out.consensusRootMatches = consensusRootOf(body.FinalHeader) == res.FinalConsensus.Hash
	slot := common.BigToHash(new(big.Int).SetUint64(leg.Number % EIP2935Window))
	sr, err := ethproof.VerifyStorage(common.Hash(h.StateRoot), par.EIP2935Address, body.Nodes, slot, body.Nodes)
	if err != nil {
		return out, LinkBroken(LinkProofInvalid, F.Number, leg.Number, leg.Number)
	}
	if !sr.Account.Exists || sr.Account.CodeHash != common.Hash(par.EIP2935CodeHash) {
		return out, LinkBroken(LinkCodeHashMismatch, F.Number, leg.Number, leg.Number, "want", par.EIP2935CodeHash, "got", [32]byte(sr.Account.CodeHash))
	}
	if sr.Value != common.Hash(leg.Hash) {
		return out, LinkBroken(LinkSlotValueMismatch, F.Number, leg.Number, leg.Number, "want", leg.Hash, "got", [32]byte(sr.Value))
	}
	return out, nil
}

// consensusRootOf reads item 19 (parentBeaconBlockRoot) of a header, or the zero hash when absent; reported, never required.
func consensusRootOf(raw []byte) [32]byte {
	var out [32]byte
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		return out
	}
	for i := 0; len(content) > 0; i++ {
		_, val, tail, err := rlp.Split(content)
		if err != nil {
			return out
		}
		if i == 19 && len(val) == 32 {
			copy(out[:], val)
			return out
		}
		content = tail
	}
	return out
}
