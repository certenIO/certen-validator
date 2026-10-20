// Copyright 2026 Certen Protocol

// Package arbfinal is the Arbitrum Sepolia `finalized` level of V2_SPEC_S7 (kind arb-sepolia/finalized/v1, spec 3.3 and 5.7,
// annex R11-arbitrum-sepolia A2-A5): the offline verifier, the confirmation-path classifier and the build logic (capture, then
// attest). The offline half is pure: no I/O, no clock, no randomness. There is no init(); Register(reg) is called by the
// integration package.
//
// What the level proves, verbatim (spec 1.1): "an assertion with status Confirmed (normal path) read at a finalized L1 block
// commits an L2 block that has this block as ancestor." Nothing here claims more.
package arbfinal

import (
	"encoding/binary"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// KindName is the evidence kind of this package (spec section 1 table).
const KindName = "arb-sepolia/finalized/v1"

// Statement is the section 1.1 wording of what the level proves; the report shows it verbatim and nothing may strengthen it.
const Statement = "an assertion with status Confirmed (normal path) read at a finalized L1 block commits an L2 block that has this block as ancestor."

// maxHeaderBytes bounds one header of a spine (an L1 or L2 header is 0.5-0.7 KB); the bound only keeps a hostile length from
// allocating. It is a code constant of this package.
const maxHeaderBytes = 8192

// AfterState is the assertion's after-state (spec 3.3): B32 blockHash || B32 sendRoot || u64 inboxPosition || u64
// positionInMessage || u8 machineStatus || B32 endHistoryRoot.
type AfterState struct {
	BlockHash         [32]byte
	SendRoot          [32]byte
	InboxPosition     uint64
	PositionInMessage uint64
	MachineStatus     uint8
	EndHistoryRoot    [32]byte
}

// ParentConfig is the ConfigData of the assertion's parent (spec 3.3): B32 wasmModuleRoot || B32 requiredStake || B20
// challengeManager || u64 confirmPeriodBlocks || u64 nextInboxPosition.
type ParentConfig struct {
	WasmModuleRoot      [32]byte
	RequiredStake       [32]byte
	ChallengeManager    [20]byte
	ConfirmPeriodBlocks uint64
	NextInboxPosition   uint64
}

// Evidence is the body of an arb-sepolia/finalized/v1 container, after the CFE1 header:
//
//	LC || LIST<LP> l1Spine || u64 stateBlock || u64 confBlock || B32 parentAssertionHash || AfterState || B32 sequencerBatchAcc ||
//	ParentConfig || LIST<LP> l2Spine || u32 confTxIndex || LP confTxRaw || LP confReceiptRaw || NODES
type Evidence struct {
	LC                  ethl1.LC
	L1Spine             [][]byte
	StateBlock          uint64
	ConfBlock           uint64
	ParentAssertionHash [32]byte
	After               AfterState
	SequencerBatchAcc   [32]byte
	Parent              ParentConfig
	L2Spine             [][]byte
	ConfTxIndex         uint32
	ConfTxRaw           []byte
	ConfReceiptRaw      []byte
	Nodes               [][]byte
}

// Bounds are the counts the decoder enforces: the generic ones of finality.DefaultLimits and the pins' per-chain ones.
type Bounds struct {
	finality.Limits
	MaxLinks        int
	MaxSpineHeaders int
	MaxHeaderChain  int
}

// Encode renders the container body. Nodes are sorted and deduplicated into the canonical NODES order. It does not validate
// the evidence (the vector generator builds invalid evidence on purpose); Decode is the strict half.
func (e Evidence) Encode() []byte {
	var w finality.Writer
	w.Fixed(ethl1.EncodeLC(e.LC))
	w.LPList(e.L1Spine)
	w.U64(e.StateBlock)
	w.U64(e.ConfBlock)
	w.B32(e.ParentAssertionHash)
	w.B32(e.After.BlockHash)
	w.B32(e.After.SendRoot)
	w.U64(e.After.InboxPosition)
	w.U64(e.After.PositionInMessage)
	w.U8(e.After.MachineStatus)
	w.B32(e.After.EndHistoryRoot)
	w.B32(e.SequencerBatchAcc)
	w.B32(e.Parent.WasmModuleRoot)
	w.B32(e.Parent.RequiredStake)
	w.Fixed(e.Parent.ChallengeManager[:])
	w.U64(e.Parent.ConfirmPeriodBlocks)
	w.U64(e.Parent.NextInboxPosition)
	w.LPList(e.L2Spine)
	w.U32(e.ConfTxIndex)
	w.LP(e.ConfTxRaw)
	w.LP(e.ConfReceiptRaw)
	w.Nodes(finality.EncodeNodes(e.Nodes))
	return w.Bytes()
}

// readLC reads the LC part from the container stream (spec 3.2) into an ethl1.LC. Layout bytes and ssz lengths are judged by
// ethl1 itself; here only the framing is strict.
func readLC(r *finality.Reader, maxLinks int) (ethl1.LC, error) {
	var lc ethl1.LC
	var err error
	if lc.Profile, err = r.STR("lc.profile"); err != nil {
		return lc, err
	}
	k, err := r.U8("lc.anchorKind")
	if err != nil {
		return lc, err
	}
	lc.AnchorKind = k
	if lc.AnchorPeriod, err = r.U64("lc.anchorPeriod"); err != nil {
		return lc, err
	}
	if lc.AnchorRoot, err = r.B32("lc.anchorRoot"); err != nil {
		return lc, err
	}
	lb := func(part string) (ethl1.LB, error) {
		l, err := r.U8(part + ".layout")
		if err != nil {
			return ethl1.LB{}, err
		}
		ssz, err := r.LP(part, -1)
		if err != nil {
			return ethl1.LB{}, err
		}
		return ethl1.LB{Layout: ethl1.Layout(l), SSZ: ssz}, nil
	}
	if lc.AnchorBody, err = lb("lc.anchorBody"); err != nil {
		return lc, err
	}
	n, err := r.Count("lc.links", maxLinks, 5)
	if err != nil {
		return lc, err
	}
	lc.Links = make([]ethl1.LB, 0, n)
	for i := 0; i < n; i++ {
		l, err := lb("lc.link")
		if err != nil {
			return lc, err
		}
		lc.Links = append(lc.Links, l)
	}
	if lc.FinalUpdate, err = lb("lc.finalUpdate"); err != nil {
		return lc, err
	}
	return lc, nil
}

// readL2Spine reads LIST<LP> l2Spine. A count above max_header_chain is header_chain_exceeds_bound{needed, max}, judged before
// anything is allocated.
func readL2Spine(r *finality.Reader, max int) ([][]byte, error) {
	n, err := r.U32("l2Spine.count")
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(max) {
		return nil, HeaderChainExceeds(uint64(n), uint64(max))
	}
	if uint64(n)*lpPrefixBytes > uint64(r.Left()) {
		return nil, finality.Malformed("l2Spine", finality.ReasonCountExceedsRemaining, r.Left(), int(n)*4)
	}
	out := make([][]byte, 0, n)
	for i := 0; i < int(n); i++ {
		h, err := r.LP("l2Spine", maxHeaderBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// Decode parses a container body strictly: no trailing byte, every count within its bound before anything is allocated, NODES
// ascending and unique, and encode(decode(x)) == x.
func Decode(body []byte, b Bounds) (Evidence, error) {
	var e Evidence
	r := finality.NewReader(body, b.Limits)
	var err error
	if e.LC, err = readLC(r, b.MaxLinks); err != nil {
		return e, err
	}
	if e.L1Spine, err = r.LPList("l1Spine", b.MaxSpineHeaders, maxHeaderBytes); err != nil {
		return e, err
	}
	if e.StateBlock, err = r.U64("stateBlock"); err != nil {
		return e, err
	}
	if e.ConfBlock, err = r.U64("confBlock"); err != nil {
		return e, err
	}
	if e.ParentAssertionHash, err = r.B32("parentAssertionHash"); err != nil {
		return e, err
	}
	if e.After.BlockHash, err = r.B32("afterState.blockHash"); err != nil {
		return e, err
	}
	if e.After.SendRoot, err = r.B32("afterState.sendRoot"); err != nil {
		return e, err
	}
	if e.After.InboxPosition, err = r.U64("afterState.inboxPosition"); err != nil {
		return e, err
	}
	if e.After.PositionInMessage, err = r.U64("afterState.positionInMessage"); err != nil {
		return e, err
	}
	if e.After.MachineStatus, err = r.U8("afterState.machineStatus"); err != nil {
		return e, err
	}
	if e.After.EndHistoryRoot, err = r.B32("afterState.endHistoryRoot"); err != nil {
		return e, err
	}
	if e.SequencerBatchAcc, err = r.B32("sequencerBatchAcc"); err != nil {
		return e, err
	}
	if e.Parent.WasmModuleRoot, err = r.B32("parentConfig.wasmModuleRoot"); err != nil {
		return e, err
	}
	if e.Parent.RequiredStake, err = r.B32("parentConfig.requiredStake"); err != nil {
		return e, err
	}
	cm, err := r.Fixed("parentConfig.challengeManager", 20)
	if err != nil {
		return e, err
	}
	copy(e.Parent.ChallengeManager[:], cm)
	if e.Parent.ConfirmPeriodBlocks, err = r.U64("parentConfig.confirmPeriodBlocks"); err != nil {
		return e, err
	}
	if e.Parent.NextInboxPosition, err = r.U64("parentConfig.nextInboxPosition"); err != nil {
		return e, err
	}
	if e.L2Spine, err = readL2Spine(r, b.MaxHeaderChain); err != nil {
		return e, err
	}
	if e.ConfTxIndex, err = r.U32("confTxIndex"); err != nil {
		return e, err
	}
	if e.ConfTxRaw, err = r.LP("confTxRaw", b.MaxTxLeafBytes); err != nil {
		return e, err
	}
	if e.ConfReceiptRaw, err = r.LP("confReceiptRaw", b.MaxTxLeafBytes); err != nil {
		return e, err
	}
	if e.Nodes, err = r.Nodes("nodes", b.MaxTxLeafBytes); err != nil {
		return e, err
	}
	if err := r.End("body"); err != nil {
		return e, err
	}
	return e, nil
}

// BuildContainer wraps a body in the CFE1 container for the leg block.
func BuildContainer(leg finality.BlockRef, e Evidence) ([]byte, error) {
	return finality.Container{
		Header: finality.ContainerHeader{Kind: KindName, Chain: finality.ChainArbitrumSepolia, Level: finality.LevelFinalized, BlockNumber: leg.Number, BlockHash: leg.Hash},
		Body:   e.Encode(),
	}.Encode()
}

func u64be(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// lpPrefixBytes is the least size of one LP element (its u32 length); blockStep is the number step between a block and its parent.
const (
	lpPrefixBytes uint64 = 4
	blockStep     uint64 = 1
)
