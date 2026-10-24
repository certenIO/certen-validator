// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
)

// Item names of the attestation station.
const (
	ItemAttest       = "attest"
	ItemAttestStated = "attest/stated"
)

// AttestSource is what E1 and the link assembly read besides a Source: headers by hash and whole blocks, both from the agreed reader.
type AttestSource interface {
	Source
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	// Block is the agreed header of the block with this hash and the consensus encodings of all its transactions and receipts, already
	// checked against the header's roots (ethproof.ReadBlock).
	Block(ctx context.Context, hash common.Hash) (*ethproof.Block, error)
}

// AttestRequest is the trigger of E1: the transaction that executed executeComprehensiveProof for the anchor (the submitter's receipt of it,
// or the first sight of its ProofExecuted log by any other validator, whichever is first).
type AttestRequest struct {
	TxHash common.Hash
	// AnchorID is the anchor id the trigger saw (the ProofExecuted topic): it keys a Stated result when the receipt shows no such log.
	AnchorID common.Hash
}

// AttestResult is the outcome of E1 at the attestation block B_v: its station reads (both state roots, the transaction and the receipt), the
// block's whole transaction list, and the codes it read; or the Stated part saying why nothing was captured. It is shared by every member
// leg of the batch and holds no link to a settlement block: BuildAttestPart adds the link once the settlement block is known.
type AttestResult struct {
	Chain         uint64
	AnchorID      common.Hash
	Block         ci.BlockRef // B_v
	OperationID   common.Hash
	PKC           common.Hash
	TxIndex       uint32
	HeaderV       []byte
	HeaderVParent []byte
	TxLeaf        []byte
	ReceiptLeaf   []byte
	BlockTxs      [][]byte
	Codes         []ci.Code // ascending by address
	Nodes         [][]byte  // canonical: exactly the nodes the attestation block's reads visit
	Stated        *ci.Stated
}

// ErrNotAttestation: the receipt is no successful executeComprehensiveProof of the chain's anchor; E1 is triggered by ProofExecuted only.
var ErrNotAttestation = errors.New("capture: the transaction is not a successful attestation of the anchor")

func detailBlockTooLarge(unit string, n, limit int) string {
	return fmt.Sprintf("%s=%d;limit=%d", unit, n, limit)
}

// CaptureAttest is E1. It reads the attestation block B_v: the agreed header, the whole transaction list (rule IB), the transaction and the
// receipt with their proofs, and, at B_v-1 and at B_v, the AUTH slot set, the verifier chain and the owner accounts with the codes the
// plan needs; every proof is verified against the agreed state root before it is kept, every code against its proven code hash. A block over
// the caps is Stated{block_too_large, bytes|txs, limit}; state no provider serves within the budget is Stated{attest_block_state_unavailable}
// (the only possible outcome on Adiri unless the operator's own node serves depth 1); a receipt without the ProofExecuted log of the anchor is
// Stated{attest_event_not_found}. Like CaptureSettle it spawns no goroutine of its own beyond the bounded provider calls it joins, holds its
// gate slot under defer and recovers a panic into a PanicError.
func CaptureAttest(ctx context.Context, cfg Config, req AttestRequest) (res *AttestResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, &PanicError{Value: asciiText(fmt.Sprint(r))}
		}
	}()
	if err := cfg.check(); err != nil {
		return nil, err
	}
	src, ok := cfg.Source.(AttestSource)
	if !ok {
		return nil, errors.New("capture: Config.Source does not serve blocks (AttestSource)")
	}
	clock := cfg.clock()
	parent := ctx
	ctx, cancel := clock.WithDeadline(ctx, clock.Now().Add(cfg.budget()))
	defer cancel()

	rc, rerr := src.TransactionReceipt(ctx, req.TxHash)
	if rerr != nil || rc == nil || rc.BlockNumber == nil {
		return nil, unreadable("attestation receipt", rerr)
	}
	if rc.Status != 1 || rc.TxHash != req.TxHash {
		return nil, fmt.Errorf("%w: status %d", ErrNotAttestation, rc.Status)
	}
	bv := ci.BlockRef{Number: rc.BlockNumber.Uint64(), Hash: [32]byte(rc.BlockHash)}
	m := cfg.Manifest
	anchor, aok := m.Deployment(cfg.Chain, "anchor")
	top, tok := m.Topic("ProofExecuted")
	if !aok || !tok {
		return nil, errors.New("capture: the manifest has no anchor row or ProofExecuted topic for the chain")
	}
	res = &AttestResult{Chain: cfg.Chain, Block: bv, AnchorID: req.AnchorID}
	var anchorID common.Hash
	found := false
	for _, l := range rc.Logs {
		if l.Address == common.HexToAddress(anchor.Address) && len(l.Topics) >= 2 && l.Topics[0] == common.HexToHash(top.Topic0) {
			anchorID, found = l.Topics[1], true
			break
		}
	}
	if !found {
		res.Stated = stated(ci.StatedAttestEventNotFound, bv, nil, "no ProofExecuted log of the anchor in the receipt")
		return res, nil
	}
	res.AnchorID = anchorID

	blk, berr := src.Block(ctx, rc.BlockHash)
	var ue *UnavailableError
	switch {
	case berr == nil:
	case parent.Err() != nil:
		return nil, parent.Err()
	default:
		res.Stated = stated(ci.StatedStateUnavailable, bv, []ci.ProviderFailure{{Host: "agreed", Error: asciiText(berr.Error())}}, "the attestation block")
		return res, nil
	}
	if blk == nil || blk.Header == nil || blk.Header.Hash() != rc.BlockHash || blk.Header.Number.Uint64() != bv.Number {
		return nil, errors.New("capture: the agreed block is not the receipt's block")
	}
	lim := ci.DefaultLimits()
	total := 0
	for _, t := range blk.Txs {
		total += len(t)
	}
	switch {
	case len(blk.Txs) > lim.MaxBlockTxs:
		res.Stated = stated(ci.StatedBlockTooLarge, bv, nil, detailBlockTooLarge("txs", len(blk.Txs), lim.MaxBlockTxs))
		return res, nil
	case total > lim.MaxBlockTxsBytes:
		res.Stated = stated(ci.StatedBlockTooLarge, bv, nil, detailBlockTooLarge("bytes", total, lim.MaxBlockTxsBytes))
		return res, nil
	}
	idx := int(rc.TransactionIndex)
	if idx < 0 || idx >= len(blk.Txs) || crypto.Keccak256Hash(blk.Txs[idx]) != req.TxHash {
		return nil, errors.New("capture: the block does not hold the attestation at the receipt's index")
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(blk.Txs[idx]); err != nil {
		return nil, fmt.Errorf("capture: attestation transaction: %v", err)
	}
	call, cerr := decodeAttestCall(&tx, common.HexToAddress(anchor.Address), anchorID)
	if cerr != nil {
		res.Stated = stated(ci.StatedStateUnavailable, bv, nil, "the attestation is not a direct executeComprehensiveProof call: "+cerr.Error())
		return res, nil
	}
	pb, perr := src.HeaderByHash(ctx, blk.Header.ParentHash)
	if perr != nil || pb == nil || pb.Hash() != blk.Header.ParentHash || pb.Number.Uint64()+1 != bv.Number {
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		res.Stated = stated(ci.StatedAttestBlockStateUnavailable, bv, []ci.ProviderFailure{{Host: "agreed", Error: asciiText(fmt.Sprint(perr))}}, "the parent header of the attestation block")
		return res, nil
	}
	hv, err1 := rlp.EncodeToBytes(blk.Header)
	hp, err2 := rlp.EncodeToBytes(pb)
	if err1 != nil || err2 != nil || crypto.Keccak256Hash(hv) != blk.Header.Hash() || crypto.Keccak256Hash(hp) != pb.Hash() {
		return nil, errors.New("capture: a header does not re-encode to its hash")
	}
	res.OperationID, res.PKC, res.TxIndex = call.op, call.pkc, uint32(idx)
	res.HeaderV, res.HeaderVParent, res.TxLeaf, res.ReceiptLeaf, res.BlockTxs = hv, hp, blk.Txs[idx], blk.Receipts[idx], blk.Txs

	if cfg.Gate != nil {
		release, gerr := cfg.Gate.Acquire(ctx)
		if gerr != nil {
			if parent.Err() != nil {
				return nil, parent.Err()
			}
			res.Stated = stated(ci.StatedCaptureNotAttemptedInWindow, bv, nil, "no capture slot within the budget")
			res.HeaderV, res.HeaderVParent, res.TxLeaf, res.ReceiptLeaf, res.BlockTxs = nil, nil, nil, nil, nil
			return res, nil
		}
		defer release()
	}

	facts := &Facts{Chain: cfg.Chain, Manifest: m, AnchorID: anchorID, OperationID: call.op, PKC: call.pkc, TxIndex: uint32(idx)}
	roots := map[string]blockAt{StationPre: {pb.Number.Uint64(), pb.Root}, StationPost: {bv.Number, blk.Header.Root}}
	col := newCollector(&cfg, roots)
	col.blk = &blockLists{txs: blk.Txs, receipts: blk.Receipts, txRoot: blk.Header.TxHash, receiptRoot: blk.Header.ReceiptHash}
	runErr := col.run(ctx, func(rd Reader) (bool, error) { return RunAttest(rd, facts) })
	switch {
	case runErr == nil:
	case parent.Err() != nil:
		return nil, parent.Err()
	case errors.As(runErr, &ue):
		res.Stated = stated(ci.StatedAttestBlockStateUnavailable, bv, ue.Failures, ue.What)
		res.HeaderV, res.HeaderVParent, res.TxLeaf, res.ReceiptLeaf, res.BlockTxs = nil, nil, nil, nil, nil
		return res, nil
	default:
		return nil, runErr
	}
	pool := make([][]byte, 0, len(col.pool))
	for _, n := range col.pool {
		pool = append(pool, n)
	}
	ns, nerr := ci.NewNodeSet(sortNodes(pool))
	if nerr != nil {
		return nil, nerr
	}
	st := newStrict(ns, map[string]common.Hash{StationPre: pb.Root, StationPost: blk.Header.Root}, sortCodes(col.codes, nil))
	st.txRoot, st.rcRoot = blk.Header.TxHash, blk.Header.ReceiptHash
	if pending, perr := RunAttest(st, facts); perr != nil || pending {
		return nil, &PlanError{Station: StationPost, Reason: "verified_pool_does_not_replay", Err: perr}
	}
	res.Nodes = sortNodes(ns.VisitedNodes())
	res.Codes = sortCodes(col.codes, func(a common.Address) bool { return st.proven[a] })
	size := total
	for _, n := range res.Nodes {
		size += len(n)
	}
	for _, c := range res.Codes {
		size += len(c.Runtime)
	}
	if size > lim.MaxContainerBytes {
		return nil, fmt.Errorf("%w: the attestation station alone is %d bytes", ErrTooLarge, size)
	}
	return res, nil
}

type attestCall struct{ op, pkc common.Hash }

// decodeAttestCall is step 17's strict decode of the attestation: a direct call of the anchor's executeComprehensiveProof for this anchor.
func decodeAttestCall(tx *types.Transaction, anchor common.Address, anchorID common.Hash) (attestCall, error) {
	if tx.To() == nil || *tx.To() != anchor {
		return attestCall{}, errors.New("the transaction is not sent to the anchor")
	}
	call, err := ci.DecodeComprehensiveProofCall(tx.Data(), ci.DefaultABILimits())
	if err != nil {
		return attestCall{}, err
	}
	if common.Hash(call.AnchorID) != anchorID {
		return attestCall{}, errors.New("the call names another anchor id than the log")
	}
	blob, err := ci.DecodeZKBlob(call.BLS.AggregateSignature)
	if err != nil {
		return attestCall{}, err
	}
	return attestCall{op: call.Commitments.OperationCommitment, pkc: blob.PubkeyCommitment}, nil
}

// ---- the link ----

// LinkPlan is how B_v is tied to the settlement block N: the link kind and, for link 1, the numbers of H_0 (= B_v), H_1 .. H_k.
type LinkPlan struct {
	Link       uint8
	HopNumbers []uint64
}

// OutOfReachError: the gap between B_v and N exceeds the history window and no hop chain is carried (the named limit, Q2).
type OutOfReachError struct {
	Gap, Window uint64
	HopsCarried int
	LastHop     uint64
}

func (e *OutOfReachError) Error() string {
	return fmt.Sprintf("capture: attest_block_out_of_reach gap=%d window=%d hops_carried=%d last_hop=%d", e.Gap, e.Window, e.HopsCarried, e.LastHop)
}

// DefaultMaxSpine is the largest gap tied by a header spine rather than by the EIP-2935 history contract: a spine of a few headers is
// cheaper than a state proof of the history contract, and needs none.
const DefaultMaxSpine = 16

// ChooseLink decides the link of B_v to N: the same block (link 0), a header spine up to maxSpine headers (link 2), the history contract
// with no intermediate hop while the gap fits its window (link 1, k = 0), or, beyond the window, the hop chain of WP-S8-3c: without it the
// leg is OutOfReachError. A chain without a history contract uses the spine up to the container's cap.
func ChooseLink(m *ci.Manifest, chain, bv, n uint64, maxSpine int) (LinkPlan, error) {
	if maxSpine <= 0 {
		maxSpine = DefaultMaxSpine
	}
	if n < bv {
		return LinkPlan{}, fmt.Errorf("capture: the settlement block %d is before the attestation block %d", n, bv)
	}
	gap := n - bv
	if gap == 0 {
		return LinkPlan{Link: ci.LinkSameBlock}, nil
	}
	e, has := m.EIP2935(chain)
	if gap <= uint64(maxSpine) || (!has && gap <= uint64(ci.DefaultLimits().MaxAttestSpine)) {
		return LinkPlan{Link: ci.LinkSpine}, nil
	}
	if !has || gap > e.Window {
		var w uint64
		if has {
			w = e.Window
		}
		return LinkPlan{}, &OutOfReachError{Gap: gap, Window: w, LastHop: bv}
	}
	return LinkPlan{Link: ci.LinkHops, HopNumbers: []uint64{bv}}, nil
}

// OutOfReachStated is the Stated attest part of a leg whose gap no carried link covers.
func OutOfReachStated(e *OutOfReachError, bv ci.BlockRef) *ci.Stated {
	return stated(ci.StatedAttestBlockOutOfReach, bv, nil, fmt.Sprintf("gap=%d;window=%d;hops_carried=%d;last_hop=%d", e.Gap, e.Window, e.HopsCarried, e.LastHop))
}

// ErrNotAncestor: B_v is not an ancestor of the settlement block (a reorg between the attestation and the settlement).
var ErrNotAncestor = errors.New("capture: the attestation block is not an ancestor of the settlement block")

// BuildAttestPart is the attest part of a container: the E1 result tied to the settlement block by plan. A Stated result is the Stated part.
// For link 2 the spine is read from the agreed reader, descending from the parent of the settlement header to B_v, and must end at B_v by
// hash. For link 1 the hop headers are those of the tick chain (E1b); a plan with k = 0 carries none.
func BuildAttestPart(ctx context.Context, src AttestSource, r *AttestResult, settleHeader *types.Header, plan LinkPlan, hopHeaders [][]byte) (*AttestPart, error) {
	if r == nil {
		return nil, ErrNoParts
	}
	if r.Stated != nil {
		return &AttestPart{Stated: r.Stated}, nil
	}
	proof := &ci.AttestProof{Link: plan.Link, HeaderV: r.HeaderV, HeaderVParent: r.HeaderVParent, TxIndex: r.TxIndex, TxLeaf: r.TxLeaf, ReceiptLeaf: r.ReceiptLeaf, BlockTxs: r.BlockTxs}
	switch plan.Link {
	case ci.LinkSameBlock:
		if settleHeader.Hash() != common.Hash(r.Block.Hash) {
			return nil, ErrNotAncestor
		}
	case ci.LinkSpine:
		h := settleHeader
		for h.Number.Uint64() > r.Block.Number {
			p, err := src.HeaderByHash(ctx, h.ParentHash)
			if err != nil {
				return nil, fmt.Errorf("capture: spine header %s: %w", h.ParentHash.Hex(), err)
			}
			if p == nil || p.Hash() != h.ParentHash || p.Number.Uint64()+1 != h.Number.Uint64() {
				return nil, errors.New("capture: the agreed spine header is not the parent asked for")
			}
			raw, err := rlp.EncodeToBytes(p)
			if err != nil || crypto.Keccak256Hash(raw) != p.Hash() {
				return nil, errors.New("capture: a spine header does not re-encode to its hash")
			}
			proof.Spine = append(proof.Spine, raw)
			h = p
		}
		if h.Hash() != common.Hash(r.Block.Hash) || len(proof.Spine) == 0 {
			return nil, ErrNotAncestor
		}
	case ci.LinkHops:
		if len(plan.HopNumbers) != len(hopHeaders)+1 || plan.HopNumbers[0] != r.Block.Number {
			return nil, fmt.Errorf("capture: %d hop headers do not match the hop numbers %v", len(hopHeaders), plan.HopNumbers)
		}
		proof.HopHeaders = hopHeaders
	default:
		return nil, fmt.Errorf("capture: unknown link %d", plan.Link)
	}
	return &AttestPart{Proof: proof, Codes: r.Codes, Nodes: r.Nodes}, nil
}

// ---- storage ----

const attestMagic = "CAE1"

// EncodeAttest is the canonical row of a captured attestation station.
func EncodeAttest(r *AttestResult) ([]byte, error) {
	if r == nil || r.Stated != nil {
		return nil, errors.New("capture: EncodeAttest needs a captured result")
	}
	lim := ci.DefaultLimits()
	var w wbuf
	w.raw([]byte(attestMagic))
	w.u64(r.Block.Number)
	w.raw(r.Block.Hash[:])
	w.raw(r.AnchorID[:])
	w.raw(r.OperationID[:])
	w.raw(r.PKC[:])
	w.u32(int(r.TxIndex))
	w.lp(r.HeaderV)
	w.lp(r.HeaderVParent)
	w.lp(r.TxLeaf)
	w.lp(r.ReceiptLeaf)
	if len(r.BlockTxs) > lim.MaxBlockTxs {
		return nil, ErrItemTooLarge
	}
	w.u32(len(r.BlockTxs))
	for _, t := range r.BlockTxs {
		w.lp(t)
	}
	w.u32(len(r.Codes))
	for i, c := range r.Codes {
		if i > 0 && bytes.Compare(r.Codes[i-1].Address[:], c.Address[:]) >= 0 {
			return nil, errors.New("capture: codes are not ascending and unique")
		}
		w.raw(c.Address[:])
		w.lp(c.Runtime)
	}
	w.u32(len(r.Nodes))
	for i, n := range r.Nodes {
		if i > 0 && !hashLess(r.Nodes[i-1], n) {
			return nil, errors.New("capture: nodes are not ascending by keccak256 and unique")
		}
		w.lp(n)
	}
	if len(w.b) > MaxItemBytes() {
		return nil, ErrItemTooLarge
	}
	return w.b, nil
}

// DecodeAttest is the strict inverse of EncodeAttest.
func DecodeAttest(raw []byte) (*AttestResult, error) {
	lim := ci.DefaultLimits()
	r := &rbuf{b: raw}
	if string(r.take(4)) != attestMagic {
		return nil, errors.New("capture: not an attest row")
	}
	res := &AttestResult{}
	res.Block.Number = r.u64()
	copy(res.Block.Hash[:], r.take(32))
	copy(res.AnchorID[:], r.take(32))
	copy(res.OperationID[:], r.take(32))
	copy(res.PKC[:], r.take(32))
	res.TxIndex = uint32(r.u32())
	res.HeaderV = append([]byte(nil), r.lp()...)
	res.HeaderVParent = append([]byte(nil), r.lp()...)
	res.TxLeaf = append([]byte(nil), r.lp()...)
	res.ReceiptLeaf = append([]byte(nil), r.lp()...)
	nt := r.u32()
	if nt > lim.MaxBlockTxs {
		return nil, errors.New("capture: too many block transactions")
	}
	total := 0
	for i := 0; i < nt && r.err == nil; i++ {
		t := append([]byte(nil), r.lp()...)
		if total += len(t); total > lim.MaxBlockTxsBytes {
			return nil, errors.New("capture: block transactions exceed the byte bound")
		}
		res.BlockTxs = append(res.BlockTxs, t)
	}
	nc := r.u32()
	if nc > lim.MaxCodes {
		return nil, errors.New("capture: too many codes")
	}
	for i := 0; i < nc && r.err == nil; i++ {
		var c ci.Code
		copy(c.Address[:], r.take(20))
		c.Runtime = append([]byte(nil), r.lp()...)
		if i > 0 && bytes.Compare(res.Codes[i-1].Address[:], c.Address[:]) >= 0 {
			return nil, errors.New("capture: codes are not ascending and unique")
		}
		res.Codes = append(res.Codes, c)
	}
	nn := r.u32()
	if nn > lim.MaxNodes {
		return nil, errors.New("capture: too many nodes")
	}
	for i := 0; i < nn && r.err == nil; i++ {
		n := append([]byte(nil), r.lp()...)
		if i > 0 && !hashLess(res.Nodes[i-1], n) {
			return nil, errors.New("capture: nodes are not ascending by keccak256 and unique")
		}
		res.Nodes = append(res.Nodes, n)
	}
	if r.err != nil {
		return nil, fmt.Errorf("capture: attest row: %v", r.err)
	}
	if len(r.b) != 0 {
		return nil, errors.New("capture: attest row has trailing bytes")
	}
	return res, nil
}

// SaveAttest stores a result under (chain, anchor, B_v hash): the captured row to ItemAttest, a Stated result to ItemAttestStated. The
// store's conflict semantics are those of SaveSettle.
func SaveAttest(ctx context.Context, st Store, r *AttestResult) error {
	k := Key{Chain: r.Chain, AnchorID: r.AnchorID, BlockHash: r.Block.Hash}
	var raw []byte
	var err error
	if r.Stated != nil {
		k.Item = ItemAttestStated
		raw, err = EncodeStated(r.Stated)
	} else {
		k.Item = ItemAttest
		raw, err = EncodeAttest(r)
	}
	if err != nil {
		return err
	}
	return st.Put(ctx, k, raw)
}

// LoadAttest returns the stored attestation station of (chain, anchor, B_v hash): the captured row when there is one, else the Stated row.
func LoadAttest(ctx context.Context, st Store, chain uint64, anchorID, blockHash [32]byte) (*AttestResult, error) {
	k := Key{Chain: chain, AnchorID: anchorID, BlockHash: blockHash, Item: ItemAttest}
	if raw, ok, err := st.Get(ctx, k); err != nil {
		return nil, err
	} else if ok {
		r, err := DecodeAttest(raw)
		if err != nil {
			return nil, err
		}
		r.Chain = chain
		return r, nil
	}
	k.Item = ItemAttestStated
	raw, ok, err := st.Get(ctx, k)
	if err != nil || !ok {
		return nil, err
	}
	s, err := DecodeStated(raw)
	if err != nil {
		return nil, err
	}
	return &AttestResult{Chain: chain, AnchorID: anchorID, Block: ci.BlockRef{Number: s.JudgedBlock, Hash: s.JudgedHash}, Stated: s}, nil
}
