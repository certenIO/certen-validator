// Copyright 2026 Certen Protocol

package build

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// The pending reasons this prover produces (the closed set of testdata/finality/states.json, spec section 7).
const (
	PendingCovering       = "awaiting_covering_assertion"
	PendingConfirmation   = "awaiting_assertion_confirmation"
	PendingL1Finality     = "awaiting_l1_finality_of_confirmation"
	PendingProofWindow    = "l1_proof_window_unavailable"
	PendingL1State        = "l1_state_unavailable"
	captureItemState      = "arbfinal/state/"
	captureItemConf       = "arbfinal/conf/"
	defaultLogChunk       = 2000
	defaultMaxScanBlocks  = 40000
	maxAssertionsPerBuild = 512
)

// Prover is the finality.Prover of Arbitrum Sepolia level 3.
type Prover struct {
	Pins  *finality.Pins
	L1    L1
	L2    L2
	LC    LCSource
	Store CaptureStore
	// StateAhead is how many L1 blocks above K the state block S is taken when the head allows (S >= K; 0 takes S = K).
	StateAhead uint64
	// LogChunk is the L1 block span of one eth_getLogs call (default 2000).
	LogChunk uint64
	// MaxScanBlocks bounds the L1 scan for AssertionCreated events from the leg's L1 reference (default 40,000 blocks).
	MaxScanBlocks uint64
	// OnStatus, when set, receives the informational values of a pending state that the registry has no field for (annex
	// "Named states" lists them: l2_block, latest_assertion_end_block, assertion_hash, created_l1, ...). They are logs, not state.
	OnStatus func(reason string, info map[string]any)
}

var (
	_ finality.Prover    = (*Prover)(nil)
	_ finality.Ceilinged = (*Prover)(nil)
)

// Chain implements finality.Prover.
func (p *Prover) Chain() uint64 { return finality.ChainArbitrumSepolia }

// Ceiling implements finality.Ceilinged: finalized is Arbitrum Sepolia's top level.
func (p *Prover) Ceiling() finality.Level { return finality.LevelFinalized }

func (p *Prover) logChunk() uint64 {
	if p.LogChunk > 0 {
		return p.LogChunk
	}
	return defaultLogChunk
}

func (p *Prover) maxScan() uint64 {
	if p.MaxScanBlocks > 0 {
		return p.MaxScanBlocks
	}
	return defaultMaxScanBlocks
}

func (p *Prover) status(reason string, info map[string]any) {
	if p.OnStatus != nil {
		p.OnStatus(reason, info)
	}
}

func (p *Prover) pending(have finality.LevelSet, reason string, kv ...any) *finality.PendingState {
	reached := finality.LevelIncluded
	if have.Has(finality.LevelL1Posted) {
		reached = finality.LevelL1Posted
	}
	j := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		j[fmt.Sprint(kv[i])] = kv[i+1]
	}
	return &finality.PendingState{Chain: finality.ChainArbitrumSepolia, LevelReached: reached, NextLevel: finality.LevelFinalized, Reason: reason, Judged: j}
}

// Build implements finality.Prover: it derives the leg's block from the Settlement and builds level 3.
func (p *Prover) Build(ctx context.Context, s *ethproof.Settlement, have finality.LevelSet, target finality.Level) (*finality.Addendum, *finality.PendingState, error) {
	if target != finality.LevelFinalized {
		return nil, nil, finality.NewState(finality.CodeEvidenceUnrecognised, "kind", "level:"+target.String(), "version", "")
	}
	if have.Has(finality.LevelFinalized) {
		return nil, nil, finality.NewState(finality.CodeLevelAlreadyPresent, "chain", finality.ChainArbitrumSepolia, "level", finality.LevelFinalized)
	}
	leg, err := finality.DeriveIncluded(finality.ChainArbitrumSepolia, s)
	if err != nil {
		return nil, nil, err
	}
	return p.BuildLeg(ctx, leg, have)
}

// BuildLeg builds the evidence for a leg block already derived at level 1 (the recorder names the block directly).
func (p *Prover) BuildLeg(ctx context.Context, leg finality.BlockRef, have finality.LevelSet) (*finality.Addendum, *finality.PendingState, error) {
	arb, err := arbfinal.LoadPins(p.Pins)
	if err != nil {
		return nil, nil, err
	}
	if leg.Number <= arb.BoldGenesisL2Block {
		return nil, nil, finality.NewState(arbfinal.CodePreBold, "n", leg.Number, "bold_genesis_l2_block", arb.BoldGenesisL2Block)
	}
	if _, err := finality.ReadHeader(leg.HeaderRLP); err != nil {
		return nil, nil, err
	}
	l1p, err := ethl1PinsOf(p.Pins)
	if err != nil {
		return nil, nil, err
	}
	head, err := p.L1.Head(ctx)
	if err != nil {
		return nil, p.pending(have, PendingL1State, "block", uint64(0), "providers", p.L1.Providers()), nil
	}

	// 1. the earliest created assertion whose end block is >= the leg's block
	as, pend, err := p.findCovering(ctx, arb, leg, head, have)
	if pend != nil || err != nil {
		return nil, pend, err
	}

	// 2. its confirmation
	conf, ok, err := p.findConfirmation(ctx, arb, as, head)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		p.status(PendingConfirmation, map[string]any{"assertion_hash": as.Hash, "created_l1": as.L1Block, "earliest_confirm_l1": as.L1Block + as.ParentCfg.ConfirmPeriodBlocks, "l1_head": head, "status": uint64(1)})
		return nil, p.pending(have, PendingConfirmation), nil
	}
	K := conf.Block
	S := K + p.StateAhead
	if S > head {
		S = head
	}

	// 3. capture near the head (or reuse what the store holds)
	nodes, confTx, confRcpt, confIdx, kHdr, sHdr, pend, err := p.capture(ctx, arb, as, conf, K, S, have)
	if pend != nil || err != nil {
		return nil, pend, err
	}

	// 4. L1 finality of S and K
	lc, err := p.LC.LC(ctx)
	if err != nil {
		return nil, p.pending(have, PendingL1State, "block", K, "providers", []string{"beacon"}), nil
	}
	fh, err := ethl1.VerifyFinalizedHead(l1p, lc)
	if err != nil {
		return nil, nil, arbfinal.L1FinalityUnproven(arbfinal.L1FinalityLCRefused, innerCode(err))
	}
	execRaw, err := p.L1.HeaderByHash(ctx, fh.ExecHash)
	if err != nil {
		return nil, p.pending(have, PendingL1State, "block", K, "providers", p.L1.Providers()), nil
	}
	execHdr, err := finality.ReadHeader(execRaw)
	if err != nil || execHdr.Hash != fh.ExecHash {
		return nil, p.pending(have, PendingL1State, "block", K, "providers", p.L1.Providers()), nil
	}
	top := execHdr.Number
	if top < S || top < K {
		p.status(PendingL1Finality, map[string]any{"assertion_hash": as.Hash, "confirmed_l1_block": K, "state_block": S, "finalized_head": top})
		return nil, p.pending(have, PendingL1Finality), nil
	}
	low := K
	if S < low {
		low = S
	}
	if uint64(l1p.MaxSpineHeaders) < top-low+1 {
		return nil, nil, finality.EvidenceTooLarge("l1Spine", top-low+1, uint64(l1p.MaxSpineHeaders))
	}
	asc, err := p.L1.Headers(ctx, low, top)
	if err != nil || uint64(len(asc)) != top-low+1 {
		return nil, p.pending(have, PendingL1State, "block", top, "providers", p.L1.Providers()), nil
	}
	l1Spine := reverse(asc)
	if first, rerr := finality.ReadHeader(l1Spine[0]); rerr != nil || first.Hash != fh.ExecHash {
		return nil, p.pending(have, PendingL1State, "block", top, "providers", p.L1.Providers()), nil
	}
	// the captured proofs must belong to the canonical blocks: the spine's headers for K and S are the captured ones
	if !bytes.Equal(asc[K-low], kHdr) || !bytes.Equal(asc[S-low], sHdr) {
		return nil, p.pending(have, PendingL1State, "block", K, "providers", p.L1.Providers()), nil
	}

	// 5. the L2 spine from the assertion's block down to the leg
	l2, err := p.l2Spine(ctx, arb, as, leg)
	if err != nil {
		return nil, nil, err
	}

	// 6. assemble and judge
	ev := arbfinal.Evidence{
		LC: lc, L1Spine: l1Spine, StateBlock: S, ConfBlock: K, ParentAssertionHash: as.Parent, After: as.After,
		SequencerBatchAcc: as.SeqAcc, Parent: as.ParentCfg, L2Spine: l2,
		ConfTxIndex: confIdx, ConfTxRaw: confTx, ConfReceiptRaw: confRcpt, Nodes: nodes,
	}
	container, err := arbfinal.BuildContainer(leg, ev)
	if err != nil {
		return nil, nil, err
	}
	if _, err := arbfinal.New().Verify(p.Pins, leg, container); err != nil {
		return nil, nil, err
	}
	return &finality.Addendum{Level: finality.LevelFinalized, Chain: finality.ChainArbitrumSepolia, Kind: arbfinal.KindName, Evidence: container}, nil, nil
}

// findCovering scans the Rollup's AssertionCreated events from the leg block's L1 reference forward and returns the earliest
// assertion whose end block is >= the leg's block.
func (p *Prover) findCovering(ctx context.Context, arb *arbfinal.Pins, leg finality.BlockRef, head uint64, have finality.LevelSet) (*Assertion, *finality.PendingState, error) {
	mix, err := mixHashOf(leg.HeaderRLP)
	if err != nil {
		return nil, nil, err
	}
	from := l1ReferenceOf(mix)
	if from > head {
		from = head
	}
	to := head
	if to-from > p.maxScan() {
		to = from + p.maxScan()
	}
	var latest *Assertion
	seen := 0
	for lo := from; lo <= to; lo += p.logChunk() {
		hi := lo + p.logChunk() - 1
		if hi > to {
			hi = to
		}
		logs, err := p.L1.Logs(ctx, arb.Rollup, [][]common.Hash{{TopicAssertionCreated}}, lo, hi)
		if err != nil {
			return nil, nil, finality.NewState(arbfinal.CodeHistoryUnavailable, "l1_from", lo, "l1_to", hi, "providers", p.L1.Providers())
		}
		for _, l := range logs {
			seen++
			if seen > maxAssertionsPerBuild {
				return nil, nil, finality.NewState(arbfinal.CodeHistoryUnavailable, "l1_from", from, "l1_to", to, "providers", p.L1.Providers())
			}
			a, err := DecodeCreated(l)
			if err != nil {
				return nil, nil, finality.NewState(finality.CodeVerifierFailed, "chain", finality.ChainArbitrumSepolia, "kind", arbfinal.KindName, "cause", ethrpc.RedactText(err.Error()))
			}
			raw, err := p.L2.HeaderByHash(ctx, a.After.BlockHash)
			if err != nil {
				return nil, nil, finality.NewState(arbfinal.CodeL2HeaderUnavail, "block", a.After.BlockHash)
			}
			h, err := finality.ReadHeader(raw)
			if err != nil || h.Hash != a.After.BlockHash {
				return nil, nil, finality.NewState(arbfinal.CodeL2HeaderUnavail, "block", a.After.BlockHash)
			}
			a.EndBlock = h.Number
			latest = a
			if a.EndBlock >= leg.Number {
				return a, nil, nil
			}
		}
	}
	info := map[string]any{"l2_block": leg.Number}
	if latest != nil {
		info["latest_assertion_end_block"] = latest.EndBlock
		info["latest_assertion_l1_block"] = latest.L1Block
	}
	p.status(PendingCovering, info)
	return nil, p.pending(have, PendingCovering), nil
}

// findConfirmation returns the AssertionConfirmed log of the assertion, if the Rollup has emitted one by the head.
func (p *Prover) findConfirmation(ctx context.Context, arb *arbfinal.Pins, a *Assertion, head uint64) (Log, bool, error) {
	for lo := a.L1Block; lo <= head; lo += p.logChunk() {
		hi := lo + p.logChunk() - 1
		if hi > head {
			hi = head
		}
		logs, err := p.L1.Logs(ctx, arb.Rollup, [][]common.Hash{{arb.Topic.Confirmed}, {common.Hash(a.Hash)}}, lo, hi)
		if err != nil {
			return Log{}, false, finality.NewState(arbfinal.CodeHistoryUnavailable, "l1_from", lo, "l1_to", hi, "providers", p.L1.Providers())
		}
		if len(logs) > 0 {
			return logs[0], true, nil
		}
	}
	return Log{}, false, nil
}

// capture reads, near the head, the Rollup and logic-account proofs under S and K and the confirmation transaction and receipt
// with their proofs from K's block; it keeps them in the store and reads them back from there when they exist (a later poll is
// outside the provider's window).
func (p *Prover) capture(ctx context.Context, arb *arbfinal.Pins, a *Assertion, conf Log, K, S uint64, have finality.LevelSet) (nodes [][]byte, tx, rcpt []byte, idx uint32, kHdr, sHdr []byte, pend *finality.PendingState, err error) {
	hdrs := map[uint64][]byte{}
	var set [][]byte
	blocks := []uint64{K}
	if S != K {
		blocks = append(blocks, S)
	}
	for _, x := range blocks {
		raws, herr := p.L1.Headers(ctx, x, x)
		if herr != nil || len(raws) != 1 {
			return nil, nil, nil, 0, nil, nil, p.pending(have, PendingL1State, "block", x, "providers", p.L1.Providers()), nil
		}
		hdrs[x] = raws[0]
		hf, rerr := finality.ReadHeader(raws[0])
		if rerr != nil || hf.Number != x {
			return nil, nil, nil, 0, nil, nil, p.pending(have, PendingL1State, "block", x, "providers", p.L1.Providers()), nil
		}
		item := captureItemState + hex.EncodeToString(a.Hash[:])
		if stored, ok, serr := p.Store.Get(ctx, finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: x, L1Hash: hf.Hash, Item: item}); serr == nil && ok {
			ns, derr := decodeNodes(stored)
			if derr != nil {
				return nil, nil, nil, 0, nil, nil, nil, derr
			}
			set = append(set, ns...)
			continue
		}
		ns, perr := p.stateProofs(ctx, arb, a, x, hf)
		if perr != nil {
			// near-head proofs are the one thing a late attempt cannot redo: a named state, never a weaker level
			return nil, nil, nil, 0, nil, nil, p.pending(have, PendingProofWindow, "l1_block", x, "providers", p.L1.Providers()), nil
		}
		if serr := p.Store.Put(ctx, finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: x, L1Hash: hf.Hash, Item: item}, encodeNodes(ns)); serr != nil {
			return nil, nil, nil, 0, nil, nil, nil, finality.NewState(finality.CodeVerifierFailed, "chain", finality.ChainArbitrumSepolia, "kind", arbfinal.KindName, "cause", ethrpc.RedactText(serr.Error()))
		}
		set = append(set, ns...)
	}
	// the confirmation transaction, receipt and their trie proofs at K
	kf, _ := finality.ReadHeader(hdrs[K])
	item := captureItemConf + hex.EncodeToString(a.Hash[:])
	if stored, ok, serr := p.Store.Get(ctx, finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: K, L1Hash: kf.Hash, Item: item}); serr == nil && ok {
		t, r, i, ns, derr := decodeConf(stored)
		if derr != nil {
			return nil, nil, nil, 0, nil, nil, nil, derr
		}
		return finality.EncodeNodes(append(set, ns...)), t, r, i, hdrs[K], hdrs[S], nil, nil
	}
	blk, berr := p.L1.Block(ctx, K)
	if berr != nil {
		return nil, nil, nil, 0, nil, nil, p.pending(have, PendingL1State, "block", K, "providers", p.L1.Providers()), nil
	}
	if blk.Hash != kf.Hash || !bytes.Equal(blk.HeaderRLP, hdrs[K]) || uint64(len(blk.Txs)) <= conf.TxIndex || len(blk.Receipts) != len(blk.Txs) {
		return nil, nil, nil, 0, nil, nil, p.pending(have, PendingL1State, "block", K, "providers", p.L1.Providers()), nil
	}
	if ethproof.TrieRoot(blk.Txs) != common.Hash(kf.TransactionRoot) || ethproof.TrieRoot(blk.Receipts) != common.Hash(kf.ReceiptsRoot) {
		return nil, nil, nil, 0, nil, nil, p.pending(have, PendingL1State, "block", K, "providers", p.L1.Providers()), nil
	}
	tp, terr := ethproof.Prove(blk.Txs, conf.TxIndex, common.Hash(kf.TransactionRoot))
	rp, rerr := ethproof.Prove(blk.Receipts, conf.TxIndex, common.Hash(kf.ReceiptsRoot))
	if terr != nil || rerr != nil {
		return nil, nil, nil, 0, nil, nil, nil, finality.NewState(finality.CodeVerifierFailed, "chain", finality.ChainArbitrumSepolia, "kind", arbfinal.KindName, "cause", "confirmation trie proof could not be built")
	}
	ns := append(append([][]byte(nil), tp.ProofNodes...), rp.ProofNodes...)
	idx = uint32(conf.TxIndex)
	tx, rcpt = blk.Txs[conf.TxIndex], blk.Receipts[conf.TxIndex]
	if serr := p.Store.Put(ctx, finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: K, L1Hash: kf.Hash, Item: item}, encodeConf(tx, rcpt, idx, ns)); serr != nil {
		return nil, nil, nil, 0, nil, nil, nil, finality.NewState(finality.CodeVerifierFailed, "chain", finality.ChainArbitrumSepolia, "kind", arbfinal.KindName, "cause", ethrpc.RedactText(serr.Error()))
	}
	return finality.EncodeNodes(append(set, ns...)), tx, rcpt, idx, hdrs[K], hdrs[S], nil, nil
}

// stateProofs captures the proofs one verifier pass at L1 block x reads: the Rollup account with the two EIP-1967 slots, the
// assertion node slot, the parent's config slot and the fast-confirmer slot; then the two logic accounts the slots name.
func (p *Prover) stateProofs(ctx context.Context, arb *arbfinal.Pins, a *Assertion, x uint64, hf finality.HeaderFields) ([][]byte, error) {
	node := arbfinal.NodeSlot(a.Hash, arb.Layout.AssertionsSlot)
	cfg := arbfinal.ConfigSlot(a.Parent, arb.Layout.AssertionsSlot, arb.Layout.ConfigSlotOffset)
	fast := common.BigToHash(new(big.Int).SetUint64(arb.Layout.FastConfirmerSlot))
	slots := []common.Hash{arb.AdminSlot, arb.UserSlot, node, cfg, fast}
	sp, err := p.L1.Proof(ctx, arb.Rollup, slots, x)
	if err != nil {
		return nil, err
	}
	var all [][]byte
	all = append(all, sp.Account...)
	for _, s := range slots {
		all = append(all, sp.Storage[s]...)
	}
	// the logic addresses come from the proven slot words (the same reads the verifier makes)
	root := common.Hash(hf.StateRoot)
	acct, err := ethproof.VerifyAccount(root, arb.Rollup, sp.Account)
	if err != nil || !acct.Exists {
		return nil, fmt.Errorf("the Rollup account proof at %d does not verify", x)
	}
	for _, slot := range []common.Hash{arb.AdminSlot, arb.UserSlot} {
		w, err := ethproof.VerifySlot(acct.StorageRoot, slot, sp.Storage[slot])
		if err != nil {
			return nil, fmt.Errorf("an EIP-1967 slot proof at %d does not verify", x)
		}
		lp, err := p.L1.Proof(ctx, common.BytesToAddress(w[12:]), nil, x)
		if err != nil {
			return nil, err
		}
		all = append(all, lp.Account...)
	}
	return all, nil
}

// l2Spine fetches the headers of the assertion's block down to the leg block (descending), bounded by max_header_chain.
func (p *Prover) l2Spine(ctx context.Context, arb *arbfinal.Pins, a *Assertion, leg finality.BlockRef) ([][]byte, error) {
	needed := a.EndBlock - leg.Number + 1
	if needed > uint64(arb.MaxHeaderChain) {
		return nil, arbfinal.HeaderChainExceeds(needed, uint64(arb.MaxHeaderChain))
	}
	asc, err := p.L2.Headers(ctx, leg.Number, a.EndBlock)
	if err != nil || uint64(len(asc)) != needed {
		return nil, finality.NewState(arbfinal.CodeL2HeadersUnavail, "from", leg.Number, "to", a.EndBlock)
	}
	return reverse(asc), nil
}

func reverse(a [][]byte) [][]byte {
	out := make([][]byte, len(a))
	for i := range a {
		out[len(a)-1-i] = a[i]
	}
	return out
}

// mixHashOf reads item 13 of an Arbitrum header positionally.
func mixHashOf(raw []byte) (common.Hash, error) {
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		return common.Hash{}, finality.Malformed("header", finality.ReasonHeaderNotRLPList, len(raw), 0)
	}
	for i := 0; len(content) > 0; i++ {
		_, val, tail, err := rlp.Split(content)
		if err != nil {
			return common.Hash{}, finality.MalformedAt("header", i, finality.ReasonHeaderBadItem, len(content), 0)
		}
		if i == 13 {
			if len(val) != 32 {
				return common.Hash{}, finality.MalformedAt("header", i, finality.ReasonHeaderItemNot32Bytes, len(val), 32)
			}
			return common.BytesToHash(val), nil
		}
		content = tail
	}
	return common.Hash{}, finality.Malformed("header", finality.ReasonHeaderTooFewItems, 0, 14)
}

func innerCode(err error) string {
	if f, ok := err.(*ethl1.Fault); ok {
		return f.Code
	}
	if s, ok := finality.AsNamed(err); ok {
		return s.Code
	}
	return ""
}

// encodeNodes / decodeNodes: a capture row of proof nodes.
func encodeNodes(ns [][]byte) []byte {
	var w finality.Writer
	w.LPList(ns)
	return w.Bytes()
}

func decodeNodes(b []byte) ([][]byte, error) {
	r := finality.NewReader(b, finality.DefaultLimits())
	ns, err := r.LPList("capture.nodes", finality.DefaultLimits().MaxNodes*4, finality.DefaultLimits().MaxTxLeafBytes)
	if err != nil {
		return nil, err
	}
	return ns, r.End("capture.nodes")
}

func encodeConf(tx, rcpt []byte, idx uint32, ns [][]byte) []byte {
	var w finality.Writer
	w.U32(idx)
	w.LP(tx)
	w.LP(rcpt)
	w.LPList(ns)
	return w.Bytes()
}

func decodeConf(b []byte) (tx, rcpt []byte, idx uint32, ns [][]byte, err error) {
	lim := finality.DefaultLimits()
	r := finality.NewReader(b, lim)
	if idx, err = r.U32("capture.idx"); err != nil {
		return
	}
	if tx, err = r.LP("capture.tx", lim.MaxTxLeafBytes); err != nil {
		return
	}
	if rcpt, err = r.LP("capture.receipt", lim.MaxTxLeafBytes); err != nil {
		return
	}
	if ns, err = r.LPList("capture.nodes", lim.MaxNodes*4, lim.MaxTxLeafBytes); err != nil {
		return
	}
	err = r.End("capture")
	return
}

// ethl1PinsOf converts the Sepolia section of the pins file to the L1 head verifier's pins (l1adapt's conversion).
func ethl1PinsOf(p *finality.Pins) (ethl1.Pins, error) { return l1adapt.PinsOf(p) }
