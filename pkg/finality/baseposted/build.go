// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// L2BlockData is a Base Sepolia block as the builder needs it: its transactions (EIP-2718 encodings, deposits first).
type L2BlockData struct {
	Number uint64
	Txs    [][]byte
}

// L2Source reads the L2: only the transactions are needed, the header is the leg's Settlement.Header.
type L2Source interface {
	Block(ctx context.Context, number uint64) (L2BlockData, error)
}

// LCSource supplies the L1-finality part of the evidence (a Sepolia light-client chain from a pinned anchor to a finality update).
type LCSource interface {
	Finalized(ctx context.Context) (ethl1.LC, error)
}

// HeaderSource reads one L1 header by hash: its raw RLP, parent hash and number.
type HeaderSource interface {
	HeaderByHash(ctx context.Context, hash [32]byte) (raw []byte, parent [32]byte, number uint64, err error)
}

// Builder is the finality.Prover of Base Sepolia level 2 (l1_posted). It builds from CAPTURED rows (leg-independent capture, spec
// 2.8), waits for the spine of the finalized head to cover the frame blocks, assembles the container, runs the verifier and
// returns the addendum, or a named pending/unavailability state. It never returns a weaker level.
type Builder struct {
	Pins    *finality.Pins
	Store   CaptureStore
	L1      L1Source
	Headers HeaderSource
	L2      L2Source
	LC      LCSource
	Now     func() time.Time
}

func (b *Builder) Chain() uint64           { return uint64(Chain) }
func (b *Builder) Ceiling() finality.Level { return finality.LevelL1Posted }

// capturedTx is one batch-inbox transaction of a captured L1 block with the frames it carries.
type capturedTx struct {
	key    CaptureKey
	index  uint32
	raw    []byte
	blobs  []Blob
	frames []Frame
}

func (b *Builder) load(ctx context.Context, bp *Pins) ([]capturedTx, error) {
	blocks, err := finality.CaptureKeysOfItem(ctx, b.Store, uint64(Chain), ItemInbox)
	if err != nil {
		return nil, err
	}
	var out []capturedTx
	for _, k := range blocks {
		raw, ok, err := b.Store.Get(ctx, k)
		if err != nil || !ok {
			return nil, fmt.Errorf("baseposted: capture row %s vanished", k.Item)
		}
		r := finality.NewReader(raw, finality.DefaultLimits())
		n, err := r.Count("inbox", 4096, 4)
		if err != nil {
			return nil, err
		}
		for i := 0; i < n; i++ {
			idx, err := r.U32("inbox.index")
			if err != nil {
				return nil, err
			}
			tk := k
			tk.Item = ItemTx(idx)
			txb, ok, err := b.Store.Get(ctx, tk)
			if err != nil || !ok {
				return nil, fmt.Errorf("baseposted: capture row %s missing", tk.Item)
			}
			ct := capturedTx{key: k, index: idx, raw: txb}
			var datas [][]byte
			var tx txView
			if err := tx.parse(txb); err != nil {
				return nil, err
			}
			if tx.isBlob {
				for j := 0; ; j++ {
					bk := k
					bk.Item = ItemBlob(idx, j)
					bb, ok, err := b.Store.Get(ctx, bk)
					if err != nil {
						return nil, err
					}
					if !ok {
						break
					}
					br := finality.NewReader(bb, finality.DefaultLimits())
					var bl Blob
					if bl.Raw, err = br.LP("blob.raw", BlobSize); err != nil {
						return nil, err
					}
					c, _ := br.Fixed("blob.commitment", 48)
					p, _ := br.Fixed("blob.proof", 48)
					copy(bl.Commitment[:], c)
					copy(bl.Proof[:], p)
					ct.blobs = append(ct.blobs, bl)
					d, err := blobToData(bl.Raw)
					if err != nil {
						continue // a blob that is not frame data belongs to no channel; the verifier refuses it if it is cited
					}
					datas = append(datas, d)
				}
			} else {
				datas = append(datas, tx.data)
			}
			for _, d := range datas {
				if fr, err := parseFrames(d); err == nil {
					ct.frames = append(ct.frames, fr...)
				}
			}
			out = append(out, ct)
		}
	}
	return out, nil
}

// Build implements finality.Prover for level 2.
func (b *Builder) Build(ctx context.Context, s *ethproof.Settlement, have finality.LevelSet, target finality.Level) (*finality.Addendum, *finality.PendingState, error) {
	if target != finality.LevelL1Posted {
		return nil, nil, nil // finalized is the sibling prover's level (basefinal)
	}
	if have.Has(target) {
		return nil, nil, finality.NewState(finality.CodeLevelAlreadyPresent, "chain", uint64(Chain), "level", target)
	}
	bp, err := ParsePins(b.Pins)
	if err != nil {
		return nil, nil, err
	}
	eth, err := b.Pins.Sepolia()
	if err != nil {
		return nil, nil, err
	}
	ep := l1adapt.Pins(eth)
	l2, err := finality.ReadHeader(s.Header)
	if err != nil {
		return nil, nil, err
	}
	if l2.Timestamp >= bp.DenimTime {
		return nil, nil, st(CodeBatchFormat, "type", "post_denim")
	}
	pend := func(reason string, kv map[string]any) (*finality.Addendum, *finality.PendingState, error) {
		return nil, &finality.PendingState{Chain: uint64(Chain), LevelReached: finality.LevelIncluded, NextLevel: finality.LevelL1Posted, Reason: reason, Judged: kv}, nil
	}
	txs, err := b.load(ctx, bp)
	if err != nil {
		return nil, nil, err
	}
	ch, frameTxs, bt, lastScanned := findChannel(txs, bp, l2.Timestamp)
	if ch == nil {
		return pend("l1_posted_unproven", map[string]any{"l2_timestamp": l2.Timestamp, "last_scanned_l1": lastScanned})
	}
	// L1 finality: the pending state when the spine of the finalized head does not yet reach the frame blocks.
	lc, err := b.LC.Finalized(ctx)
	if err != nil {
		return nil, nil, st("finality_source_unavailable", "reason", "lc", "endpoints", "lc")
	}
	head, err := ethl1.VerifyFinalizedHead(ep, lc)
	if err != nil {
		return nil, nil, st(CodeL1FinalityUnproven, "reason", LCRefused, "inner", faultCode(err))
	}
	maxBlock, minBlock := frameTxs[0].key.L1Block, frameTxs[0].key.L1Block
	for _, f := range frameTxs {
		if f.key.L1Block > maxBlock {
			maxBlock = f.key.L1Block
		}
		if f.key.L1Block < minBlock {
			minBlock = f.key.L1Block
		}
	}
	if bt.Type == 1 && bt.EpochNum < minBlock {
		minBlock = bt.EpochNum
	}
	raw0, _, top, err := b.Headers.HeaderByHash(ctx, head.ExecHash)
	if err != nil {
		return nil, nil, st("finality_source_unavailable", "reason", "l1_header", "endpoints", "headers")
	}
	_ = raw0
	if top < maxBlock {
		var observedSlot uint64
		if n, err := b.L1.Head(ctx); err == nil {
			if blk, err := b.L1.Block(ctx, n); err == nil && blk.Timestamp >= eth.GenesisTime {
				observedSlot = (blk.Timestamp - eth.GenesisTime) / 12
			}
		}
		return pend("block_not_yet_covered", map[string]any{"latest_finalized_exec_number": top, "latest_finalized_slot": head.Slot, "observed_head_slot": observedSlot})
	}
	// The spine: finalized head down to the lowest block the evidence cites.
	var spine [][]byte
	hash := head.ExecHash
	byNumber := map[uint64][32]byte{}
	for n := top; ; n-- {
		raw, parent, num, err := b.Headers.HeaderByHash(ctx, hash)
		if err != nil || num != n {
			return nil, nil, st("finality_source_unavailable", "reason", "l1_header", "endpoints", "headers")
		}
		spine = append(spine, raw)
		byNumber[n] = hash
		hash = parent
		if n == minBlock {
			break
		}
	}
	for _, f := range frameTxs {
		if byNumber[f.key.L1Block] != f.key.L1Hash {
			return nil, nil, st("l1_proof_window_unavailable", "l1_block", f.key.L1Block, "providers", "captured block is not on the finalized chain (reorg)")
		}
	}
	// Body.
	l2blk, err := b.L2.Block(ctx, l2.Number)
	if err != nil {
		return nil, nil, st("l2_header_unavailable", "block", l2.Number)
	}
	var deposits [][]byte
	for _, t := range l2blk.Txs {
		if len(t) > 0 && t[0] == 0x7e {
			deposits = append(deposits, t)
		} else {
			break
		}
	}
	body := Body{LC: lc, L1Spine: spine, ChannelID: ch.ID, Deposits: deposits}
	seenSys := map[CaptureKey]bool{}
	for _, f := range frameTxs {
		body.Frames = append(body.Frames, FrameTx{L1Block: f.key.L1Block, TxIndex: f.index, TxRaw: f.raw, Blobs: f.blobs})
		nk := f.key
		nk.Item = ItemTxNodes(f.index)
		nb, ok, err := b.Store.Get(ctx, nk)
		if err != nil || !ok {
			return nil, nil, fmt.Errorf("baseposted: capture row %s missing", nk.Item)
		}
		nodes, err := finality.NewReader(nb, finality.DefaultLimits()).LPList("txnodes", 64, finality.DefaultLimits().MaxTxLeafBytes)
		if err != nil {
			return nil, nil, err
		}
		body.Nodes = append(body.Nodes, nodes...)
		if !seenSys[f.key] {
			seenSys[f.key] = true
			sk := f.key
			sk.Item = ItemSysCfg
			sb, ok, err := b.Store.Get(ctx, sk)
			if err != nil || !ok {
				return nil, nil, st("batcher_state_unavailable", "l1_block", f.key.L1Block)
			}
			sn, err := finality.NewReader(sb, finality.DefaultLimits()).LPList("syscfg", 256, finality.DefaultLimits().MaxTxLeafBytes)
			if err != nil {
				return nil, nil, err
			}
			body.Nodes = append(body.Nodes, sn...)
		}
	}
	sort.SliceStable(body.Frames, func(i, j int) bool {
		if body.Frames[i].L1Block != body.Frames[j].L1Block {
			return body.Frames[i].L1Block < body.Frames[j].L1Block
		}
		return body.Frames[i].TxIndex < body.Frames[j].TxIndex
	})
	c := finality.Container{Header: finality.ContainerHeader{Kind: KindName, Chain: uint64(Chain), Level: finality.LevelL1Posted,
		BlockNumber: l2.Number, BlockHash: l2.Hash}, Body: EncodeBody(body)}
	evidence, err := c.Encode()
	if err != nil {
		return nil, nil, err
	}
	if _, err := (Kind{}).Verify(b.Pins, finality.BlockRef{Chain: uint64(Chain), Number: l2.Number, Hash: l2.Hash, HeaderRLP: s.Header}, evidence); err != nil {
		return nil, nil, err
	}
	return &finality.Addendum{Level: finality.LevelL1Posted, Chain: uint64(Chain), Kind: KindName, Evidence: evidence}, nil, nil
}

// channelRef identifies a channel found in the captured frames.
type channelRef struct{ ID [16]byte }

// findChannel groups the captured frames by channel id, assembles every complete channel, decodes it and returns the first
// whose batch for timestamp T exists, with the inbox transactions that carry its frames and the batch. lastScanned is the highest
// captured L1 block (for the pending state).
func findChannel(txs []capturedTx, bp *Pins, ts uint64) (*channelRef, []capturedTx, *Batch, uint64) {
	var last uint64
	byCh := map[[16]byte][]capturedTx{}
	var order [][16]byte
	for _, t := range txs {
		if t.key.L1Block > last {
			last = t.key.L1Block
		}
		seen := map[[16]byte]bool{}
		for _, f := range t.frames {
			if !seen[f.ID] {
				seen[f.ID] = true
				if _, ok := byCh[f.ID]; !ok {
					order = append(order, f.ID)
				}
				byCh[f.ID] = append(byCh[f.ID], t)
			}
		}
	}
	for _, id := range order {
		var frames []Frame
		for _, t := range byCh[id] {
			for _, f := range t.frames {
				if f.ID == id {
					frames = append(frames, f)
				}
			}
		}
		complete := len(frames) > 0
		var stream []byte
		for i, f := range frames {
			if uint64(f.Number) != uint64(i) || f.IsLast != (i == len(frames)-1) {
				complete = false
				break
			}
			stream = append(stream, f.Data...)
		}
		if !complete {
			continue
		}
		raw, err := decompress(stream, bp.MaxRLPBytesPerChannel)
		if err != nil {
			continue
		}
		batches, err := decodeBatches(raw, spanParams{GenesisTime: bp.L2GenesisTime, BlockTime: bp.L2BlockTime, ChainID: bp.ChainID})
		if err != nil {
			continue
		}
		for i := range batches {
			if batches[i].Timestamp == ts {
				return &channelRef{ID: id}, byCh[id], &batches[i], last
			}
		}
	}
	return nil, nil, nil, last
}

func faultCode(err error) string {
	if f, ok := err.(*ethl1.Fault); ok {
		return f.Code
	}
	return ""
}

// txView reads the two things the builder needs of a batch-inbox transaction without a signature check (the verifier checks).
type txView struct {
	isBlob bool
	data   []byte
}

func (v *txView) parse(raw []byte) error {
	var t = new(types.Transaction)
	if err := t.UnmarshalBinary(raw); err != nil {
		return err
	}
	v.isBlob = t.Type() == types.BlobTxType
	v.data = t.Data()
	return nil
}

// ChannelInfo describes one complete channel found in the captured frames: its id, the L1 blocks that carry its frames and the
// timestamps of the L2 blocks its batches cover.
type ChannelInfo struct {
	ID         [16]byte
	L1Blocks   []uint64
	Timestamps []uint64
}

// Channels lists the complete channels in the capture store, in capture order.
func (b *Builder) Channels(ctx context.Context) ([]ChannelInfo, error) {
	bp, err := ParsePins(b.Pins)
	if err != nil {
		return nil, err
	}
	txs, err := b.load(ctx, bp)
	if err != nil {
		return nil, err
	}
	byCh := map[[16]byte][]capturedTx{}
	var order [][16]byte
	for _, t := range txs {
		seen := map[[16]byte]bool{}
		for _, f := range t.frames {
			if !seen[f.ID] {
				seen[f.ID] = true
				if _, ok := byCh[f.ID]; !ok {
					order = append(order, f.ID)
				}
				byCh[f.ID] = append(byCh[f.ID], t)
			}
		}
	}
	var out []ChannelInfo
	for _, id := range order {
		var stream []byte
		ok := true
		n := 0
		for _, t := range byCh[id] {
			for _, f := range t.frames {
				if f.ID != id {
					continue
				}
				if uint64(f.Number) != uint64(n) {
					ok = false
				}
				n++
				stream = append(stream, f.Data...)
				if f.IsLast {
					n = -1 << 30
				}
			}
		}
		if !ok || n >= 0 {
			continue
		}
		raw, err := decompress(stream, bp.MaxRLPBytesPerChannel)
		if err != nil {
			continue
		}
		batches, err := decodeBatches(raw, spanParams{GenesisTime: bp.L2GenesisTime, BlockTime: bp.L2BlockTime, ChainID: bp.ChainID})
		if err != nil {
			continue
		}
		ci := ChannelInfo{ID: id}
		for _, t := range byCh[id] {
			ci.L1Blocks = append(ci.L1Blocks, t.key.L1Block)
		}
		for _, bt := range batches {
			ci.Timestamps = append(ci.Timestamps, bt.Timestamp)
		}
		out = append(out, ci)
	}
	return out, nil
}

var (
	_ finality.Prover    = (*Builder)(nil)
	_ finality.Ceilinged = (*Builder)(nil)
	_ finality.Kind      = Kind{}
)

// RegisterProver adds a configured Builder to the registry (explicit; there is no init()).
func RegisterProver(reg *finality.Registry, b *Builder) error { return reg.RegisterProver(b) }
