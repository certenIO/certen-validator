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
	// CursorSlack is how many blocks before its first cursor row the capture loop may have started scanning (the loop's first range:
	// its per-tick block bound or its start-back, whichever is larger; default 64). A leg whose frames all lie below the first cursor
	// row minus this slack was posted before the capture existed.
	CursorSlack uint64
	// HasArchive is whether an archive provider (OD4) is configured; it is carried by the capture-not-covering state so an operator can
	// see whether a deeper source exists.
	HasArchive bool
}

// Codes of this builder that are not verifier refusals (class U, go_operational scope of testdata/finality/states.json).
const (
	// CodeCaptureNotCovering: the L1 blocks that can hold the leg's batch were not scanned by this validator's capture loop.
	CodeCaptureNotCovering = "l1_capture_not_covering"
)

// The window of L1 blocks that can hold a leg's frames is [E, E+SeqWindowSize] with E the L1 origin of its L2 block (the verifier
// refuses a frame outside it: batch_outside_sequencing_window). A leg is searched in widening parts of that window.
var searchSteps = []uint64{96, 384, 1536}

// memoryPerStoredByte is the heap a loaded row costs per stored byte (measured 1.43 on blob rows: the row, the decoded frame data and
// the frames it carries), rounded to 3/2.
func rowCost(n int) int64 { return int64(n) * 3 / 2 }

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

// load reads every captured inbox block (the diagnostic listing of Channels). A build never calls it: it reads the window of its leg.
func (b *Builder) load(ctx context.Context, bp *Pins) ([]capturedTx, error) {
	return b.loadRange(ctx, bp, 0, finality.MaxCaptureBlock, nil)
}

// loadRange reads the captured inbox blocks in [from, to] with their transactions and blobs. Every row read is reserved against the
// memory budget through hold first (nil hold: unbounded, tests and the listing); a refusal is the named state
// finality_memory_budget_exceeded and nothing more is read.
func (b *Builder) loadRange(ctx context.Context, bp *Pins, from, to uint64, hold *finality.Hold) ([]capturedTx, error) {
	reserve := func(n int) error {
		if hold == nil {
			return nil
		}
		return hold.Add(rowCost(n))
	}
	blocks, err := finality.CaptureKeysOfItemIn(ctx, b.Store, uint64(Chain), from, to, ItemInbox)
	if err != nil {
		return nil, err
	}
	var out []capturedTx
	for _, k := range blocks {
		raw, ok, err := b.Store.Get(ctx, k)
		if err != nil || !ok {
			return nil, fmt.Errorf("baseposted: capture row %s vanished", k.Item)
		}
		if err := reserve(len(raw)); err != nil {
			return nil, err
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
			if err := reserve(len(txb)); err != nil {
				return nil, err
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
					if err := reserve(len(bb)); err != nil {
						return nil, err
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
	hold := finality.NewHold(ctx, uint64(Chain), "base_posted_window")
	defer hold.Release()
	sr, err := b.search(ctx, bp, l2, hold)
	if err != nil {
		return nil, nil, err
	}
	ch, frameTxs, bt, l2blk := sr.ch, sr.frameTxs, sr.bt, sr.l2blk
	if ch == nil {
		return pend("l1_posted_unproven", map[string]any{"l2_timestamp": l2.Timestamp, "last_scanned_l1": sr.lastScanned})
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
	minBlock, maxBlock := frameBlockRange(frameTxs, bt)
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
	if l2blk == nil { // a builder without the window's L2 read (the whole-store search) reads the block now
		blk, err := b.L2.Block(ctx, l2.Number)
		if err != nil {
			return nil, nil, st("l2_header_unavailable", "block", l2.Number)
		}
		l2blk = &blk
	}
	body := Body{LC: lc, L1Spine: spine, ChannelID: ch.ID, Deposits: leadingDeposits(l2blk.Txs)}
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
	sortFrames(body.Frames)
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

// searched is what search found: the channel (nil when none), the transactions that carry it, its batch, the highest L1 block the
// capture is known to have scanned, and the L2 block when the search read it.
type searched struct {
	ch          *channelRef
	frameTxs    []capturedTx
	bt          *Batch
	lastScanned uint64
	l2blk       *L2BlockData
}

// search finds the channel that carries the batch of the leg's L2 block in the captured rows, reading the window of the store the leg
// can need and no more (RB12-F1/F3). The frames of a batch lie in [E, E+SeqWindowSize], E being the L1 origin that the L2 block's first
// deposit names (the verifier refuses a frame outside it), and the rows are read in widening parts of that window, so the cost of a
// leg is the rows after its origin and not the whole table. When the capture cursor shows that the window lies wholly below the first
// block this validator's capture scanned, nothing is read at all: the evidence cannot be built from this store and the state says so
// (l1_capture_not_covering), instead of a 300 s build that ends in a timeout. A builder without an L2 source has no origin to
// start from and reads the whole range, still under the memory budget.
func (b *Builder) search(ctx context.Context, bp *Pins, l2 finality.HeaderFields, hold *finality.Hold) (searched, error) {
	var sr searched
	if b.L2 == nil {
		txs, err := b.loadRange(ctx, bp, 0, finality.MaxCaptureBlock, hold)
		if err != nil {
			return sr, err
		}
		sr.ch, sr.frameTxs, sr.bt, sr.lastScanned = findChannel(txs, bp, l2.Timestamp)
		return sr, nil
	}
	blk, err := b.L2.Block(ctx, l2.Number)
	if err != nil {
		return sr, st("l2_header_unavailable", "block", l2.Number)
	}
	sr.l2blk = &blk
	deps := leadingDeposits(blk.Txs)
	if len(deps) == 0 {
		return sr, st(CodeBatchBindingMismatch, "field", "l1_info_deposit")
	}
	origin, _, ok := l1Info(deps[0])
	if !ok {
		return sr, st(CodeBatchBindingMismatch, "field", "l1_info_deposit")
	}
	end := origin + bp.SeqWindowSize
	if end < origin {
		end = finality.MaxCaptureBlock
	}
	cov, known, err := finality.CaptureCoverageOf(ctx, b.Store, uint64(Chain))
	if err != nil {
		return sr, err
	}
	var lower uint64 // the first block the capture loop may have scanned
	if known {
		slack := b.CursorSlack
		if slack == 0 {
			slack = 64
		}
		if cov.First > slack {
			lower = cov.First - slack
		}
		sr.lastScanned = cov.Last
	}
	notCovering := func() error {
		archive := "unset"
		if b.HasArchive {
			archive = "set"
		}
		return st(CodeCaptureNotCovering, "chain", uint64(Chain), "kind", KindName, "epoch_l1_block", origin, "window_end_l1_block", end,
			"capture_first_l1_block", cov.First, "capture_slack", slackOf(b.CursorSlack), "archive_provider", archive)
	}
	if known && end < lower {
		return sr, notCovering()
	}
	var all []capturedTx
	next := origin
	for i := 0; ; i++ {
		hi := end
		if i < len(searchSteps) && origin+searchSteps[i] < end {
			hi = origin + searchSteps[i]
		}
		part, err := b.loadRange(ctx, bp, next, hi, hold)
		if err != nil {
			return sr, err
		}
		all = append(all, part...)
		var last uint64
		sr.ch, sr.frameTxs, sr.bt, last = findChannel(all, bp, l2.Timestamp)
		if !known && last > sr.lastScanned {
			sr.lastScanned = last
		}
		if sr.ch != nil || hi >= end {
			break
		}
		next = hi + 1
	}
	if sr.ch == nil && known && origin < lower {
		return sr, notCovering() // part of the window was never scanned: the channel may have been posted there
	}
	if sr.ch == nil {
		// RB12-CAPTURE-GAP: a recorded gap inside the window may hold the channel; "not posted yet" cannot be said while it is open
		pieces, err := finality.GapsIn(ctx, b.Store, uint64(Chain), origin, end)
		if err != nil {
			return sr, err
		}
		if gs := gapState(pieces, origin, end, b.HasArchive); gs != nil {
			return sr, gs
		}
	}
	return sr, nil
}

func slackOf(v uint64) uint64 {
	if v == 0 {
		return 64
	}
	return v
}

// frameBlockRange is the lowest and the highest L1 block the evidence cites: the blocks of the frame transactions and, for a span batch,
// its L1 origin when that is lower (the origin's deposit is part of what the verifier binds). frameTxs is not empty.
func frameBlockRange(frameTxs []capturedTx, bt *Batch) (minBlock, maxBlock uint64) {
	maxBlock, minBlock = frameTxs[0].key.L1Block, frameTxs[0].key.L1Block
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
	return minBlock, maxBlock
}

// leadingDeposits is the deposit transactions (type 0x7e) that open an L2 block; the first other transaction ends them.
func leadingDeposits(txs [][]byte) [][]byte {
	var deposits [][]byte
	for _, t := range txs {
		if len(t) > 0 && t[0] == 0x7e {
			deposits = append(deposits, t)
		} else {
			break
		}
	}
	return deposits
}

// sortFrames orders the frame transactions as the verifier requires them: by L1 block, then by index inside the block.
func sortFrames(frames []FrameTx) {
	sort.SliceStable(frames, func(i, j int) bool {
		if frames[i].L1Block != frames[j].L1Block {
			return frames[i].L1Block < frames[j].L1Block
		}
		return frames[i].TxIndex < frames[j].TxIndex
	})
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
