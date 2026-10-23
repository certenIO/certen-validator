// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// IndexConfig bounds one indexer step. The zero value is the production default.
type IndexConfig struct {
	BlocksPerStep   int           // captured blocks digested per step (default 128)
	StepBudget      time.Duration // wall time after which a step stops at a block boundary (default 15 s): capture is never starved
	ReconcileSpan   uint64        // L1 blocks of the reconcile walk per round (default 4096)
	ReconcileEvery  int           // a reconcile round every this many steps (default 8; the first step always reconciles)
	SelfCheckEvery  int           // a self-check every this many steps (default 256)
	SelfCheckSample int           // entries and digests recomputed per self-check (default 4)
	Logf            func(string, ...any)
	// OnState receives the named inconsistency a self-check or a corrupt row found (the runner records it in the status table).
	OnState func(*finality.StateError)
}

func (c IndexConfig) blocks() int {
	if c.BlocksPerStep > 0 {
		return c.BlocksPerStep
	}
	return 128
}

func (c IndexConfig) budget() time.Duration {
	if c.StepBudget > 0 {
		return c.StepBudget
	}
	return 15 * time.Second
}

func (c IndexConfig) span() uint64 {
	if c.ReconcileSpan > 0 {
		return c.ReconcileSpan
	}
	return 4096
}

func (c IndexConfig) every() int {
	if c.ReconcileEvery > 0 {
		return c.ReconcileEvery
	}
	return 8
}

func (c IndexConfig) selfEvery() int {
	if c.SelfCheckEvery > 0 {
		return c.SelfCheckEvery
	}
	return 256
}

func (c IndexConfig) sample() int {
	if c.SelfCheckSample > 0 {
		return c.SelfCheckSample
	}
	return 4
}

func (c IndexConfig) logf(format string, a ...any) {
	if c.Logf != nil {
		c.Logf(format, a...)
	}
}

// Indexer builds the Base capture index as captures arrive. It is driven by the capture loop after each tick, one step at a time (it is
// not safe for concurrent use), resumes from its cursor after a restart and writes only rows that are a pure function of the captured
// bytes, so seven validators sharing one database can all run it.
type Indexer struct {
	Store finality.CaptureStore
	Pins  *Pins
	Gen   uint32
	Cfg   IndexConfig

	table        *frameTable
	seeded       bool
	cursor       uint64
	haveCursor   bool
	steps        int
	reconcilePos uint64
	rng          *rand.Rand
}

var _ finality.CaptureIndexer = (*Indexer)(nil)

// NewIndexer returns an indexer of generation gen (0: finality.DefaultIndexGeneration).
func NewIndexer(store finality.CaptureStore, bp *Pins, gen uint32, cfg IndexConfig) *Indexer {
	if gen == 0 {
		gen = finality.DefaultIndexGeneration
	}
	return &Indexer{Store: store, Pins: bp, Gen: gen, Cfg: cfg, rng: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

// Chain implements finality.CaptureIndexer.
func (ix *Indexer) Chain() uint64 { return uint64(Chain) }

// Family implements finality.CaptureIndexer.
func (ix *Indexer) Family() string { return FamilyBaseInbox }

func (ix *Indexer) item(parts ...string) string {
	return finality.IndexItem(ix.Gen, FamilyBaseInbox, parts...)
}

// window is how far apart the frames of a channel the index joins may lie: the sequencing window (the verifier refuses a frame further
// than that from the batch's L1 origin).
func (ix *Indexer) window() uint64 { return ix.Pins.SeqWindowSize }

func (ix *Indexer) state(s *finality.StateError) {
	if ix.Cfg.OnState != nil {
		ix.Cfg.OnState(s)
	}
}

// memoryRefusal reports whether err is the memory budget's named refusal (the step then ends and tries again later).
func memoryRefusal(err error) bool {
	if st, ok := finality.AsNamed(err); ok {
		return st.Code == finality.CodeMemoryBudget
	}
	return false
}

// init reads the cursor and loads the digests of the last window into the frame table.
func (ix *Indexer) init(ctx context.Context) error {
	if ix.seeded {
		return nil
	}
	_, hi, ok, err := finality.ReadIndexCursor(ctx, ix.Store, uint64(Chain), ix.Gen, FamilyBaseInbox)
	if err != nil {
		return err
	}
	ix.table = newFrameTable()
	ix.haveCursor, ix.cursor = ok, hi
	if ok {
		from := uint64(0)
		if hi > ix.window() {
			from = hi - ix.window()
		}
		if _, err := ix.loadDigests(ctx, ix.table, from, hi); err != nil {
			return err
		}
	} else {
		metrics.IncFinalityIndexRebuild(uint64(Chain), FamilyBaseInbox)
		ix.Cfg.logf("[FINALITY] index base-inbox: generation %d starts (no cursor row): backfill from the first captured block", ix.Gen)
	}
	ix.seeded = true
	return nil
}

// loadDigests reads the stored digests of [from, to] into tbl and returns how many.
func (ix *Indexer) loadDigests(ctx context.Context, tbl *frameTable, from, to uint64) (int, error) {
	keys, err := finality.CaptureKeysOfItemIn(ctx, ix.Store, uint64(Chain), from, to, ix.item(itemDigest))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys {
		b, ok, err := ix.Store.Get(ctx, k)
		if err != nil {
			return n, err
		}
		if !ok {
			continue
		}
		d, err := decodeDigest(k, b)
		if err != nil {
			s := finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
			ix.state(s)
			return n, s
		}
		tbl.add(uint64(Chain), d)
		n++
	}
	return n, nil
}

// digestBlock reads the rows of one captured block and writes its digest. The rows are reserved against the memory budget while they
// are read and released before the call returns.
func (ix *Indexer) digestBlock(ctx context.Context, bk finality.CaptureKey, rep *finality.StepReport) (*blockDigest, error) {
	hold := finality.NewHold(ctx, uint64(Chain), "base_index_block")
	defer hold.Release()
	bk.Item = ""
	txs, err := loadBlockTxs(ctx, ix.Store, bk, hold)
	if err != nil {
		return nil, err
	}
	for _, t := range txs {
		rep.BytesRead += t.read
	}
	d := digestOf(bk, txs)
	dk := bk
	dk.Item = ix.item(itemDigest)
	if err := finality.IndexPut(ctx, ix.Store, FamilyBaseInbox, dk, d.encode()); err != nil {
		return nil, err
	}
	metrics.AddFinalityIndexWritten(uint64(Chain), FamilyBaseInbox, 1, 0, 0)
	return d, nil
}

// getOrMakeDigest returns the stored digest of a captured block, writing it first when absent.
func (ix *Indexer) getOrMakeDigest(ctx context.Context, bk finality.CaptureKey, rep *finality.StepReport) (d *blockDigest, wrote bool, err error) {
	dk := bk
	dk.Item = ix.item(itemDigest)
	b, ok, err := ix.Store.Get(ctx, dk)
	if err != nil {
		return nil, false, err
	}
	if ok {
		d, err := decodeDigest(bk, b)
		if err != nil {
			s := finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexEntryCorrupt, "item", dk.Item, "l1_block", bk.L1Block)
			ix.state(s)
			return nil, false, s
		}
		return d, false, nil
	}
	d, err = ix.digestBlock(ctx, bk, rep)
	return d, true, err
}

// entryExists reports whether a channel entry for id is stored at the closing block key ck.
func (ix *Indexer) entryExists(ctx context.Context, ck finality.CaptureKey, id [16]byte) (bool, error) {
	keys, err := ix.Store.ListByRange(ctx, ck.Chain, ck.L1Block, ck.L1Block, ix.item(itemChannel)+"/")
	if err != nil {
		return false, err
	}
	suffix := "/" + hex.EncodeToString(id[:])
	for _, k := range keys {
		if k.L1Hash == ck.L1Hash && strings.HasSuffix(k.Item, suffix) {
			return true, nil
		}
	}
	return false, nil
}

// ensureEntry makes the entry of channel id exist when the table holds its complete frames, or the marker when a frame that arrived late
// breaks a channel that was already closed. It returns whether it wrote an entry.
func (ix *Indexer) ensureEntry(ctx context.Context, tbl *frameTable, id [16]byte) (bool, error) {
	fr := tbl.byCh[id]
	if !complete(fr) {
		return false, ix.markBroken(ctx, id, fr)
	}
	closing := fr[len(fr)-1]
	ck := finality.CaptureKey{Chain: uint64(Chain), L1Block: closing.Block, L1Hash: closing.Hash}
	exists, err := ix.entryExists(ctx, ck, id)
	if err != nil || exists {
		return false, err
	}
	hold := finality.NewHold(ctx, uint64(Chain), "base_index_channel")
	defer hold.Release()
	var lts []loadedTx
	for _, t := range txsOf(fr) {
		lt, err := loadTxRows(ctx, ix.Store, finality.CaptureKey{Chain: uint64(Chain), L1Block: t.Block, L1Hash: t.Hash}, t.Index, hold, true)
		if err != nil {
			return false, err
		}
		if uint32(len(lt.blobs)) != t.Blobs {
			return false, finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexRowsDisagree, "item", ItemBlob(t.Index, len(lt.blobs)), "l1_block", t.Block)
		}
		lts = append(lts, lt)
	}
	e, err := ix.entryFrom(id, fr, lts, hold)
	if err != nil {
		return false, err
	}
	ck.Item = channelItem(ix.Gen, e.TMin, e.TMax, id)
	if err := finality.IndexPut(ctx, ix.Store, FamilyBaseInbox, ck, e.encode()); err != nil {
		return false, err
	}
	metrics.AddFinalityIndexWritten(uint64(Chain), FamilyBaseInbox, 0, 1, 0)
	return true, nil
}

// entryFrom builds the entry of a complete channel from its ordered frame positions and the loaded transactions that carry them. It is
// shared by the indexer and by the self-check's reference recomputation; the frames are gathered by the caller.
func (ix *Indexer) entryFrom(id [16]byte, fr []frameRef, lts []loadedTx, hold *finality.Hold) (*chanEntry, error) {
	return entryFromFrames(ix.Pins, id, fr, lts, hold)
}

func entryFromFrames(bp *Pins, id [16]byte, fr []frameRef, lts []loadedTx, hold *finality.Hold) (*chanEntry, error) {
	var frames []Frame
	for _, lt := range lts {
		for _, f := range lt.frames {
			if f.ID == id {
				frames = append(frames, f)
			}
		}
	}
	if len(frames) != len(fr) {
		return nil, finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexRowsDisagree, "item", ItemInbox, "l1_block", fr[0].Block)
	}
	var stream []byte
	for i, f := range frames {
		if uint64(f.Number) != uint64(i) || f.IsLast != (i == len(frames)-1) {
			return nil, finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexRowsDisagree, "item", ItemInbox, "l1_block", fr[0].Block)
		}
		stream = append(stream, f.Data...)
	}
	e := &chanEntry{Status: entryDecoded, Pins: pinsDigest(bp), ID: id, FirstBlock: fr[0].Block, FirstHash: fr[0].Hash, FirstTx: fr[0].TxIndex,
		NFrames: uint32(len(fr)), Txs: txsOf(fr)}
	if hold != nil {
		if err := hold.Add(int64(len(stream))); err != nil {
			return nil, err
		}
	}
	raw, err := decompress(stream, bp.MaxRLPBytesPerChannel)
	if err != nil {
		e.Status = entryDecodeFailed
		return e, nil
	}
	if hold != nil {
		if err := hold.Add(int64(len(raw)) * 2); err != nil {
			return nil, err
		}
	}
	batches, err := decodeBatches(raw, spanParams{GenesisTime: bp.L2GenesisTime, BlockTime: bp.L2BlockTime, ChainID: bp.ChainID})
	if err != nil {
		e.Status = entryDecodeFailed
		return e, nil
	}
	runs, tmin, tmax, ok := runsOf(batches, bp.L2BlockTime)
	e.TMin, e.TMax = tmin, tmax
	if !ok {
		e.Status = entryCoverageOverflow
		return e, nil
	}
	e.Runs = runs
	return e, nil
}

// markBroken writes the duplicate-after-close marker for a channel that is no longer complete but has an entry at the block of one of its
// closing frames: a late block added a frame that breaks it. A channel that never completed has nothing to mark.
func (ix *Indexer) markBroken(ctx context.Context, id [16]byte, fr []frameRef) error {
	for _, f := range fr {
		if !f.Last {
			continue
		}
		ck := finality.CaptureKey{Chain: uint64(Chain), L1Block: f.Block, L1Hash: f.Hash}
		exists, err := ix.entryExists(ctx, ck, id)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		ck.Item = markerItem(ix.Gen, id)
		if err := finality.IndexPut(ctx, ix.Store, FamilyBaseInbox, ck, []byte("dup")); err != nil {
			return err
		}
		ix.Cfg.logf("[FINALITY] index base-inbox: channel %x closed at L1 block %d is broken by a late frame; marker written", id[:4], f.Block)
	}
	return nil
}

// Step implements finality.CaptureIndexer: digest the captured blocks in (cursor, upTo] in order, write the entries of the channels they
// complete, advance the cursor, then (on schedule) reconcile late arrivals and self-check. It never returns an error for a step that
// merely ran out of its block, time or memory limits; the report says why it stopped.
func (ix *Indexer) Step(ctx context.Context, upTo uint64) (rep finality.StepReport, _ error) {
	start := time.Now()
	rep.Target = upTo
	defer func() {
		rep.Elapsed = time.Since(start)
		metrics.ObserveFinalityIndexStep(uint64(Chain), FamilyBaseInbox, rep.Elapsed.Seconds())
		if ix.table != nil {
			rep.Open = ix.table.openChannels()
		}
		metrics.SetFinalityIndexProgress(uint64(Chain), FamilyBaseInbox, rep.Through, upTo, rep.Open)
	}()
	if err := ix.init(ctx); err != nil {
		return rep, err
	}
	ix.steps++
	deadline := start.Add(ix.Cfg.budget())
	from := uint64(0)
	if ix.haveCursor {
		from = ix.cursor + 1
	}
	rep.Through = ix.cursor
	if !ix.haveCursor && upTo == 0 {
		return rep, nil
	}
	if from <= upTo {
		keys, err := finality.CaptureKeysOfItemIn(ctx, ix.Store, uint64(Chain), from, upTo, ItemSysCfg)
		if err != nil {
			return rep, err
		}
		done := upTo // the cursor candidate: everything up to here is processed
		for i := 0; i < len(keys); {
			j := i
			for j < len(keys) && keys[j].L1Block == keys[i].L1Block {
				j++
			}
			group := keys[i:j] // one height: a reorged height has several hashes, evaluated together so the result does not depend on their order
			i = j
			if cause := ix.stopCause(ctx, rep.Blocks, deadline); cause != "" {
				rep.StoppedByCap, done = cause, group[0].L1Block-1
				break
			}
			ds, err := ix.digestGroup(ctx, group, &rep)
			if err == nil {
				for _, d := range ds {
					ix.table.add(uint64(Chain), d)
				}
				if h := group[0].L1Block; h > ix.window() {
					ix.table.prune(h - ix.window())
				}
				err = ix.evalGroup(ctx, ix.table, ds, &rep)
			}
			if err != nil {
				if memoryRefusal(err) {
					rep.StoppedByCap, done = "budget", group[0].L1Block-1
					break
				}
				ix.advance(ctx, group[0].L1Block-1)
				return rep, err
			}
		}
		if err := ix.advance(ctx, done); err != nil {
			return rep, err
		}
		rep.Through = ix.cursor
	}
	if ix.haveCursor && (ix.steps-1)%ix.Cfg.every() == 0 && rep.StoppedByCap == "" {
		if err := ix.reconcile(ctx, &rep, deadline); err != nil && !memoryRefusal(err) {
			return rep, err
		}
	}
	if ix.haveCursor && ix.steps%ix.Cfg.selfEvery() == 0 {
		if err := ix.SelfCheck(ctx, ix.Cfg.sample()); err != nil {
			return rep, err
		}
	}
	if rep.Blocks > 0 || rep.Entries > 0 || rep.Late > 0 || rep.StoppedByCap != "" {
		ix.Cfg.logf("[FINALITY] index base-inbox: step %d: through %d of %d: %d blocks digested, %d entries, %d late, %d open channels, %d KB read in %s%s",
			ix.steps, rep.Through, upTo, rep.Blocks, rep.Entries, rep.Late, rep.Open, rep.BytesRead/1024, rep.Elapsed.Round(time.Millisecond), stoppedNote(rep.StoppedByCap))
	}
	return rep, nil
}

func stoppedNote(c string) string {
	if c == "" {
		return ""
	}
	return " (stopped: " + c + ")"
}

// stopCause names why a step must end before starting another block: its block bound, its time bound or the context.
func (ix *Indexer) stopCause(ctx context.Context, blocks int, deadline time.Time) string {
	switch {
	case ctx.Err() != nil:
		return "context"
	case blocks >= ix.Cfg.blocks():
		return "blocks"
	case time.Now().After(deadline):
		return "time"
	}
	return ""
}

// noBlock is the result of 'the block before block 0'.
const noBlock = ^uint64(0)

// advance writes the cursor row at block when it moves the cursor forward.
func (ix *Indexer) advance(ctx context.Context, block uint64) error {
	if block == noBlock { // the block before height 0
		return nil
	}
	if ix.haveCursor && block <= ix.cursor {
		return nil
	}

	if err := finality.WriteIndexCursor(ctx, ix.Store, uint64(Chain), ix.Gen, FamilyBaseInbox, block); err != nil {
		return err
	}
	ix.cursor, ix.haveCursor = block, true
	return nil
}

// digestGroup digests the captured blocks of one height (writing the digests that are absent).
func (ix *Indexer) digestGroup(ctx context.Context, group []finality.CaptureKey, rep *finality.StepReport) ([]*blockDigest, error) {
	var ds []*blockDigest
	for _, k := range group {
		d, wrote, err := ix.getOrMakeDigest(ctx, k, rep)
		if err != nil {
			return nil, err
		}
		if wrote {
			rep.Blocks++
		}
		ds = append(ds, d)
	}
	return ds, nil
}

// evalGroup evaluates, over tbl, every channel the digests carry frames of (once each, in order of first appearance).
func (ix *Indexer) evalGroup(ctx context.Context, tbl *frameTable, ds []*blockDigest, rep *finality.StepReport) error {
	seen := map[[16]byte]bool{}
	for _, d := range ds {
		for _, id := range channelIDs(d) {
			if seen[id] {
				continue
			}
			seen[id] = true
			w, err := ix.ensureEntry(ctx, tbl, id)
			if err != nil {
				return err
			}
			if w {
				rep.Entries++
			}
		}
	}
	return nil
}

// reconcile walks one chunk of the whole captured range, finds captured blocks that have no digest (they arrived after the cursor passed
// them: a retried capture, a block captured by another validator, a hole filled later) and indexes them: the digest, then the channels
// they touch re-evaluated over the stored digests within the sequencing window either side.
func (ix *Indexer) reconcile(ctx context.Context, rep *finality.StepReport, deadline time.Time) error {
	lo, _, ok, err := finality.BlockBoundsOf(ctx, ix.Store, uint64(Chain), ItemSysCfg)
	if err != nil || !ok {
		return err
	}
	if ix.reconcilePos < lo || ix.reconcilePos > ix.cursor {
		ix.reconcilePos = lo
	}
	from := ix.reconcilePos
	to := from + ix.Cfg.span() - 1
	if to < from || to > ix.cursor {
		to = ix.cursor
	}
	if from > to {
		return nil
	}
	sys, err := finality.CaptureKeysOfItemIn(ctx, ix.Store, uint64(Chain), from, to, ItemSysCfg)
	if err != nil {
		return err
	}
	have, err := finality.CaptureKeysOfItemIn(ctx, ix.Store, uint64(Chain), from, to, ix.item(itemDigest))
	if err != nil {
		return err
	}
	digested := map[[40]byte]bool{}
	for _, k := range have {
		digested[blockID(k)] = true
	}
	var missing []finality.CaptureKey
	for _, k := range sys {
		if !digested[blockID(k)] {
			missing = append(missing, k)
		}
	}
	var tmp *frameTable
	var tmpLo, tmpHi uint64
	next := to + 1
	for i := 0; i < len(missing); {
		j := i
		for j < len(missing) && missing[j].L1Block == missing[i].L1Block {
			j++
		}
		group := missing[i:j]
		i = j
		if cause := ix.stopCause(ctx, rep.Late, deadline); cause != "" {
			next = group[0].L1Block
			break
		}
		ds, err := ix.digestGroup(ctx, group, rep)
		if err != nil {
			if memoryRefusal(err) {
				next = group[0].L1Block
				break
			}
			return err
		}
		rep.Late += len(group)
		metrics.AddFinalityIndexWritten(uint64(Chain), FamilyBaseInbox, 0, 0, len(group))
		// the frames of the channels these blocks touch lie within the sequencing window either side of them
		h := group[0].L1Block
		if tmp == nil || h < tmpLo+ix.window() || h+ix.window() > tmpHi {
			tmp = newFrameTable()
			tmpLo = 0
			if h > ix.window() {
				tmpLo = h - ix.window()
			}
			tmpHi = h + 3*ix.window()
			if _, err := ix.loadDigests(ctx, tmp, tmpLo, tmpHi); err != nil {
				return err
			}
		}
		for _, d := range ds {
			tmp.add(uint64(Chain), d)
			if d.Block+ix.window() >= ix.cursor { // the block lies in the range the sliding table covers
				ix.table.add(uint64(Chain), d)
			}
		}
		if err := ix.evalGroup(ctx, tmp, ds, rep); err != nil {
			if memoryRefusal(err) {
				next = h
				break
			}
			return err
		}
	}
	ix.reconcilePos = next
	if next <= to {
		return nil // the round ended early (limits); the repair pass waits for a round that covers its chunk
	}
	return ix.repairEntries(ctx, from, to, rep)
}

// repairEntries makes sure that every channel that closes in [from, to] and is complete over the stored digests has its entry: a crash between
// the digest of a late block and the entry it completes, or a row lost for any other reason, leaves a digest without its entry, which the
// digest walk above cannot see. One key listing of the chunk and the digests within the sequencing window either side; entries are written
// only where absent.
func (ix *Indexer) repairEntries(ctx context.Context, from, to uint64, rep *finality.StepReport) error {
	lo := uint64(0)
	if from > ix.window() {
		lo = from - ix.window()
	}
	tbl := newFrameTable()
	if _, err := ix.loadDigests(ctx, tbl, lo, to+ix.window()); err != nil {
		return err
	}
	keys, err := ix.Store.ListByRange(ctx, uint64(Chain), from, to, ix.item(itemChannel)+"/")
	if err != nil {
		return err
	}
	have := map[[56]byte]bool{}
	for _, k := range keys {
		if n, ok := parseEntryName(ix.Gen, k); ok {
			have[entryID(k.L1Block, k.L1Hash, n.ID)] = true
		}
	}
	for id, fr := range tbl.byCh {
		if !complete(fr) {
			continue
		}
		closing := fr[len(fr)-1]
		if closing.Block < from || closing.Block > to || have[entryID(closing.Block, closing.Hash, id)] {
			continue
		}
		w, err := ix.ensureEntry(ctx, tbl, id)
		if err != nil {
			if memoryRefusal(err) {
				return nil
			}
			return err
		}
		if w {
			rep.Entries++
			ix.Cfg.logf("[FINALITY] index base-inbox: repaired the missing entry of channel %x closed at L1 block %d", id[:4], closing.Block)
		}
	}
	return nil
}

// entryID identifies a channel entry by its closing block, block hash and channel id.
func entryID(block uint64, hash [32]byte, id [16]byte) [56]byte {
	var out [56]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(block >> (56 - 8*i))
	}
	copy(out[8:], hash[:])
	copy(out[40:], id[:])
	return out
}

// blockID identifies a captured block (number and hash) as a map key.
func blockID(k finality.CaptureKey) [40]byte {
	var out [40]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(k.L1Block >> (56 - 8*i))
	}
	copy(out[8:], k.L1Hash[:])
	return out
}

// SelfCheck implements finality.CaptureIndexer: it recomputes sample stored channel entries and block digests from the captured rows by
// the reference path (loadRange, the window reader's own loader, and the same decoding) and compares BYTES with the stored rows. A
// difference is the named state index_inconsistent{self_check_mismatch}, counted, logged, and returned.
func (ix *Indexer) SelfCheck(ctx context.Context, sample int) error {
	if err := ix.init(ctx); err != nil {
		return err
	}
	lo, hi, ok, err := finality.BlockBoundsOf(ctx, ix.Store, uint64(Chain), ix.item(itemDigest))
	if err != nil || !ok {
		return err
	}
	span := ix.Cfg.span()
	at := lo
	if hi > lo+span {
		at = lo + uint64(ix.rng.Int63n(int64(hi-lo-span+1)))
	}
	var firstErr error
	note := func(s *finality.StateError) {
		metrics.IncFinalityIndexMismatch(uint64(Chain), FamilyBaseInbox)
		ix.state(s)
		ix.Cfg.logf("[FINALITY] index base-inbox: self-check MISMATCH %s", s.Error())
		if firstErr == nil {
			firstErr = s
		}
	}
	// entries
	names, err := ix.Store.ListByRange(ctx, uint64(Chain), at, at+span, ix.item(itemChannel)+"/")
	if err != nil {
		return err
	}
	ix.shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	checked := 0
	for _, k := range names {
		if checked >= sample {
			break
		}
		n, ok := parseEntryName(ix.Gen, k)
		if !ok {
			note(finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block))
			checked++
			continue
		}
		stored, ok, err := ix.Store.Get(ctx, k)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		want, err := ix.referenceEntry(ctx, n)
		if err != nil {
			if memoryRefusal(err) {
				return nil
			}
			return err
		}
		if !bytes.Equal(stored, want) {
			note(finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexSelfCheckMismatch, "item", k.Item, "l1_block", k.L1Block))
		}
		checked++
	}
	// digests
	dkeys, err := finality.CaptureKeysOfItemIn(ctx, ix.Store, uint64(Chain), at, at+span, ix.item(itemDigest))
	if err != nil {
		return err
	}
	ix.shuffle(len(dkeys), func(i, j int) { dkeys[i], dkeys[j] = dkeys[j], dkeys[i] })
	for i, k := range dkeys {
		if i >= sample {
			break
		}
		stored, ok, err := ix.Store.Get(ctx, k)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		bk := k
		bk.Item = ""
		hold := finality.NewHold(ctx, uint64(Chain), "base_index_selfcheck")
		b := &Builder{Store: ix.Store}
		all, err := b.loadRange(ctx, ix.Pins, bk.L1Block, bk.L1Block, hold)
		hold.Release()
		if err != nil {
			if memoryRefusal(err) {
				return nil
			}
			return err
		}
		var lts []loadedTx
		for _, ct := range all {
			if ct.key.L1Hash == bk.L1Hash {
				lts = append(lts, loadedTx{index: ct.index, blobs: ct.blobs, frames: ct.frames, isBlob: isBlobRaw(ct.raw)})
			}
		}
		if want := digestOf(bk, lts).encode(); !bytes.Equal(stored, want) {
			note(finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexSelfCheckMismatch, "item", k.Item, "l1_block", k.L1Block))
		}
	}
	if firstErr == nil {
		ix.Cfg.logf("[FINALITY] index base-inbox: self-check ok (%d entries, %d digests sampled around L1 block %d)", checked, minInt(len(dkeys), sample), at)
	}
	return firstErr
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (ix *Indexer) shuffle(n int, swap func(i, j int)) { ix.rng.Shuffle(n, swap) }

func isBlobRaw(raw []byte) bool {
	var tx txView
	return tx.parse(raw) == nil && tx.isBlob
}

// referenceEntry recomputes the stored bytes of one channel entry by the reference path: the window reader's loader over the blocks the
// channel spans, the same grouping findChannel does, and the shared decoding.
func (ix *Indexer) referenceEntry(ctx context.Context, n entryName) ([]byte, error) {
	// the frames of the channel lie within the sequencing window before its closing block
	from := uint64(0)
	if n.Key.L1Block > ix.window() {
		from = n.Key.L1Block - ix.window()
	}
	hold := finality.NewHold(ctx, uint64(Chain), "base_index_selfcheck")
	defer hold.Release()
	b := &Builder{Store: ix.Store}
	all, err := b.loadRange(ctx, ix.Pins, from, n.Key.L1Block, hold)
	if err != nil {
		return nil, err
	}
	var fr []frameRef
	var lts []loadedTx
	perBlock := map[finality.CaptureKey]int{}
	for _, ct := range all {
		pos := perBlock[ct.key]
		perBlock[ct.key]++
		has := false
		for fi, f := range ct.frames {
			if f.ID != n.ID {
				continue
			}
			has = true
			fr = append(fr, frameRef{Block: ct.key.L1Block, Hash: ct.key.L1Hash, TxPos: pos, TxIndex: ct.index, Blobs: uint32(len(ct.blobs)), FrameIdx: fi, Number: f.Number, Last: f.IsLast})
		}
		if has {
			lts = append(lts, loadedTx{index: ct.index, blobs: ct.blobs, frames: ct.frames})
		}
	}
	if !complete(fr) {
		return nil, finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, finality.IndexSelfCheckMismatch, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	e, err := entryFromFrames(ix.Pins, n.ID, fr, lts, hold)
	if err != nil {
		return nil, err
	}
	return e.encode(), nil
}

// IsIndexConflict reports whether err is the named conflicting-write error.
func IsIndexConflict(err error) bool { return errors.Is(err, finality.ErrIndexConflict) }
