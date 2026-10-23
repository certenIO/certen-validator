// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/metrics"
)

// IndexConfig bounds one indexer step. The zero value is the production default.
type IndexConfig struct {
	BlocksPerStep   int           // captured blocks digested per step (default 64)
	StepBudget      time.Duration // wall time after which a step stops at a block boundary (default 15 s): capture is never starved
	ReconcileSpan   uint64        // L1 blocks of the rotating reconcile walk per round (default 4096)
	ReconcileEvery  int           // a rotating round every this many steps (default 8; the first step always reconciles)
	SelfCheckEvery  int           // a self-check every this many steps (default 256)
	SelfCheckSample int           // entries and digests recomputed per self-check (default 4)
	RecentSpan      uint64        // L1 blocks below the cursor every step re-examines first (default 512): late data lies near the cursor
	MaxFps          int           // message fingerprints one entry stores; a batch with more is entryOverflow, named at lookup (default 131,072)
	Logf            func(string, ...any)
	// OnState receives the named inconsistency a self-check or a corrupt row found (the runner records it in the status table).
	OnState func(*finality.StateError)
}

func (c IndexConfig) blocks() int {
	if c.BlocksPerStep > 0 {
		return c.BlocksPerStep
	}
	return 64
}

func (c IndexConfig) maxFps() int {
	if c.MaxFps > 0 && c.MaxFps < maxFps {
		return c.MaxFps
	}
	return maxFps
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

func (c IndexConfig) recent() uint64 {
	if c.RecentSpan > 0 {
		return c.RecentSpan
	}
	return 512
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

// Indexer builds the Arbitrum batch index as batches are captured. It is driven by the capture loop after each tick, one step at a time (it
// is not safe for concurrent use), resumes from its cursor after a restart and writes only rows that are a pure function of the captured
// rows, so seven validators sharing one database can all run it.
type Indexer struct {
	Store finality.CaptureStore
	Pins  *finality.Pins
	Gen   uint32
	Cfg   IndexConfig

	arb          *arbPins
	pins         [8]byte
	haveCursor   bool
	cursor       uint64
	steps        int
	reconcilePos uint64
	rng          *rand.Rand
	hintMu       sync.Mutex
	hints        map[uint64]bool
	dropLogged   bool
	selfRes      SelfCheckResult
}

var _ finality.CaptureIndexer = (*Indexer)(nil)
var _ finality.LateBlockNoter = (*Indexer)(nil)

// NewIndexer returns an indexer of generation gen (0: finality.DefaultIndexGeneration) under the arb_sepolia pins.
func NewIndexer(store finality.CaptureStore, pins *finality.Pins, gen uint32, cfg IndexConfig) (*Indexer, error) {
	a, err := loadArbPins(pins)
	if err != nil {
		return nil, err
	}
	if gen == 0 {
		gen = finality.DefaultIndexGeneration
	}
	return &Indexer{Store: store, Pins: pins, Gen: gen, Cfg: cfg, arb: a, pins: pinsDigest(a), rng: rand.New(rand.NewSource(time.Now().UnixNano()))}, nil
}

// Chain implements finality.CaptureIndexer.
func (ix *Indexer) Chain() uint64 { return finality.ChainArbitrumSepolia }

// Family implements finality.CaptureIndexer.
func (ix *Indexer) Family() string { return FamilyArb }

func (ix *Indexer) state(s *finality.StateError) {
	if ix.Cfg.OnState != nil {
		ix.Cfg.OnState(s)
	}
}

func memoryRefusal(err error) bool {
	if st, ok := finality.AsNamed(err); ok {
		return st.Code == finality.CodeMemoryBudget
	}
	return false
}

// holdWait bounds how long a reservation of the index waits for another build to release memory: the index runs inside the capture loop and
// must never stall it. A reservation that still does not fit is the named refusal and ends the step (the index lags, it does not fail).
const holdWait = 2 * time.Second

func (ix *Indexer) hold(ctx context.Context, what string) (*finality.Hold, func()) {
	hctx, cancel := context.WithTimeout(ctx, holdWait)
	h := finality.NewHold(hctx, ix.Chain(), what)
	return h, func() { h.Release(); cancel() }
}

func (ix *Indexer) init(ctx context.Context) error {
	if ix.haveCursor || ix.steps > 0 {
		return nil
	}
	_, hi, ok, err := finality.ReadIndexCursor(ctx, ix.Store, ix.Chain(), ix.Gen, FamilyArb)
	if err != nil {
		return err
	}
	ix.haveCursor, ix.cursor = ok, hi
	if !ok {
		metrics.IncFinalityIndexRebuild(ix.Chain(), FamilyArb)
		ix.Cfg.logf("[FINALITY] index arb: generation %d starts (no cursor row): backfill from the first captured batch", ix.Gen)
	}
	return nil
}

// ---- reading the rows of one captured block ----

// blockGroup is the batch rows of one captured block (L1 height and hash), ascending by N.
type blockGroup struct {
	key  finality.CaptureKey // Item empty
	nums []uint64
}

// groupsOf groups a listing of batch/N keys (ascending by block, hash, item) by captured block.
func groupsOf(keys []finality.CaptureKey) []blockGroup {
	var out []blockGroup
	for _, k := range keys {
		n, ok := batchNumber(k.Item)
		if !ok {
			continue
		}
		bk := k
		bk.Item = ""
		if l := len(out); l > 0 && out[l-1].key == bk {
			out[l-1].nums = append(out[l-1].nums, n)
			continue
		}
		out = append(out, blockGroup{key: bk, nums: []uint64{n}})
	}
	for i := range out {
		sort.Slice(out[i].nums, func(a, b int) bool { return out[i].nums[a] < out[i].nums[b] })
	}
	return out
}

func withItem(k finality.CaptureKey, item string) finality.CaptureKey {
	k.Item = item
	return k
}

// errBlockOpen: a batch of the block has data rows that are not all stored yet (blobs awaiting the beacon). The block is not indexed until
// they are; nothing is recorded, and a later pass (the recent window, a note, the rotation) finds it.
var errBlockOpen = errors.New("arbposted index: the block has batches whose data rows are not all stored")

// unindexableError marks a failure that comes from the CONTENT of a captured block's rows (not from the store): the indexer records the
// block as unindexable and goes on, because the rows will not change.
type unindexableError struct {
	Reason string
	Err    error
}

func (e *unindexableError) Error() string { return "unindexable (" + e.Reason + "): " + e.Err.Error() }
func (e *unindexableError) Unwrap() error { return e.Err }

func unindexable(reason string, err error) error { return &unindexableError{Reason: reason, Err: err} }

type batchRows struct {
	rec      capture.BatchRecord
	row      []byte
	blobs    [][]byte // raw blobs, in order (a blob batch)
	calldata []byte   // the calldata row (a calldata batch)
	parts    uint32
	dataLen  uint64
}

type blockRows struct {
	key     finality.CaptureKey
	t       uint64
	batches []batchRows
}

// readBlock reads the rows of one captured block, reserving each against the hold, and decides whether the block is whole.
func (ix *Indexer) readBlock(ctx context.Context, g blockGroup, hold *finality.Hold) (*blockRows, error) {
	chain := ix.Chain()
	bk := g.key
	hdrKey := withItem(bk, capture.ItemHeader)
	hb, ok, err := ix.Store.Get(ctx, hdrKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, unindexable(finality.UnindexableHeaderRowMalformed, errors.New("the header row of the batch's block is not stored"))
	}
	if err := hold.Add(finality.RowCost(len(hb))); err != nil {
		return nil, err
	}
	hf, herr := finality.ReadHeader(hb)
	if herr != nil || crypto.Keccak256Hash(hb) != common.Hash(bk.L1Hash) || hf.Number != bk.L1Block {
		return nil, unindexable(finality.UnindexableHeaderRowMalformed, errors.New("the header row is not the block's header"))
	}
	out := &blockRows{key: bk, t: hf.Timestamp}
	for _, n := range g.nums {
		k := withItem(bk, capture.ItemBatch(n))
		row, ok, err := ix.Store.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errBlockOpen // listed and gone: not stored whole (cannot happen in the insert-only table)
		}
		if err := hold.Add(finality.RowCost(len(row))); err != nil {
			return nil, err
		}
		rec, derr := capture.DecodeBatchRecord(row)
		if derr != nil || rec.N != n || rec.L1Block != bk.L1Block || rec.L1Hash != bk.L1Hash {
			return nil, unindexable(finality.UnindexableBatchRowMalformed, errors.New("the batch row does not decode or is not the batch its key names"))
		}
		br := batchRows{rec: rec, row: row}
		switch rec.DataLocation {
		case capture.LocBlob:
			for j := range rec.VersionedHashes {
				bb, ok, err := ix.Store.Get(ctx, withItem(bk, capture.ItemBlob(n, j)))
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, errBlockOpen
				}
				if err := hold.Add(finality.RowCost(len(bb))); err != nil {
					return nil, err
				}
				bl, berr := capture.DecodeBlobRecord(bb)
				if berr != nil {
					return nil, unindexable(finality.UnindexableBlobRowMalformed, berr)
				}
				br.blobs = append(br.blobs, bl.Raw)
				br.dataLen += uint64(len(bb))
			}
			br.parts = uint32(len(br.blobs))
		case capture.LocTxInput, capture.LocSeparateBatchEvent:
			cd, ok, err := ix.Store.Get(ctx, withItem(bk, capture.ItemCalldata(n)))
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, errBlockOpen
			}
			if err := hold.Add(finality.RowCost(len(cd))); err != nil {
				return nil, err
			}
			br.calldata, br.parts, br.dataLen = cd, 1, uint64(len(cd))
		}
		out.batches = append(out.batches, br)
	}
	_ = chain
	return out, nil
}

// entryOf builds the entry of one batch from its rows. It is the whole decode: the status mirrors the reference reader's skips (a payload
// that does not read as messages is a candidate that never matches), the fingerprints are those of the messages, and the memory the decode
// can take (the payload bound twice) is reserved BEFORE it runs.
func (ix *Indexer) entryOf(blk *blockRows, br batchRows, hold *finality.Hold) (*arbEntry, error) {
	rec := br.rec
	e := &arbEntry{Status: entryDecoded, Pins: ix.pins, N: rec.N, L1Block: blk.key.L1Block, L1Hash: blk.key.L1Hash, T: blk.t,
		MinTs: rec.Header40[0], MaxTs: rec.Header40[1], Loc: rec.DataLocation, Parts: br.parts, TxIndex: rec.TxIndex, TxHash: rec.TxHash,
		RowLen: uint32(len(br.row)), RowSum: rowSum(br.row)}
	var payload []byte
	switch rec.DataLocation {
	case capture.LocBlob:
		if err := hold.Add(int64(ix.arb.MaxUncompressedBatch) * 2); err != nil {
			return nil, err
		}
		p, err := decodeBlobs(br.blobs)
		if err != nil {
			e.Status = entrySkipped
			return e, nil
		}
		payload = p
	case capture.LocTxInput:
		d, err := capture.ExtractTxInputData(br.calldata)
		if err != nil {
			e.Status = entrySkipped
			return e, nil
		}
		payload = d
	case capture.LocSeparateBatchEvent:
		payload = br.calldata
	default:
		e.Status = entryNoData
		return e, nil
	}
	if rec.DataLocation != capture.LocBlob {
		if err := hold.Add(int64(ix.arb.MaxUncompressedBatch) * 2); err != nil {
			return nil, err
		}
	}
	res := decodePayload(payload, ix.arb.MaxUncompressedBatch, ix.arb.MaxSegments)
	if res.status != payloadOK {
		e.Status = entrySkipped
		return e, nil
	}
	e.Segments, e.Messages, e.Delayed = uint32(res.segments), uint32(len(res.messages)), uint32(res.delayedSegments)
	fps := fpsOf(res.messages)
	if len(fps) > ix.Cfg.maxFps() {
		e.Status = entryOverflow
		return e, nil
	}
	e.Fps = fps
	return e, nil
}

// withinCaps reports whether the batch's time bounds are inside the distances the lookup's window assumes.
func withinCaps(t, minTs, maxTs uint64) bool {
	if t > minTs && t-minTs > windowDelayCap {
		return false
	}
	if maxTs > t && maxTs-t > windowFutureCap {
		return false
	}
	return true
}

// hasDigest reports whether the block already has its digest at this generation.
func (ix *Indexer) hasDigest(ctx context.Context, bk finality.CaptureKey) (bool, error) {
	keys, err := ix.Store.ListByRange(ctx, ix.Chain(), bk.L1Block, bk.L1Block, ixItem(ix.Gen, ixDigest)+"/")
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if k.L1Hash == bk.L1Hash {
			return true, nil
		}
	}
	return false, nil
}

type groupOutcome uint8

const (
	groupDone    groupOutcome = iota // the block has its digest (written now or before), or is recorded as unindexable
	groupOpen                        // the block's data rows are not all stored yet
	groupWritten                     // the block was digested now
)

// indexGroup indexes one captured block: its entries first, then its digest (the marker that the block is whole and processed).
func (ix *Indexer) indexGroup(ctx context.Context, g blockGroup, rep *finality.StepReport) (groupOutcome, error) {
	has, err := ix.hasDigest(ctx, g.key)
	if err != nil {
		return groupDone, err
	}
	if has {
		return groupDone, nil
	}
	if _, rec, err := ix.Store.Get(ctx, withItem(g.key, unindexedItem(ix.Gen))); err != nil {
		return groupDone, err
	} else if rec {
		return groupDone, nil // recorded as unindexable: its rows will not change
	}
	hold, done := ix.hold(ctx, "arb_index_block")
	defer done()
	blk, err := ix.readBlock(ctx, g, hold)
	if err != nil {
		var ue *unindexableError
		switch {
		case errors.Is(err, errBlockOpen):
			return groupOpen, nil
		case errors.As(err, &ue):
			return groupDone, ix.recordUnindexable(ctx, g.key, ue)
		}
		return groupDone, err
	}
	for _, br := range blk.batches {
		if !withinCaps(blk.t, br.rec.Header40[0], br.rec.Header40[1]) {
			return groupDone, ix.recordUnindexable(ctx, g.key, &unindexableError{Reason: finality.UnindexableWindowBeyondCap,
				Err: errors.New("the batch's time bounds are wider than the lookup window assumes")})
		}
	}
	d := &arbDigest{Block: g.key.L1Block, Hash: g.key.L1Hash, T: blk.t, Pins: ix.pins}
	for _, br := range blk.batches {
		rep.BytesRead += int64(len(br.row)) + int64(br.dataLen)
		ok, err := ix.authorizedRecord(ctx, br.rec)
		if err != nil {
			return groupDone, err
		}
		if !ok {
			continue // a record the Bridge does not hold: no entry (the readers refuse it too)
		}
		e, err := ix.entryOf(blk, br, hold)
		if err != nil {
			return groupDone, err
		}
		ek := withItem(g.key, entryItem(ix.Gen, e.MinTs, e.MaxTs, e.N))
		if err := finality.IndexPut(ctx, ix.Store, FamilyArb, ek, e.encode()); err != nil {
			return groupDone, err
		}
		metrics.AddFinalityIndexWritten(ix.Chain(), FamilyArb, 0, 1, 0)
		rep.Entries++
		d.Batches = append(d.Batches, digestBatch{N: br.rec.N, Loc: br.rec.DataLocation, Parts: br.parts, RowLen: uint32(len(br.row)), DataBytes: br.dataLen})
	}
	if err := finality.IndexPut(ctx, ix.Store, FamilyArb, withItem(g.key, digestItem(ix.Gen, blk.t)), d.encode()); err != nil {
		return groupDone, err
	}
	metrics.AddFinalityIndexWritten(ix.Chain(), FamilyArb, 1, 0, 0)
	return groupWritten, nil
}

// authorizedRecord applies THE authorization (capture.AuthorizeBatch) to a record the indexer is about to index: a record a verified proof
// contradicts is foreign and gets no entry. Unproven records are indexed (the leg's verifier decides).
func (ix *Indexer) authorizedRecord(ctx context.Context, rec capture.BatchRecord) (bool, error) {
	verdict, err := capture.AuthorizeStored(ctx, ix.Store, ix.Chain(), rec, ix.arb.bridge, ix.arb.Layout.AccArraySlot)
	if err != nil {
		return false, err
	}
	if verdict == capture.AuthForeign {
		metrics.AddFinalityCaptureForeignTxs(ix.Chain(), 1)
		return false, nil
	}
	return true, nil
}

// recordUnindexable writes the insert-only record of a captured block the indexer cannot read and lets the cursor pass it. The record is
// named (index_block_unindexable{block, reason}) in the log and the metric.
func (ix *Indexer) recordUnindexable(ctx context.Context, bk finality.CaptureKey, ue *unindexableError) error {
	if err := finality.IndexPut(ctx, ix.Store, FamilyArb, withItem(bk, unindexedItem(ix.Gen)), []byte(ue.Reason)); err != nil {
		return err
	}
	metrics.IncFinalityIndexUnindexable(ix.Chain(), FamilyArb, ue.Reason)
	ix.Cfg.logf("[FINALITY] index arb: %s", finality.IndexBlockUnindexable(ix.Chain(), bk.L1Block, ue.Reason).Error())
	return nil
}

// ---- the step ----

// Step implements finality.CaptureIndexer: index the captured batches in (cursor, upTo] in block order, advance the cursor, then reconcile
// late data (blobs that arrived after the cursor passed their block) and, on schedule, self-check. It never returns an error for a step that
// merely ran out of its block, time or memory limits; the report says why it stopped.
func (ix *Indexer) Step(ctx context.Context, upTo uint64) (rep finality.StepReport, _ error) {
	start := time.Now()
	rep.Target = upTo
	defer func() {
		rep.Elapsed = time.Since(start)
		metrics.ObserveFinalityIndexStep(ix.Chain(), FamilyArb, rep.Elapsed.Seconds())
		metrics.SetFinalityIndexProgress(ix.Chain(), FamilyArb, rep.Through, upTo, rep.Open)
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
		keys, err := ix.Store.ListByRange(ctx, ix.Chain(), from, upTo, batchKeyPrefix)
		if err != nil {
			return rep, err
		}
		done := upTo
		groups := groupsOf(keys)
		for i, g := range groups {
			if cause := ix.stopCause(ctx, i, rep.Blocks, deadline); cause != "" {
				rep.StoppedByCap, done = cause, g.key.L1Block-1
				break
			}
			out, err := ix.indexGroup(ctx, g, &rep)
			if err != nil {
				if memoryRefusal(err) {
					rep.StoppedByCap, done = "budget", g.key.L1Block-1
					break
				}
				_ = ix.advance(ctx, g.key.L1Block-1)
				return rep, err
			}
			switch out {
			case groupWritten:
				rep.Blocks++
			case groupOpen:
				rep.Open++
			}
		}
		if err := ix.advance(ctx, done); err != nil {
			return rep, err
		}
		rep.Through = ix.cursor
	}
	late := 0
	if ix.haveCursor && rep.StoppedByCap == "" {
		n, err := ix.reconcileHints(ctx, &rep, deadline)
		if err != nil && !memoryRefusal(err) {
			return rep, err
		}
		late = n
		n, err = ix.reconcileRecent(ctx, &rep, deadline, late)
		if err != nil && !memoryRefusal(err) {
			return rep, err
		}
		late += n
	}
	if ix.haveCursor && (ix.steps-1)%ix.Cfg.every() == 0 && rep.StoppedByCap == "" {
		if err := ix.reconcileRotate(ctx, &rep, deadline, late); err != nil && !memoryRefusal(err) {
			return rep, err
		}
	}
	if ix.haveCursor && ix.steps%ix.Cfg.selfEvery() == 0 {
		if err := ix.SelfCheck(ctx, ix.Cfg.sample()); err != nil {
			return rep, err
		}
	}
	if rep.Blocks > 0 || rep.Entries > 0 || rep.Late > 0 || rep.StoppedByCap != "" {
		ix.Cfg.logf("[FINALITY] index arb: step %d: through %d of %d: %d blocks digested, %d entries, %d late, %d open, %d KB read in %s%s",
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

// stopCause names why a step must end before starting another block: the context, its block bound (blocks written) or its time bound;
// never before the first block of the step (a limit set too low slows the index, it never stops it).
func (ix *Indexer) stopCause(ctx context.Context, groups, blocks int, deadline time.Time) string {
	switch {
	case ctx.Err() != nil:
		return "context"
	case groups == 0:
		return ""
	case blocks >= ix.Cfg.blocks():
		return "blocks"
	case time.Now().After(deadline):
		return "time"
	}
	return ""
}

const noBlock = ^uint64(0)

// advance writes the cursor row at block when it moves the cursor forward.
func (ix *Indexer) advance(ctx context.Context, block uint64) error {
	if block == noBlock {
		return nil
	}
	if ix.haveCursor && block <= ix.cursor {
		return nil
	}
	if err := finality.WriteIndexCursor(ctx, ix.Store, ix.Chain(), ix.Gen, FamilyArb, block); err != nil {
		return err
	}
	ix.cursor, ix.haveCursor = block, true
	return nil
}

// ---- late data: hints, the recent window, the rotating walk ----

// reconcileBlocks indexes the captured blocks of [from, to] that have batch rows and neither a digest nor an unindexable record. done is
// the number of blocks the step has already worked on this step (the first of a step is free, the rest obey the limits). It returns the
// block it stopped at (to+1 when it covered the range) and the blocks it worked on.
func (ix *Indexer) reconcileBlocks(ctx context.Context, rep *finality.StepReport, deadline time.Time, from, to uint64, done int) (uint64, int, error) {
	keys, err := ix.Store.ListByRange(ctx, ix.Chain(), from, to, batchKeyPrefix)
	if err != nil {
		return from, 0, err
	}
	have, err := ix.Store.ListByRange(ctx, ix.Chain(), from, to, ixItem(ix.Gen, ixDigest)+"/")
	if err != nil {
		return from, 0, err
	}
	unread, err := finality.CaptureKeysOfItemIn(ctx, ix.Store, ix.Chain(), from, to, unindexedItem(ix.Gen))
	if err != nil {
		return from, 0, err
	}
	seen := map[[40]byte]bool{}
	for _, k := range have {
		seen[blockID(k)] = true
	}
	for _, k := range unread {
		seen[blockID(k)] = true
	}
	var missing []blockGroup
	for _, g := range groupsOf(keys) {
		if !seen[blockID(g.key)] {
			missing = append(missing, g)
		}
	}
	next := to + 1
	worked := 0
	for i, g := range missing {
		if cause := ix.stopCause(ctx, done+i, rep.Late, deadline); cause != "" {
			next = g.key.L1Block
			break
		}
		out, err := ix.indexGroup(ctx, g, rep)
		if err != nil {
			if memoryRefusal(err) {
				next = g.key.L1Block
				break
			}
			return from, worked, err
		}
		worked++
		if out == groupWritten {
			rep.Late++
			metrics.AddFinalityIndexWritten(ix.Chain(), FamilyArb, 0, 0, 1)
		}
	}
	return next, worked, nil
}

// reconcileRecent re-examines the blocks just below the cursor, every step: a batch whose blobs arrived a few ticks after its event is
// there.
func (ix *Indexer) reconcileRecent(ctx context.Context, rep *finality.StepReport, deadline time.Time, done int) (int, error) {
	recent := ix.Cfg.recent()
	from := uint64(0)
	if ix.cursor+1 > recent {
		from = ix.cursor + 1 - recent
	}
	if from > ix.cursor {
		return 0, nil
	}
	_, n, err := ix.reconcileBlocks(ctx, rep, deadline, from, ix.cursor, done)
	return n, err
}

// reconcileRotate walks one chunk of the whole captured range (the lowest cursor row of the capture to the index cursor), rotating, so a
// block that was filled long after the cursor passed it is found at last.
func (ix *Indexer) reconcileRotate(ctx context.Context, rep *finality.StepReport, deadline time.Time, done int) error {
	lo, _, ok, err := finality.BlockBoundsOf(ctx, ix.Store, ix.Chain(), capture.ItemCursor)
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
	next, _, err := ix.reconcileBlocks(ctx, rep, deadline, from, to, done)
	if err != nil {
		return err
	}
	ix.reconcilePos = next
	return nil
}

// maxHints bounds the blocks waiting to be noted; a note is a speed-up, the rotating walk is the guarantee, so a full set drops the note.
const maxHints = 4096

// NoteLate tells the indexer that block was captured (or completed) after its cursor may have passed it. The next step indexes it
// (finality.LateBlockNoter). It is safe to call from any goroutine.
func (ix *Indexer) NoteLate(block uint64) {
	ix.hintMu.Lock()
	defer ix.hintMu.Unlock()
	if ix.hints == nil {
		ix.hints = map[uint64]bool{}
	}
	if _, noted := ix.hints[block]; !noted && len(ix.hints) >= maxHints {
		metrics.IncFinalityIndexNoteDropped(ix.Chain(), FamilyArb)
		if !ix.dropLogged {
			ix.dropLogged = true
			ix.Cfg.logf("[FINALITY] index arb: %d late-block notes are pending, further notes are dropped and counted (certen_finality_index_notes_dropped_total); the rotating walk reaches those blocks", maxHints)
		}
		return
	}
	ix.hints[block] = true
}

// reconcileHints indexes the noted blocks at or below the cursor, lowest first, under the same limits as the rest of the step. A note
// above the cursor stays (the forward step takes the block). It returns the number of blocks it worked on.
func (ix *Indexer) reconcileHints(ctx context.Context, rep *finality.StepReport, deadline time.Time) (int, error) {
	ix.hintMu.Lock()
	var noted []uint64
	for b := range ix.hints {
		if b <= ix.cursor {
			noted = append(noted, b)
		}
	}
	ix.hintMu.Unlock()
	sort.Slice(noted, func(i, j int) bool { return noted[i] < noted[j] })
	work := 0
	for _, b := range noted {
		if work > 0 && (ix.stopCause(ctx, work, rep.Late, deadline) != "" || work >= ix.Cfg.blocks()) {
			break
		}
		next, n, err := ix.reconcileBlocks(ctx, rep, deadline, b, b, work)
		if err != nil {
			return work, err
		}
		if next <= b {
			break // the step's limits ended it; the note stays
		}
		ix.hintMu.Lock()
		delete(ix.hints, b)
		ix.hintMu.Unlock()
		work += n
		if n == 0 {
			work++ // an empty note still counts as the height worked on, so the limits bound a flood of notes
		}
	}
	return work, nil
}

// ---- self-check ----

// SelfCheckResult is what one self-check did: the entries and digests it recomputed and compared, the checks it skipped because the memory
// budget refused their rows (never silent), and the mismatches it named. A result with Skipped > 0 is INCOMPLETE.
type SelfCheckResult struct {
	Generation uint32
	Around     uint64
	Entries    int
	Digests    int
	Skipped    int
	Mismatches int
}

// SelfCheckReport runs SelfCheck and returns what it did.
func (ix *Indexer) SelfCheckReport(ctx context.Context, sample int) (SelfCheckResult, error) {
	ix.selfRes = SelfCheckResult{Generation: ix.Gen}
	err := ix.SelfCheck(ctx, sample)
	res := ix.selfRes
	res.Generation = ix.Gen
	return res, err
}

// SelfCheck implements finality.CaptureIndexer: it recomputes sample stored entries and digests from the captured rows (re-reading them and
// re-running the one decoder, so a changed decoder, changed pins or a damaged index row show) and compares BYTES with the stored rows. A
// difference is the named state index_inconsistent{self_check_mismatch}, counted, logged and returned; a mismatching entry is quarantined
// by an insert-only record every reader checks.
func (ix *Indexer) SelfCheck(ctx context.Context, sample int) error {
	if err := ix.init(ctx); err != nil {
		return err
	}
	lo, hi, ok, err := finality.BlockBoundsOf(ctx, ix.Store, ix.Chain(), capture.ItemCursor)
	if err != nil || !ok {
		return err
	}
	span := ix.Cfg.span()
	at := lo
	if hi > lo+span {
		at = lo + uint64(ix.rng.Int63n(int64(hi-lo-span+1)))
	}
	ix.selfRes.Around = at
	var firstErr error
	note := func(s *finality.StateError) {
		ix.selfRes.Mismatches++
		metrics.IncFinalityIndexMismatch(ix.Chain(), FamilyArb)
		ix.state(s)
		ix.Cfg.logf("[FINALITY] index arb: self-check MISMATCH %s", s.Error())
		if firstErr == nil {
			firstErr = s
		}
	}
	names, err := ix.Store.ListByRange(ctx, ix.Chain(), at, at+span, ixItem(ix.Gen, ixEntry)+"/")
	if err != nil {
		return err
	}
	ix.rng.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	checked := 0
	for _, k := range names {
		if checked >= sample {
			break
		}
		n, good := parseEntryName(ix.Gen, k)
		if !good {
			note(finality.IndexInconsistent(ix.Chain(), FamilyArb, finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block))
			checked++
			continue
		}
		stored, found, err := ix.Store.Get(ctx, k)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		want, err := ix.referenceEntry(ctx, n)
		if err != nil {
			if memoryRefusal(err) {
				ix.skipped("entry", k)
				continue
			}
			return err
		}
		if !bytes.Equal(stored, want) {
			note(finality.IndexInconsistent(ix.Chain(), FamilyArb, finality.IndexSelfCheckMismatch, "item", k.Item, "l1_block", k.L1Block))
			ix.quarantine(ctx, k, n.N)
		}
		checked++
	}
	ix.selfRes.Entries = checked
	dkeys, err := ix.Store.ListByRange(ctx, ix.Chain(), at, at+span, ixItem(ix.Gen, ixDigest)+"/")
	if err != nil {
		return err
	}
	ix.rng.Shuffle(len(dkeys), func(i, j int) { dkeys[i], dkeys[j] = dkeys[j], dkeys[i] })
	for i, k := range dkeys {
		if i >= sample {
			break
		}
		stored, found, err := ix.Store.Get(ctx, k)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		want, err := ix.referenceDigest(ctx, k)
		if err != nil {
			if memoryRefusal(err) {
				ix.skipped("digest", k)
				continue
			}
			return err
		}
		ix.selfRes.Digests++
		if !bytes.Equal(stored, want) {
			note(finality.IndexInconsistent(ix.Chain(), FamilyArb, finality.IndexSelfCheckMismatch, "item", k.Item, "l1_block", k.L1Block))
		}
	}
	if firstErr == nil {
		ix.Cfg.logf("[FINALITY] index arb: self-check ok (%d entries, %d digests sampled around L1 block %d)", checked, ix.selfRes.Digests, at)
	}
	return firstErr
}

// skipped records a self-check that was not run because the memory budget refused the rows it reads: counted and logged, never silent.
func (ix *Indexer) skipped(what string, k finality.CaptureKey) {
	ix.selfRes.Skipped++
	metrics.IncFinalityIndexSelfCheckSkipped(ix.Chain(), FamilyArb)
	ix.Cfg.logf("[FINALITY] index arb: self-check of the %s at L1 block %d SKIPPED: the memory budget refused its rows (certen_finality_index_selfcheck_skipped_total)", what, k.L1Block)
}

// quarantine writes the self-check mismatch record of an entry (insert-only, at the entry's key, shared by every validator).
func (ix *Indexer) quarantine(ctx context.Context, k finality.CaptureKey, n uint64) {
	if err := finality.IndexPut(ctx, ix.Store, FamilyArb, withItem(k, quarantineItem(ix.Gen, n)), []byte("self_check_mismatch")); err != nil {
		ix.Cfg.logf("[FINALITY] index arb: the self-check mismatch record of batch %d could not be written: %v", n, err)
	}
}

// referenceBlock re-reads the rows of one captured block: the batch rows listed at the block with their data rows and the header row.
func (ix *Indexer) referenceBlock(ctx context.Context, bk finality.CaptureKey, hold *finality.Hold) (*blockRows, error) {
	keys, err := ix.Store.ListByRange(ctx, ix.Chain(), bk.L1Block, bk.L1Block, batchKeyPrefix)
	if err != nil {
		return nil, err
	}
	g := blockGroup{key: withItem(bk, "")}
	for _, k := range keys {
		if k.L1Hash == bk.L1Hash {
			if n, ok := batchNumber(k.Item); ok {
				g.nums = append(g.nums, n)
			}
		}
	}
	sort.Slice(g.nums, func(i, j int) bool { return g.nums[i] < g.nums[j] })
	return ix.readBlock(ctx, g, hold)
}

// referenceDigest recomputes the stored bytes of the digest of one captured block (keyed k) from its rows. The hold is released by defer.
func (ix *Indexer) referenceDigest(ctx context.Context, k finality.CaptureKey) ([]byte, error) {
	hold, done := ix.hold(ctx, "arb_index_selfcheck")
	defer done()
	blk, err := ix.referenceBlock(ctx, k, hold)
	if err != nil {
		if errors.Is(err, errBlockOpen) {
			return nil, finality.IndexInconsistent(ix.Chain(), FamilyArb, finality.IndexSelfCheckMismatch, "item", k.Item, "l1_block", k.L1Block)
		}
		var ue *unindexableError
		if errors.As(err, &ue) {
			return nil, finality.IndexInconsistent(ix.Chain(), FamilyArb, finality.IndexSelfCheckMismatch, "item", k.Item, "l1_block", k.L1Block)
		}
		return nil, err
	}
	d := &arbDigest{Block: blk.key.L1Block, Hash: blk.key.L1Hash, T: blk.t, Pins: ix.pins}
	for _, br := range blk.batches {
		ok, err := ix.authorizedRecord(ctx, br.rec)
		if err != nil {
			return nil, err
		}
		if ok {
			d.Batches = append(d.Batches, digestBatch{N: br.rec.N, Loc: br.rec.DataLocation, Parts: br.parts, RowLen: uint32(len(br.row)), DataBytes: br.dataLen})
		}
	}
	return d.encode(), nil
}

// referenceEntry recomputes the stored bytes of one entry from the rows of its batch alone (one batch row, its blobs or calldata and its
// block's header). An entry whose batch is not whole any more is a certain mismatch.
func (ix *Indexer) referenceEntry(ctx context.Context, n entryName) ([]byte, error) {
	hold, done := ix.hold(ctx, "arb_index_selfcheck")
	defer done()
	g := blockGroup{key: withItem(n.Key, ""), nums: []uint64{n.N}}
	blk, err := ix.readBlock(ctx, g, hold)
	if err != nil {
		var ue *unindexableError
		if errors.Is(err, errBlockOpen) || errors.As(err, &ue) {
			return nil, nil
		}
		return nil, err
	}
	e, err := ix.entryOf(blk, blk.batches[0], hold)
	if err != nil {
		return nil, err
	}
	return e.encode(), nil
}
