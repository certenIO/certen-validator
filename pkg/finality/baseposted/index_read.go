// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// DefaultGapMargin is how many L1 blocks past a captured later channel the capture must have scanned before a missing earlier channel is
// a capture gap and not a channel still in flight: the capture loop's own retry window for a block (BasePostedLoop.ProofWindow).
const DefaultGapMargin uint64 = 96

// IndexReader answers a build's question "which channel carries the batch of L2 timestamp T" from the index rows. It reads the key
// names of the channel entries in the widening parts of the leg's window and the (few hundred byte) entries of the channels whose
// timestamp range holds T. It decides nothing: the evidence is assembled from the captured rows and judged by Kind.Verify.
type IndexReader struct {
	Store     finality.CaptureStore
	Pins      *Pins
	Gen       uint32
	GapMargin uint64 // 0: DefaultGapMargin
}

// NewIndexReader returns a reader of generation gen (0: finality.DefaultIndexGeneration).
func NewIndexReader(store finality.CaptureStore, bp *Pins, gen uint32) *IndexReader {
	if gen == 0 {
		gen = finality.DefaultIndexGeneration
	}
	return &IndexReader{Store: store, Pins: bp, Gen: gen}
}

func (r *IndexReader) margin() uint64 {
	if r.GapMargin > 0 {
		return r.GapMargin
	}
	return DefaultGapMargin
}

// indexHit is the channel found for a timestamp.
type indexHit struct {
	entry *chanEntry
	key   finality.CaptureKey // the entry's key (the closing block)
	run   covRun
}

// Through is the L1 block the index has processed through (ok false: nothing yet).
func (r *IndexReader) Through(ctx context.Context) (uint64, bool, error) {
	_, hi, ok, err := finality.ReadIndexCursor(ctx, r.Store, uint64(Chain), r.Gen, FamilyBaseInbox)
	return hi, ok, err
}

func (r *IndexReader) inconsistent(reason string, extra ...any) *finality.StateError {
	return finality.IndexInconsistent(uint64(Chain), FamilyBaseInbox, reason, extra...)
}

// getEntry reads and checks one entry: decodes, checks the pins and looks for the duplicate-after-close marker.
func (r *IndexReader) getEntry(ctx context.Context, n entryName, io *ioCount) (*chanEntry, error) {
	b, ok, err := r.Store.Get(ctx, n.Key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, r.inconsistent(finality.IndexRowMissing, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	io.add(len(b))
	e, err := decodeEntry(b)
	if err != nil {
		return nil, r.inconsistent(finality.IndexEntryCorrupt, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	if e.ID != n.ID || e.TMin != n.TMin || e.TMax != n.TMax {
		return nil, r.inconsistent(finality.IndexRowsDisagree, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	if e.Pins != pinsDigest(r.Pins) {
		return nil, r.inconsistent(finality.IndexPinsChanged, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	mk := n.Key
	mk.Item = markerItem(r.Gen, n.ID)
	if _, marked, err := r.Store.Get(ctx, mk); err != nil {
		return nil, err
	} else if marked {
		return nil, r.inconsistent(finality.IndexDuplicateAfterOpen, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	qk := n.Key
	qk.Item = quarantineItem(r.Gen, n.ID)
	if _, quarantined, err := r.Store.Get(ctx, qk); err != nil {
		return nil, err
	} else if quarantined {
		return nil, r.inconsistent(finality.IndexSelfCheckMismatch, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	return e, nil
}

// ioCount counts the stored bytes a lookup and the assembly of its channel read.
type ioCount struct{ n int64 }

func (c *ioCount) add(n int) {
	if c != nil {
		c.n += int64(n)
	}
}

// Find is the first candidate of FindAll (nil: none).
func (r *IndexReader) Find(ctx context.Context, t, origin, end uint64, io *ioCount) (hit *indexHit, names []entryName, err error) {
	hits, names, err := r.FindAll(ctx, t, origin, end, io)
	if err != nil || len(hits) == 0 {
		return nil, names, err
	}
	return hits[0], names, nil
}

// FindAll looks for the channels that carry the batch of timestamp t among the entries that close in [origin, end], in the same widening
// parts findChannel's window is read in. names is every entry name listed (the caller classifies a miss from it). The candidates are the
// channels, in the first part that has any, whose coverage holds t, ordered by the position of their first frame: the first is exactly the
// choice findChannel makes, and a caller that cannot assemble it tries the next. A candidate that cannot be judged (an overflowing channel,
// a damaged or quarantined entry, a channel broken by a late frame) never hides another: its failure is remembered and is the answer only
// when no candidate in any part holds t (RB12-INDEX-FIX D1: one junk channel must not deny every honest leg).
func (r *IndexReader) FindAll(ctx context.Context, t, origin, end uint64, io *ioCount) (hits []*indexHit, names []entryName, err error) {
	return r.FindAllFrom(ctx, t, origin, origin, end, io)
}

// FindAllFrom is FindAll reading the entries that close in [lo, end] (lo <= origin), the widening parts anchored at origin: a channel that
// streams can close below the epoch of its batch (RB12-F14). The names it returns are those of the whole range read.
func (r *IndexReader) FindAllFrom(ctx context.Context, t, lo, origin, end uint64, io *ioCount) (hits []*indexHit, names []entryName, err error) {
	step := r.Pins.L2BlockTime
	prefix := r.item(itemChannel) + "/"
	chain := uint64(Chain)
	got := map[finality.CaptureKey]*chanEntry{}
	failed := map[finality.CaptureKey]bool{}
	var firstFailure error
	fail := func(e error) {
		if firstFailure == nil {
			firstFailure = e
		}
	}
	next := lo
	for i := 0; ; i++ {
		hi := end
		if i < len(searchSteps) && origin+searchSteps[i] < end {
			hi = origin + searchSteps[i]
		}
		keys, err := r.Store.ListByRange(ctx, chain, next, hi, prefix)
		if err != nil {
			return nil, nil, err
		}
		for _, k := range keys {
			n, ok := parseEntryName(r.Gen, k)
			if !ok {
				return nil, nil, r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
			}
			names = append(names, n)
		}
		for _, n := range names {
			if n.TMin == 0 || t < n.TMin || t > n.TMax || failed[n.Key] {
				continue
			}
			e, have := got[n.Key]
			if !have {
				if e, err = r.getEntry(ctx, n, io); err != nil {
					if _, named := finality.AsNamed(err); !named {
						return nil, nil, err // the store failed: nothing can be said
					}
					failed[n.Key] = true
					fail(err)
					continue
				}
				got[n.Key] = e
			}
			if e.Status == entryCoverageOverflow {
				failed[n.Key] = true
				fail(r.inconsistent(finality.IndexCoverageOverflow, "item", n.Key.Item, "l1_block", n.Key.L1Block))
				continue
			}
			if e.Status != entryDecoded {
				continue
			}
			for _, c := range e.Runs {
				if c.covers(t, step) { // runs are in decode order: the first run holding t holds the first batch at t
					hits = append(hits, &indexHit{entry: e, key: n.Key, run: c})
					break
				}
			}
		}
		if len(hits) > 0 {
			sort.SliceStable(hits, func(i, j int) bool { return firstLess(hits[i].entry, hits[j].entry) })
			return hits, names, nil
		}
		if hi >= end {
			return nil, names, firstFailure
		}
		next = hi + 1
	}
}

// firstLess orders channels by the position of their first frame in capture order: findChannel's order of first appearance (block, hash,
// transaction, frame inside the transaction).
func firstLess(a, b *chanEntry) bool {
	if a.FirstBlock != b.FirstBlock {
		return a.FirstBlock < b.FirstBlock
	}
	if c := bytes.Compare(a.FirstHash[:], b.FirstHash[:]); c != 0 {
		return c < 0
	}
	if a.FirstTx != b.FirstTx {
		return a.FirstTx < b.FirstTx
	}
	return a.FirstFrame < b.FirstFrame
}

// Assemble loads the transactions of the hit's channel, with all their blob rows, in the order findChannel returns them.
func (r *IndexReader) Assemble(ctx context.Context, h *indexHit, hold *finality.Hold, io *ioCount) ([]capturedTx, error) {
	out := make([]capturedTx, 0, len(h.entry.Txs))
	for _, t := range h.entry.Txs {
		bk := finality.CaptureKey{Chain: uint64(Chain), L1Block: t.Block, L1Hash: t.Hash}
		lt, err := loadTxRows(ctx, r.Store, bk, t.Index, hold, false, nil)
		if err != nil {
			return nil, err
		}
		io.add(int(lt.read))
		if uint32(len(lt.blobs)) != t.Blobs {
			return nil, r.inconsistent(finality.IndexRowsDisagree, "item", ItemBlob(t.Index, len(lt.blobs)), "l1_block", t.Block)
		}
		out = append(out, capturedTx{key: lt.key, index: lt.index, raw: lt.raw, blobs: lt.blobs})
	}
	return out, nil
}

// missClass is what a miss in the index means: the channel is not posted (or not captured) yet, or the capture has a hole.
type missClass struct {
	gap *finality.StateError // non-nil: l1_capture_gap
}

// classifyMiss decides, from the entry names of the whole window, whether a missing channel for timestamp t is a capture hole. The Base
// batcher posts L2 blocks in order, so captured channels tile L2 time: if a captured channel covers only later timestamps than t and the
// capture has scanned more than GapMargin blocks past its closing block, the channel of t cannot still be in flight and no captured row
// explains the interval between the nearest covered timestamps around t. partialFrames counts the digested frames inside the L1 range
// that belong to no entry (channels with a frame in the hole, or whose other frames the hole swallowed).
func (r *IndexReader) classifyMiss(ctx context.Context, t, origin, capHi uint64, names []entryName) (missClass, error) {
	step := r.Pins.L2BlockTime
	var below, above *entryName
	for i := range names {
		n := &names[i]
		if n.TMin == 0 {
			continue
		}
		if n.TMax < t && (below == nil || n.TMax > below.TMax) {
			below = n
		}
		if n.TMin > t && (above == nil || n.TMin < above.TMin) {
			above = n
		}
	}
	if above == nil || capHi < above.Key.L1Block || capHi-above.Key.L1Block < r.margin() {
		return missClass{}, nil
	}
	from, to := origin, above.Key.L1Block
	l2From := t
	if below != nil {
		from = below.Key.L1Block
		l2From = below.TMax + step
	}
	l2To := above.TMin - step
	if l2To < l2From {
		l2To = l2From
	}
	covered := map[[16]byte]bool{}
	for _, n := range names {
		covered[n.ID] = true
	}
	partial, err := r.partialFrames(ctx, from, to, covered)
	if err != nil {
		return missClass{}, err
	}
	return missClass{gap: finality.NewState(finality.CodeCaptureGap, "chain", uint64(Chain), "gap_state", finality.GapStateUnrecorded, "l2_timestamp", t, "l2_from", l2From, "l2_to", l2To,
		"from_l1", from, "to_l1", to, "partial_frames", partial)}, nil
}

// partialFrames counts the frames in the digests of [from, to] whose channel has no entry.
func (r *IndexReader) partialFrames(ctx context.Context, from, to uint64, covered map[[16]byte]bool) (uint64, error) {
	keys, err := finality.CaptureKeysOfItemIn(ctx, r.Store, uint64(Chain), from, to, r.item(itemDigest))
	if err != nil {
		return 0, err
	}
	var n uint64
	for _, k := range keys {
		b, ok, err := r.Store.Get(ctx, k)
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		d, err := decodeDigest(k, b)
		if err != nil {
			return 0, r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
		}
		if d.Pins != pinsDigest(r.Pins) {
			return 0, r.inconsistent(finality.IndexPinsChanged, "item", k.Item, "l1_block", k.L1Block)
		}
		for _, tx := range d.Txs {
			for _, f := range tx.Frames {
				if !covered[f.ID] {
					n++
				}
			}
		}
	}
	return n, nil
}

// unindexableIn is the named state of the lowest captured block in [origin, end] that the indexer recorded as unreadable (nil: none). A leg
// whose channel is not found and whose window holds such a block cannot be told "not posted yet": the channel may lie in it.
func (r *IndexReader) unindexableIn(ctx context.Context, origin, end uint64) (*finality.StateError, error) {
	keys, err := finality.CaptureKeysOfItemIn(ctx, r.Store, uint64(Chain), origin, end, unindexableItem(r.Gen))
	if err != nil || len(keys) == 0 {
		return nil, err
	}
	// the record is insert-only and cannot be withdrawn, so a block that has a digest (written by a roll that can read it) is readable and
	// its record is history: the lowest record WITHOUT a digest is the answer
	var k finality.CaptureKey
	found := false
	for _, cand := range keys {
		dk := cand
		dk.Item = r.item(itemDigest)
		_, has, err := r.Store.Get(ctx, dk)
		if err != nil {
			return nil, err
		}
		if !has {
			k, found = cand, true
			break
		}
	}
	if !found {
		return nil, nil
	}
	b, ok, err := r.Store.Get(ctx, k)
	if err != nil {
		return nil, err
	}
	reason := string(b)
	known := false
	for _, m := range finality.UnindexableReasons() {
		known = known || m == reason
	}
	if !ok || !known {
		return nil, r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
	}
	return finality.IndexBlockUnindexable(uint64(Chain), k.L1Block, reason), nil
}

// searchIndexed is search's index path: the same prelude (origin, window, capture cursor) and the same named outcomes, with the window
// read replaced by a lookup. It fills sr; a nil sr.ch with sr.pending set is a named pending, a nil sr.ch alone is l1_posted_unproven.
func (b *Builder) searchIndexed(ctx context.Context, bp *Pins, l2 finality.HeaderFields, hold *finality.Hold, sr *searched, origin, lo, end uint64,
	cov finality.CaptureCoverage, known bool, lower uint64, belowScanned, authentic func() error) error {
	r := b.Index
	io := &ioCount{}
	defer func() { metrics.ObserveFinalityIndexLookupBytes(uint64(Chain), FamilyBaseInbox, io.n) }()
	hits, names, err := r.FindAllFrom(ctx, l2.Timestamp, lo, origin, end, io)
	if err != nil {
		metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "inconsistent")
		return err
	}
	// the candidates in order of their first frame: one that cannot be assembled (a lost row) does not stop the search, the next is tried; when
	// none assembles the first failure is the named answer
	var firstFailure error
	for _, hit := range hits {
		txs, err := r.Assemble(ctx, hit, hold, io)
		if err != nil {
			if _, named := finality.AsNamed(err); !named {
				return err
			}
			if firstFailure == nil {
				firstFailure = err
			}
			continue
		}
		// a Denim second may straddle two channels (the index covers the timestamp, not the parent hash): the hit is the channel whose
		// batch has this block's parent hash, else the next hit is tried, as the window reader's findChannel does
		if l2.Timestamp >= bp.DenimTime {
			if ref, _, _, _ := findChannel(txs, bp, l2); ref == nil || ref.ID != hit.entry.ID {
				continue
			}
		}
		sr.ch, sr.frameTxs = &channelRef{ID: hit.entry.ID}, txs
		sr.bt = &Batch{Type: hit.run.Type, EpochNum: hit.run.Epoch, Timestamp: l2.Timestamp}
		metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "hit")
		return nil
	}
	if firstFailure != nil {
		metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "inconsistent")
		return firstFailure
	}
	if known && origin < lower {
		// part of the window was never scanned by the loop: the channel may have been posted there, unless that part is a requested prefix
		// (its blocks are captured and indexed as late blocks); the state is the window reader's own
		if err := belowScanned(); err != nil {
			metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "miss")
			return err
		}
	}
	through, haveIdx, err := r.Through(ctx)
	if err != nil {
		return err
	}
	capHi := cov.Last
	if !known {
		_, hi, ok, err := finality.BlockBoundsOf(ctx, r.Store, uint64(Chain), ItemSysCfg)
		if err != nil {
			return err
		}
		if ok {
			capHi = hi
		}
	}
	need := end
	if capHi < need {
		need = capHi
	}
	if !haveIdx || through < need {
		// still l1_posted_unproven (the closed set of pending reasons is the spec's), judged at the positions that show why: the index has not
		// reached what the capture holds (backfill after a deploy, a lagging step)
		sr.pending = "l1_posted_unproven"
		sr.judged = map[string]any{"l2_timestamp": l2.Timestamp, "last_scanned_l1": capHi, "index_behind": true, "index_through_l1": through, "window_end_l1": end}
		metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "behind")
		return nil
	}
	sr.lastScanned = capHi
	// a block of the window that the indexer could not read may hold the channel: named before any inference
	if us, err := r.unindexableIn(ctx, origin, end); err != nil {
		return err
	} else if us != nil {
		metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "unindexable")
		return us
	}
	// The end of a miss is the window reader's, by the one function (absentChannel): the recorded gaps with their evidence (RB12-CAPTURE-GAP,
	// INT-1), then the inference of a hole no record names (the index's own, below), then the determinate l1_posted_not_found of a complete
	// window with authentic() first.
	infer := func() (*finality.StateError, error) {
		mc, err := r.classifyMiss(ctx, l2.Timestamp, origin, capHi, names)
		if err != nil {
			return nil, err
		}
		return mc.gap, nil
	}
	aerr := b.absentChannel(ctx, origin, end, cov, known, authentic, infer)
	if aerr != nil {
		if gs, ok := finality.AsNamed(aerr); ok && gs.Code == CodeCaptureGap {
			metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "gap")
		} else {
			metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "miss")
		}
		return aerr
	}
	metrics.IncFinalityIndexLookup(uint64(Chain), FamilyBaseInbox, "miss")
	return nil
}

// sortedNames returns the names ordered by (timestamp range, id) for diagnostics.
func sortedNames(ns []entryName) []entryName {
	out := append([]entryName(nil), ns...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].TMin != out[j].TMin {
			return out[i].TMin < out[j].TMin
		}
		return bytes.Compare(out[i].ID[:], out[j].ID[:]) < 0
	})
	return out
}

func (n entryName) String() string {
	return fmt.Sprintf("channel %x covers %d..%d closes at %d", n.ID[:4], n.TMin, n.TMax, n.Key.L1Block)
}
