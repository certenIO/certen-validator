// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
	"github.com/certen/independant-validator/pkg/metrics"
)

// IndexReader answers a build's question "which captured batch holds the block with these signed transactions at L2 time ts" from the
// index rows (index.go). It lists the key names of the entries whose L1 block can hold a candidate, applies the reference reader's own
// predicate to them (ts inside the batch's time bounds), orders them as the reference does ((N, L1 block)), and reads the entries (a few
// KB each) of the candidates until one lists the block's fingerprint. It decides nothing: the batch it points to is judged by
// Builder.matchCandidate and the foreign check, exactly as the reference reader judges it.
type IndexReader struct {
	Store finality.CaptureStore
	Gen   uint32
	// Floor, when set, is the lowest L1 block that holds a batch the capture did not scan itself (the archive backfill's prefix scan of the batches
	// posted before the capture started): the time search starts there instead of a first-scan slack below the capture's first cursor row. Nil:
	// every batch lies within that slack, as in the live table.
	Floor func(ctx context.Context) (block uint64, ok bool, err error)
	arb   *arbPins
	pins  [8]byte
}

// NewIndexReader returns a reader of generation gen (0: finality.DefaultIndexGeneration) under the arb_sepolia pins.
func NewIndexReader(store finality.CaptureStore, pins *finality.Pins, gen uint32) (*IndexReader, error) {
	a, err := loadArbPins(pins)
	if err != nil {
		return nil, err
	}
	if gen == 0 {
		gen = finality.DefaultIndexGeneration
	}
	return &IndexReader{Store: store, Gen: gen, arb: a, pins: pinsDigest(a)}, nil
}

func (r *IndexReader) chain() uint64 { return finality.ChainArbitrumSepolia }

// Through is the L1 block the index has processed through (ok false: nothing yet).
func (r *IndexReader) Through(ctx context.Context) (uint64, bool, error) {
	_, hi, ok, err := finality.ReadIndexCursor(ctx, r.Store, r.chain(), r.Gen, FamilyArb)
	return hi, ok, err
}

func (r *IndexReader) inconsistent(reason string, extra ...any) *finality.StateError {
	return finality.IndexInconsistent(r.chain(), FamilyArb, reason, extra...)
}

// getEntry reads and checks one entry: the checksum, the name it was found under, the pins, and the self-check quarantine record.
func (r *IndexReader) getEntry(ctx context.Context, n entryName, io *ioCount) (*arbEntry, error) {
	b, ok, err := r.Store.Get(ctx, n.Key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, r.inconsistent(finality.IndexRowMissing, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	io.add(len(b))
	if err := finality.ReserveRow(ctx, len(b)); err != nil {
		return nil, err
	}
	e, derr := decodeEntry(b)
	if derr != nil {
		return nil, r.inconsistent(finality.IndexEntryCorrupt, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	if e.N != n.N || e.MinTs != n.MinTs || e.MaxTs != n.MaxTs || e.L1Block != n.Key.L1Block || e.L1Hash != n.Key.L1Hash {
		return nil, r.inconsistent(finality.IndexRowsDisagree, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	if e.Pins != r.pins {
		return nil, r.inconsistent(finality.IndexPinsChanged, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	qk := n.Key
	qk.Item = quarantineItem(r.Gen, n.N)
	if _, quarantined, err := r.Store.Get(ctx, qk); err != nil {
		return nil, err
	} else if quarantined {
		return nil, r.inconsistent(finality.IndexSelfCheckMismatch, "item", n.Key.Item, "l1_block", n.Key.L1Block)
	}
	return e, nil
}

// firstScanSlack is how far below its first cursor row the capture can have stored a batch: the first scan of a capture loop starts
// StartBack blocks below the head and ends at its first cursor row, and covers at most MaxCatchUp (400) blocks.
const firstScanSlack uint64 = 512

// ---- the time map: from an L2 time to the L1 blocks that can hold its batch ----

// probeDigest returns the first digest at or after m, up to limit: its block and L1 timestamp (from the name).
func (r *IndexReader) probeDigest(ctx context.Context, m, limit uint64, io *ioCount) (block, t uint64, ok bool, err error) {
	prefix := ixItem(r.Gen, ixDigest) + "/"
	width := uint64(8) // a batch about every 8 L1 blocks: the first window usually holds one digest; a longer stretch without one widens it
	for m <= limit {
		hi := limit
		if limit-m >= width {
			hi = m + width - 1
		}
		keys, err := r.Store.ListByRange(ctx, r.chain(), m, hi, prefix)
		if err != nil {
			return 0, 0, false, err
		}
		for _, k := range keys {
			t, good := parseDigestName(r.Gen, k)
			if !good {
				return 0, 0, false, r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
			}
			io.add(len(k.Item) + 40)
			return k.L1Block, t, true, nil
		}
		if hi == limit {
			break
		}
		m = hi + 1
		if width < 2048 { // widen through an empty stretch, but never to a window that would list the history
			width *= 4
		}
	}
	return 0, 0, false, nil
}

// firstAtOrAfter is the smallest m in [0, limit+1] such that the first digest at or after m has a timestamp >= x, or there is none. The
// timestamps of the L1 blocks grow with the block number, so the predicate is monotone in m and the digests below m all have a timestamp
// below x. block is that first digest (found false when m = limit+1 or no digest lies at or after it).
func (r *IndexReader) firstAtOrAfter(ctx context.Context, x, lo, limit uint64, io *ioCount) (m uint64, err error) {
	a, b := lo, limit+1
	for a < b {
		mid := a + (b-a)/2
		_, t, ok, err := r.probeDigest(ctx, mid, limit, io)
		if err != nil {
			return 0, err
		}
		if !ok || t >= x {
			b = mid
		} else {
			a = mid + 1
		}
	}
	return a, nil
}

// window is the L1 block range that holds every batch whose time bounds can hold ts: the batches whose L1 block has a timestamp T with
// ts - futureCap <= T <= ts + delayCap (a batch's bounds are T - delay .. T + future and the writer refuses a batch beyond the caps). The
// range runs from the first digested block with T >= ts - futureCap to the block before the first digest with T > ts + delayCap, so that a
// captured block that has no digest yet (its data is incomplete) between two digests is inside it. lo is a block no batch lies below (the
// capture's first scan, less its first range): the search starts there, not at block 0, so its probes land where the digests are.
func (r *IndexReader) window(ctx context.Context, ts, lo, through uint64, io *ioCount) (from, to uint64, err error) {
	x := uint64(0)
	if ts > windowFutureCap {
		x = ts - windowFutureCap
	}
	from, err = r.firstAtOrAfter(ctx, x, lo, through, io)
	if err != nil {
		return 0, 0, err
	}
	y := ts + windowDelayCap + 1
	if y < ts { // overflow: no upper bound
		return from, through, nil
	}
	m, err := r.firstAtOrAfter(ctx, y, from, through, io)
	if err != nil {
		return 0, 0, err
	}
	to = through
	if blk, _, ok, err := r.probeDigest(ctx, m, through, io); err != nil {
		return 0, 0, err
	} else if ok && blk > 0 {
		to = blk - 1
	}
	if to < from {
		to = from
	}
	return from, to, nil
}

// ---- Locate ----

// Locate is the indexed counterpart of capture.LoadBatches + Builder.locate: the batch whose payload holds a message with exactly the
// standard transactions std, among the captured batches whose time bounds hold hdr.Timestamp, first in (N, L1 block) order. A nil
// located with a nil pending is impossible: not finding a batch is the named pending (awaiting_batch_post, judged at the positions that
// show why) or a named state.
func (r *IndexReader) Locate(ctx context.Context, b *Builder, hdr finality.HeaderFields, std [][]byte, arb *arbPins) (*located, *finality.PendingState, error) {
	chain := r.chain()
	pend := func(extra map[string]any, newest uint64) *finality.PendingState {
		j := map[string]any{"l2_block": hdr.Number, "latest_captured_batch": newest}
		for k, v := range extra {
			j[k] = v
		}
		return pending(chain, PendingAwaitingBatchPost, b.now().Add(3*time.Minute), j)
	}
	io := &ioCount{}
	defer func() { metrics.ObserveFinalityIndexLookupBytes(chain, FamilyArb, io.n) }()
	through, have, err := r.Through(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(std) == 0 {
		// a block without a signed standard transaction is in no batch the verifier can match: pending, as the reference says
		var newest uint64
		if have {
			if newest, err = r.newestBatch(ctx, through, io); err != nil {
				return nil, nil, err
			}
		}
		return nil, pend(nil, newest), nil
	}
	capLo, capHi := uint64(0), uint64(0)
	if lo, hi, ok, err := finality.BlockBoundsOf(ctx, r.Store, chain, capture.ItemCursor); err != nil {
		return nil, nil, err
	} else if ok {
		capHi = hi
		if lo > firstScanSlack {
			capLo = lo - firstScanSlack
		}
	}
	if !have {
		metrics.IncFinalityIndexLookup(chain, FamilyArb, "behind")
		return nil, pend(map[string]any{"index_behind": true, "index_through_l1": uint64(0), "last_scanned_l1": capHi}, 0), nil
	}
	if r.Floor != nil {
		f, ok, err := r.Floor(ctx)
		if err != nil {
			return nil, nil, err
		}
		if ok && f < capLo {
			capLo = f
		}
	}
	from, to, err := r.window(ctx, hdr.Timestamp, capLo, through, io)
	if err != nil {
		return nil, nil, err
	}

	// the entries and the batch rows of the window, by key name only
	entryKeys, err := r.Store.ListByRange(ctx, chain, from, to, ixItem(r.Gen, ixEntry)+"/")
	if err != nil {
		return nil, nil, err
	}
	io.add(len(entryKeys) * 100)
	var cands []entryName
	have2 := map[[40]byte]map[uint64]bool{} // the batches that have an entry: (block, hash) -> N
	for _, k := range entryKeys {
		n, ok := parseEntryName(r.Gen, k)
		if !ok {
			return nil, nil, r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
		}
		id := blockID(k)
		if have2[id] == nil {
			have2[id] = map[uint64]bool{}
		}
		have2[id][n.N] = true
		if n.MinTs <= hdr.Timestamp && hdr.Timestamp <= n.MaxTs {
			cands = append(cands, n)
		}
	}
	// the batches whose bounds are wider than the normal window: pointed at by "w" rows at a fixed key, listed here (none in production)
	var firstFailure error
	wide, werr := r.wideCandidates(ctx, hdr.Timestamp, io)
	if werr != nil {
		if _, named := finality.AsNamed(werr); !named {
			return nil, nil, werr
		}
		firstFailure = werr // a damaged pointer is a candidate that cannot be judged, never a denial of the others (the D1 rule)
	}
	seen := map[finality.CaptureKey]bool{}
	for _, c := range cands {
		seen[c.Key] = true
	}
	for _, wn := range wide {
		if !seen[wn.Key] {
			seen[wn.Key] = true
			cands = append(cands, wn)
			id := blockID(wn.Key)
			if have2[id] == nil {
				have2[id] = map[uint64]bool{}
			}
			have2[id][wn.N] = true
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return nameLess(cands[i], cands[j]) })

	fp := messageFp(std)
	var lost []capture.BatchRecord // candidates whose blob rows are not all stored
	for _, c := range cands {
		e, err := r.getEntry(ctx, c, io)
		if err != nil {
			if _, named := finality.AsNamed(err); !named {
				return nil, nil, err // the store failed: nothing can be said
			}
			if firstFailure == nil {
				firstFailure = err
			}
			continue
		}
		switch e.Status {
		case entryOverflow:
			if firstFailure == nil {
				firstFailure = r.inconsistent(finality.IndexCoverageOverflow, "item", c.Key.Item, "l1_block", c.Key.L1Block)
			}
			continue
		case entryDecoded:
		default:
			continue // the reference skips such a batch
		}
		if !hasFp(e.Fps, fp) {
			continue
		}
		rec, err := r.batchRecord(ctx, c, e, io)
		if err != nil {
			if _, named := finality.AsNamed(err); !named {
				return nil, nil, err
			}
			if firstFailure == nil {
				firstFailure = err
			}
			continue
		}
		loc, kind, err := b.matchCandidate(ctx, rec, std, arb)
		if err != nil {
			return nil, nil, err
		}
		if kind == candidateIncomplete {
			lost = append(lost, rec) // the entry says the batch was whole and a blob row is gone: the reference names it too, if nothing else holds the block
			continue
		}
		if kind != candidateMatch {
			continue // a fingerprint collision, or rows that no longer hold what the entry says: not this batch (the reference skips it as well)
		}
		ok, err := b.authorized(ctx, rec, arb)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			continue // a foreign record is served by no reader
		}
		metrics.IncFinalityIndexLookup(chain, FamilyArb, "hit")
		return loc, nil, nil
	}
	if firstFailure != nil {
		metrics.IncFinalityIndexLookup(chain, FamilyArb, "inconsistent")
		return nil, nil, firstFailure
	}

	// no entry holds the block. The reference reader names a captured blob batch whose blobs are not all stored (its content is unknown) before it
	// says the batch is not posted; so does the index, for the batches of the window that have no entry.
	// the batch rows of the window are listed only now, when no entry holds the block: they classify the miss
	batchKeys, err := r.Store.ListByRange(ctx, chain, from, to, batchKeyPrefix)
	if err != nil {
		return nil, nil, err
	}
	io.add(len(batchKeys) * 60)
	open := lost
	unreadable := map[[40]byte]bool{} // blocks the indexer recorded as unreadable: named below, not judged here
	uk, err := finality.CaptureKeysOfItemIn(ctx, r.Store, chain, from, to, unindexedItem(r.Gen))
	if err != nil {
		return nil, nil, err
	}
	for _, k := range uk {
		unreadable[blockID(k)] = true
	}
	for _, k := range batchKeys {
		n, ok := batchNumber(k.Item)
		if !ok || have2[blockID(k)][n] || unreadable[blockID(k)] || k.L1Block > through {
			continue // (above the index cursor a batch has no entry yet: that is the lag, named below)
		}
		raw, found, err := r.Store.Get(ctx, k)
		if err != nil {
			return nil, nil, err
		}
		if !found {
			continue
		}
		io.add(len(raw))
		if err := finality.ReserveRow(ctx, len(raw)); err != nil {
			return nil, nil, err
		}
		rec, derr := capture.DecodeBatchRecord(raw)
		if derr != nil || rec.N != n || rec.L1Block != k.L1Block || rec.L1Hash != k.L1Hash {
			return nil, nil, finality.IndexBlockUnindexable(chain, k.L1Block, finality.UnindexableBatchRowMalformed)
		}
		if rec.DataLocation == capture.LocBlob && rec.Header40[0] <= hdr.Timestamp && hdr.Timestamp <= rec.Header40[1] {
			whole, err := r.blobRowsWhole(ctx, k, rec)
			if err != nil {
				return nil, nil, err
			}
			if !whole {
				open = append(open, rec)
			}
		}
	}
	if len(open) > 0 {
		sort.SliceStable(open, func(i, j int) bool {
			if open[i].N != open[j].N {
				return open[i].N < open[j].N
			}
			return open[i].L1Block < open[j].L1Block
		})
		metrics.IncFinalityIndexLookup(chain, FamilyArb, "incomplete")
		return nil, nil, b.blobUnavailable(ctx, open[len(open)-1])
	}
	newest, err := r.newestBatch(ctx, through, io)
	if err != nil {
		return nil, nil, err
	}
	if through < capHi && to >= through {
		// the index has not reached what the capture holds and the window runs past it: the batch may be captured and not indexed yet
		metrics.IncFinalityIndexLookup(chain, FamilyArb, "behind")
		return nil, pend(map[string]any{"index_behind": true, "index_through_l1": through, "last_scanned_l1": capHi, "window_end_l1": to}, newest), nil
	}
	// a block of the window that the indexer could not read may hold the batch: named before any inference
	if us, err := r.unindexableIn(ctx, from, to); err != nil {
		return nil, nil, err
	} else if us != nil {
		metrics.IncFinalityIndexLookup(chain, FamilyArb, "unindexable")
		return nil, nil, us
	}
	// the batch numbers are dense: a number missing between two captured batches of the window is a batch the capture never stored, and it may be
	// the batch of this block
	if gap, err := r.holeIn(ctx, hdr.Timestamp, batchKeys, have2); err != nil {
		return nil, nil, err
	} else if gap != nil {
		metrics.IncFinalityIndexLookup(chain, FamilyArb, "gap")
		return nil, nil, gap
	}
	metrics.IncFinalityIndexLookup(chain, FamilyArb, "miss")
	return nil, pend(nil, newest), nil
}

// unindexableIn is the named state of the lowest captured block in [from, to] that the indexer recorded as unreadable and that has no digest
// (nil: none). A leg whose batch is not found and whose window holds such a block cannot be told "not posted yet": the batch may lie in it.
func (r *IndexReader) unindexableIn(ctx context.Context, from, to uint64) (*finality.StateError, error) {
	keys, err := finality.CaptureKeysOfItemIn(ctx, r.Store, r.chain(), from, to, unindexedItem(r.Gen))
	if err != nil || len(keys) == 0 {
		return nil, err
	}
	have, err := r.Store.ListByRange(ctx, r.chain(), from, to, ixItem(r.Gen, ixDigest)+"/")
	if err != nil {
		return nil, err
	}
	digested := map[[40]byte]bool{}
	for _, k := range have {
		digested[blockID(k)] = true
	}
	for _, k := range keys {
		if digested[blockID(k)] {
			continue // a roll that could read the block digested it: the record is history
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
		return finality.IndexBlockUnindexable(r.chain(), k.L1Block, reason), nil
	}
	return nil, nil
}

// maxHoleChecks bounds how many apparent gaps of the batch numbers one lookup tests against the Bridge.
const maxHoleChecks = 8

// holeIn reports the capture hole of the window, if any: two consecutive captured batch numbers that are not consecutive AND that the Bridge
// holds both (capture.AuthorizeStored: a verified proof shows each record's accumulator). The authorization comes BEFORE the hole: a record
// that is forged (an invented event, a huge batch number) is unproven or foreign and bounds no hole, so it cannot make a leg that is simply
// not posted yet look like a capture gap. The interval it names is the L1 time (the timestamps of the digests of the two batches around the
// first hole) during which the missing batches were posted; partial_frames counts the captured batches of the window that have no entry.
// At most maxHoleChecks apparent gaps are tested; a hole whose neighbours have no captured proof is not claimed (the leg stays pending).
func (r *IndexReader) holeIn(ctx context.Context, ts uint64, batchKeys []finality.CaptureKey, entries map[[40]byte]map[uint64]bool) (*finality.StateError, error) {
	type bn struct {
		n   uint64
		key finality.CaptureKey
	}
	var all []bn
	partial := uint64(0)
	for _, k := range batchKeys {
		n, ok := batchNumber(k.Item)
		if !ok {
			continue
		}
		all = append(all, bn{n, k})
		if !entries[blockID(k)][n] {
			partial++
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n < all[j].n
		}
		return all[i].key.L1Block < all[j].key.L1Block
	})
	checks := 0
	for i := 1; i < len(all) && checks < maxHoleChecks; i++ {
		if all[i].n <= all[i-1].n+1 {
			continue
		}
		checks++
		below, err := r.proven(ctx, all[i-1].key)
		if err != nil {
			return nil, err
		}
		if !below {
			continue
		}
		// a number missing between two batches is a hole in the CAPTURE only where the capture was scanning: between a batch of a prefix window and a
		// batch of the live region (or of two windows) lies ground nobody scanned, and that is the coverage judgement's (l1_capture_not_covering with
		// its prefix state), not an N-hole. A range the prefix scan closed (a gapscan row) is ground that WAS scanned.
		if scanned, err := r.scannedBetween(ctx, all[i-1].key.L1Block, all[i].key.L1Block); err != nil {
			return nil, err
		} else if !scanned {
			continue
		}
		above, err := r.proven(ctx, all[i].key)
		if err != nil {
			return nil, err
		}
		if !above {
			continue
		}
		lo, hi := all[i-1].key.L1Block, all[i].key.L1Block
		tl, err := r.digestTime(ctx, lo)
		if err != nil {
			return nil, err
		}
		th, err := r.digestTime(ctx, hi)
		if err != nil {
			return nil, err
		}
		return finality.NewState(finality.CodeCaptureGap, "chain", r.chain(), "gap_state", finality.GapStateUnrecorded, "l2_timestamp", ts, "l2_from", tl, "l2_to", th,
			"from_l1", lo, "to_l1", hi, "partial_frames", partial), nil
	}
	return nil, nil
}

// proven reports whether the batch record at key is one the Bridge holds (a verified captured proof shows its accumulator).
func (r *IndexReader) proven(ctx context.Context, key finality.CaptureKey) (bool, error) {
	raw, ok, err := r.Store.Get(ctx, key)
	if err != nil || !ok {
		return false, err
	}
	rec, derr := capture.DecodeBatchRecord(raw)
	if derr != nil || rec.L1Block != key.L1Block || rec.L1Hash != key.L1Hash {
		return false, nil
	}
	v, err := capture.AuthorizeStored(ctx, r.Store, r.chain(), rec, r.arb.bridge, r.arb.Layout.AccArraySlot)
	return v == capture.AuthProven, err
}

// digestTime is the L1 timestamp in the name of the digest at block (0 when the block has none).
func (r *IndexReader) digestTime(ctx context.Context, block uint64) (uint64, error) {
	keys, err := r.Store.ListByRange(ctx, r.chain(), block, block, ixItem(r.Gen, ixDigest)+"/")
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if t, ok := parseDigestName(r.Gen, k); ok {
			return t, nil
		}
	}
	return 0, nil
}

// blobRowsWhole reports whether the blob rows 0..n-1 of the record are stored at its key, by a key listing of the block (no row is read): the reference's
// test (LoadBlobs returns rows until the first missing index, and the batch is incomplete when they are fewer than its versioned hashes).
func (r *IndexReader) blobRowsWhole(ctx context.Context, k finality.CaptureKey, rec capture.BatchRecord) (bool, error) {
	keys, err := r.Store.ListByRange(ctx, r.chain(), k.L1Block, k.L1Block, fmt.Sprintf("blob/%d/", rec.N))
	if err != nil {
		return false, err
	}
	have := map[string]bool{}
	for _, bk := range keys {
		if bk.L1Hash == k.L1Hash {
			have[bk.Item] = true
		}
	}
	for j := range rec.VersionedHashes {
		if !have[capture.ItemBlob(rec.N, j)] {
			return false, nil
		}
	}
	return true, nil
}

// nameLess orders entries as the reference orders its batches: by N, then by L1 block, then (a reorg at one height) by hash.
func nameLess(a, b entryName) bool {
	if a.N != b.N {
		return a.N < b.N
	}
	if a.Key.L1Block != b.Key.L1Block {
		return a.Key.L1Block < b.Key.L1Block
	}
	return bytes.Compare(a.Key.L1Hash[:], b.Key.L1Hash[:]) < 0
}

// batchRecord loads the batch row an entry was made from and checks it is that row.
func (r *IndexReader) batchRecord(ctx context.Context, n entryName, e *arbEntry, io *ioCount) (capture.BatchRecord, error) {
	bk := n.Key
	bk.Item = capture.ItemBatch(n.N)
	raw, ok, err := r.Store.Get(ctx, bk)
	if err != nil {
		return capture.BatchRecord{}, err
	}
	if !ok {
		return capture.BatchRecord{}, r.inconsistent(finality.IndexRowMissing, "item", bk.Item, "l1_block", bk.L1Block)
	}
	io.add(len(raw))
	if err := finality.ReserveRow(ctx, len(raw)); err != nil {
		return capture.BatchRecord{}, err
	}
	if uint32(len(raw)) != e.RowLen || rowSum(raw) != e.RowSum {
		return capture.BatchRecord{}, r.inconsistent(finality.IndexRowsDisagree, "item", bk.Item, "l1_block", bk.L1Block)
	}
	rec, derr := capture.DecodeBatchRecord(raw)
	if derr != nil || rec.N != n.N || rec.L1Block != bk.L1Block || rec.L1Hash != bk.L1Hash {
		return capture.BatchRecord{}, r.inconsistent(finality.IndexRowsDisagree, "item", bk.Item, "l1_block", bk.L1Block)
	}
	return rec, nil
}

// wideCandidates are the batches whose bounds hold ts among those pointed at by "w" rows (batches wider than the normal window).
func (r *IndexReader) wideCandidates(ctx context.Context, ts uint64, io *ioCount) ([]entryName, error) {
	keys, err := r.Store.ListByRange(ctx, r.chain(), 0, 0, ixItem(r.Gen, ixWide)+"/")
	if err != nil {
		return nil, err
	}
	var out []entryName
	var first error
	for _, k := range keys {
		n, ok := parseWideName(r.Gen, k)
		if !ok {
			if first == nil {
				first = r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
			}
			continue
		}
		if ts < n.MinTs || ts > n.MaxTs {
			continue
		}
		b, found, err := r.Store.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		if !found {
			if first == nil {
				first = r.inconsistent(finality.IndexRowMissing, "item", k.Item, "l1_block", k.L1Block)
			}
			continue
		}
		io.add(len(b))
		block, hash, derr := decodeWideBody(b)
		if derr != nil {
			if first == nil {
				first = r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
			}
			continue
		}
		n.Key = finality.CaptureKey{Chain: r.chain(), L1Block: block, L1Hash: hash, Item: entryItem(r.Gen, n.MinTs, n.MaxTs, n.N)}
		out = append(out, n)
	}
	return out, first
}

// newestBatch is the highest batch number among the digests nearest below the index cursor (informational: the judged field
// latest_captured_batch of the pending reason).
func (r *IndexReader) newestBatch(ctx context.Context, through uint64, io *ioCount) (uint64, error) {
	prefix := ixItem(r.Gen, ixDigest) + "/"
	for width := uint64(256); ; width *= 8 {
		lo := uint64(0)
		if through > width {
			lo = through - width
		}
		keys, err := r.Store.ListByRange(ctx, r.chain(), lo, through, prefix)
		if err != nil {
			return 0, err
		}
		if len(keys) > 0 {
			k := keys[len(keys)-1]
			b, ok, err := r.Store.Get(ctx, k)
			if err != nil || !ok {
				return 0, err
			}
			io.add(len(b))
			d, derr := decodeDigest(k, b)
			if derr != nil {
				return 0, r.inconsistent(finality.IndexEntryCorrupt, "item", k.Item, "l1_block", k.L1Block)
			}
			var newest uint64
			for _, x := range d.Batches {
				if x.N > newest {
					newest = x.N
				}
			}
			return newest, nil
		}
		if lo == 0 {
			return 0, nil
		}
	}
}

// scannedBetween reports whether every L1 block of [lo, hi] is ground the capture scanned: at or above the first block the live loop scanned (its
// cursor rows, less the first-scan slack), or inside ranges the archive backfill's prefix scan closed (gapscan rows, merged). Keys only.
func (r *IndexReader) scannedBetween(ctx context.Context, lo, hi uint64) (bool, error) {
	chain := r.chain()
	first, _, ok, err := finality.BlockBoundsOf(ctx, r.Store, chain, capture.ItemCursor)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil // a store without a cursor says nothing about what it scanned
	}
	liveLo := uint64(0)
	if first > firstScanSlack {
		liveLo = first - firstScanSlack
	}
	if lo >= liveLo {
		return true, nil
	}
	keys, err := r.Store.ListByRange(ctx, chain, 0, hi, finality.GapScanPrefix)
	if err != nil {
		return false, err
	}
	type span struct{ from, to uint64 }
	var spans []span
	for _, k := range keys {
		to, err := strconv.ParseUint(strings.TrimPrefix(k.Item, finality.GapScanPrefix), 10, 64)
		if err != nil || to < k.L1Block {
			continue
		}
		spans = append(spans, span{k.L1Block, to})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].from < spans[j].from })
	next := lo // the first block not yet shown scanned
	if liveLo <= hi && liveLo > next {
		// the part at or above liveLo is live-scanned; the part below needs the closed ranges
		hi = minU64(hi, liveLo-1)
	}
	for _, sp := range spans {
		if sp.from > next {
			break
		}
		if sp.to >= next {
			next = sp.to + 1
		}
		if next > hi {
			return true, nil
		}
	}
	return next > hi, nil
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
