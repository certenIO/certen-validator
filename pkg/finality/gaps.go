// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Capture gaps (RB12-CAPTURE-GAP, finding RB12-F13).
//
// A capture loop that cannot capture an L1 block, or that was not running while the block was produced, leaves a HOLE in the capture
// store: the cursor rows say "scanned up to here" and the rows themselves say nothing about what is missing. On 2026-10-23 the Base
// loop gave up on ~684 blocks after an outage and moved its cursor on, so a leg whose batch had been posted inside a hole could never be
// told why its evidence was not found. A gap is therefore recorded, durably, in the same insert-only store the capture rows live in
// (no migration: the table is keyed by (chain, l1_block, l1_hash, item) and an item is any name of the documented alphabet):
//
//	gap/<to>/<class>        at L1Block=from, zero hash   "CGAP1" || u64 from || u64 to || STR class
//	gapfill/<block>         at L1Block=block, its hash   "CGFL1" || u64 block || B32 hash || u8 hasInbox   (the block was captured or scanned empty)
//	gapend/<block>/<kind>   at L1Block=block, content    "CGEND1" || u64 block || STR kind || STR reason || LIST<STR provider>
//	gapnote/<block>/<class> at L1Block=block, content    "CGNT1" || u64 block || STR class || STR redacted provider text
//
// A gap row is a function of (from, to, class) alone, so any number of validators recording the same gap write the same bytes. A fill,
// an end and a note are keyed by their own content (the hash column is the SHA-256 of the bytes where the block's hash is not the
// natural key), so no two writers can conflict and nothing is ever updated or deleted: closing a gap is a NEW row. A block is open
// while it lies inside a gap and has no fill; it is unavailable_proven or retention_expired when it has an end and no fill; a fill
// closes it for good whatever else was recorded (a provider that has the data after all wins over an earlier "unavailable").
//
// Readers (the builders' coverage decision, the backfill, the operator script pr/rb12-capture-gaps.sh) go through GapsIn: it never
// answers "no gaps" for a store it could not read.

// GapClass names why a block could not be captured. The set is closed: a class outside it is refused when recorded.
type GapClass string

const (
	GapBlockUnavailable      GapClass = "block_unavailable"       // the L1 block (header, transactions) could not be read from any provider
	GapStateProofUnavailable GapClass = "state_proof_unavailable" // eth_getProof for the block is beyond every configured provider's window
	GapBlobUnavailable       GapClass = "blob_unavailable"        // the beacon blobs of the block could not be had
	GapCaptureFailed         GapClass = "capture_failed"          // the capture of the block failed for another named reason (the note says which)
	GapOutageUnscanned       GapClass = "outage_unscanned"        // the loop was not running (or too far behind its provider window) while the block was produced
	GapSpacingUnproven       GapClass = "spacing_unproven"        // no captured block for a run longer than the audit spacing: not proven scanned (spacing audit)
	GapOperatorDeclared      GapClass = "operator_declared"       // recorded by an operator for a range known from logs
	// GapCapturePrefix (prefix.go) is declared there: the store is to be extended below the first block the capture loop scanned.
)

var gapClasses = map[GapClass]bool{
	GapBlockUnavailable: true, GapStateProofUnavailable: true, GapBlobUnavailable: true, GapCaptureFailed: true,
	GapOutageUnscanned: true, GapSpacingUnproven: true, GapOperatorDeclared: true, GapCapturePrefix: true,
}

// Valid reports whether c is one of the closed set.
func (c GapClass) Valid() bool { return gapClasses[c] }

// GapState is where a block (or a range of blocks) of a gap stands.
type GapState string

const (
	GapOpen              GapState = "open"               // not captured yet; the backfill is working on it
	GapUnavailableProven GapState = "unavailable_proven" // every configured provider proved the data unavailable inside its retention
	GapRetentionExpired  GapState = "retention_expired"  // the data's retention elapsed (blobs, ~18 days) and the providers no longer have it
)

// Item prefixes of the gap rows.
const (
	GapItemPrefix = "gap/"
	GapFillPrefix = "gapfill/"
	GapEndPrefix  = "gapend/"
	GapNotePrefix = "gapnote/"
)

const (
	gapMagic  = "CGAP1"
	fillMagic = "CGFL1"
	endMagic  = "CGEND1"
	noteMagic = "CGNT1"
	// MaxGapNoteBytes bounds the provider text kept in a note (after redaction).
	MaxGapNoteBytes = 512
)

// GapRange is a run of consecutive blocks in one state. Classes is the union of the classes of the gap rows that cover it, sorted.
type GapRange struct {
	From, To uint64
	State    GapState
	Classes  []GapClass
}

// Blocks is the number of blocks of the range.
func (g GapRange) Blocks() uint64 { return g.To - g.From + 1 }

func (g GapRange) String() string {
	cs := make([]string, len(g.Classes))
	for i, c := range g.Classes {
		cs[i] = string(c)
	}
	return fmt.Sprintf("%d-%d:%s[%s]", g.From, g.To, g.State, strings.Join(cs, ","))
}

// GapEnd is the terminal record of one block: the providers proved the data unavailable, or its retention elapsed.
type GapEnd struct {
	Kind      GapState // GapUnavailableProven or GapRetentionExpired
	Reason    string   // a short token of the closed vocabulary of the recorder ("beacon_404_every_provider", "blob_retention_elapsed")
	Providers []string // host labels of the providers asked, sorted
}

func gapRowKey(chain, from, to uint64, class GapClass) CaptureKey {
	return CaptureKey{Chain: chain, L1Block: from, Item: fmt.Sprintf("%s%d/%s", GapItemPrefix, to, class)}
}

func gapRowBytes(from, to uint64, class GapClass) []byte {
	var w Writer
	w.Fixed([]byte(gapMagic))
	w.U64(from)
	w.U64(to)
	w.STR(string(class))
	return w.Bytes()
}

// RecordGap records that the blocks [from, to] of chain are not (known to be) captured, for the stated class. Recording the same gap again
// is a no-op.
func RecordGap(ctx context.Context, s CaptureStore, chain, from, to uint64, class GapClass) error {
	if to < from || to > MaxCaptureBlock {
		return fmt.Errorf("finality: bad gap range %d-%d", from, to)
	}
	if !class.Valid() {
		return fmt.Errorf("finality: gap class %q is not in the closed set", class)
	}
	return s.Put(ctx, gapRowKey(chain, from, to, class), gapRowBytes(from, to, class))
}

func contentHash(domain string, b []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RecordGapNote keeps the provider text of a failed capture (redacted by pkg/ethrpc, bounded) so an operator can see why a block is open.
// Notes are keyed by their content: different texts of different validators are different rows, never a conflict.
func RecordGapNote(ctx context.Context, s CaptureStore, chain, block uint64, class GapClass, detail string) error {
	if !class.Valid() {
		return fmt.Errorf("finality: gap class %q is not in the closed set", class)
	}
	text := ethrpc.RedactText(detail)
	if len(text) > MaxGapNoteBytes {
		text = text[:MaxGapNoteBytes]
	}
	var w Writer
	w.Fixed([]byte(noteMagic))
	w.U64(block)
	w.STR(string(class))
	w.STR(text)
	b := w.Bytes()
	return s.Put(ctx, CaptureKey{Chain: chain, L1Block: block, L1Hash: contentHash("certen:gapnote:v1", b), Item: fmt.Sprintf("%s%d/%s", GapNotePrefix, block, class)}, b)
}

// RecordGapFill closes block: it was captured (hasInbox) or scanned and found to hold nothing to capture. The row is keyed under the
// block's hash, so a reorged height closes under each hash it was read at.
func RecordGapFill(ctx context.Context, s CaptureStore, chain, block uint64, hash [32]byte, hasInbox bool) error {
	if hash == ([32]byte{}) {
		return fmt.Errorf("finality: a gap fill names the hash of the block the capture verified; block %d has none", block)
	}
	var w Writer
	w.Fixed([]byte(fillMagic))
	w.U64(block)
	w.B32(hash)
	if hasInbox {
		w.U8(1)
	} else {
		w.U8(0)
	}
	return s.Put(ctx, CaptureKey{Chain: chain, L1Block: block, L1Hash: hash, Item: fmt.Sprintf("%s%d", GapFillPrefix, block)}, w.Bytes())
}

var gapReasonRE = captureItemRE // the same alphabet as an item name: a token, not text

// RecordGapEnd records the terminal state of one block. It is keyed by its content, so validators that reached the same conclusion with
// the same providers write one row, and ones that differ write two, never a conflict.
func RecordGapEnd(ctx context.Context, s CaptureStore, chain, block uint64, e GapEnd) error {
	if e.Kind != GapUnavailableProven && e.Kind != GapRetentionExpired {
		return fmt.Errorf("finality: %q is not a terminal gap state", e.Kind)
	}
	if e.Reason == "" || len(e.Reason) > 64 || !gapReasonRE.MatchString(e.Reason) {
		return fmt.Errorf("finality: a gap end names its reason as a token, got %q", e.Reason)
	}
	ps := append([]string(nil), e.Providers...)
	sort.Strings(ps)
	out := ps[:0]
	for i, p := range ps {
		if i == 0 || p != ps[i-1] {
			out = append(out, ethrpc.RedactText(p))
		}
	}
	var w Writer
	w.Fixed([]byte(endMagic))
	w.U64(block)
	w.STR(string(e.Kind))
	w.STR(e.Reason)
	w.Count(len(out))
	for _, p := range out {
		w.STR(p)
	}
	b := w.Bytes()
	return s.Put(ctx, CaptureKey{Chain: chain, L1Block: block, L1Hash: contentHash("certen:gapend:v1", b), Item: fmt.Sprintf("%s%d/%s", GapEndPrefix, block, e.Kind)}, b)
}

// GapEndsOf reads the terminal records of one block (usually zero or one).
func GapEndsOf(ctx context.Context, s CaptureStore, chain, block uint64) ([]GapEnd, error) {
	ks, err := s.ListByRange(ctx, chain, block, block, GapEndPrefix)
	if err != nil {
		return nil, err
	}
	var out []GapEnd
	for _, k := range ks {
		b, ok, err := s.Get(ctx, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("finality: gap end row %s vanished", k)
		}
		e, err := decodeGapEnd(b)
		if err != nil {
			return nil, fmt.Errorf("finality: gap end row %s: %w", k, err)
		}
		out = append(out, e)
	}
	return out, nil
}

func decodeGapEnd(b []byte) (GapEnd, error) {
	r := NewReader(b, DefaultLimits())
	m, err := r.Fixed("magic", len(endMagic))
	if err != nil || string(m) != endMagic {
		return GapEnd{}, errors.New("not a gap end record")
	}
	if _, err := r.U64("block"); err != nil {
		return GapEnd{}, err
	}
	kind, err := r.STR("kind")
	if err != nil {
		return GapEnd{}, err
	}
	reason, err := r.STR("reason")
	if err != nil {
		return GapEnd{}, err
	}
	n, err := r.Count("providers", 64, 4)
	if err != nil {
		return GapEnd{}, err
	}
	e := GapEnd{Kind: GapState(kind), Reason: reason}
	for i := 0; i < n; i++ {
		p, err := r.STR("provider")
		if err != nil {
			return GapEnd{}, err
		}
		e.Providers = append(e.Providers, p)
	}
	return e, r.End("gap end")
}

type rawGap struct {
	from, to uint64
	class    GapClass
}

// parseGapItem reads "gap/<to>/<class>".
func parseGapItem(item string) (to uint64, class GapClass, err error) {
	rest := strings.TrimPrefix(item, GapItemPrefix)
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return 0, "", fmt.Errorf("finality: malformed gap row item %q", item)
	}
	to, err = strconv.ParseUint(rest[:i], 10, 64)
	class = GapClass(rest[i+1:])
	if err != nil || !class.Valid() {
		return 0, "", fmt.Errorf("finality: malformed gap row item %q", item)
	}
	return to, class, nil
}

// blockOfItem reads "<prefix><block>[/...]".
func blockOfItem(item, prefix string) (uint64, string, error) {
	rest := strings.TrimPrefix(item, prefix)
	tail := ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest, tail = rest[:i], rest[i+1:]
	}
	n, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("finality: malformed gap bookkeeping item %q", item)
	}
	return n, tail, nil
}

func isIn(set map[uint64]struct{}, b uint64) bool {
	_, ok := set[b]
	return ok
}

type gapScanResult struct {
	pieces []GapRange
	filled uint64 // blocks inside a gap that have a fill
}

// gapScan is the one reading of the gap rows: the pieces of [from, to] that lie in a gap and are not filled, in ascending order.
func gapScan(ctx context.Context, s CaptureStore, chain, from, to uint64) (gapScanResult, error) {
	var res gapScanResult
	if to < from {
		return res, nil
	}
	ks, err := s.ListByRange(ctx, chain, 0, to, GapItemPrefix)
	if err != nil {
		return res, err
	}
	var raws []rawGap
	for _, k := range ks {
		gt, class, err := parseGapItem(k.Item)
		if err != nil {
			return res, err
		}
		if gt < k.L1Block {
			return res, fmt.Errorf("finality: malformed gap row %s: it ends before it starts", k)
		}
		if gt < from {
			continue
		}
		f := k.L1Block
		if f < from {
			f = from
		}
		if gt > to {
			gt = to
		}
		raws = append(raws, rawGap{f, gt, class})
	}
	if len(raws) == 0 {
		return res, nil
	}
	sort.Slice(raws, func(i, j int) bool {
		if raws[i].from != raws[j].from {
			return raws[i].from < raws[j].from
		}
		return raws[i].to < raws[j].to
	})
	// the union of the gap intervals
	type iv struct{ from, to uint64 }
	var union []iv
	for _, r := range raws {
		if n := len(union); n > 0 && r.from <= union[n-1].to+1 {
			if r.to > union[n-1].to {
				union[n-1].to = r.to
			}
			continue
		}
		union = append(union, iv{r.from, r.to})
	}
	lo, hi := union[0].from, union[len(union)-1].to
	fills, err := s.ListByRange(ctx, chain, lo, hi, GapFillPrefix)
	if err != nil {
		return res, err
	}
	filled := map[uint64]struct{}{}
	for _, k := range fills {
		b, _, err := blockOfItem(k.Item, GapFillPrefix)
		if err != nil {
			return res, err
		}
		if k.L1Hash == ([32]byte{}) {
			continue // a fill closes a block for the hash the capture verified; one that names none closes nothing (RB12-GO-INT D7)
		}
		filled[b] = struct{}{}
	}
	// scan rows close every gap block of their range (RB12-ARCHIVE-BACKFILL)
	scans, err := s.ListByRange(ctx, chain, 0, hi, GapScanPrefix)
	if err != nil {
		return res, err
	}
	for _, k := range scans {
		st, _, err := blockOfItem(k.Item, GapScanPrefix)
		if err != nil {
			return res, err
		}
		if st < k.L1Block {
			return res, fmt.Errorf("finality: malformed scan row %s: it ends before it starts", k)
		}
		for _, u := range union {
			from0, to0 := k.L1Block, st
			if from0 < u.from {
				from0 = u.from
			}
			if to0 > u.to {
				to0 = u.to
			}
			for b := from0; b <= to0 && from0 <= to0; b++ {
				filled[b] = struct{}{}
			}
		}
	}
	ends, err := s.ListByRange(ctx, chain, lo, hi, GapEndPrefix)
	if err != nil {
		return res, err
	}
	endState := map[uint64]GapState{}
	for _, k := range ends {
		b, kind, err := blockOfItem(k.Item, GapEndPrefix)
		if err != nil {
			return res, err
		}
		st := GapState(kind)
		if st != GapUnavailableProven && st != GapRetentionExpired {
			return res, fmt.Errorf("finality: malformed gap end item %q", k.Item)
		}
		if prev, ok := endState[b]; !ok || st == GapUnavailableProven && prev != GapUnavailableProven {
			endState[b] = st // proved unavailability outranks an expiry
		}
	}
	special := map[uint64]struct{}{}
	for b := range filled {
		special[b] = struct{}{}
	}
	for b := range endState {
		special[b] = struct{}{}
	}
	sp := make([]uint64, 0, len(special))
	for b := range special {
		sp = append(sp, b)
	}
	sort.Slice(sp, func(i, j int) bool { return sp[i] < sp[j] })
	var pieces []GapRange
	emit := func(f, t uint64, st GapState) {
		if n := len(pieces); n > 0 && pieces[n-1].State == st && pieces[n-1].To+1 == f {
			pieces[n-1].To = t
			return
		}
		pieces = append(pieces, GapRange{From: f, To: t, State: st})
	}
	idx := 0
	for _, u := range union {
		cur := u.from
		for idx < len(sp) && sp[idx] < u.from {
			idx++
		}
		for j := idx; j < len(sp) && sp[j] <= u.to; j++ {
			b := sp[j]
			if b > cur {
				emit(cur, b-1, GapOpen)
			}
			switch {
			case isIn(filled, b):
				res.filled++
			default:
				emit(b, b, endState[b])
			}
			cur = b + 1
		}
		if cur <= u.to {
			emit(cur, u.to, GapOpen)
		}
	}
	for i := range pieces {
		set := map[GapClass]struct{}{}
		for _, r := range raws {
			if r.from <= pieces[i].To && r.to >= pieces[i].From {
				set[r.class] = struct{}{}
			}
		}
		for c := range set {
			pieces[i].Classes = append(pieces[i].Classes, c)
		}
		sort.Slice(pieces[i].Classes, func(a, b int) bool { return pieces[i].Classes[a] < pieces[i].Classes[b] })
	}
	res.pieces = pieces
	return res, nil
}

// GapsIn returns the runs of blocks of [from, to] that lie in a recorded gap and have no fill, ascending, clipped to the window. An empty
// answer means "no gap" only for a store that could be read: a failing store is an error.
func GapsIn(ctx context.Context, s CaptureStore, chain, from, to uint64) ([]GapRange, error) {
	r, err := gapScan(ctx, s, chain, from, to)
	return r.pieces, err
}

// GapTotals counts the blocks of the recorded gaps by state.
type GapTotals struct {
	Open, UnavailableProven, RetentionExpired, Filled uint64
}

// GapTotalsOf counts every gap block of the chain.
func GapTotalsOf(ctx context.Context, s CaptureStore, chain uint64) (GapTotals, error) {
	r, err := gapScan(ctx, s, chain, 0, MaxCaptureBlock)
	t := GapTotals{Filled: r.filled}
	for _, p := range r.pieces {
		switch p.State {
		case GapOpen:
			t.Open += p.Blocks()
		case GapUnavailableProven:
			t.UnavailableProven += p.Blocks()
		case GapRetentionExpired:
			t.RetentionExpired += p.Blocks()
		}
	}
	return t, err
}

// AuditSpacing records as gaps (class spacing_unproven) the runs between two consecutive captured blocks of item, in [lo, hi], that are
// longer than minSpacing: a capture loop that holds no row for such a run cannot show it scanned the blocks (a quiet run and an outage look
// alike in a store that keeps only the blocks with inbox transactions). The backfill scans them; a run that was only quiet is closed by
// fills. It returns the still-open pieces of every audited run; a repeated audit writes nothing new.
func AuditSpacing(ctx context.Context, s CaptureStore, chain uint64, item string, lo, hi, minSpacing uint64) ([]GapRange, error) {
	ks, err := s.ListByRange(ctx, chain, lo, hi, item)
	if err != nil {
		return nil, err
	}
	var prev uint64
	have := false
	var found []GapRange
	for _, k := range ks {
		if k.Item != item || have && k.L1Block == prev {
			continue
		}
		if have && k.L1Block-prev > minSpacing {
			from, to := prev+1, k.L1Block-1
			if err := RecordGap(ctx, s, chain, from, to, GapSpacingUnproven); err != nil {
				return found, err
			}
			open, err := GapsIn(ctx, s, chain, from, to)
			if err != nil {
				return found, err
			}
			found = append(found, open...)
		}
		prev, have = k.L1Block, true
	}
	return found, nil
}

// GapScanPrefix is the item prefix of the scan rows (RB12-ARCHIVE-BACKFILL, Arbitrum).
const GapScanPrefix = "gapscan/"

const scanMagic = "CGSC1"

// RecordGapScan records that every SequencerInbox-style event of the blocks [from, to] was read (a complete log answer) and captured: the
// gap blocks in that range are closed, as by a fill, for chains whose captured items are sparse events and whose blocks therefore have no
// row to fill under. The row is "gapscan/<to>" at (from, zero hash) with "CGSC1" || u64 from || u64 to, a function of the range alone.
func RecordGapScan(ctx context.Context, s CaptureStore, chain, from, to uint64) error {
	if to < from || to > MaxCaptureBlock {
		return fmt.Errorf("finality: bad scan range %d-%d", from, to)
	}
	var w Writer
	w.Fixed([]byte(scanMagic))
	w.U64(from)
	w.U64(to)
	return s.Put(ctx, CaptureKey{Chain: chain, L1Block: from, Item: fmt.Sprintf("%s%d", GapScanPrefix, to)}, w.Bytes())
}
