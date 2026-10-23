// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RB12-ARCHIVE-BACKFILL: the PREFIX extension of a capture store.
//
// A capture loop covers the L1 blocks from the one it started at. A leg whose sequencer window lies below that start was posted before
// the capture existed; its evidence can be had only by capturing those blocks later. That is a capture gap in every respect except that
// no loop ever scanned the blocks, so it is recorded the same way, as a gap row, of the class capture_prefix:
//
//	gap/<to>/capture_prefix   at L1Block=from, zero hash   "CGAP1" || u64 from || u64 to || STR "capture_prefix"
//
// "the capture store is to be extended over [from, to]". The row is a function of (from, to) alone, so any number of validators asking for
// the same window write the same bytes; it is never updated or deleted. A request names the window of ONE leg (clipped to the part below
// the scanned region), so the store is extended only where a leg needs it, and the windows of different legs merge where they touch. From
// then on the gap machinery applies unchanged: a block of a window is open until a fill row closes it, ends carry the proof that the
// providers do not have it, and a leg whose window holds an unfilled block is judged l1_capture_gap, never "not posted yet".

// GapCapturePrefix is the gap class of a capture-store prefix request.
const GapCapturePrefix GapClass = "capture_prefix"

// PrefixWindow is one requested run of blocks, both ends included.
type PrefixWindow struct{ From, To uint64 }

// Blocks is the number of blocks of the window.
func (w PrefixWindow) Blocks() uint64 { return w.To - w.From + 1 }

// PrefixPolicy bounds what may be requested. The zero value is "the extension is off".
type PrefixPolicy struct {
	// MaxBlocks is the most blocks the union of all requested windows may hold (0 = off). It bounds the growth of the capture store: a
	// Base window of 3,601 L1 blocks is about 85 MB of rows.
	MaxBlocks uint64
	// Floor is the lowest L1 block a window may start at (0 = no floor).
	Floor uint64
}

// Enabled reports whether requests are taken at all.
func (p PrefixPolicy) Enabled() bool { return p.MaxBlocks > 0 }

// PrefixVerdict is what a request came to; every verdict is named and none is an error.
type PrefixVerdict string

const (
	PrefixRecorded   PrefixVerdict = "recorded"    // the request was written
	PrefixKnown      PrefixVerdict = "known"       // recorded windows already cover it (written by this or another validator)
	PrefixOff        PrefixVerdict = "off"         // the extension is switched off (MaxBlocks 0)
	PrefixBelowFloor PrefixVerdict = "below_floor" // the window starts below the policy's floor
	PrefixOverBudget PrefixVerdict = "over_budget" // the union of the windows would exceed MaxBlocks
	prefixClassItem                = "/" + string(GapCapturePrefix)
)

// PrefixWindowsOf returns the requested windows of the chain, ascending by (From, To), from the NAMES of the gap rows alone (no row is
// read). A store that cannot be listed is an error, never "no windows".
func PrefixWindowsOf(ctx context.Context, s CaptureStore, chain uint64) ([]PrefixWindow, error) {
	ks, err := s.ListByRange(ctx, chain, 0, MaxCaptureBlock, GapItemPrefix)
	if err != nil {
		return nil, err
	}
	var out []PrefixWindow
	for _, k := range ks {
		if !strings.HasSuffix(k.Item, prefixClassItem) {
			continue
		}
		to, class, err := parseGapItem(k.Item)
		if err != nil {
			return nil, err
		}
		if class != GapCapturePrefix {
			continue
		}
		if to < k.L1Block {
			return nil, fmt.Errorf("finality: malformed prefix row %s: it ends before it starts", k)
		}
		out = append(out, PrefixWindow{From: k.L1Block, To: to})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out, nil
}

// MergePrefixWindows is the union of the windows as ascending runs; windows that overlap or touch (To+1 == From) are one run.
func MergePrefixWindows(ws []PrefixWindow) []PrefixWindow {
	c := append([]PrefixWindow(nil), ws...)
	sort.Slice(c, func(i, j int) bool {
		if c[i].From != c[j].From {
			return c[i].From < c[j].From
		}
		return c[i].To < c[j].To
	})
	var out []PrefixWindow
	for _, w := range c {
		if n := len(out); n > 0 && w.From <= out[n-1].To+1 {
			if w.To > out[n-1].To {
				out[n-1].To = w.To
			}
			continue
		}
		out = append(out, w)
	}
	return out
}

// PrefixBlocks is the number of blocks of merged (ascending, non-overlapping) runs.
func PrefixBlocks(merged []PrefixWindow) uint64 {
	var n uint64
	for _, w := range merged {
		n += w.Blocks()
	}
	return n
}

// PrefixLowest is the lowest block any run reaches.
func PrefixLowest(merged []PrefixWindow) (uint64, bool) {
	if len(merged) == 0 {
		return 0, false
	}
	return merged[0].From, true
}

// PrefixCovers reports whether [from, to] lies wholly inside the merged runs; when it does not, firstUncovered is the lowest block of the
// range that is in no run. An empty range (from > to) has nothing uncovered.
func PrefixCovers(merged []PrefixWindow, from, to uint64) (covered bool, firstUncovered uint64) {
	if from > to {
		return true, 0
	}
	cur := from
	for _, w := range merged {
		if w.To < cur {
			continue
		}
		if w.From > cur {
			return false, cur
		}
		if w.To >= to {
			return true, 0
		}
		cur = w.To + 1
	}
	return false, cur
}

// prefixMu serialises RequestPrefix within a process.
var prefixMu sync.Mutex

// RequestPrefix asks for [from, to] to be captured below the scanned region. Windows already recorded that cover it make it a no-op
// (PrefixKnown); otherwise the policy decides, by the union of the recorded windows and this one, and a granted request is one new
// insert-only gap row. The budget is read from the rows this validator can see, under a lock that makes the read and the write one step
// within the process; validators (separate processes) asking at the same instant for different windows can each pass the bound, so the
// union can exceed MaxBlocks by at most one window per other validator; it never grows without a request.
func RequestPrefix(ctx context.Context, s CaptureStore, chain, from, to uint64, pol PrefixPolicy) (PrefixVerdict, error) {
	if to < from || to > MaxCaptureBlock {
		return "", fmt.Errorf("finality: bad prefix range %d-%d", from, to)
	}
	// the read of the union and the write of the window are one step within a process (the upgrader runs several builds at once)
	prefixMu.Lock()
	defer prefixMu.Unlock()
	ws, err := PrefixWindowsOf(ctx, s, chain)
	if err != nil {
		return "", err
	}
	merged := MergePrefixWindows(ws)
	if ok, _ := PrefixCovers(merged, from, to); ok {
		return PrefixKnown, nil
	}
	if !pol.Enabled() {
		return PrefixOff, nil
	}
	if from < pol.Floor {
		return PrefixBelowFloor, nil
	}
	if PrefixBlocks(MergePrefixWindows(append(ws, PrefixWindow{From: from, To: to}))) > pol.MaxBlocks {
		return PrefixOverBudget, nil
	}
	if err := RecordGap(ctx, s, chain, from, to, GapCapturePrefix); err != nil {
		return "", err
	}
	return PrefixRecorded, nil
}

// GapSlotPrefix is the item prefix of the beacon-slot evidence of a block the providers proved unavailable.
const GapSlotPrefix = "gapslot/"

const slotMagic = "CGSL1"

func gapSlotKey(chain, block uint64) CaptureKey {
	return CaptureKey{Chain: chain, L1Block: block, Item: fmt.Sprintf("%s%d", GapSlotPrefix, block)}
}

// RecordGapSlot records the beacon slot of an L1 block whose blobs are gone: "CGSL1" || u64 block || u64 slot, at (block, zero hash). The
// slot is a function of the block (its timestamp), so every validator writes the same bytes; another slot under the same block is the
// named conflict ErrCaptureConflict. It is written BEFORE the end row of the block, so a leg never sees an end without its slot.
func RecordGapSlot(ctx context.Context, s CaptureStore, chain, block, slot uint64) error {
	var w Writer
	w.Fixed([]byte(slotMagic))
	w.U64(block)
	w.U64(slot)
	return s.Put(ctx, gapSlotKey(chain, block), w.Bytes())
}

// GapSlotOf reads the slot recorded for block; ok is false when none was recorded.
func GapSlotOf(ctx context.Context, s CaptureStore, chain, block uint64) (slot uint64, ok bool, err error) {
	b, found, err := s.Get(ctx, gapSlotKey(chain, block))
	if err != nil || !found {
		return 0, false, err
	}
	r := NewReader(b, DefaultLimits())
	m, err := r.Fixed("magic", len(slotMagic))
	if err != nil || string(m) != slotMagic {
		return 0, false, fmt.Errorf("finality: row %s is not a gap slot record", gapSlotKey(chain, block))
	}
	bl, err := r.U64("block")
	if err != nil {
		return 0, false, err
	}
	if slot, err = r.U64("slot"); err != nil {
		return 0, false, err
	}
	if bl != block {
		return 0, false, fmt.Errorf("finality: gap slot record of block %d names block %d", block, bl)
	}
	return slot, true, r.End("gap slot")
}
