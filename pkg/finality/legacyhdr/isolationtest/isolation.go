// Copyright 2026 Certen Protocol

// Package isolationtest proves, against any finality.CaptureStore, that the legacy-header rows (item legacyhdr.ItemLegacyHeader) do
// not change what any production reader of proof_finality_capture sees. The table is shared: the key is (chain, l1_block, l1_hash,
// item), and a legacy row sits at the ROLLUP's own block number (about 46.4M on Base Sepolia, 313.9M on Arbitrum Sepolia) or, for
// Ethereum Sepolia, in the very numbering space of the L1 rows. Every reader filters by an exact item or an item prefix; this package
// is the permanent guard of that argument. Used by the tests of pkg/finality/legacyhdr (memory store) and pkg/database (PostgreSQL).
package isolationtest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr"
)

// ProductionItems are the exact items and the item prefixes every reader of the capture table uses, listed from the code of main and of
// the Train 2, Train 3, capture-gap, capture-index, Sepolia-spine and archive-backfill branches (git grep of Item*/Prefix constants and
// of the literal item families, 2026-10-23). An entry ending in "/" is a family prefix; the others are exact items that are also
// scanned as prefixes (ListByRange(starts_with)). The legacy item must be disjoint from all of them in BOTH directions: none may be a
// prefix of it (or a scan by that prefix would list legacy rows), and it may not be a prefix of one (or its scan would list theirs).
var ProductionItems = []string{
	"hdr", "header", "inbox", "syscfg", "cursor", "runtime/cursor", // baseposted, arbposted, runtime, finality.CaptureCursorItem
	"tx/", "txnodes/", "blob/", "batch/", "proof/", // baseposted and arbposted families
	"calldata/", "delayedproof/", "unavailable/", "blobunavailable/", // arbposted/capture/records.go ItemCalldata, ItemDelayedProof, ItemUnavailable, ItemBlobUnavailable
	"gap/", "gapend/", "gapnote/", "gapfill/", "gapslot/", "gapclaim/", // capture-gap / archive-backfill
	"gapscan/",   // archive-backfill: the Arbitrum scan bookkeeping (gaps.go)
	"gaporphan/", // F18: the mark of an orphan block, which a gap fill of that hash no longer closes (gaps.go)
	"idx/",       // capture index (idx/g<gen>/<family>/...)
	// the parts of the Base index item names (baseposted/index.go itemDigest, itemMarker, itemQuarantine: idx/g<gen>/bi/f, /x/<id>, /q/<id>),
	// which the scanner meets as bare constants; the rows themselves are under "idx/" above
	"f", "x", "q",
	"spine/", "spine/n", // Sepolia spine chunks
	"basefinal/game/", "arbfinal/state/", "arbfinal/conf/", "arbfinal/wallet/", // attesting builders' state captures
	"runtime/", // the runtime family
}

// Disjoint returns the first production item that is a prefix of the legacy item or has the legacy item as a prefix.
func Disjoint() error { return DisjointFrom(legacyhdr.ItemLegacyHeader, ProductionItems) }

// DisjointFrom is Disjoint for any item and any production list (so the guard itself can be tested).
func DisjointFrom(item string, production []string) error {
	for _, p := range production {
		if strings.HasPrefix(item, p) {
			return fmt.Errorf("production item/prefix %q is a prefix of %q: a scan by it lists those rows", p, item)
		}
		if strings.HasPrefix(p, item) {
			return fmt.Errorf("%q is a prefix of production item %q: a scan by it lists production rows", item, p)
		}
	}
	return nil
}

// Chains are the three chain ids the check seeds: two with rollup-magnitude block numbers and one with L1-magnitude numbers. The real
// ids (84532, 421614, 11155111) for a throwaway store; ids of their own for a shared database.
type Chains struct{ L2A, L2B, L1 uint64 }

// Real are the chains of the 191 legacy legs.
var Real = Chains{L2A: 84532, L2B: 421614, L1: 11155111}

func hash(seed byte, n uint64) [32]byte {
	var h [32]byte
	h[0], h[31] = seed, byte(n)
	for i := 0; i < 8; i++ {
		h[8+i] = byte(n >> (8 * i))
	}
	return h
}

// seedProduction writes capture rows of every production item at L1-magnitude blocks (the Sepolia head is about 12M).
func seedProduction(ctx context.Context, store finality.CaptureStore, c Chains) error {
	put := func(chain, block uint64, seed byte, item string) error {
		return store.Put(ctx, finality.CaptureKey{Chain: chain, L1Block: block, L1Hash: hash(seed, block), Item: item}, []byte{seed, byte(block)})
	}
	items := []string{"hdr", "header", "inbox", "syscfg", "tx/0", "tx/3", "txnodes/0", "blob/0/1", "batch/1", "proof/1", "calldata/1", "delayedproof/2", "unavailable/3", "blobunavailable/4", "gap/105/outage_unscanned",
		"gapend/105/unavailable_proven", "gapnote/7", "gapfill/x", "gapslot/70", "gapclaim/9", "gapscan/421614", "gaporphan/105", "idx/g1/bi/c/1/2/00", "idx/g1/bi/cursor", "idx/g1/bi/f", "idx/g1/bi/x/00", "idx/g1/bi/q/00", "idx/g1/bi/u", "spine/n3",
		"basefinal/game/00ff", "arbfinal/state/aa", "arbfinal/conf/aa", "arbfinal/wallet/aa", "runtime/cursor", "cursor"}
	for _, chain := range []uint64{c.L2A, c.L2B, c.L1} {
		for i, item := range items {
			block := 11_700_000 + uint64(i)*37 // production rows live in the L1 numbering space on every chain
			if err := put(chain, block, 0x10+byte(i), item); err != nil {
				return err
			}
		}
	}
	return nil
}

// seedLegacy writes legacy header rows: Base and Arbitrum at their own block heights, Ethereum Sepolia INSIDE the range of the production
// rows (some at exactly the block number of a production row, under another hash).
func seedLegacy(ctx context.Context, store finality.CaptureStore, c Chains, item string) (n map[uint64]int, err error) {
	n = map[uint64]int{}
	put := func(chain, block uint64) error {
		n[chain]++
		return store.Put(ctx, finality.CaptureKey{Chain: chain, L1Block: block, L1Hash: hash(0xee, block), Item: item}, []byte{0xee, byte(block)})
	}
	for i := uint64(0); i < 12; i++ {
		if err = put(c.L2A, 46_468_457+i*100_321); err != nil {
			return
		}
		if err = put(c.L2B, 313_891_786+i*9_977); err != nil {
			return
		}
		if err = put(c.L1, 11_700_000+i*37); err != nil { // the very block numbers of the production rows
			return
		}
		if err = put(c.L1, 11_681_579+i*13_007); err != nil {
			return
		}
	}
	return
}

// snapshot is everything a production reader asks of a chain, flattened to a string: the capture coverage, the block bounds of every exact
// item the readers use, the key list of the window scans, and the key list of every production prefix over the whole range. The empty
// prefix (all rows) is deliberately not part of it: no production reader passes it.
func snapshot(ctx context.Context, store finality.CaptureStore, chain uint64) (string, error) {
	var b strings.Builder
	cov, ok, err := finality.CaptureCoverageOf(ctx, store, chain)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "coverage %v %v\n", cov, ok)
	for _, item := range []string{"runtime/cursor", "syscfg", "inbox", "hdr", "cursor", "idx/g1/bi/cursor", "spine/n3"} {
		lo, hi, ok, err := finality.BlockBoundsOf(ctx, store, chain, item)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "bounds %s %d %d %v\n", item, lo, hi, ok)
	}
	for _, w := range [][2]uint64{{0, finality.MaxCaptureBlock}, {11_699_000, 11_702_000}, {11_681_000, 11_832_868}} {
		ks, err := finality.CaptureKeysOfItemIn(ctx, store, chain, w[0], w[1], "inbox")
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "inbox %v %v\n", w, ks)
	}
	for _, p := range ProductionItems {
		for _, w := range [][2]uint64{{0, finality.MaxCaptureBlock}, {11_699_000, 11_702_000}} {
			ks, err := store.ListByRange(ctx, chain, w[0], w[1], p)
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "range %q %v %v\n", p, w, ks)
		}
	}
	return b.String(), nil
}

// Check is Run for the legacy item, any problem a test failure.
func Check(t testing.TB, store finality.CaptureStore, c Chains) {
	t.Helper()
	for _, p := range Run(store, c, legacyhdr.ItemLegacyHeader, true) {
		t.Error(p)
	}
}

// Run seeds production rows, takes the snapshot of every chain, adds rows of the given item and takes it again: no value may change. It
// then proves the rows are found by their own item (bounds and prefix scan return exactly what was written), so the equality is not the
// equality of two empty answers. requireDisjoint also refuses an item that is not disjoint from ProductionItems. It returns the problems
// found (none: the item is isolated).
func Run(store finality.CaptureStore, c Chains, item string, requireDisjoint bool) (problems []string) {
	ctx := context.Background()
	if requireDisjoint {
		if err := DisjointFrom(item, ProductionItems); err != nil {
			return []string{err.Error()}
		}
	}
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if err := seedProduction(ctx, store, c); err != nil {
		return []string{err.Error()}
	}
	before := map[uint64]string{}
	for _, chain := range []uint64{c.L2A, c.L2B, c.L1} {
		s, err := snapshot(ctx, store, chain)
		if err != nil {
			return []string{err.Error()}
		}
		if strings.Contains(s, "bounds runtime/cursor 0 0 false") || strings.Contains(s, "bounds inbox 0 0 false") {
			return []string{fmt.Sprintf("chain %d: the snapshot is not of production rows (no cursor or inbox rows)", chain)}
		}
		before[chain] = s
	}
	n, err := seedLegacy(ctx, store, c, item)
	if err != nil {
		return []string{err.Error()}
	}
	for _, chain := range []uint64{c.L2A, c.L2B, c.L1} {
		after, err := snapshot(ctx, store, chain)
		if err != nil {
			return append(problems, err.Error())
		}
		if after != before[chain] {
			fail("chain %d: adding %d rows of %q changed what the production readers see", chain, n[chain], item)
		}
		ks, err := store.ListByRange(ctx, chain, 0, finality.MaxCaptureBlock, item)
		if err != nil {
			return append(problems, err.Error())
		}
		own := 0
		for _, k := range ks {
			if k.Item == item {
				own++
			}
		}
		if own != n[chain] {
			fail("chain %d: the item's own scan lists %d rows, %d were written", chain, own, n[chain])
		}
		if lo, hi, ok, err := finality.BlockBoundsOf(ctx, store, chain, item); err != nil || !ok || lo >= hi {
			fail("chain %d: bounds of the item = %d %d %v %v", chain, lo, hi, ok, err)
		}
	}
	return problems
}
