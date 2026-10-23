// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// RB12-CAPTURE-GAP against the real table (proof_finality_capture): the gap rows are ordinary insert-only capture rows (no migration), the
// prefix queries do not confuse gap/ with gapfill/, and seven validators writing the same gap, fill, end and note rows at once never conflict.

func gapChainID() uint64 { return uint64(2_000_000_000 + time.Now().UnixNano()%1_000_000_000) }

type gapCapturer struct {
	store finality.CaptureStore
	chain uint64
	mu    sync.Mutex
	calls map[uint64]int
}

func (g *gapCapturer) CaptureBlockHash(ctx context.Context, n uint64) ([32]byte, bool, error) {
	g.mu.Lock()
	g.calls[n]++
	g.mu.Unlock()
	h := [32]byte{0xb1, byte(n), byte(n >> 8)}
	// the rows of the block, written the way the live capture writes them: identical bytes from every validator
	for _, item := range []string{"hdr", "inbox", "syscfg"} {
		if err := g.store.Put(ctx, finality.CaptureKey{Chain: g.chain, L1Block: n, L1Hash: h, Item: item}, []byte(fmt.Sprintf("%s-%d", item, n))); err != nil {
			return h, false, &baseposted.CaptureFailure{Block: n, State: finality.NewState(baseposted.CodeCaptureRowConflict, "chain", g.chain, "l1_block", n), Err: err}
		}
	}
	return h, true, nil
}

func TestRB12GapRowsInTheRealTable(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := gapChainID()

	// seven validators record the same gaps, fills, ends and notes concurrently
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for v := 0; v < 7; v++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, f := range []func() error{
				func() error { return finality.RecordGap(ctx, store, chain, 1000, 1228, finality.GapSpacingUnproven) },
				func() error { return finality.RecordGap(ctx, store, chain, 1500, 1500, finality.GapBlobUnavailable) },
				func() error { return finality.RecordGapFill(ctx, store, chain, 1001, [32]byte{7}, true) },
				func() error {
					return finality.RecordGapEnd(ctx, store, chain, 1500, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"b", "a"}})
				},
				func() error {
					return finality.RecordGapNote(ctx, store, chain, 1500, finality.GapBlobUnavailable, "beacon blob answer HTTP 404")
				},
			} {
				if err := f(); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a concurrent identical write conflicted: %v", err)
	}

	got, err := finality.GapsIn(ctx, store, chain, 0, finality.MaxCaptureBlock)
	if err != nil {
		t.Fatal(err)
	}
	want := "[1000-1000:open[spacing_unproven] 1002-1228:open[spacing_unproven] 1500-1500:unavailable_proven[blob_unavailable]]"
	if fmt.Sprint(got) != want {
		t.Fatalf("gaps\n got %v\nwant %s", got, want)
	}
	// the prefix queries are exact: gap/ is not gapfill/, gapend/ or gapnote/
	for prefix, n := range map[string]int{finality.GapItemPrefix: 2, finality.GapFillPrefix: 1, finality.GapEndPrefix: 1, finality.GapNotePrefix: 1} {
		ks, err := store.ListByRange(ctx, chain, 0, finality.MaxCaptureBlock, prefix)
		if err != nil || len(ks) != n {
			t.Fatalf("prefix %q: %d rows %v, want %d", prefix, len(ks), err, n)
		}
	}
	ends, err := finality.GapEndsOf(ctx, store, chain, 1500)
	if err != nil || len(ends) != 1 || fmt.Sprint(ends[0].Providers) != "[a b]" {
		t.Fatalf("%v %v", ends, err)
	}
	tot, _ := finality.GapTotalsOf(ctx, store, chain)
	if tot.Open != 228 || tot.UnavailableProven != 1 || tot.Filled != 1 {
		t.Fatalf("%+v", tot)
	}
}

func TestRB12BackfillAgainstTheRealTableIsIdempotentAcrossValidatorsAndNamesAConflict(t *testing.T) {
	ctx := context.Background()
	store := NewFinalityCaptureStore(NewClientFromDB(testDB))
	chain := gapChainID()
	if err := finality.RecordGap(ctx, store, chain, 2000, 2019, finality.GapOutageUnscanned); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var wg sync.WaitGroup
	caps := make([]*gapCapturer, 3)
	for v := range caps {
		caps[v] = &gapCapturer{store: store, chain: chain, calls: map[uint64]int{}}
		bf := &baseposted.Backfiller{Chain: chain, Store: store, Capturer: caps[v], Policy: baseposted.DefaultBackfillPolicy(), Now: func() time.Time { return now }}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if rep, err := bf.Step(ctx, 4); err != nil || rep.Failed != 0 {
					t.Errorf("a validator's step failed: %+v %v", rep, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if open, err := finality.GapsIn(ctx, store, chain, 0, finality.MaxCaptureBlock); err != nil || len(open) != 0 {
		t.Fatalf("still open: %v %v", open, err)
	}
	for n := uint64(2000); n < 2020; n++ {
		ks, _ := store.ListByRange(ctx, chain, n, n, "inbox")
		if len(ks) < 1 {
			t.Fatalf("block %d has no inbox row", n)
		}
	}
	// a row that exists with other bytes is a named conflict and the gap stays open
	if err := finality.RecordGap(ctx, store, chain, 3000, 3000, finality.GapStateProofUnavailable); err != nil {
		t.Fatal(err)
	}
	h := [32]byte{0xb1, byte(3000 & 0xff), byte(3000 >> 8)}
	if err := store.Put(ctx, finality.CaptureKey{Chain: chain, L1Block: 3000, L1Hash: h, Item: "hdr"}, []byte("other bytes")); err != nil {
		t.Fatal(err)
	}
	c := &gapCapturer{store: store, chain: chain, calls: map[uint64]int{}}
	bf := &baseposted.Backfiller{Chain: chain, Store: store, Capturer: c, Policy: baseposted.DefaultBackfillPolicy(), Now: func() time.Time { return now }, Pick: func(int) int { return 0 }}
	rep, err := bf.Step(ctx, 1)
	if err != nil || rep.Conflicts != 1 || rep.Filled != 0 {
		t.Fatalf("a conflicting row is named and not filled over: %+v %v", rep, err)
	}
	var cf *baseposted.CaptureFailure
	_, _, cerr := c.CaptureBlockHash(ctx, 3000)
	if !errors.As(cerr, &cf) || !errors.Is(cerr, finality.ErrCaptureConflict) {
		t.Fatalf("%v", cerr)
	}
	if open, _ := finality.GapsIn(ctx, store, chain, 3000, 3000); len(open) != 1 {
		t.Fatalf("the gap stays open: %v", open)
	}
}
