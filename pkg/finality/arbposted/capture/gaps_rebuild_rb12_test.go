// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-CAPTURE-GAP, the restart rebuild of the Arbitrum capturer under the mutation gate: every store failure and malformed row is an error,
// a complete batch is never a gap at any age, what is missing names the class and the fill waits for both, and "old" begins exactly at
// RebuildBlocks.

type arbFault struct {
	CaptureStore
	failList map[string]bool
	failGet  string // item prefix whose Get fails
	failPut  string // item prefix whose Put fails
}

func (f arbFault) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	if f.failList[prefix] {
		return nil, errors.New("store down: " + prefix)
	}
	return f.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
}

func (f arbFault) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if f.failGet != "" && strings.HasPrefix(k.Item, f.failGet) {
		return nil, false, errors.New("store down: get " + f.failGet)
	}
	return f.CaptureStore.Get(ctx, k)
}

func (f arbFault) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	if f.failPut != "" && strings.HasPrefix(k.Item, f.failPut) {
		return errors.New("store down: put " + f.failPut)
	}
	return f.CaptureStore.Put(ctx, k, b)
}

// arbFirstRun captures the batch event (and, unless fail, everything else); the providers are healthy again afterwards.
func arbFirstRun(t *testing.T, loc uint8, fail bool) (*scenario, CaptureStore) {
	t.Helper()
	store := NewMemStore()
	sc := newScenario(t, loc, 1)
	if fail {
		sc.beacon.err = &BeaconError{Slot: 1, Status: 404, Err: "not served"}
		sc.l1.proofErr = errors.New("down")
	}
	if _, err := newCapturer(sc, store).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	sc.beacon.err, sc.l1.proofErr = nil, nil
	return sc, store
}

func arbMoveHead(sc *scenario, head uint64) {
	sc.l1.head = head
	for n := head - 5; n <= head; n++ {
		sc.l1.headers[n] = synthHeader(n, 1700000000+n*12, sc.l1.state.root, "")
	}
}

func TestRB12ArbRebuildReportsEveryStoreFailureAndMalformedRowAsAnError(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		wrap func(CaptureStore) CaptureStore
	}{
		{"batch listing", func(s CaptureStore) CaptureStore {
			return arbFault{CaptureStore: s, failList: map[string]bool{"batch/": true}}
		}},
		{"proof listing", func(s CaptureStore) CaptureStore {
			return arbFault{CaptureStore: s, failList: map[string]bool{"proof/": true}}
		}},
		{"blob listing", func(s CaptureStore) CaptureStore {
			return arbFault{CaptureStore: s, failList: map[string]bool{"blob/": true}}
		}},
		{"batch row unreadable", func(s CaptureStore) CaptureStore { return arbFault{CaptureStore: s, failGet: "batch/"} }},
		{"header row unreadable", func(s CaptureStore) CaptureStore { return arbFault{CaptureStore: s, failGet: ItemHeader} }},
		{"gap row not recordable", func(s CaptureStore) CaptureStore { return arbFault{CaptureStore: s, failPut: "gap/"} }},
	} {
		for _, head := range []uint64{1000, 995 + 50_000} { // recent and old
			sc, store := arbFirstRun(t, LocBlob, true)
			arbMoveHead(sc, head)
			if _, err := newCapturer(sc, tc.wrap(store)).Tick(ctx); err == nil {
				t.Errorf("%s (head %d): the rebuild swallowed the failure", tc.name, head)
			}
		}
	}
	// a batch row that does not decode
	sc, store := arbFirstRun(t, LocBlob, true)
	arbMoveHead(sc, 995+50_000)
	_ = store.Put(ctx, finality.CaptureKey{Chain: ChainArbitrumSepolia, L1Block: 996, Item: "batch/78"}, []byte("garbage"))
	if _, err := newCapturer(sc, store).Tick(ctx); err == nil {
		t.Error("a batch row that does not decode was skipped")
	}
}

func TestRB12ArbACompleteBatchIsNeverAGapAtAnyAge(t *testing.T) {
	ctx := context.Background()
	for _, loc := range []uint8{LocBlob, LocTxInput} {
		for _, head := range []uint64{1000, 995 + 7200, 995 + 7201, 995 + 50_000} {
			sc, store := arbFirstRun(t, loc, false)
			arbMoveHead(sc, head)
			c := NewCapturer(store, sc.l1, sc.beacon, Config{StartBack: 20})
			if _, err := c.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			if gaps, _ := store.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, finality.GapItemPrefix); len(gaps) != 0 {
				t.Errorf("loc %d head %d: a complete batch was recorded as a gap: %v", loc, head, gaps)
			}
			if len(c.needBlobs) != 0 || len(c.needProof) != 0 {
				t.Errorf("loc %d head %d: a complete batch is waiting for blobs or a proof", loc, head)
			}
		}
	}
}

func TestRB12ArbWhatIsMissingNamesTheClassAndTheFillWaitsForBoth(t *testing.T) {
	ctx := context.Background()
	// only the proof is missing: the store holds the batch and its blobs but no proof row
	sc, store := arbFirstRun(t, LocBlob, false)
	store2 := NewMemStore()
	rows, _ := store.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "")
	for _, k := range rows {
		if strings.HasPrefix(k.Item, "proof/") {
			continue
		}
		b, _, _ := store.Get(ctx, k)
		_ = store2.Put(ctx, k, b)
	}
	sc.l1.proofErr = errors.New("down")
	arbMoveHead(sc, 995+50_000)
	var logged []string
	c := NewCapturer(store2, sc.l1, sc.beacon, Config{StartBack: 20, Logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }})
	if _, err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	gaps, _ := store2.ListByRange(ctx, ChainArbitrumSepolia, 995, 995, finality.GapItemPrefix)
	if len(gaps) != 1 || gaps[0].Item != "gap/995/state_proof_unavailable" {
		t.Fatalf("only the proof is missing: %v", gaps)
	}
	if fills, _ := store2.ListByRange(ctx, ChainArbitrumSepolia, 995, 995, finality.GapFillPrefix); len(fills) != 0 {
		t.Fatalf("not complete yet: %v", fills)
	}
	if !strings.Contains(fmt.Sprint(logged), "50000 blocks before the head") {
		t.Fatalf("the log names how old the batch is: %v", logged)
	}
	sc.l1.proofErr = nil
	c.ticks = 10 // the next tick is on the old-batch cadence
	if _, err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	fills, _ := store2.ListByRange(ctx, ChainArbitrumSepolia, 995, 995, finality.GapFillPrefix)
	if len(fills) != 1 {
		t.Fatalf("complete: one fill: %v", fills)
	}
	b, _, _ := store2.Get(ctx, fills[0])
	if len(b) == 0 || b[len(b)-1] != 1 {
		t.Fatalf("the fill says the block holds the batch: %x", b)
	}
	// the blobs AND the proof are missing: when only the blobs arrive the gap stays open
	sc3, store3 := arbFirstRun(t, LocBlob, true)
	sc3.l1.proofErr = errors.New("down")
	sc3.beacon.err = &BeaconError{Slot: 1, Status: 404, Err: "not served"}
	arbMoveHead(sc3, 995+50_000)
	c3 := newCapturer(sc3, store3)
	if _, err := c3.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	sc3.beacon.err = nil // the blobs are served from now on, the proof still is not
	c3.ticks = 10
	rep, err := c3.Tick(ctx)
	if err != nil || rep.BlobsStored != 1 {
		t.Fatalf("the blobs arrived: %+v %v", rep, err)
	}
	if fills, _ := store3.ListByRange(ctx, ChainArbitrumSepolia, 995, 995, finality.GapFillPrefix); len(fills) != 0 {
		t.Fatalf("the blobs arrived but the proof did not: the gap stays open: %v", fills)
	}
}

// The age that makes a batch "old" is exactly RebuildBlocks: at that distance it is still recent (retried every tick), one block further it is
// old (retried on the cadence).
func TestRB12ArbTheOldBatchBoundaryIsRebuildBlocks(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		head      uint64
		wantRetry bool // asked again on a tick that is not on the old cadence
	}{{995 + 7200, true}, {995 + 7201, false}} {
		sc, store := arbFirstRun(t, LocBlob, true)
		arbMoveHead(sc, tc.head)
		sc.beacon.err = &BeaconError{Slot: 1, Status: 404, Err: "not served"}
		sc.l1.proofErr = errors.New("down")
		c := newCapturer(sc, store)
		if _, err := c.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		before := sc.beacon.calls
		if _, err := c.Tick(ctx); err != nil { // tick 2: not on the cadence of 10
			t.Fatal(err)
		}
		if got := sc.beacon.calls > before; got != tc.wantRetry {
			t.Errorf("head %d: retried on a tick off the old cadence = %v, want %v", tc.head, got, tc.wantRetry)
		}
	}
}
