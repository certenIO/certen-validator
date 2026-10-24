// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// rowStore is a capture store WITHOUT PutBlock (the embedded interface hides the concrete store's method set) whose Put refuses the
// given item: the batch group is then written row by row, in the order the capturer lists it.
type rowStore struct {
	CaptureStore
	refuse string
}

func (r rowStore) Put(ctx context.Context, k Key, b []byte) error {
	if k.Item == r.refuse {
		return errors.New("store down")
	}
	return r.CaptureStore.Put(ctx, k, b)
}

// blockStore admits a block as a unit and refuses this one.
type blockStore struct{ CaptureStore }

func (blockStore) PutBlock(context.Context, []finality.CaptureRow) error {
	return errors.New("finality_capture_budget_exceeded")
}

func batchRows(t *testing.T, s CaptureStore) int {
	t.Helper()
	ks, err := s.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "batch/")
	if err != nil {
		t.Fatal(err)
	}
	return len(ks)
}

// The batch record names a batch as captured and is the row it is attested from: whatever row of the batch the store refuses, the
// record must not be there (RB11-DBFIX D7).
func TestARefusedHeaderOrCalldataRowLeavesNoBatchRecord(t *testing.T) {
	for _, item := range []string{ItemHeader, ItemCalldata(77), ItemBatch(77)} {
		mem := NewMemStore()
		sc := newScenario(t, LocTxInput, 0)
		rep, err := newCapturer(sc, rowStore{CaptureStore: mem, refuse: item}).Tick(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", item, err)
		}
		if len(rep.NewBatches) != 0 || len(rep.Errors) == 0 {
			t.Errorf("a store that refuses %s: new batches %v, errors %v", item, rep.NewBatches, rep.Errors)
		}
		if n := batchRows(t, mem); n != 0 {
			t.Errorf("a store that refuses %s holds %d batch records", item, n)
		}
	}
}

func TestABatchTheStoreRefusesAsAUnitStoresNoRowAtAll(t *testing.T) {
	mem := NewMemStore()
	sc := newScenario(t, LocTxInput, 0)
	rep, err := newCapturer(sc, blockStore{mem}).Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NewBatches) != 0 || len(rep.Errors) == 0 {
		t.Fatalf("new batches %v, errors %v", rep.NewBatches, rep.Errors)
	}
	for n := uint64(0); n < 2000; n++ {
		rows, err := mem.ListByBlock(context.Background(), ChainArbitrumSepolia, n)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Item == ItemBatch(77) || r.Item == ItemCalldata(77) {
				t.Fatalf("a refused batch left %s at block %d", r.Item, n)
			}
		}
	}
}
