// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// putOnly is a capture store WITHOUT PutBlock (embedding the interface hides the concrete store's method set), whose Put refuses
// every item in refuse. It stands for a store that cannot admit a block as a unit: the capture then writes row by row.
type putOnly struct {
	finality.CaptureStore
	refuse map[string]bool
}

func (p putOnly) Put(ctx context.Context, k CaptureKey, data []byte) error {
	if p.refuse[k.Item] {
		return errors.New("store down")
	}
	return p.CaptureStore.Put(ctx, k, data)
}

func inboxRows(t *testing.T, st finality.CaptureStore) int {
	t.Helper()
	ks, err := finality.CaptureKeysOfItem(context.Background(), st, 84532, ItemInbox)
	if err != nil {
		t.Fatal(err)
	}
	return len(ks)
}

// The inbox row names a block as captured and lists its transactions: whatever row of the block the store refuses, the row that names
// the block must not be there (RB11-DBFIX D7). On a store that writes row by row, that holds because the naming row is written last.
func TestARefusedRowLeavesNoInboxRowOnAStoreThatWritesRowByRow(t *testing.T) {
	blk, blob := sharedBlobBlock(t)
	for _, item := range []string{ItemHeader, ItemTx(1), ItemTxNodes(1), ItemBlob(1, 0), ItemSysCfg, ItemInbox} {
		mem := NewMemStore()
		st := putOnly{CaptureStore: mem, refuse: map[string]bool{item: true}}
		ok, err := newCapturer(&scriptL1{blk: blk}, &scriptBeacon{blobs: [][]byte{blob}}, st, nil).CaptureBlock(context.Background(), 1000)
		if ok || err == nil {
			t.Errorf("a store that refuses %s: (%v, %v)", item, ok, err)
		}
		if n := inboxRows(t, mem); n != 0 {
			t.Errorf("a store that refuses %s holds %d inbox rows: the block is named as captured without its rows", item, n)
		}
	}
	// the same capture on a store that takes it is whole: the inbox row and everything it lists
	mem := NewMemStore()
	if ok, err := newCapturer(&scriptL1{blk: blk}, &scriptBeacon{blobs: [][]byte{blob}}, putOnly{CaptureStore: mem}, nil).CaptureBlock(context.Background(), 1000); !ok || err != nil {
		t.Fatalf("(%v, %v)", ok, err)
	}
	if inboxRows(t, mem) != 1 || rowsOf(t, mem) != 6 {
		t.Fatalf("inbox rows %d, rows %d", inboxRows(t, mem), rowsOf(t, mem))
	}
}

// blockRefuser is a store that admits blocks as a unit and refuses this one: the capture must fail and store not one row.
type blockRefuser struct{ *MemStore }

func (blockRefuser) PutBlock(context.Context, []finality.CaptureRow) error {
	return errors.New("finality_capture_budget_exceeded")
}

func TestABlockTheStoreRefusesAsAUnitStoresNoRowAtAll(t *testing.T) {
	blk, blob := sharedBlobBlock(t)
	st := blockRefuser{NewMemStore()}
	ok, err := newCapturer(&scriptL1{blk: blk}, &scriptBeacon{blobs: [][]byte{blob}}, st, nil).CaptureBlock(context.Background(), 1000)
	if ok || err == nil {
		t.Fatalf("(%v, %v)", ok, err)
	}
	if rowsOf(t, st.MemStore) != 0 || inboxRows(t, st.MemStore) != 0 {
		t.Fatalf("a refused block left rows: %d, inbox %d", rowsOf(t, st.MemStore), inboxRows(t, st.MemStore))
	}
}
