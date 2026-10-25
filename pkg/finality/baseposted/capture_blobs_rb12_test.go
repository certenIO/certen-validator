// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
)

// RB12 OPS-A2 item 1 (ledger CG-1): a slot holds up to six blobs and a commitment costs milliseconds; the capture committed every blob of the
// slot for every transaction. It commits the blobs the kept transactions name, at their sidecar positions, and still accepts a blob only
// when the commitment of its bytes hashes to the versioned hash the transaction names.

func decoyBlob(i int) []byte {
	b := make([]byte, BlobSize)
	b[1] = byte(i + 1) // the first byte of each 32-byte word is 0, so every word is a canonical field element
	return b
}

func commitsOf(t *testing.T, slot func(needed []byte) [][]byte) (commits int, ok bool, err error, recorded []*finality.StateError, store *MemStore, blk L1BlockData) {
	t.Helper()
	kz, lerr := kzgsetup.Load(pinnedSetup)
	if lerr != nil {
		t.Fatal(lerr)
	}
	blk, needed := blobBlock(t, kz, 1000, []byte("frame data"))
	store = NewMemStore()
	c := &Capturer{Chain: 84532, Pins: newPins(), L1: &fakeL1{blk: blk}, Beacon: fakeBeacon{blobs: slot(needed)}, Store: store, GenesisTime: 1655733600, SlotSeconds: 12,
		Record: func(_ uint64, s *finality.StateError) { recorded = append(recorded, s) }}
	kzgCommitHook = func() { commits++ }
	defer func() { kzgCommitHook = nil }()
	ok, err = c.CaptureBlock(context.Background(), 1000)
	return
}

func TestCaptureCommitsOnlyTheBlobsTheKeptTransactionsNameAtTheirPositions(t *testing.T) {
	for _, decoys := range []int{0, 1, 5} { // N blobs needed: the commitments are N whatever else the slot holds
		t.Run(fmt.Sprintf("%d decoys", decoys), func(t *testing.T) {
			commits, ok, err, _, store, blk := commitsOf(t, func(needed []byte) [][]byte {
				s := [][]byte{needed}
				for i := 0; i < decoys; i++ {
					s = append(s, decoyBlob(i))
				}
				return s
			})
			if err != nil || !ok {
				t.Fatalf("capture: %v %v", ok, err)
			}
			if commits != 1 {
				t.Fatalf("%d commitments for 1 needed blob among %d", commits, 1+decoys)
			}
			if _, has, _ := store.Get(context.Background(), CaptureKey{Chain: 84532, L1Block: 1000, L1Hash: blk.Hash, Item: ItemBlob(1, 0)}); !has {
				t.Fatal("the blob row was not stored")
			}
		})
	}
}

func TestCaptureReadsABeaconThatServesAnotherOrderBySweepingTheSlot(t *testing.T) {
	commits, ok, err, _, store, blk := commitsOf(t, func(needed []byte) [][]byte {
		return [][]byte{decoyBlob(0), decoyBlob(1), decoyBlob(2), needed, decoyBlob(3)}
	})
	if err != nil || !ok {
		t.Fatalf("a beacon that lists the needed blob elsewhere must still be read: %v %v", ok, err)
	}
	if commits < 2 || commits > 6 {
		t.Fatalf("%d commitments: one at the sidecar position, then the sweep of a slot of five", commits)
	}
	if _, has, _ := store.Get(context.Background(), CaptureKey{Chain: 84532, L1Block: 1000, L1Hash: blk.Hash, Item: ItemBlob(1, 0)}); !has {
		t.Fatal("the blob row was not stored")
	}
}

func TestCaptureNamesAMissingBlobAndStoresNothingWhateverTheSlotHolds(t *testing.T) {
	_, ok, err, recorded, store, blk := commitsOf(t, func([]byte) [][]byte { return [][]byte{decoyBlob(0), decoyBlob(1)} })
	if err == nil || ok {
		t.Fatalf("a slot without the needed blob must fail: %v %v", ok, err)
	}
	if len(recorded) != 1 || recorded[0].Code != "l1_blob_unavailable" {
		t.Fatalf("recorded %v", recorded)
	}
	if _, has, _ := store.Get(context.Background(), CaptureKey{Chain: 84532, L1Block: 1000, L1Hash: blk.Hash, Item: ItemHeader}); has {
		t.Fatal("a block with a missing blob was stored")
	}
}
