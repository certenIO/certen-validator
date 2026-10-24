// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-F1 / RB12-F3 (live, 2026-10-23). A Base l1_posted build read EVERY captured inbox block into memory (rows, 131 KB blobs, decoded
// frames: measured 1.4 x the store, 2.1 GB at the production table's 1.5 GB) and then searched all of it, for every leg, four at once
// per process. That is what timed out the legs that pre-date the capture (the answer is "not captured", reached only after the
// scan) and what filled the host's memory seven validators at a time.
//
// The world below has the shape of the production table (key names and sizes only): one batch-inbox transaction per captured L1
// block, a 128 KiB blob row per transaction, the SystemConfig proof row and the header, the capture cursor written once per tick.

const (
	rbFirstBlock = 12_000_000
	rbStride     = 5 // a captured block every five L1 blocks, as Base posts
)

type countingStore struct {
	finality.CaptureStore
	bytes atomic.Int64
	gets  atomic.Int64
}

func (c *countingStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	b, ok, err := c.CaptureStore.Get(ctx, k)
	c.bytes.Add(int64(len(b)))
	c.gets.Add(1)
	return b, ok, err
}

// rbStore holds blocks inbox blocks from firstBlock on and, when cursor is set, the capture loop's cursor rows (the first one at
// first+31 and the latest at the last block, as a loop that started 32 blocks behind the head leaves them).
func rbStore(t *testing.T, firstBlock uint64, blocks int, cursor bool) *countingStore {
	t.Helper()
	st := NewMemStore()
	ctx := context.Background()
	for i := 0; i < blocks; i++ {
		var h [32]byte
		binary.BigEndian.PutUint64(h[24:], uint64(i+1))
		k := func(item string) CaptureKey {
			return CaptureKey{Chain: uint64(Chain), L1Block: firstBlock + uint64(i)*rbStride, L1Hash: h, Item: item}
		}
		tx := types.NewTx(&types.BlobTx{ChainID: uint256.NewInt(11155111), Nonce: uint64(i), GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(2), Gas: 21000,
			To: common.Address{1}, BlobFeeCap: uint256.NewInt(1), BlobHashes: []common.Hash{{1}}, V: uint256.NewInt(0), R: uint256.NewInt(1), S: uint256.NewInt(1)})
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var w finality.Writer
		w.Count(1)
		w.U32(0)
		blob := make([]byte, BlobSize)
		rand.Read(blob)
		var bw finality.Writer
		bw.LP(blob)
		bw.Fixed(make([]byte, 48))
		bw.Fixed(make([]byte, 48))
		for item, b := range map[string][]byte{ItemInbox: w.Bytes(), ItemTx(0): raw, ItemBlob(0, 0): bw.Bytes(), ItemHeader: make([]byte, 600), ItemSysCfg: make([]byte, 3000)} {
			if err := st.Put(ctx, k(item), b); err != nil {
				t.Fatal(err)
			}
		}
	}
	if cursor {
		for _, blk := range []uint64{firstBlock + 31, firstBlock + uint64(blocks-1)*rbStride} {
			var v [8]byte
			binary.BigEndian.PutUint64(v[:], blk)
			if err := st.Put(ctx, CaptureKey{Chain: uint64(Chain), L1Block: blk, Item: "runtime/cursor"}, v[:]); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &countingStore{CaptureStore: st}
}

// rbLeg is a pre-Denim Base leg (settlement header) whose L2 block opens with the L1-info deposit naming origin.
func rbLeg(t *testing.T, origin uint64) (*ethproof.Settlement, fixedL2) {
	t.Helper()
	txs := [][]byte{l1InfoDeposit(origin, [32]byte{9})}
	// the header commits to the transactions of the L2 block, as a real one does (the builder checks the provider's answer against it)
	hdr, err := rlp.EncodeToBytes(&types.Header{Number: big.NewInt(48333406), Time: 1792400000, Difficulty: big.NewInt(0), BaseFee: big.NewInt(1), TxHash: ethproof.TrieRoot(txs)})
	if err != nil {
		t.Fatal(err)
	}
	return &ethproof.Settlement{Header: hdr}, fixedL2{txs: txs}
}

func rbBuilder(t *testing.T, st finality.CaptureStore, l2 fixedL2) *Builder {
	t.Helper()
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	return &Builder{Pins: pins, Store: st, L2: l2}
}

var haveIncludedOnly = finality.LevelSet(0).With(finality.LevelIncluded)

// A leg inside the captured range reads the rows after its origin, not the table.
func TestRB12ABuildReadsOnlyTheWindowOfItsLeg(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true) // 300 blocks, ~40 MB of rows
	s, l2 := rbLeg(t, rbFirstBlock+5*290)     // origin: the 290th captured block, ten blocks from the end
	_, pend, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("a leg whose channel is not captured yet is pending, got pend=%v err=%v", pend, err)
	}
	if got := st.bytes.Load(); got > 4<<20 {
		t.Fatalf("the build read %d bytes of a 40 MB table for a leg whose window holds ten blocks (about 1.4 MB)", got)
	}
	if pend.Judged["last_scanned_l1"] != uint64(rbFirstBlock+5*299) {
		t.Fatalf("the pending names how far the capture got: %v", pend.Judged)
	}
}

// A leg whose frames can only lie below the first block this validator capture scanned is decided from the cursor, without reading a row.
func TestRB12ALegPostedBeforeTheCaptureStartedIsDecidedWithoutReadingTheStore(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	s, l2 := rbLeg(t, rbFirstBlock-20_000) // origin 20,000 blocks before the capture; its window ends 16,400 blocks before it
	_, pend, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	se, named := finality.AsNamed(err)
	if pend != nil || !named || se.Code != "l1_capture_not_covering" {
		t.Fatalf("want the named unavailable state l1_capture_not_covering, got pend=%v err=%v", pend, err)
	}
	for _, f := range []string{"chain", "kind", "epoch_l1_block", "window_end_l1_block", "capture_first_l1_block", "capture_slack", "archive_provider"} {
		if _, ok := se.Fields[f]; !ok {
			t.Errorf("the state carries what it was judged at: missing %s in %v", f, se)
		}
	}
	if se.Fields["epoch_l1_block"] != uint64(rbFirstBlock-20_000) || se.Fields["capture_first_l1_block"] != uint64(rbFirstBlock+31) || se.Fields["archive_provider"] != "unset" {
		t.Errorf("%v", se)
	}
	if st.gets.Load() != 0 {
		t.Fatalf("the decision needs the cursor and no row: %d rows were read", st.gets.Load())
	}
}

// A window that starts below the capture and ends inside it, with no channel in the covered part, is not "not posted yet": the frames may lie in the part that was never scanned.
func TestRB12ALegWhoseWindowStraddlesTheCaptureStartIsNotPendingForever(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	s, l2 := rbLeg(t, rbFirstBlock-100)
	_, pend, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if se, named := finality.AsNamed(err); pend != nil || !named || se.Code != "l1_capture_not_covering" {
		t.Fatalf("want l1_capture_not_covering, got pend=%v err=%v", pend, err)
	}
}

// A store with no cursor row (a recorder store) says nothing about what it covers: the leg is searched in its window and the pending stands.
func TestRB12AStoreWithoutACursorIsSearchedInTheLegsWindow(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, false)
	s, l2 := rbLeg(t, rbFirstBlock-20_000)
	_, pend, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("pend=%v err=%v", pend, err)
	}
	if st.gets.Load() != 0 {
		t.Fatalf("no captured block lies in the window of a leg 20,000 blocks older than the table: %d rows were read", st.gets.Load())
	}
}

// The heap a build holds does not grow with the table: 4 times the rows, the same peak (it grew by 1.4 x the extra rows before).
func TestRB12PeakHeapOfABuildDoesNotGrowWithTheCaptureStore(t *testing.T) {
	peakOf := func(blocks int) uint64 {
		st := rbStore(t, rbFirstBlock, blocks, true)
		s, l2 := rbLeg(t, rbFirstBlock+rbStride*uint64(blocks-10))
		b := rbBuilder(t, st, l2)
		runtime.GC()
		var m0 runtime.MemStats
		runtime.ReadMemStats(&m0)
		var peak atomic.Uint64
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for {
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
				select {
				case <-stop:
					return
				case <-time.After(time.Millisecond):
				}
			}
		}()
		if _, pend, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted); err != nil || pend == nil {
			t.Fatalf("pend=%v err=%v", pend, err)
		}
		close(stop)
		<-done
		if p := peak.Load(); p > m0.HeapAlloc {
			return p - m0.HeapAlloc
		}
		return 0
	}
	small, large := peakOf(100), peakOf(400) // ~13 MB and ~54 MB of rows
	t.Logf("peak heap above the store: %d KiB for 100 blocks, %d KiB for 400 blocks", small>>10, large>>10)
	if large > small+15<<20 {
		t.Fatalf("the peak heap of a build grew from %d to %d bytes with a 4 times larger table: it still holds the table", small, large)
	}
}
