// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
)

var (
	sharedOnce sync.Once
	sharedBlk  L1BlockData
	sharedBlob []byte
)

// sharedBlobBlock is the synthetic L1 block of the capture tests (one blob transaction to the inbox at index 1), built once.
func sharedBlobBlock(t *testing.T) (L1BlockData, []byte) {
	t.Helper()
	sharedOnce.Do(func() {
		kz, err := kzgsetup.Load(pinnedSetup)
		if err != nil {
			t.Fatal(err)
		}
		sharedBlk, sharedBlob = blobBlock(t, kz, 1000, []byte("frame data"))
	})
	return sharedBlk, sharedBlob
}

// scriptL1 is a parent-chain source with scripted failures.
type scriptL1 struct {
	blk      L1BlockData
	blockErr map[uint64]error
	failProf int // the n-th Proof call fails (1-based); 0: none
	noImpl   bool
	zeroImpl bool
	proofs   int
}

func (f *scriptL1) Head(context.Context) (uint64, error) { return f.blk.Number, nil }
func (f *scriptL1) Block(_ context.Context, n uint64) (L1BlockData, error) {
	if err := f.blockErr[n]; err != nil {
		return L1BlockData{}, err
	}
	if n != f.blk.Number {
		return L1BlockData{Number: n}, nil
	}
	return f.blk, nil
}
func (f *scriptL1) Proof(_ context.Context, addr [20]byte, slots [][32]byte, block uint64) (StateProof, error) {
	f.proofs++
	if f.proofs == f.failProf {
		return StateProof{}, errors.New("historical state is not available")
	}
	sp := StateProof{Nodes: [][]byte{[]byte("node-" + common.Bytes2Hex(addr[:2]))}, Values: map[[32]byte][32]byte{}}
	if len(slots) > 0 && !f.noImpl {
		var v [32]byte
		if !f.zeroImpl {
			copy(v[12:], testImpl[:])
		}
		sp.Values[eip1967ImplSlot] = v
	}
	return sp, nil
}

type scriptBeacon struct {
	err   error
	blobs [][]byte
	slots []uint64
}

func (b *scriptBeacon) Blobs(_ context.Context, slot uint64) ([][]byte, error) {
	b.slots = append(b.slots, slot)
	return b.blobs, b.err
}

// failStore refuses the Put of one item.
type failStore struct {
	*MemStore
	item string
}

func (f failStore) Put(ctx context.Context, k CaptureKey, data []byte) error {
	if k.Item == f.item {
		return errors.New("store down")
	}
	return f.MemStore.Put(ctx, k, data)
}

func newCapturer(l1 L1Source, bc BeaconSource, st CaptureStore, rec func(uint64, *finality.StateError)) *Capturer {
	return &Capturer{Chain: 84532, Pins: newPins(), L1: l1, Beacon: bc, Store: st, GenesisTime: 1655733600, SlotSeconds: 12, Record: rec}
}

func rowsOf(t *testing.T, st *MemStore) int {
	t.Helper()
	n := 0
	for _, item := range []string{ItemHeader, ItemInbox, ItemSysCfg, ItemTx(1), ItemTxNodes(1), ItemBlob(1, 0)} {
		ks, err := st.Blocks(context.Background(), 84532, item)
		if err != nil {
			t.Fatal(err)
		}
		n += len(ks)
	}
	return n
}

func TestCapturerFailsWithFalseAndAnErrorOnEveryStageAndNamesWhatIsUnavailable(t *testing.T) {
	blk, blob := sharedBlobBlock(t)
	ctx := context.Background()
	good := func() *scriptBeacon { return &scriptBeacon{blobs: [][]byte{blob}} }
	var recorded []*finality.StateError
	rec := func(_ uint64, s *finality.StateError) { recorded = append(recorded, s) }

	// the plain success: every row is there and the beacon was asked for the slot of the block time
	st := NewMemStore()
	bc := good()
	ok, err := newCapturer(&scriptL1{blk: blk}, bc, st, rec).CaptureBlock(ctx, 1000)
	if !ok || err != nil || rowsOf(t, st) != 6 || len(bc.slots) != 1 || bc.slots[0] != 5000 || len(recorded) != 0 {
		t.Fatalf("%v %v rows %d slots %v recorded %v", ok, err, rowsOf(t, st), bc.slots, recorded)
	}
	// a blob that is the wrong size and a blob nobody asked for are skipped; the asked one is found
	extra := make([]byte, BlobSize)
	extra[100] = 7
	st = NewMemStore()
	bc = &scriptBeacon{blobs: [][]byte{{1, 2, 3}, extra, blob}}
	if ok, err = newCapturer(&scriptL1{blk: blk}, bc, st, rec).CaptureBlock(ctx, 1000); !ok || err != nil || rowsOf(t, st) != 6 {
		t.Fatalf("%v %v", ok, err)
	}
	// a block whose inbox transaction carries no blob never asks the beacon and stores no blob row
	cd := blk
	cd.TxBlobHash = [][][32]byte{nil, nil}
	st = NewMemStore()
	bc = good()
	if ok, err = newCapturer(&scriptL1{blk: cd}, bc, st, rec).CaptureBlock(ctx, 1000); !ok || err != nil || len(bc.slots) != 0 || rowsOf(t, st) != 5 {
		t.Fatalf("calldata block: %v %v slots %v rows %d", ok, err, bc.slots, rowsOf(t, st))
	}

	// every failure is (false, error) and stores nothing
	badHash := blk
	badHash.Hash[0] ^= 1
	badHdr := blk
	badHdr.HeaderRLP = []byte{1, 2, 3}
	cases := []struct {
		name string
		c    func() *Capturer
		want string // a part of the error text
		rec  string // the recorded state code, or ""
	}{
		{"block unreadable", func() *Capturer {
			return newCapturer(&scriptL1{blk: blk, blockErr: map[uint64]error{1000: errors.New("rpc down")}}, good(), NewMemStore(), rec)
		}, "rpc down", ""},
		{"header not RLP", func() *Capturer { return newCapturer(&scriptL1{blk: badHdr}, good(), NewMemStore(), rec) }, "header", ""},
		{"header does not hash to the block", func() *Capturer { return newCapturer(&scriptL1{blk: badHash}, good(), NewMemStore(), rec) }, "does not hash", ""},
		{"first proof fails", func() *Capturer { return newCapturer(&scriptL1{blk: blk, failProf: 1}, good(), NewMemStore(), rec) }, "batcher_state_unavailable", "batcher_state_unavailable"},
		{"implementation proof fails", func() *Capturer { return newCapturer(&scriptL1{blk: blk, failProf: 2}, good(), NewMemStore(), rec) }, "batcher_state_unavailable", "batcher_state_unavailable"},
		{"no EIP-1967 implementation reported", func() *Capturer { return newCapturer(&scriptL1{blk: blk, noImpl: true}, good(), NewMemStore(), rec) }, "does not carry the EIP-1967", ""},
		{"zero implementation reported", func() *Capturer { return newCapturer(&scriptL1{blk: blk, zeroImpl: true}, good(), NewMemStore(), rec) }, "does not carry the EIP-1967", ""},
		{"beacon down", func() *Capturer {
			return newCapturer(&scriptL1{blk: blk}, &scriptBeacon{err: errors.New("beacon down")}, NewMemStore(), rec)
		}, "l1_blob_unavailable", "l1_blob_unavailable"},
		{"blob not served", func() *Capturer {
			return newCapturer(&scriptL1{blk: blk}, &scriptBeacon{blobs: [][]byte{extra}}, NewMemStore(), rec)
		}, "l1_blob_unavailable", "l1_blob_unavailable"},
		{"kzg setup pin wrong", func() *Capturer {
			c := newCapturer(&scriptL1{blk: blk}, good(), NewMemStore(), rec)
			p := *c.Pins
			p.KZGSetupSHA256 = strings.Repeat("00", 32)
			c.Pins = &p
			return c
		}, "", ""},
	}
	for _, c := range cases {
		recorded = nil
		cp := c.c()
		ok, err := cp.CaptureBlock(ctx, 1000)
		if ok || err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: (%v, %v), want (false, ...%s...)", c.name, ok, err, c.want)
		}
		if m, isMem := cp.Store.(*MemStore); isMem && rowsOf(t, m) != 0 {
			t.Errorf("%s: a failed capture stored %d rows", c.name, rowsOf(t, m))
		}
		switch {
		case c.rec == "" && len(recorded) != 0:
			t.Errorf("%s: recorded %v", c.name, recorded)
		case c.rec != "" && (len(recorded) != 1 || recorded[0].Code != c.rec):
			t.Errorf("%s: recorded %v", c.name, recorded)
		}
		// the same failure without a Record callback is still an error, never a panic
		cp = c.c()
		cp.Record = nil
		if ok, err := cp.CaptureBlock(ctx, 1000); ok || err == nil {
			t.Errorf("%s without Record: (%v, %v)", c.name, ok, err)
		}
	}
	// the unavailable states carry the block, the versioned hashes and the slot they were judged at
	recorded = nil
	_, _ = newCapturer(&scriptL1{blk: blk}, &scriptBeacon{err: errors.New("beacon down")}, NewMemStore(), rec).CaptureBlock(ctx, 1000)
	if len(recorded) != 1 || fmt.Sprint(recorded[0].Fields["l1_block"]) != "1000" || fmt.Sprint(recorded[0].Fields["beacon_slot"]) != "5000" || fmt.Sprint(recorded[0].Fields["http_status"]) != "0" {
		t.Fatalf("%+v", recorded)
	}
	recorded = nil
	_, _ = newCapturer(&scriptL1{blk: blk}, &scriptBeacon{blobs: [][]byte{extra}}, NewMemStore(), rec).CaptureBlock(ctx, 1000)
	if len(recorded) != 1 || fmt.Sprint(recorded[0].Fields["http_status"]) != "200" {
		t.Fatalf("%+v", recorded)
	}
	// a store that refuses any one row fails the capture
	for _, item := range []string{ItemHeader, ItemInbox, ItemTx(1), ItemTxNodes(1), ItemBlob(1, 0), ItemSysCfg} {
		fs := failStore{MemStore: NewMemStore(), item: item}
		if ok, err := newCapturer(&scriptL1{blk: blk}, good(), fs, rec).CaptureBlock(ctx, 1000); ok || err == nil {
			t.Errorf("a store that refuses %s: (%v, %v)", item, ok, err)
		}
	}
}

func TestCapturerRangeCapturesTheBlocksWithInboxTransactionsAndKeepsScanningPastAFailure(t *testing.T) {
	blk, blob := sharedBlobBlock(t)
	l1 := &scriptL1{blk: blk, blockErr: map[uint64]error{1001: errors.New("rpc down")}}
	c := newCapturer(l1, &scriptBeacon{blobs: [][]byte{blob}}, NewMemStore(), nil)
	got, errs := c.CaptureRange(context.Background(), 999, 1002)
	if len(got) != 1 || got[0] != 1000 || len(errs) != 1 || errs[1001] == nil {
		t.Fatalf("%v %v", got, errs)
	}
	// both ends are included
	c = newCapturer(&scriptL1{blk: blk}, &scriptBeacon{blobs: [][]byte{blob}}, NewMemStore(), nil)
	if got, errs = c.CaptureRange(context.Background(), 1000, 1000); len(got) != 1 || got[0] != 1000 || len(errs) != 0 {
		t.Fatalf("%v %v", got, errs)
	}
	if got, errs = c.CaptureRange(context.Background(), 1001, 1000); len(got) != 0 || len(errs) != 0 {
		t.Fatalf("an empty range: %v %v", got, errs)
	}
}

func TestMemStoreListsOnlyTheChainAndItemAscendingByBlockThenHashAndCopiesWhatItHolds(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	h := func(b byte) [32]byte { return [32]byte{b} }
	put := func(chain, block uint64, hash byte, item string) {
		t.Helper()
		if err := st.Put(ctx, CaptureKey{Chain: chain, L1Block: block, L1Hash: h(hash), Item: item}, []byte{byte(block), hash}); err != nil {
			t.Fatal(err)
		}
	}
	put(84532, 20, 5, "inbox")
	put(84532, 10, 9, "inbox")
	put(84532, 10, 3, "inbox")
	put(84532, 20, 2, "inbox")
	put(84532, 15, 1, "hdr") // another item
	put(1, 12, 1, "inbox")   // another chain
	ks, err := st.Blocks(ctx, 84532, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]uint64{{10, 3}, {10, 9}, {20, 2}, {20, 5}}
	if len(ks) != len(want) {
		t.Fatalf("%v", ks)
	}
	for i, k := range ks {
		if k.L1Block != want[i][0] || k.L1Hash != h(byte(want[i][1])) || k.Chain != 84532 || k.Item != "inbox" {
			t.Fatalf("%d: %+v", i, k)
		}
	}
	// the stored bytes are a copy of what was put and Get returns a copy
	data := []byte{1, 2, 3}
	k := CaptureKey{Chain: 7, L1Block: 1, Item: "x"}
	if err := st.Put(ctx, k, data); err != nil {
		t.Fatal(err)
	}
	data[0] = 9
	got, ok, _ := st.Get(ctx, k)
	if !ok || got[0] != 1 {
		t.Fatalf("%v %v", got, ok)
	}
	got[1] = 9
	again, _, _ := st.Get(ctx, k)
	if again[1] != 2 {
		t.Fatalf("Get returned the stored slice: %v", again)
	}
	if _, ok, _ := st.Get(ctx, CaptureKey{Chain: 7, L1Block: 2, Item: "x"}); ok {
		t.Fatal("an absent row")
	}
}

func TestImplFromProofReadsTheLow20BytesOfTheReportedWordAndRefusesAnAbsentOrZeroOne(t *testing.T) {
	var v [32]byte
	for i := range v {
		v[i] = 0xff
	}
	copy(v[12:], testImpl[:])
	got, ok := implFromProof(StateProof{Values: map[[32]byte][32]byte{eip1967ImplSlot: v}})
	if !ok || got != [20]byte(testImpl) {
		t.Fatalf("%x %v", got, ok)
	}
	if _, ok := implFromProof(StateProof{Values: map[[32]byte][32]byte{eip1967ImplSlot: {}}}); ok {
		t.Fatal("a zero implementation is refused")
	}
	if _, ok := implFromProof(StateProof{Values: map[[32]byte][32]byte{}}); ok {
		t.Fatal("an absent value is refused")
	}
	if a, ok := implFromProof(StateProof{}); ok || a != [20]byte{} {
		t.Fatal("no values")
	}
}
