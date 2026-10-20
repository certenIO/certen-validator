// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

func TestFrameBlockRangeDepositsAndFrameOrderAreTheBuildersPureSteps(t *testing.T) {
	tx := func(blk uint64) capturedTx { return capturedTx{key: CaptureKey{L1Block: blk}} }
	for _, c := range []struct {
		name     string
		txs      []capturedTx
		bt       Batch
		min, max uint64
	}{
		{"one frame transaction", []capturedTx{tx(50)}, Batch{}, 50, 50},
		{"a single frame transaction with a low span origin", []capturedTx{tx(50)}, Batch{Type: 1, EpochNum: 40}, 40, 50},
		{"ascending", []capturedTx{tx(50), tx(60), tx(70)}, Batch{}, 50, 70},
		{"descending", []capturedTx{tx(70), tx(60), tx(50)}, Batch{}, 50, 70},
		{"the extremes in the middle", []capturedTx{tx(60), tx(50), tx(70), tx(65)}, Batch{}, 50, 70},
		{"a singular batch's epoch is not read", []capturedTx{tx(50), tx(60)}, Batch{Type: 0, EpochNum: 10}, 50, 60},
		{"a batch of another type is not read", []capturedTx{tx(50), tx(60)}, Batch{Type: 2, EpochNum: 10}, 50, 60},
		{"a span origin above the lowest frame block is not read", []capturedTx{tx(50), tx(60)}, Batch{Type: 1, EpochNum: 55}, 50, 60},
		{"a span origin equal to the lowest frame block", []capturedTx{tx(50), tx(60)}, Batch{Type: 1, EpochNum: 50}, 50, 60},
		{"a span origin below the lowest frame block", []capturedTx{tx(50), tx(60)}, Batch{Type: 1, EpochNum: 49}, 49, 60},
		{"the same block twice", []capturedTx{tx(50), tx(50)}, Batch{}, 50, 50},
	} {
		bt := c.bt
		min, max := frameBlockRange(c.txs, &bt)
		if min != c.min || max != c.max {
			t.Errorf("%s: (%d, %d), want (%d, %d)", c.name, min, max, c.min, c.max)
		}
	}
	dep := func(b byte) []byte { return []byte{0x7e, b} }
	user := []byte{0x02, 0xc0}
	for _, c := range []struct {
		name string
		txs  [][]byte
		want int
	}{
		{"none", nil, 0},
		{"a user transaction first", [][]byte{user, dep(1)}, 0},
		{"an empty first transaction", [][]byte{{}, dep(1)}, 0},
		{"a deposit of one byte", [][]byte{{0x7e}, user}, 1},
		{"two deposits and a user transaction", [][]byte{dep(1), dep(2), user}, 2},
		{"a deposit after a user transaction is not leading", [][]byte{dep(1), user, dep(2)}, 1},
		{"all deposits", [][]byte{dep(1), dep(2), dep(3)}, 3},
	} {
		got := leadingDeposits(c.txs)
		if len(got) != c.want {
			t.Errorf("%s: %d deposits, want %d", c.name, len(got), c.want)
			continue
		}
		for i := range got {
			if !bytes.Equal(got[i], c.txs[i]) {
				t.Errorf("%s: deposit %d", c.name, i)
			}
		}
	}
	fr := []FrameTx{{L1Block: 7, TxIndex: 2}, {L1Block: 5, TxIndex: 9}, {L1Block: 7, TxIndex: 0}, {L1Block: 5, TxIndex: 1}, {L1Block: 6, TxIndex: 4}, {L1Block: 7, TxIndex: 1}}
	sortFrames(fr)
	want := [][2]uint64{{5, 1}, {5, 9}, {6, 4}, {7, 0}, {7, 1}, {7, 2}}
	for i, w := range want {
		if fr[i].L1Block != w[0] || uint64(fr[i].TxIndex) != w[1] {
			t.Fatalf("%v", fr)
		}
	}
	// frames equal in block and index keep their order (stable)
	st := []FrameTx{{L1Block: 3, TxIndex: 1, TxRaw: []byte{1}}, {L1Block: 3, TxIndex: 1, TxRaw: []byte{2}}}
	sortFrames(st)
	if st[0].TxRaw[0] != 1 || st[1].TxRaw[0] != 2 {
		t.Fatalf("%v", st)
	}
}

func TestTheBuilderPassesTheCoveredBoundaryAndRefusesWhatItCannotReadOrTrust(t *testing.T) {
	w := newBuildWorld(t, "evidence/valid_a.bin", "legs/a.json")
	delta := w.top - 11954001
	// every header reports a number lowered by delta: the finalized head is then exactly the frame block, which is covered (not
	// pending); the captured block is not the head's chain at that number, which the builder names
	shift := &mapHeaders{by: w.hdrs.by, fail: w.hdrs.fail, numbers: map[[32]byte]uint64{}}
	for h, r := range w.hdrs.by {
		shift.numbers[h] = r.number - delta
	}
	b := w.builder()
	b.Headers = shift
	_, p, err := w.build(t, b)
	if p != nil {
		t.Fatalf("a head at the frame block is covered: %+v", p)
	}
	wantCode(t, err, "l1_proof_window_unavailable", map[string]string{"l1_block": "11954001"})

	settle := func(b *Builder, hdr []byte) error {
		_, _, err := b.Build(context.Background(), &ethproof.Settlement{Header: hdr}, 0, finality.LevelL1Posted)
		return err
	}
	// pins without the base section, without the Sepolia section, and a leg header that is no header
	b = w.builder()
	b.Pins = &finality.Pins{}
	wantCode(t, settle(b, w.ref.HeaderRLP), finality.CodePinUnknown, map[string]string{"kind": "base_sepolia"})
	var m map[string]any
	pinsRaw, _ := readPublishedPins(setDir, "pins/main.json")
	_ = json.Unmarshal(pinsRaw, &m)
	delete(m, "eth_sepolia")
	nb, _ := json.MarshalIndent(m, "", "  ")
	noEth, err := finality.ParsePinsOverride(append(nb, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	b = w.builder()
	b.Pins = noEth
	wantCode(t, settle(b, w.ref.HeaderRLP), finality.CodePinUnknown, map[string]string{"kind": "eth_sepolia"})
	wantCode(t, settle(w.builder(), []byte{1, 2, 3}), finality.CodeEvidenceMalformed, map[string]string{"part": "header"})

	// rows the builder reads while it assembles the body
	rowErr := func(match func(k CaptureKey) bool, data []byte, ok bool, err error) *Builder {
		bb := w.builder()
		bb.Store = hookStore{MemStore: w.store, get: func(k CaptureKey) ([]byte, bool, error, bool) { return data, ok, err, match(k) }}
		return bb
	}
	isNodes := func(k CaptureKey) bool { return strings.HasPrefix(k.Item, "txnodes/") }
	isSys := func(k CaptureKey) bool { return k.Item == ItemSysCfg }
	wantCode(t, settle(rowErr(isNodes, []byte{0, 0, 0, 9}, true, nil), w.ref.HeaderRLP), finality.CodeEvidenceMalformed, nil)
	if err := settle(rowErr(isNodes, nil, true, errors.New("db down")), w.ref.HeaderRLP); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("txnodes row unreadable: %v", err)
	}
	if err := settle(rowErr(isNodes, nil, false, nil), w.ref.HeaderRLP); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("txnodes row gone: %v", err)
	}
	wantCode(t, settle(rowErr(isSys, nil, false, nil), w.ref.HeaderRLP), "batcher_state_unavailable", map[string]string{"l1_block": "11954001"})
	wantCode(t, settle(rowErr(isSys, nil, true, errors.New("db down")), w.ref.HeaderRLP), "batcher_state_unavailable", map[string]string{"l1_block": "11954001"})
	wantCode(t, settle(rowErr(isSys, []byte{0, 0, 0, 9}, true, nil), w.ref.HeaderRLP), finality.CodeEvidenceMalformed, nil)
}

// frameStream is a channel of one singular batch at timestamp ts as the frames' data: zlib of the RLP string of the batch.
func frameStream(ts uint64) []byte {
	enc := rlpOf(singularRLP{ParentHash: [32]byte{1}, EpochNum: 5, EpochHash: [32]byte{2}, Timestamp: ts})
	return compress("zlib", rlpOf(append([]byte{0}, enc...)))
}

func TestTheBuilderListsChannelsFrameByFrameWhenOneTransactionCarriesSeveralAndSkipsGapsAndOpenChannels(t *testing.T) {
	idX, idY := [16]byte{0xaa}, [16]byte{0xbb}
	data := func(frames ...Frame) []byte {
		out := []byte{0}
		for _, f := range frames {
			out = append(out, MarshalFrame(f)...)
		}
		return out
	}
	list := func(name string, txData []byte) []ChannelInfo {
		t.Helper()
		s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, txData: txData, channelLabel: name})
		st := NewMemStore()
		putSynth(t, st, s)
		chs, err := (&Builder{Pins: pinsOf(t), Store: st}).Channels(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return chs
	}
	// one transaction, two complete channels
	both := list("both", data(Frame{ID: idX, Number: 0, Data: frameStream(1790000000), IsLast: true}, Frame{ID: idY, Number: 0, Data: frameStream(1790000100), IsLast: true}))
	if len(both) != 2 || both[0].ID != idX || both[1].ID != idY || len(both[0].Timestamps) != 1 || both[0].Timestamps[0] != 1790000000 || both[1].Timestamps[0] != 1790000100 {
		t.Fatalf("%+v", both)
	}
	// a channel split over two frames of the same transaction, and interleaved with another channel's frame
	s1 := frameStream(1790000200)
	half := len(s1) / 2
	mixed := list("mixed", data(Frame{ID: idX, Number: 0, Data: s1[:half]}, Frame{ID: idY, Number: 0, Data: frameStream(1790000300), IsLast: true}, Frame{ID: idX, Number: 1, Data: s1[half:], IsLast: true}))
	if len(mixed) != 2 || mixed[0].ID != idX || mixed[0].Timestamps[0] != 1790000200 || mixed[1].ID != idY || mixed[1].Timestamps[0] != 1790000300 {
		t.Fatalf("%+v", mixed)
	}
	// a gap in the numbers, a channel without its closing frame, and a frame numbered from 1
	if got := list("gap", data(Frame{ID: idX, Number: 0, Data: s1[:half]}, Frame{ID: idX, Number: 2, Data: s1[half:], IsLast: true})); len(got) != 0 {
		t.Fatalf("a gap: %+v", got)
	}
	if got := list("open", data(Frame{ID: idX, Number: 0, Data: s1})); len(got) != 0 {
		t.Fatalf("no closing frame: %+v", got)
	}
	if got := list("late", data(Frame{ID: idX, Number: 1, Data: s1, IsLast: true})); len(got) != 0 {
		t.Fatalf("numbered from 1: %+v", got)
	}
	// the same refusals for the channel of a timestamp
	for name, d := range map[string][]byte{
		"gap":              data(Frame{ID: idX, Number: 0, Data: s1[:half]}, Frame{ID: idX, Number: 2, Data: s1[half:], IsLast: true}),
		"open":             data(Frame{ID: idX, Number: 0, Data: s1}),
		"late":             data(Frame{ID: idX, Number: 1, Data: s1, IsLast: true}),
		"last frame first": data(Frame{ID: idX, Number: 0, Data: s1[:half], IsLast: true}, Frame{ID: idX, Number: 1, Data: s1[half:], IsLast: true}),
		// the frames before the stray one already hold a whole channel: only completeness keeps it out
		"whole then stray": data(Frame{ID: idX, Number: 0, Data: s1}, Frame{ID: idX, Number: 5, Data: []byte{9}, IsLast: true}),
		"whole then open":  data(Frame{ID: idX, Number: 0, Data: s1}, Frame{ID: idX, Number: 1, Data: nil}),
	} {
		s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, txData: d, channelLabel: "x" + name})
		st := NewMemStore()
		putSynth(t, st, s)
		txs, err := (&Builder{Store: st}).load(context.Background(), newPins())
		if err != nil {
			t.Fatal(err)
		}
		if ref, _, _, _ := findChannel(txs, newPins(), 1790000200); ref != nil {
			t.Errorf("%s: an incomplete channel was found", name)
		}
	}
	// and a complete one is found through the same function
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, txData: data(Frame{ID: idX, Number: 0, Data: s1[:half]}, Frame{ID: idX, Number: 1, Data: s1[half:], IsLast: true}), channelLabel: "ok"})
	st := NewMemStore()
	putSynth(t, st, s)
	txs, _ := (&Builder{Store: st}).load(context.Background(), newPins())
	if ref, _, bt, _ := findChannel(txs, newPins(), 1790000200); ref == nil || ref.ID != idX || bt.Timestamp != 1790000200 {
		t.Fatal("a complete channel of two frames in one transaction")
	}
	// the store's own failures reach the caller
	_, err := (&Builder{Pins: pinsOf(t), Store: hookStore{MemStore: NewMemStore(), blocksErr: errors.New("db down")}}).Channels(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("%v", err)
	}
}

func TestMemStoreOrdersManyRowsOfOneBlockByHash(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	for i := 60; i >= 1; i-- { // hashes inserted in descending order
		k := CaptureKey{Chain: 1, L1Block: 10, L1Hash: [32]byte{byte(i)}, Item: "x"}
		if err := st.Put(ctx, k, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 5; i >= 1; i-- {
		if err := st.Put(ctx, CaptureKey{Chain: 1, L1Block: uint64(i), L1Hash: [32]byte{9}, Item: "x"}, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	ks, _ := st.Blocks(ctx, 1, "x")
	if len(ks) != 65 {
		t.Fatalf("%d", len(ks))
	}
	for i := 1; i < len(ks); i++ {
		a, b := ks[i-1], ks[i]
		if a.L1Block > b.L1Block || (a.L1Block == b.L1Block && bytes.Compare(a.L1Hash[:], b.L1Hash[:]) >= 0) {
			t.Fatalf("row %d: %d/%x before %d/%x", i, a.L1Block, a.L1Hash[:1], b.L1Block, b.L1Hash[:1])
		}
	}
}

func TestCapturerRefusesAHeaderThatIsNoHeaderABlobTheKZGLibraryRefusesAndATransactionSetThatIsNotTheBlocks(t *testing.T) {
	blk, blob := sharedBlobBlock(t)
	ctx := context.Background()
	var recorded []*finality.StateError
	rec := func(_ uint64, s *finality.StateError) { recorded = append(recorded, s) }
	empty := func(st *MemStore) int { n, _ := st.Blocks(ctx, 84532, ItemHeader); return len(n) }

	// a header that is not RLP is the framework's named refusal, not the hash mismatch
	badHdr := blk
	badHdr.HeaderRLP = []byte{1, 2, 3}
	st := NewMemStore()
	ok, err := newCapturer(&scriptL1{blk: badHdr}, &scriptBeacon{blobs: [][]byte{blob}}, st, rec).CaptureBlock(ctx, 1000)
	se, named := finality.AsNamed(err)
	if ok || !named || se.Code != finality.CodeEvidenceMalformed || empty(st) != 0 {
		t.Fatalf("%v %v", ok, err)
	}

	// a blob with a field element above the modulus cannot be committed to: the capture fails on that, not on a missing blob
	noncanonical := bytes.Repeat([]byte{0xff}, BlobSize)
	st = NewMemStore()
	recorded = nil
	ok, err = newCapturer(&scriptL1{blk: blk}, &scriptBeacon{blobs: [][]byte{noncanonical, blob}}, st, rec).CaptureBlock(ctx, 1000)
	if ok || err == nil || strings.Contains(err.Error(), "l1_blob_unavailable") || len(recorded) != 0 || empty(st) != 0 {
		t.Fatalf("%v %v %v", ok, err, recorded)
	}

	// transactions that do not make the header's transaction root cannot be proven
	other := blk
	other.TxRaw = [][]byte{userTx(99), blk.TxRaw[1]}
	st = NewMemStore()
	ok, err = newCapturer(&scriptL1{blk: other}, &scriptBeacon{blobs: [][]byte{blob}}, st, rec).CaptureBlock(ctx, 1000)
	if ok || err == nil || empty(st) != 0 {
		t.Fatalf("%v %v", ok, err)
	}
	_ = fmt.Sprint
}
