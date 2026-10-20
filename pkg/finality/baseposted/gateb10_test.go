// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

func pinsOf(t *testing.T) *finality.Pins {
	t.Helper()
	fp, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

// hookStore is a capture store whose reads can be made to fail or lie, per row.
type hookStore struct {
	CaptureStore
	blocksErr error
	get       func(k CaptureKey) (data []byte, ok bool, err error, handled bool)
}

func (h hookStore) ListByRange(ctx context.Context, chain, from, to uint64, itemPrefix string) ([]CaptureKey, error) {
	if h.blocksErr != nil {
		return nil, h.blocksErr
	}
	return h.CaptureStore.ListByRange(ctx, chain, from, to, itemPrefix)
}

func (h hookStore) Get(ctx context.Context, k CaptureKey) ([]byte, bool, error) {
	if h.get != nil {
		if d, ok, err, handled := h.get(k); handled {
			return d, ok, err
		}
	}
	return h.CaptureStore.Get(ctx, k)
}

// putSynth stores the rows of a synthetic calldata world the way the Capturer would: per L1 block the inbox list and the
// transactions (the builder reads nothing else of a calldata block here).
func putSynth(t *testing.T, st CaptureStore, s *synth) {
	t.Helper()
	hashOf := map[uint64][32]byte{}
	for _, c := range s.covered {
		hashOf[c.Number] = c.Hash
	}
	perBlock := map[uint64][]uint32{}
	for _, f := range s.body.Frames {
		perBlock[f.L1Block] = append(perBlock[f.L1Block], f.TxIndex)
		key := CaptureKey{Chain: uint64(Chain), L1Block: f.L1Block, L1Hash: hashOf[f.L1Block], Item: ItemTx(f.TxIndex)}
		if err := st.Put(context.Background(), key, f.TxRaw); err != nil {
			t.Fatal(err)
		}
	}
	for blk, idx := range perBlock {
		var w = newCountWriter(idx)
		key := CaptureKey{Chain: uint64(Chain), L1Block: blk, L1Hash: hashOf[blk], Item: ItemInbox}
		if err := st.Put(context.Background(), key, w); err != nil {
			t.Fatal(err)
		}
	}
}

func newCountWriter(idx []uint32) []byte {
	out := []byte{byte(len(idx) >> 24), byte(len(idx) >> 16), byte(len(idx) >> 8), byte(len(idx))}
	for _, i := range idx {
		out = append(out, byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
	}
	return out
}

func TestTheBuilderLoadsEveryInboxTransactionOfEveryCapturedBlockAndTheFramesTheyCarry(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 3, frameBlocks: []uint64{1000, 1000, 1001}})
	st := NewMemStore()
	putSynth(t, st, s)
	bp := newPins()
	b := &Builder{Store: st}
	txs, err := b.load(context.Background(), bp)
	if err != nil || len(txs) != 3 {
		t.Fatalf("%d txs, %v", len(txs), err)
	}
	for i, tx := range txs {
		f := s.body.Frames[i]
		// capture order: by block, and the transactions of a block in inbox order
		if tx.key.L1Block != f.L1Block || tx.index != f.TxIndex || !bytes.Equal(tx.raw, f.TxRaw) || len(tx.blobs) != 0 || len(tx.frames) != 1 || tx.frames[0].Number != uint16(i) || tx.frames[0].IsLast != (i == 2) {
			t.Errorf("tx %d: %+v", i, tx)
		}
	}
	ref, frameTxs, bt, last := findChannel(txs, bp, 1790000000)
	if ref == nil || ref.ID != s.body.ChannelID || len(frameTxs) != 3 || bt == nil || bt.Timestamp != 1790000000 || last != 1001 {
		t.Fatalf("%v %d %v %d", ref, len(frameTxs), bt, last)
	}
	if ref2, _, _, last2 := findChannel(txs, bp, 1790000000+2*1000); ref2 != nil || last2 != 1001 {
		t.Fatalf("a timestamp no batch covers: %v %d", ref2, last2)
	}
	chs, err := (&Builder{Pins: nil, Store: st}).Channels(context.Background())
	if err == nil {
		t.Fatalf("a builder without pins cannot list channels: %v", chs)
	}
}

func TestTheBuilderLoadRefusesARowThatIsGoneUnreadableOrNotWhatItShouldBe(t *testing.T) {
	w := newBuildWorld(t, "evidence/valid_a.bin", "legs/a.json")
	bp, err := ParsePins(w.pins)
	if err != nil {
		t.Fatal(err)
	}
	tx0 := w.body.Frames[0].TxIndex
	isItem := func(k CaptureKey, item string) bool { return k.Item == item }
	for _, c := range []struct {
		name string
		h    hookStore
		want string
	}{
		{"blocks unreadable", hookStore{blocksErr: errors.New("db down")}, "db down"},
		{"inbox row vanished", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return nil, false, nil, isItem(k, ItemInbox)
		}}, "vanished"},
		{"inbox row unreadable", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return nil, true, errors.New("db down"), isItem(k, ItemInbox)
		}}, "vanished"},
		{"inbox count over the remaining bytes", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return []byte{0, 0, 0, 9, 0, 0, 0, 1}, true, nil, isItem(k, ItemInbox)
		}}, "inbox"},
		{"inbox index missing", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return []byte{0, 0, 0, 1, 0, 0, 0}, true, nil, isItem(k, ItemInbox)
		}}, "inbox"},
		{"transaction row gone", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return nil, false, nil, isItem(k, ItemTx(tx0))
		}}, "tx/"},
		{"transaction row unreadable", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return nil, true, errors.New("db down"), isItem(k, ItemTx(tx0))
		}}, "tx/"},
		{"transaction row is no transaction", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return []byte{0x02, 0xc0}, true, nil, isItem(k, ItemTx(tx0))
		}}, ""},
		{"blob row unreadable", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return nil, true, errors.New("db down"), isItem(k, ItemBlob(tx0, 0))
		}}, "db down"},
		{"blob row cut short", hookStore{get: func(k CaptureKey) ([]byte, bool, error, bool) {
			return []byte{0, 0, 0, 5, 1, 2}, true, nil, isItem(k, ItemBlob(tx0, 0))
		}}, ""},
	} {
		h := c.h
		h.CaptureStore = w.store
		_, err := (&Builder{Store: h}).load(context.Background(), bp)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", c.name, err, c.want)
		}
	}
	// a blob that does not decode as frame data belongs to no channel: it is skipped, the channel it was part of is incomplete
	bad := make([]byte, BlobSize)
	bad[1] = 1
	var bw []byte
	bw = append(bw, 0, 2, 0, 0)
	bw = append(bw, bad...)
	bw = append(bw, make([]byte, 96)...)
	h := hookStore{CaptureStore: w.store, get: func(k CaptureKey) ([]byte, bool, error, bool) {
		return bw, true, nil, isItem(k, ItemBlob(tx0, 0))
	}}
	txs, err := (&Builder{Store: h}).load(context.Background(), bp)
	if err != nil {
		t.Fatal(err)
	}
	full, err := (&Builder{Store: w.store}).load(context.Background(), bp)
	if err != nil {
		t.Fatal(err)
	}
	var fullFrames, skipFrames int
	for _, x := range full {
		fullFrames += len(x.frames)
	}
	for _, x := range txs {
		skipFrames += len(x.frames)
	}
	if skipFrames >= fullFrames || len(txs) != len(full) {
		t.Fatalf("frames %d vs %d, txs %d vs %d", skipFrames, fullFrames, len(txs), len(full))
	}
	// calldata that is no frame stream carries no frame, and is not an error
	cd := makeSynth(t, synthOpts{compression: "zlib", calldata: true, txData: []byte{0xff}})
	st := NewMemStore()
	putSynth(t, st, cd)
	txs, err = (&Builder{Store: st}).load(context.Background(), bp)
	if err != nil || len(txs) != 1 || len(txs[0].frames) != 0 {
		t.Fatalf("%+v %v", txs, err)
	}
}

func TestTheBuilderFindsAndListsOnlyCompleteDecodableChannelsInCaptureOrder(t *testing.T) {
	ctx := context.Background()
	bp := newPins()
	st := newEditStore()
	// channel one: complete, decodable; channel two: another complete one at a later block
	one := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 2, frameBlocks: []uint64{1000, 1000}, channelLabel: "one", batchTs: 1790000000})
	two := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 1, frameBlocks: []uint64{1200}, channelLabel: "two", batchTs: 1790000100, epochNum: 1190})
	// channel three: complete but its stream does not decompress; channel four: complete, decompresses, holds an undecodable batch
	bad := []byte{0x78, 0x00, 1, 2, 3}
	three := makeSynth(t, synthOpts{compression: "zlib", calldata: true, channelLabel: "three", frameBlocks: []uint64{1100}, txData: append([]byte{0}, MarshalFrame(Frame{ID: [16]byte{3}, Number: 0, Data: bad, IsLast: true})...)})
	four := makeSynth(t, synthOpts{compression: "zlib", calldata: true, channelLabel: "four", frameBlocks: []uint64{1150}, rawStream: rlpOf([]byte{7, 1})})
	// channel five: only its second frame was captured (frame 0 missing)
	five := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 2, frameBlocks: []uint64{1300, 1300}, channelLabel: "five"})
	for _, s := range []*synth{one, two, three, four, five} {
		putSynth(t, st, s)
	}
	// drop the first frame transaction of channel five from its inbox row
	for k, v := range st.rows {
		if k.Item == ItemInbox && k.L1Block == 1300 {
			st.rows[k] = newCountWriter([]uint32{uint32(v[len(v)-1])})
		}
	}
	b := &Builder{Pins: pinsOf(t), Store: st}
	chs, err := b.Channels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(chs) != 2 || chs[0].ID != one.body.ChannelID || chs[1].ID != two.body.ChannelID {
		t.Fatalf("channels %+v", chs)
	}
	if len(chs[0].L1Blocks) != 2 || chs[0].L1Blocks[0] != 1000 || chs[0].L1Blocks[1] != 1000 || len(chs[1].L1Blocks) != 1 || chs[1].L1Blocks[0] != 1200 {
		t.Fatalf("blocks %+v", chs)
	}
	if len(chs[0].Timestamps) != 3 || chs[0].Timestamps[0] != 1790000000 || chs[1].Timestamps[0] != 1790000100 {
		t.Fatalf("timestamps %+v", chs)
	}
	txs, err := b.load(ctx, bp)
	if err != nil {
		t.Fatal(err)
	}
	// the channel for a timestamp is the first complete decodable one that has a batch for it; the highest block scanned is reported
	ref, frameTxs, bt, last := findChannel(txs, bp, 1790000100)
	if ref == nil || ref.ID != two.body.ChannelID || len(frameTxs) != 1 || bt.Timestamp != 1790000100 || last != 1300 {
		t.Fatalf("%v %d %v %d", ref, len(frameTxs), bt, last)
	}
	if ref, _, _, last = findChannel(txs, bp, 1790000000); ref == nil || ref.ID != one.body.ChannelID || last != 1300 {
		t.Fatalf("%v %d", ref, last)
	}
	if ref, _, _, last = findChannel(txs, bp, 1); ref != nil || last != 1300 {
		t.Fatalf("a timestamp of no batch: %v %d", ref, last)
	}
}
