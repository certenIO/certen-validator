// Copyright 2026 Certen Protocol

package baseposted

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
)

// The Denim world of the capture index: blocks g = 0, 1, 2... of Base Sepolia, five per timestamp second, each with its own parent hash,
// split into channels the way the live table holds them (RB12-EPS-GAP: block 50446... of 2026-10-26 was judged l1_capture_gap
// {unrecorded} although its channel was captured and indexed).
const denimS0 = uint64(1793039201)

func denimParent(g int) [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(g))
	return [32]byte(crypto.Keccak256Hash([]byte("denim-parent"), b[:]))
}

func dTs(g int) uint64 { return denimS0 + uint64(g/5) }

// denimFrames builds the frames of the channel holding blocks [from, to) as singular batches (type 0) of epoch.
func denimFrames(label string, from, to int, epoch uint64, nFrames int) []Frame {
	var stream []byte
	epochHash := crypto.Keccak256Hash([]byte("epoch"), []byte{byte(epoch)})
	for g := from; g < to; g++ {
		enc, _ := rlp.EncodeToBytes(singularRLP{ParentHash: denimParent(g), EpochNum: epoch, EpochHash: [32]byte(epochHash), Timestamp: dTs(g), Txs: [][]byte{userTx(uint64(g))}})
		b, _ := rlp.EncodeToBytes(append([]byte{0}, enc...))
		stream = append(stream, b...)
	}
	data := compress("zlib", stream)
	id := chanLabelID(label)
	per := (len(data) + nFrames - 1) / nFrames
	var out []Frame
	for i := 0; i < nFrames; i++ {
		lo, hi := i*per, (i+1)*per
		if hi > len(data) {
			hi = len(data)
		}
		if lo > hi {
			lo = hi
		}
		out = append(out, Frame{ID: id, Number: uint16(i), Data: data[lo:hi], IsLast: i == nFrames-1})
	}
	return out
}

// denimIndexWorld captures three channels A = blocks [0,52) (it ends inside the second of block 50), B = [52,532) (it starts inside that
// second), C = [532,592), indexes them and returns a searcher for the leg of block g.
func denimIndexWorld(t *testing.T) func(g int) (searched, error) {
	t.Helper()
	_, bp := idxPins(t)
	if bp.PostDenim == nil || denimS0 < bp.DenimTime {
		t.Fatal("the embedded pins carry no post_denim row")
	}
	const E = uint64(1000)
	st := NewMemStore()
	vPutBlock(t, st, bp, 1010, denimFrames("A", 0, 52, E, 2))
	vPutBlock(t, st, bp, 1020, denimFrames("B", 52, 532, E, 2))
	vPutBlock(t, st, bp, 1030, denimFrames("C", 532, 592, E, 2))
	stepAll(t, newIdx(st, bp, IndexConfig{}), 1300)
	b := &Builder{Store: st, L2: fixedL2{txs: [][]byte{l1InfoDeposit(E, [32]byte{9})}}, Index: NewIndexReader(st, bp, 0)}
	return func(g int) (searched, error) {
		return b.search(context.Background(), bp, finality.HeaderFields{Number: 50000000 + uint64(g), Timestamp: dTs(g), ParentHash: denimParent(g)}, nil)
	}
}

func TestADenimLegInAnIndexedChannelIsFoundThroughTheIndexNotJudgedACaptureGap(t *testing.T) {
	search := denimIndexWorld(t)
	for _, g := range []int{300, 302, 304, 100, 531, 540} {
		sr, err := search(g)
		want := chanLabelID("B")
		if g < 52 {
			want = chanLabelID("A")
		} else if g >= 532 {
			want = chanLabelID("C")
		}
		if err != nil || sr.ch == nil || sr.ch.ID != want {
			t.Errorf("block %d: channel %v, error %v, pending %q judged %v", g, sr.ch, err, sr.pending, sr.judged)
		}
	}
}

func TestAStraddledDenimSecondIsFoundThroughTheIndexInTheChannelWithTheParentHash(t *testing.T) {
	search := denimIndexWorld(t)
	// blocks 50 and 51 are the first two blocks of their second and end channel A, blocks 52-54 are the rest of the second and start
	// channel B: the index lists both channels for that timestamp and the parent hash tells them apart
	for g, id := range map[int][16]byte{50: chanLabelID("A"), 51: chanLabelID("A"), 52: chanLabelID("B"), 53: chanLabelID("B"), 54: chanLabelID("B")} {
		sr, err := search(g)
		if err != nil || sr.ch == nil || sr.ch.ID != id {
			t.Errorf("block %d: channel %v, error %v, pending %q judged %v", g, sr.ch, err, sr.pending, sr.judged)
		}
	}
}

func TestADenimLegWhoseParentHashNoChannelOfItsSecondNamesIsNotFoundThroughTheIndex(t *testing.T) {
	_, bp := idxPins(t)
	const E = uint64(1000)
	st := NewMemStore()
	vPutBlock(t, st, bp, 1010, denimFrames("A", 0, 52, E, 2))
	vPutBlock(t, st, bp, 1020, denimFrames("B", 52, 532, E, 2))
	stepAll(t, newIdx(st, bp, IndexConfig{}), 1300)
	b := &Builder{Store: st, L2: fixedL2{txs: [][]byte{l1InfoDeposit(E, [32]byte{9})}}, Index: NewIndexReader(st, bp, 0)}
	other := denimParent(9999)
	sr, _ := b.search(context.Background(), bp, finality.HeaderFields{Number: 50000300, Timestamp: dTs(300), ParentHash: other}, nil)
	if sr.ch != nil {
		t.Fatalf("a block whose parent hash no batch of its second commits resolved to a channel: %v", sr.ch)
	}
}

// The three channel entries the live capture table held around the stuck leg (chain 84532, L1 11999779, 11999788, 11999791, read from
// proof_finality_capture on 2026-10-26): the writer recorded them correctly, so the miss was the reader's.
func TestTheLiveDenimIndexEntriesCoverEveryBatchOfTheirChannel(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "denim_live_index", "entries.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		item, hexBytes, ok := strings.Cut(sc.Text(), "|")
		if !ok {
			t.Fatal("bad line")
		}
		b, err := hex.DecodeString(strings.TrimSpace(hexBytes))
		if err != nil {
			t.Fatal(err)
		}
		e, err := decodeEntry(b)
		if err != nil || e.Status != entryDecoded {
			t.Fatalf("%s: %v status %d", item, err, e.Status)
		}
		parts := strings.Split(item, "/")
		tmin, _ := strconv.ParseUint(parts[len(parts)-3], 10, 64)
		tmax, _ := strconv.ParseUint(parts[len(parts)-2], 10, 64)
		for s := tmin; s <= tmax; s++ {
			c := 0
			for _, r := range e.Runs {
				if r.covers(s, 2) {
					c++
				}
			}
			if c == 0 || c > 5 {
				t.Errorf("%s: second %d is covered by %d runs, a Denim second holds 1 to 5 batches", item, s, c)
			}
		}
		n++
	}
	if n != 3 {
		t.Fatalf("%d entries", n)
	}
}
