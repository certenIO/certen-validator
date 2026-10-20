// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/binary"
	"math"
	"runtime"
	"testing"
)

// The pins are 64-bit numbers added to hostile 64-bit block numbers; none of those sums may wrap, whatever the pin.
func TestPinsNearTheUint64LimitNeitherWrapTheChannelTimeoutNorTheSequencingWindowNorTheChannelCap(t *testing.T) {
	// frame blocks 1000 and 1001 with a timeout of 2^64-1: 1000 + (2^64-1) wraps to 999 and the second frame would be timed out
	timeout := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 2, frameBlocks: []uint64{1000, 1001}})
	timeout.bp.ChannelTimeout = math.MaxUint64
	mustOK(t, timeout)
	// epoch 990 with a sequencing window of 2^64-1: 990 + (2^64-1) wraps to 989 and the frame block 1000 would be outside it
	window := makeSynth(t, synthOpts{compression: "zlib", calldata: true, epochNum: 990, frameBlocks: []uint64{1000}})
	window.bp.SeqWindowSize = math.MaxUint64
	mustOK(t, window)
	// the cap is a cap at every value: from 2^63-1 up, cap+1 does not fit a signed limit and used to become a negative one that
	// read nothing
	ch := framesOf(t, makeSynth(t, synthOpts{compression: "zlib", calldata: true}))
	want, err := decompress(ch, 1<<20)
	if err != nil || len(want) == 0 {
		t.Fatalf("%d bytes, %v", len(want), err)
	}
	for _, cp := range []uint64{math.MaxInt64 - 1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64} {
		got, err := decompress(ch, cp)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("cap %d: %d bytes (want %d), %v", cp, len(got), len(want), err)
		}
		s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
		s.bp.MaxRLPBytesPerChannel = cp
		mustOK(t, s)
	}
}

// A span batch that declares transactions its payload cannot carry is refused before anything is allocated for them: the
// signatures alone take 64 bytes per transaction, and the lists are sized by the declared count (up to 2^20).
func TestASpanBatchThatDeclaresMoreTransactionsThanItCarriesAllocatesNothingForThem(t *testing.T) {
	var p []byte
	p = binary.AppendUvarint(p, 0)
	p = binary.AppendUvarint(p, 9)
	p = append(p, bytes.Repeat([]byte{0x11}, 20)...)
	p = append(p, bytes.Repeat([]byte{0x22}, 20)...)
	p = binary.AppendUvarint(p, 1)                    // block_count
	p = append(p, 0)                                  // origin bits
	p = binary.AppendUvarint(p, 1<<20)                // the block declares exactly the bound
	p = append(p, bytes.Repeat([]byte{0}, 3*1024)...) // some bytes, far fewer than 2^20 transactions need
	sp := spanParams{GenesisTime: 1695768288, BlockTime: 2, ChainID: 84532}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := decodeSpanBatch(p, sp)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("a payload that cannot carry its declared transactions was accepted")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Fatalf("%d bytes allocated for 2^20 declared transactions the payload cannot carry", got)
	}
}
