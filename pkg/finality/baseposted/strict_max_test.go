// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"math"
	"testing"
)

// The cap of a Brotli channel is uint64: the largest values must neither wrap nor refuse a channel that fits (the zlib path has the same
// test in the package; this one is the Brotli branch, which goes through strictbrotli).
func TestABrotliChannelUnderTheLargestCapsIsAccepted(t *testing.T) {
	data := bytes.Repeat([]byte("channel "), 500)
	ch := brotliChannel(t, data)
	for _, max := range []uint64{uint64(len(data)), math.MaxInt64 - 1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64} {
		got, err := decompress(ch, max)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("cap %d: err %v, %d bytes", max, err, len(got))
		}
	}
	if _, err := decompress(ch, uint64(len(data))-1); err == nil {
		t.Fatal("one byte over the cap was accepted")
	}
}
