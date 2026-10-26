// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"testing"
)

// RB12-EPS-MUTKILL-3: the blob layout (OP Blob.FromData / ToData) pinned byte for byte against an independent construction, not by a
// round trip. The stream is the 4-byte header (version 0, then the 3-byte big-endian length) followed by the data, zero padded to
// 1024 rounds of 127 stream bytes; round r owns blob bytes [128r, 128r+128): four field elements of one extra byte and 31 stream bytes
// each, the three extra stream bytes x, y, z being folded into the four leading bytes.

func expectedBlob(data []byte) []byte {
	stream := make([]byte, 1024*127)
	stream[1], stream[2], stream[3] = byte(len(data)>>16), byte(len(data)>>8), byte(len(data))
	copy(stream[4:], data)
	b := make([]byte, 131072)
	for r := 0; r < 1024; r++ {
		s, o := stream[127*r:127*r+127], b[128*r:128*r+128]
		x, y, z := s[31], s[63], s[95]
		o[0] = x & 0x3f
		copy(o[1:32], s[0:31])
		o[32] = (y & 0x0f) | ((x & 0xc0) >> 2)
		copy(o[33:64], s[32:63])
		o[64] = z & 0x3f
		copy(o[65:96], s[64:95])
		o[96] = ((z & 0xc0) >> 2) | ((y & 0xf0) >> 4)
		copy(o[97:128], s[96:127])
	}
	return b
}

func patterned(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*29 + 0xC5) // the two high bits and the high nibble of every byte vary
	}
	return out
}

func TestEncodeBlobIsTheOPLayoutByteForByteAtEveryRoundBoundary(t *testing.T) {
	lengths := []int{0, 1, 2, 26, 27, 28, 58, 59, 60, 90, 91, 92, 122, 123, 124, 125, 249, 250, 251, 252, 253, 254, 255, 256, 1000, blobMaxData - 1, blobMaxData}
	for _, n := range lengths {
		data := patterned(n)
		got, err := encodeBlob(data)
		if err != nil {
			t.Fatalf("length %d: %v", n, err)
		}
		if want := expectedBlob(data); !bytes.Equal(got, want) {
			at := 0
			for at < len(got) && got[at] == want[at] {
				at++
			}
			t.Fatalf("length %d: blob differs from the OP layout at byte %d (got %02x, want %02x)", n, at, got[at], want[at])
		}
	}
}

func TestBlobToDataReadsTheOPLayoutByteForByte(t *testing.T) {
	for _, n := range []int{0, 1, 27, 28, 123, 124, 250, 251, 1000, blobMaxData - 1, blobMaxData} {
		data := patterned(n)
		got, err := blobToData(expectedBlob(data))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("length %d: %d bytes, %v", n, len(got), err)
		}
	}
	// a single changed bit of the extra bytes changes the data they carry (x at stream 31, y at 63, z at 95 of round 0)
	data := patterned(130)
	b := expectedBlob(data)
	b[0] ^= 0x01
	got, err := blobToData(b)
	if err != nil || got[27] != data[27]^0x01 {
		t.Fatalf("x low bit: %v %02x %02x", err, got[27], data[27])
	}
	b = expectedBlob(data)
	b[32] ^= 0x10
	if got, err = blobToData(b); err != nil || got[27] != data[27]^0x40 {
		t.Fatalf("x bit 6 via byte 32: %v %02x %02x", err, got[27], data[27])
	}
}
