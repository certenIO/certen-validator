// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func frameOf(id byte, number uint16, data []byte, last byte) []byte {
	out := append(bytes.Repeat([]byte{id}, 16), 0, 0)
	binary.BigEndian.PutUint16(out[16:], number)
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	out = append(out, data...)
	return append(out, last)
}

func TestFrameParsingRefusalsAndBoundariesNameTheirCheck(t *testing.T) {
	hdr := func(n uint32) []byte { // a header declaring n bytes of data
		out := bytes.Repeat([]byte{7}, 16)
		out = append(out, 0, 1)
		return binary.BigEndian.AppendUint32(out, n)
	}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for _, c := range []struct {
		name string
		in   []byte
		want string // "" means accepted with n frames
		n    int
	}{
		{"empty", nil, "derivation version", 0},
		{"another version", []byte{1}, "derivation version", 0},
		{"the version alone has no frames", []byte{0}, "no frames", 0},
		{"a header one byte short", cat([]byte{0}, hdr(0)[:21]), "frame header", 0},
		{"a header with nothing after it", cat([]byte{0}, hdr(0)), "frame length", 0},
		{"an empty first frame, not last", cat([]byte{0}, hdr(0), []byte{0}), "", 1},
		{"an empty frame, last", cat([]byte{0}, hdr(0), []byte{1}), "", 1},
		{"is_last 2", cat([]byte{0}, hdr(0), []byte{2}), "frame is_last", 0},
		{"one datum, declared 2", cat([]byte{0}, hdr(2), []byte{5, 0}), "frame length", 0},
		{"data exactly fills, no is_last byte", cat([]byte{0}, hdr(2), []byte{5, 6}), "frame length", 0},
		{"data and is_last exactly fill", cat([]byte{0}, hdr(2), []byte{5, 6, 1}), "", 1},
		{"a trailing byte is a short header", cat([]byte{0}, hdr(0), []byte{1, 9}), "frame header", 0},
		{"two frames", cat([]byte{0}, frameOf(1, 0, []byte{1, 2}, 0), frameOf(1, 1, []byte{3}, 1)), "", 2},
	} {
		got, err := parseFrames(c.in)
		if c.want == "" {
			if err != nil || len(got) != c.n {
				t.Errorf("%s: %d frames, %v", c.name, len(got), err)
			}
			continue
		}
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// the fields of a parsed frame
	fr, err := parseFrames(cat([]byte{0}, frameOf(9, 0x0102, []byte{1, 2, 3}, 0), frameOf(8, 3, nil, 1)))
	if err != nil || len(fr) != 2 {
		t.Fatalf("%d %v", len(fr), err)
	}
	if fr[0].ID != [16]byte(bytes.Repeat([]byte{9}, 16)) || fr[0].Number != 0x0102 || !bytes.Equal(fr[0].Data, []byte{1, 2, 3}) || fr[0].IsLast ||
		fr[1].ID != [16]byte(bytes.Repeat([]byte{8}, 16)) || fr[1].Number != 3 || len(fr[1].Data) != 0 || !fr[1].IsLast {
		t.Fatalf("%+v", fr)
	}
	// the data bound: exactly maxFrameData is a frame, one more is refused even when the bytes are there
	big := bytes.Repeat([]byte{4}, maxFrameData)
	if fr, err := parseFrames(cat([]byte{0}, frameOf(1, 0, big, 1))); err != nil || len(fr) != 1 || len(fr[0].Data) != maxFrameData {
		t.Fatalf("a frame of exactly maxFrameData: %v", err)
	}
	over := append(bytes.Repeat([]byte{4}, maxFrameData+1), 1)
	if _, err := parseFrames(cat([]byte{0}, hdr(maxFrameData+1), over)); err == nil || err.Error() != "frame length" {
		t.Fatalf("a frame over maxFrameData: %v", err)
	}
}

func TestChannelDecompressionNamesItsRefusalsAndKeepsTheCapExact(t *testing.T) {
	raw := bytes.Repeat([]byte("channel data "), 50)
	z := compress("zlib", raw)
	b := compress("brotli", raw)
	if z[0]>>4 != 7 || z[0]&0x0f != 8 {
		t.Fatalf("test assumption: the zlib header byte is %#x", z[0])
	}
	for _, c := range []struct {
		name string
		ch   []byte
		cap  uint64
		want string // "" accepted
	}{
		{"empty", nil, 1 << 20, "empty channel"},
		{"zlib", z, 1 << 20, ""},
		{"brotli", b, 1 << 20, ""},
		{"a compression nibble that only matches under a looser mask", append([]byte{0x09}, z[1:]...), 1 << 20, "compression type"},
		{"another compression type", []byte{0x02, 1, 2, 3}, 1 << 20, "compression type"},
		{"the zero byte", []byte{0x00}, 1 << 20, "compression type"},
		{"zlib window larger than 32 KiB", append([]byte{0x88}, z[1:]...), 1 << 20, "zlib window"},
		{"zlib with a header that fails its check", []byte{0x78, 0x00, 1, 2, 3}, 1 << 20, "zlib: invalid header"},
		{"zlib cut short", z[:len(z)-6], 1 << 20, "unexpected EOF"},
		{"cap exactly the size", z, uint64(len(raw)), ""},
		{"cap one under the size", z, uint64(len(raw)) - 1, "channel exceeds max_rlp_bytes_per_channel"},
	} {
		got, err := decompress(c.ch, c.cap)
		if c.want == "" {
			if err != nil || !bytes.Equal(got, raw) {
				t.Errorf("%s: %d bytes, %v", c.name, len(got), err)
			}
			continue
		}
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func blobOf(t *testing.T, data []byte) []byte {
	t.Helper()
	b, err := encodeBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBlobToDataRefusalsNameTheirCheckAndEveryLengthRoundTrips(t *testing.T) {
	data := func(n int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = byte(i*7 + 3)
		}
		return out
	}
	// every length around the round boundaries (round 0 carries 123 bytes, every later one 127) and the ends
	lengths := []int{0, 1, 2, 26, 27, 28, 29, 31, 32, 122, 123, 124, 125, 126, 127, 128, 200, 249, 250, 251, 252, 253, 254, 255, 1000, 50000, blobMaxData - 1, blobMaxData}
	for k := 0; k < 12; k++ {
		lengths = append(lengths, 123+127*k-1, 123+127*k, 123+127*k+1)
	}
	for _, n := range lengths {
		d := data(n)
		got, err := blobToData(blobOf(t, d))
		if err != nil || !bytes.Equal(got, d) {
			t.Fatalf("length %d: %d bytes, %v", n, len(got), err)
		}
	}
	if _, err := encodeBlob(data(blobMaxData + 1)); err == nil || err.Error() != "blob data too long" {
		t.Fatalf("over the maximum: %v", err)
	}
	// the structure of a one-round blob: version 0 at byte 1, the length big-endian at bytes 2 to 4, the data from byte 5
	b := blobOf(t, data(100))
	if b[1] != 0 || b[2] != 0 || b[3] != 0 || b[4] != 100 || !bytes.Equal(b[5:15], data(100)[:10]) {
		t.Fatalf("layout: % x", b[:16])
	}
	if b3 := blobOf(t, data(0x012345%blobMaxData)); b3[2] != 0x01 || b3[3] != 0x23 || b3[4] != 0x45 {
		t.Fatalf("length bytes % x", b3[2:5])
	}
	mut := func(n int, f func(b []byte)) []byte {
		c := append([]byte(nil), blobOf(t, data(n))...)
		f(c)
		return c
	}
	for _, c := range []struct {
		name string
		blob []byte
		want string
	}{
		{"one byte short", blobOf(t, data(10))[:BlobSize-1], "blob length"},
		{"one byte long", append(blobOf(t, data(10)), 0), "blob length"},
		{"empty", nil, "blob length"},
		{"encoding version", mut(10, func(b []byte) { b[1] = 1 }), "blob encoding version"},
		{"length over the maximum", mut(10, func(b []byte) { b[2], b[3], b[4] = 0x02, 0, 0 }), "blob data length"},
		{"length one over the maximum", mut(10, func(b []byte) { b[2], b[3], b[4] = 0x01, 0xfc, 0xfd }), "blob data length"},
		{"high bits of the first element", mut(10, func(b []byte) { b[0] = 0x40 }), "blob field element"},
		{"high bit of the first element", mut(10, func(b []byte) { b[0] = 0x80 }), "blob field element"},
		{"high bits of element 1", mut(10, func(b []byte) { b[32] = 0x40 }), "blob field element"},
		{"high bits of element 2", mut(10, func(b []byte) { b[64] = 0x80 }), "blob field element"},
		{"high bits of element 3", mut(10, func(b []byte) { b[96] = 0xc0 }), "blob field element"},
		{"high bits of element 4 (the second round)", mut(124, func(b []byte) { b[128] = 0x40 }), "blob field element"},
		{"high bits of element 5", mut(124, func(b []byte) { b[160] = 0x40 }), "blob field element"},
		{"high bits of element 7", mut(124+127*2, func(b []byte) { b[224] = 0x40 }), "blob field element"},
		{"data tail inside the first round", mut(10, func(b []byte) { b[5+10] = 1 }), "blob data tail"},
		{"input tail in the fields of the second round", mut(10, func(b []byte) { b[128+1] = 1 }), "blob input tail"},
		{"input tail at the very end", mut(10, func(b []byte) { b[BlobSize-1] = 1 }), "blob input tail"},
	} {
		got, err := blobToData(c.blob)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %d bytes, %v, want %q", c.name, len(got), err, c.want)
		}
	}
	// a nonzero byte in the first field element that follows the data of a blob whose length ends a round exactly is an input
	// tail, never data: the decoder stops reading at the declared length
	for k := 0; k < 6; k++ {
		n := 123 + 127*k
		ipos := 128 + 128*k
		for _, off := range []int{1, 15, 31} {
			bl := mut(n, func(b []byte) { b[ipos+off] = 1 })
			if _, err := blobToData(bl); err == nil || err.Error() != "blob input tail" {
				t.Errorf("length %d, byte %d after the data: %v", n, ipos+off, err)
			}
		}
	}
}
