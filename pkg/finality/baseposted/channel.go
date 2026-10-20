// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality/strictbrotli"
)

// maxFrameData is OP's MaxFrameLen: a frame's data is at most one million bytes.
const maxFrameData = 1_000_000

// blobMaxData is OP's MaxBlobDataSize: (4*31+3)*1024 - 4.
const blobMaxData = (4*31+3)*1024 - 4

// blobToData is OP Blob.ToData (op-service/eth/blob.go): version byte 0 at offset 1, a 3-byte big-endian length at 2..4, then
// 4 rounds of field elements whose two high bits are zero, reassembled 127 bytes per 128. The rest of the blob must be zero.
func blobToData(b []byte) ([]byte, error) {
	if len(b) != BlobSize {
		return nil, errors.New("blob length")
	}
	if b[1] != 0 {
		return nil, errors.New("blob encoding version")
	}
	outLen := int(b[2])<<16 | int(b[3])<<8 | int(b[4])
	if outLen > blobMaxData {
		return nil, errors.New("blob data length")
	}
	out := make([]byte, blobMaxData)
	copy(out[0:27], b[5:])
	opos, ipos := 28, 32
	var enc [4]byte
	enc[0] = b[0]
	if enc[0]&0xc0 != 0 {
		return nil, errors.New("blob field element")
	}
	field := func() (byte, error) {
		if b[ipos]&0xc0 != 0 {
			return 0, errors.New("blob field element")
		}
		copy(out[opos:], b[ipos+1:ipos+32])
		c := b[ipos]
		opos += 32
		ipos += 32
		return c, nil
	}
	reassemble := func() {
		opos--
		x := (enc[0] & 0x3f) | ((enc[1] & 0x30) << 2)
		y := (enc[1] & 0x0f) | ((enc[3] & 0x0f) << 4)
		z := (enc[2] & 0x3f) | ((enc[3] & 0x30) << 2)
		out[opos-32] = z
		out[opos-64] = y
		out[opos-96] = x
	}
	var err error
	for i := 1; i < 4; i++ {
		if enc[i], err = field(); err != nil {
			return nil, err
		}
	}
	reassemble()
	for i := 1; i < 1024 && opos < outLen; i++ {
		for j := 0; j < 4; j++ {
			if enc[j], err = field(); err != nil {
				return nil, err
			}
		}
		reassemble()
	}
	for _, c := range out[outLen:] {
		if c != 0 {
			return nil, errors.New("blob data tail")
		}
	}
	for _, c := range b[ipos:] {
		if c != 0 {
			return nil, errors.New("blob input tail")
		}
	}
	return out[:outLen], nil
}

// encodeBlob is OP Blob.FromData (op-service/eth/blob.go), the inverse of blobToData; builders and vector generators use it.
func encodeBlob(data []byte) ([]byte, error) {
	if len(data) > blobMaxData {
		return nil, errors.New("blob data too long")
	}
	b := make([]byte, BlobSize)
	readOffset, writeOffset := 0, 0
	var buf31 [31]byte
	read1 := func() byte {
		if readOffset >= len(data) {
			return 0
		}
		v := data[readOffset]
		readOffset++
		return v
	}
	read31 := func() {
		buf31 = [31]byte{}
		if readOffset >= len(data) {
			return
		}
		readOffset += copy(buf31[:], data[readOffset:])
	}
	write1 := func(v byte) { b[writeOffset] = v; writeOffset++ }
	write31 := func() { copy(b[writeOffset:], buf31[:]); writeOffset += 31 }
	for round := 0; round < 1024 && readOffset < len(data); round++ {
		if round == 0 {
			buf31 = [31]byte{}
			ilen := uint32(len(data))
			buf31[0], buf31[1], buf31[2], buf31[3] = 0, byte(ilen>>16), byte(ilen>>8), byte(ilen)
			readOffset += copy(buf31[4:], data)
		} else {
			read31()
		}
		x := read1()
		write1(x & 0x3f)
		write31()
		read31()
		y := read1()
		write1((y & 0x0f) | ((x & 0xc0) >> 2))
		write31()
		read31()
		z := read1()
		write1(z & 0x3f)
		write31()
		read31()
		write1(((z & 0xc0) >> 2) | ((y & 0xf0) >> 4))
		write31()
	}
	if readOffset < len(data) {
		return nil, errors.New("blob data does not fit")
	}
	return b, nil
}

// ---- frames (OP derive/frame.go) ----

// Frame is one channel frame: channel_id(16) || frame_number(u16) || frame_data_length(u32) || frame_data || is_last(u8).
type Frame struct {
	ID     [16]byte
	Number uint16
	Data   []byte
	IsLast bool
}

// MarshalFrame is the frame's binary form.
func MarshalFrame(f Frame) []byte {
	out := append([]byte(nil), f.ID[:]...)
	out = binary.BigEndian.AppendUint16(out, f.Number)
	out = binary.BigEndian.AppendUint32(out, uint32(len(f.Data)))
	out = append(out, f.Data...)
	if f.IsLast {
		return append(out, 1)
	}
	return append(out, 0)
}

// parseFrames is OP ParseFrames: derivation version byte 0, then frames to the end of the data.
func parseFrames(data []byte) ([]Frame, error) {
	if len(data) == 0 || data[0] != 0 {
		return nil, errors.New("derivation version")
	}
	buf := data[1:]
	var out []Frame
	for len(buf) > 0 {
		if len(buf) < 16+2+4 {
			return nil, errors.New("frame header")
		}
		var f Frame
		copy(f.ID[:], buf[:16])
		f.Number = binary.BigEndian.Uint16(buf[16:])
		n := binary.BigEndian.Uint32(buf[18:])
		buf = buf[22:]
		if n > maxFrameData || uint64(n)+1 > uint64(len(buf)) {
			return nil, errors.New("frame length")
		}
		f.Data = append([]byte(nil), buf[:n]...)
		switch buf[n] {
		case 0:
		case 1:
			f.IsLast = true
		default:
			return nil, errors.New("frame is_last")
		}
		buf = buf[n+1:]
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, errors.New("no frames")
	}
	return out, nil
}

// ---- channel bytes ----

// decompress is the channel decompression of the derivation spec: zlib when b0&0x0f == 8 (and the CINFO nibble is at most 7),
// Brotli when b0 == 1 (version byte, then the Brotli stream). The output is capped at max bytes: one more is a bomb.
func decompress(ch []byte, max uint64) ([]byte, error) {
	if len(ch) == 0 {
		return nil, errors.New("empty channel")
	}
	var r io.Reader
	switch {
	case ch[0]&0x0f == 8:
		if ch[0]>>4 > 7 {
			return nil, errors.New("zlib window")
		}
		zr, err := zlib.NewReader(bytes.NewReader(ch))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	case ch[0] == 1:
		// strictbrotli refuses a stream that ends early, an empty one and one followed by extra bytes (the library alone answers a
		// clean EOF mid-stream and would return a prefix)
		out, exceeded, err := strictbrotli.Decompress(ch[1:], int(max))
		if err != nil {
			return nil, err
		}
		if exceeded {
			return nil, errors.New("channel exceeds max_rlp_bytes_per_channel")
		}
		return out, nil
	default:
		return nil, errors.New("compression type")
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(out)) > max {
		return nil, errors.New("channel exceeds max_rlp_bytes_per_channel")
	}
	return out, nil
}

// ---- batches ----

// Batch is one decoded block batch. Singular batches carry every field; a span batch's blocks carry what the span encodes
// (see span.go): HashLen says how many leading bytes of ParentHash and EpochHash are committed (32 singular; 20 or 0 span).
type Batch struct {
	Type       uint8
	ParentHash [32]byte
	ParentLen  int
	EpochNum   uint64
	EpochHash  [32]byte
	EpochLen   int
	Timestamp  uint64
	Txs        [][]byte
	SpanIndex  int // block index inside its span batch (0 for singular)
	SpanBlocks int // blocks in the span batch (1 for singular)
}

type singularRLP struct {
	ParentHash [32]byte
	EpochNum   uint64
	EpochHash  [32]byte
	Timestamp  uint64
	Txs        [][]byte
}

// batchFormatError is a batch type this verifier does not decode.
type batchFormatError struct{ typ uint8 }

func (e *batchFormatError) Error() string { return "unsupported batch type" }

// decodeBatches splits the decompressed channel into RLP strings (type byte || payload) and decodes each: type 0 singular,
// type 1 span (span.go). Any other type is a *batchFormatError; a stream that does not parse is a plain error.
func decodeBatches(stream []byte, sp spanParams) ([]Batch, error) {
	var out []Batch
	for len(stream) > 0 {
		kind, content, rest, err := rlp.Split(stream)
		if err != nil || kind != rlp.String || len(content) == 0 {
			return nil, errors.New("batch stream")
		}
		stream = rest
		switch content[0] {
		case 0:
			var s singularRLP
			if err := rlp.DecodeBytes(content[1:], &s); err != nil {
				return nil, errors.New("singular batch")
			}
			out = append(out, Batch{Type: 0, ParentHash: s.ParentHash, ParentLen: 32, EpochNum: s.EpochNum, EpochHash: s.EpochHash,
				EpochLen: 32, Timestamp: s.Timestamp, Txs: s.Txs, SpanBlocks: 1})
		case 1:
			bs, err := decodeSpanBatch(content[1:], sp)
			if err != nil {
				return nil, err
			}
			out = append(out, bs...)
		default:
			return nil, &batchFormatError{typ: content[0]}
		}
	}
	return out, nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
