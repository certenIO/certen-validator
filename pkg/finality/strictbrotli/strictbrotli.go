// Copyright 2026 Certen Protocol

// Package strictbrotli is the one Brotli decompression the finality verifiers use (Arbitrum batches and messages, OP channels).
//
// Why it exists. github.com/andybalholm/brotli's Reader answers a clean io.EOF when its source is exhausted while the decoder
// still needs input and has no output pending (reader.go: `if m == 0 { return 0, readErr }` at the top of Read). io.ReadAll over
// it therefore returns a PREFIX of a stream that was cut short, with a nil error. Nitro's arbcompress (the reference brotli C
// decoder) and every standard decoder refuse such a stream, so a verifier built on the library alone could accept a message the
// sequencer never posted. Decompress here refuses every incomplete stream, the empty stream, and any byte after a complete one.
//
// How completeness is established. The source handed to the decoder serves the input, then ONE probe byte, then a non-EOF
// error. After a complete stream the decoder is in its done state, where it consumes nothing and Read returns
// "brotli: excessive input" because the probe byte is left over (reader.go: decoderResultSuccess with len(r.in) > 0). If the
// stream was incomplete the probe byte is consumed as stream data (or is a decode error) and the source's non-EOF error ends the
// read: no outcome of that path is an excessive-input error, so the stream is refused. A byte after a complete stream that was
// part of the input is excessive input BEFORE the probe is served and is refused too. The argument is checked exhaustively by
// the tests: every truncation point of streams of every library quality and window, against an oracle that reads the decoder's
// own state.
package strictbrotli

import (
	"errors"
	"io"

	"github.com/andybalholm/brotli"
)

// ErrEmpty is returned for a zero-byte stream (nitro's arbcompress refuses it).
var ErrEmpty = errors.New("brotli: empty stream")

// ErrIncomplete is returned for a stream that ends before its last metablock is complete.
var ErrIncomplete = errors.New("brotli: stream is incomplete")

// ErrTrailing is returned for bytes after a complete stream.
var ErrTrailing = errors.New("brotli: bytes after the end of the stream")

// libExcessive is the text of the library's error for input left after a complete stream (reader.go errExcessiveInput).
const libExcessive = "brotli: excessive input"

// source serves in, then one probe byte, then ErrIncomplete forever (never io.EOF).
type source struct {
	in     []byte
	off    int
	probed bool
}

func (s *source) Read(p []byte) (int, error) {
	if s.off < len(s.in) {
		n := copy(p, s.in[s.off:])
		s.off += n
		return n, nil
	}
	if !s.probed {
		s.probed = true
		p[0] = 0
		return 1, nil
	}
	return 0, ErrIncomplete
}

// Decompress returns the whole decompressed stream, capped at max bytes: exceeded is true (and out nil) when the stream would
// produce more than max. An incomplete stream, an empty one or one followed by extra bytes is an error. A stream that exceeds
// the cap is reported as exceeded without being read to its end.
func Decompress(in []byte, max int) (out []byte, exceeded bool, err error) {
	if len(in) == 0 {
		return nil, false, ErrEmpty
	}
	src := &source{in: in}
	rd := brotli.NewReader(src)
	out, err = io.ReadAll(io.LimitReader(rd, int64(max)+1))
	return classify(out, err, src.probed, max)
}

// classify turns the end of the read into the verdict. err is what io.ReadAll returned, probed whether the source had served its
// probe byte. Only the library's excessive-input error AFTER the probe is the end of a complete stream; the same error before
// the probe is a byte after the stream; any other error, and a read that ended without one, is an incomplete stream.
func classify(out []byte, err error, probed bool, max int) ([]byte, bool, error) {
	if len(out) > max {
		return nil, true, nil
	}
	if err == nil {
		return nil, false, ErrIncomplete
	}
	if err.Error() != libExcessive {
		return nil, false, err
	}
	if !probed {
		return nil, false, ErrTrailing
	}
	return out, false, nil
}
