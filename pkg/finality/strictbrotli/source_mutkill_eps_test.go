// Copyright 2026 Certen Protocol

package strictbrotli

import (
	"bytes"
	"errors"
	"testing"
)

// RB12 EPSILON stage 2 (EPS-MUTKILL-1): the source the decoder reads is the argument of the completeness proof (the input, then ONE probe
// byte, then a non-EOF error forever), so its three phases are pinned directly, and the empty stream is refused as "not exceeded".

func TestSourceServesTheInputThenExactlyOneZeroProbeByteThenAnErrorThatIsNeverEOF(t *testing.T) {
	s := &source{in: []byte{1, 2, 3}}
	buf := make([]byte, 2)
	if n, err := s.Read(buf); n != 2 || err != nil || !bytes.Equal(buf, []byte{1, 2}) {
		t.Fatalf("first read: %d %v %v", n, err, buf)
	}
	if n, err := s.Read(buf); n != 1 || err != nil || buf[0] != 3 || s.probed {
		t.Fatalf("second read (the last input byte): %d %v %v probed=%v", n, err, buf, s.probed)
	}
	// The input is exhausted: the very next read serves the probe byte, a zero, and says so.
	buf[0] = 9
	if n, err := s.Read(buf); n != 1 || err != nil || buf[0] != 0 || !s.probed {
		t.Fatalf("probe read: %d %v %v probed=%v", n, err, buf, s.probed)
	}
	for i := 0; i < 3; i++ {
		if n, err := s.Read(buf); n != 0 || !errors.Is(err, ErrIncomplete) {
			t.Fatalf("read %d after the probe: %d %v", i, n, err)
		}
	}
	// An empty input serves the probe byte first.
	e := &source{}
	buf[0] = 7
	if n, err := e.Read(buf); n != 1 || err != nil || buf[0] != 0 || !e.probed {
		t.Fatalf("empty source: %d %v %v", n, err, buf)
	}
}

func TestDecompressOfNothingIsRefusedAsEmptyAndIsNeverReportedAsExceeded(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		for _, max := range []int{0, 1, 1 << 20} {
			out, exceeded, err := Decompress(in, max)
			if out != nil || exceeded || !errors.Is(err, ErrEmpty) {
				t.Errorf("Decompress(%v, %d) = (%v, %v, %v)", in, max, out, exceeded, err)
			}
		}
	}
}
