// Copyright 2026 Certen Protocol

package adiri_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-GATE-A, the builder's Roaring reader: the bytes come from an RPC endpoint that is not trusted, so a few kilobytes must
// never expand into millions of values (a run container of 65536 values costs four bytes), and a run must stay inside its
// 16-bit container.

// gateRunBitmap is a portable Roaring bitmap (cookie 12347) with one run container holding the given (start, length) runs.
func gateRunBitmap(runs [][2]uint16) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 12347) // one container (size-1 == 0 in the high half)
	b = append(b, 0x01)                               // the container is a run container
	b = binary.LittleEndian.AppendUint16(b, 0)        // key
	b = binary.LittleEndian.AppendUint16(b, 0xffff)   // cardinality - 1
	b = binary.LittleEndian.AppendUint16(b, uint16(len(runs)))
	for _, r := range runs {
		b = binary.LittleEndian.AppendUint16(b, r[0])
		b = binary.LittleEndian.AppendUint16(b, r[1])
	}
	return b
}

func TestRoaringReaderBoundsWhatAHostileEndpointCanMakeItAllocate(t *testing.T) {
	// one full 16-bit container is the most a bitmap may hold
	vals, err := adiri.DecodeRoaring(gateRunBitmap([][2]uint16{{0, 0xffff}}))
	if err != nil || len(vals) != 65536 {
		t.Fatalf("one full container: %d values, %v", len(vals), err)
	}
	// 65537 values, 5 bytes more: refused
	if _, err := adiri.DecodeRoaring(gateRunBitmap([][2]uint16{{0, 0xffff}, {0, 0}})); err == nil || !strings.Contains(err.Error(), "too many values") {
		t.Fatalf("65537 values: %v", err)
	}
	// 200 runs of 65536 values each, 810 bytes on the wire, must not become 13 million values
	hostile := make([][2]uint16, 200)
	for i := range hostile {
		hostile[i] = [2]uint16{0, 0xffff}
	}
	raw := gateRunBitmap(hostile)
	if len(raw) > 1000 {
		t.Fatalf("%d bytes", len(raw))
	}
	if vals, err := adiri.DecodeRoaring(raw); err == nil {
		t.Fatalf("a %d byte bitmap expanded into %d values", len(raw), len(vals))
	}
	// a run that leaves its container is malformed (values would spill into the key half)
	if _, err := adiri.DecodeRoaring(gateRunBitmap([][2]uint16{{0xffff, 1}})); err == nil || !strings.Contains(err.Error(), "run") {
		t.Fatalf("run past the container end: %v", err)
	}
	if vals, err := adiri.DecodeRoaring(gateRunBitmap([][2]uint16{{0xfffe, 1}})); err != nil || len(vals) != 2 || vals[1] != 0xffff {
		t.Fatalf("a run ending exactly at 65535: %v %v", vals, err)
	}
}
