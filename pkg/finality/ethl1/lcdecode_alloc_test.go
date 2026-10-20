// Copyright 2026 Certen Protocol

package ethl1

import (
	"encoding/binary"
	"runtime"
	"testing"
)

// The link count is read before the links, so a few bytes can declare a count no byte stream can hold: nothing may be sized by the
// declared count before the bytes for it are known (a 55-byte container at max_links 10 million asked for 320 MB).
func TestALinkCountTheBytesCannotHoldAllocatesNothingNearTheDeclaredCount(t *testing.T) {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, 1) // profile "x"
	b = append(b, 'x')
	b = append(b, 1) // anchor kind
	b = binary.BigEndian.AppendUint64(b, 7)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0) // anchor body layout
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint32(b, 10_000_000) // declared links; none follow
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := DecodeLC(b, 10_000_000)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("a container that ends before its links was accepted")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("decoding %d bytes allocated %d bytes", len(b), grew)
	}
}
