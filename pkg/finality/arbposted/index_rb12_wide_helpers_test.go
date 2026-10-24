// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
)

// ixWideKeyOf is the key of the pointer of the wide batch whose block hash is hash.
func ixWideKeyOf(gen uint32, minTs, maxTs, n uint64, hash [32]byte) finality.CaptureKey {
	return wideKey(gen, minTs, maxTs, n, hash)
}

// ixPointers is the number of pointer rows a self-check compared.
func ixPointers(res SelfCheckResult) int { return res.Pointers }

// ixMaxWide is the most pointers a lookup lists before it names coverage_overflow.
const ixMaxWide = maxWidePointers

// wideRows counts the pointer rows of the store.
func (w *ixWorld) wideRows() int {
	n := 0
	for k := range w.indexRows() {
		if strings.Contains(k.Item, "/arb/w/") {
			n++
		}
	}
	return n
}

// putPointer stores a pointer row that no real batch needs: a lookup lists it, and reads it only when a leg's timestamp is inside its bounds.
func (w *ixWorld) putPointer(i int) {
	w.t.Helper()
	var h [32]byte
	h[0], h[1], h[2] = byte(i), byte(i>>8), 0xfe
	k := ixWideKeyOf(1, uint64(7+i), uint64(7+i), uint64(1_000_000+i), h)
	if err := finality.IndexPut(context.Background(), w.store, FamilyArb, k, wideBody(5000, h)); err != nil {
		w.t.Fatal(err)
	}
}
