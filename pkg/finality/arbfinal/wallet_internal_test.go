// Copyright 2026 Certen Protocol

package arbfinal

import "testing"

// decodeWalletCalls keeps its own length guard: a pins file that names an all-zero wallet selector must not make a short input
// reach the argument slice.
func TestDecodeWalletCallsRefusesAnInputShorterThanASelector(t *testing.T) {
	p := &Pins{}
	for _, in := range [][]byte{nil, {}, {0}, {0, 0, 0}} {
		if calls, ok := decodeWalletCalls(p, [4]byte{}, in); ok || calls != nil {
			t.Errorf("input %x decoded to %v", in, calls)
		}
	}
	// four zero bytes, which is the (zero) selector and no arguments: the arguments do not decode
	if _, ok := decodeWalletCalls(p, [4]byte{}, []byte{0, 0, 0, 0}); ok {
		t.Error("a selector without arguments decoded")
	}
}

// selectorOf is exact at every length: no selector below four bytes, the first four bytes from four up.
func TestSelectorOfIsExactAtEveryLength(t *testing.T) {
	in := []byte{0x10, 0xb9, 0x8a, 0x35, 0xff}
	for n := 0; n <= len(in); n++ {
		sel, ok := selectorOf(in[:n])
		if n < 4 {
			if ok || sel != ([4]byte{}) {
				t.Errorf("%d bytes: %x %v", n, sel, ok)
			}
			continue
		}
		if !ok || sel != ([4]byte{0x10, 0xb9, 0x8a, 0x35}) {
			t.Errorf("%d bytes: %x %v", n, sel, ok)
		}
	}
}
