// Copyright 2026 Certen Protocol

package adiri

import (
	"bytes"
	"math"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-GATE-A, the spine's number arithmetic: the comparisons never wrap at 64 bits, whatever headers a (hostile) spine carries.

func gateSpineHeader(t *testing.T, number uint64, parent [32]byte) []byte {
	t.Helper()
	items := make([]any, 15)
	for i := range items {
		items[i] = []byte{1}
	}
	items[0] = parent[:]
	for _, i := range []int{3, 4, 5} {
		items[i] = bytes.Repeat([]byte{byte(i)}, 32)
	}
	var n []byte
	for v := number; v > 0; v >>= 8 {
		n = append([]byte{byte(v)}, n...)
	}
	items[8] = n
	items[11] = []byte{0x65}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSpineNumberStepNeverWrapsAtSixtyFourBits(t *testing.T) {
	// h1's number is 2^64-1 and its child h0 has number 0: h1.Number+1 wraps to h0's number, but there is no block below number 0
	h1 := gateSpineHeader(t, math.MaxUint64, [32]byte{})
	h0 := gateSpineHeader(t, 0, crypto.Keccak256Hash(h1))
	res := &ChainResult{Final: NumHash{Number: 0, Hash: crypto.Keccak256Hash(h0)}}
	leg := finality.BlockRef{Chain: finality.ChainAdiri, Number: math.MaxUint64, Hash: crypto.Keccak256Hash(h1)}
	_, err := verifySpine(res, [][]byte{h0, h1}, leg)
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != CodeHeaderChainBroken || st.Fields["reason"] != ReasonNumberGap || st.Fields["at_number"] != uint64(0) {
		t.Fatalf("a number that wraps to its child's must be refused as a gap: %v", err)
	}
	// a second header numbered ABOVE the tip (1 after 0) is not a descending chain either
	g1 := gateSpineHeader(t, 1, [32]byte{})
	g0 := gateSpineHeader(t, 0, crypto.Keccak256Hash(g1))
	okRes := &ChainResult{Final: NumHash{Number: 0, Hash: crypto.Keccak256Hash(g0)}}
	if _, err := verifySpine(okRes, [][]byte{g0, g1}, finality.BlockRef{Chain: finality.ChainAdiri, Number: 1, Hash: crypto.Keccak256Hash(g1)}); err == nil {
		t.Fatal("an ascending pair was accepted as a spine")
	}
	// a header that cannot be read labels the refusal with a saturating number, never a wrapped one
	_, err = verifySpine(res, [][]byte{h0, []byte("garbage")}, leg)
	st, ok = finality.AsNamed(err)
	if !ok || st.Code != CodeLinkBroken || st.Fields["at"] != uint64(0) {
		t.Fatalf("%v", err)
	}
}

func TestSaturatingNumberLabels(t *testing.T) {
	for _, c := range []struct {
		top  uint64
		i    int
		want uint64
	}{{10, 4, 6}, {5, 5, 0}, {3, 7, 0}, {0, 1, 0}, {0, 0, 0}, {math.MaxUint64, 1, math.MaxUint64 - 1}} {
		if got := numberAt(c.top, c.i); got != c.want {
			t.Errorf("numberAt(%d, %d) = %d, want %d", c.top, c.i, got, c.want)
		}
	}
	if numberBelow(0) != 0 || numberBelow(1) != 0 || numberBelow(9) != 8 {
		t.Error("numberBelow")
	}
}

func TestSpineTipNumberAndTheCallersHeaderBytesAreEachChecked(t *testing.T) {
	h0 := gateSpineHeader(t, 5, [32]byte{})
	hash := crypto.Keccak256Hash(h0)
	leg := finality.BlockRef{Chain: finality.ChainAdiri, Number: 5, Hash: hash}
	// the sealed number differs from the tip header's number although the hash is right
	_, err := verifySpine(&ChainResult{Final: NumHash{Number: 6, Hash: hash}}, [][]byte{h0}, leg)
	if st, ok := finality.AsNamed(err); !ok || st.Code != CodeLinkBroken || st.Fields["check"] != LinkTipNotFinalState {
		t.Fatalf("%v", err)
	}
	res := &ChainResult{Final: NumHash{Number: 5, Hash: hash}}
	if _, err := verifySpine(res, [][]byte{h0}, leg); err != nil {
		t.Fatalf("the single header spine: %v", err)
	}
	withBytes := leg
	withBytes.HeaderRLP = append([]byte(nil), h0...)
	if _, err := verifySpine(res, [][]byte{h0}, withBytes); err != nil {
		t.Fatalf("the caller's header equal to the spine's: %v", err)
	}
	withBytes.HeaderRLP = append([]byte(nil), h0...)
	withBytes.HeaderRLP[len(withBytes.HeaderRLP)-1] ^= 1
	_, err = verifySpine(res, [][]byte{h0}, withBytes)
	if st, ok := finality.AsNamed(err); !ok || st.Code != finality.CodeBlockMismatch || st.Fields["field"] != "spineLastHeader" {
		t.Fatalf("the caller's header differs from the spine's last: %v", err)
	}
}
