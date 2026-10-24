// Copyright 2026 Certen Protocol

package arbfinal

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// headerNumbered is judged here directly, on spines the light-client walk has not seen, so that every refusal of the framework header
// reader is reached: the verifier calls it only on a spine that walk accepted, which narrows the reasons it can meet to a few item
// shapes (the verify-level tests), and it must still answer every other reason by name.

func regularHeaderItems(number uint64) []any {
	return []any{bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x1d}, 32), make([]byte, 20), bytes.Repeat([]byte{0x03}, 32), bytes.Repeat([]byte{0x04}, 32),
		bytes.Repeat([]byte{0x05}, 32), make([]byte, 256), uint64(0), number, uint64(30_000_000), uint64(1), 1_700_000_000 + number, []byte("x"), bytes.Repeat([]byte{0x06}, 32), make([]byte, 8)}
}

func encodeItems(t *testing.T, items []any) []byte {
	t.Helper()
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// spineOf is a descending spine of n regular headers numbered top, top-1, ...
func spineOf(t *testing.T, top uint64, n int) [][]byte {
	t.Helper()
	spine := make([][]byte, n)
	for i := range spine {
		spine[i] = encodeItems(t, regularHeaderItems(top-uint64(i)))
	}
	return spine
}

func TestHeaderNumberedNamesEveryReasonOfTheFrameworkHeaderReader(t *testing.T) {
	const top = uint64(1000)
	with := func(slot int, v any) []byte {
		items := regularHeaderItems(top - 2)
		items[slot] = v
		return encodeItems(t, items)
	}
	valid := encodeItems(t, regularHeaderItems(top-2))
	cases := []struct {
		reason finality.EvidenceReason
		index  any // nil: the state carries no index
		raw    []byte
	}{
		{finality.ReasonHeaderNotRLPList, nil, []byte{0x01}},
		{finality.ReasonHeaderTrailingBytes, nil, append(append([]byte(nil), valid...), 0x00)},
		{finality.ReasonHeaderBadItem, uint64(0), []byte{0xc2, 0x82, 0x01}},
		{finality.ReasonHeaderTooFewItems, nil, encodeItems(t, regularHeaderItems(top - 2)[:11])},
		{finality.ReasonHeaderItemNot32Bytes, uint64(0), with(0, make([]byte, 31))},
		{finality.ReasonHeaderItemNot32Bytes, uint64(3), with(3, make([]byte, 33))},
		{finality.ReasonHeaderItemNot32Bytes, uint64(4), with(4, make([]byte, 31))},
		{finality.ReasonHeaderItemNot32Bytes, uint64(5), with(5, make([]byte, 33))},
		{finality.ReasonHeaderItemIsList, uint64(5), with(5, []any{make([]byte, 32)})},
		{finality.ReasonHeaderItemNotCanonUint, uint64(8), with(8, []byte{0x00, 0x01})},
		{finality.ReasonHeaderItemNotCanonUint, uint64(11), with(11, make([]byte, 9))},
		{finality.ReasonHeaderItemIsList, uint64(16), encodeItems(t, append(regularHeaderItems(top-2), uint64(7), []any{make([]byte, 32)}))},
		{finality.ReasonHeaderItemNot32Bytes, uint64(16), encodeItems(t, append(regularHeaderItems(top-2), uint64(7), make([]byte, 31)))},
	}
	for pos := 0; pos < 5; pos++ {
		k := top - uint64(pos)
		for _, c := range cases {
			spine := spineOf(t, top, 5)
			spine[pos] = c.raw // the odd raw header is at K's position; its own number is never read
			h, err := headerNumbered(spine, top, k)
			st, named := finality.AsNamed(err)
			if !named || st.Code != CodeBlockHeaderUnreadable {
				t.Errorf("pos %d reason %s: got (%v, %v)", pos, c.reason, h, err)
				continue
			}
			want := map[string]any{"block_number": k, "finalized_exec_number": top, "reason": c.reason}
			if c.index != nil {
				want["index"] = c.index
			}
			if len(st.Fields) != len(want) {
				t.Errorf("pos %d reason %s: fields %v, want %v", pos, c.reason, st.Fields, want)
				continue
			}
			for key, v := range want {
				if fmt.Sprint(st.Fields[key]) != fmt.Sprint(v) {
					t.Errorf("pos %d reason %s: field %s = %v, want %v", pos, c.reason, key, st.Fields[key], v)
				}
			}
		}
	}
}

// A readable header of K is returned as read; the others are never read, whether regular or not.
func TestHeaderNumberedReadsOnlyKAndReturnsItsFields(t *testing.T) {
	const top = uint64(1000)
	for pos := 0; pos < 5; pos++ {
		spine := spineOf(t, top, 5)
		for i := range spine {
			if i != pos {
				spine[i] = []byte{0x01} // not a header at all: must not matter
			}
		}
		h, err := headerNumbered(spine, top, top-uint64(pos))
		if err != nil || h.Number != top-uint64(pos) || h.Items != 15 {
			t.Fatalf("pos %d: (%+v, %v)", pos, h, err)
		}
	}
}

// A block that is not on the spine keeps the state it always had: above the head, below the spine, or whose position does not hold it.
func TestHeaderNumberedKeepsNotCoveredForABlockOffTheSpine(t *testing.T) {
	const top = uint64(1000)
	spine := spineOf(t, top, 5)
	for _, k := range []uint64{top + 1, top - 5, 0, top + 1<<40} {
		_, err := headerNumbered(spine, top, k)
		f, ok := err.(*ethl1.Fault)
		if !ok || f.Code != ethl1.CodeBlockNotCovered || fmt.Sprint(f.Fields["block_number"]) != fmt.Sprint(k) || fmt.Sprint(f.Fields["finalized_exec_number"]) != fmt.Sprint(top) {
			t.Errorf("k %d: %v", k, err)
		}
	}
	// the header at K's position carries another number than K: the spine is not the one the walk accepted
	wrong := spineOf(t, top, 5)
	wrong[2] = encodeItems(t, regularHeaderItems(top-3))
	if _, err := headerNumbered(wrong, top, top-2); err == nil {
		t.Error("a header numbered top-3 at the position of top-2 was returned for top-2")
	} else if f, ok := err.(*ethl1.Fault); !ok || f.Code != ethl1.CodeBlockNotCovered {
		t.Errorf("wrong position: %v", err)
	}
}
