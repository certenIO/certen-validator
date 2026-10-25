// Copyright 2026 Certen Protocol

package ethl1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"golang.org/x/crypto/sha3"
)

// The helpers below encode RLP by hand, independently of the code under test, so every expectation in this file is a
// literal the verifier has to reproduce.

func tRlpLen(prefixShort byte, n int) []byte {
	if n < 56 {
		return []byte{prefixShort + byte(n)}
	}
	var be []byte
	for v := n; v > 0; v >>= 8 {
		be = append([]byte{byte(v)}, be...)
	}
	return append([]byte{prefixShort + 55 + byte(len(be))}, be...)
}

func tRlpStr(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(tRlpLen(0x80, len(b)), b...)
}

func tRlpList(items ...[]byte) []byte {
	payload := bytes.Join(items, nil)
	return append(tRlpLen(0xc0, len(payload)), payload...)
}

func tBE(v uint64) []byte {
	var out []byte
	for ; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	return out
}

func tKeccak(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func tFill(n int, v byte) []byte { return bytes.Repeat([]byte{v}, n) }

// tHeader builds an RLP header list with total items: parent at 0, state root at 3, number at 8, timestamp at 11.
func tHeader(parent, root [32]byte, number, ts uint64, total int) []byte {
	items := make([][]byte, total)
	for i := range items {
		items[i] = tRlpStr(tFill(i%5+2, byte(0x40+i)))
	}
	items[hdrParentHash] = tRlpStr(parent[:])
	items[hdrStateRoot] = tRlpStr(root[:])
	items[hdrNumber] = tRlpStr(tBE(number))
	items[hdrTimestamp] = tRlpStr(tBE(ts))
	return tRlpList(items...)
}

func tTwelve() [][]byte {
	out := make([][]byte, 12)
	for i := range out {
		out[i] = tRlpStr([]byte{0x90, byte(i)})
	}
	return out
}

func TestRlpHeaderItemsRefusesAndCountsByLiteralReason(t *testing.T) {
	long56 := tFill(56, 0xab)
	list55 := tRlpList(tRlpStr(tFill(54, 1)))
	if len(list55) != 55+1 {
		t.Fatalf("test helper: short list of payload 55 expected, got %d bytes", len(list55))
	}
	cases := []struct {
		name   string
		in     []byte
		count  int
		reason string
	}{
		{"empty input", nil, 0, "not_a_list"},
		{"string prefix 0xbf is no list", []byte{0xbf}, 0, "not_a_list"},
		{"single byte 0x00", []byte{0x00}, 0, "not_a_list"},
		{"empty list has no items", []byte{0xc0}, 0, "too_few_items"},
		{"short list payload overrun", []byte{0xc1}, 0, "list_length_mismatch"},
		{"short list payload short by one", []byte{0xc2, 0x80}, 0, "list_length_mismatch"},
		{"short list with one trailing byte", []byte{0xc0, 0x80}, 0, "list_length_mismatch"},
		{"long list header alone", []byte{0xf8}, 0, "list_length"},
		{"long list length byte zero", []byte{0xf8, 0x00, 0x80}, 0, "list_length"},
		{"long list five length bytes", []byte{0xfc, 1, 0, 0, 0, 0, 0}, 0, "list_length"},
		{"long list length bytes missing exactly one", []byte{0xf9, 0x01}, 0, "list_length"},
		{"long list one length byte and nothing else", []byte{0xf8, 0x38}, 0, "list_length_mismatch"},
		{"long list of payload 55 is not canonical", append([]byte{0xf8, 55}, tFill(55, 0x80)...), 0, "list_length_noncanonical"},
		{"long list of payload 56 is canonical", append([]byte{0xf8, 56}, tFill(56, 0x80)...), 56, ""},
		{"long list length one too long", append([]byte{0xf8, 57}, tFill(56, 0x80)...), 0, "list_length_mismatch"},
		{"long list length one too short", append([]byte{0xf8, 56}, tFill(57, 0x80)...), 0, "list_length_mismatch"},
		{"long list with a two byte length", append([]byte{0xf9, 0x01, 0x00}, tFill(256, 0x80)...), 256, ""},
		{"long list with a two byte length that is off by one", append([]byte{0xf9, 0x01, 0x00}, tFill(257, 0x80)...), 0, "list_length_mismatch"},
		{"short list of payload 55", list55, 1, "too_few_items"},
		{"eleven items", tRlpList(tTwelve()[:11]...), 11, "too_few_items"},
		{"twelve items", tRlpList(tTwelve()...), 12, ""},
		{"thirteen items", tRlpList(append(tTwelve(), tRlpStr([]byte{0x01}))...), 13, ""},
		{"single byte item then twelve", tRlpList(append([][]byte{{0x7f}}, tTwelve()...)...), 13, ""},
		{"string 0x81 with a canonical high byte", tRlpList(append(tTwelve()[:11], []byte{0x81, 0x80})...), 12, ""},
		{"string 0x81 0x7f is not canonical", tRlpList([]byte{0x81, 0x7f}), 0, "string_noncanonical"},
		{"string 0x81 0x00 is not canonical", tRlpList([]byte{0x81, 0x00}), 0, "string_noncanonical"},
		{"string 0x81 as the last byte overruns", tRlpList([]byte{0x81}), 0, "item_overruns"},
		{"string content one byte short", tRlpList([]byte{0x83, 1, 2}), 0, "item_overruns"},
		{"string content exactly fills the list", tRlpList([]byte{0x82, 1, 2}), 1, "too_few_items"},
		{"string of 55 bytes", tRlpList(append([]byte{0xb7}, tFill(55, 0x11)...)), 1, "too_few_items"},
		{"string of 56 bytes", tRlpList(append([]byte{0xb8, 56}, long56...)), 1, "too_few_items"},
		{"string 0xb8 of 55 is not canonical", tRlpList(append([]byte{0xb8, 55}, tFill(55, 0x11)...)), 0, "string_length_noncanonical"},
		{"string 0xb8 length zero", tRlpList([]byte{0xb8, 0x00, 0x11}), 0, "string_length"},
		{"string 0xb8 without length byte", tRlpList([]byte{0xb8}), 0, "string_length"},
		{"string 0xb8 with its length byte and no content", tRlpList([]byte{0xb8, 56}), 0, "item_overruns"},
		{"string 0xb9 with both length bytes and no content", tRlpList([]byte{0xb9, 0x01, 0x00}), 0, "item_overruns"},
		{"inner list 0xf8 with its length byte and no content", tRlpList([]byte{0xf8, 56}), 0, "item_overruns"},
		{"inner list 0xf9 with both length bytes and no content", tRlpList([]byte{0xf9, 0x01, 0x00}), 0, "item_overruns"},
		{"string 0xb9 with one length byte", tRlpList([]byte{0xb9, 0x01}), 0, "string_length"},
		{"string with five length bytes", tRlpList([]byte{0xbc, 1, 0, 0, 0, 0}), 0, "string_length"},
		{"string 0xbf", tRlpList([]byte{0xbf, 1, 0, 0, 0, 0, 0, 0, 0}), 0, "string_length"},
		{"string 0xb9 two length bytes", tRlpList(append([]byte{0xb9, 0x01, 0x00}, tFill(256, 0x22)...)), 1, "too_few_items"},
		{"string 0xb9 content one byte short", tRlpList(append([]byte{0xb9, 0x01, 0x00}, tFill(255, 0x22)...)), 0, "item_overruns"},
		{"string 0xb8 content one byte short", tRlpList(append([]byte{0xb8, 56}, tFill(55, 0x22)...)), 0, "item_overruns"},
		{"empty string items count", tRlpList([]byte{0x80, 0x80, 0x80}), 3, "too_few_items"},
		{"first item is a short list", tRlpList([]byte{0xc0}), 0, "item_not_string"},
		{"first item is a short list of 55", tRlpList(append([]byte{0xf7}, tFill(55, 0x80)...)), 0, "item_not_string"},
		{"first item is a long list", tRlpList(append([]byte{0xf8, 56}, tFill(56, 0x80)...)), 0, "item_not_string"},
		{"first item is a long list of 55", tRlpList(append([]byte{0xf8, 55}, tFill(55, 0x80)...)), 0, "list_length_noncanonical"},
		{"inner list length byte zero", tRlpList([]byte{0xf8, 0x00, 0x80}), 0, "list_length"},
		{"inner list with five length bytes", tRlpList([]byte{0xfc, 1, 0, 0, 0, 0}), 0, "list_length"},
		{"inner list long header only", tRlpList([]byte{0xf9, 0x01}), 0, "list_length"},
		{"inner list overruns", tRlpList([]byte{0xc5, 0x80}), 0, "item_overruns"},
		{"inner long list overruns", tRlpList([]byte{0xf8, 56, 0x80}), 0, "item_overruns"},
		{"inner short list after twelve strings", tRlpList(append(tTwelve(), []byte{0xc1, 0x80})...), 13, ""},
		{"inner long list after twelve strings", tRlpList(append(tTwelve(), append([]byte{0xf8, 56}, tFill(56, 0x80)...))...), 13, ""},
		{"inner list two length bytes after twelve strings", tRlpList(append(tTwelve(), append([]byte{0xf9, 0x01, 0x00}, tFill(256, 0x80)...))...), 13, ""},
		{"overrunning inner list after twelve strings", tRlpList(append(tTwelve(), []byte{0xc3, 0x80})...), 0, "item_overruns"},
		{"noncanonical string after twelve strings", tRlpList(append(tTwelve(), []byte{0x81, 0x05})...), 0, "string_noncanonical"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, n, reason := rlpHeaderItems(c.in)
			if n != c.count || reason != c.reason {
				t.Fatalf("got count=%d reason=%q, want count=%d reason=%q", n, reason, c.count, c.reason)
			}
		})
	}
}

func TestRlpHeaderItemsReturnsEveryPayloadAtItsPosition(t *testing.T) {
	var in [][]byte
	var want [12][]byte
	for i := 0; i < 14; i++ {
		var payload []byte
		switch {
		case i == 4:
			payload = nil
		case i == 5:
			payload = []byte{0x7f}
		case i == 6:
			payload = []byte{0x80}
		case i == 9:
			payload = tFill(56, 0x99)
		case i == 10:
			payload = tFill(300, 0x98)
		default:
			payload = tFill(i+2, byte(0x10+i))
		}
		in = append(in, tRlpStr(payload))
		if i < 12 {
			want[i] = payload
		}
	}
	items, n, reason := rlpHeaderItems(tRlpList(in...))
	if n != 14 || reason != "" {
		t.Fatalf("got count=%d reason=%q, want 14 and success", n, reason)
	}
	for i := range want {
		if !bytes.Equal(items[i], want[i]) || (want[i] == nil) != (len(items[i]) == 0) {
			t.Fatalf("item %d: got %x, want %x", i, items[i], want[i])
		}
	}
}

// A four-byte length is the widest the walker takes; payloads of 2^24 bytes are the smallest that need all four bytes.
func TestRlpHeaderItemsFourByteLengthsAreTheWidestTaken(t *testing.T) {
	big := tFill(1<<24, 0x33)
	str := append([]byte{0xbb, 0x01, 0x00, 0x00, 0x00}, big...)
	list := append([]byte{0xfb, 0x01, 0x00, 0x00, 0x00}, big...)
	cases := []struct {
		name  string
		items [][]byte
		count int
	}{
		{"string with a four byte length first", [][]byte{str}, 1},
		{"list with a four byte length after twelve strings", append(tTwelve(), list), 13},
	}
	for _, c := range cases {
		payload := bytes.Join(c.items, nil)
		outer := append([]byte{0xfb, byte(len(payload) >> 24), byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload))}, payload...)
		items, n, reason := rlpHeaderItems(outer)
		wantReason := ""
		if c.count < 12 {
			wantReason = "too_few_items"
		}
		if n != c.count || reason != wantReason {
			t.Fatalf("%s: got count=%d reason=%q, want count=%d reason=%q", c.name, n, reason, c.count, wantReason)
		}
		if c.count == 1 && len(items[0]) != 1<<24 {
			t.Fatalf("%s: first item has %d bytes, want %d", c.name, len(items[0]), 1<<24)
		}
	}
}

func TestRlpUint64(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		ok   bool
	}{
		{nil, 0, true},
		{[]byte{}, 0, true},
		{[]byte{0x00}, 0, false},
		{[]byte{0x00, 0x01}, 0, false},
		{[]byte{0x01}, 1, true},
		{[]byte{0x7f}, 0x7f, true},
		{[]byte{0x01, 0x00}, 256, true},
		{[]byte{0x12, 0x34}, 0x1234, true},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8}, 0x0102030405060708, true},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxUint64, true},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, 0, false},
		{tFill(9, 0xff), 0, false},
	}
	for _, c := range cases {
		got, ok := rlpUint64(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("rlpUint64(%x) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestReadSpineHeaderReadsPositionsAndNamesEachRefusal(t *testing.T) {
	parent := [32]byte{0xaa}
	root := [32]byte{0xbb, 0x01}
	raw := tHeader(parent, root, 0x0102030405, 0x60708090, 23)
	h, reason := readSpineHeader(raw)
	if reason != "" {
		t.Fatalf("valid header refused: %s", reason)
	}
	if h.parent != parent || h.stateRoot != root || h.number != 0x0102030405 || h.timestamp != 0x60708090 || h.hash != tKeccak(raw) {
		t.Fatalf("header misread: %+v", h)
	}
	if h.hash == ([32]byte{}) || h.parent == h.stateRoot {
		t.Fatal("hash, parent and state root must be distinct non-zero values")
	}
	itemsWith := func(mod func(items [][]byte)) []byte {
		items := make([][]byte, 12)
		for i := range items {
			items[i] = tRlpStr([]byte{0x70, byte(i)})
		}
		items[hdrParentHash] = tRlpStr(parent[:])
		items[hdrStateRoot] = tRlpStr(root[:])
		items[hdrNumber] = tRlpStr([]byte{0x05})
		items[hdrTimestamp] = tRlpStr([]byte{0x06})
		mod(items)
		return tRlpList(items...)
	}
	cases := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"not a list", []byte{0x01}, "not_a_list"},
		{"too few items", tRlpList(tTwelve()[:11]...), "too_few_items"},
		{"parent 31 bytes", itemsWith(func(i [][]byte) { i[hdrParentHash] = tRlpStr(parent[:31]) }), "hash_item_length"},
		{"parent 33 bytes", itemsWith(func(i [][]byte) { i[hdrParentHash] = tRlpStr(append(parent[:], 1)) }), "hash_item_length"},
		{"state root 31 bytes", itemsWith(func(i [][]byte) { i[hdrStateRoot] = tRlpStr(root[:31]) }), "hash_item_length"},
		{"state root 33 bytes", itemsWith(func(i [][]byte) { i[hdrStateRoot] = tRlpStr(append(root[:], 1)) }), "hash_item_length"},
		{"number with a leading zero", itemsWith(func(i [][]byte) { i[hdrNumber] = []byte{0x82, 0x00, 0x05} }), "number_item"},
		{"number of nine bytes", itemsWith(func(i [][]byte) { i[hdrNumber] = tRlpStr(tFill(9, 0x01)) }), "number_item"},
		{"timestamp with a leading zero", itemsWith(func(i [][]byte) { i[hdrTimestamp] = []byte{0x82, 0x00, 0x05} }), "timestamp_item"},
		{"timestamp of nine bytes", itemsWith(func(i [][]byte) { i[hdrTimestamp] = tRlpStr(tFill(9, 0x01)) }), "timestamp_item"},
	}
	for _, c := range cases {
		got, reason := readSpineHeader(c.raw)
		if reason != c.reason {
			t.Fatalf("%s: reason %q, want %q", c.name, reason, c.reason)
		}
		if got.hash != ([32]byte{}) {
			t.Fatalf("%s: a refused header must not carry a hash", c.name)
		}
	}
	// an empty number and an empty timestamp are zero, not refusals
	zero, reason := readSpineHeader(itemsWith(func(i [][]byte) { i[hdrNumber] = []byte{0x80}; i[hdrTimestamp] = []byte{0x80} }))
	if reason != "" || zero.number != 0 || zero.timestamp != 0 {
		t.Fatalf("empty number/timestamp: %+v %q", zero, reason)
	}
}

func hx(b [32]byte) string { return "0x" + hex.EncodeToString(b[:]) }

func TestCoversChecksEachLinkAndNamesTheBreak(t *testing.T) {
	root := func(n byte) [32]byte { return [32]byte{0xc0, n} }
	// headers 100, 99, 98 chained by hash
	h98 := tHeader([32]byte{0x97}, root(98), 98, 1980, 21)
	h99 := tHeader(tKeccak(h98), root(99), 99, 1990, 23)
	h100 := tHeader(tKeccak(h99), root(100), 100, 2000, 23)
	head := FinalizedHead{ExecHash: tKeccak(h100)}

	out, err := head.Covers([][]byte{h100, h99, h98}, 3)
	if err != nil {
		t.Fatalf("a valid spine of exactly max headers: %v", err)
	}
	want := []L1Block{
		{Hash: tKeccak(h100), Number: 100, StateRoot: root(100), Timestamp: 2000},
		{Hash: tKeccak(h99), Number: 99, StateRoot: root(99), Timestamp: 1990},
		{Hash: tKeccak(h98), Number: 98, StateRoot: root(98), Timestamp: 1980},
	}
	if len(out) != 3 || out[0] != want[0] || out[1] != want[1] || out[2] != want[2] {
		t.Fatalf("covered blocks %+v, want %+v", out, want)
	}
	one, err := head.Covers([][]byte{h100}, 1)
	if err != nil || len(one) != 1 || one[0] != want[0] {
		t.Fatalf("single header spine: %+v %v", one, err)
	}

	junk := []byte{0x01}
	wrongParent := tHeader([32]byte{0xde, 0xad}, root(99), 99, 1990, 23)
	// a top header at 99 whose hash link to the child is right but whose child carries number n
	numberCase := func(n uint64) (FinalizedHead, [][]byte, [32]byte) {
		child := tHeader([32]byte{0x55}, root(1), n, 1, 23)
		top := tHeader(tKeccak(child), root(99), 99, 1990, 23)
		return FinalizedHead{ExecHash: tKeccak(top)}, [][]byte{top, child}, tKeccak(child)
	}
	head97, spine97, hash97 := numberCase(97)
	head99, spine99, hash99 := numberCase(99)
	head100, spine100, hash100 := numberCase(100)
	zeroTop := tHeader([32]byte{0x56}, root(0), 0, 0, 23)
	wrapChild := tHeader([32]byte{0x57}, root(2), math.MaxUint64, 5, 23)
	wrapHead := FinalizedHead{ExecHash: tKeccak(zeroTop)}

	cases := []struct {
		name  string
		head  FinalizedHead
		spine [][]byte
		max   int
		want  string
	}{
		{"empty", head, nil, 3,
			`{"code":"finality_evidence_malformed","fields":{"got_len":"0","index":"0","part":"spine","reason":"empty","want_len":"1"}}`},
		{"one over max", head, [][]byte{h100, h99, h98}, 2,
			`{"code":"finality_evidence_too_large","fields":{"count":"3","limit":"2","part":"spine"}}`},
		{"first header not rlp", head, [][]byte{junk, h99}, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"0","got_hash":%q,"reason":"rlp","spine":"l1","want_hash":%q}}`, hx(tKeccak(junk)), hx(head.ExecHash))},
		{"second header not rlp", head, [][]byte{h100, junk}, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"99","got_hash":%q,"reason":"rlp","spine":"l1","want_hash":%q}}`, hx(tKeccak(junk)), hx(tKeccak(h99)))},
		{"first hash is not the finalized head", head, [][]byte{h99}, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"99","got_hash":%q,"reason":"hash","spine":"l1","want_hash":%q}}`, hx(tKeccak(h99)), hx(head.ExecHash))},
		{"second hash is not the parent", head, [][]byte{h100, wrongParent}, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"99","got_hash":%q,"reason":"hash","spine":"l1","want_hash":%q}}`, hx(tKeccak(wrongParent)), hx(tKeccak(h99)))},
		{"number two below the previous", head97, spine97, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"98","got_hash":%q,"reason":"number","spine":"l1","want_hash":%q}}`, hx(hash97), hx(hash97))},
		{"hash right but the number equals the previous", head99, spine99, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"98","got_hash":%q,"reason":"number","spine":"l1","want_hash":%q}}`, hx(hash99), hx(hash99))},
		{"hash right but the number is above the previous", head100, spine100, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"98","got_hash":%q,"reason":"number","spine":"l1","want_hash":%q}}`, hx(hash100), hx(hash100))},
		{"below block zero the number wraps and is still refused", wrapHead, [][]byte{zeroTop, wrapChild}, 3,
			fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"18446744073709551615","got_hash":%q,"reason":"hash","spine":"l1","want_hash":%q}}`, hx(tKeccak(wrapChild)), hx([32]byte{0x56}))},
	}
	for _, c := range cases {
		_, err := c.head.Covers(c.spine, c.max)
		if err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
		if err.Error() != c.want {
			t.Fatalf("%s:\n got %s\nwant %s", c.name, err.Error(), c.want)
		}
	}

	// number 0 at the top with a child whose hash matches and whose number is the wrapped value: refused by number
	zeroParent := tKeccak(h98)
	zeroTop2 := tHeader(zeroParent, root(0), 0, 0, 23)
	wrapChild2 := h98 // hash matches zeroParent; its number is 98, not the wrapped value
	_, err = FinalizedHead{ExecHash: tKeccak(zeroTop2)}.Covers([][]byte{zeroTop2, wrapChild2}, 3)
	if err == nil || err.Error() != fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"18446744073709551615","got_hash":%q,"reason":"number","spine":"l1","want_hash":%q}}`, hx(tKeccak(h98)), hx(zeroParent)) {
		t.Fatalf("a child of block zero: %v", err)
	}
	wrapped := tHeader([32]byte{0x01}, root(7), math.MaxUint64, 9, 23)
	zeroTop3 := tHeader(tKeccak(wrapped), root(0), 0, 0, 23)
	_, err = FinalizedHead{ExecHash: tKeccak(zeroTop3)}.Covers([][]byte{zeroTop3, wrapped}, 3)
	if err == nil || err.Error() != fmt.Sprintf(`{"code":"finality_header_chain_broken","fields":{"at_number":"18446744073709551615","got_hash":%q,"reason":"number","spine":"l1","want_hash":%q}}`, hx(tKeccak(wrapped)), hx(tKeccak(wrapped))) {
		t.Fatalf("a child of block zero that carries the wrapped number must still be refused: %v", err)
	}
}

func TestBlockAtBoundaries(t *testing.T) {
	covered := []L1Block{{Number: 10, Timestamp: 100}, {Number: 9, Timestamp: 90}, {Number: 8, Timestamp: 80}}
	for _, c := range []struct {
		number uint64
		ts     uint64
	}{{10, 100}, {9, 90}, {8, 80}} {
		b, err := BlockAt(covered, c.number)
		if err != nil || b.Number != c.number || b.Timestamp != c.ts {
			t.Fatalf("BlockAt(%d) = %+v %v", c.number, b, err)
		}
	}
	for _, n := range []uint64{11, 7, 0, math.MaxUint64} {
		_, err := BlockAt(covered, n)
		want := fmt.Sprintf(`{"code":"finality_block_not_covered","fields":{"block_number":"%d","finalized_exec_number":"10"}}`, n)
		if err == nil || err.Error() != want {
			t.Fatalf("BlockAt(%d): %v, want %s", n, err, want)
		}
	}
	_, err := BlockAt(nil, 5)
	if err == nil || err.Error() != `{"code":"finality_block_not_covered","fields":{"block_number":"5","finalized_exec_number":"0"}}` {
		t.Fatalf("empty covered: %v", err)
	}
	single := []L1Block{{Number: 3, Timestamp: 33}}
	if b, err := BlockAt(single, 3); err != nil || b.Timestamp != 33 {
		t.Fatalf("single: %+v %v", b, err)
	}
	if _, err := BlockAt(single, 2); err == nil {
		t.Fatal("a number one below a one-block spine must be refused")
	}
}
