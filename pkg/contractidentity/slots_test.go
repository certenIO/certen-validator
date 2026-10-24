// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func h32(s string) common.Hash { return common.HexToHash(s) }

func wantSlotReason(t *testing.T, err error, reason string) {
	t.Helper()
	var se *SlotError
	if !errors.As(err, &se) || !errors.Is(err, ErrSlot) || se.Reason != reason {
		t.Fatalf("want slot refusal %q, got %v", reason, err)
	}
}

func TestMappingSlotKeyEncodings(t *testing.T) {
	addr := common.HexToAddress("0x91C798AA0Ad11d2670029b3B0572d154bd42c059")
	// the address key is left-padded, the uint key big-endian, bytes32 verbatim, bytes4 right-padded
	if k := KeyAddress(addr); !bytes.Equal(k[:12], make([]byte, 12)) || !bytes.Equal(k[12:], addr[:]) {
		t.Fatalf("address key %x", k)
	}
	if k := KeyUint64(0x0102); k[30] != 1 || k[31] != 2 || !bytes.Equal(k[:30], make([]byte, 30)) {
		t.Fatalf("uint key %x", k)
	}
	if k := KeyBytes4([4]byte{0x57, 0x56, 0x52, 0xc2}); !bytes.Equal(k[:4], []byte{0x57, 0x56, 0x52, 0xc2}) || !bytes.Equal(k[4:], make([]byte, 28)) {
		t.Fatalf("bytes4 key %x", k)
	}
	if k := KeyBool(true); k[31] != 1 {
		t.Fatalf("bool key %x", k)
	}
	if _, err := KeyUint(big.NewInt(-1)); err == nil {
		t.Fatal("negative uint accepted")
	}
	if _, err := KeyUint(new(big.Int).Lsh(big.NewInt(1), 256)); err == nil {
		t.Fatal("257-bit uint accepted")
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if k, err := KeyUint(max); err != nil || !bytes.Equal(k[:], bytes.Repeat([]byte{0xff}, 32)) {
		t.Fatalf("2^256-1 refused: %v", err)
	}
	// the formula itself: keccak256(key || base)
	ka := KeyAddress(addr)
	want := crypto.Keccak256(append(ka[:], SlotIndex(28).Bytes()...))
	if got := MappingSlotAt(KeyAddress(addr), 28); got != common.BytesToHash(want) {
		t.Fatalf("operators slot %s want %x", got.Hex(), want)
	}
	// the operators row of the manifest: operators[0x91C7...] at slot 28 on Sepolia
	if got := MappingSlotAt(KeyAddress(addr), 28); got != h32("0x94bf703a529a3df38f0abaeaa8c71daea7a66817d1c4a604e61d1c6288ba0b7e") {
		t.Fatalf("operators[owner] = %s", got.Hex())
	}
}

func TestNestedMappingSlotIsStep14Form(t *testing.T) {
	book := h32("0xb00cb00cb00cb00cb00cb00cb00cb00cb00cb00cb00cb00cb00cb00cb00cb00c")
	// keccak256(abi.encode(uint256(page), keccak256(abi.encode(book, uint256(slot)))))
	inner := crypto.Keccak256(append(book.Bytes(), SlotIndex(10).Bytes()...))
	k2 := KeyUint64(2)
	want := crypto.Keccak256(append(k2[:], inner...))
	if got := PageSlot(10, book, 2); got != common.BytesToHash(want) {
		t.Fatalf("PageSlot %s want %x", got.Hex(), want)
	}
	// the two levels are not interchangeable and each key and base matters
	seen := map[common.Hash]string{}
	for _, c := range []struct {
		name string
		s    common.Hash
	}{
		{"base10 page2", PageSlot(10, book, 2)},
		{"base9 page2", PageSlot(9, book, 2)},
		{"base10 page1", PageSlot(10, book, 1)},
		{"base10 page0", PageSlot(10, book, 0)},
		{"swapped", NestedMappingSlot(10, KeyUint64(2), KeyBytes32(book))},
		{"single level", MappingSlotAt(KeyBytes32(book), 10)},
	} {
		if prev, ok := seen[c.s]; ok {
			t.Fatalf("%s collides with %s", c.name, prev)
		}
		seen[c.s] = c.name
	}
}

func TestArrayElementSlotBoundaries(t *testing.T) {
	start := ArrayDataStart(13)
	if want := common.BytesToHash(crypto.Keccak256(SlotIndex(13).Bytes())); start != want {
		t.Fatalf("data start %s want %s", start.Hex(), want.Hex())
	}
	// the live-verified F-S8-5 row: validatorList[0] of the Sepolia anchor at base 13
	if start != h32("0xd7b6990105719101dabeb77144f2a3385c8033acd3af97e9423a695e81ad1eb5") {
		t.Fatalf("validatorList[0] slot %s", start.Hex())
	}
	for _, c := range []struct {
		elemBytes   int
		index       uint64
		addToStart  uint64
		offsetBytes int
	}{
		{20, 0, 0, 0}, {20, 1, 1, 0}, {20, 63, 63, 0}, // address[]: one per slot (itemsPerSlot 1)
		{32, 5, 5, 0},
		{16, 0, 0, 0}, {16, 1, 0, 16}, {16, 2, 1, 0}, {16, 3, 1, 16}, {16, 4, 2, 0}, // uint128[]: two per slot
		{1, 31, 0, 31}, {1, 32, 1, 0}, // bytes1[]: 32 per slot, the slot edge
		{8, 3, 0, 24}, {8, 4, 1, 0}, // uint64[]: 4 per slot
	} {
		slot, off, err := ArrayElementSlot(13, c.index, c.elemBytes)
		if err != nil {
			t.Fatal(err)
		}
		want := new(big.Int).Add(new(big.Int).SetBytes(start[:]), new(big.Int).SetUint64(c.addToStart))
		if slot != common.BigToHash(want) || off != c.offsetBytes {
			t.Fatalf("elem %d index %d: slot %s off %d, want +%d off %d", c.elemBytes, c.index, slot.Hex(), off, c.addToStart, c.offsetBytes)
		}
	}
	// the wrong formula of F-S8-5 (floor(i*elementBytes/32)) differs from the right one for address[] at index 1
	right, _, _ := ArrayElementSlot(13, 1, 20)
	wrong := common.BigToHash(new(big.Int).Add(new(big.Int).SetBytes(start[:]), new(big.Int).SetUint64(1*20/32)))
	if right == wrong {
		t.Fatal("F-S8-5: the corrected formula equals the defective one")
	}
	for _, bad := range []int{0, -1, 33, 1000} {
		if _, _, err := ArrayElementSlot(13, 0, bad); err == nil {
			t.Fatalf("element size %d accepted", bad)
		} else {
			wantSlotReason(t, err, SlotReasonElementBytes)
		}
	}
	if p, _ := ArrayItemsPerSlot(20); p != 1 {
		t.Fatalf("address[] itemsPerSlot %d", p)
	}
	if p, _ := ArrayItemsPerSlot(17); p != 1 {
		t.Fatalf("17-byte itemsPerSlot %d", p)
	}
	if p, _ := ArrayItemsPerSlot(16); p != 2 {
		t.Fatalf("uint128[] itemsPerSlot %d", p)
	}
}

func TestArrayElementSlotWrapsModulo2To256(t *testing.T) {
	// the slot arithmetic is EVM addition: a base whose data start is 2^256-1 wraps to 0 at index 1 (search a base is infeasible,
	// so check addToSlot, the one place the arithmetic lives)
	top := common.BigToHash(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)))
	if got := addToSlot(top, big.NewInt(1)); got != (common.Hash{}) {
		t.Fatalf("2^256-1 + 1 = %s", got.Hex())
	}
	if got := MemberSlot(top, 2); got != h32("0x01") {
		t.Fatalf("member slot wrap %s", got.Hex())
	}
	if got := MemberSlot(h32("0x0a"), 3); got != h32("0x0d") {
		t.Fatalf("member slot %s", got.Hex())
	}
}

func TestPackedExtractionCountsFromTheLeastSignificantByte(t *testing.T) {
	// anchors[id] word 10: validator b0-b19, valid b20, proofExecuted b21, governanceExecuted b22, governanceLevel b23, bytes 24-31 zero
	var w common.Hash
	val := common.HexToAddress("0xd4A3dBbAE0C04D4307c5E00A5E05b66AcC289f5D")
	copy(w[12:], val[:]) // bytes 0..19 are word[31..12]
	w[31-20], w[31-21], w[31-22], w[31-23] = 1, 1, 0, 4
	if a, err := PackedAddress(w, 0); err != nil || a != val {
		t.Fatalf("validator %v %v", a, err)
	}
	for off, want := range map[int]bool{20: true, 21: true, 22: false} {
		if b, err := PackedBool(w, off); err != nil || b != want {
			t.Fatalf("bool b%d = %v %v", off, b, err)
		}
	}
	if v, err := PackedUint64(w, 23, 1); err != nil || v != 4 {
		t.Fatalf("governanceLevel %d %v", v, err)
	}
	if v, err := PackedUint64(w, 20, 3); err != nil || v != 0x0101 {
		t.Fatalf("b20..b22 as uint %#x %v", v, err)
	}
	// bytes 24..31 are zero here: reading them as a uint64 gives 0, and the word's high byte is b31
	if v, err := PackedUint64(w, 24, 8); err != nil || v != 0 {
		t.Fatalf("b24..b31 %d %v", v, err)
	}
	// boundaries: offset+length == 32 passes, 33 fails; zero and negative lengths fail; length > 8 as uint fails
	if _, err := PackedBytes(w, 31, 1); err != nil {
		t.Fatalf("b31: %v", err)
	}
	if b, _ := PackedBytes(w, 0, 32); !bytes.Equal(b, w[:]) {
		t.Fatal("full-word read differs")
	}
	for _, c := range [][2]int{{31, 2}, {0, 33}, {32, 1}, {-1, 1}, {0, 0}, {5, -2}} {
		if _, err := PackedBytes(w, c[0], c[1]); err == nil {
			t.Fatalf("offset %d length %d accepted", c[0], c[1])
		} else {
			wantSlotReason(t, err, SlotReasonOffsetRange)
		}
	}
	if _, err := PackedUint64(w, 0, 9); err == nil {
		t.Fatal("9-byte uint64 accepted")
	} else {
		wantSlotReason(t, err, SlotReasonPackedNotUint64)
	}
	// a packed bool byte of 2 is refused
	w[31-22] = 2
	if _, err := PackedBool(w, 22); err == nil {
		t.Fatal("bool byte 2 accepted")
	} else {
		wantSlotReason(t, err, SlotReasonWordNotBool)
	}
}

func TestWholeWordReaders(t *testing.T) {
	var w common.Hash
	w[31] = 1
	if b, err := WordBool(w); err != nil || !b {
		t.Fatal("bool 1")
	}
	w[31] = 2
	if _, err := WordBool(w); err == nil {
		t.Fatal("bool 2 accepted")
	}
	w = common.Hash{}
	w[0] = 1
	if _, err := WordBool(w); err == nil {
		t.Fatal("bool with a high byte accepted")
	}
	if _, err := WordUint64(w); err == nil {
		t.Fatal("uint64 with a high byte accepted")
	}
	w = common.Hash{}
	w[23] = 1
	if _, err := WordUint64(w); err == nil {
		t.Fatal("uint64 with byte 23 set accepted")
	}
	w = common.Hash{}
	w[24] = 1
	if v, err := WordUint64(w); err != nil || v != 1<<56 {
		t.Fatalf("uint64 %d %v", v, err)
	}
	w = common.Hash{}
	w[11] = 1
	if _, err := WordAddress(w); err == nil {
		t.Fatal("address with a high byte accepted")
	}
	w = common.Hash{}
	w[12] = 1
	if a, err := WordAddress(w); err != nil || a[0] != 1 {
		t.Fatalf("address %v %v", a, err)
	}
}

func shortHead(data string) common.Hash {
	var w common.Hash
	copy(w[:], data)
	w[31] = byte(2 * len(data))
	return w
}

func TestDynHeadBoundaries(t *testing.T) {
	const max = 1024
	// empty
	h, err := ParseDynHead(common.Hash{}, max)
	if err != nil || h.Long || h.Length != 0 || len(h.Short) != 0 {
		t.Fatalf("empty %+v %v", h, err)
	}
	// short of 31 bytes: the largest short value, low byte 62
	d31 := strings.Repeat("a", 31)
	w31 := shortHead(d31)
	if w31[31] != 62 {
		t.Fatalf("low byte %d", w31[31])
	}
	h, err = ParseDynHead(w31, max)
	if err != nil || h.Long || string(h.Short) != d31 || h.Length != 31 {
		t.Fatalf("short 31 %+v %v", h, err)
	}
	// 32 bytes is LONG: the head is 2*32+1 = 65
	var w32 common.Hash
	w32[31] = 65
	h, err = ParseDynHead(w32, max)
	if err != nil || !h.Long || h.Length != 32 || h.DynWordCount() != 1 {
		t.Fatalf("long 32 %+v %v", h, err)
	}
	// 33 bytes: 67, two data words
	var w33 common.Hash
	w33[31] = 67
	h, err = ParseDynHead(w33, max)
	if err != nil || !h.Long || h.Length != 33 || h.DynWordCount() != 2 {
		t.Fatalf("long 33 %+v %v", h, err)
	}
	// an even low byte above 62 is no value at all; a long head for a short length is non-canonical
	var bad common.Hash
	bad[31] = 64
	_, err = ParseDynHead(bad, max)
	wantSlotReason(t, err, SlotReasonDynHeadInvalid)
	bad[31] = 63 // long form of length 31
	_, err = ParseDynHead(bad, max)
	wantSlotReason(t, err, SlotReasonDynHeadInvalid)
	bad[31] = 1 // long form of length 0
	_, err = ParseDynHead(bad, max)
	wantSlotReason(t, err, SlotReasonDynHeadInvalid)
	// non-zero padding in a short value
	pad := shortHead("abc")
	pad[10] = 1
	_, err = ParseDynHead(pad, max)
	wantSlotReason(t, err, SlotReasonDynPadding)
	// bounds: N passes, N+1 fails (short and long), and a length beyond 64 bits fails before any read
	var wl common.Hash
	new(big.Int).SetUint64(2*max + 1).FillBytes(wl[24:])
	if _, err := ParseDynHead(wl, max); err != nil {
		t.Fatalf("limit length refused: %v", err)
	}
	new(big.Int).SetUint64(2*(max+1) + 1).FillBytes(wl[24:])
	_, err = ParseDynHead(wl, max)
	wantSlotReason(t, err, SlotReasonDynTooLong)
	_, err = ParseDynHead(w31, 30)
	wantSlotReason(t, err, SlotReasonDynTooLong)
	if _, err = ParseDynHead(w31, 31); err != nil {
		t.Fatal(err)
	}
	huge := common.Hash{}
	huge[0], huge[31] = 0x80, 1
	_, err = ParseDynHead(huge, max)
	wantSlotReason(t, err, SlotReasonDynTooLong)
	huge = common.Hash{}
	huge[23], huge[31] = 1, 1
	_, err = ParseDynHead(huge, max)
	wantSlotReason(t, err, SlotReasonDynTooLong)
}

func TestDynAssemble(t *testing.T) {
	slot := SlotIndex(11)
	if DynDataSlot(slot, 0) != common.BytesToHash(crypto.Keccak256(slot.Bytes())) {
		t.Fatal("data start")
	}
	if DynDataSlot(slot, 3) != addToSlot(DynDataSlot(slot, 0), big.NewInt(3)) {
		t.Fatal("data word 3")
	}
	data := []byte(strings.Repeat("0123456789", 7)) // 70 bytes: 3 words
	head := DynHead{Long: true, Length: 70}
	var words []common.Hash
	for i := 0; i < 3; i++ {
		var w common.Hash
		copy(w[:], data[i*32:])
		words = append(words, w)
	}
	got, err := head.Assemble(words)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("assemble %q %v", got, err)
	}
	// 64 bytes exactly: two full words, no padding to check
	h64 := DynHead{Long: true, Length: 64}
	if got, err := h64.Assemble(words[:2]); err != nil || len(got) != 64 {
		t.Fatalf("64 bytes: %v", err)
	}
	// the word count must match exactly (a missing and an extra data word)
	if _, err := head.Assemble(words[:2]); err == nil {
		t.Fatal("missing data word accepted")
	} else {
		wantSlotReason(t, err, SlotReasonDynWordCount)
	}
	if _, err := head.Assemble(append(append([]common.Hash{}, words...), common.Hash{})); err == nil {
		t.Fatal("extra data word accepted")
	}
	// non-zero byte after the value in the last word
	words[2][31] = 1
	if _, err := head.Assemble(words); err == nil {
		t.Fatal("padding byte accepted")
	} else {
		wantSlotReason(t, err, SlotReasonDynPadding)
	}
	// short values take no data words
	sh := DynHead{Length: 3, Short: []byte("abc")}
	if got, err := sh.Assemble(nil); err != nil || string(got) != "abc" {
		t.Fatal("short assemble")
	}
	if _, err := sh.Assemble(words[:1]); err == nil {
		t.Fatal("short value with data words accepted")
	}
	// Assemble returns a copy
	got, _ = sh.Assemble(nil)
	got[0] = 'z'
	if sh.Short[0] != 'a' {
		t.Fatal("Assemble aliased the head")
	}
}

// ---- the manifest slotChecks rows (live-verified) ----

type slotCheckRow struct {
	ChainID      uint64   `json:"chainId"`
	Contract     string   `json:"contract"`
	Address      string   `json:"address"`
	Label        string   `json:"label"`
	Slot         string   `json:"slot"`
	ValueType    string   `json:"valueType"`
	Formula      string   `json:"formula"`
	Kind         string   `json:"kind"`
	Key          *string  `json:"key"`
	BaseSlot     *uint64  `json:"baseSlot"`
	Index        *uint64  `json:"index"`
	ItemsPerSlot *uint64  `json:"itemsPerSlot"`
	ByteOffset   *int     `json:"byteOffset"`
	LengthSlot   *uint64  `json:"lengthSlot"`
	Args         []string `json:"args"`
	StoredWord   string   `json:"storedWord"`
	Call         *struct {
		Args []string `json:"args"`
	} `json:"call"`
}

func (r slotCheckRow) args() []string {
	if r.Call != nil {
		return r.Call.Args
	}
	return r.Args
}

var (
	reScalar  = regexp.MustCompile(`^scalar: slot (\d+)`)
	rePacked  = regexp.MustCompile(`^slot (\d+): bytes`)
	reMapping = regexp.MustCompile(`^keccak256\(abi\.encode\((address|bytes32|bytes4)[^,]*, uint256\((\d+)\)\)\)`)
	reArray   = regexp.MustCompile(`^keccak256\(abi\.encode\(uint256\((\d+)\)\)\) \+ floor\((\d+) / (\d+)\)`)
)

type slotCheckTally struct {
	scalar, packed, array, mapping, dynString int
	keyNotRecorded                            []string
}

func keyFor(r slotCheckRow, typ string, sib func(label string) []*slotCheckRow) ([]SlotKey, bool) {
	var raws []string
	switch {
	case r.Key != nil:
		raws = []string{*r.Key}
	case len(r.args()) == 1:
		raws = []string{r.args()[0]}
	default:
		src := map[string]string{"validators": "validatorList", "anchors": "anchorIds", "_deployedAccounts": "_allAccounts"}[r.Label]
		if src == "" {
			return nil, false
		}
		for _, s := range sib(src) {
			raws = append(raws, s.StoredWord)
		}
		if len(raws) == 0 {
			return nil, false
		}
	}
	var out []SlotKey
	for _, raw := range raws {
		b, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
		if err != nil {
			return nil, false
		}
		switch typ {
		case "address":
			if len(b) == 32 { // a stored word
				a, err := WordAddress(common.BytesToHash(b))
				if err != nil {
					return nil, false
				}
				out = append(out, KeyAddress(a))
			} else if len(b) == 20 {
				out = append(out, KeyAddress(common.BytesToAddress(b)))
			} else {
				return nil, false
			}
		case "bytes32":
			if len(b) != 32 {
				return nil, false
			}
			out = append(out, KeyBytes32(common.BytesToHash(b)))
		case "bytes4":
			if len(b) != 32 || !bytes.Equal(b[4:], make([]byte, 28)) {
				return nil, false
			}
			out = append(out, KeyBytes4([4]byte(b[:4])))
		default:
			return nil, false
		}
	}
	return out, true
}

func checkSlotRows(t *testing.T, rows []slotCheckRow) slotCheckTally {
	t.Helper()
	var tally slotCheckTally
	for i, r := range rows {
		id := strconv.Itoa(i) + ":" + r.Label + "@" + strconv.FormatUint(r.ChainID, 10)
		want := h32(r.Slot)
		// a row without a recorded key is checked against EVERY key of the sibling row set that lists the key space on the same chain and
		// contract (validators against validatorList[0..6], anchors against anchorIds, _deployedAccounts against _allAccounts): it must match one
		sib := func(label string) []*slotCheckRow {
			var out []*slotCheckRow
			for j := range rows {
				if rows[j].ChainID == r.ChainID && rows[j].Contract == r.Contract && rows[j].Label == label {
					out = append(out, &rows[j])
				}
			}
			return out
		}
		switch {
		case r.Kind == "arrayElement":
			elem := 32
			if r.ItemsPerSlot != nil && *r.ItemsPerSlot > 1 {
				elem = int(32 / *r.ItemsPerSlot)
			}
			got, off, err := ArrayElementSlot(*r.LengthSlot, *r.Index, elem)
			if err != nil || got != want {
				t.Fatalf("%s: array slot %s want %s (%v)", id, got.Hex(), want.Hex(), err)
			}
			if per, _ := ArrayItemsPerSlot(elem); per != *r.ItemsPerSlot || off != *r.ByteOffset {
				t.Fatalf("%s: itemsPerSlot %d offset %d, manifest %d / %d", id, per, off, *r.ItemsPerSlot, *r.ByteOffset)
			}
			// address[] elements are read as addresses, bytes32[] as words; both are whole words here
			if r.ValueType == "address" {
				if _, err := WordAddress(h32(r.StoredWord)); err != nil {
					t.Fatalf("%s: %v", id, err)
				}
			}
			tally.array++
		case reScalar.MatchString(r.Formula):
			n, _ := strconv.ParseUint(reScalar.FindStringSubmatch(r.Formula)[1], 10, 64)
			if SlotIndex(n) != want {
				t.Fatalf("%s: scalar slot %d is %s", id, n, want.Hex())
			}
			tally.scalar++
		case rePacked.MatchString(r.Formula):
			n, _ := strconv.ParseUint(rePacked.FindStringSubmatch(r.Formula)[1], 10, 64)
			if SlotIndex(n) != want {
				t.Fatalf("%s: packed slot %d is %s", id, n, want.Hex())
			}
			// slot 30 of the anchor: blsZKVerifier b0-b19, blsZKVerificationEnabled b20 (0/1), minimumGovernanceLevel b21, ForValueOps b22
			w := h32(r.StoredWord)
			if _, err := PackedAddress(w, 0); err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			if _, err := PackedBool(w, 20); err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			tally.packed++
		case strings.HasPrefix(r.Formula, "string storage rule"):
			if _, err := ParseDynHead(h32(r.StoredWord), 1024); err != nil {
				t.Fatalf("%s: string head %s: %v", id, r.StoredWord, err)
			}
			if r.Slot != "0x0" && r.Slot != "0xb" {
				t.Fatalf("%s: string slot %s", id, r.Slot)
			}
			tally.dynString++
		case reMapping.MatchString(r.Formula):
			m := reMapping.FindStringSubmatch(r.Formula)
			base, _ := strconv.ParseUint(m[2], 10, 64)
			keys, ok := keyFor(r, m[1], sib)
			if !ok {
				tally.keyNotRecorded = append(tally.keyNotRecorded, id)
				continue
			}
			matched := false
			for _, key := range keys {
				if MappingSlotAt(key, base) == want {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("%s: no candidate key (%d) derives slot %s (type %s base %d)", id, len(keys), want.Hex(), m[1], base)
			}
			tally.mapping++
		default:
			t.Fatalf("%s: unclassified slotChecks formula %q", id, r.Formula)
		}
	}
	return tally
}

func TestSlotChecksCoverage(t *testing.T) {
	raw, err := os.ReadFile("testdata/contractidentity/slots/slotchecks.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Source string         `json:"source"`
		Rows   []slotCheckRow `json:"rows"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(doc.Source, "991de99fb47db8ec89c5aa107a2d503b0ee30814") {
		t.Fatalf("source %q", doc.Source)
	}
	tally := checkSlotRows(t, doc.Rows)
	total := tally.scalar + tally.packed + tally.array + tally.mapping + tally.dynString + len(tally.keyNotRecorded)
	if total != len(doc.Rows) || len(doc.Rows) != 188 {
		t.Fatalf("classified %d of %d rows (%+v)", total, len(doc.Rows), tally)
	}
	// Pinned census: every row is either re-derived or listed by name as a row whose key the manifest does not record.
	if tally.scalar != 64 || tally.packed != 4 || tally.array != 36 || tally.mapping != 68 || tally.dynString != 8 {
		t.Fatalf("census %+v", tally)
	}
	sort.Strings(tally.keyNotRecorded)
	for _, id := range tally.keyNotRecorded {
		if !strings.Contains(id, "_adiToAccount") && !strings.Contains(id, "_consumedLeaf") {
			t.Fatalf("a row other than _adiToAccount / _consumedLeaf lacks its key: %s", id)
		}
	}
	if len(tally.keyNotRecorded) != 8 {
		t.Fatalf("rows without a recorded key: %v", tally.keyNotRecorded)
	}
	t.Logf("slotChecks: %d scalar, %d packed, %d array elements, %d mapping rows re-derived, %d strings, %d rows without a recorded key %v",
		tally.scalar, tally.packed, tally.array, tally.mapping, tally.dynString, len(tally.keyNotRecorded), tally.keyNotRecorded)
}

func TestEmbeddedManifestSlotChecksRederive(t *testing.T) {
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var rows []slotCheckRow
	if err := json.Unmarshal(m.Section("slotChecks"), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("the embedded manifest has no slotChecks")
	}
	tally := checkSlotRows(t, rows)
	if tally.mapping == 0 || tally.array == 0 {
		t.Fatalf("nothing re-derived: %+v", tally)
	}
}
