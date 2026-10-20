// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
)

// RB11-GATE-A: tests added so that the mutants of tools\pv2mut.ps1 over the framework files are killed. Each test pins a boundary,
// an error path or a strictness helper that the vector judges and the behaviour tests reach only on their happy path. Every
// expectation is a literal (a count, a reason, a byte), never computed from the code under test.

func wantNamed(t *testing.T, err error, code string, kv ...any) *StateError {
	t.Helper()
	st, ok := AsNamed(err)
	if !ok {
		t.Fatalf("want the named state %s, got %v", code, err)
	}
	if st.Code != code {
		t.Fatalf("want %s, got %s", code, st.Error())
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if got := fmt.Sprint(st.Fields[fmt.Sprint(kv[i])]); got != fmt.Sprint(kv[i+1]) {
			t.Fatalf("%s: field %v is %q, want %q", st.Error(), kv[i], got, fmt.Sprint(kv[i+1]))
		}
	}
	return st
}

func TestReaderPrimitivesRefuseOneByteShortAndAcceptExactlyEnough(t *testing.T) {
	lim := DefaultLimits()
	for _, c := range []struct {
		name string
		n    int
		read func(r *Reader) error
	}{
		{"u8", 1, func(r *Reader) error { _, err := r.U8("p"); return err }},
		{"u32", 4, func(r *Reader) error { _, err := r.U32("p"); return err }},
		{"u64", 8, func(r *Reader) error { _, err := r.U64("p"); return err }},
		{"fixed3", 3, func(r *Reader) error { _, err := r.Fixed("p", 3); return err }},
	} {
		if err := c.read(NewReader(make([]byte, c.n), lim)); err != nil {
			t.Errorf("%s: exactly %d bytes were refused: %v", c.name, c.n, err)
		}
		short := NewReader(make([]byte, c.n-1), lim)
		wantNamed(t, c.read(short), CodeEvidenceMalformed, "part", "p", "reason", ReasonTruncated, "got_len", c.n-1, "want_len", c.n)
	}
	wantNamed(t, func() error { _, err := NewReader(nil, lim).U8("p"); return err }(), CodeEvidenceMalformed, "reason", ReasonTruncated)
	v, err := NewReader([]byte{0x80}, lim).U8("p")
	if err != nil || v != 0x80 {
		t.Fatalf("u8 %d %v", v, err)
	}
	u32, err := NewReader([]byte{0, 0, 1, 2}, lim).U32("p")
	if err != nil || u32 != 258 {
		t.Fatalf("u32 %d %v", u32, err)
	}
	u64, err := NewReader([]byte{0, 0, 0, 0, 0, 0, 1, 2}, lim).U64("p")
	if err != nil || u64 != 258 {
		t.Fatalf("u64 %d %v", u64, err)
	}
}

func TestReaderLPBoundsAreExactAndTheLengthPrefixCanBeShort(t *testing.T) {
	lim := DefaultLimits()
	lp := func(n uint32, body ...byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, n), body...)
	}
	// the u32 length itself is short
	_, err := NewReader([]byte{0, 0}, lim).LP("p", 10)
	wantNamed(t, err, CodeEvidenceMalformed, "part", "p.len", "reason", ReasonTruncated)
	// n == max is accepted, n == max+1 is the bound's refusal with the number
	got, err := NewReader(lp(1, 9), lim).LP("p", 1)
	if err != nil || !bytes.Equal(got, []byte{9}) {
		t.Fatalf("n == max was refused: %v", err)
	}
	_, err = NewReader(lp(2, 9, 9), lim).LP("p", 1)
	wantNamed(t, err, CodeEvidenceTooLarge, "part", "p", "count", 2, "limit", 1)
	// max 0 is a bound of zero, not "unbounded"
	_, err = NewReader(lp(1, 9), lim).LP("p", 0)
	wantNamed(t, err, CodeEvidenceTooLarge, "limit", 0)
	got, err = NewReader(lp(0), lim).LP("p", 0)
	if err != nil || len(got) != 0 {
		t.Fatalf("an empty LP under max 0: %v", err)
	}
	// a negative max leaves only the remaining length as the bound
	got, err = NewReader(lp(3, 1, 2, 3), lim).LP("p", -1)
	if err != nil || len(got) != 3 {
		t.Fatalf("max -1: %v", err)
	}
	_, err = NewReader(lp(5, 1, 2), lim).LP("p", -1)
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonLengthExceedsRemaining, "got_len", 2, "want_len", 5)
	_, err = NewReader(lp(5, 1, 2), lim).LP("p", 100)
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonLengthExceedsRemaining)
}

func TestReaderSTRAcceptsSevenBitNonNULAndRefusesTheRest(t *testing.T) {
	lim := DefaultLimits()
	str := func(b ...byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	got, err := NewReader(str(0x01, 0x7f, 'a'), lim).STR("p")
	if err != nil || got != "\x01\x7fa" {
		t.Fatalf("0x7f is ASCII and must be accepted: %q %v", got, err)
	}
	for _, bad := range []byte{0x00, 0x80, 0xff} {
		_, err := NewReader(str('a', bad), lim).STR("p")
		wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonStrNotASCIIOrNUL, "index", 1)
	}
	_, err = NewReader(str(make([]byte, 0)...), lim).STR("p")
	if err != nil {
		t.Fatalf("empty STR: %v", err)
	}
}

func TestReaderCountBoundsAreExact(t *testing.T) {
	lim := DefaultLimits()
	count := func(n uint32, extra int) []byte {
		return append(binary.BigEndian.AppendUint32(nil, n), make([]byte, extra)...)
	}
	_, err := NewReader([]byte{0}, lim).Count("p", 5, 1)
	wantNamed(t, err, CodeEvidenceMalformed, "part", "p.count", "reason", ReasonTruncated)
	if n, err := NewReader(count(2, 2), lim).Count("p", 2, 1); err != nil || n != 2 {
		t.Fatalf("n == limit and exactly fitting: %d %v", n, err)
	}
	_, err = NewReader(count(3, 9), lim).Count("p", 2, 1)
	wantNamed(t, err, CodeEvidenceTooLarge, "count", 3, "limit", 2)
	// minElem 1: two elements need two bytes
	_, err = NewReader(count(2, 1), lim).Count("p", 5, 1)
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonCountExceedsRemaining, "got_len", 1, "want_len", 2)
	// minElem 4 (an LP list): one byte short of n*4 is refused, exactly n*4 is accepted
	_, err = NewReader(count(2, 7), lim).Count("p", 5, 4)
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonCountExceedsRemaining)
	if n, err := NewReader(count(2, 8), lim).Count("p", 5, 4); err != nil || n != 2 {
		t.Fatalf("exact fit at minElem 4: %d %v", n, err)
	}
	// minElem 0 states no per-element floor
	if n, err := NewReader(count(1000, 0), lim).Count("p", 5000, 0); err != nil || n != 1000 {
		t.Fatalf("minElem 0: %d %v", n, err)
	}
}

func TestEncodeNodesSortsByKeccakDropsDuplicatesAndReaderNodesRefusesEqualHashes(t *testing.T) {
	a, b, c := []byte("node-a"), []byte("node-b"), []byte("node-c")
	enc := EncodeNodes([][]byte{c, a, b, a, c})
	if len(enc) != 3 {
		t.Fatalf("%d nodes after dedupe", len(enc))
	}
	var w Writer
	w.Nodes(enc)
	got, err := NewReader(w.Bytes(), DefaultLimits()).Nodes("nodes", 4096)
	if err != nil || len(got) != 3 {
		t.Fatalf("a canonical NODES set was refused: %v", err)
	}
	// the same node twice is an equal hash: refused at index 1, as is the descending order
	var dup Writer
	dup.Nodes([][]byte{a, a})
	_, err = NewReader(dup.Bytes(), DefaultLimits()).Nodes("nodes", 4096)
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonNodesNotAscendingUnique, "index", 1)
	var rev Writer
	rev.Nodes([][]byte{enc[2], enc[1], enc[0]})
	_, err = NewReader(rev.Bytes(), DefaultLimits()).Nodes("nodes", 4096)
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonNodesNotAscendingUnique, "index", 1)
	// an LP list whose count byte is short reports the list, and an element error carries its index
	_, err = NewReader([]byte{0, 0}, DefaultLimits()).LPList("l", 3, 10)
	wantNamed(t, err, CodeEvidenceMalformed, "part", "l.count", "reason", ReasonTruncated)
	var big Writer
	big.LPList([][]byte{{1}, {1, 2, 3}})
	_, err = NewReader(big.Bytes(), DefaultLimits()).LPList("l", 5, 2)
	wantNamed(t, err, CodeEvidenceTooLarge, "part", "l", "index", 1)
}

func TestContainerSizeBoundIsExactAndEveryHeaderPartCanBeTruncated(t *testing.T) {
	enc, err := Container{Header: ContainerHeader{Kind: "k", Chain: 7, Level: LevelFinalized, BlockNumber: 9, BlockHash: fill(0x44)}, Body: []byte("body")}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	lim := DefaultLimits()
	lim.MaxEvidenceBytes = len(enc)
	if _, err := DecodeContainer(enc, lim); err != nil {
		t.Fatalf("a container of exactly MaxEvidenceBytes was refused: %v", err)
	}
	lim.MaxEvidenceBytes = len(enc) - 1
	_, err = DecodeContainer(enc, lim)
	wantNamed(t, err, CodeEvidenceTooLarge, "part", "evidence", "count", len(enc), "limit", len(enc)-1)
	// magic 4 | kind STR 4+1 | chain 8 | level 1 | blockNumber 8 | blockHash 32
	for _, c := range []struct {
		cut  int
		part string
	}{{3, "header.magic"}, {5, "header.kind.len"}, {9, "header.chain"}, {16, "header.chain"}, {17, "header.level"}, {18, "header.blockNumber"}, {25, "header.blockNumber"}, {26, "header.blockHash"}, {57, "header.blockHash"}} {
		_, err := DecodeContainer(enc[:c.cut], DefaultLimits())
		wantNamed(t, err, CodeEvidenceMalformed, "part", c.part, "reason", ReasonTruncated)
	}
	got, err := DecodeContainer(enc[:58], DefaultLimits())
	if err != nil || len(got.Body) != 0 || got.Header.Chain != 7 || got.Header.BlockNumber != 9 {
		t.Fatalf("the header alone (58 bytes): %+v %v", got, err)
	}
	// a magic that is not CFE1 and a level that is not stored
	bad := append([]byte(nil), enc...)
	bad[0] = 'X'
	_, err = DecodeContainer(bad, DefaultLimits())
	wantNamed(t, err, CodeEvidenceUnrecognised)
	lv := append([]byte(nil), enc...)
	lv[17] = byte(LevelIncluded)
	_, err = DecodeContainer(lv, DefaultLimits())
	wantNamed(t, err, CodeEvidenceMalformed, "part", "header.level", "reason", ReasonLevelNotStored)
	if _, err := (Container{Header: ContainerHeader{Kind: "k", Level: LevelIncluded}}).Encode(); err == nil {
		t.Fatal("a container of the derived level 1 was encoded")
	}
}

func TestNewAddendumRefusesEveryContainerHeaderDisagreementAndAnUndecodableContainer(t *testing.T) {
	b := testBase()
	d0 := LegBindingOf(b)
	ok := containerFor(t, kBaseFin, b, LevelFinalized, "x")
	if _, err := NewAddendum(d0, testProofID, nil, ChainBaseSepolia, LevelFinalized, kBaseFin, ok); err != nil {
		t.Fatalf("the agreeing container was refused: %v", err)
	}
	// not a container at all: the decode refusal itself, not a header mismatch
	_, err := NewAddendum(d0, testProofID, nil, ChainBaseSepolia, LevelFinalized, kBaseFin, []byte("CFE1"))
	wantNamed(t, err, CodeEvidenceMalformed, "part", "header.kind.len", "reason", ReasonTruncated)
	_, err = NewAddendum(d0, testProofID, nil, ChainBaseSepolia, LevelFinalized, kBaseFin, nil)
	wantNamed(t, err, CodeEvidenceMalformed, "part", "header.magic")
	enc := func(h ContainerHeader) []byte {
		raw, err := Container{Header: h, Body: []byte("x")}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	good := ContainerHeader{Kind: kBaseFin, Chain: ChainBaseSepolia, Level: LevelFinalized, BlockNumber: b.Number, BlockHash: b.Hash}
	for name, h := range map[string]ContainerHeader{
		"kind alone":  {Kind: "other/finalized/v1", Chain: good.Chain, Level: good.Level, BlockNumber: good.BlockNumber, BlockHash: good.BlockHash},
		"chain alone": {Kind: good.Kind, Chain: ChainSepolia, Level: good.Level, BlockNumber: good.BlockNumber, BlockHash: good.BlockHash},
		"level alone": {Kind: good.Kind, Chain: good.Chain, Level: LevelL1Posted, BlockNumber: good.BlockNumber, BlockHash: good.BlockHash},
	} {
		_, err := NewAddendum(d0, testProofID, nil, ChainBaseSepolia, LevelFinalized, kBaseFin, enc(h))
		if st, ok := AsNamed(err); !ok || st.Code != CodeBlockMismatch || st.Fields["field"] != "header" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTopIsTheHighestStoredLevelWhateverTheOrder(t *testing.T) {
	b := testBase()
	for _, order := range [][]Level{{LevelL1Posted, LevelFinalized}, {LevelFinalized, LevelL1Posted}, {LevelFinalized}, {LevelL1Posted}} {
		chain := buildChain(t, b, order...)
		want := LevelL1Posted
		for _, l := range order {
			if l == LevelFinalized {
				want = LevelFinalized
			}
		}
		if got := Top(chain); got != want {
			t.Errorf("order %v: Top = %s, want %s", order, got, want)
		}
	}
	if Top(nil) != LevelNone {
		t.Fatal("Top of an empty chain is none")
	}
}

func TestProofIDDashesAreEnforcedAtTheirPositions(t *testing.T) {
	// 36 lower-case hex characters, no dash anywhere
	_, err := ParseProofID("0123456789abcdef0123456789abcdef0123")
	wantNamed(t, err, CodeAddendumMalformed, "field", "proofId", "reason", AddendumNotUUID)
	// dashes at the right places except one that is a hex digit
	good := "01234567-89ab-cdef-0123-456789abcdef"
	for _, pos := range []int{8, 13, 18, 23} {
		bad := []byte(good)
		bad[pos] = 'a'
		_, err := ParseProofID(string(bad))
		wantNamed(t, err, CodeAddendumMalformed, "reason", AddendumNotUUID)
	}
	if _, err := ParseProofID(good); err != nil {
		t.Fatal(err)
	}
}

func TestStrictHexAndTheLengthFixedHashReaders(t *testing.T) {
	_, err := strictHex("aa", "f", 0)
	wantNamed(t, err, CodeAddendumMalformed, "field", "f", "reason", AddendumNot32Bytes)
	if b, err := strictHex("", "f", 0); err != nil || len(b) != 0 {
		t.Fatalf("empty hex of fixed length 0: %v", err)
	}
	if b, err := strictHex("", "f", -1); err != nil || len(b) != 0 {
		t.Fatal(err)
	}
	_, err = strictHex("abc", "f", -1)
	wantNamed(t, err, CodeAddendumMalformed, "reason", AddendumNotLowerHex)
	_, err = strictHex("AB", "f", -1)
	wantNamed(t, err, CodeAddendumMalformed, "reason", AddendumNotLowerHex)
	_, err = strictHex32(json.RawMessage(`5`), "ownHash")
	wantNamed(t, err, CodeAddendumMalformed, "field", "ownHash", "reason", AddendumBadValue)
	_, err = strictHex32(json.RawMessage(`"aa"`), "ownHash")
	wantNamed(t, err, CodeAddendumMalformed, "reason", AddendumNot32Bytes)
	_, err = CarriedLeg{Chain: 1, BlockNumber: 2, BlockHash: "zz"}.Ref()
	wantNamed(t, err, CodeAddendumMalformed, "field", "leg.blockHash", "reason", AddendumNotLowerHex)
	ref, err := CarriedLeg{Chain: 1, BlockNumber: 2, BlockHash: strings.Repeat("11", 32)}.Ref()
	if err != nil || ref.Hash != fill(0x11) || ref.Chain != 1 || ref.Number != 2 {
		t.Fatalf("%+v %v", ref, err)
	}
}

func TestAddendumJSONRefusesAWrongTypeInEveryMember(t *testing.T) {
	b := testBase()
	one := buildChain(t, b, LevelFinalized)[0]
	raw, err := json.Marshal(one)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		member string
		value  any
	}{
		{"proofId", 5}, {"seq", "x"}, {"level", 5}, {"chain", "x"}, {"kind", 5}, {"evidence", 5}, {"prevHash", 5}, {"ownHash", 5},
	} {
		mut := map[string]any{}
		for k, v := range doc {
			mut[k] = v
		}
		mut[c.member] = c.value
		bad, _ := json.Marshal(mut)
		var a Addendum
		wantNamed(t, json.Unmarshal(bad, &a), CodeAddendumMalformed, "field", c.member, "reason", AddendumBadValue)
	}
	// not an object / not json at all
	var a Addendum
	wantNamed(t, json.Unmarshal([]byte(`[1]`), &a), CodeAddendumMalformed, "field", "addendum", "reason", AddendumNotJSON)
	wantNamed(t, a.UnmarshalJSON([]byte(`7`)), CodeAddendumMalformed, "reason", AddendumNotJSON)
	wantNamed(t, a.UnmarshalJSON([]byte(`{"proofId":`)), CodeAddendumMalformed, "reason", AddendumNotJSON)
	if err := json.Unmarshal(raw, &a); err != nil || a.OwnHash != one.OwnHash {
		t.Fatalf("the genuine form was refused: %v", err)
	}
}

func TestSectionParsingNamesTheFirstFailureAndSectionUnmarshalIsStrict(t *testing.T) {
	var s Section
	wantNamed(t, json.Unmarshal([]byte(`{}`), &s), CodeAddendumMalformed, "field", "finality", "reason", AddendumMissingKey, "key", "format")
	_, err := ParseSection([]byte(`[1]`))
	wantNamed(t, err, CodeAddendumMalformed, "field", "finality", "reason", AddendumNotJSON)
	leg := `{"blockHash":"` + strings.Repeat("11", 32) + `","blockNumber":2,"chain":%s}`
	doc := func(legJSON, addenda string) []byte {
		return []byte(`{"addenda":` + addenda + `,"format":"` + SectionFormat + `","leg":` + legJSON + `}`)
	}
	_, err = ParseSection(doc(fmt.Sprintf(leg, `"x"`), `[]`))
	wantNamed(t, err, CodeAddendumMalformed, "field", "leg.chain", "reason", AddendumBadValue)
	_, err = ParseSection(doc(strings.Replace(fmt.Sprintf(leg, `1`), `"blockNumber":2`, `"blockNumber":"x"`, 1), `[]`))
	wantNamed(t, err, CodeAddendumMalformed, "field", "leg.blockNumber", "reason", AddendumBadValue)
	_, err = ParseSection(doc(strings.Replace(fmt.Sprintf(leg, `1`), strings.Repeat("11", 32), "11", 1), `[]`))
	wantNamed(t, err, CodeAddendumMalformed, "field", "leg.blockHash", "reason", AddendumNot32Bytes)
	_, err = ParseSection(doc(fmt.Sprintf(leg, `1`), `null`))
	wantNamed(t, err, CodeAddendumMalformed, "field", "addenda", "reason", AddendumBadValue)
	_, err = ParseSection(doc(fmt.Sprintf(leg, `1`), `[{"proofId":5}]`))
	wantNamed(t, err, CodeAddendumMalformed, "index", 0)
	// the genuine section round-trips through json.Unmarshal into the strict reader
	b := testBase()
	chain := buildChain(t, b, LevelL1Posted, LevelFinalized)
	raw, err := json.Marshal(NewSection(b, chain))
	if err != nil {
		t.Fatal(err)
	}
	var back Section
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Addenda) != 2 || back.Leg.BlockNumber != b.Number {
		t.Fatalf("%+v %v", back, err)
	}
}

func TestBlockRefStringAndSettlementBlockAndSubjectOfAMissingSettlement(t *testing.T) {
	if got := (BlockRef{Chain: 1, Number: 2, Hash: fill(0x33)}).String(); got != "chain 1 block 2 33333333" {
		t.Fatalf("%q", got)
	}
	bare := Settlement{Chain: ChainBaseSepolia, Subject: Subject{BlockNumber: 5, BlockHash: fill(0x22)}}
	if blk := bare.Block(); blk.Chain != ChainBaseSepolia || blk.Number != 5 || blk.Hash != fill(0x22) || blk.HeaderRLP != nil {
		t.Fatalf("a settlement without L6 evidence: %+v", blk)
	}
	real := realSettlement(t, "base_sepolia_47368146")
	if blk := real.Block(); len(blk.HeaderRLP) == 0 || !bytes.Equal(blk.HeaderRLP, real.Included.Header) {
		t.Fatal("the L6 header is carried in the block")
	}
	_, err := SubjectOfSettlement(nil)
	wantNamed(t, err, CodeIncludedUnavailable)
	sub, err := SubjectOfSettlement(real.Included)
	if err != nil || sub.BlockNumber != 47368146 {
		t.Fatalf("%+v %v", sub, err)
	}
}

func TestStateRenderingParsingAndCanonicalForms(t *testing.T) {
	// AsNamed
	if _, ok := AsNamed(errors.New("plain")); ok {
		t.Fatal("a plain error is not a named state")
	}
	if st, ok := AsNamed(fmt.Errorf("wrapped: %w", NewState("c", "k", 1))); !ok || st.Code != "c" {
		t.Fatal("a wrapped named state is found")
	}
	var typedNil *StateError
	if st, ok := AsNamed(typedNil); ok || st != nil {
		t.Fatal("a typed nil state is not a named state")
	}
	if st, ok := AsNamed(nil); ok || st != nil {
		t.Fatal("nil is not a named state")
	}
	// NewState ignores a dangling key
	s := NewState("c", "a", 1, "dangling")
	if len(s.Fields) != 1 {
		t.Fatalf("%v", s.Fields)
	}
	if got := NewState("c", "k1", "v1", "k2", uint64(2)).Error(); got != `c{k1="v1",k2="2"}` {
		t.Fatalf("%s", got)
	}
	if got := NewState("c").Error(); got != `c{}` {
		t.Fatalf("%s", got)
	}
	// HTML characters are not escaped in the canonical form
	if got := string(canonString("a<b&c>d")); got != `"a<b&c>d"` {
		t.Fatalf("%s", got)
	}
	// named byte slices and arrays render as 0x hex, other slices through Sprint
	type blob []byte
	if got := string(canonValue(blob{1, 0xab})); got != `"0x01ab"` {
		t.Fatalf("%s", got)
	}
	if got := string(canonValue([3]byte{0xde, 0xad, 0x01})); got != `"0xdead01"` {
		t.Fatalf("%s", got)
	}
	if got := string(canonValue([]int{1, 2})); got != `"[1 2]"` {
		t.Fatalf("%s", got)
	}
	// Malformed clamps a negative length to zero and keeps a positive one; equal values are kept
	m := Malformed("p", ReasonTruncated, -3, 5)
	if m.Fields["got_len"] != uint64(0) || m.Fields["want_len"] != uint64(5) {
		t.Fatalf("%v", m.Fields)
	}
	if m := Malformed("p", ReasonTruncated, 4, 4); m.Fields["got_len"] != uint64(4) {
		t.Fatalf("%v", m.Fields)
	}
	// a pending with an ETA carries it (UTC), one without does not
	eta := time.Date(2026, 10, 20, 12, 0, 0, 0, time.FixedZone("x", 3600))
	with := (&PendingState{Chain: 1, LevelReached: LevelL1Posted, NextLevel: LevelFinalized, Reason: "r", ETA: eta}).State()
	if got := with.Fields["eta"]; got != eta.UTC() {
		t.Fatalf("eta %v", got)
	}
	without := (&PendingState{Chain: 1, LevelReached: LevelL1Posted, NextLevel: LevelFinalized, Reason: "r"}).State()
	if _, has := without.Fields["eta"]; has {
		t.Fatal("a pending without an ETA must not carry one")
	}
}

func TestTheLevelAvailabilityOfEverySupportedChainAndTheUnsupportedOne(t *testing.T) {
	_, err := LevelAvailability(999)
	wantNamed(t, err, CodeChainUnsupported, "chain", 999)
	sep, err := LevelAvailability(ChainSepolia)
	if err != nil || sep[LevelIncluded] != "" || sep[LevelL1Posted] != "" || sep[LevelFinalized] != kSepFin {
		t.Fatalf("%v %v", sep, err)
	}
	base, err := LevelAvailability(ChainBaseSepolia)
	if err != nil || base[LevelL1Posted] != kBaseL1 || base[LevelFinalized] != kBaseFin || len(base) != 3 {
		t.Fatalf("%v %v", base, err)
	}
}

func TestRegistryProfilesChainsAndKindVersions(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Profile(999); err == nil {
		t.Fatal("an unprofiled chain has no profile")
	} else {
		wantNamed(t, err, CodeChainUnsupported, "chain", 999)
	}
	chains := r.Chains()
	if len(chains) < 3 {
		t.Fatalf("%v", chains)
	}
	for i := 1; i < len(chains); i++ {
		if chains[i-1] >= chains[i] {
			t.Fatalf("Chains are not strictly ascending: %v", chains)
		}
	}
	if chains[0] == 0 {
		t.Fatalf("a zero chain leads: %v", chains)
	}
	p, err := r.Profile(chains[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterProfile(p); err == nil {
		t.Fatal("a second profile for a chain was registered")
	}
	if err := r.RegisterProfile(ChainProfile{}); err == nil {
		t.Fatal("an invalid profile was registered")
	}
	for in, want := range map[string]string{"a/b/v1": "v1", "/v2": "v2", "noslash": "", "": "", "x/": ""} {
		if got := kindVersion(in); got != want {
			t.Errorf("kindVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// blankKind returns a Verdict with no Kind name and the level the test chooses.
type blankKind struct {
	fakeKind
	claim Level
}

func (k *blankKind) Verify(*Pins, BlockRef, []byte) (Verdict, error) {
	return Verdict{Level: k.claim}, nil
}

func TestJudgeAddendumKeepsTheKindsNameAndRefusesAKindThatProvesAnotherLevel(t *testing.T) {
	b := testBase()
	r := NewRegistry()
	k := &blankKind{fakeKind: fakeKind{chain: ChainBaseSepolia, name: kBaseFin, level: LevelFinalized}, claim: LevelFinalized}
	if err := r.RegisterKind(k); err != nil {
		t.Fatal(err)
	}
	a := Addendum{Level: LevelFinalized, Chain: ChainBaseSepolia, Kind: kBaseFin, Evidence: containerFor(t, kBaseFin, b, LevelFinalized, "x")}
	v, err := r.JudgeAddendum(b, a, nil)
	if err != nil || v.Kind != kBaseFin {
		t.Fatalf("a blank verdict kind takes the addendum's: %+v %v", v, err)
	}
	// a kind of the l1_posted row that claims finalized, about a finalized addendum: the claim equals the addendum's level but
	// not the row's, so it is refused
	r2 := NewRegistry()
	l1 := &blankKind{fakeKind: fakeKind{chain: ChainBaseSepolia, name: kBaseL1, level: LevelL1Posted}, claim: LevelFinalized}
	if err := r2.RegisterKind(l1); err != nil {
		t.Fatal(err)
	}
	a2 := Addendum{Level: LevelFinalized, Chain: ChainBaseSepolia, Kind: kBaseL1, Evidence: containerFor(t, kBaseL1, b, LevelFinalized, "x")}
	_, err = r2.JudgeAddendum(b, a2, nil)
	wantNamed(t, err, CodeVerifierFailed)
	// the other direction: the row's level but not the addendum's
	r3 := NewRegistry()
	fin := &blankKind{fakeKind: fakeKind{chain: ChainBaseSepolia, name: kBaseFin, level: LevelFinalized}, claim: LevelFinalized}
	if err := r3.RegisterKind(fin); err != nil {
		t.Fatal(err)
	}
	a3 := Addendum{Level: LevelL1Posted, Chain: ChainBaseSepolia, Kind: kBaseFin, Evidence: containerFor(t, kBaseFin, b, LevelL1Posted, "x")}
	_, err = r3.JudgeAddendum(b, a3, nil)
	wantNamed(t, err, CodeVerifierFailed)
}

func TestAbsentLevelOfAnUnsupportedChainIsPendingNotNotApplicable(t *testing.T) {
	r := NewRegistry()
	st := r.absentOrNA(999, LevelFinalized, LevelNone, nil)
	if st.Status != StatusPending {
		t.Fatalf("an unsupported chain's absent level is %s", st.Status)
	}
	if na := r.absentOrNA(ChainSepolia, LevelL1Posted, LevelNone, nil); na.Status != StatusNotApplicable {
		t.Fatalf("Sepolia has no l1_posted: %s", na.Status)
	}
}

func headerWithItems(t *testing.T, n int, number []byte) []byte {
	t.Helper()
	items := make([]any, n)
	for i := range items {
		items[i] = []byte{1}
	}
	for _, i := range []int{0, 3, 4, 5} {
		items[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
	}
	items[8] = number
	if n > 11 {
		items[11] = []byte{0x65}
	}
	if n >= 17 {
		items[16] = bytes.Repeat([]byte{0x77}, 32)
	}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadHeaderItemCountAndUintWidthBoundaries(t *testing.T) {
	// 12 items is the floor; 16 items has no withdrawals root, 17 has it
	if _, err := ReadHeader(headerWithItems(t, 11, []byte{1})); err == nil {
		t.Fatal("11 items were accepted")
	} else {
		wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonHeaderTooFewItems, "got_len", 11, "want_len", 12)
	}
	h12, err := ReadHeader(headerWithItems(t, 12, []byte{1}))
	if err != nil || h12.Items != 12 || h12.WithdrawalsRoot != nil {
		t.Fatalf("%+v %v", h12, err)
	}
	h16, err := ReadHeader(headerWithItems(t, 16, []byte{1}))
	if err != nil || h16.WithdrawalsRoot != nil {
		t.Fatalf("16 items carry no withdrawals root: %+v %v", h16, err)
	}
	h17, err := ReadHeader(headerWithItems(t, 17, []byte{1}))
	if err != nil || h17.WithdrawalsRoot == nil || h17.WithdrawalsRoot[0] != 0x77 {
		t.Fatalf("17 items carry it: %+v %v", h17, err)
	}
	// an 8 byte number is the widest uint, a 9 byte one and a leading zero are refused
	h8, err := ReadHeader(headerWithItems(t, 15, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	if err != nil || h8.Number != 0x0102030405060708 {
		t.Fatalf("%+v %v", h8, err)
	}
	_, err = ReadHeader(headerWithItems(t, 15, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}))
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonHeaderItemNotCanonUint, "index", 8)
	_, err = ReadHeader(headerWithItems(t, 15, []byte{0, 1}))
	wantNamed(t, err, CodeEvidenceMalformed, "reason", ReasonHeaderItemNotCanonUint, "index", 8)
	// an empty number is zero
	h0, err := ReadHeader(headerWithItems(t, 15, []byte{}))
	if err != nil || h0.Number != 0 {
		t.Fatalf("%+v %v", h0, err)
	}
}
