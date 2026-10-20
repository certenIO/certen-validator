// Copyright 2026 Certen Protocol

package adiri_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-GATE-A, CFA1: the encoder's limits, the decoder's every truncation and bound, the accessors' index ranges and the record
// size floor, on a small hand-built chain. Every expectation is a literal.

func gateKey(seed byte) []byte { return bytes.Repeat([]byte{seed}, adiri.KeyBytes) }

func gateTable(n int, seed byte) [][]byte {
	t := make([][]byte, n)
	for i := range t {
		t[i] = gateKey(seed + byte(i))
	}
	return t
}

func gateCFA1() *adiri.CFA1 {
	return &adiri.CFA1{
		Tables: [][][]byte{gateTable(3, 0x10), gateTable(3, 0x20)},
		Records: []adiri.Record{
			{CommitteeIdx: 0, NextIdx: 1, FinalState: adiri.NumHash{Number: 5, Hash: [32]byte{1}}, FinalConsensus: adiri.NumHash{Number: 6, Hash: [32]byte{2}}, Signers: []uint8{0, 2}},
			{CommitteeIdx: 1, NextIdx: 0, FinalState: adiri.NumHash{Number: 7, Hash: [32]byte{3}}, FinalConsensus: adiri.NumHash{Number: 8, Hash: [32]byte{4}}, Signers: []uint8{1}},
		},
	}
}

func gateNamed(t *testing.T, err error, code string, kv ...any) *finality.StateError {
	t.Helper()
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if got := fmt.Sprint(st.Fields[fmt.Sprint(kv[i])]); got != fmt.Sprint(kv[i+1]) {
			t.Fatalf("%s: field %v is %q, want %q", st.Error(), kv[i], got, fmt.Sprint(kv[i+1]))
		}
	}
	return st
}

func TestCFA1RoundTripAndAccessorsStayInsideTheirRanges(t *testing.T) {
	c := gateCFA1()
	enc, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := adiri.DecodeCFA1(enc, finality.DefaultLimits())
	if err != nil || len(back.Records) != 2 || len(back.Tables) != 2 || back.Records[1].Signers[0] != 1 {
		t.Fatalf("%v", err)
	}
	again, err := back.Encode()
	if err != nil || !bytes.Equal(again, enc) {
		t.Fatal("encode(decode(x)) != x")
	}
	for i, want := range []byte{0x10, 0x20} {
		if got := c.Committee(i); len(got) != 3 || got[0][0] != want {
			t.Errorf("Committee(%d)", i)
		}
	}
	if c.Next(0)[0][0] != 0x20 || c.Next(1)[0][0] != 0x10 {
		t.Error("Next")
	}
	for _, i := range []int{-1, 2, 3} {
		if c.Committee(i) != nil || c.Next(i) != nil {
			t.Errorf("index %d is out of range", i)
		}
	}
	bad := gateCFA1()
	bad.Records[0].CommitteeIdx, bad.Records[0].NextIdx = 2, 2 // == len(Tables)
	if bad.Committee(0) != nil || bad.Next(0) != nil {
		t.Error("a table index equal to the table count is out of range")
	}
	last := gateCFA1()
	last.Records[0].CommitteeIdx, last.Records[0].NextIdx = 1, 1
	if last.Committee(0) == nil || last.Next(0) == nil {
		t.Error("the last table is in range")
	}
}

func TestCFA1EveryProperPrefixIsRefusedAndTheLimitsAreExact(t *testing.T) {
	enc, err := gateCFA1().Encode()
	if err != nil {
		t.Fatal(err)
	}
	lim := finality.DefaultLimits()
	for n := 0; n < len(enc); n++ {
		if _, err := adiri.DecodeCFA1(enc[:n], lim); err == nil {
			t.Fatalf("a %d byte prefix of a %d byte CFA1 was accepted", n, len(enc))
		}
	}
	at := lim
	at.MaxCFA1Tables, at.MaxCFA1Records = 2, 2
	if _, err := adiri.DecodeCFA1(enc, at); err != nil {
		t.Fatalf("counts equal to the limits are accepted: %v", err)
	}
	at.MaxCFA1Tables = 1
	_, err = adiri.DecodeCFA1(enc, at)
	gateNamed(t, err, finality.CodeEvidenceTooLarge, "part", "cfa1.tables", "count", 2, "limit", 1)
	at = lim
	at.MaxCFA1Records = 1
	_, err = adiri.DecodeCFA1(enc, at)
	gateNamed(t, err, finality.CodeEvidenceTooLarge, "part", "cfa1.records", "count", 2, "limit", 1)
}

func TestCFA1RecordCountMustFitTheRemainingBytesAtTheRecordFloor(t *testing.T) {
	// n records without signers occupy exactly n * 131 bytes: the floor is met with equality and missed by one byte
	const floor = 1 + 1 + 8 + 32 + 8 + 32 + adiri.SigBytes + 1
	if floor != 131 {
		t.Fatalf("floor %d", floor)
	}
	c := &adiri.CFA1{Tables: [][][]byte{gateTable(1, 0x10)}, Records: []adiri.Record{{}, {}, {}}}
	enc, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adiri.DecodeCFA1(enc, finality.DefaultLimits()); err != nil {
		t.Fatalf("records that exactly fit: %v", err)
	}
	// claim one record more than there are bytes for
	off := 4 + 2 + 1 + adiri.KeyBytes
	over := append([]byte(nil), enc...)
	over[off+3] = 4
	_, err = adiri.DecodeCFA1(over, finality.DefaultLimits())
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "cfa1.records", "reason", finality.ReasonCountExceedsRemaining, "got_len", 3*floor, "want_len", 4*floor)
	zero := append([]byte(nil), enc...)
	zero[off], zero[off+1], zero[off+2], zero[off+3] = 0, 0, 0, 0
	_, err = adiri.DecodeCFA1(zero, finality.DefaultLimits())
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "cfa1.n_records", "reason", finality.ReasonCFA1NoRecords)
}

func TestCFA1TableAndSignerIndicesAreStrict(t *testing.T) {
	lim := finality.DefaultLimits()
	enc := func(mut func(c *adiri.CFA1)) []byte {
		c := gateCFA1()
		mut(c)
		raw, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// a committee or next table index equal to the table count is out of range and the reported size is the larger index
	_, err := adiri.DecodeCFA1(enc(func(c *adiri.CFA1) { c.Records[0].CommitteeIdx = 2 }), lim)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "cfa1.record", "reason", finality.ReasonCFA1TableIndexOutOfRange, "got_len", 2, "want_len", 2)
	_, err = adiri.DecodeCFA1(enc(func(c *adiri.CFA1) { c.Records[1].NextIdx = 2 }), lim)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "reason", finality.ReasonCFA1TableIndexOutOfRange, "index", 1)
	_, err = adiri.DecodeCFA1(enc(func(c *adiri.CFA1) { c.Records[0].CommitteeIdx, c.Records[0].NextIdx = 1, 5 }), lim)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "reason", finality.ReasonCFA1TableIndexOutOfRange, "got_len", 5)
	_, err = adiri.DecodeCFA1(enc(func(c *adiri.CFA1) { c.Records[0].CommitteeIdx, c.Records[0].NextIdx = 5, 1 }), lim)
	gateNamed(t, err, finality.CodeEvidenceMalformed, "reason", finality.ReasonCFA1TableIndexOutOfRange, "got_len", 5)
	// signer indices: strictly increasing and below the committee size (3)
	ok := func(s ...uint8) error {
		_, err := adiri.DecodeCFA1(enc(func(c *adiri.CFA1) { c.Records[0].Signers = s }), lim)
		return err
	}
	for _, good := range [][]uint8{{}, {0}, {2}, {0, 1, 2}, {1, 2}} {
		if err := ok(good...); err != nil {
			t.Errorf("signers %v: %v", good, err)
		}
	}
	for _, bad := range [][]uint8{{3}, {0, 3}, {1, 1}, {2, 1}, {0, 0}, {255}} {
		gateNamed(t, ok(bad...), "committee_chain_broken", "check", "signer_index_invalid", "committee_size", 3)
	}
	st := gateNamed(t, ok(0, 1, 1), "committee_chain_broken", "index", 2, "signer", 1)
	if st.Fields["epoch"] != uint64(0) {
		t.Fatalf("%v", st.Fields)
	}
}

func TestCFA1EncodeRefusesWhatTheFormatCannotHold(t *testing.T) {
	reason := func(c *adiri.CFA1) string {
		_, err := c.Encode()
		st, ok := finality.AsNamed(err)
		if !ok {
			t.Fatalf("want a named refusal, got %v", err)
		}
		return fmt.Sprint(st.Fields["reason"])
	}
	one := func(tables [][][]byte) *adiri.CFA1 { return &adiri.CFA1{Tables: tables, Records: []adiri.Record{{}}} }
	if got := reason(one([][][]byte{{}})); got != string(finality.ReasonCFA1TableSize) {
		t.Errorf("empty table: %s", got)
	}
	if got := reason(one([][][]byte{gateTable(256, 0)})); got != string(finality.ReasonCFA1TableSize) {
		t.Errorf("256 keys: %s", got)
	}
	if _, err := one([][][]byte{gateTable(255, 0)}).Encode(); err != nil {
		t.Errorf("255 keys: %v", err)
	}
	if got := reason(one([][][]byte{{make([]byte, adiri.KeyBytes-1)}})); got != string(finality.ReasonCFA1KeyLength) {
		t.Errorf("short key: %s", got)
	}
	if got := reason(one([][][]byte{{make([]byte, adiri.KeyBytes+1)}})); got != string(finality.ReasonCFA1KeyLength) {
		t.Errorf("long key: %s", got)
	}
	long := &adiri.CFA1{Tables: [][][]byte{gateTable(1, 0)}, Records: []adiri.Record{{Signers: make([]uint8, 256)}}}
	if got := reason(long); got != string(finality.ReasonCFA1SignersTooMany) {
		t.Errorf("256 signers: %s", got)
	}
	long.Records[0].Signers = make([]uint8, 255)
	if _, err := long.Encode(); err != nil {
		t.Errorf("255 signers: %v", err)
	}
	// the table count is a u16: 65536 tables are refused by name, 65535 encode with the count bytes 0xff 0xff
	many := make([][][]byte, 65536)
	if got := reason(one(many)); got != string(finality.ReasonCFA1TooLargeToEncode) {
		t.Errorf("65536 tables: %s", got)
	}
	k := gateTable(1, 0)
	fits := make([][][]byte, 65535)
	for i := range fits {
		fits[i] = k
	}
	enc, err := one(fits).Encode()
	if err != nil || enc[4] != 0xff || enc[5] != 0xff {
		t.Fatalf("65535 tables: %v", err)
	}
	three := make([][][]byte, 300)
	for i := range three {
		three[i] = k
	}
	enc, err = one(three).Encode()
	if err != nil || enc[4] != 0x01 || enc[5] != 0x2c {
		t.Fatalf("300 tables encode their count as 0x012c: %v % x", err, enc[:6])
	}
}
