// Copyright 2026 Certen Protocol

package adiri_test

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB11-GATE-A, CFA1: a truncated chain is refused AT the field that is cut, by name, never later and never as another reason.

// gateFieldsOfCFA1 lists the fields of gateCFA1's encoding in order with their parts, so that the expected refusal of every
// proper prefix is derived from the layout alone.
func gateFieldsOfCFA1(c *adiri.CFA1) (names []string, sizes []int) {
	add := func(n string, s int) { names, sizes = append(names, n), append(sizes, s) }
	add("cfa1.magic", 4)
	add("cfa1.n_tables", 2)
	for _, t := range c.Tables {
		add("cfa1.table.n", 1)
		for range t {
			add("cfa1.table.key", adiri.KeyBytes)
		}
	}
	add("cfa1.n_records", 4)
	return
}

func TestCFA1PrefixesAreRefusedAtTheCutFieldByName(t *testing.T) {
	c := gateCFA1()
	enc, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	names, sizes := gateFieldsOfCFA1(c)
	header := 0
	for _, s := range sizes {
		header += s
	}
	pos := 0
	for i, name := range names {
		for cut := pos; cut < pos+sizes[i]; cut++ { // every prefix that ends inside this field
			_, err := adiri.DecodeCFA1(enc[:cut], finality.DefaultLimits())
			gateNamed(t, err, finality.CodeEvidenceMalformed, "part", name, "reason", finality.ReasonTruncated)
		}
		pos += sizes[i]
	}
	// from the end of the header on, the record count (2) cannot fit in what remains until the last three bytes
	for cut := header; cut < len(enc)-3; cut++ {
		_, err := adiri.DecodeCFA1(enc[:cut], finality.DefaultLimits())
		gateNamed(t, err, finality.CodeEvidenceMalformed, "part", "cfa1.records", "reason", finality.ReasonCountExceedsRemaining)
	}
	for cut, part := range map[int]string{len(enc) - 3: "cfa1.record.signature", len(enc) - 2: "cfa1.record.n_signers", len(enc) - 1: "cfa1.record.signers"} {
		_, err := adiri.DecodeCFA1(enc[:cut], finality.DefaultLimits())
		gateNamed(t, err, finality.CodeEvidenceMalformed, "part", part, "reason", finality.ReasonTruncated)
	}
}

// A record whose signer list is long leaves the NEXT record fewer bytes than its fixed part: the record count still fits at the
// start (n records need n*131 bytes) but the second record is cut inside each of its fields in turn.
func TestCFA1ASecondRecordStarvedByALongSignerListIsRefusedAtItsCutField(t *testing.T) {
	const fixed = 1 + 1 + 8 + 32 + 8 + 32 + adiri.SigBytes + 1
	fields := []struct {
		part string
		size int
	}{
		{"cfa1.record.committee_idx", 1}, {"cfa1.record.next_idx", 1}, {"cfa1.record.final_state.number", 8}, {"cfa1.record.final_state.hash", 32},
		{"cfa1.record.final_consensus.number", 8}, {"cfa1.record.final_consensus.hash", 32}, {"cfa1.record.signature", adiri.SigBytes}, {"cfa1.record.n_signers", 1},
	}
	// a 255 key committee so that signers 0..ns-1 are valid
	c := &adiri.CFA1{Tables: [][][]byte{gateTable(255, 0)}, Records: []adiri.Record{{}, {}}}
	good, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	tail := good[len(good)-fixed:] // a complete second record without signers
	head := append([]byte(nil), good[:len(good)-2*fixed]...)
	for ns := 1; ns <= 131; ns++ {
		rem := fixed - ns // bytes left for the second record after the first has taken its fixed part and ns signers
		if rem < 0 || rem > fixed-1 {
			continue
		}
		raw := append([]byte(nil), head...)
		raw = append(raw, 0, 0) // committee_idx, next_idx of record 0
		raw = append(raw, make([]byte, fixed-2)...)
		raw[len(head)+fixed-1] = byte(ns) // n_signers of record 0
		for s := 0; s < ns; s++ {
			raw = append(raw, byte(s))
		}
		raw = append(raw, tail[:rem]...)
		want, off := "", 0
		for _, f := range fields {
			if rem < off+f.size {
				want = f.part
				break
			}
			off += f.size
		}
		_, err := adiri.DecodeCFA1(raw, finality.DefaultLimits())
		if want == "" {
			t.Fatalf("ns %d rem %d: no field is cut", ns, rem)
		}
		gateNamed(t, err, finality.CodeEvidenceMalformed, "part", want, "reason", finality.ReasonTruncated)
	}
}
