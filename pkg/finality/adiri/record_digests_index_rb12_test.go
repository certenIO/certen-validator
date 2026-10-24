// Copyright 2026 Certen Protocol

package adiri_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// RB12-OPS-A1 item 8 (BETA finding B-ADIRI-1): RecordDigests, which is exported and digests any CFA1, indexed the committee tables with the
// record's table indices unchecked and PANICKED for an index outside the tables (the TS twin's F1-FIX differential reproduced 77 panics).
// VerifyCommitteeChain and DecodeCFA1 apply checkRecordTables first, so the verifier never reached the index; the exported method did not
// carry the rule. It now refuses with the state DecodeCFA1 uses for the same condition: finality_evidence_malformed{part: cfa1.record,
// reason: cfa1_table_index_out_of_range, index: i}. Never a panic and never an answer for such a record.

func tableOf(n int, salt byte) [][]byte {
	t := make([][]byte, n)
	for i := range t {
		t[i] = make([]byte, adiri.KeyBytes)
		t[i][0], t[i][1] = salt, byte(i)
	}
	return t
}

func chainOf(nTables, nRecords int) *adiri.CFA1 {
	cf := &adiri.CFA1{}
	for i := 0; i < nTables; i++ {
		cf.Tables = append(cf.Tables, tableOf(4+i%3, byte(i)))
	}
	for i := 0; i < nRecords; i++ {
		cf.Records = append(cf.Records, adiri.Record{
			CommitteeIdx: uint8(i % nTables), NextIdx: uint8((i + 1) % nTables),
			FinalState:     adiri.NumHash{Number: uint64(100 + i), Hash: [32]byte{byte(i), 1}},
			FinalConsensus: adiri.NumHash{Number: uint64(200 + i), Hash: [32]byte{byte(i), 2}},
			Signers:        []uint8{0, 1, 2},
		})
	}
	return cf
}

func digestsOf(cf *adiri.CFA1) (d [][32]byte, err error, panicked any) {
	defer func() { panicked = recover() }()
	d, err = cf.RecordDigests()
	return
}

func wantIndexRefusal(t *testing.T, what string, record int, err error) {
	t.Helper()
	s, ok := finality.AsNamed(err)
	if !ok || s.Code != finality.CodeEvidenceMalformed || s.Fields["part"] != "cfa1.record" ||
		s.Fields["reason"] != finality.ReasonCFA1TableIndexOutOfRange || s.Fields["index"] != uint64(record) {
		t.Errorf("%s: got %v, want finality_evidence_malformed{cfa1.record, cfa1_table_index_out_of_range, index %d}", what, err, record)
	}
}

// Every shape of an out-of-range table index, in either field or both, at the first, a middle and the last record of a chain.
func TestRecordDigestsRefusesATableIndexOutsideTheTablesWithANamedState(t *testing.T) {
	cases := 0
	for _, nTables := range []int{1, 2, 3, 200, 255} {
		var bad []uint8
		for _, v := range []int{nTables, nTables + 1, 127, 128, 254, 255} { // the uint8 wrap of a negative index is 255
			if v >= nTables && v <= 255 {
				bad = append(bad, uint8(v))
			}
		}
		seen := map[uint8]bool{}
		for _, idx := range bad {
			if seen[idx] {
				continue
			}
			seen[idx] = true
			for _, at := range []int{0, 1, 2} {
				for _, field := range []string{"committee", "next", "both"} {
					cf := chainOf(nTables, 3)
					r := &cf.Records[at]
					if field != "next" {
						r.CommitteeIdx = idx
					}
					if field != "committee" {
						r.NextIdx = idx
					}
					name := fmt.Sprintf("%d tables, %s index %d at record %d", nTables, field, idx, at)
					d, err, p := digestsOf(cf)
					if p != nil {
						t.Errorf("%s: RecordDigests panicked: %v", name, p)
					} else {
						wantIndexRefusal(t, name, at, err)
						if d != nil {
							t.Errorf("%s: digests returned beside a refusal", name)
						}
					}
					cases++
				}
			}
		}
	}
	if cases < 77 {
		t.Fatalf("%d cases, the differential reproduced 77 panics", cases)
	}
	t.Logf("%d out-of-range shapes", cases)
}

// A fuzz-style table: random chains with random indices over the whole uint8 range. RecordDigests never panics; it refuses exactly when some
// record names a table that is not there (naming the FIRST such record), and answers one digest per record otherwise; VerifyCommitteeChain
// on the same chain never panics either and every error it returns is a named state.
func TestRecordDigestsOverRandomIndicesNeverPanicsAndRefusesExactlyTheOutOfRangeOnes(t *testing.T) {
	r := rand.New(rand.NewSource(20261023))
	refused, answered := 0, 0
	for n := 0; n < 3000; n++ {
		nTables := 1 + r.Intn(5)
		if r.Intn(20) == 0 {
			nTables = 1 + r.Intn(255)
		}
		cf := chainOf(nTables, 1+r.Intn(6))
		first := -1
		for i := range cf.Records {
			if r.Intn(4) == 0 {
				cf.Records[i].CommitteeIdx = uint8(r.Intn(256))
			}
			if r.Intn(4) == 0 {
				cf.Records[i].NextIdx = uint8(r.Intn(256))
			}
			if first < 0 && (int(cf.Records[i].CommitteeIdx) >= nTables || int(cf.Records[i].NextIdx) >= nTables) {
				first = i
			}
		}
		d, err, p := digestsOf(cf)
		if p != nil {
			t.Fatalf("chain %d (%d tables): RecordDigests panicked: %v", n, nTables, p)
		}
		if first >= 0 {
			wantIndexRefusal(t, fmt.Sprintf("chain %d (%d tables)", n, nTables), first, err)
			refused++
		} else {
			if err != nil || len(d) != len(cf.Records) {
				t.Fatalf("chain %d (%d tables): %d digests, err %v", n, nTables, len(d), err)
			}
			for i := 1; i < len(d); i++ { // each digest commits to its parent: no two records of this chain digest alike
				if d[i] == d[i-1] {
					t.Fatalf("chain %d: digests %d and %d are equal", n, i-1, i)
				}
			}
			answered++
		}
		par := &adiri.Params{ChainID: 2017, Codec: adiri.Codec, GenesisCommittee: cf.Tables[0], MinCommittee: 4, MaxHeaders: 16}
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("chain %d: VerifyCommitteeChain panicked: %v", n, p)
				}
			}()
			if _, err := adiri.VerifyCommitteeChain(par, cf, adiri.ModeOneByOne, nil); err != nil {
				if _, named := finality.AsNamed(err); !named {
					t.Fatalf("chain %d: an unnamed error: %v", n, err)
				}
			}
		}()
	}
	if refused < 300 || answered < 300 {
		t.Fatalf("the table covered %d refusals and %d answers", refused, answered)
	}
}

// No change for a valid chain (the measured anchors of epochs 0, 1, 2 and 642 are pinned by TestRecordDigestsEqualTheMeasuredAnchors): a chain
// digests without a refusal, and the digests are the same after Encode and DecodeCFA1.
func TestRecordDigestsOfAValidChainIsUnchanged(t *testing.T) {
	cf := chainOf(3, 5)
	d, err := cf.RecordDigests()
	if err != nil || len(d) != 5 {
		t.Fatalf("%d digests, err %v", len(d), err)
	}
	enc, err := cf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := adiri.DecodeCFA1(enc, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	d2, err := back.RecordDigests()
	if err != nil || len(d2) != len(d) {
		t.Fatalf("decoded chain: %d digests, err %v", len(d2), err)
	}
	for i := range d {
		if d[i] != d2[i] {
			t.Fatalf("digest %d changed through Encode/DecodeCFA1", i)
		}
	}
}

func mustDigests(t *testing.T, cf *adiri.CFA1) [][32]byte {
	t.Helper()
	d, err := cf.RecordDigests()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
