// Copyright 2026 Certen Protocol

package arbposted

import (
	"math"
	"regexp"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// The longest item name of every row kind of the Arbitrum index: it satisfies the capture's name rule and bound (and so the production table's
// constraint, which pkg/database TestFinalityCaptureIndexArbRowsFitTheProductionTable pins with the same literal strings).
func TestRB12ArbIndexLongestNamesFitTheProductionTable(t *testing.T) {
	const max = uint64(math.MaxUint64)
	gen := uint32(math.MaxUint32)
	want := map[string]string{
		"digest":     "idx/g4294967295/arb/f/18446744073709551615",
		"entry":      "idx/g4294967295/arb/e/18446744073709551615/18446744073709551615/18446744073709551615",
		"quarantine": "idx/g4294967295/arb/q/18446744073709551615",
		"unindexed":  "idx/g4294967295/arb/u",
		"cursor":     "idx/g4294967295/arb/cursor",
	}
	got := map[string]string{
		"digest":     digestItem(gen, max),
		"entry":      entryItem(gen, max, max, max),
		"quarantine": quarantineItem(gen, max),
		"unindexed":  unindexedItem(gen),
		"cursor":     finality.IndexCursorItem(gen, FamilyArb),
	}
	re := regexp.MustCompile(`^[a-z0-9_-]+(/[a-z0-9_-]+)*$`) // migration 00028: proof_finality_capture_item_is_name
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: the code spells %q, the production-table test pins %q", k, got[k], w)
		}
		if len(w) > finality.MaxCaptureItem || len(w) > 160 || !re.MatchString(w) {
			t.Errorf("%s: %q (%d bytes) breaks the table's name rule", k, w, len(w))
		}
		if err := finality.CheckCaptureItem(w); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	// the names parse back to what they were made from, at every digit width
	for _, n := range []uint64{0, 9, 10, 99, 100, max} {
		k := finality.CaptureKey{Chain: 1, L1Block: 5, Item: entryItem(1, n/2, n, n)}
		nm, ok := parseEntryName(1, k)
		if !ok || nm.MinTs != n/2 || nm.MaxTs != n || nm.N != n {
			t.Errorf("entry name for %d: %+v %v", n, nm, ok)
		}
		d := finality.CaptureKey{Chain: 1, L1Block: 5, Item: digestItem(1, n)}
		if tt, ok := parseDigestName(1, d); !ok || tt != n {
			t.Errorf("digest name for %d: %d %v", n, tt, ok)
		}
	}
	// a name that is not canonical (a leading zero, a sign, a range upside down) is not a name
	for _, item := range []string{ixItem(1, ixEntry, "05", "9", "1"), ixItem(1, ixEntry, "9", "5", "1"), ixItem(1, ixEntry, "1", "2"), ixItem(1, ixEntry, "1", "2", "3", "4"), ixItem(1, ixDigest, "007")} {
		if _, ok := parseEntryName(1, finality.CaptureKey{Item: item}); ok {
			t.Errorf("%s parses as an entry name", item)
		}
		if _, ok := parseDigestName(1, finality.CaptureKey{Item: item}); ok {
			t.Errorf("%s parses as a digest name", item)
		}
	}
}
