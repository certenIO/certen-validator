// Copyright 2026 Certen Protocol

package contractidentity

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// isGoverningBookOf: byte for byte the factory function (exactly one '/', right after the ADI; no upper case; at least one name byte).
func TestA2IsGoverningBookOf(t *testing.T) {
	for _, c := range []struct {
		adi, book string
		ok        bool
	}{
		{"acc://x.acme", "acc://x.acme/book", true},
		{"acc://x.acme", "acc://x.acme/b", true},
		{"acc://x.acme", "acc://x.acme/", false},       // b.length < a.length + 2
		{"acc://x.acme", "acc://x.acme", false},        // no name
		{"acc://x.acme/", "acc://x.acme//book", false}, // the ADI ends with '/'
		{"", "/book", false},
		{"acc://x.acme", "acc://x.acme/bo/ok", false},    // a second '/'
		{"acc://x.acme", "acc://x.acmeX/book", false},    // not the ADI prefix
		{"acc://x.acme", "acc://x.acme/Book", false},     // upper case
		{"acc://X.acme", "acc://X.acme/book", false},     // upper case ADI
		{"acc://x.acme", "acc://x.acmebook/book", false}, // '/' not right after the ADI
	} {
		if got := a2IsGoverningBookOf(c.adi, c.book); got != c.ok {
			t.Errorf("isGoverningBookOf(%q, %q) = %v, want %v", c.adi, c.book, got, c.ok)
		}
	}
}

// _requiredLevelFor: a stored requirement wins; otherwise the value thresholds 10 / 1 / 0.1 ether, exact at each bound.
func TestA2RequiredFor(t *testing.T) {
	eth := func(wei string) *big.Int { v, _ := new(big.Int).SetString(wei, 10); return v }
	for _, c := range []struct {
		stored int
		value  string
		want   int
	}{
		{0, "10000000000000000000", 4}, {0, "9999999999999999999", 3}, {0, "1000000000000000000", 3}, {0, "999999999999999999", 2},
		{0, "100000000000000000", 2}, {0, "99999999999999999", 1}, {0, "0", 1}, {3, "0", 3}, {1, "10000000000000000000", 1},
	} {
		if got := a2RequiredFor(c.stored, eth(c.value)); got != c.want {
			t.Errorf("required(stored %d, value %s) = %d, want %d", c.stored, c.value, got, c.want)
		}
	}
}

// authorityLevelOfPage (CertenAccountV7_3.sol:392-398): NONE for page 0 or book 0, the stored level when set, NONE for a foreign book,
// else ROOT / ADMIN / OPERATOR by page; a stored level above 4 is reported.
func TestA2LevelOf(t *testing.T) {
	gov, other := common.HexToHash("0x01"), common.HexToHash("0x02")
	set, one := common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1))
	for _, c := range []struct {
		page      uint64
		book, set common.Hash
		stored    common.Hash
		level     int
		source    string
		invalid   bool
	}{
		{0, gov, common.Hash{}, common.Hash{}, 0, "none", false}, {1, common.Hash{}, common.Hash{}, common.Hash{}, 0, "none", false},
		{1, gov, common.Hash{}, common.Hash{}, 4, "governing_default", false}, {2, gov, common.Hash{}, common.Hash{}, 3, "governing_default", false},
		{3, gov, common.Hash{}, common.Hash{}, 1, "governing_default", false}, {1, other, common.Hash{}, common.Hash{}, 0, "none", false},
		{3, other, set, common.BigToHash(big.NewInt(4)), 4, "stored", false}, {3, gov, set, one, 1, "stored", false},
		{1, gov, set, common.BigToHash(big.NewInt(5)), 0, "stored", true},
	} {
		level, source, inv := a2LevelOf(c.page, c.book, c.set, c.stored, gov)
		if level != c.level || source != c.source || (inv != nil) != c.invalid {
			t.Errorf("levelOf(page %d, book %s, set %s, stored %s) = %d %s %v", c.page, c.book.Hex()[:6], c.set.Hex()[:6], c.stored.Hex()[:6], level, source, inv)
		}
	}
}
