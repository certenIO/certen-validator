// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"encoding/json"
	"math"
	"math/big"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARBFINAL-FIX (BETA audit G5). max_uncompressed_batch had a lower bound (> 0) and no upper bound, and the zero-heavy layer's cap
// max + max/100 + 64 wraps near the largest int. A pins file may not name a bound above Nitro's MaxDecompressedLen (16 MiB = 16,777,216, the
// value the shipped pins carry and V2_SPEC_S7 section 4.2 pins): a larger bound makes the verifier accept batches Nitro refuses. The
// arithmetic of the cap saturates at the largest int.

// wantMaxBatchCorrupt is the canonical text of the refusal, written out here and not built by the constructor under test.
const wantMaxBatchCorrupt = `{"code":"finality_pins_corrupt","fields":{"key":"arb_sepolia.max_uncompressed_batch","reason":"bad_value"}}`

func TestMaxUncompressedBatchIsBoundedByNitrosLimit(t *testing.T) {
	var shipped struct {
		Arb struct {
			Max int `json:"max_uncompressed_batch"`
		} `json:"arb_sepolia"`
	}
	if err := json.Unmarshal(finality.EmbeddedPinsBytes(), &shipped); err != nil {
		t.Fatal(err)
	}
	if shipped.Arb.Max != 16777216 || shipped.Arb.Max != MaxUncompressedBatchLimit {
		t.Fatalf("the shipped pin %d, the limit %d: the shipped value is 16777216 and is the limit", shipped.Arb.Max, MaxUncompressedBatchLimit)
	}
	with := func(v string) *finality.Pins {
		return pinsWith(t, func(top map[string]any) { arbOf(top)["max_uncompressed_batch"] = json.RawMessage(v) })
	}
	// N passes, N+1 does not (class 7: the boundary is exact), and nothing larger does, whatever the way it is written
	for _, v := range []string{"1", "1000", "16777215", "16777216"} {
		a, err := loadArbPins(with(v))
		if err != nil || a == nil {
			t.Errorf("%s: refused: %v", v, err)
		}
	}
	for _, v := range []string{
		"16777217",                                                       // limit + 1
		"16777218", "33554432", "2147483647", "2147483648", "4294967296", // 2^31 - 1, 2^31, 2^32
		"9223372036854775806", "9223372036854775807", // MaxInt64 - 1, MaxInt64
		"9223372036854775808",  // MaxInt64 + 1: does not fit an int
		"18446744073709551615", // MaxUint64
		"18446744073709551616", // MaxUint64 + 1
		"100000000000000000000000000000000000000",
	} {
		_, err := loadArbPins(with(v))
		if canon(err) != wantMaxBatchCorrupt {
			t.Errorf("%s: %s, want %s", v, canon(err), wantMaxBatchCorrupt)
		}
	}
	// a section that does not decode for another reason is "the section does not parse", unless its bound is an integer beyond the limit: the
	// probe of the bound has the same exact boundary (the limit is not beyond it, limit + 1 is)
	for v, want := range map[string]string{"16777216": string(PinMismatch("section").Canonical()), "16777217": wantMaxBatchCorrupt} {
		p := pinsWith(t, func(top map[string]any) {
			arbOf(top)["max_uncompressed_batch"] = json.RawMessage(v)
			arbOf(top)["a_key_the_section_does_not_know"] = 1
		})
		if _, err := loadArbPins(p); canon(err) != want {
			t.Errorf("unknown key beside a bound of %s: %s, want %s", v, canon(err), want)
		}
	}
	// the lower bound and the type judgements are as before
	for v, want := range map[string]string{"0": string(PinMismatch("max_uncompressed_batch").Canonical()), "-1": string(PinMismatch("max_uncompressed_batch").Canonical()),
		"1.5": string(PinMismatch("section").Canonical()), `"16777216"`: string(PinMismatch("section").Canonical()), "1e3": string(PinMismatch("section").Canonical())} {
		if _, err := loadArbPins(with(v)); canon(err) != want {
			t.Errorf("%s: %s, want %s", v, canon(err), want)
		}
	}
}

// The cap of the zero-heavy layer is 101% of the batch bound plus 64 (nitro@ccc5c82 arbstate zero-heavy decoding), computed without
// wrapping: exact where it fits, the largest int where it does not.
func TestZeroheavyLimitIsTheNitroCapAndNeverWraps(t *testing.T) {
	exact := func(m int) int {
		s := new(big.Int).SetInt64(int64(m))
		s.Add(s, new(big.Int).Quo(new(big.Int).SetInt64(int64(m)), big.NewInt(100)))
		s.Add(s, big.NewInt(64))
		switch {
		case s.Cmp(big.NewInt(math.MaxInt)) > 0:
			return math.MaxInt
		case s.Cmp(big.NewInt(math.MinInt)) < 0:
			return math.MinInt
		}
		return int(s.Int64())
	}
	// the first m whose cap does not fit an int
	edge := 0
	lo, hi := 1, math.MaxInt
	for lo < hi {
		mid := lo + (hi-lo)/2
		if new(big.Int).Add(new(big.Int).Add(big.NewInt(int64(mid)), big.NewInt(int64(mid/100))), big.NewInt(64)).IsInt64() {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	edge = lo
	cases := []int{math.MinInt, math.MinInt + 1, math.MinInt / 100 * 99, -6400, -6399, -64, -1, 0, 1, 36, 100, 101, 999, 1000, 16777216, 1 << 40, edge - 3, edge - 2, edge - 1, edge, edge + 1, edge + 2, math.MaxInt - 64, math.MaxInt - 1, math.MaxInt}
	for _, m := range cases {
		if got, want := zeroheavyLimit(m), exact(m); got != want {
			t.Errorf("zeroheavyLimit(%d) = %d, want %d", m, got, want)
		}
	}
	if zeroheavyLimit(edge) != math.MaxInt || zeroheavyLimit(edge+1) != math.MaxInt {
		t.Errorf("the saturation starts at %d: got %d at it and %d above it", edge, zeroheavyLimit(edge), zeroheavyLimit(edge+1))
	}
	for _, m := range cases {
		if m > 0 && zeroheavyLimit(m) < m {
			t.Errorf("zeroheavyLimit(%d) = %d is below the bound it extends: it wrapped", m, zeroheavyLimit(m))
		}
	}
	if zeroheavyLimit(math.MaxInt) != math.MaxInt || zeroheavyLimit(math.MaxInt-1) != math.MaxInt {
		t.Error("the largest bounds do not saturate")
	}
}

// Through decodePayload: the layer's output may be exactly the cap and not one byte more (N passes, N+1 fails), and the largest bounds decode
// an ordinary payload (they neither wrap into a refusal nor into a cap that is no cap).
func TestZeroheavyLayerCapIsExactAndTheLargestBoundsDecode(t *testing.T) {
	// A layer output that is brotli-headed junk: within the cap it reaches the brotli stage and is undecodable; one byte over the cap it is
	// refused by the layer as too large. The smallest bound whose cap holds the output passes, the bound below it does not.
	junk := append([]byte{headerBrotli}, bytes.Repeat([]byte{0xff}, 200)...)
	zhJunk := zhPayload(junk)
	m := 1
	for zeroheavyLimit(m) < len(junk) {
		m++
	}
	if r := decodePayload(zhJunk, m, 100); r.status != payloadUndecodable {
		t.Errorf("a layer output within the cap (bound %d, cap %d, output %d): %+v", m, zeroheavyLimit(m), len(junk), r)
	}
	if r := decodePayload(zhJunk, m-1, 100); r.status != payloadTooLarge || !r.exceededUncompressed {
		t.Errorf("a layer output over the cap (bound %d, cap %d, output %d): %+v", m-1, zeroheavyLimit(m-1), len(junk), r)
	}
	// an ordinary zero-heavy payload decodes under the largest bounds
	zh := zhPayload(payloadOf(seg(segL2Message, signedTxMsg(legacyTx(1)))))
	for _, huge := range []int{1 << 40, math.MaxInt - 64, math.MaxInt - 1, math.MaxInt} {
		if r := decodePayload(zh, huge, 100); r.status != payloadOK || len(r.messages) != 1 {
			t.Errorf("bound %d: %+v", huge, r)
		}
	}
}
