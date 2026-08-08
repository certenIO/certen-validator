package entitlement

import "testing"

// Cross-language signing vectors.
//
// Header.SigningBytes() here and headerSigningBytes() in the gateway
// (src/services/billing/entitlement.service.ts) must produce IDENTICAL bytes.
// They are two implementations of one wire format, and a divergence is not a bug
// that surfaces as a failing test — it is a fleet-wide outage, because every
// validator's signature check fails at once and, under `enforce`, every block is
// refused.
//
// The literals below are duplicated verbatim in
// test/unit/billing/entitlement-signing-vectors.test.ts. If you change one,
// change both; and if they ever disagree the answer is NOT to make one match the
// other — work out which side already shipped, because that is the one epochs in
// the wild were signed against.
//
// \x1f is the ASCII unit separator used as the field delimiter.

func vectorHeader() Header {
	return Header{
		Epoch:          42,
		Root:           "aabbcc",
		SetHash:        "ddeeff",
		PrevRoot:       "112233",
		NativeUSDMicro: 1913960000,
		IssuedAtUnix:   1786000000,
		NotAfterUnix:   1786007200,
		KeyID:          "entitlement-v1",
	}
}

const v1Vector = "certen:entitlement:v1\x1f42\x1faabbcc\x1fddeeff\x1f112233" +
	"\x1f1913960000\x1f1786000000\x1f1786007200\x1fentitlement-v1"

// v1 must be byte-stable forever: every epoch ever published was signed with
// this preimage, and changing it retroactively invalidates all of them.
func TestV1SigningBytesAreExact(t *testing.T) {
	if got := string(vectorHeader().SigningBytes()); got != v1Vector {
		t.Fatalf("v1 preimage changed.\n got: %q\nwant: %q", got, v1Vector)
	}
}

// An empty slice must be indistinguishable from absent — same bytes, same signature.
func TestEmptyCostBasisIsV1(t *testing.T) {
	h := vectorHeader()
	h.CostBasis = []ChainCostBasis{}
	if got := string(h.SigningBytes()); got != v1Vector {
		t.Fatalf("empty cost basis must produce v1 bytes, got %q", got)
	}
}

func TestV2SigningBytesAreExact(t *testing.T) {
	h := vectorHeader()
	h.CostBasis = []ChainCostBasis{{ChainID: 84532, BaseMicroUSD: 13622, PerLegMicroUSD: 5981}}

	want := "certen:entitlement:v2\x1f" + v1Vector + "\x1f84532:13622:5981"
	if got := string(h.SigningBytes()); got != want {
		t.Fatalf("v2 preimage mismatch.\n got: %q\nwant: %q", got, want)
	}
}

// Chain order must not change the signature. The publisher's row order is an
// accident of a SQL query; the signature must not be.
func TestSigningBytesIndependentOfChainOrder(t *testing.T) {
	a := vectorHeader()
	a.CostBasis = []ChainCostBasis{
		{ChainID: 421614, BaseMicroUSD: 29983, PerLegMicroUSD: 9000},
		{ChainID: 84532, BaseMicroUSD: 13622, PerLegMicroUSD: 5981},
	}
	b := vectorHeader()
	b.CostBasis = []ChainCostBasis{
		{ChainID: 84532, BaseMicroUSD: 13622, PerLegMicroUSD: 5981},
		{ChainID: 421614, BaseMicroUSD: 29983, PerLegMicroUSD: 9000},
	}

	if string(a.SigningBytes()) != string(b.SigningBytes()) {
		t.Fatal("signing bytes depend on chain order; every validator must agree regardless of it")
	}
}

// Signing must not reorder the caller's slice: a mutating sort produces a
// signature that verifies once and never again.
func TestSigningDoesNotMutateCallerSlice(t *testing.T) {
	h := vectorHeader()
	h.CostBasis = []ChainCostBasis{
		{ChainID: 421614, BaseMicroUSD: 1, PerLegMicroUSD: 2},
		{ChainID: 84532, BaseMicroUSD: 3, PerLegMicroUSD: 4},
	}
	_ = h.SigningBytes()
	if h.CostBasis[0].ChainID != 421614 {
		t.Fatal("SigningBytes reordered the caller's cost basis")
	}
}

// Values above 2^53 must survive exactly — the gateway carries these as bigint
// precisely because Number would truncate them.
func TestLargeValuesSurviveExactly(t *testing.T) {
	h := vectorHeader()
	h.CostBasis = []ChainCostBasis{{ChainID: 1, BaseMicroUSD: 9007199254740993, PerLegMicroUSD: 0}}

	if got := string(h.SigningBytes()); !contains(got, "1:9007199254740993:0") {
		t.Fatalf("large value truncated or reformatted: %q", got)
	}
}

func TestCostBasisForFindsAndReportsAbsence(t *testing.T) {
	h := vectorHeader()
	h.CostBasis = []ChainCostBasis{{ChainID: 84532, BaseMicroUSD: 7, PerLegMicroUSD: 3}}

	if c, ok := h.CostBasisFor(84532); !ok || c.BaseMicroUSD != 7 {
		t.Fatalf("CostBasisFor(84532) = %+v, ok=%v", c, ok)
	}
	if _, ok := h.CostBasisFor(999999); ok {
		t.Fatal("an unpublished chain must report absent, not a zero basis")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
