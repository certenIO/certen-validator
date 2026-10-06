// Copyright 2026 Certen Protocol

package entitlement

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// Header v3 (RB7 Task 4 follow-up): the signed header carries a native USD rate per enabled settlement chain instead of
// one ETH rate. The literals below are duplicated verbatim in the gateway's
// test/unit/billing/entitlement-signing-vectors.test.ts; see signing_vectors_test.go for why they must never drift.

func v3VectorHeader() Header {
	h := vectorHeader()
	h.NativeUSDMicro = 0
	h.CostBasis = []ChainCostBasis{{ChainID: 84532, BaseMicroUSD: 13622, PerLegMicroUSD: 5981}}
	h.NativeRates = []ChainNativeRate{
		{ChainID: 2017, USDPerNativeMicro: 1925, Source: "corroborated:coingecko,coinpaprika,tolerance_bps=300", ObservedAtUnix: 1785999900},
		{ChainID: 84532, USDPerNativeMicro: 2713640000, Source: "corroborated:coingecko,coinpaprika,tolerance_bps=300", ObservedAtUnix: 1785999950},
	}
	return h
}

const v1VectorZeroRate = "certen:entitlement:v1\x1f42\x1faabbcc\x1fddeeff\x1f112233" +
	"\x1f0\x1f1786000000\x1f1786007200\x1fentitlement-v1"

const v3Vector = "certen:entitlement:v3\x1f" + v1VectorZeroRate +
	"\x1fcost_basis\x1f84532:13622:5981" +
	"\x1fnative_rates" +
	"\x1f2017:1925:1785999900:corroborated:coingecko,coinpaprika,tolerance_bps=300" +
	"\x1f84532:2713640000:1785999950:corroborated:coingecko,coinpaprika,tolerance_bps=300"

func TestV3SigningBytesAreExact(t *testing.T) {
	if got := string(v3VectorHeader().SigningBytes()); got != v3Vector {
		t.Fatalf("v3 preimage mismatch.\n got: %q\nwant: %q", got, v3Vector)
	}
}

// An empty cost basis is a labelled empty list: the rates can never be read as cost-basis entries.
func TestV3WithNoCostBasisKeepsBothLabels(t *testing.T) {
	h := v3VectorHeader()
	h.CostBasis = nil
	want := "certen:entitlement:v3\x1f" + v1VectorZeroRate + "\x1fcost_basis\x1fnative_rates" +
		"\x1f2017:1925:1785999900:corroborated:coingecko,coinpaprika,tolerance_bps=300" +
		"\x1f84532:2713640000:1785999950:corroborated:coingecko,coinpaprika,tolerance_bps=300"
	if got := string(h.SigningBytes()); got != want {
		t.Fatalf("v3 preimage without a cost basis.\n got: %q\nwant: %q", got, want)
	}
}

// v1 and v2 are untouched: every epoch already published still verifies, and a v2 publisher stays a valid rollback.
func TestV3LeavesV1AndV2BytesUnchanged(t *testing.T) {
	h := vectorHeader()
	if string(h.SigningBytes()) != v1Vector {
		t.Fatal("v1 bytes changed")
	}
	h.CostBasis = []ChainCostBasis{{ChainID: 84532, BaseMicroUSD: 13622, PerLegMicroUSD: 5981}}
	if string(h.SigningBytes()) != "certen:entitlement:v2\x1f"+v1Vector+"\x1f84532:13622:5981" {
		t.Fatal("v2 bytes changed")
	}
	h.NativeRates = []ChainNativeRate{}
	if string(h.SigningBytes()) != "certen:entitlement:v2\x1f"+v1Vector+"\x1f84532:13622:5981" {
		t.Fatal("an empty rate list must leave the header at v2")
	}
}

func TestV3IsIndependentOfRateOrderAndDoesNotMutate(t *testing.T) {
	a := v3VectorHeader()
	b := v3VectorHeader()
	b.NativeRates[0], b.NativeRates[1] = b.NativeRates[1], b.NativeRates[0]
	if string(a.SigningBytes()) != string(b.SigningBytes()) {
		t.Fatal("v3 bytes depend on the rates' order")
	}
	if b.NativeRates[0].ChainID != 84532 {
		t.Fatal("SigningBytes reordered the caller's rates")
	}
}

// Every signed field is in the preimage: changing any one invalidates the signature.
func TestEveryRateFieldIsSigned(t *testing.T) {
	base := string(v3VectorHeader().SigningBytes())
	for name, mutate := range map[string]func(*Header){
		"rate":     func(h *Header) { h.NativeRates[0].USDPerNativeMicro++ },
		"observed": func(h *Header) { h.NativeRates[0].ObservedAtUnix++ },
		"source":   func(h *Header) { h.NativeRates[0].Source = "manual" },
		"chain":    func(h *Header) { h.NativeRates[0].ChainID = 2018 },
		"single":   func(h *Header) { h.NativeUSDMicro = 1 },
	} {
		h := v3VectorHeader()
		mutate(&h)
		if string(h.SigningBytes()) == base {
			t.Errorf("%s is not covered by the signature", name)
		}
	}
}

// A v3 epoch verifies in the consensus gate exactly like v1/v2: same signature rule, same freshness, same leaf proof.
func TestAV3EpochVerifiesInTheGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	set := &Set{Leaves: []Leaf{{ADIURL: "acc://payer.acme/data", Status: StatusActive,
		IntentCeilingMicroUSD: 5_000_000, EpochCeilingMicroUSD: 50_000_000}}}
	sh, _ := set.SetHash()
	h := v3VectorHeader()
	h.Root, h.SetHash, h.KeyID = set.Root(), sh, "k"
	h.Signature = hex.EncodeToString(ed25519.Sign(priv, h.SigningBytes()))
	proof, leaf, _ := set.BuildProof("acc://payer.acme/data")
	ev := &Evidence{Header: h, Leaf: leaf, Proof: proof}
	if err := Verify(ev, "acc://payer.acme/data", h.IssuedAtUnix+1, KeySet{"k": pub}); err != nil {
		t.Fatalf("a v3 epoch was refused: %v", err)
	}
	ev.Header.NativeRates[1].USDPerNativeMicro = 1 // a mirror rewriting ETH's rate
	if err := Verify(ev, "acc://payer.acme/data", h.IssuedAtUnix+1, KeySet{"k": pub}); err == nil {
		t.Fatal("a rewritten rate verified")
	}
}

func rateReason(t *testing.T, err error) string {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("not a VerifyError: %v", err)
	}
	return ve.Reason
}

func TestNativeRateFor(t *testing.T) {
	now := int64(1786000100)
	h := v3VectorHeader()
	if r, err := h.NativeRateFor(2017, now); err != nil || r != 1925 {
		t.Fatalf("2017: %d %v", r, err)
	}
	if r, err := h.NativeRateFor(84532, now); err != nil || r != 2713640000 {
		t.Fatalf("84532: %d %v", r, err)
	}
	cases := map[string]struct {
		mutate func(*Header)
		chain  int64
		reason string
	}{
		"a chain the epoch does not price":    {func(*Header) {}, 421614, ReasonRateUnpriced},
		"a v2 header (one ETH rate)":          {func(h *Header) { h.NativeRates = nil; h.NativeUSDMicro = 3e9 }, 84532, ReasonRateUnpriced},
		"a v3 header with a single rate too":  {func(h *Header) { h.NativeUSDMicro = 3e9 }, 84532, ReasonRateInvalid},
		"a zero rate":                         {func(h *Header) { h.NativeRates[1].USDPerNativeMicro = 0 }, 84532, ReasonRateInvalid},
		"two rates for one chain":             {func(h *Header) { h.NativeRates[0].ChainID = 84532 }, 84532, ReasonRateInvalid},
		"an empty source":                     {func(h *Header) { h.NativeRates[1].Source = " " }, 84532, ReasonRateInvalid},
		"a control character in the source":   {func(h *Header) { h.NativeRates[1].Source = "a\x1f9:9:9:x" }, 84532, ReasonRateInvalid},
		"observed after the epoch was issued": {func(h *Header) { h.NativeRates[1].ObservedAtUnix = h.IssuedAtUnix + 1 }, 84532, ReasonRateInvalid},
		"observed too long ago": {func(h *Header) {
			h.NativeRates[1].ObservedAtUnix = now - MaxNativeRateAge - 1
		}, 84532, ReasonRateStale},
	}
	for name, c := range cases {
		h := v3VectorHeader()
		c.mutate(&h)
		_, err := h.NativeRateFor(c.chain, now)
		if got := rateReason(t, err); got != c.reason {
			t.Errorf("%s: %s (%v), want %s", name, got, err, c.reason)
		}
	}
	// The age limit is inclusive.
	h = v3VectorHeader()
	h.NativeRates[1].ObservedAtUnix = now - MaxNativeRateAge
	if _, err := h.NativeRateFor(84532, now); err != nil {
		t.Fatalf("a rate exactly MaxNativeRateAge old: %v", err)
	}
}

// The store prices only from an epoch it fetched, verified, still holds as fresh and that has not expired.
func TestStoreNativeUSDMicroRefusals(t *testing.T) {
	if _, err := NewStore(StoreConfig{}, nil, nil).NativeUSDMicro(84532, time.Now()); rateReason(t, err) != ReasonRateUnpriced ||
		!strings.Contains(err.Error(), "CERTEN_ENTITLEMENT_URL") {
		t.Fatalf("a disabled store: %v", err)
	}
	s := NewStore(StoreConfig{URL: "http://127.0.0.1:0", MaxAge: time.Minute}, nil, nil)
	if _, err := s.NativeUSDMicro(84532, time.Now()); rateReason(t, err) != ReasonRateUnpriced {
		t.Fatalf("a store that never fetched: %v", err)
	}
	h := v3VectorHeader()
	s.header, s.fetchedAt = &h, time.Unix(h.IssuedAtUnix, 0)
	at := time.Unix(h.IssuedAtUnix+30, 0)
	if r, err := s.NativeUSDMicro(84532, at); err != nil || r != 2713640000 {
		t.Fatalf("a fresh epoch: %d %v", r, err)
	}
	if _, err := s.NativeUSDMicro(84532, at.Add(2*time.Minute)); rateReason(t, err) != ReasonRateStale {
		t.Fatalf("an epoch held past MaxAge: %v", err)
	}
	s.cfg.MaxAge = 0
	if _, err := s.NativeUSDMicro(84532, time.Unix(h.NotAfterUnix+1, 0)); rateReason(t, err) != ReasonRateStale {
		t.Fatalf("an expired epoch: %v", err)
	}
}

// The gateway's v3 document carries every enabled chain's own rate: TEL's for 2017 and ETH's for the live chains.
func TestGatewayProducedV3DocumentPricesEachChainItself(t *testing.T) {
	doc, _ := loadV3RoundTrip(t)
	now := doc.Header.IssuedAtUnix + 60
	for id, want := range map[int64]int64{2017: 1925, 84532: 2713640000, 11155111: 2713640000, 421614: 2713640000} {
		if got, err := doc.Header.NativeRateFor(id, now); err != nil || got != want {
			t.Fatalf("chain %d: %d %v, want %d", id, got, err, want)
		}
	}
	if doc.Header.NativeUSDMicro != 0 {
		t.Fatalf("a v3 document states a single rate %d", doc.Header.NativeUSDMicro)
	}
	if _, err := doc.Header.NativeRateFor(1, now); rateReason(t, err) != ReasonRateUnpriced {
		t.Fatalf("a chain the document does not price: %v", err)
	}
}
