// Copyright 2026 Certen Protocol

package execution

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/ethereum/go-ethereum/common"
)

// RB7 Task 4 follow-up: each chain's gas is priced at the native rate the gateway SIGNS for that chain into the
// entitlement epoch (header v3, `native_rates`). It used to be an operator-stated CERTEN_NATIVE_USD (ETH's price) or
// CERTEN_NATIVE_USD_<chainId>; those are now refused at boot. A chain with no fresh signed rate is refused by name -
// never priced at ETH's rate, at the single rate a v1/v2 header carries, or at a configured one.

// fixedRates is a rate source for the tests that only need a number.
type fixedRates map[int64]int64

func (f fixedRates) NativeUSDMicro(chainID int64, _ time.Time) (int64, error) {
	if r, ok := f[chainID]; ok {
		return r, nil
	}
	return 0, fmt.Errorf("NATIVE_RATE_UNPRICED: chain %d", chainID)
}

// withRates installs src for one test and removes it afterwards.
func withRates(t *testing.T, src NativeRateSource) {
	t.Helper()
	SetNativeRateSource(src)
	t.Cleanup(func() { SetNativeRateSource(nil) })
}

// signedStore serves one signed epoch with header h (an empty account set) from a local server and returns the
// validator's own entitlement.Store after it fetched and verified it - the same path main.go wires.
func signedStore(t *testing.T, h entitlement.Header) *entitlement.Store {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := entitlement.Set{Leaves: []entitlement.Leaf{}}
	if h.SetHash, err = set.SetHash(); err != nil {
		t.Fatal(err)
	}
	h.Root, h.KeyID = set.Root(), "rates-test"
	h.Signature = hex.EncodeToString(ed25519.Sign(priv, h.SigningBytes()))
	body, err := json.Marshal(entitlement.Document{Header: h, Set: set})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	store := entitlement.NewStore(entitlement.StoreConfig{URL: srv.URL, MaxAge: 15 * time.Minute, Timeout: 5 * time.Second},
		entitlement.KeySet{"rates-test": pub}, nil)
	if err := store.Refresh(t.Context()); err != nil {
		t.Fatalf("the store refused the signed epoch: %v", err)
	}
	return store
}

// v3Header is a fresh epoch signing the given chain -> micro-USD rates.
func v3Header(rates map[int64]int64) entitlement.Header {
	now := time.Now().Unix()
	h := entitlement.Header{Epoch: 7, IssuedAtUnix: now - 10, NotAfterUnix: now + 900}
	for id, r := range rates {
		h.NativeRates = append(h.NativeRates, entitlement.ChainNativeRate{
			ChainID: id, USDPerNativeMicro: r, Source: "corroborated:test", ObservedAtUnix: now - 30,
		})
	}
	return h
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	var ve *entitlement.VerifyError
	if !errors.As(err, &ve) || ve.Reason != reason {
		t.Fatalf("want %s, got %v", reason, err)
	}
}

const ethRate, telRate = 3000 * usd, 2000 // $3,000 per ETH; $0.002 per TEL

// In one process, a 2017 transaction is priced at TEL's signed rate and an 84532 one at ETH's.
func TestEachChainIsPricedAtItsOwnSignedRate(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	withRates(t, signedStore(t, v3Header(map[int64]int64{84532: ethRate, 2017: telRate})))
	const gas = 2_500_000
	bid := big.NewInt(50 * gwei) // 0.125 native: $375 at ETH's rate, $0.00025 at TEL's
	var exceeded *ErrTxCostCeilingExceeded
	if err := txCostCeiling(gas, bid, 84532); !errors.As(err, &exceeded) {
		t.Fatalf("84532 at ETH's signed rate: %v", err)
	}
	if err := txCostCeiling(gas, bid, 2017); err != nil {
		t.Fatalf("2017 at TEL's signed rate: %v", err)
	}
	if got, err := nativeUSDMicroFor(2017, time.Now()); err != nil || got != telRate {
		t.Fatalf("2017 rate %d %v", got, err)
	}
}

// A chain the epoch does not price is refused by name, never priced at ETH's rate.
func TestAChainWithoutASignedRateIsRefusedByName(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	withRates(t, signedStore(t, v3Header(map[int64]int64{84532: ethRate})))
	err := txCostCeiling(21000, big.NewInt(7), 2017)
	wantReason(t, err, entitlement.ReasonRateUnpriced)
	if !strings.Contains(err.Error(), "2017") {
		t.Fatalf("the refusal does not name the chain: %v", err)
	}
}

// A v1/v2 epoch carries one rate (ETH's) for every chain. It prices nothing: the chain is refused by name.
func TestAHeaderBeforeV3PricesNoChain(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	now := time.Now().Unix()
	v2 := entitlement.Header{Epoch: 7, NativeUSDMicro: ethRate, IssuedAtUnix: now - 10, NotAfterUnix: now + 900,
		CostBasis: []entitlement.ChainCostBasis{{ChainID: 84532, BaseMicroUSD: 13622, PerLegMicroUSD: 5981}}}
	withRates(t, signedStore(t, v2))
	for _, id := range []int64{84532, 2017} {
		wantReason(t, txCostCeiling(21000, big.NewInt(7), id), entitlement.ReasonRateUnpriced)
	}
}

// A signed rate observed more than MaxNativeRateAge ago is refused, even inside an unexpired epoch.
func TestAStaleSignedRateIsRefused(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	h := v3Header(map[int64]int64{84532: ethRate})
	h.NativeRates[0].ObservedAtUnix = time.Now().Unix() - entitlement.MaxNativeRateAge - 60
	withRates(t, signedStore(t, h))
	wantReason(t, txCostCeiling(21000, big.NewInt(7), 84532), entitlement.ReasonRateStale)
}

// An active ceiling with no rate source wired refuses by name rather than sending unpriced.
func TestAnActiveCeilingWithNoSourceRefuses(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	withRates(t, nil)
	if err := txCostCeiling(21000, big.NewInt(7), 84532); err == nil || !strings.Contains(err.Error(), "NATIVE_RATE_UNPRICED") {
		t.Fatalf("an active ceiling with no rate source: %v", err)
	}
}

// A configured price never prices a chain any more: with the ceiling active and no signed rate, a transaction is
// refused by name, whatever CERTEN_NATIVE_USD or CERTEN_NATIVE_USD_<chainId> say. (Before, 2017 was priced at
// CERTEN_NATIVE_USD_2017 and 84532 at CERTEN_NATIVE_USD, and both passed.)
func TestAConfiguredPriceNeverPricesAChain(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	t.Setenv("CERTEN_NATIVE_USD", "3000")
	t.Setenv("CERTEN_NATIVE_USD_2017", "0.002")
	withRates(t, nil)
	for _, id := range []int64{2017, 84532} {
		if err := txCostCeiling(21000, big.NewInt(7), id); err == nil || !strings.Contains(err.Error(), "NATIVE_RATE_UNPRICED") {
			t.Fatalf("chain %d was priced from configuration: %v", id, err)
		}
	}
}

// The operator-stated prices the signed rates replace are refused at boot, each by name: a price nobody signs cannot
// stand beside the signed one, and ignoring it would silently switch off a ceiling its operator believed active.
func TestTheConfiguredNativePricesAreRefusedAtBoot(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "")
	if err := CheckEnv(); err != nil {
		t.Fatalf("a deployment without the old prices was refused: %v", err)
	}
	for _, name := range []string{"CERTEN_NATIVE_USD", "CERTEN_NATIVE_USD_2017", "CERTEN_NATIVE_USD_84532"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "3000")
			if err := CheckEnv(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s=3000 passed the boot check: %v", name, err)
			}
		})
	}
}

// The three live chains (all ETH) are byte-identical: priced at the signed rate R, every verdict and every refusal
// text is exactly what the old CERTEN_NATIVE_USD=R path produced, which was checkTxCostCeiling at that price.
func TestTheLiveChainsDecideExactlyAsAtTheSameETHPrice(t *testing.T) {
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	const r = 2_713_640_000 // $2,713.64 per ETH
	withRates(t, signedStore(t, v3Header(map[int64]int64{84532: r, 11155111: r, 421614: r, 2017: telRate})))
	for _, id := range []int64{84532, 11155111, 421614} {
		for _, gas := range []uint64{21_000, 156_318, 650_000, 2_500_000} {
			for _, g := range []int64{1, 7, 24 * gwei, 100 * gwei} {
				bid := big.NewInt(g)
				want := checkTxCostCeiling(gas, bid, r, 25*usd, id)
				got := txCostCeiling(gas, bid, id)
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Fatalf("chain %d gas %d bid %d: got %v, want %v", id, gas, g, got, want)
				}
			}
		}
	}
}

// The provenance a member records names the leg chain's own token: TEL on 2017, ETH on the live chains (as before).
func TestTheProvenanceTokenIsTheLegChainsNativeToken(t *testing.T) {
	for id, want := range map[int64]string{2017: "TEL", 84532: "ETH", 11155111: "ETH", 421614: "ETH"} {
		p := &PendingBatchIntent{Legs: []LegExecution{{ChainID: id, Target: common.HexToAddress("0x01"), Value: big.NewInt(1)}}}
		if got := p.provenance().TokenSymbol; got != want {
			t.Fatalf("chain %d: provenance token %q, want %q", id, got, want)
		}
	}
}
