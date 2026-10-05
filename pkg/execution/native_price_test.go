// Copyright 2026 Certen Protocol

package execution

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB7 Task 4 (V-3): one CERTEN_NATIVE_USD priced every chain's gas as ETH. A Telcoin Adiri (2017) transaction pays TEL,
// so it is priced at CERTEN_NATIVE_USD_2017 - and refused, never priced at ETH's rate, when that is not set. The ETH
// chains keep CERTEN_NATIVE_USD exactly as before.

func TestATelcoinAdiriTransactionIsNeverPricedAtETHsRate(t *testing.T) {
	t.Setenv("CERTEN_NATIVE_USD", "3000")
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	t.Setenv("CERTEN_NATIVE_USD_2017", "")
	err := txCostCeiling(21000, big.NewInt(7), 2017)
	if err == nil || !strings.Contains(err.Error(), "TEL") || !strings.Contains(err.Error(), "CERTEN_NATIVE_USD_2017") {
		t.Fatalf("a 2017 transaction with no TEL price: %v", err)
	}
}

// In one process, a 2017 transaction is priced at TEL's price and an 84532 one at ETH's.
func TestEachChainIsPricedInItsOwnNativeToken(t *testing.T) {
	t.Setenv("CERTEN_NATIVE_USD", "3000")
	t.Setenv("CERTEN_MAX_TX_COST_USD", "25")
	t.Setenv("CERTEN_NATIVE_USD_2017", "0.002")
	const gas, gwei = 2_500_000, 1_000_000_000
	bid := big.NewInt(50 * gwei) // 0.125 native: $375 at ETH's price, $0.00025 at TEL's
	var exceeded *ErrTxCostCeilingExceeded
	if err := txCostCeiling(gas, bid, 84532); !errors.As(err, &exceeded) {
		t.Fatalf("84532 at ETH's price: %v", err)
	}
	if err := txCostCeiling(gas, bid, 2017); err != nil {
		t.Fatalf("2017 at TEL's price: %v", err)
	}
	if got, err := nativeUSDMicroFor(2017); err != nil || got != 2000 {
		t.Fatalf("2017 price %d %v", got, err)
	}
}

// The ETH chains, with no price of their own (as on all seven validators), read CERTEN_NATIVE_USD exactly as before -
// including the unset case, which leaves the dollar ceiling inactive; a price of their own, when set, is theirs.
func TestTheETHChainsKeepCERTEN_NATIVE_USD(t *testing.T) {
	for _, v := range []string{"", "3000"} {
		t.Setenv("CERTEN_NATIVE_USD", v)
		want, _ := nativeUSDMicro()
		for _, id := range []int64{11155111, 84532, 421614, 1} {
			if got, err := nativeUSDMicroFor(id); err != nil || got != want {
				t.Fatalf("chain %d with CERTEN_NATIVE_USD=%q: %d %v, want %d", id, v, got, err, want)
			}
		}
	}
	t.Setenv("CERTEN_NATIVE_USD_84532", "2500")
	if got, _ := nativeUSDMicroFor(84532); got != 2500_000000 {
		t.Fatalf("84532's own price not read: %d", got)
	}
	t.Setenv("CERTEN_NATIVE_USD_84532", "-1")
	if err := CheckEnv(); err == nil || !strings.Contains(err.Error(), "CERTEN_NATIVE_USD_84532") {
		t.Fatalf("an unusable per-chain price passed the boot check: %v", err)
	}
	// A chain whose gas token is not known has no price that applies.
	if _, err := nativeUSDMicroFor(424242); err == nil {
		t.Fatal("an unknown chain was priced")
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
