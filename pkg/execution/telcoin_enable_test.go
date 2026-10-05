// Copyright 2026 Certen Protocol

package execution

import (
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// RB7 §4.1 / RB8 §0: Telcoin Adiri (2017) is a catalogued chain, enabled only by naming it in CERTEN_SETTLEMENT_CHAINS.
// Before RB7 the build did not know it, and naming it stopped the boot.
func TestCERTEN_SETTLEMENT_CHAINSCanEnableTelcoinAdiri(t *testing.T) {
	t.Setenv(SettlementChainsEnv, "11155111,84532,421614,2017")
	got, err := SettlementChainsFromEnv(supportedchains.IDs())
	if err != nil || len(got) != 4 || got[0] != 2017 {
		t.Fatalf("(%v, %v)", got, err)
	}
}

// The live value boots exactly the three live chains, as before.
func TestTheLiveSettlementChainsAreUnchanged(t *testing.T) {
	t.Setenv(SettlementChainsEnv, "11155111,84532,421614")
	got, err := SettlementChainsFromEnv(supportedchains.IDs())
	if err != nil || len(got) != 3 || got[0] != 84532 || got[1] != 421614 || got[2] != 11155111 {
		t.Fatalf("(%v, %v)", got, err)
	}
}

func adiriConfig(maxGas, gasLimit int64) *config.AnchorConfig {
	c := &config.AnchorConfig{}
	c.Network.EVMChains = map[int64]*config.EVMChainConfig{
		2017: {ChainID: 2017, RPCURL: "http://127.0.0.1:1", MaxGasPriceGwei: maxGas, GasLimitAnchor: gasLimit},
	}
	return c
}

// RB7 §4.2: an enabled 2017 needs its anchor, its RPC, and a gas ceiling and anchor gas limit measured for its own fee
// market - none compiled in. Each missing one stops the boot, by the variable to set. Before, a 2017 with no ceiling was
// accepted, and a zero ceiling is no ceiling at all.
func TestAnEnabledTelcoinAdiriRequiresItsConfiguration(t *testing.T) {
	t.Setenv("CERTEN_ANCHOR_V8_2017", "")
	if _, err := NewEVMChainResolverFromEnv(adiriConfig(250, 3000000), []int64{2017}); err == nil ||
		!strings.Contains(err.Error(), "CERTEN_ANCHOR_V8_2017") {
		t.Fatalf("no anchor: %v", err)
	}
	t.Setenv("CERTEN_ANCHOR_V8_2017", "0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a34")
	if _, err := NewEVMChainResolverFromEnv(&config.AnchorConfig{}, []int64{2017}); err == nil || !strings.Contains(err.Error(), "2017 has no RPC") {
		t.Fatalf("no RPC: %v", err)
	}
	if _, err := NewEVMChainResolverFromEnv(adiriConfig(0, 3000000), []int64{2017}); err == nil ||
		!strings.Contains(err.Error(), "TELCOIN_ADIRI_MAX_GAS_PRICE_GWEI") {
		t.Fatalf("no gas ceiling: %v", err)
	}
	if _, err := NewEVMChainResolverFromEnv(adiriConfig(250, 0), []int64{2017}); err == nil ||
		!strings.Contains(err.Error(), "TELCOIN_ADIRI_GAS_LIMIT_ANCHOR") {
		t.Fatalf("no anchor gas limit: %v", err)
	}
	t.Setenv("CERTEN_NATIVE_USD_2017", "")
	if _, err := NewEVMChainResolverFromEnv(adiriConfig(250, 3000000), []int64{2017}); err == nil ||
		!strings.Contains(err.Error(), "CERTEN_NATIVE_USD_2017") {
		t.Fatalf("no TEL price: %v", err)
	}
	t.Setenv("CERTEN_NATIVE_USD_2017", "0.002")
	r, err := NewEVMChainResolverFromEnv(adiriConfig(250, 3000000), []int64{2017})
	if err != nil {
		t.Fatalf("a fully configured 2017 was refused: %v", err)
	}
	if _, anchor, err := r.Endpoint(2017); err != nil || anchor != common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a34") {
		t.Fatalf("2017 endpoint: %s %v", anchor.Hex(), err)
	}
}

// The live chains, configured from their catalogue defaults (no gas variables set, as on all seven validators), pass.
func TestTheLiveChainsPassTheGasCheckOnTheirDefaults(t *testing.T) {
	for _, id := range []int64{11155111, 84532, 421614} {
		c, _ := supportedchains.Lookup(id)
		if err := requireGasSettings(&config.EVMChainConfig{ChainID: id, MaxGasPriceGwei: c.DefaultMaxGasPriceGwei,
			GasLimitAnchor: c.DefaultGasLimitAnchor}); err != nil {
			t.Fatalf("chain %d: %v", id, err)
		}
	}
}

// RB5-F57 / RB7 §3A.6: 2017 has no default leaf version - it never deploys V7_2 - so enabling it without a 2017 entry in
// CERTEN_ACCOUNT_LEAF_VERSIONS stops the boot by name, and 2017=v4 is accepted.
func TestAnEnabledTelcoinAdiriRequiresItsLeafVersion(t *testing.T) {
	t.Setenv(AccountLeafVersionsEnv, "84532=v4,11155111=v4,421614=v4")
	if _, err := AccountLeafVersionsFromEnv([]int64{84532, 2017}); !errors.Is(err, ErrNoAccountLeafVersion) ||
		!strings.Contains(err.Error(), "2017") {
		t.Fatalf("2017 with no leaf version: %v", err)
	}
	t.Setenv(AccountLeafVersionsEnv, "84532=v4,11155111=v4,421614=v4,2017=v4")
	v, err := AccountLeafVersionsFromEnv([]int64{84532, 2017})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v.For(2017); err != nil || got != AccountLeafV4 {
		t.Fatalf("2017: %v %v", got, err)
	}
}
