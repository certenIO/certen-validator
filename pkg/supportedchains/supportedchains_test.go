package supportedchains

import (
	"strings"
	"testing"
)

// The catalogue holds the three chains running CERTEN's current contracts and Telcoin Adiri, and nothing retired.
func TestTheCatalogueIsTheThreeLiveChainsAndTelcoinAdiri(t *testing.T) {
	want := map[int64]string{11155111: "ethereum-sepolia", 84532: "base-sepolia", 421614: "arbitrum-sepolia", 2017: "telcoin-adiri"}
	if len(All) != len(want) {
		t.Fatalf("%d catalogued chains, want %d", len(All), len(want))
	}
	for id, name := range want {
		c, ok := Lookup(id)
		if !ok || c.Name != name {
			t.Fatalf("chain %d: %+v, %v", id, c, ok)
		}
	}
	for _, retired := range []int64{1, 11155420, 80002, 97, 1287, 296, 0} {
		if IsSupported(retired) {
			t.Fatalf("chain %d is catalogued", retired)
		}
	}
	if Describe() != "ethereum-sepolia (11155111), base-sepolia (84532), arbitrum-sepolia (421614), telcoin-adiri (2017)" {
		t.Fatalf("describe: %s", Describe())
	}
}

// The three live chains' entries are exactly the values every table that repeated them held at origin/main 0fc818e:
// strategy network names, ethrpc keys, loadEVMChainsFromEnv's rows and the Arbitrum L1-block property.
func TestTheLiveChainsEntriesAreUnchanged(t *testing.T) {
	type row struct {
		network, rpcKey, display, rpcEnv, wsEnv, legacy, gas, factory, explorer string
		maxGas, prio, gasLimit                                                  int64
		parent                                                                  bool
	}
	want := map[int64]row{
		11155111: {"sepolia", "ethereum-sepolia", "Ethereum Sepolia", "ETHEREUM_SEPOLIA_RPC_URL", "ETHEREUM_SEPOLIA_WS_URL",
			"ETHEREUM_URL", "SEPOLIA", "SEPOLIA", "https://sepolia.etherscan.io", 100, 2, 500000, false},
		84532: {"base-sepolia", "base-sepolia", "Base Sepolia", "BASE_SEPOLIA_RPC_URL", "BASE_SEPOLIA_WS_URL",
			"", "BASE", "BASE_SEPOLIA", "https://sepolia.basescan.org", 1, 0, 2000000, false},
		421614: {"arbitrum-sepolia", "arbitrum-sepolia", "Arbitrum Sepolia", "ARBITRUM_SEPOLIA_RPC_URL", "ARBITRUM_SEPOLIA_WS_URL",
			"", "ARBITRUM", "ARBITRUM_SEPOLIA", "https://sepolia.arbiscan.io", 1, 0, 2000000, true},
	}
	for id, w := range want {
		c, _ := Lookup(id)
		got := row{c.Network, c.RPCKey, c.DisplayName, c.RPCURLEnv(), c.WSURLEnv(), c.LegacyRPCEnv, c.GasEnvPrefix,
			c.FactoryEnvPrefix, c.ExplorerURL, c.DefaultMaxGasPriceGwei, c.DefaultMaxPriorityFeeGwei, c.DefaultGasLimitAnchor,
			c.ContractBlockIsParent}
		if got != w {
			t.Fatalf("chain %d:\n got %+v\nwant %+v", id, got, w)
		}
		if c.NativeSymbol != "ETH" || c.NativeDecimals != 18 {
			t.Fatalf("chain %d native %s/%d", id, c.NativeSymbol, c.NativeDecimals)
		}
	}
}

// Telcoin Adiri: chain 2017, TEL with 18 decimals, its own block numbers, and no gas default compiled in.
func TestTelcoinAdiriIsCataloguedWithItsOwnFactsAndNoCopiedDefaults(t *testing.T) {
	c, ok := Lookup(2017)
	if !ok {
		t.Fatal("2017 is not catalogued")
	}
	if c.NativeSymbol != "TEL" || c.NativeDecimals != 18 || c.ContractBlockIsParent || c.Family != "telcoin" || !c.Testnet {
		t.Fatalf("2017: %+v", c)
	}
	if c.RPCURLEnv() != "TELCOIN_ADIRI_RPC_URL" || c.URLFallbacksEnv() != "TELCOIN_ADIRI_URL_FALLBACKS" ||
		c.MaxGasPriceEnv() != "TELCOIN_ADIRI_MAX_GAS_PRICE_GWEI" || c.GasLimitAnchorEnv() != "TELCOIN_ADIRI_GAS_LIMIT_ANCHOR" {
		t.Fatalf("2017 env names: %s %s %s %s", c.RPCURLEnv(), c.URLFallbacksEnv(), c.MaxGasPriceEnv(), c.GasLimitAnchorEnv())
	}
	if c.DefaultMaxGasPriceGwei != 0 || c.DefaultGasLimitAnchor != 0 || c.LegacyRPCEnv != "" {
		t.Fatalf("2017 carries a compiled default: %+v", c)
	}
}

func TestLookupNameTakesEveryNameOfAChainAndNothingElse(t *testing.T) {
	for name, id := range map[string]int64{
		"ethereum-sepolia": 11155111, "sepolia": 11155111, "eth-sepolia": 11155111, "Ethereum_Sepolia": 11155111,
		"base-sepolia": 84532, "Base Sepolia": 84532, "arbitrum-sepolia": 421614,
		"telcoin-adiri": 2017, "Telcoin Adiri": 2017, "adiri": 2017, "TEL_ADIRI": 2017,
	} {
		c, ok := LookupName(name)
		if !ok || c.ID != id {
			t.Fatalf("%q: %+v %v, want %d", name, c, ok, id)
		}
	}
	for _, name := range []string{"", "telcoin", "base", "arbitrum", "ethereum", "optimism-sepolia", "arb"} {
		if c, ok := LookupName(name); ok {
			t.Fatalf("%q names %d", name, c.ID)
		}
	}
}

// RB7 §4.1 / RB8 §0: the enabled set is CERTEN_SETTLEMENT_CHAINS alone; a catalogued chain it does not name is not
// enabled - 2017 included, which no default names.
func TestTheEnabledSetIsTheConfigurationAlone(t *testing.T) {
	t.Setenv(EnabledEnv, "11155111,84532,421614")
	for _, id := range []int64{11155111, 84532, 421614} {
		if !IsEnabled(id) {
			t.Fatalf("%d not enabled", id)
		}
	}
	if IsEnabled(2017) {
		t.Fatal("2017 is enabled without being named")
	}
	cs, err := Enabled()
	if err != nil || len(cs) != 3 || cs[0].ID != 11155111 || cs[2].ID != 421614 {
		t.Fatalf("enabled %+v %v", cs, err)
	}

	t.Setenv(EnabledEnv, "2017,84532")
	if ids, err := EnabledFromEnv(); err != nil || len(ids) != 2 || ids[0] != 2017 || ids[1] != 84532 {
		t.Fatalf("enabled %v %v", ids, err)
	}
	if !IsEnabled(2017) || IsEnabled(11155111) {
		t.Fatal("the enabled set is not what the configuration names")
	}

	for _, bad := range []string{"", "  ", "84532,x", "84532,84532", "84532,11155420"} {
		t.Setenv(EnabledEnv, bad)
		if _, err := EnabledFromEnv(); err == nil || !strings.Contains(err.Error(), EnabledEnv) {
			t.Fatalf("%q: %v", bad, err)
		}
		if IsEnabled(84532) {
			t.Fatalf("%q enables 84532", bad)
		}
	}
}

func TestDescribeIDsListsInCatalogueOrder(t *testing.T) {
	if got := DescribeIDs([]int64{421614, 11155111, 84532}); got != "ethereum-sepolia (11155111), base-sepolia (84532), arbitrum-sepolia (421614)" {
		t.Fatalf("%s", got)
	}
	if got := DescribeIDs([]int64{97, 2017}); got != "telcoin-adiri (2017), 97" {
		t.Fatalf("%s", got)
	}
}
