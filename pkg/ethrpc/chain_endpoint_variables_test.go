package ethrpc

import (
	"reflect"
	"strings"
	"testing"
)

// RB12-DBFIX-FIX: the variables that make up a chain's endpoint list are one table, read by EndpointsForChain and by every check
// that must name them (the finality runtime's startup validation, the read-only deploy check). A variable that EndpointsForChain
// reads and the table lacks was how ETHEREUM_SEPOLIA_URL_FALLBACKS escaped the deploy check.

func TestEndpointVariablesForChainNameEveryVariableEndpointsForChainReads(t *testing.T) {
	for _, chain := range []string{"ethereum-sepolia", "base-sepolia", "arbitrum-sepolia", "telcoin-adiri", "optimism-sepolia", "Base Sepolia", "sepolia"} {
		names := EndpointVariablesForChain(chain)
		if len(names) == 0 {
			t.Fatalf("%q: no variables", chain)
		}
		// each variable on its own makes EndpointsForChain return exactly that entry, in the list's order
		for i, name := range names {
			for _, other := range names {
				t.Setenv(other, "")
			}
			want := "https://only-" + strings.ToLower(strings.ReplaceAll(name, "_", "-")) + ".example/k"
			t.Setenv(name, want)
			got := EndpointsForChain(chain)
			if len(got) != 1 || got[0] != want {
				t.Fatalf("%q: variable %d %s is in the table but EndpointsForChain does not read it: %v", chain, i, name, got)
			}
			t.Setenv(name, "")
		}
		// and the table is complete: every variable EndpointsForChain reads is in it. Each name in the table set to a distinct value
		// yields exactly the table's order.
		var wantAll []string
		for _, name := range names {
			v := "https://all-" + strings.ToLower(strings.ReplaceAll(name, "_", "-")) + ".example"
			t.Setenv(name, v)
			wantAll = append(wantAll, v)
		}
		if got := EndpointsForChain(chain); !reflect.DeepEqual(got, wantAll) {
			t.Fatalf("%q: EndpointsForChain with every listed variable set is\n %v\nwant the table's order\n %v", chain, got, wantAll)
		}
		for _, name := range names {
			t.Setenv(name, "")
		}
	}
}

func TestEndpointVariablesForChainAreTheDocumentedOnes(t *testing.T) {
	for chain, want := range map[string][]string{
		"ethereum-sepolia": {"ETHEREUM_SEPOLIA_RPC_URL", "ETHEREUM_URL", "ETHEREUM_SEPOLIA_URL_FALLBACKS", "ETHEREUM_URL_FALLBACKS", "INFURA_SEPOLIA_URL", "ALCHEMY_SEPOLIA_URL"},
		"base-sepolia":     {"BASE_SEPOLIA_RPC_URL", "BASE_SEPOLIA_URL_FALLBACKS", "INFURA_BASE_SEPOLIA_URL", "ALCHEMY_BASE_SEPOLIA_URL"},
		"Telcoin Adiri":    {"TELCOIN_ADIRI_RPC_URL", "TELCOIN_ADIRI_URL_FALLBACKS", "INFURA_TELCOIN_ADIRI_URL", "ALCHEMY_TELCOIN_ADIRI_URL"},
	} {
		if got := EndpointVariablesForChain(chain); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: %v want %v", chain, got, want)
		}
	}
}

func TestEndpointVariablesForAnEmptyChainKeyAreTheEthereumOnlyVariables(t *testing.T) {
	want := []string{EnvPrimary, EnvPrimaryAlt, EnvFallbacks, EnvInfura, EnvAlchemy}
	if got := EndpointVariablesForChain(""); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v want %v", got, want)
	}
	// the Ethereum-only list: ETHEREUM_URL wins over the alternative, which is consulted only when it is unset
	t.Setenv(EnvPrimary, "https://primary.example")
	t.Setenv(EnvPrimaryAlt, "https://alt.example")
	t.Setenv(EnvFallbacks, "")
	t.Setenv(EnvInfura, "")
	t.Setenv(EnvAlchemy, "")
	if got := EndpointsForChain(""); !reflect.DeepEqual(got, []string{"https://primary.example"}) {
		t.Fatalf("%v", got)
	}
}
