// Copyright 2026 Certen Protocol

package runtime

import (
	"strings"
	"testing"
)

// RB11-DBFIX D4: every URL-valued variable is validated at startup. A list entry must be an http(s) URL with a host; a variable
// that is set but holds no entry (",,,") is a refusal and never an empty list that overrides the default; the refusal names the
// variable and the INDEX of the entry and never its value, which may hold a credential.

var rtURLLists = []string{EnvL1RPCURLs, EnvL1ProofURLs, EnvArchiveURLs, EnvLCURLs, EnvBeaconURLs, EnvAdiriURLs}

func TestRTConfigRefusesAURLListEntryThatIsNotAnHTTPURLWithAHostNamingTheVariableAndIndexNeverTheValue(t *testing.T) {
	const secret = "hunter2-fake-credential"
	for _, env := range rtURLLists {
		for name, tc := range map[string]struct {
			value string
			index string
		}{
			"words that are not a url":             {"not a url", "entry 0"},
			"a scheme-less host and path":          {"https://ok.example/k1, user:" + secret + "@rpc.example.com/path", "entry 1"},
			"a scheme-less host with a credential": {"user:" + secret + "@rpc.example.com", "entry 0"},
			"a scheme that is not http(s)":         {"https://ok.example/k1,ftp://u:" + secret + "@host.example/x,https://ok2.example", "entry 1"},
			"a websocket scheme":                   {"wss://u:" + secret + "@host.example/x", "entry 0"},
			"no host":                              {"https://ok.example,https:///" + secret, "entry 1"},
			"a port and no host":                   {"http://:8545/" + secret, "entry 0"},
			"a port that is not a number":          {"https://host.example:" + secret + "/x", "entry 0"},
			"a bare word after a good entry":       {"https://ok.example/k,typo" + secret, "entry 1"},
		} {
			t.Run(env+"/"+name, func(t *testing.T) {
				rtClearEnv(t)
				t.Setenv(env, tc.value)
				_, err := ConfigFromEnv()
				if err == nil {
					t.Fatalf("%s=%q was accepted", env, tc.value)
				}
				msg := err.Error()
				if !strings.Contains(msg, env) || !strings.Contains(msg, tc.index) {
					t.Fatalf("the refusal %q must name %s and %s", msg, env, tc.index)
				}
				if strings.Contains(msg, secret) || strings.Contains(msg, "rpc.example.com") || strings.Contains(msg, "host.example") {
					t.Fatalf("the refusal leaks the value: %q", msg)
				}
			})
		}
		t.Run(env+"/a variable that holds no entry does not become an empty list that overrides the default", func(t *testing.T) {
			for _, v := range []string{",,,", " , ; ", ";"} {
				rtClearEnv(t)
				t.Setenv(env, v)
				c, err := ConfigFromEnv()
				if err == nil {
					t.Fatalf("%s=%q was accepted (L1RPC %v, LC %v)", env, v, c.L1RPC, c.LC)
				}
				if !strings.Contains(err.Error(), env) || !strings.Contains(err.Error(), "no entry") {
					t.Fatalf("the refusal %q must name %s and say it holds no entry", err, env)
				}
			}
		})
		t.Run(env+"/good lists are accepted in every separator the validator already accepted", func(t *testing.T) {
			rtClearEnv(t)
			t.Setenv(env, "https://a.example/k1, http://b.example:8545;https://c.example/path?x=1\nhttps://u:p@d.example")
			c, err := ConfigFromEnv()
			if err != nil {
				t.Fatalf("a good list was refused: %v", err)
			}
			_ = c
		})
	}
}

func TestRTConfigRefusesAPerChainProviderListEntryThatIsNotAnHTTPURLNamingTheChainAndIndexNeverTheValue(t *testing.T) {
	const secret = "hunter2-fake-credential"
	for env, chain := range map[string]string{
		"BASE_SEPOLIA_RPC_URL": "base-sepolia", "ARBITRUM_SEPOLIA_URL_FALLBACKS": "arbitrum-sepolia", "TELCOIN_ADIRI_RPC_URL": "telcoin-adiri",
		"ETHEREUM_SEPOLIA_RPC_URL": "ethereum-sepolia",
	} {
		rtClearEnv(t)
		t.Setenv(env, "https://ok.example/k,user:"+secret+"@rpc.example.com/p")
		_, err := ConfigFromEnv()
		if err == nil {
			t.Fatalf("%s with a scheme-less entry was accepted", env)
		}
		if !strings.Contains(err.Error(), chain) || !strings.Contains(err.Error(), "entry 1") || strings.Contains(err.Error(), secret) {
			t.Fatalf("%s: the refusal %q must name %s and entry 1 and not the value", env, err, chain)
		}
	}
}
