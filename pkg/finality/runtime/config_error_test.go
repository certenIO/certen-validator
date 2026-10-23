// Copyright 2026 Certen Protocol

package runtime

import (
	"errors"
	"strings"
	"testing"
)

// RB12-DBFIX-FIX (verifier V3, V4): a refused provider entry is a typed ConfigError naming the variable, the position of the entry
// and a class - never the value - so the process can announce it as a named state instead of dying, and so a deploy check can print
// the same words. The rule is url.Parse's: what it rejects is refused, a scheme in any case is read as url.Parse reads it.

func TestRTConfigRefusalIsATypedErrorNamingVariablePositionAndClassNeverTheValue(t *testing.T) {
	const secret = "hunter2-fake-credential"
	for _, tc := range []struct {
		name, value string
		entry       int
		class       string
	}{
		{"an escape url.Parse rejects (the verifier's input)", "https://ok.example,https://u:p%ss" + secret + "@h/", 1, ClassBadEscape},
		{"a port that is not a number (the verifier's input)", "https://h:abc" + secret + "/", 0, ClassBadPort},
		{"a websocket scheme", "wss://u:" + secret + "@host.example/x", 0, ClassOtherScheme},
		{"a scheme-less host", "rpc.example.com/" + secret, 0, ClassNoScheme},
		{"words", "https://ok.example/k, not", 1, ClassNoScheme},
		{"no host", "https://ok.example,https:///" + secret, 1, ClassNoHost},
		{"a control character", "https://ok.example/k,https://host.example/\x01" + secret, 1, ClassControlCharacter},
		{"a bad userinfo", "https://u" + secret + "<>@host.example/", 0, ClassBadUserinfo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range ProviderVariables() {
				rtClearEnv(t)
				t.Setenv(v.Name, tc.value)
				_, err := ConfigFromEnv()
				var ce *ConfigError
				if !errors.As(err, &ce) {
					t.Fatalf("%s: want a *ConfigError, got %T %v", v.Name, err, err)
				}
				if ce.Variable != v.Name || ce.Entry != tc.entry || ce.Class != tc.class || ce.Chain != v.Chain {
					t.Fatalf("%s: got variable=%q chain=%q entry=%d class=%q, want variable=%q chain=%q entry=%d class=%q", v.Name, ce.Variable, ce.Chain, ce.Entry, ce.Class, v.Name, v.Chain, tc.entry, tc.class)
				}
				for _, bad := range []string{secret, "host.example", "ok.example", "rpc.example.com", "hunter2", "%ss"} {
					if strings.Contains(err.Error(), bad) {
						t.Fatalf("%s: the refusal %q holds part of the value (%q)", v.Name, err.Error(), bad)
					}
				}
			}
		})
	}
}

// The scheme of a URL is case-insensitive (url.Parse lower-cases it); the rule must not refuse what the runtime would use.
func TestRTConfigAcceptsASchemeInAnyCaseAndEveryEntryUrlParseAccepts(t *testing.T) {
	for _, v := range ProviderVariables() {
		for _, good := range []string{"HTTPS://h.example/", "Http://h.example:8545/k", "https://u:p%40w@h.example/p%20q?x=%zz", "https://[::1]:8545/", "https://h.example/#frag"} {
			rtClearEnv(t)
			t.Setenv(v.Name, good)
			if _, err := ConfigFromEnv(); err != nil {
				t.Fatalf("%s=%q was refused: %v", v.Name, good, err)
			}
		}
	}
}

// Every variable the finality runtime parses as a provider list is in the table, and a variable that is set but holds no entry is
// reported as a refusal of the whole variable (Entry -1) for the CERTEN_FINALITY_* lists.
func TestRTProviderVariablesCoverEveryListConfigFromEnvReads(t *testing.T) {
	names := map[string]string{}
	for _, v := range ProviderVariables() {
		names[v.Name] = v.Chain
	}
	for _, want := range []string{
		EnvL1RPCURLs, EnvL1ProofURLs, EnvArchiveURLs, EnvLCURLs, EnvBeaconURLs, EnvAdiriURLs,
		"ETHEREUM_SEPOLIA_RPC_URL", "ETHEREUM_URL", "ETHEREUM_SEPOLIA_URL_FALLBACKS", "ETHEREUM_URL_FALLBACKS", "INFURA_SEPOLIA_URL", "ALCHEMY_SEPOLIA_URL",
		"BASE_SEPOLIA_RPC_URL", "BASE_SEPOLIA_URL_FALLBACKS", "INFURA_BASE_SEPOLIA_URL", "ALCHEMY_BASE_SEPOLIA_URL",
		"ARBITRUM_SEPOLIA_RPC_URL", "ARBITRUM_SEPOLIA_URL_FALLBACKS", "INFURA_ARBITRUM_SEPOLIA_URL", "ALCHEMY_ARBITRUM_SEPOLIA_URL",
		"TELCOIN_ADIRI_RPC_URL", "TELCOIN_ADIRI_URL_FALLBACKS", "INFURA_TELCOIN_ADIRI_URL", "ALCHEMY_TELCOIN_ADIRI_URL",
	} {
		if _, ok := names[want]; !ok {
			t.Errorf("%s is read by ConfigFromEnv as a provider list and is not in ProviderVariables()", want)
		}
		delete(names, want)
	}
	for extra := range names {
		t.Errorf("%s is in ProviderVariables() but this test does not know it", extra)
	}

	rtClearEnv(t)
	t.Setenv(EnvLCURLs, " , ;")
	refused := CheckProviderEnvironment()
	if len(refused) != 1 || refused[0].Variable != EnvLCURLs || refused[0].Entry != -1 || refused[0].Class != ClassNoEntry {
		t.Fatalf("a list variable holding no entry: %+v", refused)
	}
}

func TestRTCheckProviderEnvironmentReportsEveryRefusedEntryInTableOrder(t *testing.T) {
	rtClearEnv(t)
	t.Setenv("ETHEREUM_SEPOLIA_URL_FALLBACKS", "https://ok.example,wss://k@h.example,ftp://x.example")
	t.Setenv("BASE_SEPOLIA_RPC_URL", "https://h:abc/")
	t.Setenv(EnvBeaconURLs, "HTTPS://fine.example/")
	got := CheckProviderEnvironment()
	type pos struct {
		v     string
		entry int
		class string
	}
	var want = []pos{{"BASE_SEPOLIA_RPC_URL", 0, ClassBadPort}}
	// table order: the CERTEN_FINALITY_* lists, then the chains (ethereum-sepolia first)
	want = append([]pos{{"ETHEREUM_SEPOLIA_URL_FALLBACKS", 1, ClassOtherScheme}, {"ETHEREUM_SEPOLIA_URL_FALLBACKS", 2, ClassOtherScheme}}, want...)
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, w := range want {
		if got[i].Variable != w.v || got[i].Entry != w.entry || got[i].Class != w.class {
			t.Fatalf("refusal %d: %+v, want %+v", i, got[i], w)
		}
	}
	rtClearEnv(t)
	if got := CheckProviderEnvironment(); len(got) != 0 {
		t.Fatalf("an empty environment is refused: %+v", got)
	}
}

func TestRTEntryClassNamesEveryKindOfDefectAndNeverTheText(t *testing.T) {
	for _, tc := range []struct{ entry, class string }{
		{"https://h.example/", ""},
		{"HTTP://h.example", ""},
		{"https://h.example/%zz", ClassBadEscape},
		{"https://h.example:80x/", ClassBadPort},
		{"https://u<@h.example/", ClassBadUserinfo},
		{"https://ex{ample.com/", ClassBadHost},
		{"https://[::1/", ClassBadHost},
		// words of the classification inside the URL text must not steer it: the class comes from the parse error alone
		{"https://ex{ample.com/invalid port", ClassBadHost},
		{"https://h.example/%zz/host", ClassBadEscape},
		{"https://h.example/\x7f", ClassControlCharacter},
		{"://h.example", ClassNoScheme},
		{"h.example/path", ClassNoScheme},
		{"1http://h.example", ClassNoScheme},
		{"ws://h.example", ClassOtherScheme},
		{"https:///path", ClassNoHost},
		{"https:opaque", ClassNoHost},
	} {
		if got := entryClass(tc.entry); got != tc.class {
			t.Errorf("entryClass(%q) = %q, want %q", tc.entry, got, tc.class)
		}
	}
	// a bracketed host that is not an address: accepted or refused as a host defect or as unparseable, whichever the Go release in use does
	if got := entryClass("https://[abc]/"); got != ClassBadHost && got != ClassUnparseable && got != "" {
		t.Errorf("entryClass of a bracketed non-address = %q", got)
	}
}

func TestRTProviderEntryCountCountsNonBlankEntriesBySeparator(t *testing.T) {
	for in, want := range map[string]int{"": 0, " , ;\n": 0, "a": 1, "a, b;c\nd\te": 5, "a\r\nb": 2} {
		if got := ProviderEntryCount(in); got != want {
			t.Errorf("ProviderEntryCount(%q) = %d, want %d", in, got, want)
		}
	}
}

// The class comes from the parse error's kind alone; an error this release does not know is still a refusal, named unparseable.
func TestRTParseErrorClassMapsEveryKnownKindAndDefaultsToUnparseable(t *testing.T) {
	for msg, want := range map[string]string{
		"net/url: invalid control character in URL":      ClassControlCharacter,
		`invalid URL escape "%zz"`:                       ClassBadEscape,
		`invalid port ":x" after host`:                   ClassBadPort,
		"net/url: invalid userinfo":                      ClassBadUserinfo,
		"missing protocol scheme":                        ClassNoScheme,
		"first path segment in URL cannot contain colon": ClassNoScheme,
		`invalid character "{" in host name`:             ClassBadHost,
		"missing ']' in host":                            ClassBadHost,
		"an error a later Go release may add":            ClassUnparseable,
		"":                                               ClassUnparseable,
	} {
		if got := parseErrorClass(msg); got != want {
			t.Errorf("parseErrorClass(%q) = %q, want %q", msg, got, want)
		}
	}
}
