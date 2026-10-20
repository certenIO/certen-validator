// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10-B11: the sanitiser rewrites every URL-looking token to scheme://host/<redacted> and touches nothing else.
func TestRedactEndpoints(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"a quoted url.Error URL", `Post "https://eth-sepolia.g.alchemy.com/v2/SECRETKEY123": dial tcp 10.0.0.1:443: i/o timeout`,
			`Post "https://eth-sepolia.g.alchemy.com/<redacted>": dial tcp 10.0.0.1:443: i/o timeout`},
		{"an escaped quoted URL", `{"err":"Post \"https://mainnet.infura.io/v3/SECRETKEY123\": EOF"}`,
			`{"err":"Post \"https://mainnet.infura.io/<redacted>\": EOF"}`},
		{"userinfo and query and fragment", `Get https://user:SECRETKEY123@rpc.example.org:8545/a/b?apikey=SECRETKEY123#SECRETKEY123: EOF`,
			`Get https://rpc.example.org:8545/<redacted>: EOF`},
		{"userinfo only", `https://user:SECRETKEY123@rpc.example.org`, `https://rpc.example.org/<redacted>`},
		{"a query on the host", `https://rpc.example.org?key=SECRETKEY123`, `https://rpc.example.org/<redacted>`},
		{"a ws URL ending a sentence", `bad handshake wss://x.example.org/v2/SECRETKEY123.`, `bad handshake wss://x.example.org/<redacted>.`},
		{"a URL in parentheses", `(see https://x.example.org/v2/SECRETKEY123)`, `(see https://x.example.org/<redacted>)`},
		{"two URLs", `a https://a.example.org/k1 b https://b.example.org/k2`, `a https://a.example.org/<redacted> b https://b.example.org/<redacted>`},
		{"a bare host and path", `dial eth-sepolia.g.alchemy.com/v2/SECRETKEY123: connection refused`, `dial eth-sepolia.g.alchemy.com/<redacted>: connection refused`},
		{"a bare host:port and path", `proxyconnect x.example.org:443/v2/SECRETKEY123 refused`, `proxyconnect x.example.org:443/<redacted> refused`},
		{"a bare host and a key query", `GET x.example.org?apikey=SECRETKEY123 failed`, `GET x.example.org/<redacted> failed`},
		{"a bare IP and path", `10.1.2.3:8545/SECRETKEY123 refused`, `10.1.2.3:8545/<redacted> refused`},
		{"a public URL with nothing after its host is kept", `Post "https://sepolia.base.org": EOF`, `Post "https://sepolia.base.org": EOF`},
		{"a public URL with a bare slash is kept", `https://sepolia.base.org/ is down`, `https://sepolia.base.org/ is down`},
		{"a bare host is kept", `rpc.telcoin.network: no such host`, `rpc.telcoin.network: no such host`},
		{"text with no URL", `distance to target block exceeds maximum proof window (block 42, 14.79ms of 300ms, 2m0s)`,
			`distance to target block exceeds maximum proof window (block 42, 14.79ms of 300ms, 2m0s)`},
		{"hashes and hex", `0x9d3a1f5b02c47e8be6d1a09a7c3f5b02c47e8be6d1a09a7c3f5b02c47e8be6d1 serves 0x01`, `0x9d3a1f5b02c47e8be6d1a09a7c3f5b02c47e8be6d1a09a7c3f5b02c47e8be6d1 serves 0x01`},
		{"already redacted", `Post "https://x.example.org/<redacted>": EOF`, `Post "https://x.example.org/<redacted>": EOF`},
		{"empty", ``, ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ethproof.RedactEndpoints(tc.in)
			if got != tc.want {
				t.Fatalf("\n in: %s\ngot: %s\nwant: %s", tc.in, got, tc.want)
			}
			if again := ethproof.RedactEndpoints(got); again != got {
				t.Fatalf("not idempotent: %q then %q", got, again)
			}
			if strings.Contains(got, "SECRET") {
				t.Fatalf("a secret is left: %s", got)
			}
		})
	}
}

// A secret is never left whatever surrounds the URL.
func TestRedactEndpointsNeverLeavesTheSecret(t *testing.T) {
	urls := []string{
		"https://h.example.org/v2/SECRET", "http://h.example.org:80/SECRET", "wss://h.example.org/SECRET/x?y=SECRET",
		"https://u:SECRET@h.example.org/", "https://h.example.org/p?apikey=SECRET&b=SECRET", "https://[::1]:8545/SECRET",
	}
	wraps := []string{"%s", `"%s"`, `\"%s\"`, "(%s)", "[%s]", "<%s>", "%s.", "%s,", "%s:", "x=%s;", "'%s'", "`%s`", "a %s b", "{%s}"}
	for _, u := range urls {
		for _, w := range wraps {
			in := strings.Replace(w, "%s", u, 1)
			got := ethproof.RedactEndpoints(in)
			if strings.Contains(got, "SECRET") {
				t.Errorf("secret left:\n in: %s\nout: %s", in, got)
			}
			if !strings.Contains(got, "h.example.org") && !strings.Contains(got, "[::1]") {
				t.Errorf("host lost:\n in: %s\nout: %s", in, got)
			}
			if again := ethproof.RedactEndpoints(got); again != got {
				t.Errorf("not idempotent: %q then %q", got, again)
			}
		}
	}
}

// A URL echoed inside a JSON body writes its ampersand as a unicode escape: the query behind it is still the URL's.
func TestRedactEndpointsKeepsAJSONEscapedAmpersandInsideTheURL(t *testing.T) {
	esc := "\\" + "u0026"
	in := `{"message":"bad request https://x.example.org/v2/a?b=1` + esc + `apikey=SECRETKEY123` + esc + `c=2 refused"}`
	want := `{"message":"bad request https://x.example.org/<redacted> refused"}`
	if got := ethproof.RedactEndpoints(in); got != want {
		t.Fatalf("\n in: %s\ngot: %s\nwant: %s", in, got, want)
	}
}
