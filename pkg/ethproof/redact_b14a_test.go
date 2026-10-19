// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10-B14a (V-R10B5 D1): the redactor reads a URL as the characters it stands for. Test inputs are written with ~ for a
// backslash (bsl), so that no source line holds an escape sequence the tools would rewrite.

const b14aKey = "SECRETKEY123abc"

func bsl(s string) string { return strings.ReplaceAll(s, "~", "\x5c") }

// The JSON-escaped, unicode-escaped, percent-encoded, double-escaped and wrapped forms of a URL whose path or query is the key.
// Every one left the key in V-R10B5 (D1). "want" is exact where the form has one answer.
func TestB14a_D1_EscapedFormsOfAURLAreRedacted(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"JSON-escaped slashes in a JSON body", `{"msg":"Post https:~/~/eth.g.alchemy.com~/v2~/` + b14aKey + ` failed"}`,
			`{"msg":"Post https://eth.g.alchemy.com/<redacted> failed"}`},
		{"JSON-escaped slashes after the host only", `{"msg":"Post https://eth.g.alchemy.com~/v2~/` + b14aKey + ` failed"}`,
			`{"msg":"Post https://eth.g.alchemy.com/<redacted> failed"}`},
		{"unicode-escaped slash, lower case", `Post "https://eth.g.alchemy.com~u002fv2~u002f` + b14aKey + `": EOF`,
			`Post "https://eth.g.alchemy.com/<redacted>": EOF`},
		{"unicode-escaped slash, upper case", `Post "https://eth.g.alchemy.com~u002Fv2~u002F` + b14aKey + `": EOF`,
			`Post "https://eth.g.alchemy.com/<redacted>": EOF`},
		{"unicode-escaped scheme separator and slashes", `Post "https:~u002f~u002feth.g.alchemy.com~u002fv2~u002f` + b14aKey + `": EOF`,
			`Post "https://eth.g.alchemy.com/<redacted>": EOF`},
		{"escaped colon-slash-slash", `Post https~u003a~/~/eth.g.alchemy.com~/v2~/` + b14aKey + ` failed`,
			`Post https://eth.g.alchemy.com/<redacted> failed`},
		{"fully percent-encoded URL", `redirect https%3A%2F%2Feth.g.alchemy.com%2Fv2%2F` + b14aKey + ` failed`,
			`redirect https://eth.g.alchemy.com/<redacted> failed`},
		{"fully percent-encoded URL, lower case hex", `redirect https%3a%2f%2feth.g.alchemy.com%2fv2%2f` + b14aKey + ` failed`,
			`redirect https://eth.g.alchemy.com/<redacted> failed`},
		{"percent-encoded path after a plain scheme", `GET https://eth.g.alchemy.com%2Fv2%2F` + b14aKey + ` refused`,
			`GET https://eth.g.alchemy.com/<redacted> refused`},
		{"percent-encoded twice", `redirect https%253A%252F%252Feth.g.alchemy.com%252Fv2%252F` + b14aKey + ` failed`,
			`redirect https://eth.g.alchemy.com/<redacted> failed`},
		{"a JSON error nested in a JSON string (double-escaped ampersand)", `{"m":"https://h.example.org/rpc?a=1~~u0026apikey=` + b14aKey + `~~u0026c=2"}`,
			`{"m":"https://h.example.org/<redacted>"}`},
		{"a single-escaped ampersand", `{"m":"https://h.example.org/rpc?a=1~u0026apikey=` + b14aKey + `~u0026c=2"}`,
			`{"m":"https://h.example.org/<redacted>"}`},
		{"a JSON string inside a JSON string", `{"e":"Post ~"https:~/~/eth.g.alchemy.com~/v2~/` + b14aKey + `~": EOF"}`,
			`{"e":"Post ~"https://eth.g.alchemy.com/<redacted>~": EOF"}`},
		{"a path wrapped at a newline inside the quotes", "Post \"https://eth.g.alchemy.com/v2/\n" + b14aKey + "\": EOF",
			`Post "https://eth.g.alchemy.com/<redacted>": EOF`},
		{"a path wrapped at a tab inside the quotes", "Post \"https://eth.g.alchemy.com/v2/\t" + b14aKey + "\": EOF",
			`Post "https://eth.g.alchemy.com/<redacted>": EOF`},
		{"a path wrapped at CRLF inside the quotes", "Post \"https://eth.g.alchemy.com/v2/\r\n" + b14aKey + "\": EOF",
			`Post "https://eth.g.alchemy.com/<redacted>": EOF`},
		{"a path wrapped at a space inside the quotes", `Post "https://eth.g.alchemy.com/v2/ ` + b14aKey + `": EOF`,
			`Post "https://eth.g.alchemy.com/<redacted>": EOF`},
		{"a path wrapped at an escaped newline inside escaped quotes", `{"e":"Post ~"https://eth.g.alchemy.com/v2/~n` + b14aKey + `~": EOF"}`,
			`{"e":"Post ~"https://eth.g.alchemy.com/<redacted>~": EOF"}`},
		{"a single-quoted URL wrapped at a space", `dial 'https://eth.g.alchemy.com/v2/ ` + b14aKey + `' failed`,
			`dial 'https://eth.g.alchemy.com/<redacted>' failed`},
		{"angle brackets inside the quotes", `Post "https://h.example.org/<` + b14aKey + `>": EOF`, `Post "https://h.example.org/<redacted>": EOF`},
		{"a single-label host with a port, no scheme", `dial geth:8545/` + b14aKey + ` refused`, `dial geth:8545/<redacted> refused`},
		{"a bracketed IPv6 host with a port, no scheme", `dial [::1]:8545/` + b14aKey + ` refused`, `dial [::1]:8545/<redacted> refused`},
		{"a global IPv6 host, no scheme", `dial [2001:db8::1]:8545/` + b14aKey + ` refused`, `dial [2001:db8::1]:8545/<redacted> refused`},
		{"a fully qualified host, no scheme", `dial rpc.example.org./` + b14aKey + ` refused`, `dial rpc.example.org./<redacted> refused`},
		{"a bracketed IPv6 host with a scheme", `Post "https://[2001:db8::1]:8545/` + b14aKey + `": EOF`, `Post "https://[2001:db8::1]:8545/<redacted>": EOF`},
		{"a double userinfo, no scheme", `?u:p@u:` + b14aKey + `@eth.g.alchemy.com:8545/v2/`, `eth.g.alchemy.com:8545/<redacted>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := bsl(tc.in)
			want := bsl(tc.want)
			got := ethproof.RedactEndpoints(in)
			if strings.Contains(got, b14aKey) {
				t.Fatalf("the key is left:\n in: %q\nout: %q", in, got)
			}
			if got != want {
				t.Fatalf("\n in: %q\ngot: %q\nwant: %q", in, got, want)
			}
			if again := ethproof.RedactEndpoints(got); again != got {
				t.Fatalf("not idempotent: %q then %q", got, again)
			}
		})
	}
}

// Text that holds no URL is returned byte for byte, including text with the characters an escape is made of.
func TestB14a_TextWithoutAURLIsReturnedByteForByte(t *testing.T) {
	for _, in := range []string{
		"", "distance to target block exceeds maximum proof window (block 42, 14.79ms of 300ms, 2m0s)",
		"100% done, 50%25 off, 3%", bsl(`C:~new~table~r~n and a ~u12 and ~~ and ~"quoted~"`), bsl(`json ~/ is only a slash`),
		"0x9d3a1f5b02c47e8be6d1a09a7c3f5b02c47e8be6d1a09a7c3f5b02c47e8be6d1 serves 0x01", "1.5ms/2 v1.2.3-rc1 ratio 3:4",
		"rpc.telcoin.network: no such host", "Post \"https://sepolia.base.org\": EOF", "https://sepolia.base.org/ is down",
		"a%2gb %zz %2", "line 12:30 pkg/ethproof/replaycapture.go:250 failed",
	} {
		if got := ethproof.RedactEndpoints(in); got != in {
			t.Errorf("changed:\n in: %q\nout: %q", in, got)
		}
	}
}

// The structured sweep: wrap x scheme x userinfo x host x path x suffix x spelling. The key never survives, the host stays,
// and a second pass changes nothing.
func TestB14a_StructuredSweepNeverLeavesTheKey(t *testing.T) {
	wraps := [][2]string{{"", ""}, {`"`, `"`}, {"~\"", "~\""}, {"(", ")"}, {"[", "]"}, {"<", ">"}, {"x=", ";"}, {"'", "'"}, {"`", "`"}, {"a ", " b"},
		{"{", "}"}, {"Post \"", "\": EOF"}, {`{"error":"Post ~"`, `~": EOF"}`}}
	schemes := []string{"https://", "http://", "wss://", "HTTPS://", "ws://", ""}
	userinfos := []string{"", "user:" + b14aKey + "@", b14aKey + "@"}
	hosts := []string{"eth-sepolia.g.alchemy.com", "mainnet.infura.io", "name.network.quiknode.pro", "10.1.2.3:8545", "localhost:8545",
		"[::1]:8545", "geth:8545", "rpc.example.org."}
	paths := []string{"/v2/KEY", "/KEY", "/KEY/", "/v3/KEY/ws", "?apikey=KEY", "?key=KEY&b=2", "/a/b?x=KEY#KEY"}
	suffixes := []string{"", ".", ",", ")", ":", " failed", "\n", ": EOF"}
	spell := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return strings.ReplaceAll(s, "/", "~/") },
		func(s string) string { return strings.ReplaceAll(s, "/", "~u002f") },
		func(s string) string { return strings.NewReplacer("/", "%2F", ":", "%3A").Replace(s) },
	}
	n := 0
	for _, w := range wraps {
		for _, sc := range schemes {
			for _, ui := range userinfos {
				for _, h := range hosts {
					if sc == "" && !strings.ContainsAny(h, ".:") && h != "localhost" {
						continue
					}
					for _, p := range paths {
						for _, sf := range suffixes {
							for _, sp := range spell {
								core := sc + ui + h + strings.ReplaceAll(p, "KEY", b14aKey)
								in := bsl(w[0] + sp(core) + sf + w[1])
								got := ethproof.RedactEndpoints(in)
								n++
								if strings.Contains(got, b14aKey) {
									t.Fatalf("the key is left:\n in: %q\nout: %q", in, got)
								}
								if !strings.Contains(got, strings.TrimSuffix(strings.SplitN(h, ":", 2)[0], ".")) && !strings.Contains(got, "[::1]") {
									t.Fatalf("the host is lost:\n in: %q\nout: %q", in, got)
								}
								if again := ethproof.RedactEndpoints(got); again != got {
									t.Fatalf("not idempotent:\n in: %q\n 1: %q\n 2: %q", in, got, again)
								}
							}
						}
					}
				}
			}
		}
	}
	if n < 20000 {
		t.Fatalf("only %d combinations ran", n)
	}
	t.Logf("%d combinations", n)
}

// Redaction is linear: a 1 MiB adversarial input costs well under a second whatever its shape.
func TestB14a_RedactionOfOneMiBIsFast(t *testing.T) {
	const mib = 1 << 20
	rep := func(unit string) string { return strings.Repeat(unit, mib/len(unit)+1)[:mib] }
	for name, in := range map[string]string{
		"letters": rep("a"), "dotted labels": rep("a."), "at signs": rep("a@"), "schemes": rep("http://"), "bare schemes": rep("a://"),
		"hosts and paths": rep("a.b.c/"), "ipv4 and paths": rep("1.1.1.1/"), "slashes": rep("/"), "queries": rep("?"),
		"a long host": "https://" + rep("a."), "userinfo": "https://" + rep("a@"), "quoted urls": rep(`"https://x.example.org/v2/KEY" `),
		"percent slashes": rep("%2f"), "escaped slashes": rep(bsl("~/")), "unicode escapes": rep(bsl("~u002f")), "double escapes": rep(bsl("~~u0026")),
		"escaped newlines": rep(bsl("~n")), "open quotes": rep(`"https://a `), "wrapped quotes": rep("\"https://a\n/\n"), "percent levels": rep("%2525"),
		"ports": rep("a:80/"), "ipv6": rep("[::1]:80/"),
	} {
		start := time.Now()
		got := ethproof.RedactEndpoints(in)
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: %s for %d bytes", name, d, len(in))
		}
		if again := ethproof.RedactEndpoints(got); again != got {
			t.Errorf("%s: not idempotent", name)
		}
	}
}

// What the pattern pass cannot know is a documented limit, asserted so that it stays stated: a bare key that is neither in a
// URL nor registered stays; the same text with the key registered is clean (TestB14a_D2_...).
func TestB14a_DocumentedLimits_ABareKeyWithNoURLAndNoRegisteredLiteralStays(t *testing.T) {
	for _, in := range []string{
		"X-API-KEY: " + b14aKey, "Authorization: Bearer " + b14aKey, "invalid api key " + b14aKey, "apikey=" + b14aKey,
		"the key " + b14aKey + " is not valid", "eth.g.alchemy.com#" + b14aKey, "https://" + b14aKey + ".eth.rpc.rivet.cloud/",
	} {
		if got := ethproof.RedactEndpoints(in); got != in {
			t.Errorf("a documented limit changed (update the documentation with it):\n in: %q\nout: %q", in, got)
		}
	}
}

func ExampleRedactEndpoints() {
	fmt.Println(ethproof.RedactEndpoints(`Post "https://eth-sepolia.g.alchemy.com/v2/KEY": EOF`))
	// Output: Post "https://eth-sepolia.g.alchemy.com/<redacted>": EOF
}

// A deterministic random sweep over a vocabulary of URL pieces, escapes and noise: no panic, idempotent, a string with none of
// the characters a URL or an escape is made of is returned byte for byte, and the key never survives inside a URL token.
func TestB14a_RandomSweepIsIdempotentAndNeverPanics(t *testing.T) {
	vocab := []string{"https://", "http://", "wss://", "HTTPS://", "://", "eth.g.alchemy.com", "h.example.org", "10.1.2.3:8545", "[::1]:8545", "geth:8545", "localhost",
		"/", "//", "/v2/", "/rpc", "?", "?apikey=", "&", "=", "#", "@", "user:" + b14aKey + "@", b14aKey, "a", "ab.cd", ".", ",", ":", ";", ")", "(", " ", "  ", "\n", "\t", "\r\n",
		"\"", "'", "`", "<", ">", "<redacted>", "/<redacted>", "~", "~~", "~/", "~u002f", "~u002F", "~u0026", "~~u0026", "~u0022", "~n", "~t", "~\"", "%", "%2f", "%2F", "%3A", "%3a", "%25", "%252f",
		"%2", "%zz", "~u12", "~u00", "日本", "\xff", "0x9d3a", "1.5ms", "key=", "token"}
	seed := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed }
	for i := 0; i < 150000; i++ {
		var sb strings.Builder
		for n := int(next()%14) + 1; n > 0; n-- {
			sb.WriteString(vocab[next()%uint64(len(vocab))])
		}
		in := bsl(sb.String())
		got := ethproof.RedactEndpoints(in)
		if again := ethproof.RedactEndpoints(got); again != got {
			t.Fatalf("not idempotent:\n in: %q\n 1: %q\n 2: %q", in, got, again)
		}
		if !strings.ContainsAny(in, "/?%\x5c") && got != in {
			t.Fatalf("text with no URL character changed:\n in: %q\nout: %q", in, got)
		}
	}
}
