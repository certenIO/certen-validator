// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB10-B14a (V-R10B5 D1, D2): the inputs of the reviewer's battery that left the key in RedactEndpoints at 70bd455. V-R10B5
// recorded 105 inputs, 37 of which leaked, by class (its probe files were deleted); the inputs below are those classes written
// out, with the key SECRETKEY123abc. "pattern" says the pattern pass alone must clean it; the others are cleaned by the
// registered literal of the configured provider URL (D2), which is the claim: a key of a configured provider never reaches
// a stored world, a log or a proof file whatever text carries it.
var v10b5Leaks = []struct {
	name, in string
	pattern  bool
}{
	// D1: escaped forms of a URL
	{"json slashes", `{"msg":"Post https:~/~/eth.g.alchemy.com~/v2~/§ failed"}`, true},
	{"json slashes after the host", `{"msg":"Post https://eth.g.alchemy.com~/v2~/§ failed"}`, true},
	{"u002f lower", `Post "https://eth.g.alchemy.com~u002fv2~u002fK": EOF`, true},
	{"u002F upper", `Post "https://eth.g.alchemy.com~u002Fv2~u002FK": EOF`, true},
	{"u002f scheme too", `Post "https:~u002f~u002feth.g.alchemy.com~u002fv2~u002fK": EOF`, true},
	{"percent scheme", `redirect https%3A%2F%2Feth.g.alchemy.com%2Fv2%2FK failed`, true},
	{"percent path", `https://eth.g.alchemy.com%2Fv2%2FK`, true},
	{"double-escaped ampersand", `{"m":"https://h.example.org/rpc?a=1~~u0026apikey=§~~u0026c=2"}`, true},
	{"newline in the path", "Post \"https://eth.g.alchemy.com/v2/\nK\"", true},
	{"tab in the path", "Post \"https://eth.g.alchemy.com/v2/\tK\"", true},
	{"CRLF in the path", "Post \"https://eth.g.alchemy.com/v2/\r\nK\"", true},
	{"world Body with escaped slashes", `{"error":"not found https:~/~/eth.g.alchemy.com~/v2~/§"}`, true},
	{"world Transport with escaped slashes", `Post "https:~/~/eth.g.alchemy.com~/v2~/§": EOF`, true},
	// D2: a key echoed without its host
	{"path-only 404", `The requested URL /v2/§ was not found on this server.`, false},
	{"nginx request line", `502 Bad Gateway: upstream: "http://10.0.0.5:8545/", request: "POST /v2/§ HTTP/1.1", host: "eth.g.alchemy.com"`, false},
	{"request line", `POST /v2/§ HTTP/1.1`, false},
	{"bare userinfo", `user:§@rpc.example.org`, false},
	{"single-label host with a port", `geth:8545/§`, true},
	{"bare IPv6", `[2001:db8::1]:8545/§`, true},
	{"FQDN dot", `rpc.example.org./§`, true},
	{"apikey text", `apikey=§`, false},
	{"X-API-KEY header", `X-API-KEY: §`, false},
	{"bearer header", `Authorization: Bearer §`, false},
	{"prose", `invalid api key §`, false},
	// INFO items of the review: forms no HTTP stack of Go writes; with the literal they are all clean
	{"bare host and fragment", `eth.g.alchemy.com#§`, false},
	{"fullwidth solidus", `h.example.org／v2／§`, false},
	{"division slash", `h.example.org∕v2∕§`, false},
	{"backslash separators", `https:~~h.example.org~v2~§`, false},
	{"html entity slash", `https://h.example.org&#x2F;v2&#x2F;§`, false},
	{"angle brackets in an unquoted URL", `https://h.example.org/<§>`, false},
	{"after the marker", `https://h.example.org/<redacted>§`, false},
	{"key as a host label", `https://§.eth.rpc.rivet.cloud/`, false},
	{"key as a host label with a path", `https://§.eth.rpc.rivet.cloud/v2`, false},
	{"key after a redirect Location", `Location: https://h.example.org/v2/§`, true},
	{"key in a cookie", `Set-Cookie: session=§; Path=/`, false},
	{"key in a JSON field", `{"apiKey":"§","note":"bad"}`, false},
	{"key twice", `§ and https://h.example.org/v2/§ and §`, false},
}

func v10b5(in string) string { return strings.ReplaceAll(bsl(in), "§", b14aKey) }

func TestB14a_TheReviewersLeaksAreClean(t *testing.T) {
	if len(v10b5Leaks) < 37 {
		t.Fatalf("the battery lists %d leaking inputs, V-R10B5 recorded 37", len(v10b5Leaks))
	}
	// Without the literal: exactly the pattern-cleanable inputs are clean; the others are the documented limit.
	for _, tc := range v10b5Leaks {
		in := v10b5(tc.in)
		got := ethproof.RedactEndpoints(in)
		if tc.pattern && strings.Contains(got, b14aKey) {
			t.Errorf("%s: the pattern pass left the key:\n in: %q\nout: %q", tc.name, in, got)
		}
		if again := ethproof.RedactEndpoints(got); again != got {
			t.Errorf("%s: not idempotent: %q then %q", tc.name, got, again)
		}
	}
	// With the literal of the configured provider URL registered: every one is clean, idempotent, and keeps the rest of the text.
	undo := ethrpc.RegisterProviderURL("https://eth.g.alchemy.com/v2/" + b14aKey)
	defer undo()
	for _, tc := range v10b5Leaks {
		in := v10b5(tc.in)
		got := ethproof.RedactEndpoints(in)
		if strings.Contains(got, b14aKey) {
			t.Errorf("%s: the key is left with its literal registered:\n in: %q\nout: %q", tc.name, in, got)
		}
		if again := ethproof.RedactEndpoints(got); again != got {
			t.Errorf("%s: not idempotent with the literal: %q then %q", tc.name, got, again)
		}
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("%s: nothing was redacted: %q", tc.name, got)
		}
	}
	// and the documented limit holds again once the provider is no longer configured
	undo()
	if got := ethproof.RedactEndpoints("X-API-KEY: " + b14aKey); got != "X-API-KEY: "+b14aKey {
		t.Errorf("an unregistered bare key was changed: %q", got)
	}
}

// What held at 70bd455 still holds: realistic inputs that were clean stay clean and keep their shape.
func TestB14a_WhatWasCleanStaysClean(t *testing.T) {
	hosts := []string{"eth-sepolia.g.alchemy.com/v2/K", "sepolia.infura.io/v3/K", "name.network.quiknode.pro/K/", "rpc.ankr.com/eth_sepolia/K",
		"eth-sepolia.public.blastapi.io/K", "nd-123-456-789.p2pify.com/K", "sepolia.gateway.tenderly.co/K", "go.getblock.io/K", "lb.drpc.org/ogrpc?network=sepolia&dkey=K",
		"host.example.org/rpc?apikey=K", "host.example.org/?key=K", "host.example.org/x?a=1&token=K", "10.1.2.3:8545/K", "[::1]:8545/K", "localhost:8545/K"}
	schemes := []string{"https://", "http://", "wss://", "HTTPS://", "Https://", ""}
	wraps := [][2]string{{"Post \"", "\": EOF"}, {"Get ", ": 429 Too Many Requests"}, {"(", ")"}, {"[", "]"}, {"'", "'"}, {"`", "`"}, {"a ", ", b"}, {"", "."}, {"", ""}}
	for _, h := range hosts {
		for _, sc := range schemes {
			for _, w := range wraps {
				in := w[0] + sc + strings.ReplaceAll(h, "K", b14aKey) + w[1]
				got := ethproof.RedactEndpoints(in)
				if strings.Contains(got, b14aKey) {
					t.Errorf("the key is left:\n in: %q\nout: %q", in, got)
				}
				if again := ethproof.RedactEndpoints(got); again != got {
					t.Errorf("not idempotent: %q then %q", got, again)
				}
				if !strings.HasPrefix(got, w[0]) || (w[1] != "" && w[1] != "." && !strings.HasSuffix(got, w[1])) {
					t.Errorf("the surrounding text changed:\n in: %q\nout: %q", in, got)
				}
			}
		}
	}
}
