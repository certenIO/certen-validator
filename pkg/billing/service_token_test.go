package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// CROSS-LANGUAGE CONTRACT TEST.
//
// The validator (Go) signs and the gateway (TypeScript) verifies. If the two
// disagree by a single byte, every cost event fails with an opaque
// "signature-mismatch" and no cost data ever reaches the gateway — which then
// silently refuses to price every chain. That failure is expensive and
// undramatic, exactly the kind that survives to production.
//
// The identical vector is asserted on the TypeScript side in
// api-gateway/test/unit/billing/service-token-vector.test.ts. Changing either
// implementation breaks one of the two tests.
const (
	vecSecret   = "certen-test-shared-secret-vector"
	vecBody     = `{"chain":"base","gas_used":"369000","leg":"anchor"}`
	vecTime     = int64(1750000000)
	vecNonce    = "11111111-2222-4333-8444-555555555555"
	vecPath     = "/internal/v1/billing/cost-events"
	vecBodyHash = "c155e4241667eb77ee6c0282ec80b50600ab9c5ba909316514a52d690e7d7477"
	vecSigned   = "1750000000.POST./internal/v1/billing/cost-events.51." +
		vecBodyHash + ".11111111-2222-4333-8444-555555555555"
	vecHMAC = "f27bc073dad7705ed9819b9a114dfa2dc45ac165454a32cadd37987a8415ad2d"
)

func TestServiceTokenVectorMatchesGateway(t *testing.T) {
	sum := sha256.Sum256([]byte(vecBody))
	if got := hex.EncodeToString(sum[:]); got != vecBodyHash {
		t.Fatalf("body hash = %s, want %s", got, vecBodyHash)
	}
	if got := len(vecBody); got != 51 {
		t.Fatalf("body length = %d, want 51 (the gateway signs byte length, not rune count)", got)
	}

	signed := fmt.Sprintf("%d.%s.%s.%d.%s.%s",
		vecTime, "POST", canonicalPath(vecPath), len(vecBody), vecBodyHash, vecNonce)
	if signed != vecSigned {
		t.Fatalf("signed string mismatch\n got: %s\nwant: %s", signed, vecSigned)
	}

	mac := hmac.New(sha256.New, []byte(vecSecret))
	mac.Write([]byte(signed))
	if got := hex.EncodeToString(mac.Sum(nil)); got != vecHMAC {
		t.Fatalf("hmac = %s, want %s", got, vecHMAC)
	}
}

func TestServiceTokenHeaderShape(t *testing.T) {
	header := ServiceToken("post", vecPath, []byte(vecBody), vecSecret, "v2")

	parts := map[string]string{}
	for _, kv := range strings.Split(header, ",") {
		i := strings.Index(kv, "=")
		if i < 0 {
			t.Fatalf("malformed header segment %q", kv)
		}
		parts[kv[:i]] = kv[i+1:]
	}

	for _, k := range []string{"t", "m", "kv", "n", "v1"} {
		if parts[k] == "" {
			t.Fatalf("header missing %q: %s", k, header)
		}
	}
	// The gateway compares the method case-sensitively against
	// request.method.toUpperCase().
	if parts["m"] != "POST" {
		t.Fatalf("method must be upper-cased, got %q", parts["m"])
	}
	if parts["kv"] != "v2" {
		t.Fatalf("key version not propagated, got %q", parts["kv"])
	}
	if len(parts["v1"]) != 64 {
		t.Fatalf("signature must be 32 hex bytes, got %d chars", len(parts["v1"]))
	}
}

func TestServiceTokenNonceIsUnique(t *testing.T) {
	// The gateway keeps an LRU of seen nonces and rejects a repeat, so a
	// constant nonce would make the second cost event of the process fail.
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		n := newNonce()
		if seen[n] {
			t.Fatalf("duplicate nonce %s after %d draws", n, i)
		}
		seen[n] = true
	}
}

func TestCanonicalPathSortsQueryKeys(t *testing.T) {
	// Mirrors api-gateway/test/unit/billing/service-token-vector.test.ts.
	// The valueless-key row is the one that actually diverged: the gateway
	// re-emits `?flag` as `flag=`, and matching that is not optional.
	cases := map[string]string{
		"/a/b":                 "/a/b",
		"/a/b?":                "/a/b",
		"/a/b?z=1&a=2":         "/a/b?a=2&z=1",
		"/a/b?b=2&a=1&c=3":     "/a/b?a=1&b=2&c=3",
		"/internal/x?flag&a=1": "/internal/x?a=1&flag=",
	}
	for in, want := range cases {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}
