package execution

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestResolveProverPubKey locks in the #774716 fix: the ZK prover must build its
// witness against the BLOCK SIGNER's public key (carried in the ValidatorBlock),
// not the executor's own key, whenever the block supplies one. It falls back to
// the executor's key only when the block omits/garbles the pubkey.
func TestResolveProverPubKey(t *testing.T) {
	fallback := bytes.Repeat([]byte{0x11}, 96) // executor's own key
	signer := bytes.Repeat([]byte{0xab}, 96)   // block signer's key (a41cd7cf... in the wild)
	signerHex := hex.EncodeToString(signer)

	cases := []struct {
		name   string
		hexIn  string
		want   []byte
		reason string
	}{
		{"prefers block signer key", signerHex, signer, "signer differs from executor → must use signer's key"},
		{"accepts 0x prefix", "0x" + signerHex, signer, "hex may arrive with 0x prefix"},
		{"empty falls back", "", fallback, "legacy self-signed path carries no block pubkey"},
		{"short falls back", hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48)), fallback, "sub-96-byte key is unusable → fall back rather than emit a bad witness"},
		{"non-hex falls back", "not-hex-zzzz", fallback, "undecodable key must not crash the prover"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveProverPubKey(tc.hexIn, fallback)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("%s: got %s..., want %s... (%s)",
					tc.name, short(got), short(tc.want), tc.reason)
			}
		})
	}
}

func short(b []byte) string {
	s := hex.EncodeToString(b)
	if len(s) > 8 {
		return strings.ToLower(s[:8])
	}
	return s
}
