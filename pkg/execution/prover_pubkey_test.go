package execution

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// TestResolveProverPubKey locks in the #774716 fix - the ZK prover builds its witness against the BLOCK SIGNER's public
// key, not the executor's own - and RB5-F55: a missing or unusable signer key is REFUSED. It used to fall back to the
// executor's key, which can only produce a witness for a signature the executor did not make.
func TestResolveProverPubKey(t *testing.T) {
	signer := bytes.Repeat([]byte{0xab}, 96) // block signer's key (a41cd7cf... in the wild)
	signerHex := hex.EncodeToString(signer)

	for _, tc := range []struct {
		name  string
		hexIn string
	}{{"prefers block signer key", signerHex}, {"accepts 0x prefix", "0x" + signerHex}} {
		got, err := resolveProverPubKey(tc.hexIn)
		if err != nil || !bytes.Equal(got, signer) {
			t.Fatalf("%s: got %s... (%v), want the signer's key", tc.name, short(got), err)
		}
	}
	for _, tc := range []struct {
		name  string
		hexIn string
	}{
		{"empty is refused", ""},
		{"short is refused", hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 48))},
		{"non-hex is refused", "not-hex-zzzz"},
	} {
		got, err := resolveProverPubKey(tc.hexIn)
		if !errors.Is(err, ErrQuorumProof) || got != nil {
			t.Fatalf("%s: got %s... (%v); a key other than the signer's must never be used", tc.name, short(got), err)
		}
	}
}

func short(b []byte) string {
	s := hex.EncodeToString(b)
	if len(s) > 8 {
		return strings.ToLower(s[:8])
	}
	return s
}
