// Copyright 2026 Certen Protocol

package bls_zkp

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The embedded key must be the key the fleet proves with: the verification_key.bin line of the SHA256SUMS that
// deploy-validators.sh enforces on the production keys.
func TestTheEmbeddedVerificationKeyIsTheDeployedOne(t *testing.T) {
	sums, err := os.ReadFile("../../../deploy/bls_zk_keys.SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	var pinned string
	for _, line := range strings.Split(strings.ReplaceAll(string(sums), "\r\n", "\n"), "\n") {
		if f := strings.Fields(line); len(f) == 2 && strings.TrimPrefix(f[1], "*") == "verification_key.bin" {
			pinned = f[0]
		}
	}
	if pinned == "" || pinned != DeployedV2VerificationKeySHA256 {
		t.Fatalf("deploy pins %q, the package %q", pinned, DeployedV2VerificationKeySHA256)
	}
	sum := sha256.Sum256(deployedV2VerificationKey)
	if hex.EncodeToString(sum[:]) != pinned {
		t.Fatalf("the embedded key hashes to %x", sum)
	}
	if _, err := DeployedV2Verifier(); err != nil {
		t.Fatal(err)
	}
}

func TestAShortBlobIsRefusedNotVerified(t *testing.T) {
	v, err := DeployedV2Verifier()
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := v.Verify(make([]byte, 100)); ok || err == nil {
		t.Fatalf("a 100-byte blob: ok=%v err=%v", ok, err)
	}
	if _, err := DecodeV2PublicInputs(make([]byte, 575)); err == nil {
		t.Fatal("a short blob decoded")
	}
}
