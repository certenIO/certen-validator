package bls

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var secretA = bytes.Repeat([]byte{0xa1}, 32)
var secretB = bytes.Repeat([]byte{0xb2}, 32)

// THE property the design depends on: a validator whose data volume is wiped comes back with the SAME
// key, so the key registered on the anchors stays valid and nothing needs re-registering.
func TestWipedValidatorRederivesTheSameKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.hex")
	first, err := InitializeValidatorBLSKey("validator-1", path, secretA)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil { // the wipe
		t.Fatal(err)
	}
	again, err := InitializeValidatorBLSKey("validator-1", path, secretA)
	if err != nil {
		t.Fatal(err)
	}
	if first.GetPublicKey().Hex() != again.GetPublicKey().Hex() {
		t.Fatal("a wiped validator came back with a different key")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the derived key was not saved: %v", err)
	}
}

// Nobody without the secret can compute the key: not from the validator ID and chain ID (the old,
// public derivation), not from another validator's secret, not for another validator's ID.
func TestDerivedKeyNeedsTheSecret(t *testing.T) {
	_, a, err := DeriveValidatorBLSKey("validator-1", secretA)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte(fmt.Sprintf("CERTEN_BLS_KEY_V1:%s:%s", "validator-1", "certen-testnet")))
	_, public, err := GenerateKeyPairFromSeed(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	_, otherSecret, _ := DeriveValidatorBLSKey("validator-1", secretB)
	_, otherID, _ := DeriveValidatorBLSKey("validator-2", secretA)
	for name, pk := range map[string]*PublicKey{"public derivation": public, "other secret": otherSecret, "other validator": otherID} {
		if pk.Hex() == a.Hex() {
			t.Fatalf("the key equals the %s", name)
		}
	}
}

// No secret, or one too short to be a secret, is refused rather than answered with a computable key.
func TestNoSecretIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, s := range [][]byte{nil, []byte("short")} {
		if _, err := InitializeValidatorBLSKey("validator-1", filepath.Join(dir, "k.hex"), s); err == nil {
			t.Fatalf("secret %q accepted", s)
		}
	}
	if _, err := InitializeValidatorBLSKey("validator-1", "", secretA); err == nil {
		t.Fatal("no key path must be refused")
	}
}

// An existing key file is loaded as is, whatever the secret: deploying this change alters no
// validator's key, and a rotation happens only when an operator does it.
func TestExistingKeyFileIsLoadedUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.hex")
	km := NewKeyManager(path)
	if err := km.GenerateNewKey(); err != nil {
		t.Fatal(err)
	}
	loaded, err := InitializeValidatorBLSKey("validator-1", path, secretA)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GetPublicKey().Hex() != km.GetPublicKey().Hex() {
		t.Fatal("the existing key file was not loaded as is")
	}
}
