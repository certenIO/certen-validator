package bls

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"testing"
)

// A validator with no key file gets a RANDOM key, never the one computable from its public validator
// ID - that derivation let anyone compute every validator's private key.
func TestInitializeValidatorBLSKeyNeverDerives(t *testing.T) {
	seed := sha256.Sum256([]byte(fmt.Sprintf("CERTEN_BLS_KEY_V1:%s:%s", "validator-1", "certen-testnet")))
	_, derived, err := GenerateKeyPairFromSeed(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	a, err := InitializeValidatorBLSKey("validator-1", "certen-testnet", filepath.Join(t.TempDir(), "k.hex"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := InitializeValidatorBLSKey("validator-1", "certen-testnet", filepath.Join(t.TempDir(), "k.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if a.GetPublicKey().Hex() == derived.Hex() || b.GetPublicKey().Hex() == derived.Hex() {
		t.Fatal("a missing key file produced the derivable key")
	}
	if a.GetPublicKey().Hex() == b.GetPublicKey().Hex() {
		t.Fatal("two fresh keys for the same validator ID are equal: not random")
	}
	if _, err := InitializeValidatorBLSKey("validator-1", "certen-testnet", ""); err == nil {
		t.Fatal("no key path must be refused, not answered with a key")
	}
}

// An existing key file is loaded as is: deploying this change alters no validator's key.
func TestInitializeValidatorBLSKeyLoadsTheExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.hex")
	first, err := InitializeValidatorBLSKey("validator-2", "certen-testnet", path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := InitializeValidatorBLSKey("validator-2", "certen-testnet", path)
	if err != nil {
		t.Fatal(err)
	}
	if first.GetPublicKey().Hex() != again.GetPublicKey().Hex() {
		t.Fatal("the saved key was not loaded back")
	}
}
