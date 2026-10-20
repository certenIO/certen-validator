// Copyright 2026 Certen Protocol

package finality_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/build"
	"os"
	"path/filepath"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
)

// The KZG setup the Go verifier loads is go-ethereum's embedded trusted_setup.json. Its raw bytes hash to the pin
// shared.kzg_setup_sha256 and to arbposted.UsedKZGSetupSHA256, and that is the hash of the Ethereum ceremony output at
// consensus-specs v1.7.0-beta.4 (presets/mainnet/trusted_setups/trusted_setup_4096.json, raw sha256 compared 2026-10-20 by
// downloading the file at that tag: f8e44a31...5616f, V2_SPEC_S7 section 11 item 9).
func TestKZGSetupIsTheCeremonyOutputAndThePinsNameIt(t *testing.T) {
	pkg, err := build.Import("github.com/ethereum/go-ethereum/crypto/kzg4844", "", build.FindOnly)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(pkg.Dir, "trusted_setup.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != arbposted.UsedKZGSetupSHA256 {
		t.Fatalf("go-ethereum's embedded setup hashes to %s, the verifier says it uses %s", got, arbposted.UsedKZGSetupSHA256)
	}
	p, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	e, err := p.Sepolia()
	if err != nil {
		t.Fatal(err)
	}
	if v, key, err := p.KZGSetupPin("eth_sepolia.kzg_setup_sha256", e.KZGSetupSHA256); err != nil || v != arbposted.UsedKZGSetupSHA256 || key != finality.KZGSetupSharedKey {
		t.Fatalf("the embedded pins name %q under %q: %v", v, key, err)
	}
}

// The embedded pins file carries the arb_sepolia section of V2_SPEC_S7 4.2 and it is the section the verifier loads.
func TestEmbeddedPinsCarryTheArbSepoliaSection(t *testing.T) {
	p, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Sections["arb_sepolia"]; !ok {
		t.Fatal("the embedded pins have no arb_sepolia section")
	}
	var sec struct {
		ChainID   uint64            `json:"chain_id"`
		Rollup    string            `json:"rollup"`
		Bridge    string            `json:"bridge"`
		LogicPins map[string]string `json:"logic_pins"`
		MaxBlobs  int               `json:"max_blobs"`
	}
	if err := json.Unmarshal(p.Sections["arb_sepolia"], &sec); err != nil {
		t.Fatal(err)
	}
	if sec.ChainID != 421614 || sec.Rollup != "0x042B2E6C5E99d4c521bd49beeD5E99651D9B0Cf4" || sec.Bridge != "0x38f918D0E9F1b721EDaA41302E399fa1B79333a9" || sec.MaxBlobs != 16 {
		t.Fatalf("section %+v", sec)
	}
	if sec.LogicPins["0x3bd9637547d75e5b4539449e14c759b86b9d37a7c1f2b47a1524f857e4ff1a0c"] != "bridge_impl" ||
		sec.LogicPins["0xdd93a7606e6067aaae8ad5afa28b943a8272809eb72face4e2bb3bf4d0609445"] != "rollup_admin_logic" ||
		sec.LogicPins["0xeadf786edd4819d0262d9679d43b878d7005408a822aa0c43cf79bd0043c09a3"] != "rollup_user_logic" || len(sec.LogicPins) != 3 {
		t.Fatalf("logic pins %v", sec.LogicPins)
	}
}
