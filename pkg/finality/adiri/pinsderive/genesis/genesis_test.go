// Copyright 2026 Certen Protocol

package genesis

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// tn_genesis (served by every public endpoint) recomputed under go-ethereum equals the pinned genesis_hash and the state root
// the annex measured (R11-adiri M1). The pins file is read here directly: this module is separate from the validator module so
// that go-ethereum core stays out of its go.mod (activation freeze).
func TestTNGenesisRecomputesToThePinnedHash(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pins", "tn_genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	h, root, err := GenesisHashFromTN(raw)
	if err != nil {
		t.Fatal(err)
	}
	pinsRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "pins", "finality-pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins struct {
		Adiri struct {
			GenesisHash string `json:"genesis_hash"`
		} `json:"adiri"`
	}
	if err := json.Unmarshal(pinsRaw, &pins); err != nil {
		t.Fatal(err)
	}
	if "0x"+hex.EncodeToString(h[:]) != pins.Adiri.GenesisHash {
		t.Fatalf("tn_genesis recomputes to %x, pinned %s", h, pins.Adiri.GenesisHash)
	}
	if hex.EncodeToString(root[:]) != "0eecd2892fe819ad315aa6adbfe965378cbc63659b091539a7e7ea9362aea224" {
		t.Fatalf("state root %x", root)
	}
}
