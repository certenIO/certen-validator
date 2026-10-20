// Copyright 2026 Certen Protocol

package baseposted

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func testEthl1Pins() ethl1.Pins { return ethl1.Pins{MaxLinks: 64, MaxSpineHeaders: 16384} }

// tinyLC is a structurally valid LC part (the real captured one of the ethl1 set); its signatures are not judged here.
func tinyLC(t *testing.T) ethl1.LC {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "ethl1", "testdata", "finality_ethl1_v1", "lc", "valid_k1_short.bin"))
	if err != nil {
		t.Fatal(err)
	}
	lc, err := testEthl1Pins().DecodeLC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return lc
}

// readPublishedPins reads a pins file of a published set (1 or 2) and supplies the base_sepolia pins those sets predate
// (PublishedSetPinSupply): the verifier has no defaults, the harness is explicit.
func readPublishedPins(dir, name string) ([]byte, error) {
	raw, err := ReadFile(dir, name)
	if err != nil {
		return nil, err
	}
	return SupplyBaseSepoliaPins(raw, PublishedSetPinSupply)
}
