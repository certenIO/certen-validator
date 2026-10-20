// Copyright 2026 Certen Protocol

package arbposted

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// pinsWith returns the embedded pins with mut applied to the decoded top-level object, parsed as an override file.
func pinsWith(t *testing.T, mut func(top map[string]any)) *finality.Pins {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(finality.EmbeddedPinsBytes(), &top); err != nil {
		t.Fatal(err)
	}
	mut(top)
	raw, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	p, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatalf("pins variant does not parse: %v", err)
	}
	return p
}

func arbOf(top map[string]any) map[string]any { return top["arb_sepolia"].(map[string]any) }

// Every value of the arb_sepolia section is judged by name; the boundaries of the three bounds are exact (1 is a bound, 0 is not).
func TestEveryArbPinIsJudgedByName(t *testing.T) {
	if _, err := loadArbPins(pinsWith(t, func(map[string]any) {})); err != nil {
		t.Fatalf("the embedded section: %v", err)
	}
	for name, c := range map[string]struct {
		mut  func(map[string]any)
		want string
	}{
		"chain id":                        {func(a map[string]any) { a["chain_id"] = 1 }, "chain_id"},
		"parent chain id":                 {func(a map[string]any) { a["parent_chain_id"] = 1 }, "parent_chain_id"},
		"bridge without 0x":               {func(a map[string]any) { a["bridge"] = strings.TrimPrefix(a["bridge"].(string), "0x") + "00" }, "bridge"},
		"bridge too short":                {func(a map[string]any) { a["bridge"] = "0x1234" }, "bridge"},
		"bridge not hex":                  {func(a map[string]any) { a["bridge"] = "0x" + strings.Repeat("zz", 20) }, "bridge"},
		"bridge too long":                 {func(a map[string]any) { a["bridge"] = a["bridge"].(string) + "00" }, "bridge"},
		"layout name":                     {func(a map[string]any) { a["layout"].(map[string]any)["name"] = "nitro-contracts-v9" }, "layout"},
		"max blobs zero":                  {func(a map[string]any) { a["max_blobs"] = 0 }, "max_blobs"},
		"max blobs negative":              {func(a map[string]any) { a["max_blobs"] = -1 }, "max_blobs"},
		"max segments zero":               {func(a map[string]any) { a["max_segments"] = 0 }, "max_segments"},
		"max segments negative":           {func(a map[string]any) { a["max_segments"] = -1 }, "max_segments"},
		"max uncompressed zero":           {func(a map[string]any) { a["max_uncompressed_batch"] = 0 }, "max_uncompressed_batch"},
		"max uncompressed negative":       {func(a map[string]any) { a["max_uncompressed_batch"] = -1 }, "max_uncompressed_batch"},
		"a key the section does not know": {func(a map[string]any) { a["surprise"] = 1 }, "section"},
		"a value of the wrong type":       {func(a map[string]any) { a["rollup"] = 5 }, "section"},
	} {
		_, err := loadArbPins(pinsWith(t, func(top map[string]any) { c.mut(arbOf(top)) }))
		if canon(err) != string(PinMismatch(c.want).Canonical()) {
			t.Errorf("%s: %s", name, canon(err))
		}
	}
	for name, mut := range map[string]func(map[string]any){
		"max blobs 1":           func(a map[string]any) { a["max_blobs"] = 1 },
		"max segments 1":        func(a map[string]any) { a["max_segments"] = 1 },
		"max uncompressed 1":    func(a map[string]any) { a["max_uncompressed_batch"] = 1 },
		"bridge in lower case":  func(a map[string]any) { a["bridge"] = strings.ToLower(a["bridge"].(string)) },
		"bridge in upper hex":   func(a map[string]any) { a["bridge"] = "0x" + strings.ToUpper(a["bridge"].(string)[2:]) },
		"a bridge of all zeros": func(a map[string]any) { a["bridge"] = "0x" + strings.Repeat("0", 40) },
	} {
		if _, err := loadArbPins(pinsWith(t, func(top map[string]any) { mut(arbOf(top)) })); err != nil {
			t.Errorf("%s: %s", name, canon(err))
		}
	}
	// no section, no pins at all
	absent := pinsWith(t, func(top map[string]any) { delete(top, "arb_sepolia") })
	wantUnknown := string(finality.NewState(finality.CodePinUnknown, "chain", finality.ChainArbitrumSepolia, "kind", "arb_sepolia").Canonical())
	if _, err := loadArbPins(absent); canon(err) != wantUnknown {
		t.Errorf("absent section: %s", canon(err))
	}
	if _, err := loadArbPins(nil); canon(err) != wantUnknown {
		t.Errorf("nil pins: %s", canon(err))
	}
}

// The Sepolia section and the KZG pin are judged before anything is verified.
func TestTheSepoliaSectionAndTheKZGPinMustBeThere(t *testing.T) {
	p := pinsWith(t, func(top map[string]any) {})
	l1p, kzg, err := ethl1Pins(p)
	if err != nil || kzg != UsedKZGSetupSHA256 || len(l1p.Network.Forks) == 0 || l1p.MinParticipants != 342 {
		t.Fatalf("embedded pins: %v %q %+v", err, kzg, l1p)
	}
	noSepolia := pinsWith(t, func(top map[string]any) { delete(top, "eth_sepolia") })
	if _, _, err := ethl1Pins(noSepolia); canon(err) != string(finality.NewState(finality.CodePinUnknown, "chain", finality.ChainSepolia, "kind", "eth_sepolia").Canonical()) {
		t.Errorf("no eth_sepolia: %s", canon(err))
	}
	if _, err := New().Verify(noSepolia, finality.BlockRef{}, nil); err == nil {
		t.Error("a verifier without a Sepolia section accepted an empty container")
	}
	// the KZG pin is read from the shared section; a legacy copy in eth_sepolia is accepted only when it agrees, and with neither the pins
	// are corrupt (never a default)
	noLegacy := pinsWith(t, func(top map[string]any) { delete(top["eth_sepolia"].(map[string]any), "kzg_setup_sha256") })
	if _, kzg, err := ethl1Pins(noLegacy); err != nil || kzg != UsedKZGSetupSHA256 {
		t.Errorf("shared pin only: %q %v", kzg, err)
	}
	conflict := pinsWith(t, func(top map[string]any) {
		top["eth_sepolia"].(map[string]any)["kzg_setup_sha256"] = strings.Repeat("a", 64)
	})
	if _, _, err := ethl1Pins(conflict); err == nil {
		t.Error("a legacy copy that differs from the shared pin was accepted")
	}
	neither := pinsWith(t, func(top map[string]any) { delete(top, "shared") })
	if _, kzg, err := ethl1Pins(neither); err == nil || kzg != "" {
		t.Errorf("no kzg pin at all: %q %v", kzg, err)
	}
}
