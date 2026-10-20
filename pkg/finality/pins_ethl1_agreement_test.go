// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// publishedPinsFiles are the bytes of every JSON file under a testdata directory of pkg/finality whose path names pins.
func publishedPinsFiles(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		sl := filepath.ToSlash(p)
		if d.IsDir() || !strings.HasSuffix(sl, ".json") || !strings.Contains(sl, "testdata/") || !strings.Contains(sl, "pins") {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		out = append(out, b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Every number the Sepolia section carries that the L1 head verifier also runs on must equal it: a pins file that says
// committee 256, 64 epochs per period, 171 participants or a different spec would be judged under values ethl1 does not use.
func TestAPinsFileThatDisagreesWithWhatTheL1HeadVerifierRunsOnIsCorrupt(t *testing.T) {
	edit := func(set func(sec map[string]any)) error {
		var m map[string]any
		if err := json.Unmarshal(embeddedPins, &m); err != nil {
			t.Fatal(err)
		}
		set(m["eth_sepolia"].(map[string]any))
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParsePinsOverride(raw)
		return err
	}
	if err := edit(func(map[string]any) {}); err != nil {
		t.Fatalf("the embedded pins themselves: %v", err)
	}
	for _, c := range []struct {
		name string
		key  string // "": any pins_corrupt reason
		set  func(sec map[string]any)
	}{
		{"committee 256 with 171 participants", "sync_committee_size", func(s map[string]any) { s["sync_committee_size"] = 256; s["min_participants"] = 171 }},
		{"committee 1024", "sync_committee_size", func(s map[string]any) { s["sync_committee_size"] = 1024; s["min_participants"] = 683 }},
		{"epochs per period 64", "epochs_per_period", func(s map[string]any) { s["epochs_per_period"] = 64 }},
		{"epochs per period 512", "epochs_per_period", func(s map[string]any) { s["epochs_per_period"] = 512 }},
		{"spec garbage", "spec", func(s map[string]any) { s["spec"] = "garbage" }},
		{"spec empty", "spec", func(s map[string]any) { s["spec"] = "" }},
		{"genesis time zero", "genesis_time", func(s map[string]any) { s["genesis_time"] = 0 }},
		{"genesis time off by one", "genesis_time", func(s map[string]any) { s["genesis_time"] = 1655733601 }},
		{"171 participants of 512", "", func(s map[string]any) { s["min_participants"] = 171 }},
		{"341 participants of 512", "", func(s map[string]any) { s["min_participants"] = 341 }},
		{"max_links above the spec 8.2 bound", "max_links", func(s map[string]any) { s["max_links"] = 65 }},
		{"max_links 10 million", "max_links", func(s map[string]any) { s["max_links"] = 10000000 }},
	} {
		err := edit(c.set)
		se, ok := AsNamed(err)
		if !ok || se.Code != CodePinsCorrupt {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if c.key != "" && (se.Fields["reason"] != PinsBadValue || se.Fields["key"] != c.key) {
			t.Errorf("%s: %s", c.name, se.Canonical())
		}
	}
	// the values at the bounds are accepted: 342 participants, max_links 64 and 1
	for _, ok := range []func(sec map[string]any){
		func(s map[string]any) { s["min_participants"] = 342 },
		func(s map[string]any) { s["min_participants"] = 512 },
		func(s map[string]any) { s["max_links"] = 64 },
		func(s map[string]any) { s["max_links"] = 1 },
	} {
		if err := edit(ok); err != nil {
			t.Errorf("a value at the bound is refused: %v", err)
		}
	}
}

// Every pins file of every published set that carries the Sepolia section still satisfies the agreement.
func TestEveryPublishedSetsSepoliaPinsAgreeWithTheL1HeadVerifier(t *testing.T) {
	n := 0
	for _, raw := range publishedPinsFiles(t) {
		if !strings.Contains(string(raw), `"eth_sepolia"`) {
			continue
		}
		if _, err := ParsePinsOverride(raw); err != nil {
			se, _ := AsNamed(err)
			if se != nil && se.Code == CodePinsCorrupt && (se.Fields["key"] == "sync_committee_size" || se.Fields["key"] == "epochs_per_period" ||
				se.Fields["key"] == "spec" || se.Fields["key"] == "genesis_time" || se.Fields["key"] == "max_links") {
				t.Errorf("a published pins file is refused by the agreement: %s", se.Canonical())
			}
		}
		n++
	}
	if n < 10 {
		t.Fatalf("only %d published pins files scanned", n)
	}
}
