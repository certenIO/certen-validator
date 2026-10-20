// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The Pins.Extend cases of the published set finality_eth_sepolia1 (written by cmd/finalityethsepoliarecord, read here without importing
// the kind): the same extension, links and verdict, judged by the framework's own Extend.
const extendSet = "ethsepolia/testdata/finality_eth_sepolia1"

func extendRead(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(extendSet, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEveryPublishedExtendCaseGivesItsCanonicalVerdict(t *testing.T) {
	ents, err := os.ReadDir(filepath.Join(extendSet, "extend"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, en := range ents {
		if !strings.HasPrefix(en.Name(), "extend_") || !strings.HasSuffix(en.Name(), ".json") || strings.HasSuffix(en.Name(), ".pins.json") {
			continue
		}
		n++
		var c struct {
			ID           string            `json:"id"`
			Base         string            `json:"base"`
			Extension    string            `json:"extension"`
			LinksDir     string            `json:"links_dir"`
			LinksReplace map[string]string `json:"links_replace"`
			LinksDrop    []uint64          `json:"links_drop"`
			Expect       string            `json:"expect_canonical"`
		}
		if err := json.Unmarshal(extendRead(t, "extend/"+en.Name()), &c); err != nil {
			t.Fatal(err)
		}
		base, err := ParsePinsOverride(extendRead(t, c.Base))
		if err != nil {
			t.Fatal(err)
		}
		links := map[uint64][]byte{}
		lents, err := os.ReadDir(filepath.Join(extendSet, filepath.FromSlash(c.LinksDir)))
		if err != nil {
			t.Fatal(err)
		}
		for _, le := range lents {
			p, _ := strconv.ParseUint(strings.TrimSuffix(le.Name(), ".ssz"), 10, 64)
			links[p] = extendRead(t, c.LinksDir+"/"+le.Name())
		}
		for p, rel := range c.LinksReplace {
			k, _ := strconv.ParseUint(p, 10, 64)
			links[k] = extendRead(t, rel)
		}
		for _, p := range c.LinksDrop {
			delete(links, p)
		}
		got, err := base.Extend(extendRead(t, c.Extension), links)
		var canon string
		if err != nil {
			s, ok := AsNamed(err)
			if !ok {
				t.Fatalf("%s: %v", c.ID, err)
			}
			canon = string(s.Canonical())
		} else {
			e, _ := got.Sepolia()
			_, src := got.Identity()
			canon = string((&StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(len(e.Anchors)), "pins_source": src}}).Canonical())
		}
		if canon != c.Expect {
			t.Errorf("%s:\n got  %s\n want %s", c.ID, canon, c.Expect)
		}
	}
	if n < 9 {
		t.Fatalf("%d extend cases", n)
	}
}

// The whole 14-entry vector ledger re-derives from its root pin; a changed link anywhere breaks the step that uses it.
func TestTheVectorLedgerRederivesAndABrokenLinkIsNamedAtItsPeriod(t *testing.T) {
	pins, err := ParsePinsOverride(extendRead(t, "pins/main.json"))
	if err != nil {
		t.Fatal(err)
	}
	links := map[uint64][]byte{}
	lents, _ := os.ReadDir(filepath.Join(extendSet, "raw", "links"))
	for _, le := range lents {
		p, _ := strconv.ParseUint(strings.TrimSuffix(le.Name(), ".ssz"), 10, 64)
		links[p] = extendRead(t, "raw/links/"+le.Name())
	}
	if err := pins.VerifyLedger(links); err != nil {
		t.Fatal(err)
	}
	bad := map[uint64][]byte{}
	for k, v := range links {
		bad[k] = v
	}
	bad[1385] = append([]byte(nil), links[1385]...)
	bad[1385][26340] ^= 1
	err = pins.VerifyLedger(bad)
	s, ok := AsNamed(err)
	if !ok || s.Code != CodeLedgerExtensionBad || s.Fields["period"] != uint64(1385) || s.Fields["reason"] != string(LedgerLinkSHA256Mismatch) {
		t.Fatalf("%v", err)
	}
	delete(bad, 1385)
	if s, _ := AsNamed(pins.VerifyLedger(bad)); s == nil || s.Fields["period"] != uint64(1385) || s.Fields["reason"] != string(LedgerLinkMissing) {
		t.Fatalf("%v", s)
	}
	// a ledger whose first entry has no block_root is not a root pin
	noRoot, err := ParsePinsOverride(extendRead(t, "extend/base_1386.json"))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := noRoot.Sepolia()
	e.Anchors = e.Anchors[1:]
	if s, _ := AsNamed(noRoot.VerifyLedger(links)); s == nil || s.Fields["reason"] != string(LedgerRootPinUnverifiable) {
		t.Fatalf("%v", s)
	}
}
