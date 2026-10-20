// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The ledger cases of the published set finality_eth_sepolia3 (review V-C2-A1 D1/D2), judged by the framework's own VerifyLedger and
// Extend. Each case names a base file and patches it (anchor fields, one flipped byte of a link file, a moved link file); the
// patch is applied here by code independent of cmd/finalityethsepolia3record, which wrote the expected verdict.
const set3 = "ethsepolia/testdata/finality_eth_sepolia3"

func set3Read(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(set3, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSet3ManifestPinsEveryFileAndOnlyThoseFiles(t *testing.T) {
	mraw := set3Read(t, "MANIFEST.json")
	sum := sha256.Sum256(mraw)
	if got := strings.TrimSpace(string(set3Read(t, "MANIFEST.json.sha256"))); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("MANIFEST.json.sha256 %s, the manifest hashes to %x", got, sum)
	}
	var m struct {
		Set   string            `json:"set"`
		Cases []string          `json:"cases"`
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Set != "finality_eth_sepolia3" {
		t.Fatalf("set %q", m.Set)
	}
	for rel, want := range m.Files {
		s := sha256.Sum256(set3Read(t, rel))
		if hex.EncodeToString(s[:]) != want {
			t.Errorf("%s does not hash to its manifest entry", rel)
		}
	}
	var on []string
	err := filepath.Walk(set3, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(set3, p)
		on = append(on, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(on)
	for _, rel := range on {
		if _, ok := m.Files[rel]; !ok && rel != "MANIFEST.json" && rel != "MANIFEST.json.sha256" && rel != "README.md" {
			t.Errorf("%s is in the set directory but not in the manifest", rel)
		}
	}
	if got := sha256.Sum256(set3Read(t, "pins/embedded.json")); hex.EncodeToString(got[:]) != PinsSHA256 {
		t.Errorf("pins/embedded.json is not the embedded pins file (PinsSHA256)")
	}
	if len(m.Cases) < 21 {
		t.Errorf("%d cases", len(m.Cases))
	}
}

func TestEverySet3LedgerCaseGivesItsCanonicalVerdict(t *testing.T) {
	ents, err := os.ReadDir(filepath.Join(set3, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, en := range ents {
		var c struct {
			ID          string   `json:"id"`
			Op          string   `json:"op"`
			Pins        string   `json:"pins"`
			Extension   string   `json:"extension"`
			LinksDir    string   `json:"links_dir"`
			LinksOnly   []uint64 `json:"links_only"`
			AnchorPatch []struct {
				Period uint64 `json:"period"`
				Field  string `json:"field"`
				Value  string `json:"value"`
			} `json:"anchor_patch"`
			LinkPatch []struct {
				Period uint64 `json:"period"`
				Offset int    `json:"offset"`
				Xor    uint8  `json:"xor"`
				Relink bool   `json:"relink"`
			} `json:"link_patch"`
			LinkMove []struct {
				From uint64 `json:"from"`
				To   uint64 `json:"to"`
			} `json:"link_move"`
			Expect string `json:"expect_canonical"`
		}
		if err := json.Unmarshal(set3Read(t, "ledger/"+en.Name()), &c); err != nil {
			t.Fatal(err)
		}
		n++
		links := map[uint64][]byte{}
		for p := uint64(1378); p <= 1391; p++ {
			only := len(c.LinksOnly) == 0
			for _, o := range c.LinksOnly {
				only = only || o == p
			}
			if only {
				links[p] = set3Read(t, c.LinksDir+"/"+strconv.FormatUint(p, 10)+".ssz")
			}
		}
		target := c.Pins
		if c.Op == "extend" {
			target = c.Extension
		}
		var doc map[string]any
		if err := json.Unmarshal(set3Read(t, target), &doc); err != nil {
			t.Fatal(err)
		}
		anchor := func(period uint64) map[string]any {
			for _, a := range doc["eth_sepolia"].(map[string]any)["anchors"].([]any) {
				if am := a.(map[string]any); uint64(am["period"].(float64)) == period {
					return am
				}
			}
			t.Fatalf("%s: no anchor %d", c.ID, period)
			return nil
		}
		for _, lp := range c.LinkPatch {
			links[lp.Period][lp.Offset] ^= lp.Xor
			if lp.Relink {
				s := sha256.Sum256(links[lp.Period])
				anchor(lp.Period)["link_sha256"] = hex.EncodeToString(s[:])
			}
		}
		for _, ap := range c.AnchorPatch {
			switch ap.Field {
			case "block_root":
				anchor(ap.Period)["block_root"] = ap.Value
			case "period":
				v, _ := strconv.ParseUint(ap.Value, 10, 64)
				anchor(ap.Period)["period"] = float64(v)
			default:
				t.Fatalf("%s: patch field %q", c.ID, ap.Field)
			}
		}
		for _, mv := range c.LinkMove {
			links[mv.To] = links[mv.From]
			delete(links, mv.From)
		}
		patched := set3Read(t, target)
		if len(c.AnchorPatch)+len(c.LinkPatch) > 0 {
			patched, _ = json.MarshalIndent(doc, "", "  ")
			patched = append(patched, '\n')
		}
		var verdict error
		var canon string
		switch c.Op {
		case "verify_ledger":
			p, err := ParsePinsOverride(patched)
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			if verdict = p.VerifyLedger(links); verdict == nil {
				e, _ := p.Sepolia()
				canon = string((&StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(len(e.Anchors))}}).Canonical())
			}
		case "extend":
			base, err := ParsePinsOverride(set3Read(t, c.Pins))
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			got, err := base.Extend(patched, links)
			if verdict = err; err == nil {
				e, _ := got.Sepolia()
				_, src := got.Identity()
				canon = string((&StateError{Code: "verified", Fields: map[string]any{"anchors": uint64(len(e.Anchors)), "pins_source": src}}).Canonical())
			}
		default:
			t.Fatalf("%s: op %q", c.ID, c.Op)
		}
		if verdict != nil {
			s, ok := AsNamed(verdict)
			if !ok {
				t.Fatalf("%s: unnamed verdict %v", c.ID, verdict)
			}
			canon = string(s.Canonical())
		}
		if canon != c.Expect {
			t.Errorf("%s:\n got  %s\n want %s", c.ID, canon, c.Expect)
		}
	}
	if n != 16 {
		t.Fatalf("%d ledger cases, want 16", n)
	}
}

// The closed reason set carries the new reason as a typed constant and in the registry.
func TestTheNewLedgerReasonIsRegistered(t *testing.T) {
	if string(LedgerBlockRootOnAppendedEntry) != "block_root_on_appended_entry" {
		t.Fatal(LedgerBlockRootOnAppendedEntry)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"base_not_prefix", "block_root_on_appended_entry", "committee_root_mismatch"`) {
		t.Fatal("states.json does not list block_root_on_appended_entry")
	}
}
