// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// RB12 OPS-A2 item 15: the nine golden status documents of proofs_service (pkg/server/testdata/finality_status, OPS-C) are shared fixtures.
// Both readers must agree on each of them byte for byte: the file is the one proofs_service holds (sha256), and the validator reads it as
// the manifest says (validatorReads), which proofs_service also asserts of its own reader.
func TestGoldenStatusDocumentsAreReadAsTheManifestSays(t *testing.T) {
	dir := filepath.Join("testdata", "finality_status")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Entries map[string]struct {
			SHA256         string          `json:"sha256"`
			ValidatorReads json.RawMessage `json:"validatorReads"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != 9 {
		t.Fatalf("%d golden documents, want 9", len(m.Entries))
	}
	for name, e := range m.Entries {
		doc, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(doc); hex.EncodeToString(sum[:]) != e.SHA256 {
			t.Errorf("%s: sha256 %x differs from the manifest's %s", name, sum, e.SHA256)
			continue
		}
		v, err := ParseBuilderStatusDocument(doc)
		if err != nil {
			t.Errorf("%s: the validator refuses a document proofs_service accepts: %v", name, err)
			continue
		}
		eta := ""
		if !v.ETA.IsZero() {
			eta = v.ETA.UTC().Format("2006-01-02T15:04:05Z")
		}
		got := map[string]any{"class": string(v.Class), "levelReached": v.LevelReached.String(), "nextLevel": v.NextLevel.String(), "eta": eta, "seq": v.Seq, "pinsSha256": v.PinsSHA256}
		var state any
		if len(v.State) > 0 {
			if err := json.Unmarshal(v.State, &state); err != nil {
				t.Fatal(err)
			}
		}
		got["state"] = state
		var want map[string]any
		if err := json.Unmarshal(e.ValidatorReads, &want); err != nil {
			t.Fatal(err)
		}
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(want)
		if !bytes.Equal(gb, wb) {
			t.Errorf("%s: the validator reads\n%s\nthe manifest says\n%s", name, gb, wb)
		}
	}
}
