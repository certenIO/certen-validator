// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// SetName5 is the post-Denim vector set (RB11-D-POST): real legs of Base Sepolia blocks whose five-block timestamp seconds the
// timestamp-keyed lookup could not tell apart. Sets 1 to 4 are never edited.
const SetName5 = "finality_base_posted5"

var setDir5 = filepath.Join("testdata", SetName5)

// publishedPinsDigest is the digest of the pins file the set was judged under; the manifest carries it.
const publishedPinsDigest5 = "9f4fc10feca95909272c9f6eaef1a38d7a06110cfead0a88cb79e8ffd7a3d1cf"

type manifest5 struct {
	Format string            `json:"format"`
	Set    string            `json:"set"`
	Pins   string            `json:"pins_sha256_embedded"`
	Cases  []string          `json:"cases"`
	Files  map[string]string `json:"files"`
}

func loadManifest5(t *testing.T) manifest5 {
	t.Helper()
	raw, err := ReadFile(setDir5, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadFile(setDir5, "MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != FileSHA256(raw) {
		t.Fatalf("MANIFEST.sha256 %s, manifest hashes to %s", strings.TrimSpace(string(want)), FileSHA256(raw))
	}
	var m manifest5
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSet5ManifestPinsEveryFileAndTheEmbeddedPinsDigest(t *testing.T) {
	m := loadManifest5(t)
	if m.Set != SetName5 || m.Format != "certen-base-posted-vectors/1" || len(m.Cases) < 14 {
		t.Fatalf("set %q format %q with %d cases", m.Set, m.Format, len(m.Cases))
	}
	if m.Pins != publishedPinsDigest5 || finality.PinsSHA256 != publishedPinsDigest5 {
		t.Fatalf("the set was judged under pins %s, the verifier embeds %s", m.Pins, finality.PinsSHA256)
	}
	listed := map[string]bool{"manifest.json": true, "MANIFEST.sha256": true, ".gitattributes": true}
	for name, h := range m.Files {
		b, err := ReadFile(setDir5, name)
		if err != nil {
			t.Fatal(err)
		}
		if FileSHA256(b) != h {
			t.Errorf("%s: manifest says %s, file hashes to %s", name, h, FileSHA256(b))
		}
		listed[name] = true
	}
	err := filepath.Walk(setDir5, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(setDir5, p)
		if !listed[filepath.ToSlash(rel)] {
			t.Errorf("%s is in the set directory but not in the manifest", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSet5PinsMainCarriesTheEmbeddedBaseSepoliaSectionByteForByteInValue(t *testing.T) {
	var emb, set map[string]json.RawMessage
	if err := json.Unmarshal(finality.EmbeddedPinsBytes(), &emb); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadFile(setDir5, "pins/main.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	var a, b any
	if err := json.Unmarshal(emb["base_sepolia"], &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(set["base_sepolia"], &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("pins/main.json base_sepolia differs from the embedded pins: the set would be judged under another post_denim row")
	}
	if !bytes.Contains(emb["base_sepolia"], []byte("post_denim")) {
		t.Fatal("the embedded pins carry no post_denim row")
	}
}

func TestSet5EveryCaseIsJudgedByTheRealVerifierToItsExpectedBytes(t *testing.T) {
	m := loadManifest5(t)
	nOK, nState := 0, 0
	for _, id := range m.Cases {
		raw, err := ReadFile(setDir5, "cases/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c Case
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		var e Expect
		if err := json.Unmarshal(c.Expect, &e); err != nil {
			t.Fatal(err)
		}
		got, err := c.Run(setDir5)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if want := ExpectBytes(e); !bytes.Equal(got, want) {
			t.Errorf("%s:\n want %s\n got  %s", id, want, got)
		}
		if e.Result == "ok" {
			nOK++
		} else {
			nState++
		}
	}
	if nOK < 6 || nState < 8 {
		t.Fatalf("%d valid and %d refused cases", nOK, nState)
	}
}

// Set 1 holds the real pre-Denim legs: under pins that gained the post_denim row they are judged exactly as the published set says,
// pre-Denim blocks keep the timestamp-keyed lookup.
func TestSet1PreDenimLegsAreJudgedTheSameUnderPinsWithThePostDenimRow(t *testing.T) {
	var emb map[string]json.RawMessage
	if err := json.Unmarshal(finality.EmbeddedPinsBytes(), &emb); err != nil {
		t.Fatal(err)
	}
	var embBase map[string]json.RawMessage
	if err := json.Unmarshal(emb["base_sepolia"], &embBase); err != nil {
		t.Fatal(err)
	}
	row := embBase["post_denim"]
	if len(row) == 0 {
		t.Fatal("the embedded pins carry no post_denim row")
	}
	edit := func(raw []byte) ([]byte, error) {
		raw, err := SupplyBaseSepoliaPins(raw, PublishedSetPinSupply)
		if err != nil {
			return nil, err
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		var sec map[string]json.RawMessage
		if err := json.Unmarshal(m["base_sepolia"], &sec); err != nil {
			return nil, err
		}
		sec["post_denim"] = row
		m["base_sepolia"], _ = json.Marshal(sec)
		return json.MarshalIndent(m, "", "  ")
	}
	n := 0
	for _, id := range []string{"valid_a", "valid_b", "valid_a_denim_after_block", "batch_not_found_for_timestamp", "leg_parent_hash_altered", "deposit_epoch_number_altered"} {
		raw, err := ReadFile(setDir, "cases/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c Case
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		var e Expect
		if err := json.Unmarshal(c.Expect, &e); err != nil {
			t.Fatal(err)
		}
		got, err := c.RunEdited(setDir, edit)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if want := ExpectBytes(e); !bytes.Equal(got, want) {
			t.Errorf("%s under the post_denim pins:\n want %s\n got  %s", id, want, got)
		}
		n++
	}
	if n != 6 {
		t.Fatal(n)
	}
}
