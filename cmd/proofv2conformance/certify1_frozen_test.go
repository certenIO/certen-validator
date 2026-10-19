package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// certify1F51ManifestSHA256 is the hash of testdata/certify1_f5_1_manifest.json, the manifest of validator 3fdd056 byte for byte
// (git show 3fdd056:pkg/proof/v2/testdata/certify1/manifest.json, blob 698cd5055cf914ca8be9c534670af5f3180710e6).
const certify1F51ManifestSHA256 = "8ddfbb6cf37cb3ce0322b252679179e955e4f5eb3d744f2bd5b4f95874778dd8"

func readManifestCases(t *testing.T, path string) (map[string]map[string]any, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Cases []map[string]any `json:"cases"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, c := range m.Cases {
		out[c["name"].(string)] = c
	}
	return out, raw
}

// A frozen document's manifest entry says what that frozen document is (V-M1, notes 4 and 5): every key of every frozen entry is the F5-1 value
// of validator 3fdd056, except the keys the verifier's moved verdict changes, and those are the fixed table's, never the verifier's own output.
// The 13 unmoved documents with a regenerated sibling differ from the F5-1 entry in the note only; the 2 evidence 2.0 ones not at all; the
// regenerated "-g" sibling keeps the words of the genesis-link-carrying spec.
func TestCertify1FrozenEntriesAreTheF5_1Ones(t *testing.T) {
	old, oldRaw := readManifestCases(t, filepath.Join("testdata", "certify1_f5_1_manifest.json"))
	if sum := sha256.Sum256(oldRaw); hex.EncodeToString(sum[:]) != certify1F51ManifestSHA256 {
		t.Fatalf("testdata/certify1_f5_1_manifest.json is %x, not the pinned F5-1 manifest", sum)
	}
	if len(old) != 33 || len(certify1Frozen) != 33 || len(certify1FrozenTexts) != 33 {
		t.Fatalf("%d F5-1 entries, %d pins, %d texts, want 33", len(old), len(certify1Frozen), len(certify1FrozenTexts))
	}
	if len(certify1FrozenMoves) != 18 {
		t.Fatalf("%d fixed moves, want 18", len(certify1FrozenMoves))
	}
	cur, _ := readManifestCases(t, filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", "certify1", "manifest.json"))
	// The keys a moved verdict changes: the verdict, its text, the report a verified vector had, the report it was the same as, and the note.
	movedKeys := map[string]bool{"expect": true, "state": true, "fields": true, "wording": true, "prefix": true, "report": true, "sameReportAs": true, "note": true}
	noteOnly := 0
	for name, pin := range certify1Frozen {
		o, ok := old[name]
		if !ok {
			t.Errorf("%s: not in the F5-1 manifest", name)
			continue
		}
		c, ok := cur[name]
		if !ok {
			t.Errorf("%s: not in the manifest", name)
			continue
		}
		txt := certify1FrozenTexts[name]
		if o["description"] != txt.Description || o["world"] != txt.World || o["edit"] != txt.Edit || o["sha256"] != pin {
			t.Errorf("%s: the pinned text or hash is not the F5-1 entry", name)
		}
		_, moved := certify1FrozenMoves[name]
		keys := map[string]bool{}
		for k := range o {
			keys[k] = true
		}
		for k := range c {
			keys[k] = true
		}
		for k := range keys {
			if movedKeys[k] && (moved || k == "note") {
				continue
			}
			if !reflect.DeepEqual(o[k], c[k]) {
				t.Errorf("%s: key %q is %v, the F5-1 entry has %v", name, k, c[k], o[k])
			}
		}
		_, sibling := cur[name+certify1GenesisSuffix]
		note, _ := c["note"].(string)
		if err := checkCertify1FrozenEntry(entryOf(t, c), sibling); err != nil {
			t.Error(err)
		}
		if !moved && note != "" {
			noteOnly++
		}
		if sibling != (note != "") {
			t.Errorf("%s: sibling %v, note %q", name, sibling, note)
		}
		if sibling {
			s := cur[name+certify1GenesisSuffix]
			if s["sha256"] == pin || strings.Contains(note, "-g") {
				t.Errorf("%s: its sibling is the frozen document or the note names it", name)
			}
		}
	}
	if noteOnly != 13 {
		t.Errorf("%d unmoved frozen documents carry the unmoved note, want 13", noteOnly)
	}
	// The sibling of the re-rooted anchor is the document with a genesis link; the frozen entry says it has none.
	sib := cur["anchor-re-rooted-off-the-verified-root"+certify1GenesisSuffix]
	if sib == nil || !strings.Contains(sib["edit"].(string), "genesisLink") || !strings.Contains(sib["description"].(string), "genesis link") {
		t.Errorf("the -g sibling of anchor-re-rooted-off-the-verified-root lost the genesis-link words: %v", sib)
	}
	if fz := cur["anchor-re-rooted-off-the-verified-root"]; strings.Contains(fz["edit"].(string), "genesisLink") || strings.Contains(fz["description"].(string), "genesis link") {
		t.Errorf("the frozen anchor-re-rooted-off-the-verified-root entry names a genesis link its bytes do not have: %v", fz)
	}
}

func entryOf(t *testing.T, m map[string]any) Certify1Case {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var c Certify1Case
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
