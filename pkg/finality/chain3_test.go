// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// The finality_chain3 consumer (R12-OUTCOME-TX): the optional leg.headerRlp of the portable finality member. It uses only the exported
// behaviour the vectors describe (ParseSection, CarriedLeg.Ref), so the same files, copied byte for byte, are the TypeScript twin's oracle.

func TestChain3ManifestPinsEveryFileAndItself(t *testing.T) {
	raw := readSet(t, "finality_chain3", "MANIFEST.json")
	var m struct {
		Set   string            `json:"set"`
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Set != "finality_chain3" || len(m.Files) != 4 {
		t.Fatalf("manifest: %v %+v", err, m)
	}
	for name, want := range m.Files {
		sum := sha256.Sum256(readSet(t, "finality_chain3", name))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: manifest says %s, file hashes to %s", name, want, got)
		}
	}
	sum := sha256.Sum256(raw)
	if got := strings.TrimSpace(string(readSet(t, "finality_chain3", "MANIFEST.json.sha256"))); got != hex.EncodeToString(sum[:]) {
		t.Errorf("MANIFEST.json.sha256 %s, the manifest hashes to %x", got, sum)
	}
}

func TestChain3EveryLegVectorIsJudgedAsWritten(t *testing.T) {
	var set struct {
		Vectors []struct {
			Name        string `json:"name"`
			Input       string `json:"input"`
			Expect      string `json:"expect"`
			HeaderBytes int    `json:"headerBytes"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(readSet(t, "finality_chain3", "legs.json"), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) != 14 {
		t.Fatalf("%d vectors", len(set.Vectors))
	}
	for _, v := range set.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			sec, err := ParseSection([]byte(v.Input))
			headerBytes := 0
			if err == nil {
				var ref BlockRef
				if ref, err = sec.Leg.Ref(); err == nil {
					headerBytes = len(ref.HeaderRLP)
				}
			}
			if got := canonOf(err); got != v.Expect {
				t.Fatalf("\n got  %s\n want %s", got, v.Expect)
			}
			if v.Expect == "ok" && headerBytes != v.HeaderBytes {
				t.Fatalf("the reference holds %d header bytes, want %d", headerBytes, v.HeaderBytes)
			}
		})
	}
}
