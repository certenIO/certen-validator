// Copyright 2026 Certen Protocol

package adiri_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// finality_adiri4 (RB11-GATE-A): the pins-strictness verdicts (vectors.json, judged by TestEveryVectorVerdictBothModesIdentical like
// every other vector) and the load-time checks of the genesis link (genesis_link.json, judged here). Every expectation is a literal
// written by pkg/finality/adiri/vectorgen/gen_adiri4.mjs, which does not call the verifier.

type linkVec struct {
	Name    string          `json:"name"`
	Note    string          `json:"note"`
	Pins    json.RawMessage `json:"pins"`
	Link    string          `json:"link"`
	LinkHex *string         `json:"link_hex"`
	Edits   []vEdit         `json:"edits"`
	Expect  string          `json:"expect"`
}

func TestAdiri4GenesisLinkVectorsGiveTheirLoadVerdicts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir4, "genesis_link.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Format  string    `json:"format"`
		Vectors []linkVec `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Format != "finality_adiri4-genesis-link/1" || len(f.Vectors) < 12 {
		t.Fatalf("%s, %d vectors", f.Format, len(f.Vectors))
	}
	for _, v := range f.Vectors {
		var file []byte
		if v.LinkHex != nil {
			if file, err = hex.DecodeString(*v.LinkHex); err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
		} else {
			if file, err = os.ReadFile(filepath.Join(vectorDir4, filepath.FromSlash(v.Link))); err != nil {
				t.Fatal(err)
			}
			es := append([]vEdit(nil), v.Edits...)
			sort.Slice(es, func(i, j int) bool { return es[i].Offset > es[j].Offset })
			for _, e := range es {
				ins, err := hex.DecodeString(e.Insert)
				if err != nil {
					t.Fatal(err)
				}
				file = append(append(append([]byte(nil), file[:e.Offset]...), ins...), file[e.Offset+e.Delete:]...)
			}
		}
		pins := &finality.Pins{Format: finality.PinsFormat, PublishedUTC: "2026-10-20T00:00:00Z", Sections: map[string]json.RawMessage{"adiri": v.Pins}}
		got := "ok"
		if err := adiri.CheckGenesisLink(file, pins); err != nil {
			if s, ok := finality.AsNamed(err); ok {
				got = string(s.Canonical())
			} else {
				got = "ERROR: " + err.Error()
			}
		}
		if got != v.Expect {
			t.Errorf("%s (%s):\n got:  %s\n want: %s", v.Name, v.Note, got, v.Expect)
		}
	}
}
