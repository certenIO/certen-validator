package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// RB9-F6, F-VE-2 option (b): in every xpartition suite the verified vectors are exactly the ones that carry the genesis link. A vector that
// verified before the offline walk required the link keeps its document (the manifest pins its hash) and is refused certify_link_missing{genesis}
// with the note that says why; beside it, with the suffix -g, is the vector that carries the link and verifies. The manifests are the spec the
// TypeScript verifier takes, so the pairing is pinned here and not only in the generator.
func TestXPartitionVerifiedVectorsAreTheOnesWithTheGenesisLink(t *testing.T) {
	moved, siblings := 0, 0
	for _, suite := range []string{"xpartition2", "xpartition2b", "xpartition3", "xpartition3b", "xpartition4", "xpartition5", "xpartition6"} {
		cases, _ := readManifestCases(t, filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", suite, "manifest.json"))
		for name, c := range cases {
			switch {
			case c["note"] != nil: // a frozen document whose verdict moved
				moved++
				if c["expect"] != "refused" || c["state"] != "certify_link_missing" || c["note"] != xworld.GenesisMovedNote || strings.HasSuffix(name, xworld.GenesisSiblingSuffix) {
					t.Errorf("%s/%s: a moved entry is %v", suite, name, c)
				}
				f, _ := c["fields"].([]any)
				if len(f) != 1 || f[0] != "genesis" {
					t.Errorf("%s/%s: fields %v, want [genesis]", suite, name, c["fields"])
				}
				s, ok := cases[name+xworld.GenesisSiblingSuffix]
				if !ok || s["expect"] != "verified" || s["sha256"] == c["sha256"] || s["note"] != nil {
					t.Errorf("%s/%s: its sibling is %v", suite, name, s)
				}
			case c["expect"] == "verified":
				siblings++
				base := strings.TrimSuffix(name, xworld.GenesisSiblingSuffix)
				m, ok := cases[base]
				if base == name || !ok || m["note"] != xworld.GenesisMovedNote {
					t.Errorf("%s/%s: a verified vector that is not the sibling of a moved one: %v", suite, name, c)
				}
			}
		}
	}
	if moved != 41 || siblings != 41 {
		t.Errorf("%d moved vectors and %d siblings, want 41 and 41", moved, siblings)
	}
}
