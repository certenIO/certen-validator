// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// Every published vector set is run through the REAL composed verifier (verify_default.go: steps of 2a, 2b-1, 2b-2, 2c; no stand-ins) from
// its materialised inputs, without the world builder. Whatever a package test accepted over a stand-in is judged here by the real steps.
func TestEveryPublishedSetRunsThroughTheComposedVerifier(t *testing.T) {
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join("testdata", "contractidentity", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "s8_") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) < 7 {
		t.Fatalf("expected the seven published sets, found %v", names)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			set, err := ci.LoadVectorSet(setDir(name))
			if err != nil {
				t.Fatal(err)
			}
			pass := 0
			for _, r := range ci.RunSet(set, nil, ver) {
				if r.Outcome != ci.OutcomePass {
					t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
					continue
				}
				pass++
			}
			t.Logf("%s: %d of %d vectors pass", name, pass, len(set.Vectors))
		})
	}
}

// ---- the rows of the index: every published vector names one, and every row without a vector is classified ----

// unpublishedRows are the rows of Freeze inventory item 5 for which no published set holds a vector, each with the reason. The test fails when
// a row listed here gains a vector (remove it) or when a row without a vector is not listed (classify it): the list can neither rot nor hide a gap.
var unpublishedRows = map[string]string{
	"VS8-002": "world limit: the settlement chain id is the world's own (Generate), no mutation target edits LegContext.Chain; judged by TestVS8_002_ChainLookup (manifest_test.go)",
	"VS8-003": "world limit: one extension per shadowed table; judged by TestVS8_003_ExtensionMayNotShadow (manifest_test.go)",
	"VS8-004": "world limit: accepted extension rows (a new chain with dependent rows, owner rows, setRootHistory appends) need a world built on the new chain; judged by TestVS8_004_ExtensionAppendsRows (manifest_test.go)",
	"VS8-015": "world limit: 17 codes, 17 hop headers, 4097 spine headers, 4097 block txs, 16385 nodes exceed what the world derives; judged by TestCapsAreExactBoundaries (codec_test.go)",
	"VS8-016": "world limit: a 4 MB container (code 262145 B, node 131073 B, block txs 1048577 B) is not a vector file; judged by TestCapsAreExactBoundaries and TestContainerSizeCapIsExact (codec_test.go)",
	"VS8-021": "world limit: the base is always H0 (S6 proven); an s6_silent leg is the world variant s6silent, whose garbage S6 member has no mutation",
	"VS8-132": "world limit: totals and powers cannot be set through world.Set (the call is derived from the registry); judged by TestB2InnerRuleBoundaries and TestB2OuterRuleFloor (steps_2b2_unit_test.go)",
	"VS8-175": "world limit: the synthetic attestation block carries the transaction types of the world's own transactions, not one per chain table row",
	"VS8-179": "closed vocabulary: a txScan row without evidence is refused by the manifest build (verify-identity-manifest.sh), before any step of the verifier runs",
	"VS8-181": "not a vector: 'every Stated part and Open entry tried against raises status' is the exhaustive headline oracle TestHeadlineAlgebraIsExhaustive (types_test.go) and the 1500-table oracle of runner_test.go",
	"VS8-200": "not a verifier vector: the generator row (authwriters.mjs and design/vectors/s8/negctl) is judged by the manifest build",
	"VS8-201": "not a verifier vector: README, generator and JSON slot formulas agree; judged by TestSlotChecksCoverage and TestEmbeddedManifestSlotChecksRederive (slots_test.go)",
	"VS8-210": "not a verifier vector: the goldens G-S8-0..2 are judged by TestGoldenG0Digest, TestGoldenG1Container, TestGoldenG2Container and TestGoldensEqualSpecText (goldens_test.go); the 12-case corpus is cie1.mjs",
	"VS8-230": "the Go/TS parity row: it exists only when the TypeScript port consumes these sets (WP-S8-6)",
}

func TestEveryPublishedVectorNamesARowAndEveryOtherRowIsClassified(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "contractidentity", "vectors", "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Vectors []struct{ ID string }
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	for _, r := range idx.Vectors {
		rows[r.ID] = true
	}
	have := map[string]int{}
	sets := loadEverySet(t)
	for _, name := range sortedNames(sets) {
		for _, v := range sets[name].Vectors {
			if !rows[v.SpecID()] {
				t.Errorf("%s/%s: %s is not a row of the index", name, v.ID, v.SpecID())
			}
			have[v.SpecID()]++
		}
	}
	for id := range rows {
		_, classified := unpublishedRows[id]
		switch {
		case have[id] == 0 && !classified:
			t.Errorf("row %s has no published vector and is not classified", id)
		case have[id] > 0 && classified:
			t.Errorf("row %s has %d published vectors but is still classified as unpublished", id, have[id])
		}
	}
	for id := range unpublishedRows {
		if !rows[id] {
			t.Errorf("classified row %s is not a row of the index", id)
		}
	}
	t.Logf("%d rows, %d with a published vector, %d classified", len(rows), len(rows)-len(unpublishedRows), len(unpublishedRows))
}
