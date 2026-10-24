// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// writeFiles writes a published set directory: the files plus the MANIFEST of their sha256 lines (sorted, LF).
func writeFiles(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var man bytes.Buffer
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), files[n], 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(files[n])
		fmt.Fprintf(&man, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST"), man.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A set of materialised vectors built from the H0 world is loaded and run WITHOUT a world builder: the loader reads the resolved inputs
// (inputs.json, container.hex, the raw manifest document) and hands the Verifier the same context, container and manifest that the world
// produced [r3.2:E-i]. world is imported here to PRODUCE the set; the load and run path (LoadVectorSet, RunSet with a nil WorldBuilder)
// does not use it.
func TestMaterialisedH0SetRunsWithoutTheWorldBuilder(t *testing.T) {
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	type vec struct {
		id   string
		muts []ci.Mutation
	}
	flip := func(off int) []ci.Mutation {
		v := json.RawMessage(`"ff"`)
		return []ci.Mutation{{Op: "set_byte", Target: "container", Offset: &off, Value: v}}
	}
	vecs := []vec{{"VS8-170", nil}, {"VS8-012.flip_byte", flip(0)}, {"VS8-012.flip_magic", flip(1)}}
	files := map[string][]byte{}
	want := map[string]ci.Inputs{}
	for _, chain := range []uint64{11155111, 84532} {
		for _, v := range vecs {
			id := v.id
			if chain != 11155111 {
				if len(strings.SplitN(id, ".", 2)) == 2 {
					id += "_c" + fmt.Sprint(chain)
				} else {
					id += ".c" + fmt.Sprint(chain)
				}
			}
			spec, err := world.Generate(m, chain, world.VariantH0)
			if err != nil {
				t.Fatal(err)
			}
			built, err := world.Apply(m, spec, v.muts, nil)
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			in := built.Inputs
			in.ManifestRaw, in.ExtensionRaw = built.ManifestRaw, built.ExtensionRaw
			exp := ci.Expected{Headline: ci.HeadlineVerified}
			vj, err := json.MarshalIndent(ci.Vector{ID: id, Base: "H0", Mutations: append([]ci.Mutation{}, v.muts...), Expected: exp}, "", " ")
			if err != nil {
				t.Fatal(err)
			}
			files[id+".json"] = append(vj, '\n')
			mf, err := ci.Materialise(id, in, exp)
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			for n, b := range mf {
				files[n] = b
			}
			want[id] = in
		}
	}
	wj, err := json.Marshal(map[string]string{"note": "provenance only: the materialised inputs below are all a runner needs"})
	if err != nil {
		t.Fatal(err)
	}
	files["world.json"] = append(wj, '\n')
	dir := filepath.Join(t.TempDir(), "ci-h0-materialised")
	writeFiles(t, dir, files)

	set, err := ci.LoadVectorSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) != len(want) || len(set.Inputs) != len(want) {
		t.Fatalf("vectors %d inputs %d, want %d", len(set.Vectors), len(set.Inputs), len(want))
	}
	seen := map[string]bool{}
	ver := ci.VerifierFunc(func(ctx ci.LegContext, container []byte, mf *ci.Manifest) (ci.Report, error) {
		// find which vector this is by its container + context, and compare everything the runner handed over
		for id, w := range want {
			if seen[id] || !bytes.Equal(container, w.Container) {
				continue
			}
			a, err := ci.ContextToFile(ctx)
			if err != nil {
				return ci.Report{}, err
			}
			b, err := ci.ContextToFile(w.Ctx)
			if err != nil {
				return ci.Report{}, err
			}
			ja, _ := json.Marshal(a)
			jb, _ := json.Marshal(b)
			if !bytes.Equal(ja, jb) {
				continue
			}
			if mf.Source != ci.ManifestSourceEmbedded || mf.SHA256 != m.SHA256 {
				return ci.Report{}, fmt.Errorf("%s: manifest source %q", id, mf.Source)
			}
			if ctx.Tx.Hash() != w.Ctx.Tx.Hash() || !bytes.Equal(ctx.Settlement.Header, w.Ctx.Settlement.Header) || ctx.Chain != w.Ctx.Chain {
				return ci.Report{}, fmt.Errorf("%s: settlement or transaction differ", id)
			}
			seen[id] = true
			h, err := ci.ComputeHeadline(ci.HeadlineInput{Parts: allVerifiedParts(), StateRootAuthenticated: true, LevelReached: "finalized", JudgedAtLevel: "finalized",
				RegistryLink: "via S9"})
			return ci.Report{Headline: h}, err
		}
		return ci.Report{}, fmt.Errorf("the verifier received inputs that match no vector")
	})
	for _, r := range ci.RunSet(set, nil, ver) { // nil: no world builder
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("the verifier saw %d of %d vectors", len(seen), len(want))
	}
}

func allVerifiedParts() []ci.PartResult {
	parts := make([]ci.PartResult, len(ci.JudgedParts))
	for i, p := range ci.JudgedParts {
		parts[i] = ci.PartResult{Part: p, Status: ci.StatusVerified}
	}
	return parts
}
