// Copyright 2026 Certen Protocol

package world

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// WORLD-FIX (change requests C1 and C2 of S8_FREEZE.md 5b): Builder.Build carries the raw manifest, pin and extension documents so that
// VS8-001/003/004 are expressible through RunSet, and WriteSet writes the materialised files of every vector.

func mutation(op, target, path string, value any) ci.Mutation {
	m := ci.Mutation{Op: op, Target: target, Path: path}
	if value != nil {
		m.Value, _ = json.Marshal(value)
	}
	return m
}

func worldJSON(t *testing.T, chain uint64, variant string) (*ci.Manifest, *Spec, []byte) {
	t.Helper()
	m := manifest(t)
	sp, err := Generate(m, chain, variant)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sp.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	return m, sp, raw
}

// shadowMutation redefines the eip2935 row of Base Sepolia in an extension: the VS8-003 class.
func shadowMutation(t *testing.T) ci.Mutation {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(ci.EmbeddedManifestBytes(), &doc); err != nil {
		t.Fatal(err)
	}
	row := doc["eip2935"].(map[string]any)["84532"]
	return mutation("set_field", "extension", "eip2935.84532", row)
}

func TestBuilderCarriesTheRawDocuments(t *testing.T) {
	_, _, raw := worldJSON(t, sepolia, VariantH0)

	// unmodified: the embedded bytes, the embedded pin (nil), no extension
	in, err := Builder{}.Build(raw, ci.Vector{ID: "VS8-170", Base: "H0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in.ManifestRaw, ci.EmbeddedManifestBytes()) || in.ManifestPin != nil || in.ExtensionRaw != nil {
		t.Fatalf("unmodified: raw %d bytes, pin %v, extension %d bytes", len(in.ManifestRaw), in.ManifestPin, len(in.ExtensionRaw))
	}
	mf, st, err := in.ResolveManifest()
	if err != nil || st != nil || mf.Source != ci.ManifestSourceEmbedded {
		t.Fatalf("resolve: %v %v", st, err)
	}

	// an edited manifest: its own bytes, its own recomputed pin, a valid override
	v := ci.Vector{ID: "VS8-100.edited", Base: "H0", Mutations: []ci.Mutation{mutation("set_field", "manifest", "policy.minimumGovernanceLevel.min", 0)}}
	in, err = Builder{}.Build(raw, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := ci.ManifestHash(in.ManifestRaw)
	if bytes.Equal(in.ManifestRaw, ci.EmbeddedManifestBytes()) || in.ManifestPin == nil || *in.ManifestPin != h {
		t.Fatalf("edited: pin %v, hash of the raw bytes %x", in.ManifestPin, h)
	}
	mf, st, err = in.ResolveManifest()
	if err != nil || st != nil || !strings.HasPrefix(mf.Source, "override:") {
		t.Fatalf("resolve edited: %v %v", st, err)
	}

	// a shadowing extension: Apply does not fail, the refusal is carried and equals what the runner resolves from the raw documents
	v = ci.Vector{ID: "VS8-003.eip2935", Base: "H0", Mutations: []ci.Mutation{shadowMutation(t)}}
	built, err := func() (*Built, error) {
		m, sp, _ := worldJSON(t, sepolia, VariantH0)
		return Apply(m, sp, v.Mutations, nil)
	}()
	if err != nil {
		t.Fatalf("a shadowing extension made Apply fail instead of being the vector's result: %v", err)
	}
	if built.Step0 == nil || built.Step0.Code != ci.CodeManifestShadow || built.ExtensionRaw == nil || !bytes.Equal(built.Inputs.ExtensionRaw, built.ExtensionRaw) {
		t.Fatalf("step 0 %v", built.Step0)
	}
	in, err = Builder{}.Build(raw, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, st, err = in.ResolveManifest()
	if err != nil || st == nil || !bytes.Equal(st.Canonical(), built.Step0.Canonical()) {
		t.Fatalf("the runner resolves %v (%v), the builder carried %v", st, err, built.Step0)
	}
}

// A structurally broken manifest document is a step-0 result too (VS8-001), not a failure to build the vector: its pin is the hash of its own
// bytes, the parse fails and the result is manifest_corrupt. (A one-byte alteration that keeps the document valid JSON of the right shape but
// leaves the pin stale cannot be expressed by the closed mutation vocabulary: the pin of an edited manifest is always recomputed, FORMAT.md.)
func TestVS8_001_BrokenManifestIsAResultThroughRunSet(t *testing.T) {
	_, _, raw := worldJSON(t, sepolia, VariantH0)
	reached := false
	ver := ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
		reached = true
		return ci.Report{}, errors.New("the verifier must not be reached")
	})
	for name, mu := range map[string]ci.Mutation{
		"schema":      mutation("set_field", "manifest", "schema", "other"),
		"chains gone": mutation("unset_field", "manifest", "chains", nil),
	} {
		v := ci.Vector{ID: "VS8-001.x", Base: "H0", Mutations: []ci.Mutation{mu}, Expected: refusedExpected(ci.CodeManifestCorrupt, `{}`)}
		in, err := Builder{}.Build(raw, v, nil)
		if err != nil {
			t.Fatalf("%s: Build fails instead of carrying the broken document: %v", name, err)
		}
		if _, st, rerr := in.ResolveManifest(); rerr != nil || st == nil || st.Code != ci.CodeManifestCorrupt {
			t.Fatalf("%s: resolve -> %v, %v", name, st, rerr)
		}
		res := ci.RunSet(&ci.VectorSet{Vectors: []ci.Vector{v}, World: raw}, Builder{}, ver)
		if len(res) != 1 || res[0].Outcome != ci.OutcomePass || reached {
			t.Fatalf("%s: %+v (verifier reached: %v)", name, res, reached)
		}
	}
}

func refusedExpected(code, fields string) ci.Expected {
	return ci.Expected{Headline: ci.HeadlineRefused, States: []ci.ExpectedState{{Part: "first", Code: code, Fields: json.RawMessage(fields)}}}
}

// VS8-003 through RunSet with the world builder: the verifier is never reached and the shadow refusal is the result.
func TestVS8_003_ShadowIsAResultThroughRunSet(t *testing.T) {
	_, _, raw := worldJSON(t, sepolia, VariantH0)
	v := ci.Vector{ID: "VS8-003.eip2935", Base: "H0", Mutations: []ci.Mutation{shadowMutation(t)},
		Expected: refusedExpected(ci.CodeManifestShadow, `{"table":"eip2935","key":"84532"}`)}
	reached := false
	ver := ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
		reached = true
		return ci.Report{}, errors.New("the verifier must not be reached")
	})
	set := &ci.VectorSet{Vectors: []ci.Vector{v}, World: raw}
	res := ci.RunSet(set, Builder{}, ver)
	if len(res) != 1 || res[0].Outcome != ci.OutcomePass || reached {
		t.Fatalf("%+v (verifier reached: %v)", res, reached)
	}
	// the same vector with the wrong expectation fails: the result is judged, not assumed
	v.Expected = refusedExpected(ci.CodeManifestShadow, `{"table":"eip2935","key":"2017"}`)
	if res = ci.RunSet(&ci.VectorSet{Vectors: []ci.Vector{v}, World: raw}, Builder{}, ver); res[0].Outcome != ci.OutcomeFail {
		t.Fatalf("a wrong expectation passed: %+v", res)
	}
}

// ---- WriteSet writes the materialised files (C2) ----

func okReport() ci.Report {
	parts := make([]ci.PartResult, len(ci.JudgedParts))
	for i, p := range ci.JudgedParts {
		parts[i] = ci.PartResult{Part: p, Status: ci.StatusVerified}
	}
	h, err := ci.ComputeHeadline(ci.HeadlineInput{Parts: parts, StateRootAuthenticated: true, LevelReached: "finalized", JudgedAtLevel: "finalized", RegistryLink: "via S9"})
	if err != nil {
		panic(err)
	}
	return ci.Report{Headline: h}
}

// effectivePin is the pin the manifest bytes are loaded against: the embedded one when none is given.
func effectivePin(p *[32]byte) [32]byte {
	if p == nil {
		return ci.ManifestHash(ci.EmbeddedManifestBytes())
	}
	return *p
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestWriteSetMaterialisesEveryVector(t *testing.T) {
	m, sp, _ := worldJSON(t, sepolia, VariantH0)
	off := 0
	vecs := []ci.Vector{
		{ID: "VS8-170", Base: "H0", Expected: ci.Expected{Headline: ci.HeadlineVerified}},
		{ID: "VS8-012.flip", Base: "H0", Mutations: []ci.Mutation{{Op: "set_byte", Target: "container", Offset: &off, Value: json.RawMessage(`"ff"`)}}, Expected: ci.Expected{Headline: ci.HeadlineVerified}},
		// a mutation that is NOT idempotent: applying it twice would give a different container
		{ID: "VS8-012.append", Base: "H0", Mutations: []ci.Mutation{{Op: "append_hex", Target: "container", Value: json.RawMessage(`"00"`)}}, Expected: ci.Expected{Headline: ci.HeadlineVerified}},
		{ID: "VS8-003.eip2935", Base: "H0", Mutations: []ci.Mutation{shadowMutation(t)}, Expected: refusedExpected(ci.CodeManifestShadow, `{"table":"eip2935","key":"84532"}`)},
		{ID: "VS8-100.edited", Base: "H0", Mutations: []ci.Mutation{mutation("set_field", "manifest", "policy.minimumGovernanceLevel.min", 0)}, Expected: ci.Expected{Headline: ci.HeadlineVerified}},
		{ID: "VS8-102.hops_base", Base: "H0", Mutations: []ci.Mutation{Set("chain", 84532), Set("variant", "hops")}, Expected: ci.Expected{Headline: ci.HeadlineVerified}},
	}
	dir := filepath.Join(t.TempDir(), "worldmat1")
	if err := WriteSet(dir, sp, vecs); err != nil {
		t.Fatal(err)
	}
	manifestText, err := os.ReadFile(filepath.Join(dir, "MANIFEST"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(manifestText)), "\n") {
		listed[strings.SplitN(l, "  ", 2)[1]] = true
	}
	for _, v := range vecs {
		for _, suffix := range []string{".json", ".inputs.json", ".expected.json", ".container.hex"} {
			if !listed[v.ID+suffix] {
				t.Errorf("MANIFEST does not list %s%s", v.ID, suffix)
			}
		}
	}
	if !listed["world.json"] || !listed["manifest."+sha(ci.EmbeddedManifestBytes())+".json"] {
		t.Errorf("MANIFEST lacks world.json or the embedded manifest document: %v", listed)
	}

	// loaded: every vector is materialised; the runner needs NO world builder
	set, err := ci.LoadVectorSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) != len(vecs) || len(set.Inputs) != len(vecs) {
		t.Fatalf("loaded %d vectors, %d inputs", len(set.Vectors), len(set.Inputs))
	}
	// the materialised inputs equal what Apply builds from the same world: no mutation was applied twice
	for _, v := range vecs {
		sp2, err := Generate(m, sepolia, VariantH0)
		if err != nil {
			t.Fatal(err)
		}
		want, err := Apply(m, sp2, v.Mutations, nil)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		got := set.Inputs[v.ID]
		if !bytes.Equal(got.Container, want.Inputs.Container) || !bytes.Equal(got.ManifestRaw, want.ManifestRaw) || !bytes.Equal(got.ExtensionRaw, want.ExtensionRaw) {
			t.Errorf("%s: materialised inputs differ from Apply", v.ID)
		}
		if effectivePin(got.ManifestPin) != effectivePin(want.ManifestPin) {
			t.Errorf("%s: pin differs", v.ID)
		}
	}
	appendIn, flipIn, baseIn := set.Inputs["VS8-012.append"].Container, set.Inputs["VS8-012.flip"].Container, set.Inputs["VS8-170"].Container
	if !bytes.Equal(appendIn, append(append([]byte(nil), baseIn...), 0)) || flipIn[0] != 0xff || bytes.Equal(flipIn, baseIn) {
		t.Error("the container mutations are not applied exactly once")
	}

	// run with a nil world builder: the shadow vector is a step 0 result, the others reach the verifier with exactly the materialised bytes
	var seen [][]byte
	ver := ci.VerifierFunc(func(c ci.LegContext, container []byte, mf *ci.Manifest) (ci.Report, error) {
		seen = append(seen, append([]byte(nil), container...))
		return okReport(), nil
	})
	for _, r := range ci.RunSet(set, nil, ver) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	if len(seen) != len(vecs)-1 {
		t.Errorf("the verifier was reached %d times, want %d (the shadow vector is a step 0 result)", len(seen), len(vecs)-1)
	}

	// deterministic: a second write of the same input is byte-identical
	dir2 := filepath.Join(t.TempDir(), "worldmat2")
	if err := WriteSet(dir2, sp, vecs); err != nil {
		t.Fatal(err)
	}
	m2, err := os.ReadFile(filepath.Join(dir2, "MANIFEST"))
	if err != nil || !bytes.Equal(manifestText, m2) {
		t.Fatalf("a second write differs: %v", err)
	}
}

func TestWriteSetWritesNothingWhenAVectorCannotBeBuilt(t *testing.T) {
	_, sp, _ := worldJSON(t, sepolia, VariantH0)
	dir := filepath.Join(t.TempDir(), "worldmat3")
	vecs := []ci.Vector{
		{ID: "VS8-170", Base: "H0", Expected: ci.Expected{Headline: ci.HeadlineVerified}},
		{ID: "VS8-171", Base: "H0", Mutations: []ci.Mutation{Set("stations.settle.nope", 1)}, Expected: ci.Expected{Headline: ci.HeadlineVerified}},
	}
	err := WriteSet(dir, sp, vecs)
	if err == nil || !strings.Contains(err.Error(), "VS8-171") {
		t.Fatalf("error %v", err)
	}
	if _, serr := os.Stat(dir); !os.IsNotExist(serr) {
		t.Fatalf("a partial set was left behind: %v", serr)
	}
}

// The H0 containers are UNCHANGED by the world fix: the sha256 values recorded before the change.
func TestH0ContainerHashesAreUnchangedByTheWorldFix(t *testing.T) {
	m := manifest(t)
	for variant, want := range map[string]string{
		VariantH0:   "a3b70595c56ff2bd2ed180d20a8ebc8ba85bf8da70f609061073d44b274f3664",
		VariantHops: "e4db02eee5f7d88778c3d3ca05e8d8e237876516f5e3eba056cdcc5fbccb68f4",
	} {
		sp, err := Generate(m, sepolia, variant)
		if err != nil {
			t.Fatal(err)
		}
		w, err := Derive(m, sp)
		if err != nil {
			t.Fatal(err)
		}
		built, err := Apply(m, sp, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha(w.ContainerBytes); got != want || sha(built.Inputs.Container) != want {
			t.Errorf("%s: container sha256 %s (Apply %s), want %s", variant, got, sha(built.Inputs.Container), want)
		}
	}
}
