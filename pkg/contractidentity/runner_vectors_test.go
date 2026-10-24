// Copyright 2026 Certen Protocol

package contractidentity

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// materialisedVector writes one vector (id, inputs, expected) into the file map of a set: its <id>.json and the materialised files.
func materialisedVector(t *testing.T, files map[string]string, id string, in Inputs, exp Expected) {
	t.Helper()
	vj, err := json.MarshalIndent(Vector{ID: id, Base: "H0", Mutations: []Mutation{}, Expected: exp}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	files[id+".json"] = string(vj) + "\n"
	mf, err := Materialise(id, in, exp)
	if err != nil {
		t.Fatal(err)
	}
	for n, b := range mf {
		files[n] = string(b)
	}
}

func firstState(code string, fields string) Expected {
	return Expected{Headline: HeadlineRefused, States: []ExpectedState{{Part: "first", Code: code, Fields: json.RawMessage(fields)}}}
}

// recordingVerifier performs the chain lookup of step 0 and reports verified; it counts its calls and records the manifest sources it saw.
type recordingVerifier struct {
	calls   int
	sources []string
}

func (r *recordingVerifier) Verify(ctx LegContext, container []byte, m *Manifest) (Report, error) {
	r.calls++
	r.sources = append(r.sources, m.Source)
	if _, err := m.Chain(ctx.Chain); err != nil {
		st, _ := AsState(err)
		h, herr := ComputeHeadline(HeadlineInput{Framework: st})
		return Report{Headline: h}, herr
	}
	h, err := ComputeHeadline(verifiedInput())
	return Report{Headline: h}, err
}

// VS8-001..004 end to end through RunSet on a set of MATERIALISED vectors (no world builder): a corrupt manifest and a shadowing extension
// are the RESULT of the vector (the Verifier is never reached), an accepted extension reaches the Verifier with its manifest_source.
func TestVS8_001_004_ThroughRunSet(t *testing.T) {
	raw := EmbeddedManifestBytes()
	altered := append([]byte(nil), raw...)
	altered[len(altered)/2] ^= 0x01
	ctx := validContext()
	cont, err := Encode(g1Container(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	base := Inputs{Ctx: ctx, Container: cont, ManifestRaw: raw}
	with := func(f func(in *Inputs)) Inputs {
		in := base
		f(&in)
		return in
	}
	appendRoot := marshal(t, map[string]any{"schema": ManifestSchema, "policy": map[string]any{"setRootHistory": []any{map[string]any{"chainId": 11155111, "root": "0x" + strings.Repeat("ab", 32), "validFromBlock": 99999999, "validToBlock": nil, "thresholdNumerator": 2, "thresholdDenominator": 3}}}})
	shadow := marshal(t, map[string]any{"schema": ManifestSchema, "policy": map[string]any{"blsThreshold": map[string]any{"numerator": 1, "denominator": 2}}})
	overrideDoc := primaryDoc(t)
	overrideDoc["description"] = "a modified but self-consistent manifest"
	overrideRaw := marshal(t, overrideDoc)
	overridePin := ManifestHash(overrideRaw)

	files := map[string]string{"world.json": "{}\n"}
	materialisedVector(t, files, "VS8-001", with(func(in *Inputs) { in.ManifestRaw = altered }), firstState(CodeManifestCorrupt, `{}`))
	materialisedVector(t, files, "VS8-002", with(func(in *Inputs) { in.Ctx.Chain = 5 }), firstState(CodeManifestUnknown, `{"chain":"5"}`))
	materialisedVector(t, files, "VS8-003.blsThreshold", with(func(in *Inputs) { in.ExtensionRaw = shadow }), firstState(CodeManifestShadow, `{"table":"policy","key":"blsThreshold"}`))
	materialisedVector(t, files, "VS8-004.append_setroot", with(func(in *Inputs) { in.ExtensionRaw = appendRoot }), Expected{Headline: HeadlineVerified})
	materialisedVector(t, files, "VS8-004.new_chain", with(func(in *Inputs) { in.Ctx.Chain = 31337; in.ExtensionRaw = newChainExtension(t, nil) }), Expected{Headline: HeadlineVerified})
	materialisedVector(t, files, "VS8-004.new_chain_incomplete", with(func(in *Inputs) {
		in.Ctx.Chain = 31337
		in.ExtensionRaw = newChainExtension(t, func(e map[string]any) { delete(e, "eip2935") })
	}), firstState(CodeManifestUnknown, `{"chain":"31337"}`))
	materialisedVector(t, files, "VS8-004.override", with(func(in *Inputs) { in.ManifestRaw, in.ManifestPin = overrideRaw, &overridePin }), Expected{Headline: HeadlineVerified})
	materialisedVector(t, files, "VS8-004.override_wrong_pin", with(func(in *Inputs) { in.ManifestRaw = overrideRaw }), firstState(CodeManifestCorrupt, `{}`))

	set, err := LoadVectorSet(writeSet(t, files))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Vectors) != 8 || len(set.Inputs) != 8 {
		t.Fatalf("vectors %d inputs %d", len(set.Vectors), len(set.Inputs))
	}
	rec := &recordingVerifier{}
	for _, r := range RunSet(set, nil, rec) { // nil world builder: the materialised inputs are all a runner needs
		if r.Outcome != OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	// the Verifier was reached exactly for the four vectors whose manifest resolved: new_chain, append_setroot, override, VS8-002 (unknown
	// chain is the verifier's lookup); the four others are refused while the manifest or the extension is resolved
	if rec.calls != 4 {
		t.Errorf("the verifier was reached %d times (%v), expected 4", rec.calls, rec.sources)
	}
	var ext, ovr, emb int
	for _, s := range rec.sources {
		switch {
		case strings.HasPrefix(s, "extension:"):
			ext++
		case strings.HasPrefix(s, "override:"):
			ovr++
		case s == ManifestSourceEmbedded:
			emb++
		}
	}
	if ext != 2 || ovr != 1 || emb != 1 {
		t.Errorf("manifest sources seen: extension %d override %d embedded %d (%v)", ext, ovr, emb, rec.sources)
	}
	// a wrong expectation fails: the same set with a verifier that refuses everything
	refuser := VerifierFunc(func(LegContext, []byte, *Manifest) (Report, error) {
		h, err := ComputeHeadline(HeadlineInput{Framework: ManifestCorrupt()})
		return Report{Headline: h}, err
	})
	passes := 0
	for _, r := range RunSet(set, nil, refuser) {
		if r.Outcome == OutcomePass {
			passes++
		}
	}
	if passes != 4 { // the four vectors whose result is a step 0 refusal do not depend on the verifier
		t.Errorf("passes with a refusing verifier: %d, expected 4", passes)
	}
	// without a verifier nothing runs, even a step 0 result
	for _, r := range RunSet(set, nil, nil) {
		if r.Outcome != OutcomeNotRun {
			t.Errorf("%s ran without a verifier: %s", r.ID, r.Outcome)
		}
	}
}

func TestMaterialisedSetLoaderRefusals(t *testing.T) {
	raw := EmbeddedManifestBytes()
	cont, _ := Encode(g1Container(), DefaultLimits())
	files := map[string]string{"world.json": "{}\n"}
	materialisedVector(t, files, "VS8-010", Inputs{Ctx: validContext(), Container: cont, ManifestRaw: raw}, Expected{Headline: HeadlineVerified})
	if _, err := LoadVectorSet(writeSet(t, files)); err != nil {
		t.Fatalf("good materialised set: %v", err)
	}
	cp := func() map[string]string {
		m := map[string]string{}
		for k, v := range files {
			m[k] = v
		}
		return m
	}
	var manifestName, inputsName string
	for n := range files {
		if strings.HasPrefix(n, "manifest.") {
			manifestName = n
		}
		if strings.HasSuffix(n, ".inputs.json") {
			inputsName = n
		}
	}
	bad := map[string]func(m map[string]string){
		"inputs without a vector file":     func(m map[string]string) { delete(m, "VS8-010.json") },
		"expected without inputs":          func(m map[string]string) { delete(m, inputsName) },
		"expected differs from the vector": func(m map[string]string) { m["VS8-010.expected.json"] = `{"headline":"refused"}` },
		"manifest file named by a wrong hash": func(m map[string]string) {
			m["manifest."+strings.Repeat("0", 64)+".json"] = m[manifestName]
			delete(m, manifestName)
		},
		"manifest file missing":  func(m map[string]string) { delete(m, manifestName) },
		"container file altered": func(m map[string]string) { m["VS8-010.inputs.container.hex"] = "00\n" },
		"unknown member in inputs": func(m map[string]string) {
			m[inputsName] = strings.Replace(m[inputsName], `"format"`, `"extra": 1, "format"`, 1)
		},
		"wrong inputs format": func(m map[string]string) {
			m[inputsName] = strings.Replace(m[inputsName], InputsFormat, "certen-contract-identity-inputs/2", 1)
		},
		"context chain not decimal": func(m map[string]string) {
			m[inputsName] = strings.Replace(m[inputsName], `"chain": "11155111"`, `"chain": "0x01"`, 1)
		},
	}
	for name, f := range bad {
		m := cp()
		f(m)
		if _, err := LoadVectorSet(writeSet(t, m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a vector without raw manifest bytes cannot be materialised
	if _, err := Materialise("VS8-010", Inputs{Ctx: validContext()}, Expected{Headline: HeadlineVerified}); err == nil {
		t.Error("materialised without the manifest document")
	}
	// the container hex is the full container
	if got := files["VS8-010.inputs.container.hex"]; strings.TrimSpace(got) != hex.EncodeToString(cont) {
		t.Errorf("container.hex %s", got)
	}
}

// The context survives the file form exactly (the TypeScript runner reads the same JSON).
func TestContextFileRoundTrip(t *testing.T) {
	c := validContext()
	c.Registry9 = &Registry9{Members: []RegistryMember{{Power: 5, BLSKey: strings.Repeat("0f", 96)}}, Num: 2, Den: 3, CertenSetRoot: bytes32(7), SignerCommitment: bytes32(8)}
	c.S6Status, c.S6Reason, c.S6State = S6NotProven, "", "replay_slot_unavailable"
	f, err := ContextToFile(c)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(f)
	back, err := ContextFromFile(f)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := ContextToFile(back)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(f2)
	if string(b1) != string(b2) {
		t.Fatalf("context changed through its file form\n%s\n%s", b1, b2)
	}
	if back.Chain != c.Chain || back.ADIURL != c.ADIURL || back.S6Status != S6NotProven || back.Batch != c.Batch || back.Registry9.Members[0].Power != 5 || back.Tx.Hash() != c.Tx.Hash() {
		t.Fatalf("context members differ: %+v", back)
	}
	if err := back.ValidateContext(); err != nil {
		t.Fatalf("the round-tripped context is not complete: %v", err)
	}
}
