// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ethereum/go-ethereum/crypto"
)

// ---- E-f: the closed Stated reasons are a verifier rule (VS8-024) ----

func TestVS8_024_UnknownStatedReason(t *testing.T) {
	for _, reason := range generatedVocab["stated_reason_builders"] {
		c := g1Container()
		c.Settle.Stated.Reason, c.Attest.Stated.Reason = reason, reason
		if st := c.CheckStatedReasons(); st != nil {
			t.Errorf("builder reason %s refused: %v", reason, st)
		}
	}
	if len(generatedVocab["stated_reason_builders"]) != 6 {
		t.Fatalf("the builder reasons are six: %v", generatedVocab["stated_reason_builders"])
	}
	for _, other := range []string{"some_other_reason", "state_unavailable_", "x", strings.Repeat("a", 64), "unknown"} {
		for _, part := range []string{PartSettle, PartAttest} {
			c := g1Container()
			if part == PartSettle {
				c.Settle.Stated.Reason = other
			} else {
				c.Attest.Stated.Reason = other
			}
			// decode keeps the syntax check only: the container is accepted and canonical ...
			raw, err := Encode(c, DefaultLimits())
			if err != nil {
				t.Fatalf("%s/%s: encode: %v", part, other, err)
			}
			got, err := Decode(raw, DefaultLimits())
			if err != nil {
				t.Fatalf("%s/%s: decode must accept the syntax: %v", part, other, err)
			}
			again, _ := Encode(got, DefaultLimits())
			if !bytes.Equal(again, raw) {
				t.Fatalf("encode(decode(x)) != x")
			}
			// ... and the verifier rule refuses it as evidence_malformed{part,reason:unknown_stated_reason}
			wantState(t, got.CheckStatedReasons(), Malformed(part, MalformedUnknownStatedReason, 0, 0, 0))
			// the framework refusal makes the headline refused whatever the parts say
			h, err := ComputeHeadline(HeadlineInput{Framework: got.CheckStatedReasons()})
			if err != nil || h.Kind != HeadlineRefused || h.First.Fields["reason"] != MalformedUnknownStatedReason {
				t.Fatalf("headline %+v %v", h, err)
			}
		}
	}
	// settle is checked first; captured parts have nothing to check
	c := g1Container()
	c.Settle.Stated.Reason, c.Attest.Stated.Reason = "zzz", "yyy"
	wantState(t, c.CheckStatedReasons(), Malformed(PartSettle, MalformedUnknownStatedReason, 0, 0, 0))
	if st := g2Container().CheckStatedReasons(); st != nil {
		t.Errorf("captured parts refused: %v", st)
	}
}

// ---- E-g: registry9 in the context ----

func TestContextRegistry9(t *testing.T) {
	c := validContext()
	c.Registry9 = &Registry9{Members: []RegistryMember{{Power: 1, BLSKey: strings.Repeat("0f", 96)}}}
	if m := missingOf(t, c); m != nil {
		t.Fatalf("a valid Registry9 is refused: %v", m)
	}
	c.Registry9 = nil
	if m := missingOf(t, c); m != nil {
		t.Fatalf("an absent Registry9 must be legal: %v", m)
	}
	for name, reg := range map[string]*Registry9{
		"no members": {},
		"upper case": {Members: []RegistryMember{{BLSKey: strings.Repeat("0F", 96)}}},
		"0x prefix":  {Members: []RegistryMember{{BLSKey: "0x" + strings.Repeat("0f", 96)}}},
		"191 chars":  {Members: []RegistryMember{{BLSKey: strings.Repeat("0", 191)}}},
		"193 chars":  {Members: []RegistryMember{{BLSKey: strings.Repeat("0", 193)}}},
	} {
		c := validContext()
		c.Registry9 = reg
		if got := missingOf(t, c); len(got) != 1 || got[0] != CtxRegistry9 {
			t.Errorf("%s: missing = %v", name, got)
		}
	}
	// token order: registry9 comes before s7
	c = validContext()
	c.Registry9, c.S7 = &Registry9{}, nil
	if got := missingOf(t, c); strings.Join(got, ",") != "registry9,s7" {
		t.Errorf("missing = %v", got)
	}
	// the chain is part of the token settlement
	c = validContext()
	c.Chain = 0
	if got := missingOf(t, c); strings.Join(got, ",") != CtxSettlement {
		t.Errorf("chain 0: %v", got)
	}
}

// ---- E-j: immutable constants and the creation artifacts ----

func TestImmutableRuleValue(t *testing.T) {
	m := embeddedOK(t)
	for _, key := range []string{"CertenAccountV7_3/r5", "CertenAccountFactoryV11/r5"} {
		b, ok := m.Build(key)
		if !ok {
			t.Fatal(key)
		}
		found := false
		for _, im := range b.Immutables {
			if im.Rule.Kind == "constant" {
				found = true
				if im.Rule.Kind != "constant" || !strings.EqualFold(im.Rule.Value, "0x0000000071727De22E5E9d8BAf0edAc6f37da032") {
					t.Errorf("%s constant rule %+v", key, im.Rule)
				}
			}
		}
		if !found {
			t.Errorf("%s has no constant immutable", key)
		}
	}
	b, _ := m.Build("BLSZKVerifierV2_1/r5")
	if r := b.Immutables[0].Rule; r.Kind != "deployment" || r.Contract != "BLSZKVerifierV2Generated" || r.Value != "" {
		t.Errorf("deployment rule %+v", r)
	}
	// a rule without a value reports none (the spec literal then applies)
	b, _ = m.Build("CertenAnchorV8_2/r5")
	if b.Immutables[0].Rule.Value != "" {
		t.Errorf("chainId rule carries a value %q", b.Immutables[0].Rule.Value)
	}
}

func TestCreationArtifactBytes(t *testing.T) {
	data := []byte("creation-code-bytes")
	k := crypto.Keccak256Hash(data)
	s := sha256.Sum256(data)
	doc := primaryDoc(t)
	doc["creationArtifacts"] = map[string]any{"CertenAccountV7_3/r5": map[string]any{
		"file": "identity-bytecode/CertenAccountV7_3.creation.bin", "bytes": len(data), "keccak256": k.Hex(), "sha256": hex.EncodeToString(s[:]),
	}, "BadPath/r5": map[string]any{"file": "../outside.bin", "bytes": 1, "keccak256": k.Hex(), "sha256": "00"}}
	m := loadFixture(t, doc)
	fsys := fstest.MapFS{"identity-bytecode/CertenAccountV7_3.creation.bin": {Data: data}}
	got, err := m.CreationArtifactBytes("CertenAccountV7_3/r5", fsys)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("%v %q", err, got)
	}
	// absent: no row, no file; mismatched: other bytes, other length; a path outside the directory
	if _, err := m.CreationArtifactBytes("CertenAnchorV8_2/r5", fsys); !errors.Is(err, ErrCreationArtifactAbsent) {
		t.Errorf("no row: %v", err)
	}
	if _, err := m.CreationArtifactBytes("CertenAccountV7_3/r5", fstest.MapFS{}); !errors.Is(err, ErrCreationArtifactAbsent) {
		t.Errorf("no file: %v", err)
	}
	for name, d := range map[string][]byte{"other bytes": []byte("creation-code-byteX"), "shorter": data[:5], "longer": append(append([]byte(nil), data...), 0)} {
		fs2 := fstest.MapFS{"identity-bytecode/CertenAccountV7_3.creation.bin": {Data: d}}
		if _, err := m.CreationArtifactBytes("CertenAccountV7_3/r5", fs2); !errors.Is(err, ErrCreationArtifactMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := m.CreationArtifactBytes("BadPath/r5", fsys); !errors.Is(err, ErrCreationArtifactMismatch) {
		t.Errorf("path outside: %v", err)
	}
	// the embedded directory holds the creation code of all seven pinned builds (MANIFEST-1.2): every row resolves, checked against its row
	emb := embeddedOK(t)
	for _, key := range []string{"BLSZKVerifierV2Generated/r5", "BLSZKVerifierV2Generated/r7", "BLSZKVerifierV2_1/r5", "CertenAccountFactoryV11/r5", "CertenAccountV7_3/r5", "CertenAnchorV8_2/r5", "CertenOutcomeRegistryV1/r5"} {
		row, ok := emb.CreationArtifact(key)
		got, err := emb.EmbeddedCreationArtifactBytes(key)
		if !ok || err != nil || len(got) != row.Bytes || crypto.Keccak256Hash(got).Hex() != row.Keccak256 {
			t.Errorf("embedded %s: %v (%d bytes, row %+v)", key, err, len(got), row)
		}
	}
	// a build without a row is a named error, never empty bytes
	if b, err := emb.EmbeddedCreationArtifactBytes("CertenAccountV7_2/r5"); !errors.Is(err, ErrCreationArtifactAbsent) || b != nil {
		t.Errorf("embedded, no row: %d bytes, %v", len(b), err)
	}
}

// ---- E-e: the extension rule for new chains, generations, retirement ----

// newChainExtension is a complete extension adding chain 31337 modelled on Base Sepolia (84532).
func newChainExtension(t *testing.T, mutate func(ext map[string]any)) []byte {
	t.Helper()
	doc := primaryDoc(t)
	const chain = 31337
	dep := []any{}
	for _, d := range doc["deployments"].([]any) {
		row := d.(map[string]any)
		if n, _ := row["chainId"].(json.Number).Int64(); n == 84532 {
			cp := map[string]any{}
			for k, v := range row {
				cp[k] = v
			}
			cp["chainId"] = chain
			dep = append(dep, cp)
		}
	}
	pol := doc["policy"].(map[string]any)
	owner := []any{}
	for _, o := range pol["owner"].(map[string]any)["84532"].([]any) {
		owner = append(owner, o)
	}
	ext := map[string]any{
		"schema":      ManifestSchema,
		"chains":      []any{map[string]any{"chainId": chain, "name": "Local", "snapshotBlock": 1, "snapshotBlockHash": "0x01"}},
		"eip2935":     map[string]any{"31337": doc["eip2935"].(map[string]any)["84532"]},
		"deployments": dep,
		"policy": map[string]any{
			"txScan": map[string]any{"31337": pol["txScan"].(map[string]any)["84532"]},
			"owner":  map[string]any{"31337": owner},
		},
	}
	if mutate != nil {
		mutate(ext)
	}
	return marshal(t, ext)
}

func TestVS8_004_NewChainExtension(t *testing.T) {
	m := embeddedOK(t)
	merged, err := m.WithExtension(newChainExtension(t, nil))
	if err != nil {
		t.Fatalf("a complete new chain was refused: %v", err)
	}
	if ce, err := merged.Chain(31337); err != nil || ce.Name != "Local" {
		t.Fatalf("chain: %+v %v", ce, err)
	}
	if len(merged.Deployments(31337)) != 5 || len(merged.OwnerRows(31337, "anchor")) != 1 || len(merged.OwnerRows(31337, "verifier")) != 1 {
		t.Fatalf("deployments %d", len(merged.Deployments(31337)))
	}
	if _, ok := merged.EIP2935(31337); !ok {
		t.Error("eip2935 row missing")
	}
	if _, ok := merged.TxScan(31337); !ok {
		t.Error("txScan row missing")
	}
	if !strings.HasPrefix(merged.Source, "extension:") {
		t.Errorf("source %q", merged.Source)
	}
	if _, err := m.Chain(31337); err == nil {
		t.Error("the base manifest gained the chain")
	}
	// each dependent row is required: manifest_unknown{chain}
	incomplete := map[string]func(ext map[string]any){
		"no eip2935": func(e map[string]any) { delete(e, "eip2935") },
		"no txScan":  func(e map[string]any) { delete(e["policy"].(map[string]any), "txScan") },
		"no owner":   func(e map[string]any) { delete(e["policy"].(map[string]any), "owner") },
		"no verifier owner": func(e map[string]any) {
			o := e["policy"].(map[string]any)["owner"].(map[string]any)
			var keep []any
			for _, r := range o["31337"].([]any) {
				if r.(map[string]any)["role"] == "anchor" {
					keep = append(keep, r)
				}
			}
			o["31337"] = keep
		},
		"no deployments": func(e map[string]any) { delete(e, "deployments") },
		"no outcomeRegistry deployment": func(e map[string]any) {
			var keep []any
			for _, r := range e["deployments"].([]any) {
				if r.(map[string]any)["role"] != RoleOutcomeRegistry {
					keep = append(keep, r)
				}
			}
			e["deployments"] = keep
		},
		"a deployment whose build does not exist": func(e map[string]any) {
			e["deployments"].([]any)[0].(map[string]any)["build"] = "NoSuchContract/r5"
		},
	}
	for name, f := range incomplete {
		t.Run(name, func(t *testing.T) {
			_, err := m.WithExtension(newChainExtension(t, f))
			wantState(t, err, ManifestUnknown(31337))
		})
	}
	// a dependent row for a chain that is in neither the base nor the extension's chains
	_, err = m.WithExtension(newChainExtension(t, func(e map[string]any) { delete(e, "chains") }))
	wantState(t, err, ManifestUnknown(31337))
	_, err = m.WithExtension(marshal(t, map[string]any{"schema": ManifestSchema, "eip2935": map[string]any{"99999": primaryDoc(t)["eip2935"].(map[string]any)["84532"]}}))
	wantState(t, err, ManifestUnknown(99999))
	// a txScan row of an EXISTING chain is a shadow, of a new chain it is accepted (above)
	_, err = m.WithExtension(marshal(t, map[string]any{"schema": ManifestSchema, "policy": map[string]any{"txScan": map[string]any{"84532": map[string]any{}}}}))
	wantState(t, err, ManifestShadow("policy.txScan", "84532"))
}

func TestExtensionGenerations(t *testing.T) {
	m := embeddedOK(t)
	n := len(m.Generations())
	mk := func(role, gen, kind, masked string) map[string]any {
		return map[string]any{"role": role, "generation": gen, "pinned": false, "kind": kind, "maskedKeccak": masked, "runtimeBytes": 1, "references": []any{}, "source": "x"}
	}
	h := func(b string) string { return "0x" + strings.Repeat(b, 32) }
	ext := func(rows ...map[string]any) []byte {
		l := make([]any, len(rows))
		for i, r := range rows {
			l[i] = r
		}
		return marshal(t, map[string]any{"schema": ManifestSchema, "generations": l})
	}
	// [r3.2:E-e2] the pair (role, generation) is NOT unique: a catalogued and an observed CertenAccountV7 row and two `unidentified`
	// families are four rows of one extension, accepted because their masked runtime hashes differ
	merged, err := m.WithExtension(ext(
		mk("account", "CertenAccountV7", "catalogued", h("a1")), mk("account", "CertenAccountV7", "observed", h("a2")),
		mk("account", "unidentified", "observed", h("a3")), mk("account", "unidentified", "observed", h("a4"))))
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Generations()) != n+4 || len(m.Generations()) != n {
		t.Fatalf("generations %d (base %d, was %d)", len(merged.Generations()), len(m.Generations()), n)
	}
	for _, c := range []struct{ masked, gen, kind string }{{h("a1"), "CertenAccountV7", GenCatalogued}, {h("a2"), "CertenAccountV7", GenObserved}, {h("a3"), "unidentified", GenObserved}} {
		g, ok := merged.GenerationFor("account", strings.ToUpper(c.masked[:2])+c.masked[2:])
		if !ok || g.Generation != c.gen || g.Kind != c.kind {
			t.Errorf("lookup of %s: %+v %v", c.masked, g, ok)
		}
	}
	if _, ok := merged.GenerationFor("anchor", h("a1")); ok {
		t.Error("a generation was found under another role")
	}
	// the same masked hash in the same role is a shadow whatever the generation name; the key is (role, canonical masked) [r3.6:H14]
	shadow := func(base *Manifest, e []byte, key string) {
		t.Helper()
		_, err := base.WithExtension(e)
		wantState(t, err, ManifestShadow("generations", key))
	}
	shadow(merged, ext(mk("account", "OtherName", "observed", h("a1"))), "account,"+h("a1"))
	_, err = merged.WithExtension(ext(mk("account", "CertenAccountV7", "catalogued", "0x"+strings.Repeat("A3", 32)))) // another spelling is refused as not canonical, not lower-cased into a shadow
	wantManifestCorrupt(t, err, "upper-case spelling of a stored key")
	shadow(m, ext(mk("account", "x", "observed", h("b1")), mk("account", "y", "observed", h("b1"))), "account,"+h("b1")) // inside one extension
	// a row of the BASE manifest cannot be redefined either (rows of the pinned table, every one of them)
	for _, g := range m.Generations() {
		shadow(m, ext(mk(g.Role, "renamed", "observed", g.MaskedKeccak)), g.Role+","+strings.ToLower(g.MaskedKeccak))
	}
	// the same hash in ANOTHER role is a different key and is accepted
	if _, err = merged.WithExtension(ext(mk("factory", "CertenAccountFactoryV8", "catalogued", h("a1")))); err != nil {
		t.Fatalf("another role: %v", err)
	}
	// and a new key is accepted after an earlier extension
	if _, err = merged.WithExtension(ext(mk("account", "CertenAccountV8", "catalogued", h("c1")))); err != nil {
		t.Fatal(err)
	}
}
