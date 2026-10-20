// Copyright 2026 Certen Protocol

package adiri_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// The registry (testdata/finality/states.json, format certen-finality-states/2) is the machine form of V2_SPEC_S7 section 7.
// This file holds the conformance scan the framework runs for its own package, applied to pkg/finality/adiri: every state the
// package can raise is registered with its fields, every `reason` is a member of a CLOSED set, and the vectors pin the token.

type regSpec struct {
	Required            []string            `json:"required"`
	Optional            []string            `json:"optional"`
	Enums               map[string][]string `json:"enums"`
	EnumsDefinedBy      map[string]string   `json:"enums_defined_by"`
	ConditionalRequired []struct {
		When     map[string]string `json:"when"`
		Required []string          `json:"required"`
	} `json:"conditional_required"`
}

type registry struct {
	PendingReasons map[string]struct{ Required []string } `json:"pending_reasons"`
	States         map[string]regSpec                     `json:"states"`
}

func loadReg(t testing.TB) registry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r registry
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// conformsTo is the framework's conforms() for a code and its fields.
func (r registry) conformsTo(code string, fields map[string]any) string {
	spec, ok := r.States[code]
	if !ok {
		return "code " + code + " is not registered"
	}
	required := append([]string(nil), spec.Required...)
	for _, c := range spec.ConditionalRequired {
		hit := true
		for k, v := range c.When {
			if fmt.Sprint(fields[k]) != v {
				hit = false
			}
		}
		if hit {
			required = append(required, c.Required...)
		}
	}
	allowed := map[string]bool{}
	for _, f := range required {
		allowed[f] = true
		if _, has := fields[f]; !has {
			return code + " lacks required field " + f
		}
	}
	for f, set := range spec.Enums {
		if v, has := fields[f]; has {
			found := false
			for _, m := range set {
				found = found || fmt.Sprint(v) == m
			}
			if !found {
				return fmt.Sprintf("%s field %s = %v is not in its closed set %v", code, f, v, set)
			}
		}
	}
	for _, f := range spec.Optional {
		allowed[f] = true
	}
	for f := range fields {
		if !allowed[f] {
			return code + " carries unregistered field " + f
		}
	}
	return ""
}

// Every state a vector expects conforms: registered code, required and conditionally required fields, closed enums, no
// unregistered field. The tokens, not sentences, are what the vectors pin; and every member of the closed check and reason
// sets of the Adiri states is pinned by at least one vector.
func TestEveryExpectedStateConformsToTheRegistry(t *testing.T) {
	reg := loadReg(t)
	f := loadVectors(t)
	codes := map[string]int{}
	pinned := map[string]bool{}
	for _, v := range f.Vectors {
		var e struct {
			Code   string         `json:"code"`
			Fields map[string]any `json:"fields"`
		}
		if err := json.Unmarshal([]byte(v.Expect), &e); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if e.Code == "finalized" {
			continue
		}
		codes[e.Code]++
		if msg := reg.conformsTo(e.Code, e.Fields); msg != "" {
			t.Errorf("%s: %s", v.Name, msg)
		}
		for _, k := range []string{"check", "reason"} {
			if x, ok := e.Fields[k]; ok {
				pinned[e.Code+"/"+k+"/"+fmt.Sprint(x)] = true
			}
		}
	}
	for _, c := range []string{"committee_chain_broken", "evidence_pin_mismatch", "adiri_incarnation_mismatch", "epoch_record_codec_unsupported", "finality_link_broken", "finality_header_chain_broken", "finality_block_mismatch", "finality_evidence_too_large", "finality_evidence_malformed"} {
		if codes[c] == 0 {
			t.Errorf("no vector expects %s", c)
		}
	}
	for _, c := range []struct{ code, field string }{
		{"committee_chain_broken", "check"}, {"committee_chain_broken", "reason"}, {"finality_link_broken", "check"}, {"finality_header_chain_broken", "reason"},
	} {
		for _, m := range reg.States[c.code].Enums[c.field] {
			if !pinned[c.code+"/"+c.field+"/"+m] {
				t.Errorf("no vector pins %s.%s = %s", c.code, c.field, m)
			}
		}
	}
	// the evidence_malformed tokens the Adiri body can raise are pinned (the framework's own tokens have their own vectors)
	for _, m := range []string{"spine_empty", "link_kind_unknown", "link_kind_2_at_seal", "trailing_bytes"} {
		if !pinned["finality_evidence_malformed/reason/"+m] {
			t.Errorf("no vector pins finality_evidence_malformed.reason = %s", m)
		}
	}
}

// The package's typed reason constants are exactly the registry's closed sets (committee_chain_broken.reason is the union of the
// incompatibility and the signature sets), and the constructors yield conforming states.
func TestTheTypedReasonConstantsAreExactlyTheRegistrysClosedSets(t *testing.T) {
	reg := loadReg(t)
	same := func(name string, got []string, want []string) {
		t.Helper()
		sort.Strings(got)
		w := append([]string(nil), want...)
		sort.Strings(w)
		if strings.Join(got, "|") != strings.Join(w, "|") {
			t.Errorf("%s: constants %v, registry %v", name, got, w)
		}
	}
	same("committee_chain_broken.reason", []string{
		string(adiri.ReasonLargerThanExpected), string(adiri.ReasonSetMismatch), string(adiri.ReasonNotSubset), string(adiri.ReasonBelowTwoThirds),
		string(adiri.ReasonBelowMinCommitteeSize), string(adiri.ReasonEncoding), string(adiri.ReasonIdentity), string(adiri.ReasonSubgroup), string(adiri.ReasonPairing),
	}, reg.States["committee_chain_broken"].Enums["reason"])
	same("finality_header_chain_broken.reason", []string{string(adiri.ReasonParentHash), string(adiri.ReasonNumberGap)}, reg.States["finality_header_chain_broken"].Enums["reason"])
	same("finality_source_unavailable.reason", []string{string(adiri.SourceEpochRecord), string(adiri.SourceHeaders), string(adiri.SourceEpochRecordsFail), string(adiri.SourceHistoryProof)},
		reg.States["finality_source_unavailable"].Enums["reason"])
	same("committee_chain_broken.check", []string{adiri.CheckCommitteeIncompatible, adiri.CheckDuplicateKey, adiri.CheckBelowQuorum, adiri.CheckSignerIndexInvalid, adiri.CheckPublicKeyInvalid, adiri.CheckSignatureInvalid},
		reg.States["committee_chain_broken"].Enums["check"])
	same("finality_link_broken.check", []string{adiri.LinkTipNotFinalState, adiri.LinkBlockAfterSeal, adiri.LinkSlotValueMismatch, adiri.LinkCodeHashMismatch, adiri.LinkProofInvalid, adiri.LinkHeaderDecode},
		reg.States["finality_link_broken"].Enums["check"])
	for _, code := range []string{"committee_chain_broken", "finality_header_chain_broken", "finality_source_unavailable"} {
		s := reg.States[code]
		if _, has := s.Enums["reason"]; !has || len(s.EnumsDefinedBy) != 0 {
			t.Errorf("%s: reason needs a closed enum and no enums_defined_by (%v / %v)", code, s.Enums, s.EnumsDefinedBy)
		}
	}
	for _, c := range []struct {
		code string
		st   *finality.StateError
	}{
		{"adiri_incarnation_mismatch", adiri.IncarnationMismatch(adiri.NumHash{}, adiri.NumHash{})},
		{"evidence_pin_mismatch", adiri.PinMismatch("chain_id", uint64(1), uint64(2))},
		{"committee_chain_broken", adiri.ChainBroken(1, adiri.CheckBelowQuorum, "got", uint64(1), "need", uint64(4))},
		{"epoch_record_codec_unsupported", adiri.CodecUnsupported(1, "a", "b")},
		{"finality_link_broken", adiri.LinkBroken(adiri.LinkProofInvalid, 1, 2, 3)},
		{"finality_header_chain_broken", adiri.HeaderChainBroken(1, [32]byte{}, [32]byte{}, adiri.ReasonNumberGap)},
		{"finality_source_unavailable", adiri.SourceUnavailable(adiri.SourceHeaders, []string{"e"}, "block", uint64(5))},
		{"committee_shrunk", adiri.Shrunk(3, 4, 5)},
	} {
		if c.st.Code != c.code {
			t.Errorf("%s: constructor raises %s", c.code, c.st.Code)
		}
		if msg := reg.conformsTo(c.st.Code, c.st.Fields); msg != "" {
			t.Errorf("constructor: %s", msg)
		}
	}
	for _, r := range []string{adiri.PendingEpochOpen, adiri.PendingCertPending, adiri.PendingEpochOverdue, adiri.PendingHistoryProof} {
		if _, ok := reg.PendingReasons[r]; !ok {
			t.Errorf("pending reason %s is not registered", r)
		}
	}
}

// frameworkReasonConsts maps the finality package's typed reason constants (state.go) to their values.
func frameworkReasonConsts(t *testing.T) map[string]string {
	t.Helper()
	af, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "state.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range af.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						out[n.Name], _ = strconv.Unquote(lit.Value)
					}
				}
			}
		}
	}
	return out
}

// The source scan: every reason this package gives a framework constructor is a finality.<Constant> that is a member of its
// state's closed set.
func TestEveryReasonRaisedByThePackageIsAMemberOfItsClosedSet(t *testing.T) {
	reg := loadReg(t)
	fc := frameworkReasonConsts(t)
	ctors := map[string]struct {
		arg  int
		code string
	}{"Malformed": {1, "finality_evidence_malformed"}, "MalformedAt": {2, "finality_evidence_malformed"}, "PinsCorrupt": {0, "finality_pins_corrupt"}}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked, newStates := 0, 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "finality" {
				return true
			}
			if c, ok := ctors[sel.Sel.Name]; ok {
				arg, ok := call.Args[c.arg].(*ast.SelectorExpr)
				if !ok {
					t.Errorf("%s: the reason of finality.%s is not a finality constant", fset.Position(call.Pos()), sel.Sel.Name)
					return true
				}
				val, known := fc[arg.Sel.Name]
				found := false
				for _, m := range reg.States[c.code].Enums["reason"] {
					found = found || m == val
				}
				if !known || !found {
					t.Errorf("%s: finality.%s reason %s (%q) is not in the closed set of %s", fset.Position(call.Pos()), sel.Sel.Name, arg.Sel.Name, val, c.code)
				}
				checked++
			}
			if sel.Sel.Name == "NewState" {
				newStates++
			}
			return true
		})
	}
	if checked < 15 || newStates < 5 {
		t.Fatalf("the scan checked %d constructor reasons and %d NewState calls: it is not seeing the package", checked, newStates)
	}
}

// ParsePins raises registered reasons with the offending key, never a sentence.
func TestParsePinsRaisesRegisteredReasonsWithTheKey(t *testing.T) {
	reg := loadReg(t)
	emb, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	var sec map[string]any
	if err := json.Unmarshal(emb.Sections["adiri"], &sec); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		mut    func(m map[string]any)
		reason string
		key    string
	}{
		"unknown key":      {func(m map[string]any) { m["extra"] = 1 }, "unknown_key", "adiri.extra"},
		"type error":       {func(m map[string]any) { m["chain_id"] = "2017" }, "bad_value", "adiri.chain_id"},
		"short genesis":    {func(m map[string]any) { m["genesis_hash"] = "0x12" }, "bad_value", "adiri.genesis_hash"},
		"short key":        {func(m map[string]any) { m["genesis_committee"] = []any{"abcd"} }, "bad_value", "adiri.genesis_committee"},
		"zero min":         {func(m map[string]any) { m["min_committee_size"] = 0 }, "bad_value", "adiri.min_committee_size"},
		"zero max headers": {func(m map[string]any) { m["max_headers"] = 0 }, "bad_value", "adiri.max_headers"},
		"zero chain":       {func(m map[string]any) { m["chain_id"] = 0 }, "bad_value", "adiri.chain_id"},
		"bad link sha":     {func(m map[string]any) { m["genesis_link_sha256"] = "ab" }, "bad_value", "adiri.genesis_link_sha256"},
	}
	for name, c := range cases {
		raw, _ := json.Marshal(sec)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		c.mut(m)
		raw, _ = json.Marshal(m)
		_, err := adiri.ParsePins(&finality.Pins{Sections: map[string]json.RawMessage{"adiri": raw}})
		s, ok := finality.AsNamed(err)
		if !ok || s.Code != finality.CodePinsCorrupt || fmt.Sprint(s.Fields["reason"]) != c.reason || s.Fields["key"] != c.key {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if msg := reg.conformsTo(s.Code, s.Fields); msg != "" {
			t.Errorf("%s: %s", name, msg)
		}
	}
}

// The superseded vector sets stay byte-identical (their manifests are checked in TestManifestHashesEveryVectorFile);
// finality_adiri3 re-issues every vector of finality_adiri1 and finality_adiri2 with the same name, leg, pins and evidence, and
// changes ONLY the expectation, for exactly two reasons: byte values render as 0x-prefixed hex (framework
// certen-finality-states/2), and four sentence reasons became registered tokens.
func TestAdiri3ReissuesTheSupersededSetsChangingOnlyTheirExpectations(t *testing.T) {
	cur := loadVectors(t)
	byName := map[string]vVec{}
	for _, v := range cur.Vectors {
		byName[v.Name] = v
	}
	hex64 := regexp.MustCompile(`"([0-9a-f]{64})"`)
	tokenFor := map[string][2]string{ // vector -> {old sentence, new token}
		"syn-kind2-leg-is-seal":   {"linkKind 2 is used only when the leg block is below the seal; the seal itself is a single-header spine", "link_kind_2_at_seal"},
		"syn2-empty-spine":        {"a spine holds at least the seal header", "spine_empty"},
		"syn2-link-kind-3":        {"linkKind is 1 (spine) or 2 (history slot)", "link_kind_unknown"},
		"syn2-body-trailing-byte": {"trailing bytes", "trailing_bytes"},
	}
	n, changedTokens := 0, 0
	for _, d := range supersededDirs {
		old := loadSet(t, d)
		for _, ov := range old.Vectors {
			n++
			nv, ok := byName[ov.Name]
			if !ok {
				t.Errorf("%s: %s is not re-issued in finality_adiri3", d, ov.Name)
				continue
			}
			oe, ne := evidenceOf(t, old, ov), evidenceOf(t, cur, nv)
			if string(oe) != string(ne) {
				t.Errorf("%s: evidence differs", ov.Name)
			}
			a, _ := json.Marshal(ov.Leg)
			b, _ := json.Marshal(nv.Leg)
			if string(a) != string(b) || ov.Group != nv.Group || ov.Note != nv.Note {
				t.Errorf("%s: leg, group or note differs", ov.Name)
			}
			var pa, pb any
			_ = json.Unmarshal(ov.Pins, &pa)
			_ = json.Unmarshal(nv.Pins, &pb)
			ja, _ := json.Marshal(pa)
			jb, _ := json.Marshal(pb)
			if string(ja) != string(jb) {
				t.Errorf("%s: pins differ", ov.Name)
			}
			want := hex64.ReplaceAllString(ov.Expect, `"0x$1"`)
			if tok, ok := tokenFor[ov.Name]; ok {
				if !strings.Contains(want, `"`+tok[0]+`"`) {
					t.Errorf("%s: the old expectation lacks the sentence %q", ov.Name, tok[0])
				}
				want = strings.Replace(want, `"`+tok[0]+`"`, `"`+tok[1]+`"`, 1)
				changedTokens++
			}
			if want != nv.Expect {
				t.Errorf("%s: finality_adiri3 expectation is not the superseded one with 0x bytes and tokens:\n old->new %s\n adiri3   %s", ov.Name, want, nv.Expect)
			}
		}
	}
	if n != 49+10 || changedTokens != len(tokenFor) {
		t.Fatalf("%d superseded vectors compared, %d token changes (want 59 and %d)", n, changedTokens, len(tokenFor))
	}
	// the vectors finality_adiri3 adds beyond the two superseded sets: one per closed-set member they did not pin
	extra := map[string]bool{"adv-signature-bad-encoding": true}
	for _, v := range cur.Vectors {
		if !extra[v.Name] {
			continue
		}
		n++
	}
	if len(cur.Vectors) != n {
		t.Fatalf("finality_adiri3 holds %d vectors, the superseded sets plus the %d added ones %d", len(cur.Vectors), len(extra), n)
	}
}
