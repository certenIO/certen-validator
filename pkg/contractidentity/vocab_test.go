// Copyright 2026 Certen Protocol

package contractidentity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

func mustVocab(t *testing.T) *Vocabulary {
	t.Helper()
	v, err := DefaultVocabulary()
	if err != nil {
		t.Fatalf("embedded vocabulary: %v", err)
	}
	return v
}

func TestVocabularyEmbedLoads(t *testing.T) {
	v := mustVocab(t)
	if len(v.Sets) != 38 {
		t.Fatalf("vocab has %d sets, the frozen Item 4 (r3.3) yields 38", len(v.Sets))
	}
	if Check("part_malformed", PartNodes) != true || Check("no_such_set", "x") {
		t.Fatal("package Check misbehaves")
	}
}

// vocab.json and the generated constants list the same values for every enumerated set.
func TestGeneratedVocabEqualsJSON(t *testing.T) {
	v := mustVocab(t)
	for id, want := range generatedVocab {
		if got := v.Values(id); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("set %s: json %v, constants %v", id, got, want)
		}
	}
	for _, id := range v.Names() {
		if len(v.Sets[id].Values) > 0 && generatedVocab[id] == nil {
			t.Errorf("set %s has values but no generated constants", id)
		}
	}
}

// specItem4 returns the cells of the Item 4 table keyed by the name column, tags stripped.
func specItem4(t *testing.T) map[string]string {
	t.Helper()
	spec := specText(t)
	lines := strings.Split(spec, "\n")
	out := map[string]string{}
	in := false
	for _, l := range lines {
		if strings.HasPrefix(l, "### Item 4 - closed vocabularies") {
			in = true
			continue
		}
		if in && strings.HasPrefix(l, "### Item 5") {
			break
		}
		if in && strings.HasPrefix(l, "| ") {
			parts := strings.SplitN(strings.TrimSuffix(strings.TrimPrefix(l, "| "), " |"), " | ", 2)
			if len(parts) == 2 && parts[0] != "name" && !strings.HasPrefix(parts[0], "---") {
				out[strings.TrimSpace(tagRe.ReplaceAllString(parts[0], ""))] = strings.TrimSpace(tagRe.ReplaceAllString(parts[1], ""))
			}
		}
	}
	return out
}

func csv(cell string) []string {
	var out []string
	for _, p := range strings.Split(cell, ",") {
		p = strings.Trim(strings.TrimSpace(p), "`")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Every row of Item 4 of the frozen specification is a vocabulary of vocab.json, with exactly its values; the test re-parses the table
// independently of the lifting script.
func TestVocabularyEqualsSpecItem4(t *testing.T) {
	v := mustVocab(t)
	cells := specItem4(t)
	plain := map[string]string{
		"part (malformed / too_large)":         "part_malformed",
		"malformed reason":                     "malformed_reason",
		"block_mismatch field":                 "block_mismatch_field",
		"judged part (part table)":             "judged_part",
		"record_inconsistent field":            "record_inconsistent_field",
		"account_not_canonical reason":         "account_not_canonical_reason",
		"s6_link_mismatch field":               "s6_link_mismatch_field",
		"authorization_mismatch field":         "authorization_mismatch_field",
		"build_without_writer_proof condition": "build_without_writer_proof_condition",
		"registry_mismatch field":              "registry_mismatch_field",
		"authority_level_invalid field":        "authority_level_invalid_field",
		"attest_mismatch field":                "attest_mismatch_field",
		"at":                                   "at",
		"generation kind":                      "generation_kind",
		"settlement_path_unsupported reason":   "settlement_path_unsupported_reason",
		"authority_level_unproven reason":      "authority_level_unproven_reason",
		"attest_calldata_undecodable reason":   "attest_calldata_undecodable_reason",
		"authority source":                     "authority_source",
		"open kind":                            "open_kind",
		"alert field":                          "alert_field",
		"rule id":                              "rule_id",
		"settlement rule id":                   "settlement_rule_id",
		"residual id":                          "residual_id",
		"headline":                             "headline",
		"Stated reason (builders)":             "stated_reason_builders",
	}
	seen := map[string]bool{}
	for name, id := range plain {
		cell, ok := cells[name]
		if !ok {
			t.Fatalf("Item 4 has no row %q", name)
		}
		if got, want := strings.Join(v.Values(id), ","), strings.Join(csv(cell), ","); got != want {
			t.Errorf("%s: json [%s] spec [%s]", name, got, want)
		}
		seen[name] = true
	}
	// rows with a structure of their own
	special := map[string]func(cell string){
		"unproven part": func(cell string) {
			want := append(append([]string(nil), v.Values("judged_part")...), "settle", "attest", "all")
			if got := v.Values("unproven_part"); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("unproven_part %v, want %v", got, want)
			}
			if !strings.Contains(cell, "the judged parts of the part table, plus `settle`") {
				t.Errorf("unproven part cell changed: %s", cell)
			}
		},
		"header_unlinked link / reason": func(cell string) {
			parts := strings.Split(cell, " / ")
			if strings.Join(v.Values("header_unlinked_link"), ",") != strings.Join(csv(parts[0]), ",") || strings.Join(v.Values("header_unlinked_reason"), ",") != strings.Join(csv(parts[1]), ",") {
				t.Errorf("header_unlinked sets differ from %s", cell)
			}
		},
		"proof_invalid root": func(cell string) {
			if !Check("proof_invalid_root", "hop:12") || Check("proof_invalid_root", "hop:") || strings.Join(v.Values("proof_invalid_root"), ",") != "settle,attest_pre,attest_post,attest_tx,attest_receipt" || !strings.HasSuffix(cell, "hop:`<i>`") {
				t.Errorf("proof_invalid_root vs %s", cell)
			}
		},
		"role": func(cell string) {
			head := strings.SplitN(cell, " (", 2)[0]
			if strings.Join(v.Values("role"), ",") != strings.Join(csv(head), ",") {
				t.Errorf("role: %v vs %s", v.Values("role"), head)
			}
		},
		"S6Status / S6Reason / S6State": func(cell string) {
			if strings.Join(v.Values("s6_status"), ",") != "s6_proven,s6_silent,s6_not_proven" || strings.Join(v.Values("s6_reason"), ",") != "unsupported_generation,absent" || !Check("s6_state", "ReplayNotProven") || Check("s6_state", "") {
				t.Errorf("S6 vocabularies vs %s", cell)
			}
		},
		"authority level": func(cell string) {
			want := map[string]int{"NONE": 0, "OPERATOR": 1, "MANAGER": 2, "ADMIN": 3, "ROOT": 4}
			for k, n := range want {
				if got, ok := v.LevelNumber(k); !ok || got != n {
					t.Errorf("level %s = %d,%v", k, got, ok)
				}
			}
			if _, ok := v.LevelNumber("OWNER"); ok || cell != "NONE 0, OPERATOR 1, MANAGER 2, ADMIN 3, ROOT 4" {
				t.Errorf("authority level cell %s", cell)
			}
		},
		"drift / state_changed_in_block field": func(cell string) {
			for _, ok := range []string{"A01", "A21", "V01", "V03", "C01", "A09:0xab", "V02:key"} {
				if !Check("auth_row_field", ok) {
					t.Errorf("%s must be an AUTH row field", ok)
				}
			}
			for _, bad := range []string{"A00", "A22", "V00", "V04", "C02", "B01", "", "a01", "A1", "A01:"} {
				if Check("auth_row_field", bad) {
					t.Errorf("%q must not be an AUTH row field", bad)
				}
			}
			if !strings.Contains(cell, "A01-A21, V01-V03, C01") {
				t.Errorf("cell %s", cell)
			}
		},
		"registry_link value": func(cell string) {
			if strings.Join(v.Values("registry_link_value"), "|") != "via S9|via manifest_history{keys:digest,pkc:exact_set}" || cell != "via S9, via manifest_history{keys:digest,pkc:exact_set}" {
				t.Errorf("registry_link value: %v vs %s", v.Values("registry_link_value"), cell)
			}
		},
		"manifest_source": func(cell string) {
			h := strings.Repeat("a", 64)
			for _, ok := range []string{"embedded", "override:" + h, "extension:" + h} {
				if !Check("manifest_source", ok) {
					t.Errorf("%s must be a manifest_source", ok)
				}
			}
			for _, bad := range []string{"", "override:", "override:" + h[:63], "override:" + strings.ToUpper(h), "extension", "other:" + h} {
				if Check("manifest_source", bad) {
					t.Errorf("%q must not be a manifest_source", bad)
				}
			}
		},
		"tx type text": func(cell string) {
			for _, ok := range []string{"0x00", "0x02", "0x7e", "0xff"} {
				if !Check("tx_type_text", ok) {
					t.Errorf("%s must be a tx type", ok)
				}
			}
			for _, bad := range []string{"0x2", "2", "0X02", "0x0G", "0x002", ""} {
				if Check("tx_type_text", bad) {
					t.Errorf("%q must not be a tx type", bad)
				}
			}
		},
	}
	for name, fn := range special {
		cell, ok := cells[name]
		if !ok {
			t.Fatalf("Item 4 has no row %q", name)
		}
		fn(cell)
		seen[name] = true
	}
	// no Item 4 row without a check above, no vocabulary without an Item 4 row
	var unseen []string
	for name := range cells {
		if !seen[name] {
			unseen = append(unseen, name)
		}
	}
	sort.Strings(unseen)
	if len(unseen) > 0 {
		t.Fatalf("Item 4 rows with no test: %v", unseen)
	}
	if len(cells) != 35 {
		t.Fatalf("Item 4 has %d rows, the frozen spec (r3.3) has 35", len(cells))
	}
}

func TestCheckIsClosed(t *testing.T) {
	v := mustVocab(t)
	for _, id := range v.Names() {
		s := v.Sets[id]
		for _, val := range s.Values {
			if !v.Check(id, val) {
				t.Errorf("%s: its own value %q is refused", id, val)
			}
			if val != "" && v.Check(id, val+"x") && len(s.Patterns) == 0 {
				t.Errorf("%s: %q is accepted but is not a value", id, val+"x")
			}
		}
		if len(s.Patterns) == 0 && s.Free == "" && v.Check(id, "not-a-value") {
			t.Errorf("%s accepts a value outside its list", id)
		}
		if v.Check(id, "") && s.Free == "" {
			t.Errorf("%s accepts the empty string", id)
		}
	}
	if v.Check("no_such_set", "x") || v.Check("", "") {
		t.Error("an unknown vocabulary accepts a value")
	}
}

// Every binding names a field that a registry row has; a bound field refuses a value outside its vocabulary and accepts every member.
func TestBoundFieldsEnforceTheirVocabulary(t *testing.T) {
	g := mustRegistry(t)
	v := mustVocab(t)
	for key, setID := range v.Bindings {
		codeField, rowName, _ := strings.Cut(key, "@")
		code, field, _ := strings.Cut(codeField, ".")
		var tried int
		for i := range g.Rows {
			r := &g.Rows[i]
			if r.Code != Prefix+code || !r.fieldSet[field] || (rowName != "" && r.Row != rowName) {
				continue
			}
			reason := ""
			if r.ReasonSet != "" {
				for _, rs := range v.Values(r.ReasonSet) {
					if field == "reason" || contains(r.Variants[rs], field) {
						reason = rs
						break
					}
				}
			}
			fields, _ := validFields(t, v, r, reason)
			if _, bound := fields[field]; !bound && !(field == "reason" || field == "part") {
				continue // an optional field not part of this variant
			}
			fields[field] = "bogus-value"
			if _, err := g.New(r.Code, r.Row, fields); err == nil {
				t.Errorf("binding %s: %s|%s accepted a value outside %s", key, r.Code, r.Row, setID)
			}
			// the members of the set are accepted (the first few are enough: the set itself is tested exhaustively above)
			if field == "reason" && r.ReasonSet != "" {
				tried++
				continue // a family reason fixes the other required fields; the walk test constructs every member
			}
			s := v.Sets[setID]
			members := s.Values
			if len(members) > 3 {
				members = members[:3]
			}
			for _, m := range members {
				fields[field] = m
				if _, err := g.New(r.Code, r.Row, fields); err != nil {
					if field == "part" && r.Part != "" || field == "reason" && r.Reason != "" && r.ReasonSet == "" {
						continue // the row fixes this discriminant
					}
					t.Errorf("binding %s: %s|%s refused the member %q: %v", key, r.Code, r.Row, m, err)
				}
			}
			tried++
		}
		if tried == 0 {
			t.Errorf("binding %s matched no registry row/field", key)
		}
	}
}

// names_gen.go holds exactly the registry codes, the registry row cells and the vocabulary values (and nothing else) as string constants:
// a hand edit of a generated constant, or a constant left behind, is caught here.
func TestGeneratedConstantsAreTheTables(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "names_gen.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for _, val := range vs.Values {
				lit, ok := val.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("constant %v is not a string literal", vs.Names)
				}
				have[strings.Trim(lit.Value, `"`)] = true
			}
		}
	}
	want := map[string]bool{SpecSHA256: true}
	g := mustRegistry(t)
	for _, c := range g.Codes() {
		want[c] = true
	}
	for _, r := range g.Rows {
		if r.Row != "-" && r.Row != "(wrapper)" {
			want[r.Row] = true
		}
	}
	v := mustVocab(t)
	for _, id := range v.Names() {
		for _, val := range v.Sets[id].Values {
			want[val] = true
		}
	}
	for x := range want {
		if !have[x] {
			t.Errorf("table value %q has no constant in names_gen.go", x)
		}
	}
	for x := range have {
		if !want[x] {
			t.Errorf("names_gen.go has a constant %q that is in no table", x)
		}
	}
}
