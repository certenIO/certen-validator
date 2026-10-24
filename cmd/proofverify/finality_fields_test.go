// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-DBFIX D2 (V2_SPEC_S7 section 6): `proofverify --offline` prints, per leg and per VERIFIED level, the level's judged-at
// facts - the canonical Verdict.Fields of the kind (L1 slot, finalized_exec_number, a_number, k_number, confirmation_tx, ...) -
// next to the level's status, so a reader of the report sees what the level was judged at and not only that it was.
func TestPrintReportShowsTheJudgedAtFieldsOfEveryVerifiedLevelOfTheRealVectors(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range e2eLegs(t) {
		l := l
		t.Run(l.name, func(t *testing.T) {
			s := settlementOf(t, l)
			var id [16]byte
			u := uuid.New()
			copy(id[:], u[:])
			a, err := finality.NewAddendum(finality.LegBindingOf(s.Block()), id, nil, l.chain, l.level, l.kind, l.evidence)
			if err != nil {
				t.Fatal(err)
			}
			reg := finality.NewRegistry()
			if err := l.register(reg); err != nil {
				t.Fatal(err)
			}
			rep := reg.Verify(l.chain, s.Included, s.Block(), []finality.Addendum{a}, l.pins)
			st := rep.Levels[l.level]
			if st.Status != finality.StatusVerified || st.Verdict == nil || len(st.Verdict.Fields) == 0 {
				t.Fatalf("level %s of the vector is not verified with fields: %+v", l.level, st)
			}
			var out bytes.Buffer
			if code := printReport(&out, rep, "leg"); code != exitVerified {
				t.Fatalf("exit %d\n%s", code, out.String())
			}
			printed := map[string]string{}
			prefix := "  S7      " + l.level.String() + "."
			for _, line := range strings.Split(out.String(), "\n") {
				if rest, ok := strings.CutPrefix(line, prefix); ok {
					k, v, found := strings.Cut(rest, " = ")
					if !found {
						t.Fatalf("a judged-at line without a value: %q", line)
					}
					printed[k] = v
				}
			}
			var want []string
			for k, v := range st.Verdict.Fields {
				want = append(want, k)
				if got := printed[k]; got != canonOf(v) {
					t.Errorf("field %s: printed %q, canonical value %q\n%s", k, got, canonOf(v), out.String())
				}
				seen[k] = true
			}
			sort.Strings(want)
			if len(printed) != len(want) {
				t.Errorf("the report prints %d judged-at fields, the verdict has %d (%v)\n%s", len(printed), len(want), want, out.String())
			}
			t.Logf("%s %s judged-at fields: %v", l.name, l.level, want)
			// a level that is not verified prints no judged-at facts: nothing was judged at anything
			for _, other := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
				if other != l.level && strings.Contains(out.String(), "  S7      "+other.String()+".") {
					t.Errorf("the report prints judged-at fields of %s, which is not verified", other)
				}
			}
		})
	}
	t.Logf("judged-at field names over all real vectors: %d", len(seen))
}

// canonOf is the canonical text of a field value as the state registry renders it ("code{key=<value>}").
func canonOf(v any) string {
	return strings.TrimSuffix(strings.TrimPrefix(finality.NewState("x", "k", v).Error(), "x{k="), "}")
}
