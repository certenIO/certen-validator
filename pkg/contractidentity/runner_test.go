// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"errors"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ---- the step table is the specification's step list ----

// The 29 ids of the algorithm are exactly the numbered steps of the specification text (so a re-numbered spec revision fails here).
func TestStepTableEqualsTheSpecificationText(t *testing.T) {
	raw, err := os.ReadFile("testdata/contractidentity/spec/V2_SPEC_S8.r3.2.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	a := strings.Index(text, "## Offline verification algorithm")
	b := strings.Index(text, "\nInterface (Go `pkg/contractidentity`")
	if a < 0 || b < a {
		t.Fatal("the algorithm section was not found in the frozen spec")
	}
	var ids []string
	for _, m := range regexp.MustCompile(`(?m)^(\d+[a-z]?)\. \*\*`).FindAllStringSubmatch(text[a:b], -1) {
		ids = append(ids, m[1])
	}
	var have []string
	for _, id := range SpecOrder {
		have = append(have, string(id))
	}
	if !reflect.DeepEqual(ids, have) {
		t.Fatalf("spec steps %v, SpecOrder %v", ids, have)
	}
	if len(stepTable) != len(SpecOrder) || len(Specs()) != 29 {
		t.Fatalf("step table has %d rows, SpecOrder %d", len(stepTable), len(SpecOrder))
	}
}

func TestStepTable(t *testing.T) {
	seen := map[StepID]bool{}
	for _, s := range stepTable {
		if seen[s.ID] {
			t.Fatalf("step %s twice", s.ID)
		}
		seen[s.ID] = true
		for _, p := range s.Parts {
			if partIndex(p) < 0 {
				t.Errorf("step %s declares unknown part %q", s.ID, p)
			}
		}
	}
	for _, id := range SpecOrder {
		if !seen[id] {
			t.Errorf("SpecOrder names %s, which has no row", id)
		}
	}
	// ownership: 25 registrable steps, split 14 / 4 / 4 / 3, the prelude and 22b belong to the skeleton
	want := map[Owner][]StepID{
		Owner2a:       {Step1c, Step2, Step3, Step4, Step5, Step6, Step7, Step8, Step9, Step10, Step11, Step12, Step13, Step14},
		Owner2b1:      {Step15, Step16, Step17, Step20},
		Owner2b2:      {Step18, Step18b, Step19, Step22},
		Owner2c:       {Step21, Step23, Step24},
		OwnerSkeleton: {Step0, Step1, Step1b, Step22b},
	}
	total := 0
	for o, ids := range want {
		if o == OwnerSkeleton {
			for _, id := range ids {
				if s := stepIndex[id]; s.Owner != OwnerSkeleton || s.Registrable() {
					t.Errorf("step %s must belong to the skeleton", id)
				}
			}
			continue
		}
		total += len(ids)
		if got := OwnedBy(o); !reflect.DeepEqual(got, ids) {
			t.Errorf("package %s owns %v, want %v", o, got, ids)
		}
	}
	if total != 25 || len(RegistrableSteps()) != 25 {
		t.Errorf("registrable steps %d (sum %d), want 25", len(RegistrableSteps()), total)
	}
	// ExecOrder: the 25 registrable steps and 22b, every step after the steps it needs
	pos := map[StepID]int{}
	for i, id := range ExecOrder {
		if _, dup := pos[id]; dup {
			t.Fatalf("ExecOrder repeats %s", id)
		}
		pos[id] = i
	}
	if len(ExecOrder) != 26 {
		t.Fatalf("ExecOrder has %d steps, want 26", len(ExecOrder))
	}
	for _, id := range RegistrableSteps() {
		if _, ok := pos[id]; !ok {
			t.Errorf("ExecOrder lacks %s", id)
		}
	}
	for _, id := range ExecOrder {
		for _, n := range stepIndex[id].Needs {
			if stepIndex[n].Owner == OwnerSkeleton && n != Step22b {
				continue // the prelude ran before every step
			}
			if pos[n] >= pos[id] {
				t.Errorf("step %s needs %s, which executes at %d, not before %d", id, n, pos[n], pos[id])
			}
		}
	}
	// the decisive precedence: rule IB executes before the rules and the owner pin that depend on its verdict
	if !(pos[Step22] < pos[Step19] && pos[Step22] < pos[Step21] && pos[Step18] < pos[Step13] && pos[Step24] < pos[Step23] && pos[Step22b] > pos[Step21]) {
		t.Errorf("ExecOrder does not honour the forward dependencies of the specification: %v", ExecOrder)
	}
	// every judged part has a declared contributor
	for _, p := range JudgedParts {
		found := false
		for _, s := range stepTable {
			found = found || hasString(s.Parts, p)
		}
		if !found {
			t.Errorf("no step declares part %s", p)
		}
	}
}

// ---- Facts: every field is documented once, its writer belongs to the group's package and precedes its readers ----

func TestFactsTable(t *testing.T) {
	fields := map[string]bool{}
	ft := reflect.TypeOf(Facts{})
	for i := 0; i < ft.NumField(); i++ {
		g := ft.Field(i)
		if _, ok := GroupOwner(g.Name); !ok {
			t.Fatalf("Facts.%s has no owner", g.Name)
		}
		if hasUnexported(g.Type) {
			t.Errorf("Facts.%s has unexported fields: the ownership check cannot snapshot them", g.Name)
		}
		for j := 0; j < g.Type.NumField(); j++ {
			fields[g.Name+"."+g.Type.Field(j).Name] = true
		}
	}
	pos := map[StepID]int{}
	for i, id := range ExecOrder {
		pos[id] = i
	}
	documented := map[string]bool{}
	for _, f := range AllFactSpecs() {
		if documented[f.Field] {
			t.Errorf("%s documented twice", f.Field)
		}
		documented[f.Field] = true
		if !fields[f.Field] {
			t.Errorf("%s is documented but is not a Facts field", f.Field)
		}
		group := strings.SplitN(f.Field, ".", 2)[0]
		owner, _ := GroupOwner(group)
		w, ok := stepIndex[f.Writer]
		if !ok || !w.Registrable() {
			t.Errorf("%s: writer %q is not a registrable step", f.Field, f.Writer)
			continue
		}
		if w.Owner != owner {
			t.Errorf("%s: written by step %s of package %s, but group %s belongs to package %s", f.Field, f.Writer, w.Owner, group, owner)
		}
		for _, r := range f.Readers {
			if _, ok := pos[r]; !ok {
				t.Errorf("%s: reader %q is not an executed step", f.Field, r)
			} else if pos[r] <= pos[f.Writer] {
				t.Errorf("%s: reader %s executes before or at its writer %s", f.Field, r, f.Writer)
			}
		}
		if f.Note == "" {
			t.Errorf("%s has no note", f.Field)
		}
	}
	for f := range fields {
		if !documented[f] {
			t.Errorf("Facts field %s is not documented (writer and readers)", f)
		}
	}
}

// ---- helpers: a recording fake for every step ----

func skInputs(t *testing.T) (LegContext, []byte, *Manifest) {
	t.Helper()
	m, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(g1Container(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return validContext(), raw, m
}

func skRegistry9() *Registry9 {
	return &Registry9{Members: []RegistryMember{{Address: common.Address{1}, Power: 1, BLSKey: strings.Repeat("ab", 96)}}, Num: 2, Den: 3}
}

// override edits the output of the default fake of a step (it may replace it entirely) and may write Facts.
type override func(env *Env, out *StepOutput) error

func skFake(rec *[]StepID, id StepID, over override) StepFunc {
	spec := stepIndex[id]
	return func(env *Env) (StepOutput, error) {
		*rec = append(*rec, id)
		var out StepOutput
		for _, p := range spec.Parts {
			out.Parts = append(out.Parts, env.Verified(p))
		}
		switch id {
		case Step4:
			env.Facts.A.StateRootN = bytes32(0x44)
		case Step21:
			env.Facts.C.RegistryLink = "via S9"
		case Step24:
			env.Facts.C.Level = LevelBinding{Authenticated: true, JudgedAtLevel: "finalized"}
		}
		if over != nil {
			if err := over(env, &out); err != nil {
				return StepOutput{}, err
			}
		}
		return out, nil
	}
}

func skRegistry(t *testing.T, over map[StepID]override) (*StepRegistry, *[]StepID) {
	t.Helper()
	rec := &[]StepID{}
	reg := NewStepRegistry()
	for _, id := range RegistrableSteps() {
		if err := reg.Register(id, skFake(rec, id, over[id])); err != nil {
			t.Fatal(err)
		}
	}
	return reg, rec
}

func skRun(t *testing.T, ctx LegContext, raw []byte, m *Manifest, over map[StepID]override) (Report, Trace, []StepID, error) {
	t.Helper()
	reg, rec := skRegistry(t, over)
	v, err := NewVerifier(reg)
	if err != nil {
		t.Fatal(err)
	}
	rep, tr, err := v.VerifyTrace(ctx, raw, m)
	return rep, tr, *rec, err
}

func skPart(t *testing.T, rep Report, part string) PartResult {
	t.Helper()
	for _, p := range rep.Parts {
		if p.Part == part {
			return p
		}
	}
	t.Fatalf("part %s is not in the report", part)
	return PartResult{}
}

func refusedPart(part string) PartResult {
	return PartResult{Part: part, Status: StatusRefused, State: stRefused()}
}
func unprovenPart(part string) PartResult {
	return PartResult{Part: part, Status: StatusUnproven, State: stUnproven()}
}

// ---- NewVerifier / registration ----

func TestNewVerifierRefusesAnIncompleteRegistry(t *testing.T) {
	if _, err := NewVerifier(nil); err == nil {
		t.Fatal("a nil registry built a verifier")
	}
	if _, err := NewVerifier(NewStepRegistry()); err == nil || !strings.Contains(err.Error(), "25 steps") {
		t.Fatalf("an empty registry: %v", err)
	}
	for _, missing := range RegistrableSteps() {
		reg := NewStepRegistry()
		rec := &[]StepID{}
		for _, id := range RegistrableSteps() {
			if id != missing {
				if err := reg.Register(id, skFake(rec, id, nil)); err != nil {
					t.Fatal(err)
				}
			}
		}
		_, err := NewVerifier(reg)
		if err == nil || !strings.Contains(err.Error(), "1 steps have no registered function: "+string(missing)) {
			t.Errorf("without step %s: %v", missing, err)
		}
		if got := reg.Missing(); len(got) != 1 || got[0] != missing {
			t.Errorf("Missing() = %v, want [%s]", got, missing)
		}
		if _, err := RunSteps(&Env{Facts: &Facts{}, Manifest: &Manifest{}}, reg); err == nil {
			t.Errorf("RunSteps accepted a registry without step %s", missing)
		}
	}
	// a complete registry builds, and later registrations cannot change it
	reg, _ := skRegistry(t, nil)
	v, err := NewVerifier(reg)
	if err != nil {
		t.Fatal(err)
	}
	delete(reg.fns, Step5)
	ctx, raw, m := skInputs(t)
	if _, _, err := v.VerifyTrace(ctx, raw, m); err != nil {
		t.Fatalf("a built verifier changed with its registry: %v", err)
	}
}

func TestRegisterRefusesWhatIsNotAStep(t *testing.T) {
	reg := NewStepRegistry()
	fn := func(*Env) (StepOutput, error) { return StepOutput{}, nil }
	for _, id := range []StepID{Step0, Step1, Step1b, Step22b} {
		if err := reg.Register(id, fn); err == nil || !strings.Contains(err.Error(), "skeleton") {
			t.Errorf("the skeleton's step %s was registrable: %v", id, err)
		}
	}
	if err := reg.Register("99", fn); err == nil {
		t.Error("an unknown step id was registrable")
	}
	if err := reg.Register(Step3, nil); err == nil {
		t.Error("a nil function was registrable")
	}
	if err := reg.Register(Step3, fn); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(Step3, fn); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("double registration: %v", err)
	}
	var nilReg *StepRegistry
	if err := nilReg.Register(Step3, fn); err == nil {
		t.Error("a nil registry accepted a step")
	}
	if _, err := BuildRegistry(func(r *StepRegistry) error { return r.Register(Step5, fn) }, nil); err == nil {
		t.Error("a nil registrar was accepted")
	}
	r2, err := BuildRegistry(func(r *StepRegistry) error { return r.Register(Step5, fn) }, func(r *StepRegistry) error { return r.Register(Step6, fn) })
	if err != nil || len(r2.Registered()) != 2 {
		t.Fatalf("BuildRegistry: %v %v", r2.Registered(), err)
	}
}

// ---- order, recording, the verified path ----

func TestRunExecutesEveryStepInOrderAndAssemblesAVerifiedReport(t *testing.T) {
	ctx, raw, m := skInputs(t)
	var traced Trace
	reg, rec := skRegistry(t, nil)
	v, err := NewVerifier(reg, WithTrace(func(tr Trace) { traced = tr }))
	if err != nil {
		t.Fatal(err)
	}
	rawBefore := append([]byte(nil), raw...)
	rep, err := v.Verify(ctx, raw, m)
	if err != nil {
		t.Fatal(err)
	}
	var want []StepID
	for _, id := range ExecOrder {
		if id != Step22b {
			want = append(want, id)
		}
	}
	if !reflect.DeepEqual(*rec, want) {
		t.Fatalf("steps ran as %v, want %v", *rec, want)
	}
	if !reflect.DeepEqual(traced.Executed, ExecOrder) || len(traced.NotRun) != 0 || traced.Halt != nil {
		t.Fatalf("trace %+v", traced)
	}
	if !traced.NodesCheck.Evaluated || traced.NodesCheck.Unreferenced != 0 {
		t.Fatalf("nodes check %+v", traced.NodesCheck)
	}
	if !bytes.Equal(raw, rawBefore) {
		t.Fatal("the verifier mutated the container bytes")
	}
	h := rep.Headline
	if h.Kind != HeadlineVerified || h.JudgedAtLevel != "finalized" || h.StateRoot != bytes32(0x44) || h.Block != leg0.Number || h.RegistryLink != "via S9" {
		t.Fatalf("headline %+v", h)
	}
	if len(rep.Parts) != len(JudgedParts) {
		t.Fatalf("%d parts", len(rep.Parts))
	}
	for _, p := range rep.Parts {
		if p.Status != StatusVerified {
			t.Errorf("part %s is %s", p.Part, p.Status)
		}
	}
	if rep.Chain != chain0 || rep.Block != leg0.Number || rep.BlockHash != leg0.Hash || rep.ManifestSHA256 != m.SHA256 || rep.ManifestSource != m.Source ||
		!rep.StateRootAuthenticated || rep.JudgedAtLevel != "finalized" || !reflect.DeepEqual(rep.Residuals, FixedResiduals()) {
		t.Fatalf("report members %+v", rep)
	}
	if _, err := rep.Canonical(); err != nil {
		t.Fatalf("the report is not canonical: %v", err)
	}
}

// ---- the first failing step of a part decides it; parts are independent ----

func TestFirstFailingStepOfAPartDecidesAndPartsAreIndependent(t *testing.T) {
	ctx, raw, m := skInputs(t)
	over := map[StepID]override{
		// code_identity: step 5 says unproven, step 10 later says refused -> step 5 decides (spec order), step 10's state is only a finding
		Step5: func(env *Env, out *StepOutput) error {
			out.Parts = []PartResult{unprovenPart(JudgedCodeIdentity)}
			return nil
		},
		Step10: func(env *Env, out *StepOutput) error {
			out.Parts = []PartResult{refusedPart(JudgedCodeIdentity)}
			return nil
		},
		// pointer: refused, independent of the others
		Step9: func(env *Env, out *StepOutput) error {
			out.Parts = []PartResult{refusedPart(JudgedPointer)}
			return nil
		},
		// account_provenance: step 6 verified, step 7 unproven, step 8 refused -> step 7 decides
		Step7: func(env *Env, out *StepOutput) error {
			out.Parts = []PartResult{unprovenPart(JudgedAccountProvenance)}
			return nil
		},
		Step8: func(env *Env, out *StepOutput) error {
			out.Parts = []PartResult{refusedPart(JudgedAccountProvenance)}
			return nil
		},
	}
	rep, tr, _, err := skRun(t, ctx, raw, m, over)
	if err != nil {
		t.Fatal(err)
	}
	if p := skPart(t, rep, JudgedCodeIdentity); p.Status != StatusUnproven || p.State.Code != stUnproven().Code {
		t.Errorf("code_identity: %+v", p)
	}
	if p := skPart(t, rep, JudgedAccountProvenance); p.Status != StatusUnproven {
		t.Errorf("account_provenance: %+v", p)
	}
	if p := skPart(t, rep, JudgedPointer); p.Status != StatusRefused {
		t.Errorf("pointer: %+v", p)
	}
	if p := skPart(t, rep, JudgedRecord); p.Status != StatusVerified {
		t.Errorf("record: %+v", p)
	}
	if rep.Headline.Kind != HeadlineRefused || !reflect.DeepEqual(rep.Headline.Parts, []string{JudgedPointer}) || rep.Headline.First.Code != stRefused().Code {
		t.Errorf("headline %+v", rep.Headline)
	}
	var sup []string
	for _, f := range tr.Findings {
		if f.Superseded {
			sup = append(sup, string(f.Step)+"/"+f.Part)
		}
	}
	if !reflect.DeepEqual(sup, []string{"10/code_identity", "8/account_provenance"}) && !reflect.DeepEqual(sup, []string{"8/account_provenance", "10/code_identity"}) {
		t.Errorf("superseded findings %v", sup)
	}
	// the same refusal with the state root NOT authenticated is `pending` with the refusal in findings (n2)
	over[Step24] = func(env *Env, out *StepOutput) error {
		env.Facts.C.Level = LevelBinding{Authenticated: false, JudgedAtLevel: "included", S7FinalizedStatus: "finality_not_final"}
		return nil
	}
	rep, _, _, err = skRun(t, ctx, raw, m, over)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Headline.Kind != HeadlinePending || rep.Headline.LevelReached != "included" || len(rep.Headline.Findings) != 1 || rep.Headline.S7FinalizedStatus != "finality_not_final" {
		t.Errorf("pending headline %+v", rep.Headline)
	}
	if skPart(t, rep, JudgedPointer).Status != StatusRefused || rep.StateRootAuthenticated {
		t.Error("the pending report must still show the part refused")
	}
}

func TestOpenEntriesAttachToTheirPartWhateverItsStatus(t *testing.T) {
	ctx, raw, m := skInputs(t)
	over := map[StepID]override{
		Step13: func(env *Env, out *StepOutput) error {
			e, err := env.Open(JudgedStateAtSettlement, OpenDrift, CodeDrift, "", map[string]any{"field": "A14", "attest": "0x01", "settle": "0x02"})
			out.Open = []OpenEntry{e}
			return err
		},
		Step19: func(env *Env, out *StepOutput) error {
			e, err := env.Open(JudgedAuthorizationAttest, OpenAlert, CodeAlert, "", map[string]any{"field": AlertInnerOuterDiffer, "at": AtAttestPost, "onchain": "1", "want": "2"})
			out.Open = []OpenEntry{e}
			out.RulesJudged = []string{"THRESHOLD-A", "BINDING", "BINDING"}
			return err
		},
	}
	rep, _, _, err := skRun(t, ctx, raw, m, over)
	if err != nil {
		t.Fatal(err)
	}
	s := skPart(t, rep, JudgedStateAtSettlement)
	if s.Status != StatusOpen || len(s.Open) != 1 || s.Open[0].Kind != OpenDrift {
		t.Errorf("state_at_settlement: %+v", s)
	}
	a := skPart(t, rep, JudgedAuthorizationAttest)
	if a.Status != StatusVerified || len(a.Open) != 1 || a.Open[0].Kind != OpenAlert {
		t.Errorf("authorization_attest keeps its status and carries the alert: %+v", a)
	}
	if rep.Headline.Kind != HeadlineVerifiedCore || len(rep.Headline.Open) != 2 || len(rep.OpenEntries()) != 2 {
		t.Errorf("headline %+v", rep.Headline)
	}
	if !reflect.DeepEqual(rep.RulesJudged, []string{"BINDING", "THRESHOLD-A"}) {
		t.Errorf("rules judged %v", rep.RulesJudged)
	}
}

func TestS6NotApplicableIsDecisiveAndLaterContributorsMayBeSilent(t *testing.T) {
	ctx, raw, m := skInputs(t)
	ctx.S6Status, ctx.S6 = S6Silent, nil
	ctx.S6Reason = S6ReasonAbsent
	over := map[StepID]override{
		Step3: func(env *Env, out *StepOutput) error {
			out.Parts = []PartResult{env.Verified(JudgedSettlementPath), env.NotApplicableS6(S6S6Silent)}
			return nil
		},
		Step4: func(env *Env, out *StepOutput) error { out.Parts = nil; return nil },
	}
	rep, _, _, err := skRun(t, ctx, raw, m, over)
	if err != nil {
		t.Fatal(err)
	}
	if p := skPart(t, rep, JudgedS6Link); p.Status != StatusNotApplicable || p.Reason != S6S6Silent {
		t.Errorf("s6_link: %+v", p)
	}
	if rep.Headline.Kind != HeadlineVerified || rep.S6.Status != S6Silent || rep.S6.Reason != S6ReasonAbsent {
		t.Errorf("headline %+v s6 %+v", rep.Headline, rep.S6)
	}
}

func TestCallIntoInfrastructureHaltsTheRun(t *testing.T) {
	ctx, raw, m := skInputs(t)
	infra := stInfra()
	over := map[StepID]override{
		Step3: func(env *Env, out *StepOutput) error {
			out.Parts = nil
			for _, p := range JudgedParts {
				pr := PartResult{Part: p, Status: StatusNotApplicable}
				switch p {
				case JudgedSettlementPath:
					pr.State = infra
				case JudgedS6Link:
					pr.Reason = S6S6Silent
				}
				out.Parts = append(out.Parts, pr)
			}
			out.Halt, out.HaltReason = true, "certen_infrastructure_call"
			return nil
		},
	}
	rep, tr, rec, err := skRun(t, ctx, raw, m, over)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Headline.Kind != HeadlineNotApplicable {
		t.Fatalf("headline %+v", rep.Headline)
	}
	if rec[len(rec)-1] != Step3 || tr.Halt == nil || tr.Halt.Step != Step3 || tr.Halt.Framework {
		t.Fatalf("ran %v halt %+v", rec, tr.Halt)
	}
	if len(tr.NotRun) == 0 || tr.NotRun[0] != Step4 || tr.NodesCheck.Evaluated || !strings.Contains(tr.NodesCheck.Reason, "halted_at_step_3") {
		t.Fatalf("trace %+v", tr)
	}
}

// A framework refusal halts: no later step runs, the refused headline names it first, and the table is not completed.
func TestFrameworkRefusalHaltsAndNamesItFirst(t *testing.T) {
	ctx, raw, m := skInputs(t)
	for name, tc := range map[string]struct {
		step StepID
		st   *StateError
	}{
		"step 2 block mismatch":             {Step2, BlockMismatch("number", uint64(1), uint64(2))},
		"step 1c unknown stated reason":     {Step1c, Malformed(PartSettle, MalformedUnknownStatedReason, 0, 0, 0)},
		"step 15 unknown attest reason":     {Step15, Malformed(PartAttest, MalformedUnknownStatedReason, 0, 0, 0)},
		"step 17 framework late in the run": {Step17, Malformed(PartAttest, MalformedUnknownStatedReason, 0, 0, 0)},
	} {
		tc := tc
		t.Run(name, func(t *testing.T) {
			over := map[StepID]override{tc.step: func(env *Env, out *StepOutput) error { out.Parts, out.Framework = nil, tc.st; return nil }}
			rep, tr, rec, err := skRun(t, ctx, raw, m, over)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Headline.Kind != HeadlineRefused || !bytes.Equal(rep.Headline.First.Canonical(), tc.st.Canonical()) {
				t.Fatalf("headline %+v", rep.Headline)
			}
			if rec[len(rec)-1] != tc.step || tr.Halt == nil || !tr.Halt.Framework || tr.Halt.Step != tc.step {
				t.Fatalf("ran %v halt %+v", rec, tr.Halt)
			}
			if _, err := rep.Canonical(); err != nil {
				t.Fatalf("a framework-refused report is not canonical: %v", err)
			}
		})
	}
}

// ---- implementation defects are errors, never verdicts ----

func TestImplementationDefectsAreErrorsNotVerdicts(t *testing.T) {
	ctx, raw, m := skInputs(t)
	silent := func(env *Env, out *StepOutput) error { out.Parts = nil; return nil }
	cases := []struct {
		name string
		over map[StepID]override
		want string
	}{
		{"declared contributor is silent", map[StepID]override{Step7: silent}, "step 7 ran and did not account for part account_provenance"},
		{"part nobody reports", map[StepID]override{Step13: silent}, "step 13 ran and did not account for part state_at_settlement"},
		{"a halt that leaves parts undecided", map[StepID]override{Step3: func(_ *Env, out *StepOutput) error {
			out.Halt, out.HaltReason = true, "early"
			return nil
		}}, "was not decided by any step"},
		{"step returns an error", map[StepID]override{Step7: func(*Env, *StepOutput) error { return errors.New("boom") }}, "step 7: boom"},
		{"halt without a reason", map[StepID]override{Step7: func(_ *Env, out *StepOutput) error { out.Halt = true; return nil }}, "Halt without HaltReason"},
		{"supersede from a step other than 24", map[StepID]override{Step7: func(_ *Env, out *StepOutput) error { out.Supersede = true; return nil }}, "only step 24 may supersede"},
		{"status open emitted", map[StepID]override{Step13: func(_ *Env, out *StepOutput) error {
			out.Parts = []PartResult{{Part: JudgedStateAtSettlement, Status: StatusOpen}}
			return nil
		}}, "derives it from the Open entries"},
		{"part reported twice", map[StepID]override{Step3: func(env *Env, out *StepOutput) error {
			out.Parts = append(out.Parts, env.Verified(JudgedSettlementPath))
			return nil
		}}, "reported twice"},
		{"unknown part", map[StepID]override{Step3: func(env *Env, out *StepOutput) error {
			out.Parts = append(out.Parts, env.Verified("nonsense"))
			return nil
		}}, "unknown part"},
		{"refused part with an unproven state", map[StepID]override{Step9: func(_ *Env, out *StepOutput) error {
			out.Parts = []PartResult{{Part: JudgedPointer, Status: StatusRefused, State: stUnproven()}}
			return nil
		}}, "refused part pointer carries a U state"},
		{"rule id outside the vocabulary", map[StepID]override{Step19: func(_ *Env, out *StepOutput) error { out.RulesJudged = []string{"NOPE"}; return nil }}, "rule id"},
		{"non-framework state as a framework refusal", map[StepID]override{Step2: func(_ *Env, out *StepOutput) error { out.Framework = stRefused(); return nil }}, "not a framework refusal"},
		{"open entry of the wrong kind", map[StepID]override{Step13: func(_ *Env, out *StepOutput) error {
			out.Open = []OpenEntry{{Part: JudgedStateAtSettlement, Kind: OpenAlert, State: stDrift()}}
			return nil
		}}, "Open entry kind"},
		{"pending without a level", map[StepID]override{
			Step9:  func(_ *Env, out *StepOutput) error { out.Parts = []PartResult{refusedPart(JudgedPointer)}; return nil },
			Step24: func(env *Env, _ *StepOutput) error { env.Facts.C.Level = LevelBinding{}; return nil },
		}, "pending without level_reached"},
		{"verified without a registry link value", map[StepID]override{Step21: func(env *Env, _ *StepOutput) error { env.Facts.C.RegistryLink = ""; return nil }}, "registry_link value"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rep, _, _, err := skRun(t, ctx, raw, m, tc.over)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
			if rep.Headline.Kind != "" || len(rep.Parts) != 0 {
				t.Fatalf("a defect produced a report: %+v", rep.Headline)
			}
		})
	}
	// the typed errors
	_, _, _, err := skRun(t, ctx, raw, m, map[StepID]override{Step7: silent})
	var ue *UndecidedPartError
	if !errors.As(err, &ue) || ue.Step != Step7 || ue.Part != JudgedAccountProvenance {
		t.Errorf("error %#v is not the UndecidedPartError of step 7", err)
	}
}

func TestPanicIsAnErrorAndNeverAReport(t *testing.T) {
	ctx, raw, m := skInputs(t)
	rep, _, rec, err := skRun(t, ctx, raw, m, map[StepID]override{Step5: func(*Env, *StepOutput) error { panic("hostile evidence") }})
	var pe *PanicError
	if !errors.As(err, &pe) || pe.Step != Step5 || pe.Value != "hostile evidence" || pe.Stack == "" {
		t.Fatalf("error %#v", err)
	}
	if rep.Headline.Kind != "" || rec[len(rec)-1] != Step5 {
		t.Fatalf("report %+v after %v", rep.Headline, rec)
	}
}

func TestAStepWritesOnlyItsOwnFactsGroup(t *testing.T) {
	ctx, raw, m := skInputs(t)
	for name, tc := range map[string]struct {
		step  StepID
		write override
		group string
	}{
		"2a writes C": {Step5, func(env *Env, _ *StepOutput) error { env.Facts.C.RegistryLink = "x"; return nil }, "C"},
		"2a appends to B2": {Step5, func(env *Env, _ *StepOutput) error {
			env.Facts.B2.Changed = append(env.Facts.B2.Changed, AuthDiff{Row: "A01"})
			return nil
		}, "B2"},
		"2c writes A": {Step24, func(env *Env, _ *StepOutput) error { env.Facts.A.StateRootN = bytes32(9); return nil }, "A"},
		"2b-1 edits a map": {Step16, func(env *Env, _ *StepOutput) error {
			env.Facts.A.SettleAUTH = map[string]common.Hash{"A01": {}}
			return nil
		}, "A"},
		"2b-2 writes B1":      {Step22, func(env *Env, _ *StepOutput) error { env.Facts.B1.TxIndex = 7; return nil }, "B1"},
		"2b-1 writes C level": {Step20, func(env *Env, _ *StepOutput) error { env.Facts.C.Level.Authenticated = true; return nil }, "C"},
	} {
		tc := tc
		t.Run(name, func(t *testing.T) {
			_, _, _, err := skRun(t, ctx, raw, m, map[StepID]override{tc.step: tc.write})
			var fo *FactsOwnershipError
			if !errors.As(err, &fo) || fo.Step != tc.step || fo.Group != tc.group {
				t.Fatalf("error %#v, want an ownership error of step %s on group %s", err, tc.step, tc.group)
			}
		})
	}
	// writes to its own group, including nested ones, are fine
	own := map[StepID]override{
		Step5: func(env *Env, _ *StepOutput) error {
			env.Facts.A.AccountCode = []byte{1, 2, 3}
			env.Facts.A.SettleAUTH = map[string]common.Hash{"A01": {1}}
			env.Facts.A.SettleAUTH["A02"] = common.Hash{2}
			return nil
		},
		Step18: func(env *Env, _ *StepOutput) error {
			env.Facts.B2.Pre.Words = map[string]common.Hash{"A14": {1}}
			env.Facts.B2.Changed = append(env.Facts.B2.Changed, AuthDiff{Row: "A14"})
			return nil
		},
	}
	if _, _, _, err := skRun(t, ctx, raw, m, own); err != nil {
		t.Fatalf("a write to the owner's own group was refused: %v", err)
	}
	// a nested change of another group's map is seen (deep snapshot)
	over := map[StepID]override{
		Step5: func(env *Env, _ *StepOutput) error {
			env.Facts.A.SettleAUTH = map[string]common.Hash{"A01": {1}}
			return nil
		},
		Step18: func(env *Env, _ *StepOutput) error { env.Facts.A.SettleAUTH["A01"] = common.Hash{9}; return nil },
	}
	_, _, _, err := skRun(t, ctx, raw, m, over)
	var fo *FactsOwnershipError
	if !errors.As(err, &fo) || fo.Step != Step18 || fo.Group != "A" {
		t.Fatalf("a nested write to another group was not seen: %#v", err)
	}
}

// ---- s7_chain_unsupported voids the table (step 24 only) ----

func TestSupersedeVoidsEveryEarlierDecision(t *testing.T) {
	ctx, raw, m := skInputs(t)
	over := map[StepID]override{
		Step9: func(_ *Env, out *StepOutput) error { out.Parts = []PartResult{refusedPart(JudgedPointer)}; return nil },
		Step13: func(env *Env, out *StepOutput) error {
			e, err := env.Open(JudgedStateAtSettlement, OpenDrift, CodeDrift, "", map[string]any{"field": "A14", "attest": "0x01", "settle": "0x02"})
			out.Open = []OpenEntry{e}
			return err
		},
		Step24: func(env *Env, out *StepOutput) error {
			st, err := New(CodeUnproven, RowUnprovenS7ChainUnsupported, map[string]any{"part": UnprovenPartAll, "chain": uint64(11155111)})
			if err != nil {
				return err
			}
			out.Parts = nil
			for _, p := range JudgedParts {
				out.Parts = append(out.Parts, PartResult{Part: p, Status: StatusUnproven, State: st})
			}
			out.Supersede = true
			return nil
		},
	}
	rep, tr, _, err := skRun(t, ctx, raw, m, over)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Headline.Kind != HeadlineUnproven || len(rep.OpenEntries()) != 0 {
		t.Fatalf("headline %+v open %v", rep.Headline, rep.OpenEntries())
	}
	for _, p := range rep.Parts {
		if p.Status != StatusUnproven || p.State.Fields["reason"] != RowUnprovenS7ChainUnsupported {
			t.Errorf("part %s: %+v", p.Part, p)
		}
	}
	found := false
	for _, f := range tr.Findings {
		found = found || (f.Superseded && f.Part == JudgedPointer && f.Step == Step9)
	}
	if !found {
		t.Errorf("the voided refusal is not in the trace: %+v", tr.Findings)
	}
	// a superseding output must carry the whole table
	over[Step24] = func(env *Env, out *StepOutput) error {
		out.Parts, out.Supersede = []PartResult{unprovenPart(JudgedPointer)}, true
		return nil
	}
	if _, _, _, err := skRun(t, ctx, raw, m, over); err == nil || !strings.Contains(err.Error(), "carries all 11 parts") {
		t.Fatalf("partial supersede: %v", err)
	}
}

// ---- step 22b ----

func TestNodeAccounting(t *testing.T) {
	ctx, _, m := skInputs(t)
	raw, err := Encode(g2Container(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	visit := func(skip int) override {
		return func(env *Env, _ *StepOutput) error {
			for i, n := range env.Container.Nodes {
				if i != skip {
					env.Nodes.visited[crypto.Keccak256Hash(n)] = true
				}
			}
			return nil
		}
	}
	// every node visited: verified
	rep, tr, _, err := skRun(t, ctx, raw, m, map[StepID]override{Step5: visit(-1)})
	if err != nil || rep.Headline.Kind != HeadlineVerified || !tr.NodesCheck.Evaluated || tr.NodesCheck.Unreferenced != 0 {
		t.Fatalf("all visited: %v %+v %+v", err, rep.Headline, tr.NodesCheck)
	}
	// one node never visited: evidence_malformed{part:nodes, reason:nodes_unreferenced, index:<first unvisited>}, headline refused
	for _, skip := range []int{0, 1, 2} {
		rep, tr, _, err = skRun(t, ctx, raw, m, map[StepID]override{Step5: visit(skip)})
		want := Malformed(PartNodes, MalformedNodesUnreferenced, skip, 0, 0)
		if err != nil || rep.Headline.Kind != HeadlineRefused || !bytes.Equal(rep.Headline.First.Canonical(), want.Canonical()) {
			t.Fatalf("skip %d: %v %+v", skip, err, rep.Headline)
		}
		if tr.NodesCheck.FirstUnreferenced != skip || tr.NodesCheck.Unreferenced != 1 {
			t.Fatalf("skip %d: %+v", skip, tr.NodesCheck)
		}
		// 22b is a framework refusal but not a halt: the level binding and the report members were still produced
		if tr.Halt != nil || !rep.StateRootAuthenticated || len(rep.Parts) != len(JudgedParts) {
			t.Fatalf("skip %d: halt %+v auth %v parts %d", skip, tr.Halt, rep.StateRootAuthenticated, len(rep.Parts))
		}
	}
	// no node visited at all and every read plan complete: first node unreferenced
	rep, tr, _, err = skRun(t, ctx, raw, m, nil)
	if err != nil || rep.Headline.Kind != HeadlineRefused || tr.NodesCheck.FirstUnreferenced != 0 || tr.NodesCheck.Unreferenced != 3 {
		t.Fatalf("none visited: %v %+v %+v", err, rep.Headline, tr.NodesCheck)
	}
	// an incomplete read plan: not evaluated, NOT refused (nodes_unreferenced is not raised on top of another refusal)
	incomplete := map[StepID]override{Step5: func(_ *Env, out *StepOutput) error { out.ReadPlanIncomplete = "account_absent"; return nil }}
	rep, tr, _, err = skRun(t, ctx, raw, m, incomplete)
	if err != nil || rep.Headline.Kind != HeadlineVerified || tr.NodesCheck.Evaluated || tr.NodesCheck.Reason != "5:account_absent" {
		t.Fatalf("incomplete plan: %v %+v %+v", err, rep.Headline, tr.NodesCheck)
	}
	// a container with no nodes at all is fine (G-S8-1)
	ctx2, raw2, _ := skInputs(t)
	rep, tr, _, err = skRun(t, ctx2, raw2, m, nil)
	if err != nil || !tr.NodesCheck.Evaluated || rep.Headline.Kind != HeadlineVerified {
		t.Fatalf("no nodes: %v %+v", err, tr.NodesCheck)
	}
}

// ---- the prelude: steps 0, 1, 1b, 1c(a) ----

func TestPreludeRefusalsAndOrder(t *testing.T) {
	ctx, raw, m := skInputs(t)
	bad := append([]byte(nil), raw...)
	bad[0] ^= 0xff
	incomplete := ctx
	incomplete.Batch.BatchRoot = [32]byte{}
	unknown := ctx
	unknown.Chain = 999
	noChain := ctx
	noChain.Chain = 0
	badMagic := Malformed(PartMagic, MalformedBadMagic, 0, 0, 0)
	for name, tc := range map[string]struct {
		ctx  LegContext
		raw  []byte
		want *StateError
	}{
		"step 0 unknown chain":                    {unknown, raw, ManifestUnknown(999)},
		"step 0 precedes step 1":                  {unknown, bad, ManifestUnknown(999)},
		"step 1 bad magic":                        {ctx, bad, badMagic},
		"step 1 precedes step 1b":                 {incomplete, bad, badMagic},
		"step 1b incomplete context":              {incomplete, raw, ContextIncomplete([]string{CtxBatchRoot})},
		"step 1b a zero chain is the settlement":  {noChain, raw, ContextIncomplete([]string{CtxSettlement})},
		"step 1b judged even without a container": {incomplete, nil, ContextIncomplete([]string{CtxBatchRoot})},
	} {
		tc := tc
		t.Run(name, func(t *testing.T) {
			rep, tr, rec, err := skRun(t, tc.ctx, tc.raw, m, nil)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Headline.Kind != HeadlineRefused || !bytes.Equal(rep.Headline.First.Canonical(), tc.want.Canonical()) {
				t.Fatalf("headline %+v, want first %s", rep.Headline, tc.want.Canonical())
			}
			if len(rec) != 0 || tr.Halt == nil || !tr.Halt.Framework || len(rep.Parts) != 0 {
				t.Fatalf("steps ran %v, halt %+v, parts %d", rec, tr.Halt, len(rep.Parts))
			}
			if rep.Chain != tc.ctx.Chain || rep.ManifestSHA256 != m.SHA256 {
				t.Fatalf("report members %+v", rep)
			}
		})
	}
}

func TestNoContainerIsUnprovenOnEveryPart(t *testing.T) {
	for name, raw := range map[string][]byte{"nil": nil, "empty": {}} {
		ctx, _, m := skInputs(t)
		rep, tr, rec, err := skRun(t, ctx, raw, m, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rec) != 0 || rep.Headline.Kind != HeadlineUnproven || len(rep.Headline.Parts) != 9 || len(rep.Parts) != len(JudgedParts) {
			t.Fatalf("%s: ran %v headline %+v parts %d", name, rec, rep.Headline, len(rep.Parts))
		}
		for _, p := range rep.Parts {
			if p.Status != StatusUnproven || p.State.Code != CodeUnproven || p.State.Fields["part"] != UnprovenPartAll || p.State.Fields["reason"] != UnprovenNoEvidence {
				t.Errorf("%s: part %s: %+v", name, p.Part, p)
			}
		}
		if tr.NodesCheck.Evaluated || tr.NodesCheck.Reason != UnprovenNoEvidence {
			t.Errorf("%s: nodes check %+v", name, tr.NodesCheck)
		}
		if _, err := rep.Canonical(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// with a Registry9 registry_link is core too
	ctx, _, m := skInputs(t)
	ctx.Registry9 = skRegistry9()
	rep, _, _, err := skRun(t, ctx, nil, m, nil)
	if err != nil || len(rep.Headline.Parts) != 10 {
		t.Fatalf("with registry9: %v %+v", err, rep.Headline)
	}
	// a nil manifest is a defect of the caller
	reg, _ := skRegistry(t, nil)
	v, _ := NewVerifier(reg)
	if _, err := v.Verify(ctx, nil, nil); err == nil {
		t.Error("a nil manifest was accepted")
	}
}

// ---- the Env ----

func TestEnvHelpers(t *testing.T) {
	ctx, raw, m := skInputs(t)
	env, fw, err := Prelude(ctx, raw, m)
	if err != nil || fw != nil {
		t.Fatalf("%v %v", err, fw)
	}
	if env.SettleStated() == nil || env.AttestStated() == nil || env.SettleStated().Reason != "capture_not_attempted_in_window" || env.NoEvidence() || env.Nodes == nil {
		t.Fatalf("stated parts / nodes: %+v", env.Container)
	}
	if env.Leg() != leg0 || env.Chain.ChainID != chain0 || env.Registry9Present() {
		t.Fatalf("leg %+v chain %+v", env.Leg(), env.Chain)
	}
	c := env.Context()
	if c.Chain != chain0 || c.Block != leg0.Number || c.BlockHash != leg0.Hash || c.ManifestSHA256 != m.SHA256 || c.ManifestSource != m.Source {
		t.Fatalf("context %+v", c)
	}
	st := ManifestUnknown(1)
	b, err := env.StateJSON(st)
	if err != nil || !bytes.Contains(b, []byte(`"context"`)) || !bytes.Contains(b, []byte(`"manifest_sha256"`)) {
		t.Fatalf("%s %v", b, err)
	}
	// helpers validate against the registry
	if _, err := env.Refuse(JudgedPointer, "contract_identity_nope", "", nil); err == nil {
		t.Error("an unknown code was raised")
	}
	if _, err := env.Unprove(JudgedPointer, CodeUnproven, RowUnprovenSettlementNotExecuted, map[string]any{"wrong": 1}); err == nil {
		t.Error("an unknown field was raised")
	}
	p, err := env.Refuse(JudgedRecord, CodeRecordNotExecuted, "", map[string]any{"anchorId": bytes32(1), "valid": false, "proofExecuted": false})
	if err != nil || p.Status != StatusRefused || p.State.Code != CodeRecordNotExecuted {
		t.Fatalf("%+v %v", p, err)
	}
	// the header cache returns the same answer, including the same error
	_, e1 := env.Header([]byte{0xc0})
	_, e2 := env.Header([]byte{0xc0})
	if e1 == nil || e1 != e2 {
		t.Errorf("header cache: %v / %v", e1, e2)
	}
	if len(env.headers) != 1 {
		t.Errorf("header cache has %d entries", len(env.headers))
	}
}

// ---- the Report over many part tables: the runner agrees with the independent headline oracle ----

func TestEndToEndHeadlineAgreesWithTheOracle(t *testing.T) {
	// the first declared contributor of each part carries the scripted result; the other contributors say verified
	carrier := map[string]StepID{
		JudgedSettlementPath: Step3, JudgedS6Link: Step4, JudgedCodeIdentity: Step5, JudgedAccountProvenance: Step6, JudgedPointer: Step9,
		JudgedAuthorityLevel: Step14, JudgedRecord: Step11, JudgedAuthorizationAttest: Step16, JudgedIntraBlockWindow: Step22,
		JudgedRegistryLink: Step21, JudgedStateAtSettlement: Step13,
	}
	rng := rand.New(rand.NewSource(8))
	ctx0, raw, m := skInputs(t)
	// 1500 random part tables, then every single-part variation of the all-verified table (each part x each status x registry9 x
	// authenticated x an extra Open entry): the cases where ONE part decides the headline, which random tables almost never isolate
	const randomCombos = 1500
	type single struct {
		part string
		st   PartStatus
	}
	var singles []single
	for _, part := range JudgedParts {
		seen := map[PartStatus]bool{}
		for _, r9 := range []bool{true, false} {
			for _, st := range allowedStatuses(part, r9) {
				if !seen[st] {
					seen[st] = true
					singles = append(singles, single{part, st})
				}
			}
		}
	}
	for i := 0; i < randomCombos+8*len(singles); i++ {
		ctx := ctx0
		var registry9, auth, extra bool
		var parts []PartResult
		if i < randomCombos {
			registry9, auth, extra = rng.Intn(2) == 0, rng.Intn(2) == 0, rng.Intn(4) == 0
			for _, part := range JudgedParts {
				sts := allowedStatuses(part, registry9)
				parts = append(parts, mkPart(part, sts[rng.Intn(len(sts))], extra))
			}
		} else {
			k := i - randomCombos
			flags, sg := k%8, singles[k/8]
			registry9, auth, extra = flags&1 != 0, flags&2 != 0, flags&4 != 0
			allowed := false
			for _, st := range allowedStatuses(sg.part, registry9) {
				allowed = allowed || st == sg.st
			}
			if !allowed {
				continue
			}
			for _, part := range JudgedParts {
				st := StatusVerified
				if part == sg.part {
					st = sg.st
				}
				parts = append(parts, mkPart(part, st, extra))
			}
		}
		if registry9 {
			ctx.Registry9 = skRegistry9()
		}
		if i < randomCombos && rng.Intn(6) == 0 { // the verified/open mix only: no refusals, so that verified and verified_core are exercised
			for k := range parts {
				if parts[k].Status == StatusRefused || parts[k].Status == StatusUnproven {
					parts[k] = mkPart(parts[k].Part, StatusVerified, false)
				}
			}
		}
		over := map[StepID]override{}
		for _, p := range parts {
			p := p
			id := carrier[p.Part]
			prev := over[id]
			over[id] = func(env *Env, out *StepOutput) error {
				if prev != nil {
					if err := prev(env, out); err != nil {
						return err
					}
				}
				for k := range out.Parts {
					if out.Parts[k].Part == p.Part {
						q := p
						q.Open = nil
						if p.Status == StatusOpen {
							q = env.Verified(p.Part)
						}
						out.Parts[k] = q
					}
				}
				out.Open = append(out.Open, p.Open...)
				return nil
			}
		}
		over[Step24] = func(env *Env, _ *StepOutput) error {
			env.Facts.C.Level = LevelBinding{Authenticated: auth, JudgedAtLevel: "finalized"}
			return nil
		}
		rep, _, _, err := skRun(t, ctx, raw, m, over)
		if err != nil {
			t.Fatalf("combo %d: %v", i, err)
		}
		want, refusedN, unprovenN, openN := oracle(parts, registry9, auth, extra)
		if rep.Headline.Kind != want {
			t.Fatalf("combo %d (registry9=%v auth=%v extra=%v): headline %s, oracle %s", i, registry9, auth, extra, rep.Headline.Kind, want)
		}
		_ = refusedN
		_ = unprovenN
		if got := len(rep.OpenEntries()); got != openN {
			t.Fatalf("combo %d: %d Open entries, oracle %d", i, got, openN)
		}
		for _, p := range parts {
			if got := skPart(t, rep, p.Part).Status; got != p.Status {
				t.Fatalf("combo %d: part %s is %s, scripted %s", i, p.Part, got, p.Status)
			}
		}
		if _, err := rep.Canonical(); err != nil {
			t.Fatalf("combo %d: %v", i, err)
		}
	}
}
