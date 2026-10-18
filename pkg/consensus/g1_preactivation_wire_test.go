package consensus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-K defect 1, at the wire. The v14 binary decoded a ValidatorBlock into structs that do not have evidence 2.1's members, so a 2.0
// document that carries a key named like one of them was decoded whatever the key's JSON type ({"votes": 5} decoded without error), and
// CheckTx, ProcessProposal and FinalizeBlock decided the block as if the key were absent. This binary decoded the whole struct and failed
// the decode (CheckTx and FinalizeBlock code 1, ProcessProposal REJECT) where v14 did not. The raw JSON of each class below is run through
// every decode site (abci_validator.go CheckTx, ProcessProposal, processValidatorTransaction) and the decision is required to be the
// decision on the same block without the member; the decode of every class was measured at v14 (checkins/RB9-K.md: the detached worktree
// at d20f693 decodes every class and accepts it).

// wireFixture is the production 2.0 certificate block of the stored fixture, signed, and an app holding the registry and the spine.
type wireFixture struct {
	app   *ValidatorApp
	store *ledger.LedgerStore
	spine *ledger.AccumulateSpineLog
	block []byte
}

func newWireFixture(t *testing.T) *wireFixture {
	t.Helper()
	f := loadIntentFixtureV3(t)
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, f)
	vb := v3Block(t, f, "validator-1")
	if err := buildV3(t, f, vb, reg, rf, spine, v3Evidence(t, f)); err != nil {
		t.Fatal(err)
	}
	block, err := json.Marshal(vb)
	if err != nil {
		t.Fatal(err)
	}
	app, store := rotationApp(t, newRotationFixture())
	app.cometChainID = intentChain
	r := *reg
	r.Height = 10
	if err := store.SaveBLSRegistry(&ledger.BLSRegistryLog{Versions: []ledger.BLSRegistryRecord{r}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAccumulateSpine(spine); err != nil {
		t.Fatal(err)
	}
	return &wireFixture{app: app, store: store, spine: spine, block: block}
}

func (w *wireFixture) activate(t *testing.T) {
	t.Helper()
	if err := w.store.SaveG1Activation(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{*g1Active}}); err != nil {
		t.Fatal(err)
	}
}

// decisions are the three decode sites' results for tx, as comparable strings.
func (w *wireFixture) decisions(t *testing.T, tx []byte) (check, proposal, finalize string) {
	t.Helper()
	cr, err := w.app.CheckTx(context.Background(), &abcitypes.RequestCheckTx{Tx: tx})
	if err != nil {
		t.Fatal(err)
	}
	pr, err := w.app.ProcessProposal(context.Background(), &abcitypes.RequestProcessProposal{Txs: [][]byte{tx}})
	if err != nil {
		t.Fatal(err)
	}
	w.app.currentBlockHeight, w.app.blockRulesV15Verdict = 12, false
	fr := w.app.processValidatorTransaction(tx)
	return fmt.Sprintf("%d %s", cr.Code, cr.Log), pr.Status.String(), fmt.Sprintf("%d %s", fr.Code, fr.Log)
}

func TestWireA20DocumentWithAWronglyTypedEvidence21MemberIsDecidedAsV14Did(t *testing.T) {
	w := newWireFixture(t)
	wantCheck, wantProposal, wantFinalize := w.decisions(t, w.block)
	t.Logf("control (no member): CheckTx %q, ProcessProposal %s, FinalizeBlock %q", wantCheck, wantProposal, wantFinalize)
	for _, c := range []string{wantCheck, wantFinalize} {
		if strings.HasPrefix(c, "1 ") {
			t.Fatalf("the control block does not decode: %s", c)
		}
	}
	// Measured at v14 (d20f693) for the same bytes: CheckTx 2 and FinalizeBlock 2 (the fixture block fails the invariants), ProcessProposal ACCEPT.
	if !strings.HasPrefix(wantCheck, "2 ") || !strings.HasPrefix(wantFinalize, "2 ") {
		t.Fatalf("the control block is decided differently from v14 (CheckTx 2, FinalizeBlock 2): %.80s / %.80s", wantCheck, wantFinalize)
	}
	if wantProposal != abcitypes.ResponseProcessProposal_ACCEPT.String() {
		t.Fatalf("the control block is not accepted by ProcessProposal: %s", wantProposal)
	}
	for _, member := range wireMembers {
		for _, value := range wireValues {
			tx := injectWire(t, w.block, member, value)
			check, proposal, fin := w.decisions(t, tx)
			if check != wantCheck {
				t.Errorf("%s = %s: CheckTx %q; v14 ignored the key and decided as without it: %q", member, value, check, wantCheck)
			}
			if proposal != wantProposal {
				t.Errorf("%s = %s: ProcessProposal %s; v14 decided %s", member, value, proposal, wantProposal)
			}
			if fin != wantFinalize {
				t.Errorf("%s = %s: FinalizeBlock %q; v14 decided %q", member, value, fin, wantFinalize)
			}
		}
	}
}

// The certificate judgement FinalizeBlock reaches after the decode (processValidatorTransaction: json.Unmarshal into a ValidatorBlock, then
// judgeIntentCertificate): before the activation every class is accepted with no v15 verdict, as v14 accepted it; from the height after
// the activation a 2.0 document is refused by name, whatever the member.
func TestWireA20DocumentWithAWronglyTypedMemberIsJudgedAsV14DidAndRefusedAfterTheActivation(t *testing.T) {
	w := newWireFixture(t)
	decode := func(member, value string) *ValidatorBlock {
		var vb ValidatorBlock
		if err := json.Unmarshal(injectWire(t, w.block, member, value), &vb); err != nil {
			t.Fatalf("%s = %s: the block does not decode (v14 decoded it): %v", member, value, err)
		}
		return &vb
	}
	for _, member := range wireMembers {
		for _, value := range wireValues {
			vb := decode(member, value)
			w.app.currentBlockHeight, w.app.blockRulesV15Verdict = 12, false
			if res := w.app.judgeIntentCertificate(vb); res != nil {
				t.Errorf("%s = %s, no activation: result code %d (%s); v14 accepted the same bytes", member, value, res.Code, res.Log)
			}
			if w.app.blockRulesV15Verdict {
				t.Errorf("%s = %s: a block v14 accepted was counted a v15 verdict", member, value)
			}
		}
	}
	w.activate(t)
	for _, member := range wireMembers {
		for _, value := range wireValues {
			vb := decode(member, value)
			w.app.currentBlockHeight, w.app.blockRulesV15Verdict = 13, false
			res := w.app.judgeIntentCertificate(vb)
			if res == nil || res.Code != codeIntentCertificateRefused || !strings.Contains(res.Log, ErrIntentProofV21Missing.Error()) {
				t.Errorf("%s = %s, activation in force: %+v; want code %d with %v", member, value, res, codeIntentCertificateRefused, ErrIntentProofV21Missing)
			}
			if !w.app.blockRulesV15Verdict {
				t.Errorf("%s = %s: the refusal only v15 reaches was not counted a v15 verdict", member, value)
			}
		}
	}
	vb := decode("votes", `5`)
	if _, _, err := judgeProofV2(vb.IntentCertificate, nil, nil, nil, [32]byte{}, [32]byte{}, [32]byte{}, w.spine, g1Active, nil); !errors.Is(err, ErrIntentProofV21Missing) {
		t.Fatalf("a 2.0 document under the activation: %v", err)
	}
}

// A document that claims 2.1 is decoded completely, so a wrongly typed 2.1 member fails the decode (it is a 2.1 document and must be
// well formed); a wrongly typed version fails it as it failed in v14; a wrongly typed member v14 did have fails it as in v14.
func TestWireDecodeFailuresThatRemainFailures(t *testing.T) {
	w := newWireFixture(t)
	as21 := func(member, value string) []byte {
		return injectWire(t, injectWire(t, w.block, "version", `"2.1"`), member, value)
	}
	for name, tx := range map[string][]byte{
		"a 2.1 document with votes = 5":                   as21("votes", `5`),
		"a 2.1 document with a page's roles = true":       as21("pages[*].roles", `true`),
		"a 2.1 document with check.routing = 5":           as21("check.routing", `5`),
		"a wrongly typed version (number)":                injectWire(t, w.block, "version", `2.1`),
		"a wrongly typed version (object) with votes = 5": injectWire(t, injectWire(t, w.block, "version", `{}`), "votes", `5`),
		"a 2.0 document whose majors (a v14 member) = x":  injectWire(t, w.block, "majors", `"x"`),
	} {
		check, proposal, fin := w.decisions(t, tx)
		if !strings.HasPrefix(check, "1 ") || proposal != abcitypes.ResponseProcessProposal_REJECT.String() || !strings.HasPrefix(fin, "1 ") {
			t.Errorf("%s: CheckTx %q, ProcessProposal %s, FinalizeBlock %q; want code 1 / REJECT / code 1 (the decode fails)", name, check, proposal, fin)
		}
	}
}

// The decode path's own guard (the reflection guard of Evidence20View, extended): the structs the certified decode uses for a document that
// does not claim 2.1 are, field by field and tag by tag, the independent copy of v14's structs in g1_preactivation_doc_test.go, and the
// fields they have are exactly the lists Evidence20View keeps. A member added to Evidence, SetCheck or PageState is therefore ignored by the
// decode (it is in neither v14 struct) until it is classified in the doc test's lists and, if v14 had it, added to the structs.
func TestCertifiedEvidenceDecodeShapeIsV14(t *testing.T) {
	var same func(path string, a, b reflect.Type)
	same = func(path string, a, b reflect.Type) {
		if a == b {
			return
		}
		if a.Kind() != b.Kind() {
			t.Errorf("%s: %s is not %s", path, a, b)
			return
		}
		switch a.Kind() {
		case reflect.Struct:
			if a.NumField() != b.NumField() {
				t.Errorf("%s: %d fields, v14 had %d", path, a.NumField(), b.NumField())
				return
			}
			for i := 0; i < a.NumField(); i++ {
				fa, fb := a.Field(i), b.Field(i)
				if fa.Name != fb.Name || fa.Tag != fb.Tag {
					t.Errorf("%s: field %s `%s`, v14 had %s `%s`", path, fa.Name, fa.Tag, fb.Name, fb.Tag)
					continue
				}
				same(path+"."+fa.Name, fa.Type, fb.Type)
			}
		case reflect.Slice, reflect.Ptr:
			same(path+"[]", a.Elem(), b.Elem())
		default:
			t.Errorf("%s: %s is not %s", path, a, b)
		}
	}
	same("EvidenceV14", reflect.TypeOf(proofv2.EvidenceV14{}), reflect.TypeOf(evidenceV14{}))

	// And the lists Evidence20View keeps are exactly those structs' fields.
	for _, c := range []struct {
		name string
		typ  reflect.Type
		kept []string
	}{{"Evidence", reflect.TypeOf(proofv2.EvidenceV14{}), evidenceKept}, {"SetCheck", reflect.TypeOf(proofv2.SetCheckV14{}), setCheckKept},
		{"PageState", reflect.TypeOf(proofv2.PageStateV14{}), pageStateKept}} {
		var got []string
		for i := 0; i < c.typ.NumField(); i++ {
			got = append(got, c.typ.Field(i).Name)
		}
		sort.Strings(got)
		want := append([]string(nil), c.kept...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: the certified decode's fields %v, Evidence20View keeps %v", c.name, got, want)
		}
	}
}

// For a document that claims 2.0 and carries a member of every kind evidence 2.1 defines, in its own type, the certified decode is the
// evidence 2.0 view of the full decode: the two ways of reaching the document v14 saw agree (and the view stays the in-memory form).
func TestCertifiedEvidenceDecodeEqualsTheViewOfTheFullDecode(t *testing.T) {
	f := loadIntentFixtureV3(t)
	raw, err := json.Marshal(populated21(t, f))
	if err != nil {
		t.Fatal(err)
	}
	full := new(proofv2.Evidence)
	if err := json.Unmarshal(raw, full); err != nil {
		t.Fatal(err)
	}
	got, err := proofv2.UnmarshalCertifiedEvidence(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(Evidence20View(full))
	if string(a) != string(b) {
		t.Fatalf("the certified decode of a 2.0 document with 2.1 members differs from the view of its full decode.\n got %.300s\nwant %.300s", a, b)
	}
	if got.Votes != nil || got.Anchors != nil || got.Transaction != "" || got.Check.Routing != nil || got.Pages[0].Partition != "" || got.Pages[0].Roles != nil || got.Pages[0].History != nil {
		t.Fatal("the certified decode of a 2.0 document kept an evidence 2.1 member")
	}
	// The same bytes claiming 2.1 are decoded completely.
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	m["version"] = json.RawMessage(`"2.1"`)
	raw21, _ := json.Marshal(m)
	d21, err := proofv2.UnmarshalCertifiedEvidence(raw21)
	if err != nil || len(d21.Votes) == 0 || d21.Transaction == "" || d21.Check.Routing == nil || d21.Pages[0].Partition == "" {
		t.Fatalf("a document that claims 2.1 was not decoded completely: %v", err)
	}
}
