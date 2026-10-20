package consensus

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-VB defect 2. "Before the activation every block is decided as v14 decided it" was false for one input class: a document that claims
// evidence 2.0 and carries members only evidence 2.1 defines (votes, anchors, a routing proof, a page's partition, roles and history, the
// transaction, a vote's production with its sequenced message). The v14 binary decoded the certificate into structs that do not have those
// fields, so they were dropped and the certificate was judged on what remained (result code 0); this binary decodes them, and the 2.0
// verifier refuses a 2.0 document that carries 2.1 members ("evidence 2.0 carries 2.1 members"), so the same bytes got code 10. Before the
// activation a 2.0 document is judged on its evidence-2.0 view: the same document with every member v14's decode dropped cleared.

// evidenceV14 mirrors proofv2.Evidence, SetCheck and PageState as they are at the rules v14 head d20f693 (pkg/proof/v2/evidence.go,
// page.go): what v14's JSON decode kept of a certificate's proof v2.
type evidenceV14 struct {
	Version string                  `json:"version"`
	Account string                  `json:"account"`
	TxHash  string                  `json:"txHash"`
	Receipt string                  `json:"receipt"`
	Majors  uint64                  `json:"majors"`
	Certify []string                `json:"certify"`
	Anchor  proofv2.PartitionAnchor `json:"anchor"`
	Pages   []pageStateV14          `json:"pages,omitempty"`
	Check   setCheckV14             `json:"check"`
}

type setCheckV14 struct {
	Majors uint64                     `json:"majors"`
	Hops   []string                   `json:"hops"`
	Set    govproof.ValidatorSetProof `json:"set"`
}

type pageStateV14 struct {
	URL         string               `json:"url"`
	State       string               `json:"state"`
	Receipt     string               `json:"receipt"`
	Chains      []govproof.ChainRoot `json:"chains,omitempty"`
	PendingHash string               `json:"pendingHash,omitempty"`
	ChainError  string               `json:"chainError,omitempty"`
}

// populated21 is the production 2.0 document with a member of every kind evidence 2.1 defines, set to a value that is not the zero value.
func populated21(t *testing.T, f *intentFixtureV3) *proofv2.Evidence {
	t.Helper()
	ev := v3Evidence(t, f)
	ev.Anchors = map[string]proofv2.PartitionAnchor{"acc://bvn-BVN1.acme": {Message: "00", Receipt: "00"}}
	ev.Votes = []proofv2.Vote{{Authority: "acc://a.acme/book", Origin: "acc://a.acme/book/1", Vote: "accept", Message: "00",
		Transport: proofv2.VoteTransport{Kind: proofv2.TransportInline}, Receipt: "00",
		Hops:     []proofv2.VoteHop{{Page: "acc://a.acme/book/1", Message: "00", Block: 1}},
		Counted:  []proofv2.VoteHop{{Page: "acc://a.acme/book/1", Message: "01", Block: 2}},
		Produced: &proofv2.Production{Account: "acc://a.acme", Chain: "main", Message: "00", Sequenced: "00"}}}
	ev.Transaction = "00"
	ev.Check.Routing = new(govproof.AccountStateProof)
	for i := range ev.Pages {
		ev.Pages[i].Partition = "acc://bvn-BVN1.acme"
		ev.Pages[i].Roles = []proofv2.PageRole{proofv2.RoleAuthorityPage}
		ev.Pages[i].History = &proofv2.PageHistory{Entries: []proofv2.HistoryEntry{{Transaction: "00"}}}
	}
	return ev
}

// The view is exactly what v14's decode kept: the document with every 2.1 member, marshalled and decoded into v14's structs, is the same
// bytes as the view of that document. The classification test below fails when a field is added to one of these structs without being
// classified, so a new 2.1 member cannot be left out of the view.
func TestEvidence20ViewIsExactlyWhatV14Decoded(t *testing.T) {
	f := loadIntentFixtureV3(t)
	full := populated21(t, f)
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var v14 evidenceV14
	if err := json.Unmarshal(raw, &v14); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(v14)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(Evidence20View(full))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("the evidence 2.0 view of a document with 2.1 members is not what v14's decode kept.\n got %.300s\nwant %.300s", got, want)
	}
	// The view of a clean 2.0 document is that document, and it does not alias or modify the document it was made from.
	clean := v3Evidence(t, f)
	before, _ := json.Marshal(clean)
	view := Evidence20View(clean)
	if after, _ := json.Marshal(view); string(after) != string(before) {
		t.Fatal("the view of a clean 2.0 document differs from the document")
	}
	view.Pages[0].URL = "acc://changed"
	view.Certify[0] = "ff"
	if again, _ := json.Marshal(clean); string(again) != string(before) {
		t.Fatal("the view shares memory with its document")
	}
	if full.Transaction == "" || len(full.Votes) == 0 || full.Pages[0].Partition == "" {
		t.Fatal("making the view modified the document it was made from")
	}
}

// Every field of the three structs is classified: kept by v14 (and so kept by the view) or an evidence 2.1 member (cleared). A field added
// to Evidence, SetCheck or PageState fails this test until it is placed in one list - and, as a 2.1 member, the view clears it.
func TestEveryEvidenceFieldIsClassifiedForThe20View(t *testing.T) {
	names := func(v interface{}) []string {
		var n []string
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			n = append(n, rt.Field(i).Name)
		}
		sort.Strings(n)
		return n
	}
	join := func(a, b []string) []string {
		out := append(append([]string(nil), a...), b...)
		sort.Strings(out)
		return out
	}
	for _, c := range []struct {
		name         string
		fields       []string
		kept, only21 []string
	}{
		{"Evidence", names(proofv2.Evidence{}), names(evidenceV14{}), []string{"Anchors", "GenesisLink", "Links", "Transaction", "Votes"}},
		{"SetCheck", names(proofv2.SetCheck{}), names(setCheckV14{}), []string{"Routing"}},
		{"PageState", names(proofv2.PageState{}), names(pageStateV14{}), []string{"History", "Partition", "Roles"}},
	} {
		if got, want := strings.Join(join(c.kept, c.only21), ","), strings.Join(c.fields, ","); got != want {
			t.Errorf("%s: the v14 fields and the audited evidence 2.1 members are\n  %s\nthe struct has\n  %s\nclassify the new field in Evidence20View (consensus/intent_certificate.go) and here", c.name, got, want)
		}
	}
}

// The pre-activation verdict, through the app's own judgement of a block (the function FinalizeBlock calls): a 2.0 certificate whose
// document carries members of each class evidence 2.1 defines is accepted before the activation, with no v15 verdict recorded, exactly as
// v14 accepted the same bytes (code 0); from the height after the activation it is refused by name as a 2.0 document, as today.
func TestPreActivationA20DocumentWithEvidence21MembersIsJudgedAsV14DidAndRefusedAfter(t *testing.T) {
	f := loadIntentFixtureV3(t)
	rf, reg := intentRegistry(t)
	spine := v3Spine(t, f)

	built := func(inject func(ev *proofv2.Evidence)) *ValidatorBlock {
		vb := v3Block(t, f, "validator-1")
		if err := buildV3(t, f, vb, reg, rf, spine, v3Evidence(t, f)); err != nil {
			t.Fatal(err)
		}
		// The certificate is signed over the root of the 2.0 document; members added to the document afterwards are not part of that root
		// (govRoot v3 commits what the verifier established, not the document's JSON), so the signature is unchanged.
		ev := *vb.IntentCertificate.ProofV2
		ev.Pages = append([]proofv2.PageState(nil), ev.Pages...)
		inject(&ev)
		cert := *vb.IntentCertificate
		cert.ProofV2 = &ev
		vb.IntentCertificate = &cert
		return vb
	}
	classes := map[string]func(ev *proofv2.Evidence){
		"no 2.1 member (the control)": func(ev *proofv2.Evidence) {},
		"votes with hops, counted and a produced block": func(ev *proofv2.Evidence) {
			ev.Votes = populated21(t, f).Votes
		},
		"a vote's production with its sequenced message": func(ev *proofv2.Evidence) {
			ev.Votes = []proofv2.Vote{{Authority: "acc://a.acme/book", Produced: &proofv2.Production{Sequenced: "00"}}}
		},
		"anchors":            func(ev *proofv2.Evidence) { ev.Anchors = populated21(t, f).Anchors },
		"the transaction":    func(ev *proofv2.Evidence) { ev.Transaction = "00" },
		"the routing proof":  func(ev *proofv2.Evidence) { ev.Check.Routing = new(govproof.AccountStateProof) },
		"a page's partition": func(ev *proofv2.Evidence) { ev.Pages[0].Partition = "acc://bvn-BVN1.acme" },
		"a page's roles":     func(ev *proofv2.Evidence) { ev.Pages[1].Roles = []proofv2.PageRole{proofv2.RoleAuthorityPage} },
		"a page's history": func(ev *proofv2.Evidence) {
			ev.Pages[2].History = &proofv2.PageHistory{Entries: []proofv2.HistoryEntry{{Transaction: "00"}}}
		},
		"every member at once": func(ev *proofv2.Evidence) {
			all := populated21(t, f)
			ev.Anchors, ev.Votes, ev.Transaction, ev.Check.Routing = all.Anchors, all.Votes, all.Transaction, all.Check.Routing
			ev.Pages = all.Pages
		},
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

	// No activation: every class is accepted, as v14 accepted it, and nothing is counted a v15 verdict.
	for name, inject := range classes {
		vb := built(inject)
		app.currentBlockHeight, app.blockRulesV15Verdict = 12, false
		if res := app.judgeIntentCertificate(vb); res != nil {
			t.Errorf("%s, no activation: result code %d (%s); v14 accepted the same bytes (code 0)", name, res.Code, res.Log)
		}
		if app.blockRulesV15Verdict {
			t.Errorf("%s: a block v14 accepted was counted a v15 verdict", name)
		}
	}

	// From the height after the activation the same documents are 2.0 documents and are refused by name, as they are today.
	if err := store.SaveG1Activation(&ledger.G1ActivationLog{Activations: []ledger.G1ActivationRecord{*g1Active}}); err != nil {
		t.Fatal(err)
	}
	for name, inject := range classes {
		vb := built(inject)
		app.currentBlockHeight, app.blockRulesV15Verdict = 13, false
		res := app.judgeIntentCertificate(vb)
		if res == nil || res.Code != codeIntentCertificateRefused || !strings.Contains(res.Log, ErrIntentProofV21Missing.Error()) {
			t.Errorf("%s, activation in force: %+v; want code %d with %v", name, res, codeIntentCertificateRefused, ErrIntentProofV21Missing)
		}
		if !app.blockRulesV15Verdict {
			t.Errorf("%s: the refusal only v15 reaches was not counted a v15 verdict", name)
		}
	}
	// And judgeProofV2 says so directly.
	vb := built(classes["every member at once"])
	if _, _, err := judgeProofV2(vb.IntentCertificate, nil, nil, nil, [32]byte{}, [32]byte{}, [32]byte{}, spine, g1Active, nil); !errors.Is(err, ErrIntentProofV21Missing) {
		t.Fatalf("a 2.0 document under the activation: %v", err)
	}
}
