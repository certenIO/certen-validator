package proof

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RB4-F66. CERTEN anchors nothing of an intent's governance on the live batch path (createBatchAnchor stores a zero
// governanceRoot, and neither the leaf nor the quorum's BLS message carries any governance value). The first step of
// the fix is a record every validator derives identically from its own proof: WHO decided the transaction - each
// required authority, the page that cast its vote, that page's version and thresholds, the entries it counted and
// the delegates behind them - and a commitment to it. These tests pin what the record contains, that it is a function
// of the chain and not of how it was read, and that it is refused rather than guessed when the proof cannot support it.

func loadG1Output(t *testing.T, name string) (json.RawMessage, *G0Result) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var g0 G0Result
	if err := json.Unmarshal(raw, &g0); err != nil {
		t.Fatal(err)
	}
	return raw, &g0
}

func decisionOf(t *testing.T, name string) (*AuthorizationRecord, *G0Result) {
	t.Helper()
	raw, g0 := loadG1Output(t, name)
	rec, err := AuthorizationRecordFromRaw(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if rec == nil {
		t.Fatalf("%s: the G1 output carries a vote record, and none was read", name)
	}
	return rec, g0
}

// The record read from a live, delegated Kermit transaction names every hop down to the key.
func TestGovernanceDecision_ReadsWhoDecided(t *testing.T) {
	rec, g0 := decisionOf(t, "gdr_g1_delegated_case_c.json")
	gdr, err := GovernanceDecisionRecord(g0, rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"acc://certen-p7c.acme/data", "acc://certen-p7c.acme/book", "acc://certen-p7c.acme/book/1",
		"delegate:acc://certen-p7c.acme/book2", "acc://certen-p7c.acme/book2/1",
		"key:c0265bd3e745825832605b75cbd40e5bde38fd21037769bbb202b5f7822fc465",
		"f25a6dfd561fc8e8fbda779341be6a2d0d90d3b64ad7db69f95d88b49d2f5be3",
	} {
		if !strings.Contains(string(gdr), want) {
			t.Errorf("the decision record does not carry %s", want)
		}
	}
}

// A golden: the encoding is a protocol value (it becomes part of the quorum-signed batch id), so it is pinned.
func TestGovernanceDecision_CommitmentIsPinned(t *testing.T) {
	for name, want := range map[string]string{
		"gdr_g1_delegated_case_c.json": goldenCaseC,
		"gdr_g1_phasec_98e40472.json":  goldenPhaseC,
	} {
		rec, g0 := decisionOf(t, name)
		gdr, err := GovernanceDecisionRecord(g0, rec)
		if err != nil {
			t.Fatal(err)
		}
		c := GovernanceCommitment(gdr)
		if got := hex.EncodeToString(c[:]); got != want {
			t.Errorf("%s: commitment %s, pinned %s", name, got, want)
		}
	}
}

// The record does not depend on the order anything was listed in.
func TestGovernanceDecision_IsIndependentOfOrder(t *testing.T) {
	rec, g0 := decisionOf(t, "gdr_g1_delegated_case_c.json")
	want, err := GovernanceDecisionRecord(g0, rec)
	if err != nil {
		t.Fatal(err)
	}
	// A second, unrelated authority, listed first and then last.
	extra := AuthorizationAuthority{Authority: "acc://aaa.acme/book", Vote: AuthorizationBook{
		Book: "acc://aaa.acme/book", Voted: true, Vote: "accept", By: "acc://aaa.acme/book/1",
		Pages: []AuthorizationPage{{Page: "acc://aaa.acme/book/1", Voted: true, Vote: "accept", Version: 1, Threshold: 2,
			DecidedAt: 5, Counted: []AuthorizationEntry{
				{Entry: "key:" + strings.Repeat("b", 64), Vote: "accept", By: "m2", Block: 5}, {Entry: "key:" + strings.Repeat("a", 64), Vote: "accept", By: "m1", Block: 4}}}}}}
	a := *rec
	a.Authorities = append([]AuthorizationAuthority{extra}, rec.Authorities...)
	b := *rec
	flipped := extra
	flipped.Vote.Pages = []AuthorizationPage{extra.Vote.Pages[0]}
	flipped.Vote.Pages[0].Counted = []AuthorizationEntry{extra.Vote.Pages[0].Counted[1], extra.Vote.Pages[0].Counted[0]}
	b.Authorities = append(append([]AuthorizationAuthority{}, rec.Authorities...), flipped)
	ga, err := GovernanceDecisionRecord(g0, &a)
	if err != nil {
		t.Fatal(err)
	}
	gb, err := GovernanceDecisionRecord(g0, &b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ga) != string(gb) || string(ga) == string(want) {
		t.Fatal("the record depends on the order authorities or entries were listed in")
	}
}

// Every fact of the decision is committed: changing any one changes the commitment.
func TestGovernanceDecision_CommitsEveryFact(t *testing.T) {
	base := func() (*AuthorizationRecord, *G0Result) { return decisionOf(t, "gdr_g1_delegated_case_c.json") }
	rec, g0 := base()
	gdr, err := GovernanceDecisionRecord(g0, rec)
	if err != nil {
		t.Fatal(err)
	}
	want := GovernanceCommitment(gdr)
	page := func(r *AuthorizationRecord) *AuthorizationPage { return &r.Authorities[0].Vote.Pages[0] }
	inner := func(r *AuthorizationRecord) *AuthorizationPage { return &page(r).Delegates[0].Pages[0] }
	for name, mutate := range map[string]func(*AuthorizationRecord, *G0Result){
		"transaction":        func(_ *AuthorizationRecord, g *G0Result) { g.TxHash = strings.Repeat("ab", 32) },
		"execution block":    func(_ *AuthorizationRecord, g *G0Result) { g.ExecMBI++ },
		"page version":       func(r *AuthorizationRecord, _ *G0Result) { page(r).Version++ },
		"accept threshold":   func(r *AuthorizationRecord, _ *G0Result) { page(r).Threshold++ },
		"reject threshold":   func(r *AuthorizationRecord, _ *G0Result) { page(r).RejectThreshold++ },
		"response threshold": func(r *AuthorizationRecord, _ *G0Result) { page(r).ResponseThreshold++ },
		"decided at":         func(r *AuthorizationRecord, _ *G0Result) { page(r).DecidedAt++ },
		"counted message":    func(r *AuthorizationRecord, _ *G0Result) { page(r).Counted[0].By += "x" },
		"counted block":      func(r *AuthorizationRecord, _ *G0Result) { page(r).Counted[0].Block++ },
		"delegate key": func(r *AuthorizationRecord, _ *G0Result) {
			inner(r).Counted[0].Entry = "key:" + strings.Repeat("0", 64)
		},
		"delegate page version": func(r *AuthorizationRecord, _ *G0Result) { inner(r).Version++ },
		"authority disabled":    func(r *AuthorizationRecord, _ *G0Result) { r.Authorities[0].Disabled = true },
	} {
		r, g := base()
		mutate(r, g)
		gdr, err := GovernanceDecisionRecord(g, r)
		if err != nil {
			continue // refusing the altered record is as good as committing to the change
		}
		if GovernanceCommitment(gdr) == want {
			t.Errorf("changing the %s does not change the commitment", name)
		}
	}
}

// What is not part of the decision - messages excluded for a reason, signatures that reached no required
// authority - depends on when the record was read, and is not committed.
func TestGovernanceDecision_DoesNotCommitWhatDidNotDecide(t *testing.T) {
	rec, g0 := decisionOf(t, "gdr_g1_delegated_case_c.json")
	gdr, _ := GovernanceDecisionRecord(g0, rec)
	rec.Unused = append(rec.Unused, AuthorizationExclusion{By: "late", Reason: "signed later"})
	rec.Authorities[0].Vote.Pages[0].Excluded = append(rec.Authorities[0].Vote.Pages[0].Excluded,
		AuthorizationExclusion{By: "late", Reason: "recorded after the page's vote was decided"})
	again, err := GovernanceDecisionRecord(g0, rec)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(gdr) {
		t.Fatal("exclusions changed the decision record")
	}
}

// A record that cannot support a decision is refused by name, never encoded around.
func TestGovernanceDecision_RefusesWhatItCannotSupport(t *testing.T) {
	for name, mutate := range map[string]func(*AuthorizationRecord, *G0Result){
		"not satisfied":       func(r *AuthorizationRecord, _ *G0Result) { r.Satisfied = false },
		"no authorities":      func(r *AuthorizationRecord, _ *G0Result) { r.Authorities = nil },
		"authority not voted": func(r *AuthorizationRecord, _ *G0Result) { r.Authorities[0].Vote.Voted = false },
		"not an acceptance":   func(r *AuthorizationRecord, _ *G0Result) { r.Authorities[0].Vote.Vote = "reject" },
		"no deciding page": func(r *AuthorizationRecord, _ *G0Result) {
			r.Authorities[0].Vote.By = "acc://certen-p7c.acme/book/9"
		},
		"page not decided": func(r *AuthorizationRecord, _ *G0Result) { r.Authorities[0].Vote.Pages[0].DecidedAt = 0 },
		"nothing counted":  func(r *AuthorizationRecord, _ *G0Result) { r.Authorities[0].Vote.Pages[0].Counted = nil },
		"delegate without its record": func(r *AuthorizationRecord, _ *G0Result) {
			r.Authorities[0].Vote.Pages[0].Delegates = nil
		},
		"another principal": func(_ *AuthorizationRecord, g *G0Result) { g.Principal = "someone-else.acme" },
		"no transaction":    func(_ *AuthorizationRecord, g *G0Result) { g.TxHash = "" },
		"no execution":      func(_ *AuthorizationRecord, g *G0Result) { g.ExecMBI = 0 },
	} {
		rec, g0 := decisionOf(t, "gdr_g1_delegated_case_c.json")
		mutate(rec, g0)
		if _, err := GovernanceDecisionRecord(g0, rec); err == nil {
			t.Errorf("%s: encoded instead of refused", name)
		}
	}
	if _, err := GovernanceDecisionRecord(&G0Result{Principal: "x.acme", TxHash: strings.Repeat("ab", 32), ExecMBI: 1}, nil); err == nil {
		t.Error("no vote record: encoded instead of refused")
	}
}

// A malformed record in the CLI output is an error, not an absence.
func TestGovernanceDecision_AMalformedRecordIsNotAnAbsence(t *testing.T) {
	if rec, err := AuthorizationRecordFromRaw(json.RawMessage(`{"authorization": "not a record"}`)); err == nil {
		t.Fatalf("a malformed record was read as %+v", rec)
	}
	rec, err := AuthorizationRecordFromRaw(json.RawMessage(`{"tx_hash": "ab"}`))
	if err != nil || rec != nil {
		t.Fatalf("an output with no record: %+v %v", rec, err)
	}
}

// Pinned, and reproduced by an encoder written independently from the specification (evidence/rb4/
// f66_gdr_independent.txt): the Kermit delegated corpus case C and the Phase C multi-leg transaction 98e40472.
const (
	goldenCaseC  = "5e4d4896bb6f45a124f9c9c5116ae29e3bfb951eec02b1a6d0220b7d81787b26"
	goldenPhaseC = "bf70dbca95fcf373511b454ad486f6c85396a5c2ff7119b55c7538be834c0d1f"
)

// The CLI's G1 output is parsed with its vote record kept on the wrapper - never inside G1Result, which is part of
// the ValidatorBlock's BundleID.
func TestGovernanceDecision_TheAdapterKeepsTheRecord(t *testing.T) {
	pretty, _ := loadG1Output(t, "gdr_g1_delegated_case_c.json")
	// The CLI prints its log lines and then the result on one line.
	var compact bytes.Buffer
	if err := json.Compact(&compact, pretty); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte("[G1] log line\n"), compact.Bytes()...)
	g := &CLIGovernanceProofGenerator{logger: log.New(io.Discard, "", 0)}
	gp, err := g.parseOutput(GovLevelG1, raw, kermitRouter(t))
	if err != nil {
		t.Fatal(err)
	}
	if gp.Authorization == nil || len(gp.Authorization.Authorities) != 1 || !gp.Authorization.Satisfied {
		t.Fatalf("the vote record was not kept: %+v", gp.Authorization)
	}
	g1json, _ := json.Marshal(gp.G1)
	if strings.Contains(string(g1json), "authorization") || strings.Contains(string(g1json), "decidedAt") {
		t.Fatal("the vote record leaked into G1Result")
	}

	var bad map[string]json.RawMessage
	_ = json.Unmarshal(compact.Bytes(), &bad)
	bad["authorization"] = json.RawMessage(`{"account": 7}`)
	broken, _ := json.Marshal(bad)
	if _, err := g.parseOutput(GovLevelG1, broken, kermitRouter(t)); err == nil {
		t.Fatal("a malformed vote record was accepted")
	}
}
