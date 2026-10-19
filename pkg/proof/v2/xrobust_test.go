// Copyright 2026 Certen Protocol
//
// RB9-L: a crafted document is refused, never a panic. Every committed vector (the xpartition2 .. xpartition5 suites, the real Kermit
// documents and the 2.0 conformance documents) is mutated at every member (internal/jsonmutate) and judged three times:
//
//   - as a PORTABLE document by VerifyPortable, the verifier proofverify runs offline;
//   - as an EVIDENCE document, the form a consensus certificate carries (hex receipts and all), decoded by UnmarshalCertifiedEvidence and
//     judged against the spine a chain holds by VerifyEvidence21FromSpine / VerifyFromSpine, the verifiers consensus runs;
//   - as the same EVIDENCE document judged by the offline walk (Verify21FromGenesis / VerifyFromGenesis) from the archive and the incarnation
//     inputs, so a member only the offline walk reads is exercised in the evidence form too (RB9-F6).
//
// The assertions, for every mutation:
//
//   - no panic;
//   - a mutation that leaves the verifier the very input it had (the member was already null, empty, zero or absent) is judged exactly as
//     before, error text included;
//   - a document the unmutated vector refuses stays refused, or verifies only as evidence 2.1 whose report lists the states it could not
//     establish (a named downgrade the consensus binding refuses: intentcert.BindProofV21);
//   - a document the unmutated vector verifies is refused after the mutation, or verifies as such a downgrade, unless the member is genuinely
//     optional: the verifier reads nothing the mutation changed, so the document verifies with a report byte for byte the original's.
//     Every such member is listed in robustOptionalMembers with the reason it does not matter, and a member that is not listed fails.
//
// TestRobustnessEveryVectorEveryMember runs in the normal run, over every vector.

package proofv2

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	jm "github.com/certen/independant-validator/internal/jsonmutate"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/proof"
)

// robustSource is one document the instrument mutates and the function that judges it.
type robustSource struct {
	name  string
	raw   []byte
	judge jm.Judge
	// walk bounds the members mutated; the zero value is every member.
	walk jm.WalkSpec
}

var robustSuites = []string{"xpartition2", "xpartition2b", "xpartition3", "xpartition3b", "xpartition4", "xpartition5"}

func readMaybeGzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if !strings.HasSuffix(path, ".gz") {
		return io.ReadAll(f)
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(z)
}

// shallow keeps the members of a document down to the given depth. It bounds the portable form of the real documents, whose verification
// walks hundreds of spine records for every mutation: their members are mutated at every depth in the evidence form, which is judged
// against a spine log built once, and the portable form of the same documents is mutated at its top two levels (the format, the pin, the
// genesis, every spine record as a whole and the evidence's own members); the synthetic documents carry the same member shapes at every
// depth and are mutated in full in the portable form.
func shallow(depth int) func(jm.Path) bool {
	return func(p jm.Path) bool { return len(p) <= depth }
}

// portableInput is what the verifier is given of a portable document once it is imported - the evidence, the archive, the incarnation's
// inputs and the pin - as one canonical string; "" when the document does not import (or does not re-encode, which a document that
// imports but cannot be written back is).
func portableInput(p *Portable) (s string) {
	defer func() {
		if recover() != nil {
			s = ""
		}
	}()
	ev, ar, in, pin, err := Import(p)
	if err != nil {
		return ""
	}
	a, err := MarshalArchive(ar)
	if err != nil {
		return ""
	}
	return jm.Canonical(ev) + "|" + string(a) + "|" + jm.Canonical(in) + "|" + hex.EncodeToString(pin[:])
}

// portableJudge judges a portable document as proofverify does (VerifyPortable); the report of a verified one is its canonical JSON. A
// mutated document that imports to exactly what the unmutated one does (base) is the same input to the verifier: it is marked Noop.
func portableJudge(base []byte) jm.Judge {
	var baseInput string
	if p := new(Portable); json.Unmarshal(base, p) == nil {
		baseInput = portableInput(p)
	}
	return func(raw []byte) jm.Verdict {
		p := new(Portable)
		if err := json.Unmarshal(raw, p); err != nil {
			return jm.Verdict{Refused: true, Err: "decode: " + err.Error()}
		}
		same := baseInput != "" && portableInput(p) == baseInput
		rep, err := VerifyPortable(p)
		if err != nil {
			return jm.Verdict{Refused: true, Err: err.Error(), Noop: same}
		}
		v := reportVerdict(rep)
		v.Noop = same
		return v
	}
}

func reportVerdict(rep *Report) jm.Verdict {
	j, err := json.Marshal(rep)
	if err != nil {
		return jm.Verdict{Panicked: "harness: the report does not encode: " + err.Error()}
	}
	// What the consensus binding refuses a report for (intentcert.BindProofV21): a state it could not establish, and a sequenced vote whose
	// production is not bound to it.
	var un []string
	for _, u := range rep.Unproven {
		un = append(un, u.Code)
	}
	for _, d := range rep.Disclosures {
		if d.Code == StateVoteProductionUnbound {
			un = append(un, d.Code)
		}
	}
	return jm.Verdict{Report: string(j), Unproven: un}
}

// reportEvidenceKeys are the members of a report that are the evidence a document carries beyond the chain it is proven into: the pages and
// their chains (and whether they are bound), the roles, the votes' arrivals and mode, the routing proof, what could not be established,
// and the verdict on the validator set (which a missing or partial set proof makes weaker, by name: validator_set_asserted and its kin,
// which the govRoot computation refuses). A mutation may change these (it carries less, or other, evidence); it may not change anything else
// a report says (the incarnation, the certified root and block, the set check's block, the validators and threshold, the partition and block
// of the transaction, the roots a root commits), and it may not make the set verdict stronger.
var reportEvidenceKeys = []string{"Pages", "PageChains", "Proven", "Unproven", "Disclosures", "AuthorizationMode", "Arrivals", "RoutingHeight", "SetVerdict"}

// factsOf is a report without its evidence members, as one string, and the version it is of.
func factsOf(report string) (facts, version string) {
	var m map[string]any
	if json.Unmarshal([]byte(report), &m) != nil {
		return report, ""
	}
	for _, k := range reportEvidenceKeys {
		delete(m, k)
	}
	out, _ := json.Marshal(m)
	v, _ := m["Version"].(string)
	return string(out), v
}

// setVerdictOf is the verdict on the validator set a report carries.
func setVerdictOf(report string) string {
	var m struct{ SetVerdict string }
	_ = json.Unmarshal([]byte(report), &m)
	return m.SetVerdict
}

// spineLogFor is the spine a chain holds after verifying a document's archive from its genesis (what consensus judges evidence against).
func spineLogFor(in proof.IncarnationInputs, ar *Archive, pin [32]byte) (*ledger.AccumulateSpineLog, error) {
	gen, set, err := AcceptSpineGenesis(in, pin, 5)
	if err != nil {
		return nil, err
	}
	l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
	cps, sets, err := ExtendSpine(l, ar.Majors, 6)
	if err != nil {
		return nil, err
	}
	l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
	return l, nil
}

// judgeEvidence judges the evidence a certificate carries as consensus does: decoded by UnmarshalCertifiedEvidence, verified by the
// entry point of its version against the chain's spine.
func judgeEvidence(base []byte, l *ledger.AccumulateSpineLog, pin [32]byte) jm.Judge {
	canonical := func(raw []byte) string {
		doc, err := UnmarshalCertifiedEvidence(raw)
		if err != nil || doc == nil {
			return ""
		}
		return jm.Canonical(doc)
	}
	baseInput := canonical(base)
	return func(raw []byte) jm.Verdict {
		doc, err := UnmarshalCertifiedEvidence(raw)
		if err != nil {
			return jm.Verdict{Refused: true, Err: "decode: " + err.Error()}
		}
		if doc == nil {
			return jm.Verdict{Refused: true, Err: "no evidence"}
		}
		same := baseInput != "" && jm.Canonical(doc) == baseInput
		var rep *Report
		if doc.Version == Version21 {
			rep, err = VerifyEvidence21FromSpine(doc, l, pin)
		} else {
			rep, err = VerifyFromSpine(doc, l, pin)
		}
		if err != nil {
			return jm.Verdict{Refused: true, Err: err.Error(), Noop: same}
		}
		v := reportVerdict(rep)
		v.Noop = same
		return v
	}
}

// judgeEvidenceOffline judges the evidence a certificate carries by the offline walk: decoded by UnmarshalCertifiedEvidence, verified by the
// entry point of its version from the archive and the incarnation inputs (RB9-F6).
func judgeEvidenceOffline(base []byte, ar *Archive, in proof.IncarnationInputs, pin [32]byte) jm.Judge {
	canonical := func(raw []byte) string {
		doc, err := UnmarshalCertifiedEvidence(raw)
		if err != nil || doc == nil {
			return ""
		}
		return jm.Canonical(doc)
	}
	baseInput := canonical(base)
	return func(raw []byte) jm.Verdict {
		doc, err := UnmarshalCertifiedEvidence(raw)
		if err != nil {
			return jm.Verdict{Refused: true, Err: "decode: " + err.Error()}
		}
		if doc == nil {
			return jm.Verdict{Refused: true, Err: "no evidence"}
		}
		same := baseInput != "" && jm.Canonical(doc) == baseInput
		var rep *Report
		if doc.Version == Version21 {
			rep, err = Verify21FromGenesis(doc, ar, in, pin)
		} else {
			rep, err = VerifyFromGenesis(doc, ar, in, pin)
		}
		if err != nil {
			return jm.Verdict{Refused: true, Err: err.Error(), Noop: same}
		}
		v := reportVerdict(rep)
		v.Noop = same
		return v
	}
}

// evidenceOfflineSource is the evidence form of a portable source judged by the offline walk. It keeps the portable source's bounds: the real
// documents walk hundreds of spine records for every mutation.
func evidenceOfflineSource(t *testing.T, src robustSource) (robustSource, bool) {
	t.Helper()
	p := new(Portable)
	if err := json.Unmarshal(src.raw, p); err != nil {
		return robustSource{}, false
	}
	ev, ar, in, pin, err := Import(p)
	if err != nil {
		return robustSource{}, false
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return robustSource{name: src.name + " (evidence form, offline)", raw: raw, judge: judgeEvidenceOffline(raw, ar, in, pin), walk: src.walk}, true
}

// evidenceSource converts a portable source to the evidence form a certificate carries, judged against the spine its archive gives. ok is
// false when the portable document does not import (it is refused before there is an evidence to mutate).
func evidenceSource(t *testing.T, src robustSource) (robustSource, bool) {
	t.Helper()
	p := new(Portable)
	if err := json.Unmarshal(src.raw, p); err != nil {
		return robustSource{}, false
	}
	ev, ar, in, pin, err := Import(p)
	if err != nil {
		return robustSource{}, false
	}
	l, err := spineLogFor(in, ar, pin)
	if err != nil {
		return robustSource{}, false
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	// The evidence form is mutated at every depth (only the arrays of a real document are sampled): it is judged against a spine log built
	// once, so a mutation costs a verification, not a walk of the whole spine.
	return robustSource{name: src.name + " (evidence form)", raw: raw, judge: judgeEvidence(raw, l, pin), walk: jm.WalkSpec{ArrayLimit: src.walk.ArrayLimit}}, true
}

// robustPortableSources loads every vector document, in a fixed order.
func robustPortableSources(t *testing.T) []robustSource {
	t.Helper()
	var out []robustSource
	for _, suite := range robustSuites {
		files, err := filepath.Glob("testdata/" + suite + "/*.json")
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(files)
		for _, f := range files {
			if filepath.Base(f) == "manifest.json" {
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, robustSource{name: suite + "/" + filepath.Base(f), raw: raw, judge: portableJudge(raw)})
		}
	}
	return append(out, robustRealSources(t)...)
}

// robustRealSources are the real documents: the 2.1 document of a live Kermit transaction and the 2.0 conformance documents.
func robustRealSources(t *testing.T) []robustSource {
	t.Helper()
	var out []robustSource
	r := loadReal21(t)
	p, err := Export(r.ev, r.ar, r.in, r.pin)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, robustSource{name: "real/bvn1-billing-receipts-2.1", raw: raw, judge: portableJudge(raw),
		walk: jm.WalkSpec{Keep: shallow(2), ArrayLimit: 3}})
	for _, name := range []string{"valid.json.gz", "network-update.json.gz"} {
		raw, err := readMaybeGzip("testdata/conformance/" + name)
		if err != nil {
			t.Fatal(err)
		}
		// A conformance document with a few spine records (network-update.json) is synthetic and walked in full; the Kermit 2.0 document
		// (valid.json, 491 records) is bounded like the real 2.1 document.
		var probe struct {
			Majors []json.RawMessage `json:"majors"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatal(err)
		}
		var walk jm.WalkSpec
		if len(probe.Majors) > 20 {
			walk = jm.WalkSpec{Keep: shallow(2), ArrayLimit: 3}
		}
		out = append(out, robustSource{name: "conformance/" + strings.TrimSuffix(name, ".gz"), raw: raw, judge: portableJudge(raw), walk: walk})
	}
	return out
}

// robustAllSources is every vector in both forms: the portable document, then the evidence a certificate carries.
func robustAllSources(t *testing.T) []robustSource {
	t.Helper()
	portable := robustPortableSources(t)
	out := append([]robustSource(nil), portable...)
	for _, s := range portable {
		if e, ok := evidenceSource(t, s); ok {
			out = append(out, e)
		}
	}
	for _, s := range portable {
		if e, ok := evidenceOfflineSource(t, s); ok {
			out = append(out, e)
		}
	}
	return out
}

// robustFinding is one thing a run found wrong.
type robustFinding struct {
	class string
	what  string
}

// formOf is "ev" for an evidence-form source and "portable" for the rest: the prefix of the keys of robustOptionalMembers.
func formOf(src robustSource) string {
	if strings.HasSuffix(src.name, " (evidence form, offline)") {
		return "evo" // its own form: what the spine-log loop mutated is mutated again here (onceEach), its optional members keyed as ev's (checkOptional)
	}
	if strings.HasSuffix(src.name, " (evidence form)") {
		return "ev"
	}
	return "portable"
}

// examineRobust turns the outcomes of one document into findings and the optional members it observed. A mutation after which the
// verifier is given the very input it was given before (Noop) must be judged exactly as before. A mutation that makes a verified
// document's report differ may change only what the report says of the evidence the document carries (reportEvidenceKeys: fewer or
// other pages, chains unbound, states listed as not established, a weaker verdict on the validator set); each of those is committed into
// the govRoot the proposer signs (pages, chains, votes), refused by the consensus binding (what is not established, a set verdict that is
// not verified) or derived from what is committed, so a different report is a different claim, not a silent one.
func examineRobust(src robustSource, base jm.Verdict, outs []jm.Outcome) (findings []robustFinding, optional map[string]string) {
	optional = map[string]string{}
	form := formOf(src)
	for _, o := range outs {
		v := o.V
		where := src.name + " :: " + o.M.String()
		switch {
		case v.Panicked != "":
			findings = append(findings, robustFinding{class: "PANIC " + v.Panicked, what: where})
		case v.Noop:
			if v.Refused != base.Refused || v.Report != base.Report || v.Err != base.Err {
				findings = append(findings, robustFinding{class: "The verifier's input is the vector's, and the verdict is not", what: where})
			}
		case v.Refused:
		case base.Refused:
			if _, ver := factsOf(v.Report); ver == Version21 && len(v.Unproven) == 0 {
				findings = append(findings, robustFinding{class: "A document the vector refuses VERIFIED after a mutation, listing nothing unproven", what: where})
			}
		case v.Report == base.Report:
			optional[form+":"+o.M.Path.Shape()] = src.name + " :: " + o.M.Path.String() + " <- " + o.M.Kind
		default:
			vf, _ := factsOf(v.Report)
			bf, _ := factsOf(base.Report)
			switch {
			case vf != bf:
				findings = append(findings, robustFinding{class: "VERIFIED with a report that differs from the vector's in what it proves beyond its evidence", what: where})
			case setVerdictOf(v.Report) == string(proof.VerdictVerified) && setVerdictOf(base.Report) != string(proof.VerdictVerified):
				findings = append(findings, robustFinding{class: "VERIFIED with a stronger verdict on the validator set than the vector's", what: where})
			}
		}
	}
	return findings, optional
}

// reportRobust fails t once per class of finding, naming the number of mutations and the first few.
func reportRobust(t *testing.T, findings []robustFinding) {
	t.Helper()
	byClass := map[string][]string{}
	for _, f := range findings {
		byClass[f.class] = append(byClass[f.class], f.what)
	}
	classes := make([]string, 0, len(byClass))
	for c := range byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		ws := byClass[c]
		show := ws
		if len(show) > 12 {
			show = show[:12]
		}
		t.Errorf("%s\n   %d mutation(s), e.g.\n   %s", c, len(ws), strings.Join(show, "\n   "))
	}
}

// robustMutationsOf lists every mutation of a source, in a fixed order, and the whole document as something else.
func robustMutationsOf(t *testing.T, src robustSource) (any, []jm.Mutation) {
	t.Helper()
	tree, err := jm.ParseTree(src.raw)
	if err != nil {
		t.Fatalf("%s: %v", src.name, err)
	}
	var muts []jm.Mutation
	jm.Walk(tree, src.walk, func(p jm.Path, v any) { muts = append(muts, jm.MutationsOf(p, v)...) })
	return tree, append(muts, jm.WholeDocument()...)
}

// runRobustSources mutates every source at every member it keeps and returns the findings, the optional members observed and the number
// of mutations judged.
func runRobustSources(t *testing.T, srcs []robustSource) ([]robustFinding, map[string]string, int) {
	t.Helper()
	workers := runtime.GOMAXPROCS(0)
	var all []robustFinding
	optional := map[string]string{}
	total := 0
	for _, src := range srcs {
		base := jm.Guard(func() jm.Verdict { return src.judge(src.raw) })
		if base.Panicked != "" {
			t.Fatalf("%s: the unmutated document panics: %s", src.name, base.Panicked)
		}
		tree, muts := robustMutationsOf(t, src)
		// The control: the document re-encoded from its tree is judged exactly as the original.
		again, _ := json.Marshal(tree)
		if ctl := jm.Guard(func() jm.Verdict { return src.judge(again) }); ctl.Refused != base.Refused || ctl.Report != base.Report {
			t.Fatalf("%s: the tree's re-encoding is judged differently from the file (%q vs %q)", src.name, ctl.Err, base.Err)
		}
		start := time.Now()
		outs := jm.Run(tree, muts, src.judge, workers)
		fs, opt := examineRobust(src, base, outs)
		t.Logf("%-80s %6d mutations %4d findings %v", src.name, len(muts), len(fs), time.Since(start).Round(time.Second))
		all = append(all, fs...)
		for k, e := range opt {
			if _, ok := optional[k]; !ok {
				optional[k] = e
			}
		}
		total += len(muts)
	}
	return all, optional, total
}

// robustOptionalMembers are the members whose removal, nulling or replacement leaves a verified document verified with the same report,
// keyed "<form>:<member shape>" (form portable or ev; an array index is *). The value is the reason the member does not matter. A member is
// listed only for what it was observed to be: the verifier reads nothing of it in the documents named.
var robustOptionalMembers = optionalTable(
	grp("Evidence.Account is the principal's URL: the 2.1 verifier reads it (the principal chain, the carried transaction, the vote "+
		"membership); nothing in the verification of evidence 2.0 does, and a 2.0 document names it for its reader (the 2.0 conformance documents)",
		"ev:account", "portable:evidence/account"),
	grp("the sequence number of the SequencedMessage that delivered a partition's anchor is outside the anchor transaction's hash, which "+
		"is what the receipt proves into the certified root; the verifier reads the wrapper's Source only, and requires it to equal the body's "+
		"(xdirectory.go partition())",
		"ev:anchor/message", "ev:anchors/acc://bvn-BVN2.acme/message", "ev:anchors/acc://bvn-BVN3.acme/message", "ev:anchors/acc://dn.acme/message",
		"portable:evidence/anchors/acc://dn.acme/message/number"),
	grp("merkle.Receipt carries, besides Start, Entries and Anchor, position fields (StartIndex, EndIndex, End) that Validate does not read (the genesis link is one: "+
		"of its 15 mutations in the real document exactly one, hollow-receipt.End, leaves it verified, by both loops; every other mutation, an absent link included, is refused); "+
		"a minor-root run's merkle state keeps a HashList the verifier does not read (Anchor() folds Pending), and a validator signature's "+
		"TransactionHash is not read: the quorum check verifies each signature over the delivered anchor message (sig.Verify(nil, anchor))",
		"ev:anchor/receipt", "ev:certify/*", "ev:check/hops/*", "ev:genesisLink", "portable:evidence/certify/*/signatures/*/transactionHash",
		"portable:majors/*/signatures/*/transactionHash"),
	grp("the Anchors entry for the transaction's own partition must equal Evidence.Anchor and is set aside when it does "+
		"(xverify.go verify21): a document whose only entries are its own carries nothing that field does not",
		"ev:anchors", "ev:anchors/acc://bvn-BVN1.acme", "portable:evidence/anchors"),
	grp("a set check with no minor-root runs of its own is the set proven at the certified block, a smaller proof of the same fact: the "+
		"runs extend the spine to a later certified block, and a document whose check block is its certified block verifies without them",
		"ev:check/hops"),
	grp("the archived quorum of a run (or of a spine record) holds more signatures than the threshold: removing one leaves the quorum "+
		"met (verifyQuorum counts distinct valid validators against the threshold)",
		"portable:evidence/certify/*/signatures/*", "portable:majors/*/signatures/*"),
	grp("ChainRoot.Anchor is a restatement recomputed from Pending, and an empty one is not compared (ChainRoot.derive); a chain's Name is "+
		"read only to find the main chain (MainChainHeight) and, for a page, the chains the timeline looks up by name - the names are not covered "+
		"by the state hasher's chain component (computeChainsComponent hashes the roots in order), which is recorded as a finding",
		"ev:check/routing/chains/*/anchor", "ev:check/routing/chains/*/name", "ev:check/set/globals/chains/*/anchor", "ev:check/set/globals/chains/*/name",
		"ev:check/set/network/chains/*/anchor", "ev:check/set/network/chains/*/name", "ev:pages/*/chains/*/anchor",
		"portable:evidence/check/globals/chains/*/anchor", "portable:evidence/check/network/chains/*/anchor",
		"portable:evidence/check/routing/chains/*/anchor", "portable:evidence/pages/*/chains/*/anchor"),
	grp("bookkeeping of the receipt the node served (the block of the state): recomputeReceipt hashes Start, Entries and Anchor only",
		"ev:check/routing/stateReceipt/localBlock", "ev:check/set/globals/stateReceipt/localBlock", "ev:check/set/network/stateReceipt/localBlock"),
	grp("the document's set check is of a validator set that changed after genesis (the network account's main chain holds more than "+
		"its genesis entry): its verdict is validator_set_asserted whatever the set's receipts and incarnation carry (validator_set_proof.go "+
		"Verify, steps 10 and 16 precede 17), and the set is bound by being equal to the record the spine derived (sameEntry), which every "+
		"verification requires; govRoot refuses a report whose set verdict is not verified (the network-update conformance document)",
		"ev:check/set/globals/stateReceipt", "ev:check/set/globals/stateReceipt/entries", "ev:check/set/network/stateReceipt",
		"ev:check/set/network/stateReceipt/entries", "ev:check/set/incarnation", "portable:evidence/check/globals/stateReceipt",
		"portable:evidence/check/globals/stateReceipt/entries", "portable:evidence/check/network/stateReceipt",
		"portable:evidence/check/network/stateReceipt/entries", "portable:evidence/check/incarnation"),
	grp("Vote.Cause is recorded and committed into govRoot v4 (intentcert EncodeVoteV4) and read by no verifier step: a recorded fact "+
		"that is not proven (recorded as a finding)",
		"ev:votes/*/cause"),
)

type optionalGroup struct {
	reason string
	shapes []string
}

func grp(reason string, shapes ...string) optionalGroup { return optionalGroup{reason, shapes} }

func optionalTable(groups ...optionalGroup) map[string]string {
	out := map[string]string{}
	for _, g := range groups {
		for _, s := range g.shapes {
			out[s] = g.reason
		}
	}
	return out
}

// checkOptional requires every optional member observed to be listed with a reason; when exact, every listed member must have been
// observed (the full run), so a stale entry cannot hide a member that has become required.
func checkOptional(t *testing.T, observed map[string]string, exact bool) {
	t.Helper()
	// the offline evidence-form loop ("evo") reads the same members as the spine-log one ("ev"): one table lists both
	norm := map[string]string{}
	for k, e := range observed {
		if strings.HasPrefix(k, "evo:") {
			k = "ev:" + strings.TrimPrefix(k, "evo:")
		}
		if _, ok := norm[k]; !ok {
			norm[k] = e
		}
	}
	observed = norm
	var unlisted []string
	for k := range observed {
		if _, ok := robustOptionalMembers[k]; !ok {
			unlisted = append(unlisted, k)
		}
	}
	sort.Strings(unlisted)
	for _, k := range unlisted {
		t.Errorf("an optional member that is not listed (verified with the original report after the mutation %q, e.g. %s)", k, observed[k])
	}
	if exact {
		var stale []string
		for k := range robustOptionalMembers {
			if _, ok := observed[k]; !ok {
				stale = append(stale, k)
			}
		}
		sort.Strings(stale)
		for _, k := range stale {
			t.Errorf("robustOptionalMembers lists %q, which no mutation of any vector exercised", k)
		}
	}
}

// robustLiteral mutates every member of every document, not each distinct (place, value) once (see onceEach). It is a mode of the one test,
// which runs either way:
//
//	go test ./pkg/proof/v2/ -run TestRobustnessEveryVectorEveryMember -args -robust.literal
var robustLiteral = flag.Bool("robust.literal", false, "mutate every member of every vector, not each distinct (place, value) once")

// onceEach lets a member (with everything below it) be mutated once across the documents it is run over: a later document leaves out a
// member that an earlier one carried at the same place with the same value. The documents of a suite are one world with a few members
// changed each (a vote, a page, an anchor), so what each adds is mutated and what they share is mutated once: every vector is covered at
// every member that distinguishes it. -robust.literal drops the economy and mutates all of it.
func onceEach(srcs []robustSource) []robustSource {
	seen := map[string]bool{}
	out := make([]robustSource, len(srcs))
	for i, s := range srcs {
		form := formOf(s)
		s.walk.Covered = func(p jm.Path, v any) bool {
			j, _ := json.Marshal(v)
			sum := sha256.Sum256(j)
			k := form + ":" + p.Shape() + ":" + hex.EncodeToString(sum[:])
			if seen[k] {
				return true
			}
			seen[k] = true
			return false
		}
		out[i] = s
	}
	return out
}

// Every committed vector, in both forms, at every member that distinguishes it: no mutation panics, none turns a refusal into a verified
// claim of everything, and none that verifies leaves the report unchanged unless the member is listed as genuinely optional.
func TestRobustnessEveryVectorEveryMember(t *testing.T) {
	srcs := robustAllSources(t)
	if !*robustLiteral {
		srcs = onceEach(srcs)
	}
	findings, optional, total := runRobustSources(t, srcs)
	t.Logf("%d documents, %d mutations judged (literal %v)", len(srcs), total, *robustLiteral)
	reportRobust(t, findings)
	checkOptional(t, optional, *robustLiteral)
	if total < 20000 {
		t.Fatalf("only %d mutations: the vectors were not all loaded", total)
	}
}
