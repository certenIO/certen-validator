// Command proofv2conformance writes the cross-language conformance suite for proof v2 (docs/proof/PROOF_V2.md §9): the
// live Kermit proof in portable form, and one tampered copy per attack, each made by editing the JSON as an attacker
// would, with the verdict every verifier must reach. The Go verifier (pkg/proof/v2) and the TypeScript verifier
// (certen-sdk) both run the suite; they must agree on every case.
//
//	go run ./cmd/proofv2conformance -out pkg/proof/v2/testdata/conformance
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// Case is one entry of the manifest: the base proof with Patch applied, and the verdict every verifier must reach.
type Case struct {
	Name   string       `json:"name"`
	Expect string       `json:"expect"` // "verified" or "refused"
	Attack string       `json:"attack,omitempty"`
	Patch  []proofv2.Op `json:"patch,omitempty"`
	Report *Report      `json:"report,omitempty"` // for a verified case, what the verifier must report
}

// Report is the part of a verifier's report every implementation must reproduce.
type Report struct {
	Incarnation    string `json:"incarnation"`
	Majors         uint64 `json:"majors"`
	CertifiedBlock uint64 `json:"certifiedBlock"`
	CertifiedRoot  string `json:"certifiedRoot"`
	CheckBlock     uint64 `json:"checkBlock"`
	SetVerdict     string `json:"setVerdict"`
	Validators     int    `json:"validators"`
	Threshold      uint64 `json:"threshold"`
	Partition      string `json:"partition"`
	AnchorBlock    uint64 `json:"anchorBlock"`
	Pages          int    `json:"pages"`

	// GovRootV3 is the govRoot v3 (docs/proof/GOVROOT_V3.md) of the verified report with the proof's govRootV3Inputs.
	GovRootV3 string `json:"govRootV3"`
}

// govRootV3Inputs are the fixed synthetic governance results, key page, key book and operation id the valid case
// carries; pkg/intentcert's golden test uses the same values and pins the root the manifest reports.
func govRootV3Inputs(rep *proofv2.Report, ev *proofv2.Evidence) intentcert.GovRootV3Inputs {
	g0 := proof.G0Result{Scope: "acc://govroot-v3-golden.acme", Chain: "main", Principal: "acc://govroot-v3-golden.acme", G0ProofComplete: true}
	g1 := proof.G1Result{G0Result: g0, RequiredThreshold: 1, UniqueValidKeys: 1, ThresholdSatisfied: true, G1ProofComplete: true}
	g2 := proof.G2Result{G1Result: g1, PayloadVerified: true, EffectVerified: true, G2ProofComplete: true}
	return intentcert.GovRootV3Inputs{Report: rep, Evidence: ev, G0: &g0, G1: &g1, G2: &g2,
		KeyPageURL: "acc://govroot-v3-golden.acme/book/1", KeyBookURL: "acc://govroot-v3-golden.acme/book", OperationID: [32]byte{7}}
}

func main() {
	src := flag.String("testdata", "pkg/proof/v2/testdata", "the v2 testdata directory (archive and evidence)")
	inc := flag.String("incarnation-evidence", "pkg/proof/testdata/incarnation/kermit.json", "incarnation evidence")
	evidence := flag.String("evidence", "evidence_3cfb04cf.json.gz", "the live evidence, in -testdata")
	out := flag.String("out", "pkg/proof/v2/testdata/conformance", "output directory")
	flag.Parse()
	if err := run(*src, *inc, *evidence, *out); err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
}

func run(src, incPath, evidence, out string) error {
	ar, err := proofv2.UnmarshalArchive(must(gunzip(filepath.Join(src, "archive.json.gz"))))
	if err != nil {
		return err
	}
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(must(gunzip(filepath.Join(src, evidence))), ev); err != nil {
		return err
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(must(os.ReadFile(incPath)), inc); err != nil {
		return err
	}
	ir, err := inc.Verify()
	if err != nil {
		return err
	}
	p, err := proofv2.Export(ev, ar, ir.Inputs, ir.Incarnation)
	if err != nil {
		return err
	}

	// The valid case, and what any verifier must report for it: verified as another language's verifier reads it,
	// with govRoot v3 over that report and the evidence read back.
	pev, par, pin, ppin, err := proofv2.Import(p)
	if err != nil {
		return err
	}
	rep, err := proofv2.VerifyFromGenesis(pev, par, pin, ppin)
	if err != nil {
		return fmt.Errorf("the valid case does not verify: %w", err)
	}
	gin := govRootV3Inputs(rep, pev)
	govRoot, _, err := intentcert.GovRootV3(gin)
	if err != nil {
		return fmt.Errorf("the valid case's govRoot v3: %w", err)
	}
	if p.GovRootV3Inputs, err = intentcert.PortableGovRootV3Inputs(gin); err != nil {
		return err
	}
	// The suite's verifiers compute the root from the portable inputs; they must give the root the results give.
	if again, _, err := intentcert.GovRootV3FromPortable(rep, pev, p.GovRootV3Inputs); err != nil || again != govRoot {
		return fmt.Errorf("govRoot v3 from the portable inputs is %x (%v), from the results %x", again, err, govRoot)
	}
	base, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}

	var cases []Case
	write := func(name string, doc any) error {
		j, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		f, err := os.Create(filepath.Join(out, name))
		if err != nil {
			return err
		}
		defer f.Close()
		z := gzip.NewWriter(f)
		if _, err := z.Write(j); err != nil {
			return err
		}
		return z.Close()
	}

	if err := write("valid.json.gz", p); err != nil {
		return err
	}
	cases = append(cases, Case{Name: "valid", Expect: "verified", Report: &Report{
		Incarnation: fmt.Sprintf("%x", rep.Incarnation), Majors: rep.Majors, CertifiedBlock: rep.CertifiedBlock,
		CertifiedRoot: fmt.Sprintf("%x", rep.CertifiedRoot), CheckBlock: rep.CheckBlock, SetVerdict: string(rep.SetVerdict),
		Validators: rep.Validators, Threshold: rep.Threshold, Partition: rep.Partition, AnchorBlock: rep.AnchorBlock, Pages: len(rep.Pages),
		GovRootV3: fmt.Sprintf("%x", govRoot),
	}})

	// Each attack edits a fresh copy of the JSON. The Go verifier must refuse it here, or the suite is not written.
	for _, a := range attacks {
		var doc map[string]any
		if err := json.Unmarshal(base, &doc); err != nil {
			return err
		}
		if err := a.edit(doc); err != nil {
			return fmt.Errorf("%s: %w", a.name, err)
		}
		j, _ := json.Marshal(doc)
		tp := new(proofv2.Portable)
		if err := json.Unmarshal(j, tp); err == nil {
			if _, err := proofv2.VerifyPortable(tp); err == nil {
				return fmt.Errorf("%s: the Go verifier accepted it", a.name)
			}
		}
		var orig map[string]any
		_ = json.Unmarshal(base, &orig)
		patch := diff(nil, orig, doc)
		if len(patch) == 0 {
			return fmt.Errorf("%s: changed nothing", a.name)
		}
		// The patch must reproduce the attack exactly.
		replay := map[string]any{}
		_ = json.Unmarshal(base, &replay)
		if err := proofv2.ApplyPatch(replay, patch); err != nil {
			return fmt.Errorf("%s: %w", a.name, err)
		}
		r1, _ := json.Marshal(replay)
		if string(r1) != string(j) {
			return fmt.Errorf("%s: the patch does not reproduce the attack", a.name)
		}
		cases = append(cases, Case{Name: a.file, Expect: "refused", Attack: a.name, Patch: patch})
	}

	m, _ := json.MarshalIndent(map[string]any{"format": proofv2.PortableFormat, "base": "valid.json.gz", "cases": cases}, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), append(m, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d cases to %s\n", len(cases), out)
	return nil
}

// diff returns the operations that turn a into b.
func diff(path []any, a, b any) []proofv2.Op {
	at := func() []any { return append([]any(nil), path...) }
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return []proofv2.Op{{Path: at(), Set: b}}
		}
		var ops []proofv2.Op
		for _, k := range sortedKeys(av) {
			if _, ok := bv[k]; !ok {
				ops = append(ops, proofv2.Op{Path: append(at(), k), Delete: true})
			}
		}
		for _, k := range sortedKeys(bv) {
			x := bv[k]
			y, ok := av[k]
			if !ok {
				ops = append(ops, proofv2.Op{Path: append(at(), k), Set: x})
				continue
			}
			ops = append(ops, diff(append(at(), k), y, x)...)
		}
		return ops
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return []proofv2.Op{{Path: at(), Set: b}}
		}
		if len(bv) < len(av) {
			same := true
			for i := range bv {
				if len(diff(nil, av[i], bv[i])) != 0 {
					same = false
					break
				}
			}
			if same {
				n := len(bv)
				return []proofv2.Op{{Path: at(), Truncate: &n}}
			}
		}
		if len(bv) != len(av) {
			return []proofv2.Op{{Path: at(), Set: b}}
		}
		var ops []proofv2.Op
		for i := range av {
			ops = append(ops, diff(append(at(), i), av[i], bv[i])...)
		}
		return ops
	default:
		aj, _ := json.Marshal(a)
		bj, _ := json.Marshal(b)
		if string(aj) != string(bj) {
			return []proofv2.Op{{Path: at(), Set: b}}
		}
		return nil
	}
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

type attack struct {
	file, name string
	edit       func(map[string]any) error
}

var attacks = []attack{
	{"receipt-step", "a step of the transaction's receipt changed", func(d map[string]any) error {
		return flipHex(get(d, "evidence", "receipt", "entries", 3, "hash"))
	}},
	{"tx-swap", "a different transaction claimed", func(d map[string]any) error {
		return flipHex(get(d, "evidence", "txHash"))
	}},
	{"sigs-stripped", "the certifying anchor's signatures stripped (a signature-less anchor presented as certified)", func(d map[string]any) error {
		c := lastOf(get(d, "evidence", "certify"))
		return set(c, "signatures", []any{})
	}},
	{"sig-forged", "one signature on the certifying anchor forged", func(d map[string]any) error {
		c := lastOf(get(d, "evidence", "certify"))
		return flipHex(get(c, "signatures", 0, "signature"))
	}},
	{"root-fork", "the certifying run forked off the verified root", func(d map[string]any) error {
		c := lastOf(get(d, "evidence", "certify"))
		pend, _ := get(c, "rootProof", "merkleState", "pending").v.([]any)
		for i, x := range pend {
			if x != nil {
				return flipHex(ref{pend, i})
			}
		}
		return fmt.Errorf("no pending entry")
	}},
	{"major-skipped", "a major block replaced by the next one (a window skipped)", func(d map[string]any) error {
		ms, _ := d["majors"].([]any)
		ms[5] = ms[6]
		return nil
	}},
	{"archive-short", "one major block fewer than the evidence builds on", func(d map[string]any) error {
		ms, _ := d["majors"].([]any)
		d["majors"] = ms[:len(ms)-1]
		return nil
	}},
	{"anchor-major-altered", "a major block's anchor altered", func(d map[string]any) error {
		return bump(get(d, "majors", 10, "anchor", "message", "transaction", "body", "minorBlockIndex"))
	}},
	{"network-entry-altered", "the proven network account's validator set altered", func(d map[string]any) error {
		return flipHexMid(get(d, "evidence", "check", "network", "account", "entry", "data", 0))
	}},
	{"network-record-altered", "the decoded network record disagrees with the account's entry", func(d map[string]any) error {
		return flipHex(get(d, "evidence", "check", "network", "record", "validators", 0, "publicKey"))
	}},
	{"main-height-understated", "the network account's main chain height changed (an update omitted)", func(d map[string]any) error {
		chains, _ := get(d, "evidence", "check", "network", "chains").v.([]any)
		for _, c := range chains {
			cm := c.(map[string]any)
			if cm["name"] == "main" {
				p, _ := cm["pending"].([]any)
				cm["pending"] = append(p, strings.Repeat("ab", 32))
				return nil
			}
		}
		return fmt.Errorf("no main chain")
	}},
	{"set-check-majors-mismatch", "the set check's runs dropped and its spine position changed", func(d map[string]any) error {
		chk := get(d, "evidence", "check").v.(map[string]any)
		majors, ok := get(d, "evidence", "majors").v.(float64)
		if !ok || majors < 2 {
			return fmt.Errorf("evidence.majors is %v", get(d, "evidence", "majors").v)
		}
		chk["majors"] = majors - 1
		return set(chk, "hops", []any{})
	}},
	{"page-threshold", "a page's threshold changed", func(d map[string]any) error {
		return bump(get(d, "evidence", "pages", 0, "account", "acceptThreshold"))
	}},
	{"page-step-dropped", "a page proven to a different root (a receipt step dropped)", func(d map[string]any) error {
		r := get(d, "evidence", "pages", 0, "receipt").v.(map[string]any)
		es := r["entries"].([]any)
		r["entries"] = es[:len(es)-1]
		return nil
	}},
	{"page-url-swap", "a page presented as another account's", func(d map[string]any) error {
		p0 := get(d, "evidence", "pages", 0).v.(map[string]any)
		p1 := get(d, "evidence", "pages", 1).v.(map[string]any)
		p0["url"] = p1["url"]
		return nil
	}},
	{"anchor-block-altered", "the partition anchor names another block", func(d map[string]any) error {
		return bump(get(d, "evidence", "anchor", "message", "message", "transaction", "body", "minorBlockIndex"))
	}},
	{"pin-other", "another incarnation pinned", func(d map[string]any) error {
		return flipHex(get(d, "pin"))
	}},
	{"genesis-record-altered", "the genesis network record altered", func(d map[string]any) error {
		return flipHexMid(get(d, "genesis", "networkRecord"))
	}},
	{"genesis-json-altered", "the decoded genesis network disagrees with its record", func(d map[string]any) error {
		return flipHex(get(d, "genesis", "network", "validators", 0, "publicKey"))
	}},
	{"version-unknown", "a version the verifier does not know", func(d map[string]any) error {
		return set(get(d, "evidence").v.(map[string]any), "version", "1.0")
	}},
	{"format-unknown", "a portable format the verifier does not know", func(d map[string]any) error {
		d["format"] = "certen-proof-v2-accumulate-portable/0"
		return nil
	}},
}

// ref is a settable position in decoded JSON.
type ref struct {
	parent any // map[string]any or []any
	key    any // string or int
}

func (r ref) value() any {
	switch p := r.parent.(type) {
	case map[string]any:
		return p[r.key.(string)]
	case []any:
		return p[r.key.(int)]
	}
	return nil
}

func (r ref) set(v any) {
	switch p := r.parent.(type) {
	case map[string]any:
		p[r.key.(string)] = v
	case []any:
		p[r.key.(int)] = v
	}
}

type got struct {
	v   any
	ref ref
}

// get walks a path; a missing step panics, so a suite can never be written against a shape it does not have.
func get(doc any, path ...any) got {
	cur := doc
	var r ref
	for _, k := range path {
		switch c := cur.(type) {
		case map[string]any:
			ks := k.(string)
			if _, ok := c[ks]; !ok {
				panic(fmt.Sprintf("path %v: no %q", path, ks))
			}
			r, cur = ref{c, ks}, c[ks]
		case []any:
			ki := k.(int)
			if ki >= len(c) {
				panic(fmt.Sprintf("path %v: index %d of %d", path, ki, len(c)))
			}
			r, cur = ref{c, ki}, c[ki]
		default:
			panic(fmt.Sprintf("path %v: %T at %v", path, cur, k))
		}
	}
	return got{cur, r}
}

func lastOf(g got) map[string]any {
	l := g.v.([]any)
	return l[len(l)-1].(map[string]any)
}

func set(m any, k string, v any) error {
	mm, ok := m.(map[string]any)
	if !ok {
		return fmt.Errorf("not an object")
	}
	mm[k] = v
	return nil
}

func flipHex(x any) error {
	var r ref
	switch t := x.(type) {
	case got:
		r = t.ref
	case ref:
		r = t
	}
	s, ok := r.value().(string)
	if !ok || len(s) < 2 {
		return fmt.Errorf("not a hex string: %v", r.value())
	}
	c := s[len(s)-1]
	n := byte('0')
	if c == '0' {
		n = '1'
	}
	r.set(s[:len(s)-1] + string(n))
	return nil
}

func flipHexMid(g got) error {
	s, ok := g.ref.value().(string)
	if !ok || len(s) < 4 {
		return fmt.Errorf("not a hex string")
	}
	i := len(s) / 2
	c := s[i]
	n := byte('0')
	if c == '0' {
		n = '1'
	}
	g.ref.set(s[:i] + string(n) + s[i+1:])
	return nil
}

func bump(g got) error {
	f, ok := g.ref.value().(float64)
	if !ok {
		return fmt.Errorf("not a number: %v", g.ref.value())
	}
	g.ref.set(f + 1)
	return nil
}

func gunzip(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(z)
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
