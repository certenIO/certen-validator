// Copyright 2026 Certen Protocol
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/finality"
)

// EPS-MUTKILL-6: literal-expectation tests for the contract-identity CLI code (render rows, strict member parser, hex fields, S6 deriver,
// judge, no-evidence rewrite). Every refusal is pinned by its exact text so a mutant that turns one guard off cannot hide behind another.

// wantText compares exactly, or by prefix when the expectation starts with "~" (library error texts).
func wantText(t *testing.T, name, got, want string) {
	t.Helper()
	if strings.HasPrefix(want, "~") {
		if !strings.HasPrefix(got, want[1:]) {
			t.Errorf("%s: %q, want prefix %q", name, got, want[1:])
		}
		return
	}
	if got != want {
		t.Errorf("%s: %q, want %q", name, got, want)
	}
}

func TestCIRenderPrintsEveryRowLiterallyAndRefusesAHeadlineThatDoesNotCarryIt(t *testing.T) {
	s6 := func(f map[string]any, code string) *ci.StateError {
		return &ci.StateError{Code: code, Reason: "rsn", Fields: f}
	}
	cases := []struct {
		name, line, err string
		h               ci.Headline
		code            int
	}{
		{name: "verified without level", h: ci.Headline{Kind: ci.HeadlineVerified, RegistryLink: "r9"},
			err: `a verified headline names no judged level or registry link (level "", registry "r9")`},
		{name: "verified without registry", h: ci.Headline{Kind: ci.HeadlineVerified, JudgedAtLevel: "finalized"},
			err: `a verified headline names no judged level or registry link (level "finalized", registry "")`},
		{name: "verified", h: ci.Headline{Kind: ci.HeadlineVerified, JudgedAtLevel: "finalized", RegistryLink: "r9"},
			line: "contract identity: VERIFIED at finalized (registry r9)", code: 0},
		{name: "not applicable without state", h: ci.Headline{Kind: ci.HeadlineNotApplicable}, err: "a not_applicable headline carries no state"},
		{name: "not applicable reason", h: ci.Headline{Kind: ci.HeadlineNotApplicable, NotApplicable: &ci.StateError{Code: "the_code", Reason: "the_reason"}},
			line: "contract identity: not applicable (the_reason)", code: 5},
		{name: "not applicable code fallback", h: ci.Headline{Kind: ci.HeadlineNotApplicable, NotApplicable: &ci.StateError{Code: "the_code"}},
			line: "contract identity: not applicable (the_code)", code: 5},
		{name: "core without entry", h: ci.Headline{Kind: ci.HeadlineVerifiedCore}, err: "a verified_core headline carries no open entry"},
		{name: "core entry without state", h: ci.Headline{Kind: ci.HeadlineVerifiedCore, Open: []ci.OpenEntry{{Part: "registry_link"}}},
			err: "an open entry of part registry_link carries no state"},
		{name: "core s6 state", code: 10, line: "contract identity: verified core, 1 open: s6_link:s6_not_proven(sx)",
			h: ci.Headline{Kind: ci.HeadlineVerifiedCore, Open: []ci.OpenEntry{{Part: ci.JudgedS6Link, State: s6(map[string]any{"state": "sx"}, ci.CodeNotChecked)}}}},
		{name: "core s6 non-string state", code: 10, line: "contract identity: verified core, 1 open: s6_link:rsn",
			h: ci.Headline{Kind: ci.HeadlineVerifiedCore, Open: []ci.OpenEntry{{Part: ci.JudgedS6Link, State: s6(map[string]any{"state": 7}, ci.CodeNotChecked)}}}},
		{name: "core s6 other code", code: 10, line: "contract identity: verified core, 1 open: s6_link:rsn",
			h: ci.Headline{Kind: ci.HeadlineVerifiedCore, Open: []ci.OpenEntry{{Part: ci.JudgedS6Link, State: s6(map[string]any{"state": "sx"}, "other_code")}}}},
		{name: "core other part with state field", code: 10, line: "contract identity: verified core, 1 open: registry_link:rsn",
			h: ci.Headline{Kind: ci.HeadlineVerifiedCore, Open: []ci.OpenEntry{{Part: ci.JudgedRegistryLink, State: s6(map[string]any{"state": "sx"}, ci.CodeNotChecked)}}}},
		{name: "core code fallback and two entries", code: 10, line: "contract identity: verified core, 2 open: registry_link:c1, s6_link:rsn",
			h: ci.Headline{Kind: ci.HeadlineVerifiedCore, Open: []ci.OpenEntry{{Part: ci.JudgedRegistryLink, State: &ci.StateError{Code: "c1"}},
				{Part: ci.JudgedS6Link, State: s6(nil, "c2")}}}},
		{name: "pending", h: ci.Headline{Kind: ci.HeadlinePending, Findings: make([]ci.Finding, 2)},
			line: "contract identity: PENDING (state root not authenticated; 2 findings)", code: 20},
		{name: "unproven without part", h: ci.Headline{Kind: ci.HeadlineUnproven}, err: "an unproven headline names no part"},
		{name: "unproven", h: ci.Headline{Kind: ci.HeadlineUnproven, Parts: []string{"a", "b"}}, line: "contract identity: UNPROVEN: a, b", code: 30},
		{name: "refused without first", h: ci.Headline{Kind: ci.HeadlineRefused}, err: "a refused headline names no first refusal"},
		{name: "unknown kind", h: ci.Headline{Kind: "zzz"}, err: `unknown headline kind "zzz"`},
	}
	for _, c := range cases {
		line, code, err := renderContractIdentity(c.h)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != c.err || line != c.line || code != c.code {
			t.Errorf("%s: line %q code %d err %q, want line %q code %d err %q", c.name, line, code, got, c.line, c.code, c.err)
		}
	}
	first := ci.Unrecognised("x/9")
	line, code, err := renderContractIdentity(ci.Headline{Kind: ci.HeadlineRefused, First: first})
	if err != nil || code != 40 || line != "contract identity: REFUSED: "+first.Error() {
		t.Errorf("refused: %q %d %v", line, code, err)
	}
}

func TestCIStrictObjectNamesEachDefectOfTheMemberText(t *testing.T) {
	for _, c := range []struct{ in, err string }{
		{"", "not a JSON object"},
		{"[1]", "not a JSON object"},
		{"7", "not a JSON object"},
		{`{"a":1,"a":2}`, `duplicate key "a"`},
		{`{"a":1} x`, "trailing data after the object"},
		{`{1:2}`, "~invalid character '1'"},
		{`{"a":}`, "~invalid character '}' looking for beginning of value"},
		{`{"a":1`, "~"},
	} {
		m, err := strictObject([]byte(c.in))
		if err == nil || m != nil {
			t.Errorf("%q: accepted (%v, %v)", c.in, m, err)
			continue
		}
		if c.err != "~" {
			wantText(t, c.in, err.Error(), c.err)
		}
	}
	m, err := strictObject([]byte(`{"a":1,"b":"x"}`))
	if err != nil || len(m) != 2 || string(m["a"]) != "1" || string(m["b"]) != `"x"` {
		t.Errorf("a clean object: %v %v", m, err)
	}
	if m, err = strictObject([]byte(`{}`)); err != nil || len(m) != 0 {
		t.Errorf("an empty object: %v %v", m, err)
	}
}

func TestCIHexFieldNamesEachDefect(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"ab", 0, "x is not 0x-prefixed hex"},
		{"0Xab", 0, "x is not 0x-prefixed hex"},
		{"0xzz", 0, "~x is not hex: "},
		{"0xabc", 0, "~x is not hex: "},
		{"0xab", 2, "x is 1 bytes, want 2"},
		{"0xabab", 1, "x is 2 bytes, want 1"},
		{"0x", 32, "x is 0 bytes, want 32"},
		{"0x", 0, "x is empty"},
	} {
		b, err := hexField(c.in, "x", c.n)
		if err == nil || b != nil {
			t.Errorf("%q/%d accepted: %x", c.in, c.n, b)
			continue
		}
		wantText(t, c.in, err.Error(), c.want)
	}
	for _, c := range []struct {
		in string
		n  int
	}{{"0xab", 0}, {"0xab", 1}, {"0xabcd", 2}} {
		b, err := hexField(c.in, "x", c.n)
		if err != nil || !bytes.Equal(b, mustHex(t, c.in[2:])) {
			t.Errorf("%q/%d: %x %v", c.in, c.n, b, err)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ciMutCtx() (ci.LegContext, [32]byte) {
	hash := bytes32(0x22)
	var hdr types.Header
	hdr.Number = bigU(100)
	raw, _ := rlp.EncodeToBytes(&hdr)
	return ci.LegContext{Chain: 11155111, Settlement: &ethproof.Settlement{Header: raw, BlockHash: hash}}, hash
}

func TestCIParseMemberRefusesEachDefectWithItsOwnText(t *testing.T) {
	ctx, hash := ciMutCtx()
	lim := ci.DefaultLimits()
	legJSON := `{"chain":11155111,"blockNumber":100,"blockHash":"0x` + strings.Repeat("22", 32) + `"}`
	ev := "0x" + hex.EncodeToString([]byte("CIE1-test-vector"))
	d := ci.DigestOf(11155111, 100, hash, []byte("CIE1-test-vector"))
	dg := "0x" + hex.EncodeToString(d[:])
	mk := func(leg, evidence, digest string) string {
		return `{"format":"` + ciMemberFormat + `","leg":` + leg + `,"evidence":` + evidence + `,"digest":` + digest + `}`
	}
	q := func(s string) string { return `"` + s + `"` }
	legWith := func(old, new string) string { return strings.Replace(legJSON, old, new, 1) }
	fmtErr := fmt.Sprintf("format is not a printable ASCII string of 1 to %d bytes", lim.MaxKindBytes)
	cases := []struct{ name, member, err string }{
		{"not an object", `[1]`, "not a JSON object"},
		{"empty object", `{}`, "format is not a string"},
		{"format number", `{"format":5}`, "format is not a string"},
		{"format empty", `{"format":""}`, fmtErr},
		{"format over the bound", `{"format":"` + strings.Repeat("a", lim.MaxKindBytes+1) + `"}`, fmtErr},
		{"format control byte inside", `{"format":"a\u001fb"}`, fmtErr},
		{"format control byte alone", `{"format":"\u001f"}`, fmtErr},
		{"format DEL inside", `{"format":"a\u007fb"}`, fmtErr},
		{"format non ASCII", `{"format":"é"}`, fmtErr},
		{"unknown member key", mk(legJSON, q(ev), q(dg))[:len(mk(legJSON, q(ev), q(dg)))-1] + `,"x":1}`, `unknown key "x"`},
		{"missing leg", `{"format":"` + ciMemberFormat + `","evidence":"` + ev + `","digest":"` + dg + `"}`, "missing leg"},
		{"missing evidence", `{"format":"` + ciMemberFormat + `","leg":` + legJSON + `,"digest":"` + dg + `"}`, "missing evidence"},
		{"missing digest", `{"format":"` + ciMemberFormat + `","leg":` + legJSON + `,"evidence":"` + ev + `"}`, "missing digest"},
		{"evidence number", mk(legJSON, `1`, q(dg)), "evidence is not a string"},
		{"digest number", mk(legJSON, q(ev), `1`), "digest is not a string"},
		{"leg not an object", mk(`5`, q(ev), q(dg)), "leg: not a JSON object"},
		{"leg unknown key", mk(legWith("}", `,"x":1}`), q(ev), q(dg)), `leg: unknown key "x"`},
		{"leg missing chain", mk(`{"blockNumber":100,"blockHash":"0x`+strings.Repeat("22", 32)+`"}`, q(ev), q(dg)), "leg: missing chain"},
		{"leg missing number", mk(`{"chain":1,"blockHash":"0x`+strings.Repeat("22", 32)+`"}`, q(ev), q(dg)), "leg: missing blockNumber"},
		{"leg missing hash", mk(`{"chain":1,"blockNumber":100}`, q(ev), q(dg)), "leg: missing blockHash"},
		{"leg chain string", mk(legWith("11155111", `"x"`), q(ev), q(dg)), "~leg.chain: json: cannot unmarshal string into Go value of type uint64"},
		{"leg hash not hex prefixed", mk(legWith("0x2222", "2222"), q(ev), q(dg)), "leg.blockHash is not 0x-prefixed hex"},
		{"leg hash short", mk(legWith(strings.Repeat("22", 32), "00"), q(ev), q(dg)), "leg.blockHash is 1 bytes, want 32"},
		{"evidence not prefixed", mk(legJSON, `"abcd"`, q(dg)), "evidence is not 0x-prefixed hex"},
		{"evidence odd", mk(legJSON, `"0xabc"`, q(dg)), "~evidence is not hex: "},
		{"evidence empty", mk(legJSON, `"0x"`, q(dg)), "evidence is empty"},
		{"evidence oversize without prefix", mk(legJSON, `"`+strings.Repeat("a", 2*lim.MaxContainerBytes+2)+`"`, q(dg)), "evidence is not 0x-prefixed hex"},
		{"digest not prefixed", mk(legJSON, q(ev), `"abcd"`), "digest is not 0x-prefixed hex"},
		{"digest short", mk(legJSON, q(ev), `"0x00"`), "digest is 1 bytes, want 32"},
		{"digest wrong", mk(legJSON, q(ev), q("0x"+strings.Repeat("00", 32))), "~digest 0x0000000000000000000000000000000000000000000000000000000000000000 is not the container's digest under the leg (0x"},
	}
	for _, c := range cases {
		m, st, err := parseCIMember([]byte(c.member), ctx)
		if m != nil || st != nil || err == nil {
			t.Errorf("%s: accepted or stated (%v, %v, %v)", c.name, m, st, err)
			continue
		}
		wantText(t, c.name, err.Error(), c.err)
	}

	// a format of another kind is a named state (never an error) while it is printable ASCII of 1..MaxKindBytes
	for _, f := range []string{"a", "a b", "a~b", "other/2", strings.Repeat("a", lim.MaxKindBytes)} {
		b, _ := json.Marshal(map[string]string{"format": f})
		m, st, err := parseCIMember(b, ctx)
		if m != nil || err != nil || st == nil || st.Error() != ci.Unrecognised(f).Error() {
			t.Errorf("format %q: %v %v %v", f, m, st, err)
		}
	}

	// the container bound is exact on the decoded size, counted from the hex text (an odd length counts its half byte)
	for _, n := range []int{2*lim.MaxContainerBytes + 1, 2*lim.MaxContainerBytes + 2} {
		m, st, err := parseCIMember([]byte(mk(legJSON, `"0x`+strings.Repeat("a", n)+`"`, q(dg))), ctx)
		want := ci.TooLarge("container", uint64(lim.MaxContainerBytes+1), uint64(lim.MaxContainerBytes))
		if m != nil || err != nil || st == nil || st.Error() != want.Error() {
			t.Errorf("hex length %d: %v %v %v", n, m, st, err)
		}
	}

	// the clean member parses, with or without a Settlement to bind the leg to
	good := mk(legJSON, q(ev), q(dg))
	for _, c := range []ci.LegContext{ctx, {Chain: 11155111}, {Chain: 7, Settlement: &ethproof.Settlement{}}} {
		m, st, err := parseCIMember([]byte(good), c)
		if err != nil || st != nil || m == nil || m.chain != 11155111 || m.number != 100 || m.hash != hash || string(m.container) != "CIE1-test-vector" || m.digest != d {
			t.Errorf("a clean member in %+v: %+v %v %v", c.Settlement, m, st, err)
		}
	}

	// a Settlement header that does not decode in full binds nothing: the partial Number of a truncated header is not a block
	type nine struct {
		A, B    [32]byte
		C       [20]byte
		D, E, F [32]byte
		G       [256]byte
		H, N    interface{}
	}
	trunc, err := rlp.EncodeToBytes(&nine{H: bigU(0), N: bigU(999)})
	if err != nil {
		t.Fatal(err)
	}
	var probe types.Header
	if rlp.DecodeBytes(trunc, &probe) == nil {
		t.Fatal("the truncated header decodes in full")
	}
	m, st, err := parseCIMember([]byte(good), ci.LegContext{Chain: 11155111, Settlement: &ethproof.Settlement{Header: trunc, BlockHash: bytes32(0x99)}})
	if err != nil || st != nil || m == nil {
		t.Errorf("a member bound to an undecodable header: %v %v %v", m, st, err)
	}
	// and a short undecodable header (one byte) binds nothing either
	for _, h := range [][]byte{{0xc0}, {0x01}} {
		m, st, err = parseCIMember([]byte(good), ci.LegContext{Chain: 3, Settlement: &ethproof.Settlement{Header: h}})
		if err != nil || st != nil || m == nil {
			t.Errorf("a member bound to header %x: %v %v %v", h, m, st, err)
		}
	}
}

func TestCIJudgeSaysExactlyWhyItStoppedAndRewritesOnlyAReportOfNoEvidence(t *testing.T) {
	ctx, _ := ciMutCtx()
	noEv := ci.PartResult{Part: ci.JudgedS6Link, Status: ci.StatusUnproven, State: &ci.StateError{Code: ci.CodeNotChecked, Reason: ci.UnprovenNoEvidence, Fields: map[string]any{"part": ci.UnprovenPartAll}}}
	with := func(f func(p *ci.PartResult)) ci.PartResult { p := noEv; f(&p); return p }
	unproven := func(parts ...ci.PartResult) ci.Verifier {
		return ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
			return ci.Report{Headline: ci.Headline{Kind: ci.HeadlineUnproven, Parts: []string{"p1", "p2"}}, Parts: parts}, nil
		})
	}
	run := func(v ci.Verifier, member string) (string, int) {
		var out bytes.Buffer
		c := judgeContractIdentity(&out, json.RawMessage(member), ctx, nil, v)
		return out.String(), c
	}
	for _, c := range []struct {
		name  string
		v     ci.Verifier
		parts string
	}{
		{"all parts say no evidence", unproven(noEv, noEv), "all"},
		{"one part", unproven(noEv), "all"},
		{"no parts at all", unproven(), "p1, p2"},
		{"one part is refused", unproven(noEv, with(func(p *ci.PartResult) { p.Status = ci.StatusRefused })), "p1, p2"},
		{"only the first is refused", unproven(with(func(p *ci.PartResult) { p.Status = ci.StatusRefused }), noEv), "p1, p2"},
		{"a refused part with the state of no evidence", unproven(with(func(p *ci.PartResult) { p.Status = ci.StatusRefused })), "p1, p2"},
		{"a part without a state", unproven(with(func(p *ci.PartResult) { p.State = nil })), "p1, p2"},
		{"another reason", unproven(with(func(p *ci.PartResult) { p.State = &ci.StateError{Reason: "other", Fields: p.State.Fields} })), "p1, p2"},
		{"another part field", unproven(with(func(p *ci.PartResult) {
			p.State = &ci.StateError{Reason: ci.UnprovenNoEvidence, Fields: map[string]any{"part": "registry"}}
		})), "p1, p2"},
		{"no part field", unproven(with(func(p *ci.PartResult) { p.State = &ci.StateError{Reason: ci.UnprovenNoEvidence} })), "p1, p2"},
	} {
		out, code := run(c.v, "")
		if want := "contract identity: UNPROVEN: " + c.parts + "\n"; out != want || code != 30 {
			t.Errorf("%s: %q exit %d, want %q exit 30", c.name, out, code, want)
		}
	}
	// the rewrite is the unproven headline's alone
	core := ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
		return ci.Report{Headline: ci.Headline{Kind: ci.HeadlineRefused, First: ci.Unrecognised("x/1")}, Parts: []ci.PartResult{noEv}}, nil
	})
	if out, code := run(core, ""); code != 40 || !strings.HasPrefix(out, "contract identity: REFUSED: ") {
		t.Errorf("a refused headline: %q %d", out, code)
	}

	// the refusals of the judge itself, each with its exact text
	trap := ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) { return ci.Report{}, fmt.Errorf("boom") })
	for _, c := range []struct{ name, member, want string }{
		{"a one byte member is a member", `1`, "proofverify: contractIdentity member: not a JSON object\n"},
		{"a verifier error", ``, "proofverify: contract identity verifier: boom\n"},
		{"a whitespace member is absent", " \n\t ", "proofverify: contract identity verifier: boom\n"},
		{"a null member is absent", `null`, "proofverify: contract identity verifier: boom\n"},
	} {
		if out, code := run(trap, c.member); out != c.want || code != 2 {
			t.Errorf("%s: %q exit %d", c.name, out, code)
		}
	}
	bad := ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
		return ci.Report{Headline: ci.Headline{Kind: ci.HeadlineVerified}}, nil
	})
	want := "proofverify: contract identity report: a verified headline names no judged level or registry link (level \"\", registry \"\")\n"
	if out, code := run(bad, ""); out != want || code != 2 {
		t.Errorf("a headline that does not carry its row: %q exit %d", out, code)
	}
	pan := ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) { panic("kaboom") })
	if out, code := run(pan, ""); out != "proofverify: contract identity verifier panicked: kaboom\n" || code != 2 {
		t.Errorf("a panicking verifier: %q exit %d", out, code)
	}
}

func TestCIDeriveS6AnAbsentTransactionOrHeaderIsSilentAbsent(t *testing.T) {
	h := &types.Header{Number: bigU(1)}
	tx := types.NewTx(&types.LegacyTx{Data: []byte{1, 2, 3, 4}})
	for _, c := range []struct {
		name string
		h    *types.Header
		tx   *types.Transaction
	}{{"no tx", h, nil}, {"no header", nil, tx}, {"neither", nil, nil}} {
		r := deriveS6(c.h, c.tx, true, nil, nil)
		if r.Status != ci.S6Silent || r.Reason != "absent" || r.Link != nil || r.State != "" {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
	if r := deriveS6(h, tx, true, nil, nil); r.Status != ci.S6Silent || r.Reason != "unsupported_generation" {
		t.Errorf("a call of no pinned generation: %+v", r)
	}
}

func TestCIReportContractIdentityFileReturnsTheS7CodeAloneForAFileItCannotReadOrParse(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(junk, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "absent.json"), junk} {
		for _, s7 := range []int{0, 1, 3} {
			var out bytes.Buffer
			if code := reportContractIdentityFile(&out, path, nil, &finality.Report{}, s7, &ciRequest{}); code != s7 || out.Len() != 0 {
				t.Errorf("%s with S7 exit %d: exit %d, output %q", filepath.Base(path), s7, code, out.String())
			}
		}
	}
	// a readable document with no outcome evidence is a usage error that names it, and S7 FAILED still wins
	ok := filepath.Join(dir, "doc.json")
	if err := os.WriteFile(ok, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for s7, want := range map[int]int{0: 2, 3: 2, 1: 1} {
		var out bytes.Buffer
		code := reportContractIdentityFile(&out, ok, nil, &finality.Report{}, s7, &ciRequest{})
		if code != want || out.String() != "proofverify: --contract-identity needs the outcome evidence (--outcome-file) as the Settlement source\n" {
			t.Errorf("S7 exit %d: exit %d %q", s7, code, out.String())
		}
	}
	for name, leg := range map[string]*legSettlement{"no ev": {s: &ethproof.Settlement{}}, "no settlement": {ev: &execution.OutcomeEvidence{}}} {
		if _, err := legContextFromOutcome(leg, nil); err == nil || err.Error() != "--contract-identity needs the outcome evidence (--outcome-file) as the Settlement source" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := legContextFromOutcome(&legSettlement{ev: &execution.OutcomeEvidence{}, s: &ethproof.Settlement{}}, nil); err == nil ||
		!strings.HasPrefix(err.Error(), "the outcome evidence settlement does not verify: ") {
		t.Errorf("a settlement that does not verify: %v", err)
	}
}

func TestCIHash32AndRegistry9FromOutcomeNameWhatIsWrong(t *testing.T) {
	h64 := "0x" + strings.Repeat("ab", 32)
	for _, c := range []struct{ in string }{{""}, {"0x"}, {"0x00"}, {"0x" + strings.Repeat("ab", 31)}, {"0x" + strings.Repeat("ab", 33)}, {"0xzz"}, {strings.Repeat("a", 63)}} {
		if _, err := hash32(c.in, "nm"); err == nil || err.Error() != "nm is not 32 bytes of hex" {
			t.Errorf("%q: %v", c.in, err)
		}
	}
	if b, err := hash32(h64, "nm"); err != nil || b != [32]byte(mustHex(t, strings.Repeat("ab", 32))) {
		t.Errorf("0x-prefixed: %x %v", b, err)
	}
	if b, err := hash32(strings.Repeat("ab", 32), "nm"); err != nil || b[0] != 0xab {
		t.Errorf("bare hex: %x %v", b, err)
	}

	ev := &execution.OutcomeEvidence{}
	if r, err := registry9FromOutcome(ev); r != nil || err != nil {
		t.Errorf("no validator set: %v %v", r, err)
	}
	ev.Quorum.ThresholdNumerator, ev.Quorum.ThresholdDenominator = 2, 3
	ev.Quorum.Validators = []execution.OutcomeQuorumValidator{{Address: "0x" + strings.Repeat("11", 20), VotingPower: "7", BLSPublicKey: "0xAB"}}
	if r, err := registry9FromOutcome(ev); r != nil || err == nil || err.Error() != "anchor.certenSetRoot is not 32 bytes of hex" {
		t.Errorf("no set root: %v %v", r, err)
	}
	ev.Anchor.CertenSetRoot = h64
	r, err := registry9FromOutcome(ev)
	if err != nil || r == nil || r.Num != 2 || r.Den != 3 || r.CertenSetRoot != [32]byte(mustHex(t, strings.Repeat("ab", 32))) || len(r.Members) != 1 ||
		r.Members[0].Power != 7 || r.Members[0].BLSKey != "ab" || r.Members[0].Address.Hex() != "0x1111111111111111111111111111111111111111" {
		t.Errorf("a one member registry: %+v %v", r, err)
	}
	ev.Quorum.Validators = append(ev.Quorum.Validators, execution.OutcomeQuorumValidator{Address: "0x" + strings.Repeat("22", 20), VotingPower: "x1"})
	if r, err := registry9FromOutcome(ev); r != nil || err == nil || err.Error() != `quorum validator 1: voting power "x1" is not a uint64` {
		t.Errorf("a power that is not a number: %v %v", r, err)
	}
}
