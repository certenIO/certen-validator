// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
	"github.com/certen/independant-validator/pkg/finality"
)

// WP-S8-CLI (Go half): Freeze item 6 maps the six headline rows of the contract-identity verifier to CLI text and exit codes, and
// `verified_core` is never printed as, counted as or exit-coded as `verified`.

func TestCIRowsMapToTheTextAndExitCodeOfFreezeItem6(t *testing.T) {
	s6 := ci.Must(ci.CodeNotChecked, ci.RowNotCheckedS6LinkS6NotProven, map[string]any{"state": "s6_replay_unproven{reason=state_unavailable}"})
	cases := []struct {
		name string
		h    ci.Headline
		line string
		code int
	}{
		{"verified", ci.Headline{Kind: ci.HeadlineVerified, JudgedAtLevel: "finalized", RegistryLink: "registry9"},
			"contract identity: VERIFIED at finalized (registry registry9)", 0},
		{"not_applicable", ci.Headline{Kind: ci.HeadlineNotApplicable, NotApplicable: &ci.StateError{Code: "contract_identity_not_applicable", Reason: "certen_infrastructure"}},
			"contract identity: not applicable (certen_infrastructure)", 5},
		{"verified_core", ci.Headline{Kind: ci.HeadlineVerifiedCore, Open: []ci.OpenEntry{{Part: ci.JudgedS6Link, Kind: ci.OpenNotChecked, State: s6},
			{Part: ci.JudgedRegistryLink, Kind: ci.OpenNotChecked, State: &ci.StateError{Code: ci.CodeNotChecked, Reason: "no_registry_in_file"}}}},
			"contract identity: verified core, 2 open: s6_link:s6_not_proven(s6_replay_unproven{reason=state_unavailable}), registry_link:no_registry_in_file", 10},
		{"pending", ci.Headline{Kind: ci.HeadlinePending, Findings: []ci.Finding{{Part: ci.JudgedRecord}, {Part: ci.JudgedPointer}}},
			"contract identity: PENDING (state root not authenticated; 2 findings)", 20},
		{"unproven", ci.Headline{Kind: ci.HeadlineUnproven, Parts: []string{"code_identity", "record"}},
			"contract identity: UNPROVEN: code_identity, record", 30},
		{"refused", ci.Headline{Kind: ci.HeadlineRefused, First: ci.BlockMismatch("hash", "0x01", "0x02")},
			"contract identity: REFUSED: " + ci.BlockMismatch("hash", "0x01", "0x02").Error(), 40},
	}
	seen := map[int]string{}
	for _, c := range cases {
		line, code, err := renderContractIdentity(c.h)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if line != c.line || code != c.code {
			t.Errorf("%s: got %q exit %d, want %q exit %d", c.name, line, code, c.line, c.code)
		}
		if prev, dup := seen[code]; dup {
			t.Errorf("%s shares exit code %d with %s", c.name, code, prev)
		}
		seen[code] = c.name
		// the hard rule: only `verified` is exit 0 and only `verified` says VERIFIED
		if (code == 0) != (c.h.Kind == ci.HeadlineVerified) || strings.Contains(line, "VERIFIED") != (c.h.Kind == ci.HeadlineVerified) {
			t.Errorf("%s: %q exit %d breaks the verified_core rule", c.name, line, code)
		}
	}
	if _, _, err := renderContractIdentity(ci.Headline{Kind: "verified_ish"}); err == nil {
		t.Error("an unknown headline kind rendered instead of failing")
	}
	// a verified headline without its level or registry link is not rendered as verified
	if _, _, err := renderContractIdentity(ci.Headline{Kind: ci.HeadlineVerified}); err == nil {
		t.Error("a verified headline with no judged level rendered")
	}
}

func TestCICombinedExit(t *testing.T) {
	for _, c := range []struct{ s7, s8, want int }{
		{exitVerified, 0, 0}, {exitVerified, 10, 10}, {exitVerified, 40, 40}, {exitSummaryOnly, 0, exitSummaryOnly},
		{exitSummaryOnly, 20, 20}, {exitFailed, 0, exitFailed}, {exitFailed, 40, exitFailed}, {exitFailed, 2, exitFailed}, {exitVerified, 2, 2},
	} {
		if got := combineExit(c.s7, c.s8); got != c.want {
			t.Errorf("combineExit(S7 %d, S8 %d) = %d, want %d", c.s7, c.s8, got, c.want)
		}
	}
}

// ---- the real verifier over the published vector sets, through the CLI function ----

func vectorsDir(set string) string {
	return filepath.Join("..", "..", "pkg", "contractidentity", "testdata", "contractidentity", "vectors", set)
}

func memberFor(t *testing.T, ctx ci.LegContext, container []byte) json.RawMessage {
	t.Helper()
	var h types.Header
	if err := rlp.DecodeBytes(ctx.Settlement.Header, &h); err != nil {
		t.Fatal(err)
	}
	d := ci.DigestOf(ctx.Chain, h.Number.Uint64(), ctx.Settlement.BlockHash, container)
	b, err := json.Marshal(map[string]any{"format": ciMemberFormat,
		"leg":      map[string]any{"chain": ctx.Chain, "blockNumber": h.Number.Uint64(), "blockHash": fmt.Sprintf("0x%x", ctx.Settlement.BlockHash)},
		"evidence": "0x" + hex.EncodeToString(container), "digest": "0x" + hex.EncodeToString(d[:])})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sampleVectors returns up to perKind materialised inputs for every expected headline kind found in the published sets.
func sampleVectors(t *testing.T, perKind int) map[string][]ci.Inputs {
	t.Helper()
	out := map[string][]ci.Inputs{}
	for _, set := range []string{"s8_int_1", "s8_int_2", "s8_int_3", "s8_2c_1", "s8_2c_2", "s8_2c_3", "s8_2b2_1", "s8_2a_1"} {
		vs, err := ci.LoadVectorSet(vectorsDir(set))
		if err != nil {
			t.Fatalf("%s: %v", set, err)
		}
		for _, v := range vs.Vectors {
			in, ok := vs.Inputs[v.ID]
			if !ok || len(in.Container) == 0 || in.ExtensionRaw != nil || in.Ctx.Settlement == nil || len(in.Ctx.Settlement.Header) == 0 {
				continue
			}
			if _, st, err := in.ResolveManifest(); err != nil || st != nil {
				continue
			}
			if k := v.Expected.Headline; len(out[k]) < perKind {
				out[k] = append(out[k], in)
			}
		}
	}
	return out
}

func TestCIRealVerifierHeadlinesThroughTheCLIFunction(t *testing.T) {
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{ci.HeadlineVerified: 0, ci.HeadlineNotApplicable: 5, ci.HeadlineVerifiedCore: 10, ci.HeadlinePending: 20,
		ci.HeadlineUnproven: 30, ci.HeadlineRefused: 40}
	samples := sampleVectors(t, 3)
	for kind, ins := range samples {
		code, known := want[kind]
		if !known {
			t.Fatalf("published vectors expect headline %q, which Freeze item 6 does not map", kind)
		}
		for _, in := range ins {
			m, st, err := in.ResolveManifest()
			if err != nil || st != nil {
				t.Fatalf("manifest: %v %v", err, st)
			}
			var out bytes.Buffer
			got := judgeContractIdentity(&out, memberFor(t, in.Ctx, in.Container), in.Ctx, m, ver)
			if got != code || !strings.HasPrefix(out.String(), "contract identity: ") {
				t.Errorf("a %s vector: exit %d, want %d\n%s", kind, got, code, out.String())
			}
			if kind == ci.HeadlineVerifiedCore && (got == 0 || strings.Contains(out.String(), "VERIFIED")) {
				t.Errorf("verified_core printed or exit-coded as verified: exit %d\n%s", got, out.String())
			}
		}
	}
	for _, k := range []string{ci.HeadlineVerifiedCore, ci.HeadlineRefused, ci.HeadlineUnproven} {
		if len(samples[k]) == 0 {
			t.Errorf("no published vector with headline %s was found to run", k)
		}
	}
	t.Logf("headline kinds exercised against the real verifier: %v", func() map[string]int {
		m := map[string]int{}
		for k, v := range samples {
			m[k] = len(v)
		}
		return m
	}())
}

func TestCIAbsentMemberIsUnprovenAll(t *testing.T) {
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	ver0 := sampleVectors(t, 1)[ci.HeadlineVerified]
	if len(ver0) == 0 {
		t.Fatal("no published verified vector to take a valid context from")
	}
	in := ver0[0]
	m, _, _ := in.ResolveManifest()
	for _, absent := range []json.RawMessage{nil, json.RawMessage("null")} {
		var out bytes.Buffer
		if code := judgeContractIdentity(&out, absent, in.Ctx, m, ver); code != 30 || out.String() != "contract identity: UNPROVEN: all\n" {
			t.Errorf("absent member %q: exit %d %q", absent, code, out.String())
		}
	}
}

// ---- hostile members: refused or an error by name, and the verifier is not reached ----

func TestCIHostileMembersNeverReachTheVerifierAndNeverPass(t *testing.T) {
	reached := 0
	trap := ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) {
		reached++
		return ci.Report{}, fmt.Errorf("the verifier must not be reached")
	})
	hash := bytes32(0x22)
	var hdr types.Header
	hdr.Number = bigU(100)
	raw, _ := rlp.EncodeToBytes(&hdr)
	ctx := ci.LegContext{Chain: 11155111, Settlement: &ethproof.Settlement{Header: raw, BlockHash: hash}}
	leg := `{"chain":11155111,"blockNumber":100,"blockHash":"0x` + strings.Repeat("22", 32) + `"}`
	ev := "0x" + hex.EncodeToString([]byte("CIE1-test-vector"))
	d := ci.DigestOf(11155111, 100, hash, []byte("CIE1-test-vector"))
	dg := "0x" + hex.EncodeToString(d[:])
	mk := func(format, legJSON, evidence, digest string, extra string) string {
		return `{"format":"` + format + `","leg":` + legJSON + `,"evidence":"` + evidence + `","digest":"` + digest + `"` + extra + `}`
	}
	max := ci.DefaultLimits().MaxContainerBytes
	cases := []struct {
		name, member string
		code         int
		text         string
	}{
		{"wrong version", mk("certen-contract-identity/2", leg, ev, dg, ""), 40, "contract identity: REFUSED: contract_identity_evidence_unrecognised{"},
		{"wrong family", mk("certen-finality-addenda/1", leg, ev, dg, ""), 40, "contract identity: REFUSED: contract_identity_evidence_unrecognised{"},
		{"oversize evidence", mk(ciMemberFormat, leg, "0x"+strings.Repeat("ab", max+1), dg, ""), 40,
			"contract identity: REFUSED: " + ci.TooLarge("container", uint64(max+1), uint64(max)).Error()},
		{"leg chain differs", mk(ciMemberFormat, strings.Replace(leg, "11155111", "1", 1), ev, dg, ""), 40, "contract identity: REFUSED: contract_identity_block_mismatch{field=\"chain\""},
		{"leg number differs", mk(ciMemberFormat, strings.Replace(leg, `"blockNumber":100`, `"blockNumber":101`, 1), ev, dg, ""), 40, "contract identity: REFUSED: contract_identity_block_mismatch{field=\"number\""},
		{"leg hash differs", mk(ciMemberFormat, strings.Replace(leg, "22", "23", 1), ev, dg, ""), 40, "contract identity: REFUSED: contract_identity_block_mismatch{field=\"hash\""},
		{"unknown member field", mk(ciMemberFormat, leg, ev, dg, `,"extra":1`), 2, "proofverify: contractIdentity member"},
		{"unknown leg field", mk(ciMemberFormat, strings.Replace(leg, "}", `,"x":1}`, 1), ev, dg, ""), 2, "proofverify: contractIdentity member"},
		{"duplicate key", mk(ciMemberFormat, leg, ev, dg, `,"digest":"`+dg+`"`), 2, "proofverify: contractIdentity member"},
		{"evidence without 0x", mk(ciMemberFormat, leg, "abcd", dg, ""), 2, "proofverify: contractIdentity member"},
		{"evidence odd length", mk(ciMemberFormat, leg, "0xabc", dg, ""), 2, "proofverify: contractIdentity member"},
		{"evidence empty", mk(ciMemberFormat, leg, "0x", dg, ""), 2, "proofverify: contractIdentity member"},
		{"evidence upper-case 0X", mk(ciMemberFormat, leg, "0Xabcd", dg, ""), 2, "proofverify: contractIdentity member"},
		{"digest wrong", mk(ciMemberFormat, leg, ev, "0x"+strings.Repeat("00", 32), ""), 2, "proofverify: contractIdentity member"},
		{"digest short", mk(ciMemberFormat, leg, ev, "0x00", ""), 2, "proofverify: contractIdentity member"},
		{"digest missing", `{"format":"` + ciMemberFormat + `","leg":` + leg + `,"evidence":"` + ev + `"}`, 2, "proofverify: contractIdentity member"},
		{"not an object", `[1]`, 2, "proofverify: contractIdentity member"},
		{"empty object", `{}`, 2, "proofverify: contractIdentity member"},
		{"leg block number as string", mk(ciMemberFormat, strings.Replace(leg, `"blockNumber":100`, `"blockNumber":"100"`, 1), ev, dg, ""), 2, "proofverify: contractIdentity member"},
	}
	for _, c := range cases {
		var out bytes.Buffer
		code := judgeContractIdentity(&out, json.RawMessage(c.member), ctx, nil, trap)
		if code != c.code || !strings.HasPrefix(out.String(), c.text) {
			t.Errorf("%s: exit %d, want %d; output %.200q", c.name, code, c.code, out.String())
		}
		if code == 0 {
			t.Errorf("%s: a hostile member exited 0", c.name)
		}
	}
	if reached != 0 {
		t.Errorf("the verifier was reached %d times by members that cannot form a container", reached)
	}
	// the bound is exact: MaxContainerBytes reaches the verifier, one more does not
	var out bytes.Buffer
	exact := bytes.Repeat([]byte{0xab}, max)
	de := ci.DigestOf(11155111, 100, hash, exact)
	if code := judgeContractIdentity(&out, json.RawMessage(mk(ciMemberFormat, leg, "0x"+hex.EncodeToString(exact), "0x"+hex.EncodeToString(de[:]), "")), ctx, nil, trap); code != 2 || reached != 1 {
		t.Errorf("a container of exactly %d bytes: exit %d, verifier reached %d times", max, code, reached)
	}
}

func TestCIVerifierErrorAndPanicAreExit2WithNoReport(t *testing.T) {
	hash := bytes32(0x22)
	var hdr types.Header
	hdr.Number = bigU(100)
	raw, _ := rlp.EncodeToBytes(&hdr)
	ctx := ci.LegContext{Chain: 11155111, Settlement: &ethproof.Settlement{Header: raw, BlockHash: hash}}
	container := []byte("CIE1-test-vector")
	member := memberFor(t, ctx, container)
	for name, v := range map[string]ci.Verifier{
		"error":        ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) { return ci.Report{}, fmt.Errorf("boom") }),
		"panic":        ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) { panic("boom") }),
		"empty report": ci.VerifierFunc(func(ci.LegContext, []byte, *ci.Manifest) (ci.Report, error) { return ci.Report{}, nil }),
	} {
		var out bytes.Buffer
		if code := judgeContractIdentity(&out, member, ctx, nil, v); code != 2 || !strings.HasPrefix(out.String(), "proofverify: ") || strings.Contains(out.String(), "contract identity:") {
			t.Errorf("%s: exit %d %q", name, code, out.String())
		}
	}
}

// ---- the S6 deriver ----

func TestDeriveS6FromTheReplayGuardVectors(t *testing.T) {
	var proven, named, refused int
	for _, v := range s6Vectors(t) {
		h, tx, ok, logs, err := v.decode()
		if err != nil {
			continue
		}
		ev, err := ethproof.DecodeReplayGuardEvidence([]byte(v.Evidence))
		if err != nil {
			continue
		}
		got := deriveS6(h, tx, ok, logs, ev)
		ref := s6replay1.Judge(v.Settlement, []byte(v.Evidence))
		switch {
		case ref.Result == s6replay1.ResultProven && ref.State == ethproof.ReplayProven:
			proven++
			if got.Status != ci.S6Proven || got.Link == nil || got.Link.Contract == ([20]byte{}) || got.Link.SettlementBlock.Number != h.Number.Uint64() || got.Link.ProvenAt.Number == 0 {
				t.Errorf("%s: proven evidence derived %+v", v.Name, got)
			}
		default:
			if _, pinned := ethproof.SettlementCallGeneration(tx.Data()); !pinned {
				if got.Status != ci.S6Silent || got.Reason != "unsupported_generation" {
					t.Errorf("%s: an unpinned call derived %+v", v.Name, got)
				}
				continue
			}
			if ref.Result == s6replay1.ResultProven {
				named++
			} else {
				refused++
			}
			if got.Status != ci.S6NotProven || got.State == "" || got.Link != nil || !strings.Contains(got.State, ref.Reason) || !strings.Contains(got.State, ref.State) {
				t.Errorf("%s (%s): a non-proof derived %+v, want s6_not_proven carrying %s{reason=%s}", v.Name, ref.Result, got, ref.State, ref.Reason)
			}
		}
	}
	if proven == 0 || named+refused == 0 {
		t.Fatalf("the vectors exercised %d proven and %d non-proof cases", proven, named+refused)
	}
	// no evidence on a pinned call: s6_silent{absent}; a call of no pinned generation: s6_silent{unsupported_generation}
	for _, v := range s6Vectors(t) {
		h, tx, ok, logs, err := v.decode()
		if err != nil {
			continue
		}
		if _, pinned := ethproof.SettlementCallGeneration(tx.Data()); pinned {
			if got := deriveS6(h, tx, ok, logs, nil); got.Status != ci.S6Silent || got.Reason != "absent" {
				t.Fatalf("%s: no evidence derived %+v", v.Name, got)
			}
			return
		}
	}
	t.Fatal("no vector with a pinned settlement call")
}

func TestFinalityFileWithTheFlagNeedsTheOutcomeEvidence(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	doc := writeDoc(t, []byte(`{"contractIdentity":null}`))
	// a Settlement from the database has no batch facts: the flag cannot be served from it
	var out bytes.Buffer
	code := reportFinalityFileCI(&out, doc, finality.Default, pins, &legSettlement{chain: 1, s: &ethproof.Settlement{}, source: "db"}, &ciRequest{verifier: ver})
	if code != exitUsage || !strings.Contains(out.String(), "--outcome-file") {
		t.Errorf("exit %d\n%s", code, out.String())
	}
	// without the flag the same document is judged exactly as before
	var plain, viaCI bytes.Buffer
	c1 := reportFinalityFile(&plain, doc, finality.Default, pins, nil)
	c2 := reportFinalityFileCI(&viaCI, doc, finality.Default, pins, nil, nil)
	if c1 != c2 || plain.String() != viaCI.String() || strings.Contains(plain.String(), "contract identity") {
		t.Errorf("the no-flag path changed: %d %q vs %d %q", c1, plain.String(), c2, viaCI.String())
	}
}

func bigU(n uint64) *big.Int { return new(big.Int).SetUint64(n) }

type s6Vector struct{ s6replay1.Vector }

func (v s6Vector) decode() (*types.Header, *types.Transaction, bool, []*types.Log, error) {
	return s6replay1.DecodeSettlement(v.Settlement)
}

func s6Vectors(t *testing.T) []s6Vector {
	t.Helper()
	var out []s6Vector
	for _, v := range s6replay1.BuildVectors() {
		out = append(out, s6Vector{v})
	}
	if len(out) == 0 {
		t.Fatal("no S6 vectors")
	}
	return out
}

func bytes32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}
