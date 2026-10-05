package intentcert

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The live Kermit proof v2 fixture (pkg/proof/v2/testdata: billing-receipts 3cfb04cf..., BVN1 block 13595785, three
// pages) under the Kermit incarnation pin.
const kermitPin = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

// The golden govRoot v3 of the fixture with goldenV3Inputs' synthetic governance results, key page, key book and
// operation id. cmd/proofv2conformance writes the same inputs into the conformance fixture, whose manifest must carry
// this value (pkg/proof/v2 TestConformanceSuite). The root, every slot and the pages root were recomputed independently
// in Python (pycryptodome keccak, hashlib sha256, Accumulate's merkle State fold) from the report's facts and the
// evidence's page bytes on 2026-10-05.
const goldenGovRootV3 = "0477ea2c8f1d2ad8d3a84a5dc3f87f241e57efc97688016f88cb4001521dcee2"

func gunzipFile(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// verifiedKermit verifies the fixture and returns the report and the evidence it verified.
func verifiedKermit(t *testing.T) (*proofv2.Report, *proofv2.Evidence) {
	t.Helper()
	ar, err := proofv2.UnmarshalArchive(gunzipFile(t, "../proof/v2/testdata/archive.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(gunzipFile(t, "../proof/v2/testdata/evidence_3cfb04cf.json.gz"), ev); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	inc := new(proof.IncarnationEvidence)
	if err := json.Unmarshal(raw, inc); err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	b, _ := hex.DecodeString(kermitPin)
	copy(pin[:], b)
	rep, err := proofv2.Verify(ev, ar, inc, pin)
	if err != nil {
		t.Fatal(err)
	}
	return rep, ev
}

// goldenV3Inputs are fixed synthetic governance results (the slots commit sha256 of their canonical v2 JSON, so any
// fixed value pins the layout) with a fixed key page, key book and operation id.
func goldenV3Inputs(rep *proofv2.Report, ev *proofv2.Evidence) GovRootV3Inputs {
	g0 := proof.G0Result{Scope: "acc://govroot-v3-golden.acme", Chain: "main", Principal: "acc://govroot-v3-golden.acme", G0ProofComplete: true}
	g1 := proof.G1Result{G0Result: g0, RequiredThreshold: 1, UniqueValidKeys: 1, ThresholdSatisfied: true, G1ProofComplete: true}
	g2 := proof.G2Result{G1Result: g1, PayloadVerified: true, EffectVerified: true, G2ProofComplete: true}
	return GovRootV3Inputs{Report: rep, Evidence: ev, G0: &g0, G1: &g1, G2: &g2,
		KeyPageURL: "acc://govroot-v3-golden.acme/book/1", KeyBookURL: "acc://govroot-v3-golden.acme/book", OperationID: [32]byte{7}}
}

// Pins govRoot v3 of the live fixture and each of its slots: a change to any slot's tag, field order or width, to
// the pages root, or to which report fact feeds a slot, changes one of these.
func TestGovRootV3_GoldenKermit(t *testing.T) {
	rep, ev := verifiedKermit(t)
	root, slots, err := GovRootV3(goldenV3Inputs(rep, ev))
	if err != nil {
		t.Fatal(err)
	}
	pages, err := PagesRootV3(rep, ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		name string
		got  [32]byte
		want string
	}{
		{"pagesRoot", pages, "098140cec776ff0e54890ba7e1524fc1a5df4bf67406fbaf700edf78e2f5842d"},
		{"L1", slots.L1AccountHash, "f121d4b96688a1c64d61cff382bd887d075eee5be8bf8dd35d1a263667adb02a"},
		{"L2", slots.L2BPTRoot, "1b602cf696b9809f9d9a3a0516fa70115df922495e394e26005909969b5125cb"},
		{"L3", slots.L3BlockHash, "b89a9fb22a6b03621c37441ae5576f21bd69544920cfa9543895f4428f0f8c01"},
		{"L4", slots.L4ConsensusProofH, "219ae1d36a27a5fd21fb9ce15a9614cd72cb268f1c7571be04481f0b25de2730"},
		{"G0", slots.G0CanonicalHash, "b8b04f234b4010ac19bca4e5d536dd020963f86cb76d125398bfe474fd9bd492"},
		{"G1", slots.G1CanonicalHash, "158ab6196ec3797b1356af9aa5c24a54a088ce40a2d4d58f187db9c2b0ee2fd4"},
		{"G2", slots.G2CanonicalHash, "12a810adc09cc3d31f9b08307c15cc70d5c0475ba00339b026d8592b5dc5961c"},
		{"key page", slots.KeypageURLHash, "7c57efb65d2b0b2c0b656d95a1e0d9a37b8235b244188bcaa1ba1aa9c3b4fab1"},
		{"key book", slots.KeybookURLHash, "9150443fb53795d49b65b3f1a87332cbb8f7a260deeca6ff21a2fea97280487c"},
		{"operation id", slots.OperationID, "0700000000000000000000000000000000000000000000000000000000000000"},
	} {
		if got := hex.EncodeToString(s.got[:]); got != s.want {
			t.Errorf("%s: got %s want %s", s.name, got, s.want)
		}
	}
	if got := hex.EncodeToString(root[:]); got != goldenGovRootV3 {
		t.Fatalf("govRoot v3: got %s want %s", got, goldenGovRootV3)
	}
	// The root is the contracts layer's over these slots, and differs from v2's over the same slots.
	if again, err := contracts.ComputeAccumulateGovRootV3(slots); err != nil || again != root {
		t.Fatalf("recomputed %x, %v", again, err)
	}
	if v2, _ := contracts.ComputeAccumulateGovRootV2(slots); v2 == root {
		t.Fatal("govRoot v3 equals v2 over the same slots")
	}
}

// Pins that every input is required and each refusal is named: no silently-zero slot, no pages-less G1 (the one
// named G1 refusal), no weaker set verdict, no evidence that disagrees with the report.
func TestGovRootV3_RefusesIncompleteInputs(t *testing.T) {
	rep, ev := verifiedKermit(t)
	for name, c := range map[string]struct {
		mut  func(in *GovRootV3Inputs)
		want string
	}{
		"no report":         {func(in *GovRootV3Inputs) { in.Report = nil }, "no verified proof v2 report"},
		"no evidence":       {func(in *GovRootV3Inputs) { in.Evidence = nil }, "needs the verified report and its evidence"},
		"no G0":             {func(in *GovRootV3Inputs) { in.G0 = nil }, "no G0 result"},
		"no G1":             {func(in *GovRootV3Inputs) { in.G1 = nil }, "no G1 result"},
		"no G2":             {func(in *GovRootV3Inputs) { in.G2 = nil }, "no G2 result"},
		"no key page":       {func(in *GovRootV3Inputs) { in.KeyPageURL = "" }, "the key page slot is required"},
		"no key book":       {func(in *GovRootV3Inputs) { in.KeyBookURL = "" }, "the key book slot is required"},
		"no operation id":   {func(in *GovRootV3Inputs) { in.OperationID = [32]byte{} }, "the operation id slot is required"},
		"no tx hash":        {func(in *GovRootV3Inputs) { r := *in.Report; r.TxHash = [32]byte{}; in.Report = &r }, "the transaction hash is required"},
		"no anchor tx hash": {func(in *GovRootV3Inputs) { r := *in.Report; r.AnchorTxHash = [32]byte{}; in.Report = &r }, "the partition anchor transaction hash is required"},
		"no state root":     {func(in *GovRootV3Inputs) { r := *in.Report; r.AnchorStateRoot = [32]byte{}; in.Report = &r }, "the partition state tree anchor is required"},
		"no certified root": {func(in *GovRootV3Inputs) { r := *in.Report; r.CertifiedRoot = [32]byte{}; in.Report = &r }, "the certified root chain anchor is required"},
		"no set root":       {func(in *GovRootV3Inputs) { r := *in.Report; r.AccumulateSetRoot = [32]byte{}; in.Report = &r }, "the accumulate set root is required"},
		"no incarnation":    {func(in *GovRootV3Inputs) { r := *in.Report; r.Incarnation = [32]byte{}; in.Report = &r }, "the incarnation is required"},
		"no anchor block":   {func(in *GovRootV3Inputs) { r := *in.Report; r.AnchorBlock = 0; in.Report = &r }, "no anchor block"},
		"set only asserted": {func(in *GovRootV3Inputs) {
			r := *in.Report
			r.SetVerdict = proof.VerdictValidatorSetAsserted
			in.Report = &r
		}, "validator_set_asserted, not verified"},
		"no captured pages":  {func(in *GovRootV3Inputs) { r := *in.Report; r.Pages, r.PageChains = nil, nil; in.Report = &r }, G1HistoricalUnavailable},
		"evidence page gone": {func(in *GovRootV3Inputs) { e := *in.Evidence; e.Pages = e.Pages[1:]; in.Evidence = &e }, "the evidence carries 2"},
		"evidence state differs": {func(in *GovRootV3Inputs) {
			e := *in.Evidence
			e.Pages = append([]proofv2.PageState(nil), e.Pages...)
			e.Pages[0].State = e.Pages[0].State[:len(e.Pages[0].State)-2]
			in.Evidence = &e
		}, "not the account the report proved"},
		"evidence page swapped": {func(in *GovRootV3Inputs) {
			e := *in.Evidence
			e.Pages = append([]proofv2.PageState(nil), e.Pages...)
			e.Pages[0], e.Pages[1] = e.Pages[1], e.Pages[0]
			in.Evidence = &e
		}, "its evidence"},
	} {
		in := goldenV3Inputs(rep, ev)
		c.mut(&in)
		_, _, err := GovRootV3(in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
}

// cloneReport copies a report deeply enough to change its page lists independently.
func cloneReport(r *proofv2.Report) *proofv2.Report {
	c := *r
	c.Pages = append(c.Pages[:0:0], r.Pages...)
	c.PageChains = append(c.PageChains[:0:0], r.PageChains...)
	return &c
}

// Pins that the root depends on every input: changing any single one, each report fact the slots commit, each page's
// bound byte and main height, changes the root.
func TestGovRootV3_EveryInputChangesTheRoot(t *testing.T) {
	rep, ev := verifiedKermit(t)
	base, _, err := GovRootV3(goldenV3Inputs(rep, ev))
	if err != nil {
		t.Fatal(err)
	}
	// The fixture's pages were captured without their chains, so all are unbound (bound 0, height 0); the bound cases
	// mark one bound, as a page whose chains Verify proved would be.
	for _, pc := range rep.PageChains {
		if pc.Bound {
			t.Fatal("the fixture now has a bound page; revisit the bound cases below")
		}
	}
	flip := func(h [32]byte) [32]byte { h[31] ^= 1; return h }
	for name, mut := range map[string]func(in *GovRootV3Inputs){
		"tx hash":           func(in *GovRootV3Inputs) { in.Report.TxHash = flip(in.Report.TxHash) },
		"anchor tx hash":    func(in *GovRootV3Inputs) { in.Report.AnchorTxHash = flip(in.Report.AnchorTxHash) },
		"anchor block":      func(in *GovRootV3Inputs) { in.Report.AnchorBlock++ },
		"state root":        func(in *GovRootV3Inputs) { in.Report.AnchorStateRoot = flip(in.Report.AnchorStateRoot) },
		"certified root":    func(in *GovRootV3Inputs) { in.Report.CertifiedRoot = flip(in.Report.CertifiedRoot) },
		"certified block":   func(in *GovRootV3Inputs) { in.Report.CertifiedBlock++ },
		"set root":          func(in *GovRootV3Inputs) { in.Report.AccumulateSetRoot = flip(in.Report.AccumulateSetRoot) },
		"incarnation":       func(in *GovRootV3Inputs) { in.Report.Incarnation = flip(in.Report.Incarnation) },
		"G0":                func(in *GovRootV3Inputs) { g := *in.G0; g.Chain = "other"; in.G0 = &g },
		"G1":                func(in *GovRootV3Inputs) { g := *in.G1; g.RequiredThreshold++; in.G1 = &g },
		"G2":                func(in *GovRootV3Inputs) { g := *in.G2; g.SecurityLevel = "other"; in.G2 = &g },
		"key page":          func(in *GovRootV3Inputs) { in.KeyPageURL += "x" },
		"key book":          func(in *GovRootV3Inputs) { in.KeyBookURL += "x" },
		"operation id":      func(in *GovRootV3Inputs) { in.OperationID = flip(in.OperationID) },
		"page bound":        func(in *GovRootV3Inputs) { in.Report.PageChains[0].Bound, in.Report.PageChains[0].MainHeight = true, 0 },
		"page bound height": func(in *GovRootV3Inputs) { in.Report.PageChains[0].Bound, in.Report.PageChains[0].MainHeight = true, 1 },
		"page dropped":      func(in *GovRootV3Inputs) { trimPages(in, 1) },
	} {
		in := goldenV3Inputs(cloneReport(rep), ev)
		mut(&in)
		got, _, err := GovRootV3(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got == base {
			t.Errorf("%s: the root did not change", name)
		}
	}
}

// trimPages drops the first n pages from the report and its evidence alike.
func trimPages(in *GovRootV3Inputs, n int) {
	in.Report.Pages, in.Report.PageChains = in.Report.Pages[n:], in.Report.PageChains[n:]
	e := *in.Evidence
	e.Pages = e.Pages[n:]
	in.Evidence = &e
}

// Pins that the pages are committed in canonical URL order, not capture order: every permutation of the fixture's
// pages gives one root.
func TestGovRootV3_PageOrderIndependent(t *testing.T) {
	rep, ev := verifiedKermit(t)
	base, _, err := GovRootV3(goldenV3Inputs(rep, ev))
	if err != nil {
		t.Fatal(err)
	}
	for _, perm := range [][]int{{0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		r := cloneReport(rep)
		e := *ev
		e.Pages = make([]proofv2.PageState, len(perm))
		for i, j := range perm {
			r.Pages[i], r.PageChains[i], e.Pages[i] = rep.Pages[j], rep.PageChains[j], ev.Pages[j]
		}
		got, _, err := GovRootV3(goldenV3Inputs(r, &e))
		if err != nil {
			t.Fatal(err)
		}
		if got != base {
			t.Fatalf("order %v: %x, capture order %x", perm, got, base)
		}
	}
}

// Pins the unbound page's record: bound 0 with main height 0. An unbound page commits a different root from the same
// page bound (even at height 0, so the bound byte itself is committed), a bound page's main height is committed, and
// an unbound page's main height (which nothing proved) is not.
func TestGovRootV3_UnboundPageIsNamedInTheCommitment(t *testing.T) {
	rep, ev := verifiedKermit(t)
	unbound, err := PagesRootV3(rep, ev)
	if err != nil {
		t.Fatal(err)
	}
	root := func(bound bool, height uint64) [32]byte {
		r := cloneReport(rep)
		r.PageChains[0].Bound, r.PageChains[0].MainHeight = bound, height
		h, err := PagesRootV3(r, ev)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if root(false, 0) != unbound {
		t.Fatal("the fixture's first page is not unbound at height 0")
	}
	if root(true, 0) == unbound {
		t.Fatal("the bound byte is not committed")
	}
	if root(true, 1) == root(true, 2) {
		t.Fatal("a bound page's main height is not committed")
	}
	if root(false, 99) != unbound {
		t.Fatal("an unbound page's main height reached the commitment")
	}
}

// Pins that the hashes path the conformance suite uses is the same computation as GovRoot V3 itself.
func TestGovRootV3_FromPortableMatches(t *testing.T) {
	rep, ev := verifiedKermit(t)
	in := goldenV3Inputs(rep, ev)
	want, _, err := GovRootV3(in)
	if err != nil {
		t.Fatal(err)
	}
	p, err := PortableGovRootV3Inputs(in)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := GovRootV3FromPortable(rep, ev, p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("portable %x, direct %x", got, want)
	}
	p.G1Hash = p.G0Hash
	if other, _, err := GovRootV3FromPortable(rep, ev, p); err != nil || other == want {
		t.Fatalf("a changed portable input kept the root: %v", err)
	}
	if _, _, err := GovRootV3FromPortable(rep, ev, &proofv2.PortableGovRootV3Inputs{}); err == nil {
		t.Fatal("empty portable inputs accepted")
	}
}
