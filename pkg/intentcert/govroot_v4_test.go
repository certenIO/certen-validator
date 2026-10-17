package intentcert

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

const goldenV4Path = "testdata/govroot_v4/cross_partition_golden.json"

// v4Inputs are the govRoot v4 inputs of a fixture: its 2.1 report and evidence, fixed synthetic governance results (the slots
// commit sha256 of their canonical v2 JSON, so any fixed value pins the layout), a key page, key book and operation id.
func v4Inputs(f *x21) GovRootV4Inputs {
	rep, _, _, kp := f.report()
	ev := f.evidence(rep)
	g0 := proof.G0Result{Scope: xPrincipal, Chain: "main", Principal: xPrincipal, G0ProofComplete: true}
	g1 := proof.G1Result{G0Result: g0, RequiredThreshold: 1, UniqueValidKeys: 1, ThresholdSatisfied: true, G1ProofComplete: true}
	g2 := proof.G2Result{G1Result: g1, PayloadVerified: true, EffectVerified: true, G2ProofComplete: true}
	return GovRootV4Inputs{Report: rep, Evidence: ev, G0: &g0, G1: &g1, G2: &g2,
		KeyPageURL: kp, KeyBookURL: "acc://erp.acme/book", OperationID: [32]byte{7}}
}

// golden is the file's form: every committed leg, hex.
type goldenV4 struct {
	Fixture   string            `json:"fixture"`
	Inputs    map[string]string `json:"inputs"`
	PagesRoot string            `json:"pagesRoot"`
	VotesRoot string            `json:"votesRoot"`
	Slots     map[string]string `json:"slots"`
	GovRoot   string            `json:"govRootV4"`
}

func hx(b [32]byte) string { return hex.EncodeToString(b[:]) }

func computeGoldenV4(t *testing.T) *goldenV4 {
	t.Helper()
	in := v4Inputs(newX21())
	root, slots, err := GovRootV4(in)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := PagesRootV4(in.Report, in.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	votes, err := VotesRootV4(in.Evidence.Votes)
	if err != nil {
		t.Fatal(err)
	}
	h0, h1, h2, err := governanceHashesV3(in)
	if err != nil {
		t.Fatal(err)
	}
	return &goldenV4{
		Fixture:   "pkg/intentcert/x21_fixture_test.go newX21: principal on BVN1, authority book on BVN2, header book on BVN2, delegate on BVN3, initiator and certified key page on BVN3",
		Inputs:    map[string]string{"g0Hash": hx(h0), "g1Hash": hx(h1), "g2Hash": hx(h2), "keyPage": in.KeyPageURL, "keyBook": in.KeyBookURL, "operationId": hx(in.OperationID)},
		PagesRoot: hx(pages), VotesRoot: hx(votes),
		Slots: map[string]string{"L1": hx(slots.L1AccountHash), "L2": hx(slots.L2BPTRoot), "L3": hx(slots.L3BlockHash), "L4": hx(slots.L4ConsensusProofH),
			"G0": hx(slots.G0CanonicalHash), "G1": hx(slots.G1CanonicalHash), "G2": hx(slots.G2CanonicalHash),
			"keyPage": hx(slots.KeypageURLHash), "keyBook": hx(slots.KeybookURLHash), "operationId": hx(slots.OperationID)},
		GovRoot: hx(root),
	}
}

// Pins govRoot v4 of the cross-partition fixture, every slot and both roots of the G1 slot against the golden file. The file is
// specification: it is written once, by running this test with CERTEN_WRITE_GOLDENS=1 on a tree whose independent recomputation
// (TestGovRootV4_IndependentRecomputation) passes, and never rewritten to follow a change - new evidence gets a new tag and a
// new file. Without the variable the test only reads.
func TestGovRootV4_GoldenCrossPartition(t *testing.T) {
	got := computeGoldenV4(t)
	if os.Getenv("CERTEN_WRITE_GOLDENS") == "1" {
		if _, err := os.Stat(goldenV4Path); err == nil {
			t.Fatalf("%s exists: a golden is never rewritten", goldenV4Path)
		}
		if err := os.MkdirAll(filepath.Dir(goldenV4Path), 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenV4Path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(goldenV4Path)
	if err != nil {
		t.Fatalf("the golden is part of the specification and must exist: %v", err)
	}
	var want goldenV4
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got.PagesRoot != want.PagesRoot || got.VotesRoot != want.VotesRoot || got.GovRoot != want.GovRoot {
		t.Errorf("roots: got pages %s votes %s govRoot %s, golden pages %s votes %s govRoot %s",
			got.PagesRoot, got.VotesRoot, got.GovRoot, want.PagesRoot, want.VotesRoot, want.GovRoot)
	}
	for k, v := range want.Slots {
		if got.Slots[k] != v {
			t.Errorf("slot %s: got %s want %s", k, got.Slots[k], v)
		}
	}
	for k, v := range want.Inputs {
		if got.Inputs[k] != v {
			t.Errorf("input %s: got %s want %s", k, got.Inputs[k], v)
		}
	}
	if len(want.Slots) != 10 || len(want.Inputs) != 6 {
		t.Errorf("the golden pins %d slots and %d inputs, want 10 and 6", len(want.Slots), len(want.Inputs))
	}
}

// k256 and s256 are the raw hashes the independent recomputation uses.
func k256(parts ...[]byte) [32]byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	var o [32]byte
	copy(o[:], crypto.Keccak256(b))
	return o
}

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// The root, every slot, the pages root and the votes root recomputed from explicit byte layouts with raw keccak256 and sha256 -
// none of the production slot functions - and compared with what GovRootV4 returns.
func TestGovRootV4_IndependentRecomputation(t *testing.T) {
	f := newX21()
	in := v4Inputs(f)
	rep, ev := in.Report, in.Evidence
	root, slots, err := GovRootV4(in)
	if err != nil {
		t.Fatal(err)
	}
	h0, h1, h2, err := governanceHashesV3(in)
	if err != nil {
		t.Fatal(err)
	}

	// Pages: sha256(url) | sha256(state) | bound | height | sha256(partition) | block | sha256(roles), sorted by url.
	type rec struct {
		url  string
		leaf [32]byte
	}
	var recs []rec
	for i, a := range rep.Pages {
		u := strings.ToLower(a.GetUrl().String())
		state, _ := hex.DecodeString(ev.Pages[i].State)
		uh, sh := sha256.Sum256([]byte(u)), sha256.Sum256(state)
		ph := sha256.Sum256([]byte(strings.ToLower(rep.Proven[i].Partition)))
		var rs []string
		for _, r := range rep.Proven[i].Roles {
			rs = append(rs, string(r))
		}
		// The fixture lists its roles in canonical order already; sort them as the design's order to be explicit.
		order := map[string]int{"principal-chain": 0, "authority-book": 1, "authority-page": 2, "header-authority": 3, "delegate-book": 4,
			"delegate-page": 5, "voter": 6, "initiator-signer": 7, "certified-key-page": 8}
		for a := 1; a < len(rs); a++ {
			for b := a; b > 0 && order[rs[b]] < order[rs[b-1]]; b-- {
				rs[b], rs[b-1] = rs[b-1], rs[b]
			}
		}
		rh := sha256.Sum256([]byte(strings.Join(rs, ",")))
		var r []byte
		r = append(r, uh[:]...)
		r = append(r, sh[:]...)
		r = append(r, 0)         // chains unbound
		r = append(r, u64(0)...) // main height
		r = append(r, ph[:]...)
		r = append(r, u64(rep.Proven[i].Block)...)
		r = append(r, rh[:]...)
		recs = append(recs, rec{u, sha256.Sum256(r)})
	}
	for a := 1; a < len(recs); a++ {
		for b := a; b > 0 && recs[b].url < recs[b-1].url; b-- {
			recs[b], recs[b-1] = recs[b-1], recs[b]
		}
	}
	var ph merkle.Hasher
	for _, r := range recs {
		ph.AddHash2(r.leaf)
	}
	var pagesRoot [32]byte
	copy(pagesRoot[:], ph.MerkleHash())

	// Votes: sha256(json of each vote) (one vote in the fixture), merkle.
	vb, _ := json.Marshal(ev.Votes[0])
	var vh merkle.Hasher
	vh.AddHash2(sha256.Sum256(vb))
	var votesRoot [32]byte
	copy(votesRoot[:], vh.MerkleHash())

	l1 := k256([]byte("certen:l1:v3:"), rep.TxHash[:], rep.AnchorTxHash[:], u64(rep.AnchorBlock))
	l2 := k256([]byte("certen:l2:v3:"), rep.CertifiedRoot[:], u64(rep.CertifiedBlock))
	l3 := k256([]byte("certen:l3:v3:"), rep.AnchorStateRoot[:], u64(rep.AnchorBlock))
	l4 := k256([]byte("certen:l4gov:v3:"), rep.AccumulateSetRoot[:], rep.Incarnation[:], u64(rep.CertifiedBlock))
	g0 := k256([]byte("certen:g0:v3:"), h0[:], rep.TxHash[:], rep.CertifiedRoot[:])
	g1 := k256([]byte("certen:g1:v4:"), h1[:], pagesRoot[:], votesRoot[:])
	g2 := k256([]byte("certen:g2:v3:"), h2[:], g1[:])
	kp := k256([]byte(strings.ToLower(in.KeyPageURL)))
	kb := k256([]byte(strings.ToLower(in.KeyBookURL)))
	for name, c := range map[string][2][32]byte{
		"L1": {slots.L1AccountHash, l1}, "L2": {slots.L2BPTRoot, l2}, "L3": {slots.L3BlockHash, l3}, "L4": {slots.L4ConsensusProofH, l4},
		"G0": {slots.G0CanonicalHash, g0}, "G1": {slots.G1CanonicalHash, g1}, "G2": {slots.G2CanonicalHash, g2},
		"key page": {slots.KeypageURLHash, kp}, "key book": {slots.KeybookURLHash, kb}, "operation id": {slots.OperationID, in.OperationID},
	} {
		if c[0] != c[1] {
			t.Errorf("%s: production %x, independent %x", name, c[0], c[1])
		}
	}
	if p, err := PagesRootV4(rep, ev); err != nil || p != pagesRoot {
		t.Errorf("pages root: production %x (%v), independent %x", p, err, pagesRoot)
	}
	if v, err := VotesRootV4(ev.Votes); err != nil || v != votesRoot {
		t.Errorf("votes root: production %x (%v), independent %x", v, err, votesRoot)
	}
	var domain [32]byte
	copy(domain[:], "certen:govroot:v4")
	want := k256(domain[:], l1[:], l2[:], l3[:], l4[:], g0[:], g1[:], g2[:], kp[:], kb[:], in.OperationID[:])
	if root != want {
		t.Errorf("govRoot v4: production %x, independent %x", root, want)
	}
}

// The v4 tags are the ones the design names, are not used by v3, and the root is not a v3 root.
func TestGovRootV4_TagsAndDomainSeparation(t *testing.T) {
	if contracts.GovRootV4TagG1 != proofv2.DomainG1V4 || contracts.GovRootV4Domain != proofv2.DomainGovRootV4 {
		t.Fatalf("tags %q %q differ from the design's %q %q", contracts.GovRootV4TagG1, contracts.GovRootV4Domain, proofv2.DomainG1V4, proofv2.DomainGovRootV4)
	}
	if contracts.GovRootV4TagG1 == contracts.GovRootV3TagG1 || contracts.GovRootV4Domain == contracts.GovRootV3Domain {
		t.Fatal("a v4 tag is a v3 tag")
	}
	in := v4Inputs(newX21())
	v4, slots, err := GovRootV4(in)
	if err != nil {
		t.Fatal(err)
	}
	// The same inputs under v3 (which does not read partition, block, roles or votes) differ, and so do the roots over the same slots.
	v3, v3slots, err := GovRootV3(in)
	if err != nil {
		t.Fatal(err)
	}
	if v3 == v4 || v3slots.G1CanonicalHash == slots.G1CanonicalHash {
		t.Fatal("govRoot v3 and v4 over the same inputs are equal")
	}
	if again, _ := contracts.ComputeAccumulateGovRootV3(slots); again == v4 {
		t.Fatal("the v4 root equals the v3 root over the same slots")
	}
	// L1-L4 and G0 commit the same facts in the same bytes as v3.
	if v3slots.L1AccountHash != slots.L1AccountHash || v3slots.L2BPTRoot != slots.L2BPTRoot || v3slots.L3BlockHash != slots.L3BlockHash ||
		v3slots.L4ConsensusProofH != slots.L4ConsensusProofH || v3slots.G0CanonicalHash != slots.G0CanonicalHash {
		t.Fatal("a slot that commits the same facts differs between v3 and v4")
	}
}

// Pins that the root depends on every input: each report fact, each page's partition, block, roles and state, each vote, the
// pages and votes that exist.
func TestGovRootV4_EveryInputChangesTheRoot(t *testing.T) {
	base, _, err := GovRootV4(v4Inputs(newX21()))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(h [32]byte) [32]byte { h[31] ^= 1; return h }
	for name, mut := range map[string]func(in *GovRootV4Inputs){
		"tx hash":         func(in *GovRootV4Inputs) { in.Report.TxHash = flip(in.Report.TxHash) },
		"anchor tx hash":  func(in *GovRootV4Inputs) { in.Report.AnchorTxHash = flip(in.Report.AnchorTxHash) },
		"anchor block":    func(in *GovRootV4Inputs) { in.Report.AnchorBlock++ },
		"state root":      func(in *GovRootV4Inputs) { in.Report.AnchorStateRoot = flip(in.Report.AnchorStateRoot) },
		"certified root":  func(in *GovRootV4Inputs) { in.Report.CertifiedRoot = flip(in.Report.CertifiedRoot) },
		"certified block": func(in *GovRootV4Inputs) { in.Report.CertifiedBlock++ },
		"set root":        func(in *GovRootV4Inputs) { in.Report.AccumulateSetRoot = flip(in.Report.AccumulateSetRoot) },
		"incarnation":     func(in *GovRootV4Inputs) { in.Report.Incarnation = flip(in.Report.Incarnation) },
		"G0":              func(in *GovRootV4Inputs) { g := *in.G0; g.Chain = "other"; in.G0 = &g },
		"G1":              func(in *GovRootV4Inputs) { g := *in.G1; g.RequiredThreshold++; in.G1 = &g },
		"G2":              func(in *GovRootV4Inputs) { g := *in.G2; g.SecurityLevel = "other"; in.G2 = &g },
		"key page":        func(in *GovRootV4Inputs) { in.KeyPageURL += "x" },
		"key book":        func(in *GovRootV4Inputs) { in.KeyBookURL += "x" },
		"operation id":    func(in *GovRootV4Inputs) { in.OperationID = flip(in.OperationID) },
		"page bound":      func(in *GovRootV4Inputs) { in.Report.PageChains[0].Bound, in.Report.PageChains[0].MainHeight = true, 0 },
		"page bound height": func(in *GovRootV4Inputs) {
			in.Report.PageChains[0].Bound, in.Report.PageChains[0].MainHeight = true, 1
		},
		// What 2.1 adds.
		"a page's partition": func(in *GovRootV4Inputs) {
			in.Report.Proven[1].Partition = partBVN3
			in.Evidence.Pages[1].Partition = partBVN3
		},
		"a page's block": func(in *GovRootV4Inputs) { in.Report.Proven[1].Block++ },
		"a page's roles": func(in *GovRootV4Inputs) {
			in.Report.Proven[1].Roles = []proofv2.PageRole{proofv2.RoleAuthorityBook, proofv2.RoleVoter}
			in.Evidence.Pages[1].Roles = in.Report.Proven[1].Roles
		},
		"a page's state": func(in *GovRootV4Inputs) {
			kp := page(xBook1)
			kp.AcceptThreshold = 2
			in.Report.Pages[2] = kp
			st, _ := kp.MarshalBinary()
			in.Evidence.Pages[2].State = hex.EncodeToString(st)
		},
		"a page dropped": func(in *GovRootV4Inputs) {
			n := len(in.Report.Pages) - 1
			in.Report.Pages, in.Report.PageChains, in.Report.Proven, in.Evidence.Pages = in.Report.Pages[:n], in.Report.PageChains[:n], in.Report.Proven[:n], in.Evidence.Pages[:n]
		},
		"a vote's vote":    func(in *GovRootV4Inputs) { in.Evidence.Votes[0].Vote = "reject" },
		"a vote's origin":  func(in *GovRootV4Inputs) { in.Evidence.Votes[0].Origin = xBook1 },
		"a vote's number":  func(in *GovRootV4Inputs) { in.Evidence.Votes[0].Transport.Number++ },
		"a vote's hop":     func(in *GovRootV4Inputs) { in.Evidence.Votes[0].Hops[0].Block++ },
		"a vote's receipt": func(in *GovRootV4Inputs) { in.Evidence.Votes[0].Receipt = "0a0c" },
		"a vote added": func(in *GovRootV4Inputs) {
			v := in.Evidence.Votes[0]
			v.Authority, v.Origin = xHdrBook, xHdrPage
			in.Evidence.Votes = append(in.Evidence.Votes, v)
		},
	} {
		in := v4Inputs(newX21())
		mut(&in)
		got, _, err := GovRootV4(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got == base {
			t.Errorf("%s: the root did not change", name)
		}
	}
}

// Pins that every input is required and each refusal is named: no page without a partition, block or role, no records that
// disagree with the evidence, no intent without a vote.
func TestGovRootV4_RefusesIncompleteInputs(t *testing.T) {
	for name, c := range map[string]struct {
		mut  func(in *GovRootV4Inputs)
		want string
	}{
		"no report":   {func(in *GovRootV4Inputs) { in.Report = nil }, "no verified proof v2 report"},
		"no evidence": {func(in *GovRootV4Inputs) { in.Evidence = nil }, "evidence is not version 2.1"},
		"evidence 2.0": {func(in *GovRootV4Inputs) {
			in.Evidence.Version = proofv2.Version
		}, "evidence is not version 2.1"},
		"no G0":                   {func(in *GovRootV4Inputs) { in.G0 = nil }, "no G0 result"},
		"no key page":             {func(in *GovRootV4Inputs) { in.KeyPageURL = "" }, "the key page slot is required"},
		"no operation id":         {func(in *GovRootV4Inputs) { in.OperationID = [32]byte{} }, "the operation id slot is required"},
		"no tx hash":              {func(in *GovRootV4Inputs) { in.Report.TxHash = [32]byte{} }, "the transaction hash is required"},
		"no anchor block":         {func(in *GovRootV4Inputs) { in.Report.AnchorBlock = 0 }, "no anchor block"},
		"set only asserted":       {func(in *GovRootV4Inputs) { in.Report.SetVerdict = proof.VerdictValidatorSetAsserted }, "validator_set_asserted, not verified"},
		"no proven records":       {func(in *GovRootV4Inputs) { in.Report.Proven = nil }, "0 (partition, block, roles) records"},
		"a proven record missing": {func(in *GovRootV4Inputs) { in.Report.Proven = in.Report.Proven[1:] }, "(partition, block, roles) records"},
		"proven records reordered": {func(in *GovRootV4Inputs) {
			in.Report.Proven[0], in.Report.Proven[1] = in.Report.Proven[1], in.Report.Proven[0]
		}, "its proven record"},
		"a page with no partition": {func(in *GovRootV4Inputs) { in.Report.Proven[2].Partition = "" }, proofv2.StateForeignPartitionMismatch},
		"a page with no block":     {func(in *GovRootV4Inputs) { in.Report.Proven[2].Block = 0 }, proofv2.StatePageBlockMismatch},
		"a page with no role":      {func(in *GovRootV4Inputs) { in.Report.Proven[2].Roles = nil; in.Evidence.Pages[2].Roles = nil }, "no role"},
		"an unknown role": {func(in *GovRootV4Inputs) {
			in.Report.Proven[2].Roles = []proofv2.PageRole{"owner"}
		}, "unknown page role"},
		"evidence partition differs": {func(in *GovRootV4Inputs) { in.Evidence.Pages[2].Partition = partBVN1 }, "the evidence claims"},
		"evidence roles differ": {func(in *GovRootV4Inputs) {
			in.Evidence.Pages[2].Roles = []proofv2.PageRole{proofv2.RoleVoter}
		}, "the report records roles"},
		"evidence state differs": {func(in *GovRootV4Inputs) {
			s := in.Evidence.Pages[2].State
			in.Evidence.Pages[2].State = s[:len(s)-2]
		}, "not the account the report proved"},
		"no votes":     {func(in *GovRootV4Inputs) { in.Evidence.Votes = nil }, "records no authority vote"},
		"a vote twice": {func(in *GovRootV4Inputs) { in.Evidence.Votes = append(in.Evidence.Votes, in.Evidence.Votes[0]) }, "recorded twice"},
		"a page twice": {func(in *GovRootV4Inputs) {
			in.Report.Pages = append(in.Report.Pages, in.Report.Pages[0])
			in.Report.PageChains = append(in.Report.PageChains, in.Report.PageChains[0])
			in.Report.Proven = append(in.Report.Proven, in.Report.Proven[0])
			in.Evidence.Pages = append(in.Evidence.Pages, in.Evidence.Pages[0])
		}, "captured twice"},
	} {
		in := v4Inputs(newX21())
		c.mut(&in)
		_, _, err := GovRootV4(in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", name, err, c.want)
		}
	}
}

// The order the pages and votes are listed in does not change the root, and the portable form computes the same root.
func TestGovRootV4_OrderIndependentAndPortable(t *testing.T) {
	base, _, err := GovRootV4(v4Inputs(newX21()))
	if err != nil {
		t.Fatal(err)
	}
	// The same governing set captured in another order (the sort by canonical URL decides).
	f := newX21()
	f.order[0], f.order[len(f.order)-1] = f.order[len(f.order)-1], f.order[0]
	got, _, err := GovRootV4(v4Inputs(f))
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Fatalf("the root depends on capture order: %x vs %x", got, base)
	}
	in := v4Inputs(newX21())
	p, err := PortableGovRootV4Inputs(in)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := GovRootV4FromPortable(in.Report, in.Evidence, p)
	if err != nil || again != base {
		t.Fatalf("portable: %x, %v; want %x", again, err, base)
	}
	if _, _, err := GovRootV4FromPortable(in.Report, in.Evidence, nil); err == nil {
		t.Fatal("a portable proof with no inputs block was accepted")
	}
}

// Votes are committed in canonical order: the same votes in another order are the same root.
func TestVotesRootV4OrderIndependent(t *testing.T) {
	a := proofv2.Vote{Authority: xBook, Origin: xBook1, Vote: "accept", Message: "aa", Receipt: "01", Transport: proofv2.VoteTransport{Kind: proofv2.TransportInline}}
	b := proofv2.Vote{Authority: xHdrBook, Origin: xHdrPage, Vote: "accept", Message: "bb", Receipt: "02", Transport: proofv2.VoteTransport{Kind: proofv2.TransportInline}}
	r1, err := VotesRootV4([]proofv2.Vote{a, b})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := VotesRootV4([]proofv2.Vote{b, a})
	if err != nil || r1 != r2 {
		t.Fatalf("order changed the votes root: %x vs %x (%v)", r1, r2, err)
	}
}
