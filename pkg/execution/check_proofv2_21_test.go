package execution

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/ledger"
	certenproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB9-VB defect 1: checkProofV2 (the offline check of a stored certificate, cmd/proofverify) called the 2.0-only VerifyFromGenesis for every
// v3 certificate, so every evidence 2.1 certificate failed with "not a v2 Accumulate proof" and the is21 branch of intentcert.ProofV2Root was
// unreachable from this caller. These tests run checkProofV2 over the REAL stored 2.1 document (a live Kermit transaction on
// certen-protocol.acme/billing-receipts, BVN1 block 14713382) and over the real stored production 2.0 document.

const real21DocDir = "../proof/v2/testdata/xpartition3/real-bvn1-billing-receipts/"

func v21Gunzip(t *testing.T, path string) []byte {
	t.Helper()
	gz, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func kermitTrust(t *testing.T, ar *proofv2.Archive) (*ProofV2Trust, certenproof.IncarnationReport) {
	t.Helper()
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var ie certenproof.IncarnationEvidence
	if err := json.Unmarshal(raw, &ie); err != nil {
		t.Fatal(err)
	}
	ir, err := ie.Verify()
	if err != nil {
		t.Fatal(err)
	}
	return &ProofV2Trust{Archive: ar, Inputs: ir.Inputs}, *ir
}

// derivedVoteEvidence21 derives the intent's govvote evidence FROM THE DOCUMENT ITSELF (the production intent builds it from the network):
// the carried transaction, the principal's resolved authority set read from the proven pages, every carried signature with the block it
// arrived in, every recorded vote. It shows self-consistency of the document and the facts, not a binding to independently captured facts.
func derivedVoteEvidence21(t *testing.T, ev *proofv2.Evidence, anchorBlock uint64) json.RawMessage {
	t.Helper()
	accts := map[string]protocol.Account{}
	for _, p := range ev.Pages {
		raw, err := hex.DecodeString(p.State)
		if err != nil {
			t.Fatal(err)
		}
		a, err := protocol.UnmarshalAccount(raw)
		if err != nil {
			t.Fatal(err)
		}
		accts[govvote.CanonicalAccSpelling(p.URL)] = a
	}
	g := govvote.Evidence{Version: "test", Account: ev.Account, Transaction: ev.Transaction}
	for cur := ev.Account; ; {
		a, ok := accts[govvote.CanonicalAccSpelling(cur)]
		if !ok {
			t.Fatalf("principal chain: %s is not among the document's pages", cur)
		}
		fa, ok := a.(protocol.FullAccount)
		if !ok {
			t.Fatalf("principal chain: %s is %T", cur, a)
		}
		if len(fa.GetAuth().Authorities) > 0 {
			for _, e := range fa.GetAuth().Authorities {
				g.Authorities = append(g.Authorities, govvote.AccountAuthority{URL: e.Url.String(), Disabled: e.Disabled})
			}
			break
		}
		u, err := url.Parse(cur)
		if err != nil {
			t.Fatal(err)
		}
		parent, ok := u.Parent()
		if !ok {
			t.Fatalf("principal chain: %s lists no authority", cur)
		}
		cur = parent.String()
	}
	seen := map[string]bool{}
	for _, v := range ev.Votes {
		g.Votes = append(g.Votes, govvote.VoteEvidence{Fact: govvote.RecordedVote{Authority: v.Authority, Origin: v.Origin, Block: int64(anchorBlock)}})
		for _, h := range append(append([]proofv2.VoteHop(nil), v.Hops...), v.Counted...) {
			if seen[h.Message] {
				continue
			}
			seen[h.Message] = true
			g.Signatures = append(g.Signatures, govvote.SignatureEvidence{Signature: h.Signature, Fact: govvote.SigFact{Signer: h.Page, Block: int64(h.Block)}})
		}
	}
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type real21Case struct {
	ev          *proofv2.Evidence
	trust       *ProofV2Trust
	inc         [32]byte
	rep         *proofv2.Report
	g0          *certenproof.G0Result
	g1          *certenproof.G1Result
	g2          *certenproof.G2Result
	page, book  string
	voteEvid    json.RawMessage
	op          [32]byte
	spine       *ledger.AccumulateSpineLog
	incEvidence certenproof.IncarnationReport
}

func loadReal21Case(t *testing.T) *real21Case {
	t.Helper()
	c := &real21Case{ev: new(proofv2.Evidence), op: [32]byte{7}}
	if err := json.Unmarshal(v21Gunzip(t, real21DocDir+"evidence21.json.gz"), c.ev); err != nil {
		t.Fatal(err)
	}
	ar, err := proofv2.UnmarshalArchive(v21Gunzip(t, real21DocDir+"archive.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	c.trust, c.incEvidence = kermitTrust(t, ar)
	c.inc = c.incEvidence.Incarnation
	// The report by the genesis verifier of evidence 2.1 (what the offline check must reach).
	if c.rep, err = proofv2.Verify21FromGenesis(c.ev, ar, c.trust.Inputs, c.inc); err != nil {
		t.Fatalf("the real 2.1 verifier refuses the real stored document: %v", err)
	}
	for _, p := range c.rep.Proven {
		for _, d := range p.Declared {
			if d == proofv2.RoleCertifiedKeyPage {
				c.page = p.URL
			}
		}
	}
	if c.page == "" {
		t.Fatal("the document records no certified key page")
	}
	u, err := url.Parse(c.page)
	if err != nil {
		t.Fatal(err)
	}
	bk, ok := u.Parent()
	if !ok {
		t.Fatalf("%s has no book", c.page)
	}
	c.book = bk.String()
	// G0 carries exactly the fields the binding checks against the report, set from the REAL report; G1 names the certified page; the
	// intent these levels belong to no longer exists (Kermit serves the pages only inside its retention window).
	c.g0 = &certenproof.G0Result{EntryHashExec: hex.EncodeToString(c.rep.TxHash[:]), ExecWitness: hex.EncodeToString(c.rep.AnchorRootChainAnchor[:]),
		ExecMBI: int64(c.rep.AnchorBlock)}
	c.g0.Receipt.Start = c.g0.EntryHashExec
	c.g1 = &certenproof.G1Result{G0Result: *c.g0}
	c.g1.AuthoritySnapshot.Page = c.page
	c.g2 = &certenproof.G2Result{G1Result: *c.g1}
	c.voteEvid = derivedVoteEvidence21(t, c.ev, c.rep.AnchorBlock)
	// The spine a chain holds after verifying the archive from Kermit's genesis: the route judgeProofV2 takes.
	gen, set, err := proofv2.AcceptSpineGenesis(c.trust.Inputs, c.inc, 5)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
	cps, sets, err := proofv2.ExtendSpine(l, ar.Majors, 6)
	if err != nil {
		t.Fatal(err)
	}
	l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
	c.spine = l
	return c
}

func (c *real21Case) inputs(ev *proofv2.Evidence) consensus.IntentMessageInputs {
	return consensus.IntentMessageInputs{GovRootV3: "0x01", ProofV2: ev, KeyPageURL: c.page, KeyBookURL: c.book}
}

// judgeProofV2's root for the same document: VerifyEvidence21FromSpine (the verifier consensus calls) over the chain's spine, then the binding
// and govRoot v4 that consensus.judgeProofV2 returns (intentcert.ProofV2Root).
func (c *real21Case) consensusRoot(t *testing.T) [32]byte {
	t.Helper()
	rep, err := proofv2.VerifyEvidence21FromSpine(c.ev, c.spine, c.inc)
	if err != nil {
		t.Fatalf("the consensus verifier refuses the real stored document: %v", err)
	}
	if rep.AccumulateSetRoot != c.rep.AccumulateSetRoot {
		t.Fatalf("the spine route derives set root %x, the genesis route %x", rep.AccumulateSetRoot, c.rep.AccumulateSetRoot)
	}
	root, is21, err := intentcert.ProofV2Root(rep, c.ev, c.g0, c.g1, c.g2, c.page, c.book, c.voteEvid, c.op)
	if err != nil || !is21 {
		t.Fatalf("consensus' binding of the real document: %v (is21 %v)", err, is21)
	}
	return root
}

func TestCheckProofV2VerifiesARealEvidence21Document(t *testing.T) {
	c := loadReal21Case(t)
	want := c.consensusRoot(t)

	root, is21, err := checkProofV2(c.inputs(c.ev), c.trust, c.inc, c.op, c.rep.AccumulateSetRoot, c.g0, c.g1, c.g2, c.voteEvid)
	if err != nil {
		t.Fatalf("the offline check refuses the real stored 2.1 document: %v", err)
	}
	if !is21 {
		t.Fatal("the offline check did not take the evidence 2.1 path")
	}
	if root != want {
		t.Fatalf("the offline check computes govRoot v4 %x, consensus' judgement of the same document %x", root, want)
	}
	v4, _, err := intentcert.GovRootV4(intentcert.GovRootV4Inputs{Report: c.rep, Evidence: c.ev, G0: c.g0, G1: c.g1, G2: c.g2,
		KeyPageURL: c.page, KeyBookURL: c.book, OperationID: c.op})
	if err != nil || v4 != root {
		t.Fatalf("the root %x is not govRoot v4 over the report %x (%v)", root, v4, err)
	}

	// The offline check is not weaker than the verifier: another L4 set root, an edited document and a missing vote evidence are refused.
	bad := c.rep.AccumulateSetRoot
	bad[0] ^= 1
	if _, _, err := checkProofV2(c.inputs(c.ev), c.trust, c.inc, c.op, bad, c.g0, c.g1, c.g2, c.voteEvid); err == nil || !strings.Contains(err.Error(), "set root") {
		t.Fatalf("another stored Directory set root: %v", err)
	}
	edited := new(proofv2.Evidence)
	raw, _ := json.Marshal(c.ev)
	if err := json.Unmarshal(raw, edited); err != nil {
		t.Fatal(err)
	}
	edited.Votes[0].Vote = "reject"
	if _, _, err := checkProofV2(c.inputs(edited), c.trust, c.inc, c.op, c.rep.AccumulateSetRoot, c.g0, c.g1, c.g2, c.voteEvid); err == nil {
		t.Fatal("an edited 2.1 document is accepted by the offline check")
	}
	if _, is, err := checkProofV2(c.inputs(c.ev), c.trust, c.inc, c.op, c.rep.AccumulateSetRoot, c.g0, c.g1, c.g2, nil); err == nil || !is {
		t.Fatalf("a 2.1 certificate without the intent's vote evidence: is21 %v, %v", is, err)
	}
}

func TestCheckProofV2StillTakesTheVersion20PathForA20Document(t *testing.T) {
	// The real stored production 2.0 document (proof 6c831fec): version 2.0 goes to VerifyFromGenesis, binds with BindProofV2 and commits
	// govRoot v3, exactly as before.
	var fx struct {
		G0      json.RawMessage   `json:"g0"`
		G1      json.RawMessage   `json:"g1"`
		G2      json.RawMessage   `json:"g2"`
		ProofV2 *proofv2.Evidence `json:"proof_v2"`
		Archive json.RawMessage   `json:"archive"`
	}
	if err := json.Unmarshal(v21Gunzip(t, "../consensus/testdata/intent_cert/proof_6c831fec_v3.json.gz"), &fx); err != nil {
		t.Fatal(err)
	}
	var g0 certenproof.G0Result
	var g1 certenproof.G1Result
	var g2 certenproof.G2Result
	for _, x := range []struct {
		raw json.RawMessage
		v   interface{}
	}{{fx.G0, &g0}, {fx.G1, &g1}, {fx.G2, &g2}} {
		if err := json.Unmarshal(x.raw, x.v); err != nil {
			t.Fatal(err)
		}
	}
	ar, err := proofv2.UnmarshalArchive(fx.Archive)
	if err != nil {
		t.Fatal(err)
	}
	trust, ir := kermitTrust(t, ar)
	if fx.ProofV2.Version != proofv2.Version {
		t.Fatalf("the production fixture is evidence %q, not 2.0", fx.ProofV2.Version)
	}
	rep, err := proofv2.VerifyFromGenesis(fx.ProofV2, ar, trust.Inputs, ir.Incarnation)
	if err != nil {
		t.Fatal(err)
	}
	op := [32]byte{7}
	page, book := g1.AuthoritySnapshot.Page, "acc://rb4-phase-c-09282125.acme/book"
	want, _, err := intentcert.GovRootV3(intentcert.GovRootV3Inputs{Report: rep, Evidence: fx.ProofV2, G0: &g0, G1: &g1, G2: &g2,
		KeyPageURL: page, KeyBookURL: book, OperationID: op})
	if err != nil {
		t.Fatal(err)
	}
	in := consensus.IntentMessageInputs{GovRootV3: "0x01", ProofV2: fx.ProofV2, KeyPageURL: page, KeyBookURL: book}
	root, is21, err := checkProofV2(in, trust, ir.Incarnation, op, rep.AccumulateSetRoot, &g0, &g1, &g2, nil)
	if err != nil {
		t.Fatalf("the offline check refuses the real stored 2.0 document: %v", err)
	}
	if is21 || root != want {
		t.Fatalf("2.0 document: is21 %v, root %x, govRoot v3 %x", is21, root, want)
	}

	// A document that claims 2.0 and carries evidence 2.1 members is judged as consensus judges it before the activation, on its evidence-2.0
	// view (the members v14's decode dropped cleared): the same verdict and the same govRoot v3 as the document without them.
	withVotes := new(proofv2.Evidence)
	rawDoc, _ := json.Marshal(fx.ProofV2)
	if err := json.Unmarshal(rawDoc, withVotes); err != nil {
		t.Fatal(err)
	}
	withVotes.Votes = []proofv2.Vote{{Authority: "acc://a.acme/book", Vote: "accept"}}
	withVotes.Transaction = "00"
	withVotes.Pages[0].Roles = []proofv2.PageRole{proofv2.RoleAuthorityPage}
	in.ProofV2 = withVotes
	root2, is21, err := checkProofV2(in, trust, ir.Incarnation, op, rep.AccumulateSetRoot, &g0, &g1, &g2, nil)
	if err != nil || is21 || root2 != want {
		t.Fatalf("a 2.0 document with 2.1 members: root %x (want %x), is21 %v, %v", root2, want, is21, err)
	}

	// A 2.1 document relabelled 2.0 is judged on the 2.0 view, never as 2.1; an unknown version is refused by name.
	c := loadReal21Case(t)
	two := new(proofv2.Evidence)
	raw, _ := json.Marshal(c.ev)
	if err := json.Unmarshal(raw, two); err != nil {
		t.Fatal(err)
	}
	two.Version = proofv2.Version
	if _, is, _ := checkProofV2(c.inputs(two), c.trust, c.inc, c.op, c.rep.AccumulateSetRoot, c.g0, c.g1, c.g2, c.voteEvid); is {
		t.Fatal("a document that claims 2.0 was judged as evidence 2.1")
	}
	two.Version = "9.9"
	if _, _, err := checkProofV2(c.inputs(two), c.trust, c.inc, c.op, c.rep.AccumulateSetRoot, c.g0, c.g1, c.g2, c.voteEvid); err == nil {
		t.Fatal("an unknown evidence version is accepted by the offline check")
	}
}
