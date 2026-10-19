package consensus

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The real stored 2.1 document: a live Kermit transaction on certen-protocol.acme/billing-receipts (BVN1 block 14713382), assembled by
// Builder.Build21 from a live capture (RB9-C1b-2). The consensus certificate path below is run over it with the REAL verifier, the REAL
// BindProofV21 and the REAL govRoot v4; what is synthetic is named at each use.
const real21Dir = "../proof/v2/testdata/xpartition3/real-bvn1-billing-receipts/"

func gunzipFile(t *testing.T, path string) []byte {
	t.Helper()
	gz, err := os.ReadFile(filepath.FromSlash(path))
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

// real21World is the stored document with the spine a chain holds after verifying the document's archive from Kermit's genesis.
type real21World struct {
	ev    *proofv2.Evidence
	spine *ledger.AccumulateSpineLog
	inc   [32]byte
	ar    *proofv2.Archive           // the archive the spine was extended from, for the offline walk (RB9-F6)
	in    govproof.IncarnationInputs // the pinned incarnation's inputs, for the offline walk (RB9-F6)
}

func loadReal21World(t *testing.T) real21World {
	t.Helper()
	w := real21World{ev: new(proofv2.Evidence)}
	if err := json.Unmarshal(gunzipFile(t, real21Dir+"evidence21.json.gz"), w.ev); err != nil {
		t.Fatal(err)
	}
	ar, err := proofv2.UnmarshalArchive(gunzipFile(t, real21Dir+"archive.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../proof/testdata/incarnation/kermit.json")
	if err != nil {
		t.Fatal(err)
	}
	var inc govproof.IncarnationEvidence
	if err := json.Unmarshal(raw, &inc); err != nil {
		t.Fatal(err)
	}
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	gen, set, err := proofv2.AcceptSpineGenesis(ir.Inputs, ir.Incarnation, 5)
	if err != nil {
		t.Fatal(err)
	}
	l := &ledger.AccumulateSpineLog{Genesis: gen, Sets: []ledger.AccumulateSpineSet{set}}
	cps, sets, err := proofv2.ExtendSpine(l, ar.Majors, 6)
	if err != nil {
		t.Fatal(err)
	}
	l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
	w.spine, w.inc, w.ar, w.in = l, ir.Incarnation, ar, ir.Inputs
	return w
}

func (w real21World) clone(t *testing.T) *proofv2.Evidence {
	t.Helper()
	raw, err := json.Marshal(w.ev)
	if err != nil {
		t.Fatal(err)
	}
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(raw, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// voteEvidenceOf derives the intent's govvote evidence from the document itself (the production intent builds it from the network): the
// carried transaction, the principal's resolved authority set read from the proven pages, every carried signature with the block it
// arrived in, and every recorded vote. This is what the binding reads of the vote evidence (GoverningFactsFromVoteEvidence); the
// receipts and page histories a production vote evidence also carries are not part of what the binding reads and are not synthesised.
func voteEvidenceOf(t *testing.T, ev *proofv2.Evidence, anchorBlock uint64) json.RawMessage {
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
		g.Votes = append(g.Votes, govvote.VoteEvidence{Fact: govvote.RecordedVote{Authority: v.Authority, Origin: v.Origin,
			Block: int64(anchorBlock)}})
		for _, h := range append(append([]proofv2.VoteHop(nil), v.Hops...), v.Counted...) {
			if seen[h.Message] {
				continue
			}
			seen[h.Message] = true
			g.Signatures = append(g.Signatures, govvote.SignatureEvidence{Signature: h.Signature,
				Fact: govvote.SigFact{Signer: h.Page, Block: int64(h.Block)}})
		}
	}
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// real21Certificate is the intent certificate evidence around the stored document, and the G0-G2 the binding and govRoot v4 read.
// SYNTHETIC, and only here: the intent whose proof this document is no longer exists (Kermit serves the pages only inside its retention
// window), so there is no G0/G1/G2 or L1-L4 proof of it. G0 carries exactly the four fields the binding checks against the report (entry,
// receipt start, witness, execution block) set from the REAL report; G1 names the certified key page, the one thing the binding reads of
// it; G1/G2 otherwise take the shape of the production proof's (the fixture), which govRoot v4 only hashes.
type real21Cert struct {
	cert        *IntentCertificateEvidence
	g0          *govproof.G0Result
	g1          *govproof.G1Result
	g2          *govproof.G2Result
	accRoot     [32]byte
	operationID [32]byte
}

func real21CertificateFor(t *testing.T, w real21World, ev *proofv2.Evidence) real21Cert {
	t.Helper()
	rep, err := proofv2.VerifyEvidence21FromSpine(w.ev, w.spine, w.inc)
	if err != nil {
		t.Fatalf("the real verifier refuses the real stored document: %v", err)
	}
	var page string
	for _, p := range rep.Proven {
		for _, d := range p.Declared {
			if d == proofv2.RoleCertifiedKeyPage {
				page = p.URL
			}
		}
	}
	if page == "" {
		t.Fatal("the document records no certified key page")
	}
	u, err := url.Parse(page)
	if err != nil {
		t.Fatal(err)
	}
	book, ok := u.Parent()
	if !ok {
		t.Fatalf("%s has no book", page)
	}

	f := loadIntentFixtureV3(t)
	vb := v3Block(t, f, "validator-1")
	c := real21Cert{g0: vb.GovernanceProof.G0Proof, g1: vb.GovernanceProof.G1Proof, g2: vb.GovernanceProof.G2Proof}
	c.g0.EntryHashExec = hex.EncodeToString(rep.TxHash[:])
	c.g0.Receipt.Start = c.g0.EntryHashExec
	c.g0.ExecWitness = hex.EncodeToString(rep.AnchorRootChainAnchor[:])
	c.g0.ExecMBI = int64(rep.AnchorBlock)
	c.g1.G0Result = *c.g0
	c.g1.AuthoritySnapshot.Page = page
	c.g2.G1Result = *c.g1
	c.operationID = [32]byte{7}
	// The L4 leg's validator set root: the production proof's, from the fixture's chained proof. Kermit's set did not change between the two
	// proofs, so it is also the set the spine derives for the document; were it not, judgeProofV2 would refuse (ErrIntentAccumulateSetMismatch).
	c.accRoot, err = accumulateset.CommittedAccumulateSetRoot(vb.LiteClientProof.Layer4DN, w.inc)
	if err != nil {
		t.Fatal(err)
	}
	c.cert = &IntentCertificateEvidence{KeyPageURL: page, KeyBookURL: book.String(), ProofV2: ev,
		VoteEvidence: voteEvidenceOf(t, ev, rep.AnchorBlock)}
	return c
}

func (c real21Cert) judge(w real21World, g *ledger.G1ActivationRecord) ([32]byte, *proofv2.Report, error) {
	return judgeProofV2(c.cert, c.g0, c.g1, c.g2, w.inc, c.operationID, c.accRoot, w.spine, g, nil)
}

// MERGE CONDITION of RB9-C2-F7: a certificate over a REAL stored evidence 2.1 document is accepted by consensus' own judgement of the
// proof v2 (judgeProofV2, the function intentInputs calls) when the rules v15 activation is in force at the block - the document verified
// by the real VerifyEvidence21FromSpine against the spine a chain holds, bound by the real BindProofV21 over the intent's vote evidence,
// committed by the real govRoot v4 - and by nothing else: not before the activation, not as a 2.0 document, not edited.
func TestRulesV15AcceptsAVerifiedEvidence21(t *testing.T) {
	w := loadReal21World(t)
	c := real21CertificateFor(t, w, w.clone(t))

	root, rep, err := c.judge(w, g1Active)
	if err != nil {
		t.Fatalf("a real stored 2.1 document under the activation: %v", err)
	}
	if rep.Version != proofv2.Version21 || len(rep.Unproven) != 0 || len(rep.Proven) < 5 {
		t.Fatalf("the report the consensus path judged is not the complete 2.1 report: version %q, %d unproven, %d proven", rep.Version, len(rep.Unproven), len(rep.Proven))
	}
	// The root is govRoot v4 over exactly this report, evidence and the intent's G0-G2.
	want, _, err := intentcert.GovRootV4(intentcert.GovRootV4Inputs{Report: rep, Evidence: c.cert.ProofV2, G0: c.g0, G1: c.g1, G2: c.g2,
		KeyPageURL: c.cert.KeyPageURL, KeyBookURL: c.cert.KeyBookURL, OperationID: c.operationID})
	if err != nil || want != root {
		t.Fatalf("the judged root %x is not govRoot v4 %x (%v)", root, want, err)
	}

	// Not before the activation: the same bytes are refused by name, and the real verifier is not even asked.
	if _, _, err := c.judge(w, nil); !errors.Is(err, ErrIntentProofV21NotInForce) {
		t.Fatalf("2.1 before the activation: %v", err)
	}
	// The shared 2.0 entry points still refuse the document: no 2.0 call site can accept it.
	if _, err := proofv2.VerifyFromSpine(c.cert.ProofV2, w.spine, w.inc); err == nil || !strings.Contains(err.Error(), "not a v2 Accumulate proof") {
		t.Fatalf("VerifyFromSpine accepts or mis-refuses a 2.1 document: %v", err)
	}
	// A 2.0 document is not a 2.1 certificate once the activation is in force, and the 2.1 entry point refuses it.
	two := *c.cert.ProofV2
	two.Version = proofv2.Version
	if _, err := proofv2.VerifyEvidence21FromSpine(&two, w.spine, w.inc); err == nil {
		t.Fatal("VerifyEvidence21FromSpine accepts a 2.0 document")
	}
	c2 := c
	cert2 := *c.cert
	cert2.ProofV2 = &two
	c2.cert = &cert2
	if _, _, err := c2.judge(w, g1Active); !errors.Is(err, ErrIntentProofV21Missing) {
		t.Fatalf("a 2.0 document under the activation: %v", err)
	}

	// The REAL verifier judges the document: each edit that the production verifier refuses is refused, by name, as an invalid proof.
	edits := map[string]func(ev *proofv2.Evidence){
		"a vote value flipped":      func(ev *proofv2.Evidence) { ev.Votes[0].Vote = "reject" },
		"the transaction dropped":   func(ev *proofv2.Evidence) { ev.Transaction = "" },
		"a page state edited":       func(ev *proofv2.Evidence) { ev.Pages[0].State = ev.Pages[1].State },
		"a vote's receipt replaced": func(ev *proofv2.Evidence) { ev.Votes[0].Receipt = ev.Votes[0].Hops[0].Receipt },
	}
	for name, edit := range edits {
		ev := w.clone(t)
		edit(ev)
		c3 := c
		cert3 := *c.cert
		cert3.ProofV2 = ev
		c3.cert = &cert3
		if _, _, err := c3.judge(w, g1Active); !errors.Is(err, ErrIntentProofV2Invalid) && !errors.Is(err, ErrIntentGovRootMismatch) {
			t.Errorf("%s: the certificate is judged %v", name, err)
		}
	}

	// One validator set: a document whose spine-derived set is not the L4 leg's is refused.
	c4 := c
	c4.accRoot[0] ^= 1
	if _, _, err := c4.judge(w, g1Active); !errors.Is(err, ErrIntentAccumulateSetMismatch) {
		t.Fatalf("a different L4 set root: %v", err)
	}
	// The binding reads the intent's own vote evidence: another transaction in it, or the certified page outside the declared book, is
	// refused by the binding (not by the root).
	c5 := c
	cert5 := *c.cert
	cert5.KeyBookURL = "acc://certen-protocol.acme/another-book"
	c5.cert = &cert5
	if _, _, err := c5.judge(w, g1Active); err == nil {
		t.Fatal("a certified page outside the declared book is accepted")
	}
}
