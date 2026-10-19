package intentcert

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// The real stored 2.1 document (Kermit, captured live 2026-10-18 by cmd/proofv2xbuild, assembled by Builder.Build21): a transaction on
// certen-protocol.acme/billing-receipts (BVN1) with the pages of its book, the history of the voting page, the arrival proofs, the
// production of the vote, the carried transaction and the routing table.
const realDir = "../proof/v2/testdata/xpartition3/real-bvn1-billing-receipts/"

const realPin = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

type real21 struct {
	ev  *proofv2.Evidence
	rep *proofv2.Report
}

// loadReal21 verifies the stored document with the REAL verifier (Verify21FromGenesis from the pinned Kermit incarnation) and returns
// its evidence and report.
func loadReal21(t *testing.T) real21 {
	t.Helper()
	ev := new(proofv2.Evidence)
	if err := json.Unmarshal(gunzipFile(t, realDir+"evidence21.json.gz"), ev); err != nil {
		t.Fatal(err)
	}
	ar, err := proofv2.UnmarshalArchive(gunzipFile(t, realDir+"archive.json.gz"))
	if err != nil {
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
	ir, err := inc.Verify()
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	b, _ := hex.DecodeString(realPin)
	copy(pin[:], b)
	ev.GenesisLink = recordedGenesisLink(t, ir.Inputs.GenesisRootChainAnchor) // the offline walk requires it of every evidence 2.1 document (RB9-F6)
	rep, err := proofv2.Verify21FromGenesis(ev, ar, ir.Inputs, pin)
	if err != nil {
		t.Fatalf("the stored real document does not verify: %v", err)
	}
	return real21{ev: ev, rep: rep}
}

// factsOf derives the governing facts from the document itself: a vote evidence (govvote.Evidence) whose transaction is the document's
// carried transaction, whose authorities are the principal's proven authorities, whose signatures are the signatures of the cause chains
// the document carries, and whose votes are the document's votes. Block numbers the document does not carry as such are the latest block
// the verifier established for them (a recorded vote: the anchor block; a signature: its hop's block).
func (r real21) factsOf(t *testing.T) (*GoverningFacts, string) {
	t.Helper()
	ev := &govvote.Evidence{Version: govvote.EvidenceVersion, Account: r.ev.Account, Transaction: r.ev.Transaction}
	for _, a := range r.rep.Pages {
		if strings.EqualFold(a.GetUrl().String(), r.ev.Account) {
			fa, ok := a.(protocol.FullAccount)
			if !ok {
				t.Fatalf("the principal is %T", a)
			}
			for _, e := range fa.GetAuth().Authorities {
				ev.Authorities = append(ev.Authorities, govvote.AccountAuthority{URL: e.Url.String(), Disabled: e.Disabled})
			}
		}
	}
	for _, v := range r.ev.Votes {
		for _, h := range append(append([]proofv2.VoteHop(nil), v.Hops...), v.Counted...) {
			ev.Signatures = append(ev.Signatures, govvote.SignatureEvidence{Fact: govvote.SigFact{ID: h.Message, Signer: h.Page, Block: int64(h.Block)}, Signature: h.Signature})
		}
		ev.Votes = append(ev.Votes, govvote.VoteEvidence{Fact: govvote.RecordedVote{ID: v.Message, Authority: v.Authority, Origin: v.Origin, Block: int64(r.rep.AnchorBlock)}})
	}
	facts, err := GoverningFactsFromVoteEvidence(ev)
	if err != nil {
		t.Fatalf("the governing facts of the real document: %v", err)
	}
	// The certified key page: the page the document records with the declared role.
	var page string
	for _, p := range r.rep.Proven {
		for _, d := range p.Declared {
			if d == proofv2.RoleCertifiedKeyPage {
				page = p.URL
			}
		}
	}
	if page == "" {
		t.Fatal("the real document records no certified key page")
	}
	return facts, page
}

// g0g1 are the two results the binding reads, synthesised ONLY as far as it reads them: G0's entry hash, receipt start, witness and
// execution block, copied from the report, and G1's key page. They are not governance proofs of the transaction (the live network no
// longer serves the historical state they are built from); everything else in the binding is the document's.
func (r real21) g0g1(page string) (*proof.G0Result, *proof.G1Result) {
	hx := func(b [32]byte) string { return hex.EncodeToString(b[:]) }
	g0 := &proof.G0Result{EntryHashExec: hx(r.rep.TxHash), ExecWitness: hx(r.rep.AnchorRootChainAnchor), ExecMBI: int64(r.rep.AnchorBlock)}
	g0.Receipt.Start = g0.EntryHashExec
	g1 := &proof.G1Result{}
	g1.AuthoritySnapshot.Page = page
	return g0, g1
}

func bookOf(t *testing.T, page string) string {
	t.Helper()
	u, err := url.Parse(page)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := u.Parent()
	if !ok {
		t.Fatalf("%s has no book", page)
	}
	return p.String()
}

// BindProofV21 accepts the real stored document: its real report (real verifier), the facts derived from the document, the certified key
// page and book it records. Nothing about the document is relaxed for the binding: the same report with anything unproven, another
// transaction, another declared book, or an executor version the table does not establish is refused.
func TestBindProofV21AcceptsTheRealStored21Document(t *testing.T) {
	r := loadReal21(t)
	if len(r.rep.Unproven) != 0 {
		t.Fatalf("the stored document is not fully proven: %v", r.rep.Unproven)
	}
	facts, page := r.factsOf(t)
	book := bookOf(t, page)
	g0, g1 := r.g0g1(page)
	if err := BindProofV21(r.rep, g0, g1, page, book, facts); err != nil {
		t.Fatalf("the real document: %v", err)
	}

	// The executor version was derived from the pinned table: the document carries no ledger page (live Kermit serves none).
	for _, p := range r.rep.Proven {
		for _, role := range p.Roles {
			if role == proofv2.RoleSystemLedger {
				t.Fatalf("%s: the document unexpectedly carries a ledger page", p.URL)
			}
		}
		if _, ok := proofv2.ExecutorFloorAt(p.Partition, p.Block); !ok {
			t.Fatalf("%s at %s block %d: the pinned table does not establish the executor version", p.URL, p.Partition, p.Block)
		}
	}

	// The same report with one more unproven entry is not a verified S3: refused with that entry.
	un := *r.rep
	un.Unproven = append(append([]proofv2.NamedState(nil), r.rep.Unproven...),
		proofv2.NamedState{Code: proofv2.StateCompletenessUnproven, Partition: r.rep.Partition, Block: r.rep.AnchorBlock, Detail: "appended"})
	err := BindProofV21(&un, g0, g1, page, book, facts)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateCompletenessUnproven || ns.Block != r.rep.AnchorBlock {
		t.Fatalf("an unproven entry: %v", err)
	}

	// Another transaction's facts.
	bad := *facts
	bad.TxHash[0] ^= 1
	wantState(t, "another transaction", BindProofV21(r.rep, g0, g1, page, book, &bad), proofv2.StateTransactionMismatch)

	// Another declared book.
	wantState(t, "another declared book", BindProofV21(r.rep, g0, g1, page, "acc://certen-protocol.acme/other-book", facts), proofv2.StateCertifiedPageUnproven)

	// A report judged at a block the table does not establish.
	early := *r.rep
	early.Proven = append([]proofv2.ProvenPage(nil), r.rep.Proven...)
	early.Proven[0].Block = 1000
	if err := BindProofV21(&early, g0, g1, page, book, facts); err == nil {
		t.Fatal("a page proven at a block before the activation was bound")
	}
}

// govRoot v4 computes over the real document: the pages root commits the recorded roles (proven and declared), the votes root the
// real vote with its real receipts, arrival proofs and production, under the explicit encoding.
func TestGovRootV4ComputesOverTheRealStored21Document(t *testing.T) {
	r := loadReal21(t)
	facts, page := r.factsOf(t)
	g0, g1 := r.g0g1(page)
	if err := BindProofV21(r.rep, g0, g1, page, bookOf(t, page), facts); err != nil {
		t.Fatal(err)
	}
	pages, err := PagesRootV4(r.rep, r.ev)
	if err != nil {
		t.Fatalf("pages root: %v", err)
	}
	votes, err := VotesRootV4(r.ev.Votes)
	if err != nil {
		t.Fatalf("votes root: %v", err)
	}
	if votes != rawVotesRoot(r.ev.Votes) {
		t.Fatalf("votes root %x, independent %x", votes, rawVotesRoot(r.ev.Votes))
	}
	h := [32]byte{9}
	root, _, err := GovRootV4FromHashes(GovRootV4HashInputs{Report: r.rep, Evidence: r.ev, G0Hash: h, G1Hash: h, G2Hash: h, KeyPageURL: page, KeyBookURL: bookOf(t, page), OperationID: h})
	if err != nil {
		t.Fatalf("govRoot v4: %v", err)
	}
	if root == [32]byte{} || pages == [32]byte{} || votes == [32]byte{} {
		t.Fatal("a zero root")
	}
}

// recordedGenesisLink is Kermit's recorded answer to the genesis question for the stored real document (pkg/proof/v2/testdata/certify1-live/links.json,
// label genesis): the receipt from the pinned genesis root chain anchor to the real certified root, hex. Every evidence 2.1 document needs it of the
// offline walk (RB9-F6, F-VE-2 option b); the committed fixture is the continuous document without it, unchanged.
func recordedGenesisLink(t *testing.T, genesis [32]byte) string {
	t.Helper()
	raw, err := os.ReadFile("../proof/v2/testdata/certify1-live/links.json")
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Links []struct {
			Label   string `json:"label"`
			Prev    string `json:"prev"`
			Receipt string `json:"receipt"`
		} `json:"links"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	for _, l := range rec.Links {
		if l.Label == "genesis" {
			if l.Prev != hex.EncodeToString(genesis[:]) || l.Receipt == "" {
				t.Fatalf("the recorded genesis answer starts at %s (want %x) or is a refusal", l.Prev, genesis)
			}
			return l.Receipt
		}
	}
	t.Fatal("no recorded answer labelled genesis")
	return ""
}
