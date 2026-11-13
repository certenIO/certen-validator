package intentcert

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DAX-1G (G-83): an intent opened through a SEPARATE, non-voting initiator identity (the transaction-controls `*-erp` pattern, decision 0042)
// can never reach a bound proof under evidence 2.1, because no member of the document carries the initiator's signature: the verifier lists
// the role initiator-signer as Declared and reports g1_initiator_signature_not_carried, and BindProofV21 refuses any report with an Unproven
// entry. These tests run the REAL path over a world document: xworld document -> proofv2.VerifyPortable (export, import, offline walk) ->
// GoverningFactsFromVoteEvidence (the binding's own reader of the intent's vote evidence) -> BindProofV21. The world is built at blocks the
// pinned executor-activation table proves (xworld.LayoutBVNProven), so the binding can judge it; the earlier worlds' blocks are below it.

// nvWorld builds the world with the vote's production bound (so nothing about the votes is left unproven) at proven blocks.
func nvWorld(t *testing.T, tl xworld.Timeline) *xworld.Built {
	t.Helper()
	tl.ProduceBlock, tl.BindSequenced = 66, true
	b, err := xworld.Build(xworld.Options{Layout: xworld.LayoutBVNProven, GenesisLinked: true, Timeline: &tl})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func nvAddRoles(t *testing.T, ev *proofv2.Evidence, page string, roles ...proofv2.PageRole) {
	t.Helper()
	for i := range ev.Pages {
		if strings.EqualFold(ev.Pages[i].URL, page) {
			rs, err := proofv2.CanonicalRoles(append(append([]proofv2.PageRole{}, ev.Pages[i].Roles...), roles...))
			if err != nil {
				t.Fatal(err)
			}
			ev.Pages[i].Roles = rs
			return
		}
	}
	t.Fatalf("no page %s", page)
}

// nvVerify is the verifier's verdict on the world, through the portable form.
func nvVerify(t *testing.T, b *xworld.Built) (*proofv2.Report, error) {
	t.Helper()
	p, err := b.Portable()
	if err != nil {
		t.Fatal(err)
	}
	return proofv2.VerifyPortable(p)
}

// nvFacts reads the governing facts exactly as the binding does, from the intent's own vote evidence: the transaction, the principal's
// authority, the signatures of the pages the evidence examined - the vote's key signature, and the declared signer's signature when it is a
// page of its own (the initiating signature, as the transaction's signature set holds it) - and the vote the principal recorded.
func nvFacts(t *testing.T, b *xworld.Built, initiating *proofv2.VoteHop) *GoverningFacts {
	t.Helper()
	ev := b.Evidence
	ge := &govvote.Evidence{Version: govvote.EvidenceVersion, Account: ev.Account, Transaction: ev.Transaction,
		Authorities: []govvote.AccountAuthority{{URL: xworld.BankBook}}}
	vote := ev.Votes[0]
	for _, h := range vote.Hops {
		ge.Signatures = append(ge.Signatures, govvote.SignatureEvidence{
			Fact:      govvote.SigFact{ID: h.Message, Signer: govvote.CanonicalAccSpelling(h.Page), Version: 1, Block: int64(h.Block)},
			Signature: h.Signature})
	}
	if initiating != nil {
		ge.Signatures = append(ge.Signatures, govvote.SignatureEvidence{
			Fact:      govvote.SigFact{ID: initiating.Message, Signer: govvote.CanonicalAccSpelling(initiating.Page), Version: 1, Block: int64(initiating.Block)},
			Signature: initiating.Signature})
	}
	ge.Votes = append(ge.Votes, govvote.VoteEvidence{Fact: govvote.RecordedVote{ID: vote.Message,
		Authority: govvote.CanonicalAccSpelling(vote.Authority), Origin: govvote.CanonicalAccSpelling(vote.Origin),
		Vote: protocol.VoteTypeAccept, Block: int64(xworld.ProvenBlockBVN1) - 1}})
	facts, err := GoverningFactsFromVoteEvidence(ge)
	if err != nil {
		t.Fatalf("the intent's vote evidence: %v", err)
	}
	return facts
}

// nvBind is BindProofV21 over the verified report with the G0 and G1 that bind to it (the certified key page is G1's page).
func nvBind(rep *proofv2.Report, facts *GoverningFacts, keyPage, keyBook string) error {
	hx := func(b [32]byte) string { return hex.EncodeToString(b[:]) }
	g0 := &proof.G0Result{EntryHashExec: hx(rep.TxHash), ExecWitness: hx(rep.AnchorRootChainAnchor), ExecMBI: int64(rep.AnchorBlock)}
	g0.Receipt.Start = g0.EntryHashExec
	g1 := &proof.G1Result{}
	g1.AuthoritySnapshot.Page = keyPage
	return BindProofV21(rep, g0, g1, keyPage, keyBook, facts)
}

// Fixture control: a VOTING initiator in the same shape - the authority page that votes also signed first and paid, and is the certified key
// page - verifies with nothing unproven and BINDS on the base. This is what makes the failure below attributable to the initiator and not to
// the harness (blocks, G0, G1, facts): the same path accepts the voting shape.
func TestWorldVotingInitiatorVerifiesAndBinds(t *testing.T) {
	b := nvWorld(t, xworld.Timeline{Initiate: true})
	nvAddRoles(t, b.Evidence, xworld.BankPage1, proofv2.RoleInitiatorSigner, proofv2.RoleCertifiedKeyPage)
	rep, err := nvVerify(t, b)
	if err != nil {
		t.Fatalf("the voting-initiator world does not verify: %v", err)
	}
	if len(rep.Unproven) != 0 {
		t.Fatalf("the voting-initiator world leaves %v unproven", rep.Unproven)
	}
	facts := nvFacts(t, b, nil)
	if got := strings.Join(facts.Initiators, ","); got != strings.ToLower(xworld.BankPage1) {
		t.Fatalf("the intent's vote evidence names the initiating pages %q, want the voting page %s", got, xworld.BankPage1)
	}
	if err := nvBind(rep, facts, xworld.BankPage1, xworld.BankBook); err != nil {
		t.Fatalf("BindProofV21 refuses the voting-initiator world: %v", err)
	}
}

// T1 (G-83), the situation as the DESIRED behaviour: a transaction initiated by a page that is NOT a voting authority - ErpPage1 of an
// identity that is no authority of the principal signs first and pays, BankBook then votes through BankPage1 - whose page records the role
// initiator-signer, verifies with the role PROVEN (nothing unproven, no Declared initiator-signer) and BindProofV21 accepts it, with the
// initiator proven. On the base it failed with g1_initiator_signature_not_carried (fail-before recorded in state/dax/dax1g/evidence/t1-run-2.txt): no
// member of the document carried the initiating signature, and initiatorPages searched only the cause chains of the votes. It now passes because the
// document carries it (Evidence.InitiatingSignature) and the verifier proves it (xroles.go carriedInitiatorPages); bind_v21.go is not changed.
func TestNonVotingInitiatorIsProvenAndBound(t *testing.T) {
	b := nvWorld(t, xworld.Timeline{ExternalInitiator: true})
	if b.Initiating == nil {
		t.Fatal("the world holds no initiating signature")
	}

	// The fixture is the situation: the signature on ErpPage1 initiated the transaction (its metadata hash is Header.Initiator), no signature of
	// a vote's cause chain did, and ErpPage1 is no authority of the principal and no voter.
	txRaw, err := hex.DecodeString(b.Evidence.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalBinary(txRaw); err != nil {
		t.Fatal(err)
	}
	sigRaw, err := hex.DecodeString(b.Initiating.Signature)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.UnmarshalSignature(sigRaw)
	if err != nil {
		t.Fatal(err)
	}
	if did, _ := protocol.SignatureDidInitiate(sig, txn.Header.Initiator[:], nil); !did || !strings.EqualFold(b.Initiating.Page, xworld.ErpPage1) {
		t.Fatalf("the world's initiating signature on %s does not initiate the transaction", b.Initiating.Page)
	}
	for _, v := range b.Evidence.Votes {
		if strings.EqualFold(v.Origin, xworld.ErpPage1) || strings.EqualFold(v.Authority, xworld.ErpBook) {
			t.Fatalf("the initiator votes: %+v", v)
		}
		for _, h := range v.Hops {
			hs, err := hex.DecodeString(h.Signature)
			if err != nil {
				t.Fatal(err)
			}
			s, err := protocol.UnmarshalSignature(hs)
			if err != nil {
				t.Fatal(err)
			}
			if did, _ := protocol.SignatureDidInitiate(s, txn.Header.Initiator[:], nil); did {
				t.Fatalf("a vote's cause chain carries the initiating signature (%s): this is the voting shape", h.Page)
			}
		}
	}
	recorded := false
	for _, p := range b.Evidence.Pages {
		if strings.EqualFold(p.URL, xworld.ErpPage1) {
			for _, r := range p.Roles {
				recorded = recorded || r == proofv2.RoleInitiatorSigner
			}
		}
	}
	if !recorded {
		t.Fatalf("%s does not record initiator-signer", xworld.ErpPage1)
	}

	rep, err := nvVerify(t, b)
	if err != nil {
		t.Fatalf("the non-voting-initiator world does not verify: %v", err)
	}
	if len(rep.Unproven) != 0 {
		t.Fatalf("the report is not a verified S3: %v", rep.Unproven)
	}
	found := false
	for _, g := range rep.Proven {
		if !strings.EqualFold(g.URL, xworld.ErpPage1) {
			continue
		}
		found = true
		has := false
		for _, r := range g.Roles {
			has = has || r == proofv2.RoleInitiatorSigner
		}
		if !has {
			t.Fatalf("%s: initiator-signer is not a proven role (roles %v, declared %v)", g.URL, g.Roles, g.Declared)
		}
		for _, r := range g.Declared {
			if r != proofv2.RoleCertifiedKeyPage {
				t.Fatalf("%s: %s is only declared", g.URL, r)
			}
		}
	}
	if !found {
		t.Fatalf("%s is not among the proven pages", xworld.ErpPage1)
	}

	facts := nvFacts(t, b, b.Initiating)
	if got := strings.Join(facts.Initiators, ","); got != strings.ToLower(xworld.ErpPage1) {
		t.Fatalf("the intent's vote evidence names the initiating pages %q, want %s", got, xworld.ErpPage1)
	}
	if err := nvBind(rep, facts, xworld.ErpPage1, xworld.ErpBook); err != nil {
		var ns *proofv2.NamedState
		if errors.As(err, &ns) {
			t.Fatalf("BindProofV21 refuses the non-voting-initiator world: %s: %v", ns.Code, err)
		}
		t.Fatalf("BindProofV21 refuses the non-voting-initiator world: %v", err)
	}
}

// The binding rule, which DAX-1G does not change (bind_v21.go is untouched). On the document WITHOUT the member (the world built as every document
// made before the member is: the page records initiator-signer, nothing carries the signature) the report names g1_initiator_signature_not_carried
// and the binding refuses it by that entry, before anything else is judged. The report a verifier that PROVES the initiating signature must
// produce for the same transaction - nothing unproven, initiator-signer a proven role of ErpPage1 and only certified-key-page declared - is bound
// as it stands (the report is edited from the member-absent world's, so the binding alone is shown sufficient: T1 turns green by the verifier and
// the document, never by the binding). The same report without the role proven is refused by the initiator's state. Passes before and after the
// verifier's change: the member-absent document stays refused and its report stays unbound.
func TestBindingAcceptsTheReportAProvenNonVotingInitiatorProduces(t *testing.T) {
	b := nvWorld(t, xworld.Timeline{ExternalInitiator: true, OmitInitiatingSignature: true})
	rep, err := nvVerify(t, b)
	if err != nil {
		t.Fatal(err)
	}
	facts := nvFacts(t, b, b.Initiating)

	// The member-absent report: refused by its own first named state, before anything else is judged.
	if err := nvBind(rep, facts, xworld.ErpPage1, xworld.ErpBook); err == nil {
		t.Fatal("a report with an unproven initiator was bound")
	} else if !strings.Contains(err.Error(), proofv2.StateInitiatorSignatureNotCarried) {
		t.Fatalf("refused, but not by the unproven initiating signature: %v", err)
	}

	// The report a proving verifier produces for the same document.
	fixed := *rep
	fixed.Unproven = nil
	fixed.Proven = append([]proofv2.ProvenPage(nil), rep.Proven...)
	for i, g := range fixed.Proven {
		if !strings.EqualFold(g.URL, xworld.ErpPage1) {
			continue
		}
		g.Roles = append(append([]proofv2.PageRole(nil), g.Roles...), proofv2.RoleInitiatorSigner)
		var declared []proofv2.PageRole
		for _, r := range g.Declared {
			if r != proofv2.RoleInitiatorSigner {
				declared = append(declared, r)
			}
		}
		g.Declared = declared
		fixed.Proven[i] = g
	}
	if err := nvBind(&fixed, facts, xworld.ErpPage1, xworld.ErpBook); err != nil {
		t.Fatalf("BindProofV21 refuses the report of a proven non-voting initiator: %v", err)
	}

	// And the role is what the binding needs: proven nowhere, it refuses the same report by the initiator's state.
	unproven := fixed
	unproven.Proven = append([]proofv2.ProvenPage(nil), fixed.Proven...)
	for i, g := range unproven.Proven {
		if strings.EqualFold(g.URL, xworld.ErpPage1) {
			var roles []proofv2.PageRole
			for _, r := range g.Roles {
				if r != proofv2.RoleInitiatorSigner {
					roles = append(roles, r)
				}
			}
			g.Roles = append(roles, proofv2.RoleSyntheticChain) // some other proven role, so the certified page still proves something
			unproven.Proven[i] = g
		}
	}
	err = nvBind(&unproven, facts, xworld.ErpPage1, xworld.ErpBook)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateInitiatorPageUnproven {
		t.Fatalf("the initiating page without its role proven: want %s, got %v", proofv2.StateInitiatorPageUnproven, err)
	}
}
