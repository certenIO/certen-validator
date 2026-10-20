package intentcert

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func bind21(t *testing.T, f *x21) error {
	t.Helper()
	rep, g0, g1, kp := f.report()
	facts := f.facts
	return BindProofV21(rep, g0, g1, kp, xERPBook, &facts)
}

func wantState(t *testing.T, name string, err error, code string) {
	t.Helper()
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) {
		t.Errorf("%s: want the named state %s, got %v", name, code, err)
		return
	}
	if ns.Code != code {
		t.Errorf("%s: want %s, got %v", name, code, err)
	}
}

// The complete governing set of the cross-identity intent binds.
func TestBindProofV21AcceptsTheCompleteGoverningSet(t *testing.T) {
	if err := bind21(t, newX21()); err != nil {
		t.Fatalf("the complete set: %v", err)
	}
}

// The harbor-mfg shape: the certified key page is the initiator page of an identity unrelated to the principal's, on another
// partition, and is not an authority. It is refused while the initiator page is not among the proven pages (or is proven but
// not as the initiator), and accepted once it is proven with both roles.
func TestBindProofV21HarborMfgCertifiedPageIsAnotherIdentitysInitiator(t *testing.T) {
	// Not proven at all: the certified-key-page rule, now satisfied only through the proven set.
	wantState(t, "initiator page not proven", bind21(t, newX21().drop(xERP)), proofv2.StateCertifiedPageUnproven)
	// Declared as the certified key page and proven a voter, but not proven as the initiator: the initiator page is not proven as the initiator.
	wantState(t, "certified but not as initiator", bind21(t, newX21().roles(xERP, proofv2.RoleVoter)), proofv2.StateInitiatorPageUnproven)
	// Proven as the initiator only, with no declared certified-key-page: the certified-key-page rule is not met.
	wantState(t, "initiator but not certified", bind21(t, newX21().declare(xERP)), proofv2.StateCertifiedPageUnproven)
	// Both roles: accepted.
	if err := bind21(t, newX21()); err != nil {
		t.Fatalf("proven as the initiator and the certified key page: %v", err)
	}
	// The page being among rep.Pages is not enough: the base rule's list is not the proven set.
	f := newX21()
	rep, g0, g1, kp := f.report()
	for i := range rep.Proven {
		if canon(rep.Proven[i].URL) == canon(xERP) {
			rep.Proven[i].Roles, rep.Proven[i].Declared = []proofv2.PageRole{proofv2.RoleInitiatorSigner}, nil
		}
	}
	facts := f.facts
	wantState(t, "in the pages list only", BindProofV21(rep, g0, g1, kp, xERPBook, &facts), proofv2.StateCertifiedPageUnproven)
}

// Each class of D1(a)-(f) that is missing is refused, by the named state of its class.
func TestBindProofV21RefusesEachMissingClass(t *testing.T) {
	for _, c := range []struct {
		name string
		f    *x21
		code string
	}{
		{"principal not proven", newX21().drop(xPrincipal), proofv2.StateCompletenessUnproven},
		{"principal chain role missing", newX21().roles(xPrincipal, proofv2.RoleAuthorityPage), proofv2.StateCompletenessUnproven},
		{"principal chain on another partition", newX21().place(xPrincipal, partBVN2, blkY2), proofv2.StateForeignPartitionMismatch},
		{"authority book not proven", newX21().drop(xBook), proofv2.StateAuthorityMissing},
		{"authority book without its role", newX21().roles(xBook, proofv2.RoleVoter), proofv2.StateAuthorityMissing},
		{"authority page 1 not proven (PageCount 2)", newX21().drop(xBook1), proofv2.StateBookPageCountUnproven},
		{"authority page 2 not proven (PageCount 2)", newX21().drop(xBook2), proofv2.StateBookPageCountUnproven},
		{"authority page without its role", newX21().roles(xBook1, proofv2.RoleVoter), proofv2.StateBookPageCountUnproven},
		{"header authority book not proven", newX21().drop(xHdrBook), proofv2.StateHeaderAuthorityMissing},
		{"header authority page not proven", newX21().drop(xHdrPage), proofv2.StateHeaderAuthorityMissing},
		{"header authority without its role", newX21().roles(xHdrBook, proofv2.RoleAuthorityBook), proofv2.StateHeaderAuthorityMissing},
		{"delegate book not proven", newX21().drop(xDelBook), proofv2.StateDelegateEntryAbsent},
		{"delegate page not proven", newX21().drop(xDelPage), proofv2.StateDelegateEntryAbsent},
		{"delegate book without its role", newX21().roles(xDelBook, proofv2.RoleAuthorityBook), proofv2.StateDelegateEntryAbsent},
		{"voter page without the voter role", newX21().roles(xBook2, proofv2.RoleAuthorityPage), proofv2.StateCompletenessUnproven},
		{"delegated vote's origin without the voter role", newX21().roles(xDelPage, proofv2.RoleDelegatePage), proofv2.StateCompletenessUnproven},
		{"initiator page without its role", newX21().roles(xERP, proofv2.RoleVoter), proofv2.StateInitiatorPageUnproven},
		{"initiating signature's delegator not proven", newX21().drop(xERPDeleg), proofv2.StateInitiatorPageUnproven},
		{"certified key page not proven", newX21().drop(xERP), proofv2.StateCertifiedPageUnproven},
		{"page with no partition", newX21().place(xBook1, "", blkY2), proofv2.StateForeignPartitionMismatch},
		{"page with no block", newX21().place(xBook1, partBVN2, 0), proofv2.StatePageBlockMismatch},
		{"page on the transaction's partition at another block", newX21().place(xPrincipal, partBVN1, blkX+1), proofv2.StatePageBlockMismatch},
	} {
		wantState(t, c.name, bind21(t, c.f), c.code)
	}
}

// A counted signature or delegated arrival may not be later than the block, on the page's own partition, the page is proven at;
// a recorded vote may not be later than the principal's anchor block.
func TestBindProofV21RefusesAPageProvenBeforeAnArrival(t *testing.T) {
	f := newX21()
	f.facts.Signatures[0].Block = blkY3 + 1 // the ERP page is proven at blkY3 on BVN3
	wantState(t, "signature after the page's block", bind21(t, f), proofv2.StateBlockBeforeArrival)

	f = newX21()
	f.facts.Arrivals[0].Block = blkY2 + 1
	wantState(t, "delegated vote after the page's block", bind21(t, f), proofv2.StateBlockBeforeArrival)

	f = newX21()
	f.facts.Votes[0].Block = blkX + 1
	wantState(t, "vote after the anchor block", bind21(t, f), proofv2.StateBlockBeforeArrival)

	// On each page's OWN partition: a signature at BVN3's block 305 is judged against BVN3's block, never the principal's 100.
	f = newX21()
	f.facts.Signatures[0].Block = blkY3 - 1
	if err := bind21(t, f); err != nil {
		t.Fatalf("a signature earlier than its page's own block: %v", err)
	}
}

// A 2.1 report cannot be bound by the weaker rule; a 2.0 report still is, exactly as before.
func TestBindProofV2RefusesAnEvidence21Report(t *testing.T) {
	rep, g0, g1, kp := newX21().report()
	err := BindProofV2(rep, g0, g1, kp)
	if err == nil || !strings.Contains(err.Error(), "BindProofV21") {
		t.Fatalf("want a refusal naming BindProofV21, got %v", err)
	}
	rep.Proven = nil
	if err := BindProofV2(rep, g0, g1, kp); err != nil {
		t.Fatalf("with the proven records removed the report is a 2.0 one and binds as before: %v", err)
	}
}

// The G0 and G1 bindings of BindProofV2 apply to a 2.1 report too.
func TestBindProofV21AppliesTheG0AndG1Bindings(t *testing.T) {
	rep, g0, g1, kp := newX21().report()
	facts := newX21().facts
	g0.ExecMBI++
	if err := BindProofV21(rep, g0, g1, kp, xERPBook, &facts); err == nil || !strings.Contains(err.Error(), "execution block") {
		t.Errorf("G0 block: %v", err)
	}
	rep, g0, g1, kp = newX21().report()
	g1.AuthoritySnapshot.Page = "acc://other.acme/book/1"
	if err := BindProofV21(rep, g0, g1, kp, xERPBook, &facts); err == nil || !strings.Contains(err.Error(), "not the page G1 validated against") {
		t.Errorf("G1 page: %v", err)
	}
	rep, g0, g1, kp = newX21().report()
	rep.Proven = rep.Proven[:2]
	if err := BindProofV21(rep, g0, g1, kp, xERPBook, &facts); err == nil {
		t.Error("proven records that do not describe the pages were accepted")
	}
}

// Delegation is followed breadth first to protocol.DelegationDepthLimit: the books to level 20 are required, a level-21 book is
// not (no executed signature passes through it), and a cycle is legal.
func TestBindProofV21DelegateDepthAndCycles(t *testing.T) {
	chain := func(n int) *x21 {
		f := newX21()
		f.facts.Arrivals, f.facts.Votes = nil, nil
		f.drop(xDelBook).drop(xDelPage)
		f.add(page(xBook2, "acc://d0.acme/book"), partBVN2, blkY2, proofv2.RoleAuthorityPage)
		for i := 0; i < n; i++ {
			b, p := fmt.Sprintf("acc://d%d.acme/book", i), fmt.Sprintf("acc://d%d.acme/book/1", i)
			next := fmt.Sprintf("acc://d%d.acme/book", i+1)
			f.add(book(b, 1), partBVN3, blkY3, proofv2.RoleDelegateBook)
			f.add(page(p, next), partBVN3, blkY3, proofv2.RoleDelegatePage)
		}
		return f
	}
	// d0 is level 1 (one delegator), d19 is level 20; d20 is level 21 and is neither required nor followed.
	if err := bind21(t, chain(20)); err != nil {
		t.Fatalf("books to level 20: %v", err)
	}
	if err := bind21(t, chain(23)); err != nil {
		t.Fatalf("books beyond level 20 present too: %v", err)
	}
	wantState(t, "level 20 book missing", bind21(t, chain(20).drop("acc://d19.acme/book")), proofv2.StateDelegateEntryAbsent)
	wantState(t, "level 20 page missing", bind21(t, chain(20).drop("acc://d19.acme/book/1")), proofv2.StateDelegateEntryAbsent)
	wantState(t, "level 3 book missing", bind21(t, chain(20).drop("acc://d2.acme/book")), proofv2.StateDelegateEntryAbsent)
	// A cycle back to the authority book and to an earlier delegate is not an error.
	f := chain(4)
	f.add(page("acc://d3.acme/book/1", xBook, "acc://d1.acme/book"), partBVN3, blkY3, proofv2.RoleDelegatePage)
	if err := bind21(t, f); err != nil {
		t.Fatalf("a delegation cycle: %v", err)
	}
}

// A role the design does not name is refused, never ignored.
func TestBindProofV21RefusesAnUnknownRole(t *testing.T) {
	f := newX21().roles(xHdrPage, proofv2.RoleHeaderAuthority, proofv2.PageRole("owner"))
	if err := bind21(t, f); err == nil || !strings.Contains(err.Error(), "unknown page role") {
		t.Fatalf("an unknown role was accepted: %v", err)
	}
}

// GoverningFactsFromVoteEvidence reads the governing facts from a real transaction and real signatures.
func TestGoverningFactsFromVoteEvidence(t *testing.T) {
	txn := &protocol.Transaction{Body: &protocol.SendTokens{To: []*protocol.TokenRecipient{{Url: mustURL("acc://to.acme/tokens"), Amount: *big.NewInt(1)}}}}
	txn.Header.Principal = mustURL(xPrincipal)
	txn.Header.Authorities = append(txn.Header.Authorities, mustURL(xHdrBook))

	// The initiating signature is delegated: erpdel's page signs on behalf of the ERP page.
	inner := &protocol.ED25519Signature{PublicKey: keyHash(1), Signature: keyHash(2), Signer: mustURL(xERPDeleg), SignerVersion: 1, Timestamp: 5}
	initiating := &protocol.DelegatedSignature{Signature: inner, Delegator: mustURL(xERP)}
	copy(txn.Header.Initiator[:], initiating.Metadata().Hash())
	other := &protocol.ED25519Signature{PublicKey: keyHash(3), Signature: keyHash(4), Signer: mustURL(xBook1), SignerVersion: 1, Timestamp: 6}

	enc := func(s protocol.Signature) string {
		b, err := s.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b)
	}
	tb, err := txn.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	ev := &govvote.Evidence{
		Version: govvote.EvidenceVersion, Account: xPrincipal, Transaction: hex.EncodeToString(tb),
		Authorities: []govvote.AccountAuthority{{URL: xBook}, {URL: "acc://off.acme/book", Disabled: true}},
		Extra:       []string{"acc://extra.acme/book"},
		Signatures: []govvote.SignatureEvidence{
			{Fact: govvote.SigFact{ID: "a", Signer: canon(xBook1), Block: 7}, Signature: enc(other)},
			{Fact: govvote.SigFact{ID: "b", Signer: canon(xERPDeleg), Path: []string{canon(xERP)}, Block: 9}, Signature: enc(initiating)},
		},
		Votes:    []govvote.VoteEvidence{{Fact: govvote.RecordedVote{ID: "v", Authority: canon(xBook), Origin: canon(xBook1), Block: 3}}},
		Arrivals: []govvote.ArrivalEvidence{{Fact: govvote.ArrivalFact{ID: "r", Page: canon(xBook2), Origin: canon(xDelPage), Path: []string{canon(xERP)}, Block: 4}}},
	}
	got, err := GoverningFactsFromVoteEvidence(ev)
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal != canon(xPrincipal) || got.Type != protocol.TransactionTypeSendTokens {
		t.Errorf("principal/type: %+v", got)
	}
	if string(got.TxHash[:]) != string(txn.GetHash()) || got.TxHash == [32]byte{} {
		t.Errorf("the facts' transaction hash %x is not the transaction's %x", got.TxHash, txn.GetHash())
	}
	if want := []string{canon(xHdrBook), "acc://extra.acme/book"}; strings.Join(got.HeaderAuthorities, ",") != strings.Join(want, ",") {
		t.Errorf("header authorities %v, want %v", got.HeaderAuthorities, want)
	}
	if want := canon(xERPDeleg); len(got.Initiators) != 1 || got.Initiators[0] != want {
		t.Errorf("initiators %v, want [%s]", got.Initiators, want)
	}
	if len(got.InitiatorPath) != 1 || got.InitiatorPath[0] != canon(xERP) {
		t.Errorf("initiator path %v, want [%s]", got.InitiatorPath, canon(xERP))
	}
	if len(got.Authorities) != 2 || !got.Authorities[1].Disabled {
		t.Errorf("authorities %v", got.Authorities)
	}
	if len(got.Signatures) != 2 || got.Signatures[1].Block != 9 || len(got.Votes) != 1 || len(got.Arrivals) != 1 || got.Arrivals[0].Path[0] != canon(xERP) {
		t.Errorf("signatures/votes/arrivals: %+v", got)
	}

	// Evidence with no signature that initiated the transaction cannot say who initiated and paid: refused by name.
	bad := *ev
	bad.Signatures = bad.Signatures[:1]
	_, err = GoverningFactsFromVoteEvidence(&bad)
	wantState(t, "no initiating signature", err, proofv2.StateInitiatorPageUnproven)

	// Evidence for another principal than its transaction names is refused.
	bad = *ev
	bad.Account = "acc://someone.acme/else"
	if _, err := GoverningFactsFromVoteEvidence(&bad); err == nil {
		t.Error("evidence for another principal was read")
	}
	if _, err := GoverningFactsFromVoteEvidence(nil); err == nil {
		t.Error("nil evidence was read")
	}
	// The facts are JSON-free values; they round-trip through the evidence's own encoding untouched.
	if _, err := json.Marshal(got); err != nil {
		t.Error(err)
	}
}

// The base rule bound a report whose only page was the certified key page of an unrelated identity; BindProofV21 refuses the same
// report, and BindProofV2 refuses it as evidence 2.1.
func TestBindProofV21RefusesAReportWithOnlyTheCertifiedPage(t *testing.T) {
	f := newX21()
	for _, u := range []string{xPrincipal, xBook, xBook1, xBook2, xHdrBook, xHdrPage, xDelBook, xDelPage, xERPDeleg} {
		f.drop(u)
	}
	rep, g0, g1, kp := f.report()
	facts := f.facts
	err := BindProofV21(rep, g0, g1, kp, xERPBook, &facts)
	wantState(t, "only the certified page", err, proofv2.StateCompletenessUnproven)
	if err := BindProofV2(rep, g0, g1, kp); err == nil {
		t.Fatal("BindProofV2 bound a 2.1 report")
	}
}
