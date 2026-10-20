package intentcert

import (
	"errors"
	"strings"
	"testing"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

func wantDetail(t *testing.T, name string, err error, code, contains string) {
	t.Helper()
	wantState(t, name, err, code)
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Errorf("%s: want a refusal containing %q, got %v", name, contains, err)
	}
}

func bind21Book(t *testing.T, f *x21, book string) error {
	t.Helper()
	rep, g0, g1, kp := f.report()
	facts := f.facts
	return BindProofV21(rep, g0, g1, kp, book, &facts)
}

// RB9-C1a-F4 / C1b-2: the verifier can only DECLARE certified-key-page (it depends on the intent certificate), so the binding justifies it:
// the page is proven, recorded as the certified key page, a page of the book the certificate declares, and a page of the governing set.
func TestBindProofV21CertifiedPageIsJustifiedAgainstTheDeclaredBook(t *testing.T) {
	// The verifier's own form: initiator-signer proven, certified-key-page declared, the book the certificate names.
	if err := bind21Book(t, newX21(), xERPBook); err != nil {
		t.Fatalf("the declared certified page of the declared book: %v", err)
	}
	// Recorded in Roles rather than Declared is the same fact.
	if err := bind21Book(t, newX21().roles(xERP, proofv2.RoleInitiatorSigner, proofv2.RoleCertifiedKeyPage).declare(xERP), xERPBook); err != nil {
		t.Fatalf("certified-key-page among the proven roles: %v", err)
	}
	// The spelling of the declared book does not matter.
	if err := bind21Book(t, newX21(), "ACC://ERP.acme/book/"); err != nil {
		t.Fatalf("another spelling of the declared book: %v", err)
	}
	// A page of another book than the certificate declares.
	wantDetail(t, "page not in the declared book", bind21Book(t, newX21(), "acc://bank.acme/book"), proofv2.StateCertifiedPageUnproven, "declares the book")
	// The page itself named as the book.
	wantState(t, "the page named as the book", bind21Book(t, newX21(), xERP), proofv2.StateCertifiedPageUnproven)
	// No book declared.
	wantDetail(t, "no declared book", bind21Book(t, newX21(), ""), proofv2.StateCertifiedPageUnproven, "declares no key book")
	// The page does not record the role at all.
	wantDetail(t, "page lacks the role", bind21Book(t, newX21().declare(xERP), xERPBook), proofv2.StateCertifiedPageUnproven, "not recorded as certified-key-page")
	// The page is not proven.
	wantDetail(t, "page not proven", bind21Book(t, newX21().drop(xERP), xERPBook), proofv2.StateCertifiedPageUnproven, "not among the pages the report proved")
	// A proven page that is not a key page cannot be the certified key page.
	f := newX21().declare(xPrincipal, proofv2.RoleCertifiedKeyPage)
	rep, g0, g1, _ := f.report()
	g1.AuthoritySnapshot.Page = xPrincipal
	facts := f.facts
	wantDetail(t, "not a key page", BindProofV21(rep, g0, g1, xPrincipal, "acc://cust.acme", &facts), proofv2.StateCertifiedPageUnproven, "not a key page")
	// The page records the role but proves nothing of the governing set: the certificate cannot name any proven page.
	f = newX21().roles(xERP).declare(xERP, proofv2.RoleCertifiedKeyPage)
	wantDetail(t, "no governing role", bind21Book(t, f, xERPBook), proofv2.StateCertifiedPageUnproven, "proves no role of the governing set")
}

// A role the verifier could not prove - it records the page with the role only as Declared because the transaction or the initiating
// signature is not carried - never satisfies the binding: it is refused as "declared, not proven", by the state of its class.
func TestBindProofV21RolesOnlyDeclaredAreRefused(t *testing.T) {
	// header-authority, on the book and on the page.
	f := newX21().roles(xHdrBook).declare(xHdrBook, proofv2.RoleHeaderAuthority)
	wantDetail(t, "header authority book declared only", bind21Book(t, f, xERPBook), proofv2.StateHeaderAuthorityMissing, "declared, not proven")
	f = newX21().roles(xHdrPage).declare(xHdrPage, proofv2.RoleHeaderAuthority)
	wantDetail(t, "header authority page declared only", bind21Book(t, f, xERPBook), proofv2.StateHeaderAuthorityMissing, "declared, not proven")
	// initiator-signer: the initiating page, and a delegator of the initiating signature.
	f = newX21().roles(xERP, proofv2.RoleVoter).declare(xERP, proofv2.RoleInitiatorSigner, proofv2.RoleCertifiedKeyPage)
	wantDetail(t, "initiating page declared only", bind21Book(t, f, xERPBook), proofv2.StateInitiatorPageUnproven, "declared, not proven")
	f = newX21().roles(xERPDeleg).declare(xERPDeleg, proofv2.RoleInitiatorSigner)
	wantDetail(t, "initiating delegator declared only", bind21Book(t, f, xERPBook), proofv2.StateInitiatorPageUnproven, "declared, not proven")
	// A role that is not declared either keeps its old message (the role is simply not there).
	err := bind21Book(t, newX21().roles(xHdrPage, proofv2.RoleVoter), xERPBook)
	wantState(t, "header authority page without the role", err, proofv2.StateHeaderAuthorityMissing)
	if err == nil || strings.Contains(err.Error(), "declared, not proven") {
		t.Errorf("a page that records nothing was called declared: %v", err)
	}
}

// The governing facts are read from the transaction in the vote evidence; the report proved a transaction. They must be one.
func TestBindProofV21TheFactsAreAboutTheProvenTransaction(t *testing.T) {
	f := newX21()
	f.facts.TxHash[31] ^= 1
	wantDetail(t, "another transaction", bind21(t, f), proofv2.StateTransactionMismatch, "the report proved")
	f = newX21()
	f.facts.TxHash = [32]byte{}
	wantState(t, "no transaction hash", bind21(t, f), proofv2.StateTransactionMismatch)
}

// A report that names anything unproven is not a verified S3: the binding refuses with that entry itself.
func TestBindProofV21RefusesAReportWithAnythingUnproven(t *testing.T) {
	for _, c := range []struct {
		name string
		u    []proofv2.NamedState
		want proofv2.NamedState
	}{
		{"votes not re-evaluated", []proofv2.NamedState{{Code: proofv2.StateCompletenessUnproven, Partition: "acc://bvn-BVN1.acme", Block: blkX, Detail: "the votes are not re-evaluated"}},
			proofv2.NamedState{Code: proofv2.StateCompletenessUnproven, Partition: "acc://bvn-BVN1.acme", Block: blkX}},
		{"a held vote", []proofv2.NamedState{{Code: proofv2.StateVoteHeld, Partition: partBVN2, Block: blkY2, Detail: "production unproven"}},
			proofv2.NamedState{Code: proofv2.StateVoteHeld, Partition: partBVN2, Block: blkY2}},
		{"initiator not carried first", []proofv2.NamedState{
			{Code: proofv2.StateInitiatorSignatureNotCarried, Partition: partBVN3, Block: blkY3}, {Code: proofv2.StateVoteHeld, Partition: partBVN2, Block: blkY2}},
			proofv2.NamedState{Code: proofv2.StateInitiatorSignatureNotCarried, Partition: partBVN3, Block: blkY3}},
	} {
		rep, g0, g1, kp := newX21().report()
		rep.Unproven = c.u
		facts := newX21().facts
		err := BindProofV21(rep, g0, g1, kp, xERPBook, &facts)
		var ns *proofv2.NamedState
		if !errors.As(err, &ns) || ns.Code != c.want.Code || ns.Partition != c.want.Partition || ns.Block != c.want.Block {
			t.Errorf("%s: want %+v, got %v", c.name, c.want, err)
		}
	}
	// And the complete report is bound.
	if err := bind21(t, newX21()); err != nil {
		t.Fatal(err)
	}
}

func withAnchor(t *testing.T, f *x21, block uint64) error {
	t.Helper()
	rep, g0, g1, kp := f.report()
	rep.AnchorBlock, g0.ExecMBI = block, int64(block)
	facts := f.facts
	return BindProofV21(rep, g0, g1, kp, xERPBook, &facts)
}

// g1_executor_version_unsupported is derived from the pinned activation table: for every (partition, block) the report is judged at, a
// version from Baikonur on must be proven, and the ledger page, when the document carries one, must agree. No ledger page is required.
func TestBindProofV21ExecutorVersionFromThePinnedTable(t *testing.T) {
	// No ledger page in the document (live Kermit serves none): bound, the table proves the version at every (partition, block).
	if err := bind21(t, newX21()); err != nil {
		t.Fatalf("no ledger page: %v", err)
	}
	// Each partition's activation block: the version after it is proven, the block itself is not.
	act := proofv2.KermitExecutorActivations()
	// BVN2 and BVN3 carry authority/delegate pages in the fixture.
	for _, c := range []struct {
		part, page, key string
	}{{partBVN2, xBook1, "bvn2"}, {partBVN3, xDelPage, "bvn3"}} {
		a := act[c.key].Block
		wantState(t, c.key+" at the activation block", bind21(t, newX21().place(c.page, c.part, a)), proofv2.StateExecutorVersionUnsupported)
		wantState(t, c.key+" below the activation block", bind21(t, newX21().place(c.page, c.part, a-1000)), proofv2.StateExecutorVersionUnsupported)
		// (The fixture's signatures arrived at blocks above the moved page's: their blocks are cleared so only the executor rule is exercised.)
		moved := newX21().place(c.page, c.part, a+1)
		for i := range moved.facts.Signatures {
			moved.facts.Signatures[i].Block = 0
		}
		for i := range moved.facts.Arrivals {
			moved.facts.Arrivals[i].Block = 0
		}
		if err := bind21(t, moved); err != nil {
			t.Fatalf("%s one block after its activation: %v", c.key, err)
		}
	}
	// The transaction's own partition (BVN1): its anchor block decides, and the principal is proven there.
	a := act["bvn1"].Block
	b1 := newX21().place(xPrincipal, partBVN1, a+1)
	b1.facts.Votes[0].Block = 0 // the fixture's recorded vote is after the moved anchor block: only the executor rule is exercised
	if err := withAnchor(t, b1, a+1); err != nil {
		t.Fatalf("bvn1 one block after its activation: %v", err)
	}
	err := withAnchor(t, newX21().place(xPrincipal, partBVN1, a), a)
	wantDetail(t, "bvn1 at the activation block", err, proofv2.StateExecutorVersionUnsupported, "pinned activation table")
	var ns *proofv2.NamedState
	if errors.As(err, &ns) && (ns.Block != a || !strings.EqualFold(ns.Partition, partBVN1)) {
		t.Errorf("the refusal names %s block %d, want %s block %d", ns.Partition, ns.Block, partBVN1, a)
	}
	// An unknown partition is not established, never assumed.
	wantDetail(t, "unknown partition", bind21(t, newX21().place(xBook1, "acc://bvn-BVN9.acme", blkY2)), proofv2.StateExecutorVersionUnsupported, "not established")
	// The Directory is in the table.
	dn := newX21().place(xDelPage, "acc://dn.acme", act["directory"].Block+1)
	dn.facts.Signatures[1].Block, dn.facts.Arrivals[0].Block = 0, 0
	if err := bind21(t, dn); err != nil {
		t.Fatalf("a page proven through the Directory after its activation: %v", err)
	}
	wantState(t, "directory at its activation block", bind21(t, newX21().place(xDelPage, "acc://dn.acme", act["directory"].Block)), proofv2.StateExecutorVersionUnsupported)
}

// A system-ledger page, when the document carries one, is evidence that must agree with the table.
func TestBindProofV21LedgerPageMustAgreeWithThePinnedTable(t *testing.T) {
	withLedger := func(v protocol.ExecutorVersion) *x21 {
		f := newX21()
		f.add(&protocol.SystemLedger{Url: protocol.PartitionUrl("BVN2").JoinPath(protocol.Ledger), ExecutorVersion: v}, partBVN2, blkY2, proofv2.RoleSystemLedger)
		return f
	}
	if err := bind21(t, withLedger(protocol.ExecutorVersionV2Kourou)); err != nil {
		t.Fatalf("a ledger page that agrees: %v", err)
	}
	if err := bind21(t, withLedger(protocol.ExecutorVersionV2Kourou+1)); err != nil {
		t.Fatalf("a ledger page above the table's floor: %v", err)
	}
	for _, v := range []protocol.ExecutorVersion{protocol.ExecutorVersionV2Baikonur, protocol.ExecutorVersionV2Vandenberg, protocol.ExecutorVersionV1} {
		wantDetail(t, "a ledger page below the table", bind21(t, withLedger(v)), proofv2.StateExecutorVersionUnsupported, "disagrees with the pinned table")
	}
}

// RB9-J1 handoff: a document built before a vote's production carried the SequencedMessage verifies with the disclosure
// g1_vote_production_unbound (the production is not bound to the vote's message). A disclosure is not a refusal for the verifier, but the
// intent binding cannot certify a vote whose arrival is not bound to it: BindProofV21 refuses the report by that named state, with the
// partition and block it was judged at. Other disclosures stay disclosures.
func TestBindProofV21RefusesAReportWhoseVoteProductionIsUnbound(t *testing.T) {
	rep, g0, g1, kp := newX21().report()
	rep.Disclosures = []proofv2.NamedState{
		{Code: proofv2.StateAuthorityVoterOutsideList, Partition: partBVN1, Block: blkX, Detail: "a disclosure that is not a refusal"},
		{Code: proofv2.StateVoteProductionUnbound, Partition: partBVN2, Block: blkY2, Detail: "no SequencedMessage"}}
	facts := newX21().facts
	err := BindProofV21(rep, g0, g1, kp, xERPBook, &facts)
	var ns *proofv2.NamedState
	if !errors.As(err, &ns) || ns.Code != proofv2.StateVoteProductionUnbound || ns.Partition != partBVN2 || ns.Block != blkY2 {
		t.Fatalf("a report with an unbound production: want %s{%s,%d}, got %v", proofv2.StateVoteProductionUnbound, partBVN2, blkY2, err)
	}
	// Only that disclosure refuses: the others do not, and a report without any binds.
	rep.Disclosures = rep.Disclosures[:1]
	if err := BindProofV21(rep, g0, g1, kp, xERPBook, &facts); err != nil {
		t.Fatalf("a report whose only disclosure is not a refusal: %v", err)
	}
}
