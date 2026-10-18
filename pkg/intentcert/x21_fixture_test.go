package intentcert

import (
	"encoding/hex"
	"fmt"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// A 2.1 report built from real protocol accounts: the tcl model, an intent on a customer's account (BVN1) whose approving
// authority is a bank's key book on another identity and another partition (BVN2), with a header authority (BVN2), a delegate
// of the bank's second page on a third identity (BVN3), and the page of an unrelated identity's ERP (BVN3) that initiated the
// transaction and is the certified key page (the harbor-mfg shape).
const (
	partBVN1 = "acc://bvn-BVN1.acme"
	partBVN2 = "acc://bvn-BVN2.acme"
	partBVN3 = "acc://bvn-BVN3.acme"

	xPrincipal = "acc://cust.acme/payments"
	xBook      = "acc://bank.acme/book"
	xBook1     = "acc://bank.acme/book/1"
	xBook2     = "acc://bank.acme/book/2"
	xHdrBook   = "acc://hdr.acme/book"
	xHdrPage   = "acc://hdr.acme/book/1"
	xDelBook   = "acc://deleg.acme/book"
	xDelPage   = "acc://deleg.acme/book/1"
	xERP       = "acc://erp.acme/book/1"
	xERPDeleg  = "acc://erpdel.acme/book/1"
	xERPBook   = "acc://erp.acme/book" // the key book the certificate declares: the certified page's book
)

// Blocks are above each partition's executor-version activation block (the pinned table of pkg/proof/v2/xexecutor_table.go: BVN1 12491272,
// BVN2 12492057, BVN3 12491127), so the executor version governing them is proven; the fixture's earlier blocks (100, 250, 310) were not.
const (
	blkX  = 12_600_000 // the transaction's anchor block on BVN1
	blkY2 = 12_600_250
	blkY3 = 12_600_310
)

type x21 struct {
	accts map[string]protocol.Account
	order []string
	prov  map[string]proofv2.ProvenPage
	facts GoverningFacts
}

func mustURL(s string) *url.URL { return url.MustParse(s) }

func (f *x21) add(a protocol.Account, partition string, block uint64, roles ...proofv2.PageRole) {
	k := canon(a.GetUrl().String())
	if _, ok := f.accts[k]; !ok {
		f.order = append(f.order, k)
	}
	f.accts[k] = a
	f.prov[k] = proofv2.ProvenPage{URL: a.GetUrl().String(), Partition: partition, Block: block, Roles: roles}
}

// declare sets the roles the page records but the verifier cannot prove (ProvenPage.Declared); none clears them.
func (f *x21) declare(u string, roles ...proofv2.PageRole) *x21 {
	k := canon(u)
	p := f.prov[k]
	p.Declared = roles
	f.prov[k] = p
	return f
}

func (f *x21) clone() *x21 {
	c := &x21{accts: map[string]protocol.Account{}, prov: map[string]proofv2.ProvenPage{}, facts: f.facts}
	c.order = append(c.order, f.order...)
	for k, v := range f.accts {
		c.accts[k] = v
	}
	for k, v := range f.prov {
		p := v
		p.Roles = append([]proofv2.PageRole(nil), v.Roles...)
		p.Declared = append([]proofv2.PageRole(nil), v.Declared...)
		c.prov[k] = p
	}
	c.facts.Votes = append([]VoteRef(nil), f.facts.Votes...)
	c.facts.Arrivals = append([]ArrivalRef(nil), f.facts.Arrivals...)
	c.facts.Signatures = append([]SignatureRef(nil), f.facts.Signatures...)
	c.facts.Initiators = append([]string(nil), f.facts.Initiators...)
	c.facts.InitiatorPath = append([]string(nil), f.facts.InitiatorPath...)
	c.facts.HeaderAuthorities = append([]string(nil), f.facts.HeaderAuthorities...)
	c.facts.Authorities = append([]govvote.AccountAuthority(nil), f.facts.Authorities...)
	return c
}

func (f *x21) drop(u string) *x21 {
	k := canon(u)
	delete(f.accts, k)
	delete(f.prov, k)
	for i, o := range f.order {
		if o == k {
			f.order = append(f.order[:i:i], f.order[i+1:]...)
			break
		}
	}
	return f
}

func (f *x21) roles(u string, roles ...proofv2.PageRole) *x21 {
	k := canon(u)
	p := f.prov[k]
	p.Roles = roles
	f.prov[k] = p
	return f
}

func (f *x21) place(u, partition string, block uint64) *x21 {
	k := canon(u)
	p := f.prov[k]
	p.Partition, p.Block = partition, block
	f.prov[k] = p
	return f
}

func keyHash(seed byte) []byte {
	h := make([]byte, 32)
	for i := range h {
		h[i] = seed
	}
	return h
}

func page(u string, delegates ...string) *protocol.KeyPage {
	kp := &protocol.KeyPage{Url: mustURL(u), Version: 1, AcceptThreshold: 1}
	kp.Keys = append(kp.Keys, &protocol.KeySpec{PublicKeyHash: keyHash(byte(len(u)))})
	for _, d := range delegates {
		kp.Keys = append(kp.Keys, &protocol.KeySpec{Delegate: mustURL(d)})
	}
	return kp
}

func book(u string, pages uint64) *protocol.KeyBook {
	b := &protocol.KeyBook{Url: mustURL(u), BookType: protocol.BookTypeNormal, PageCount: pages}
	b.AddAuthority(mustURL(u))
	return b
}

func principalAccount(authority string) *protocol.TokenAccount {
	a := &protocol.TokenAccount{Url: mustURL(xPrincipal), TokenUrl: protocol.AcmeUrl()}
	a.AddAuthority(mustURL(authority))
	return a
}

// newX21 is the complete governing set of the fixture intent.
func newX21() *x21 {
	f := &x21{accts: map[string]protocol.Account{}, prov: map[string]proofv2.ProvenPage{}}
	f.add(principalAccount(xBook), partBVN1, blkX, proofv2.RolePrincipalChain)
	f.add(book(xBook, 2), partBVN2, blkY2, proofv2.RoleAuthorityBook)
	f.add(page(xBook1), partBVN2, blkY2, proofv2.RoleAuthorityPage)
	f.add(page(xBook2, xDelBook), partBVN2, blkY2, proofv2.RoleAuthorityPage, proofv2.RoleVoter)
	f.add(book(xHdrBook, 1), partBVN2, blkY2, proofv2.RoleHeaderAuthority)
	f.add(page(xHdrPage), partBVN2, blkY2, proofv2.RoleHeaderAuthority)
	f.add(book(xDelBook, 1), partBVN3, blkY3, proofv2.RoleDelegateBook)
	f.add(page(xDelPage), partBVN3, blkY3, proofv2.RoleDelegatePage, proofv2.RoleVoter)
	// The verifier proves initiator-signer from the carried transaction and can only declare certified-key-page (xverify.go).
	f.add(page(xERP), partBVN3, blkY3, proofv2.RoleInitiatorSigner)
	f.declare(xERP, proofv2.RoleCertifiedKeyPage)
	f.add(page(xERPDeleg), partBVN3, blkY3, proofv2.RoleInitiatorSigner)
	f.facts = GoverningFacts{
		Principal:         canon(xPrincipal),
		Type:              protocol.TransactionTypeSendTokens,
		TxHash:            h32(3),
		Authorities:       []govvote.AccountAuthority{{URL: canon(xBook)}},
		HeaderAuthorities: []string{canon(xHdrBook)},
		Initiators:        []string{canon(xERP)},
		InitiatorPath:     []string{canon(xERPDeleg)},
		Signatures:        []SignatureRef{{Signer: canon(xERP), Block: blkY3 - 5}, {Signer: canon(xDelPage), Block: blkY3 - 10}},
		Votes:             []VoteRef{{Authority: canon(xBook), Origin: canon(xBook2), Block: blkX - 4}},
		Arrivals:          []ArrivalRef{{Page: canon(xBook2), Origin: canon(xDelPage), Block: blkY2 - 6}},
	}
	return f
}

func hx32(b byte) string {
	h := h32(b)
	return hex.EncodeToString(h[:])
}

func h32(b byte) [32]byte {
	var o [32]byte
	for i := range o {
		o[i] = b
	}
	return o
}

// report returns the verified-report shape of the fixture, with G0 and G1 that bind to it and the key page.
func (f *x21) report() (*proofv2.Report, *proof.G0Result, *proof.G1Result, string) {
	rep := &proofv2.Report{
		Incarnation: h32(1), Majors: 3, CertifiedBlock: 900, CertifiedRoot: h32(2), CheckBlock: 910,
		Partition: partBVN1, AnchorBlock: blkX, SetVerdict: proof.VerdictVerified, Validators: 4, Threshold: 3,
		TxHash: h32(3), AnchorTxHash: h32(4), AnchorStateRoot: h32(5), AnchorRootChainAnchor: h32(6), AccumulateSetRoot: h32(7),
	}
	for _, k := range f.order {
		rep.Pages = append(rep.Pages, f.accts[k])
		rep.PageChains = append(rep.PageChains, proofv2.PageChain{URL: f.accts[k].GetUrl().String()})
		rep.Proven = append(rep.Proven, f.prov[k])
	}
	hx := func(b [32]byte) string { return hex.EncodeToString(b[:]) }
	g0 := &proof.G0Result{EntryHashExec: hx(rep.TxHash), ExecWitness: hx(rep.AnchorRootChainAnchor), ExecMBI: int64(rep.AnchorBlock)}
	g0.Receipt.Start = g0.EntryHashExec
	g1 := &proof.G1Result{}
	g1.AuthoritySnapshot.Page = xERP
	return rep, g0, g1, xERP
}

// evidence returns the 2.1 evidence the report was verified from: the pages' state bytes with their partitions and roles, and
// the proven votes.
func (f *x21) evidence(rep *proofv2.Report) *proofv2.Evidence {
	ev := &proofv2.Evidence{Version: proofv2.Version21, Account: xPrincipal}
	for i, a := range rep.Pages {
		st, err := a.MarshalBinary()
		if err != nil {
			panic(fmt.Sprintf("marshal %s: %v", a.GetUrl(), err))
		}
		// The recorded roles are the proven ones and the declared ones (what the verifier checked the recorded set against).
		recorded, err := proofv2.CanonicalRoles(append(append([]proofv2.PageRole(nil), rep.Proven[i].Roles...), rep.Proven[i].Declared...))
		if err != nil {
			panic(err)
		}
		ev.Pages = append(ev.Pages, proofv2.PageState{URL: a.GetUrl().String(), State: hex.EncodeToString(st),
			Partition: rep.Proven[i].Partition, Roles: recorded})
	}
	ev.Votes = []proofv2.Vote{x21Vote()}
	return ev
}

// x21Vote is a vote with every member of the final shape populated: a sequenced transport, a hop and a counted signature each with an
// arrival (a before and an at index entry), and a production with its own arrival - so the votes root commits all of it.
func x21Vote() proofv2.Vote {
	idx := func(pos uint64, b byte) proofv2.IndexProof {
		return proofv2.IndexProof{Position: pos, Entry: hx32(b), Receipt: "0f" + fmt.Sprintf("%02x", b)}
	}
	before, at := idx(4, 20), idx(5, 21)
	before2, at2 := idx(8, 22), idx(9, 23)
	prodAt := idx(2, 24)
	return proofv2.Vote{
		Authority: xBook, Origin: xBook2, Vote: "accept", Cause: "acc://" + hx32(9) + "@bank.acme/book/2",
		Transport: proofv2.VoteTransport{Kind: proofv2.TransportSequenced, Source: partBVN2, Destination: partBVN1, Number: 7},
		Message:   hx32(10), Receipt: "0a0b",
		Hops: []proofv2.VoteHop{{Page: xBook2, Message: hx32(11), Signature: "0c", Block: blkY2 - 6, Receipt: "0d",
			Arrival: &proofv2.Arrival{Before: &before, At: at}}},
		Counted: []proofv2.VoteHop{{Page: xBook1, Message: hx32(12), Signature: "0e", Block: blkY2 - 7, Receipt: "0f",
			Arrival: &proofv2.Arrival{Before: &before2, At: at2}}},
		Produced: &proofv2.Production{Account: xPrincipal, Chain: "signature", Message: hx32(10), Receipt: "1011",
			Arrival: proofv2.Arrival{At: prodAt}},
	}
}
