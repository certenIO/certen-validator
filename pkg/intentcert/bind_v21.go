package intentcert

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// SignatureRef is a user signature on the transaction the vote evidence examined: the key page it was signed by and the block
// of THAT page's partition it arrived in.
type SignatureRef struct {
	Signer string
	Block  int64
}

// VoteRef is one authority's vote as the network recorded it on the principal: the book, the page that cast it, and the block of
// the principal's partition it was recorded in.
type VoteRef struct {
	Authority string
	Origin    string
	Block     int64
}

// ArrivalRef is one delegated vote recorded on the delegator page that received it, in a block of that page's partition.
type ArrivalRef struct {
	Page   string
	Origin string
	Path   []string
	Block  int64
}

// GoverningFacts are the facts of an intent that decide which pages its proof must have proven (docs/proof/G1_CROSS_PARTITION.md
// D1(a)-(f)), read from the intent's own vote evidence: the transaction, the authority set it was judged against, and the
// signatures, delegated arrivals and recorded votes the vote model examined. Every URL is in canonical spelling.
type GoverningFacts struct {
	Principal string
	Type      protocol.TransactionType
	// TxHash is the hash of the transaction the vote evidence carries (txn.GetHash()): the binding requires it to be the transaction the
	// report proved, so the facts and the proof are about one transaction.
	TxHash [32]byte
	// Authorities are the principal's resolved authority set as the intent was judged against it, enabled and disabled.
	Authorities []govvote.AccountAuthority
	// HeaderAuthorities are the books the header and the body name (Header.Authorities, GetAdditionalAuthorities, the
	// evidence's extra set): they are all required to approve.
	HeaderAuthorities []string
	// Initiators are the pages that initiated and paid for the transaction (the initiating signature's payer, and its signer);
	// InitiatorPath are the delegators of the initiating signature.
	Initiators    []string
	InitiatorPath []string
	Signatures    []SignatureRef
	Votes         []VoteRef
	Arrivals      []ArrivalRef
}

func canon(u string) string { return govvote.CanonicalAccSpelling(u) }

func appendOnce(list []string, seen map[string]bool, u string) []string {
	u = canon(u)
	if u == "" || seen[u] {
		return list
	}
	seen[u] = true
	return append(list, u)
}

// GoverningFactsFromVoteEvidence reads GoverningFacts from an intent's vote evidence. The initiating signature is the one the
// transaction header's initiator hash names (protocol.SignatureDidInitiate); evidence that holds none cannot say which pages
// initiated and paid, and is refused by name (g1_initiator_page_unproven) rather than read as having no initiator.
func GoverningFactsFromVoteEvidence(ev *govvote.Evidence) (*GoverningFacts, error) {
	if ev == nil {
		return nil, fmt.Errorf("proof v2 binding: no vote evidence to read the governing facts from")
	}
	raw, err := hex.DecodeString(ev.Transaction)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("proof v2 binding: the governed transaction is not hex")
	}
	txn := new(protocol.Transaction)
	if err := txn.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("proof v2 binding: the governed transaction does not decode: %w", err)
	}
	if txn.Body == nil || txn.Header.Principal == nil {
		return nil, fmt.Errorf("proof v2 binding: the governed transaction has no body or principal")
	}
	if canon(ev.Account) != canon(txn.Header.Principal.String()) {
		return nil, fmt.Errorf("proof v2 binding: the vote evidence is for %s, its transaction's principal is %s", ev.Account, txn.Header.Principal)
	}
	f := &GoverningFacts{Principal: canon(ev.Account), Type: txn.Body.Type(), Authorities: append([]govvote.AccountAuthority(nil), ev.Authorities...)}
	copy(f.TxHash[:], txn.GetHash())
	for i := range f.Authorities {
		f.Authorities[i].URL = canon(f.Authorities[i].URL)
	}
	seen := map[string]bool{}
	// An authority with no URL cannot have been executed and cannot be required: refused, as an authority with no URL in the carried
	// transaction is (pkg/proof/v2 decodeTxn), never dereferenced (RB9-L).
	for _, a := range append(append([]*url.URL(nil), txn.Header.Authorities...), txn.GetAdditionalAuthorities()...) {
		if a == nil {
			return nil, fmt.Errorf("proof v2 binding: the governed transaction names an authority with no URL")
		}
		f.HeaderAuthorities = appendOnce(f.HeaderAuthorities, seen, a.String())
	}
	for _, a := range ev.Extra {
		f.HeaderAuthorities = appendOnce(f.HeaderAuthorities, seen, a)
	}

	initiated := false
	initSeen, pathSeen := map[string]bool{}, map[string]bool{}
	for i, s := range ev.Signatures {
		f.Signatures = append(f.Signatures, SignatureRef{Signer: canon(s.Fact.Signer), Block: s.Fact.Block})
		b, err := hex.DecodeString(s.Signature)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf("proof v2 binding: signature %d is not hex", i)
		}
		sig, err := protocol.UnmarshalSignature(b)
		if err != nil {
			return nil, fmt.Errorf("proof v2 binding: signature %d does not decode: %w", i, err)
		}
		if sig == nil { // Accumulate's union decoder answers neither a signature nor an error for bytes that hold no type
			return nil, fmt.Errorf("proof v2 binding: signature %d does not decode: it holds no signature", i)
		}
		if did, _ := protocol.SignatureDidInitiate(sig, txn.Header.Initiator[:], nil); !did {
			continue
		}
		initiated = true
		// The payer, as the credit payment names it (a lite token address pays as its lite identity), and the key page that
		// signed; the delegators of a delegated signature are the path.
		signer := sig.GetSigner()
		if signer != nil {
			payer := signer
			if key, _ := protocol.ParseLiteIdentity(signer); key == nil {
				if key, _, _ := protocol.ParseLiteTokenAddress(signer); key != nil {
					payer = signer.RootIdentity()
				}
			}
			f.Initiators = appendOnce(f.Initiators, initSeen, payer.String())
		}
		f.Initiators = appendOnce(f.Initiators, initSeen, s.Fact.Signer)
		for cur := sig; ; {
			d, ok := cur.(*protocol.DelegatedSignature)
			if !ok {
				break
			}
			if d.Delegator != nil {
				f.InitiatorPath = appendOnce(f.InitiatorPath, pathSeen, d.Delegator.String())
			}
			cur = d.Signature
		}
	}
	if !initiated {
		return nil, &proofv2.NamedState{Code: proofv2.StateInitiatorPageUnproven,
			Detail: "the vote evidence holds no signature the transaction header's initiator names, so the pages that initiated and paid are unknown"}
	}
	for _, v := range ev.Votes {
		f.Votes = append(f.Votes, VoteRef{Authority: canon(v.Fact.Authority), Origin: canon(v.Fact.Origin), Block: v.Fact.Block})
	}
	for _, a := range ev.Arrivals {
		r := ArrivalRef{Page: canon(a.Fact.Page), Origin: canon(a.Fact.Origin), Block: a.Fact.Block}
		for _, p := range a.Fact.Path {
			r.Path = append(r.Path, canon(p))
		}
		f.Arrivals = append(f.Arrivals, r)
	}
	return f, nil
}

// provenPage is a page of the report with where and why it was proven.
type provenPage struct {
	acct  protocol.Account
	proof proofv2.ProvenPage
}

// has says whether the page PROVES role r (rep.Proven[i].Roles: re-derived from the proven states by the verifier).
func (p *provenPage) has(r proofv2.PageRole) bool {
	for _, x := range p.proof.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// declared says whether the page records role r without the verifier having proven it (rep.Proven[i].Declared): a recorded fact whose
// justification is outside the document - the intent certificate (certified-key-page), or the transaction or initiating signature when the
// document does not carry them.
func (p *provenPage) declared(r proofv2.PageRole) bool {
	for _, x := range p.proof.Declared {
		if x == r {
			return true
		}
	}
	return false
}

// missing is the detail of a role the page does not prove: when the page records it only as declared, it says so.
func (p *provenPage) missing(r proofv2.PageRole) string {
	if p.declared(r) {
		return fmt.Sprintf("is recorded as %s but only declared, not proven (the document does not carry what justifies it)", r)
	}
	return fmt.Sprintf("is proven (roles %v) but not as %s", p.proof.Roles, r)
}

type binder struct {
	rep   *proofv2.Report
	facts *GoverningFacts
	pages map[string]*provenPage
}

func ns(code, partition string, block uint64, format string, a ...any) error {
	return &proofv2.NamedState{Code: code, Partition: partition, Block: block, Detail: fmt.Sprintf(format, a...)}
}

// BindProofV21 is BindProofV2 for a report of evidence 2.1: the G0/G1 binding of BindProofV2, a report with nothing unproven, the
// certified key page justified against the certificate's declared book, and every page of the governing set of D1(a)-(f) required among
// the report's proven pages (rep.Proven, each at its own partition and block) with its recorded role:
//
//	(a) the principal and the accounts its authority set is inherited through (role principal-chain), walked over the proven
//	    states exactly as the executor resolves an authority set (the verifier re-derives the same set; this binds the intent
//	    to it);
//	(b) every authority book of the intent, enabled or disabled, and of the proven set, with every page 1..PageCount of it
//	    (authority-book, authority-page), PageCount read from the proven book;
//	(c) every book the header and body name (header-authority, on the book and each page);
//	(d) the voter pages: the page that cast each recorded vote, and each delegator page and origin of a delegated arrival
//	    (voter), and, when every listed authority is disabled and the executor accepted an outside voter, that voter's book;
//	(e) delegates: the book each proven page of a level-n authority book delegates to, and its pages, breadth first to
//	    protocol.DelegationDepthLimit (delegate-book, delegate-page); a cycle is legal and ends the walk;
//	(f) the initiator and payer pages and the initiating signature's delegators (initiator-signer), and the certified key page
//	    (certified-key-page).
//
// Roles the verifier proves (rep.Proven[i].Roles) are the only ones that satisfy (a)-(e) and the initiator part of (f): a role a page
// records only as Declared (the transaction or initiating signature was not carried) is refused as "declared, not proven". The certified
// key page is the one role the verifier can only declare, because it depends on the intent certificate; THIS binding justifies it: the
// page is G1's page, is a proven page of the governing set (it proves at least one other role), is recorded as certified-key-page, and is
// a page of keyBookURL, the book the certificate declares. The facts' transaction must be the transaction the report proved. A report
// with any Unproven entry is not a verified S3 and is refused by that entry, and so is one that discloses g1_vote_production_unbound. The executor version in force at every (partition, block)
// the report is judged at is derived from the pinned activation table (proofv2.ExecutorFloorAt): the system-ledger page is not required
// (live Kermit serves no historical receipt for it), and when a document carries one it must agree.
//
// Each missing class is refused by the named state of pkg/proof/v2 crosspartition.go. Every proven page must also carry its
// partition and a block; a page on the transaction's partition is proven at the report's anchor block; a counted signature or
// delegated arrival must not be later than the block its page is proven at (on that page's own partition), nor a recorded vote
// later than the principal's anchor block.
func BindProofV21(rep *proofv2.Report, g0 *proof.G0Result, g1 *proof.G1Result, keyPageURL, keyBookURL string, facts *GoverningFacts) error {
	if rep == nil || g0 == nil || g1 == nil || facts == nil {
		return fmt.Errorf("proof v2 binding: the report, G0, G1 and the governing facts are all required")
	}
	// A report that names anything it could not establish is not a verified S3: its own first named state is the refusal.
	if len(rep.Unproven) > 0 {
		first := rep.Unproven[0]
		return &first
	}
	// A disclosure is a verified fact, not a refusal, except one: a sequenced vote whose production does not carry the SequencedMessage is not
	// bound to the vote's message (a document made before the verifier round VA), so its arrival block is not established. Every document
	// built since carries the message; an old capture is held until it is re-captured.
	for _, d := range rep.Disclosures {
		if d.Code == proofv2.StateVoteProductionUnbound {
			first := d
			return &first
		}
	}
	if err := bindG0(rep, g0); err != nil {
		return err
	}
	if facts.TxHash != rep.TxHash {
		return ns(proofv2.StateTransactionMismatch, rep.Partition, rep.AnchorBlock,
			"the governing facts are read from a transaction hashing to %x, the report proved %x", facts.TxHash[:8], rep.TxHash[:8])
	}
	page := govvote.CanonicalAccSpelling(keyPageURL)
	if page == "" || page != govvote.CanonicalAccSpelling(g1.AuthoritySnapshot.Page) {
		return fmt.Errorf("proof v2 binding: the certified key page %q is not the page G1 validated against (%q)", keyPageURL, g1.AuthoritySnapshot.Page)
	}
	b := &binder{rep: rep, facts: facts, pages: map[string]*provenPage{}}
	if err := b.index(); err != nil {
		return err
	}
	if err := b.executorVersions(); err != nil {
		return err
	}
	if err := b.certifiedPage(page, keyBookURL); err != nil {
		return err
	}
	if err := b.checkBlocks(); err != nil {
		return err
	}
	authorities, err := b.principalChain()
	if err != nil {
		return err
	}
	if err := b.books(authorities); err != nil {
		return err
	}
	if err := b.voters(); err != nil {
		return err
	}
	for _, p := range facts.Initiators {
		if err := b.needRole(p, proofv2.RoleInitiatorSigner, proofv2.StateInitiatorPageUnproven, "the initiating page"); err != nil {
			return err
		}
	}
	for _, p := range facts.InitiatorPath {
		if err := b.needRole(p, proofv2.RoleInitiatorSigner, proofv2.StateInitiatorPageUnproven, "a delegator of the initiating signature"); err != nil {
			return err
		}
	}
	return b.arrivalBlocks()
}

// certifiedPage justifies the role the verifier can only declare. The certified key page (G1's page) must be proven, recorded as
// certified-key-page, a page of the book the certificate declares, and a page of the governing set: it proves at least one other role
// (authority page, voter, delegate page, header authority page or initiator-signer - the harbor-mfg page is the initiator of an unrelated
// identity and proves only that), so the certificate cannot name a proven page that has nothing to do with the intent.
func (b *binder) certifiedPage(page, keyBookURL string) error {
	p, ok := b.pages[page]
	if !ok {
		return ns(proofv2.StateCertifiedPageUnproven, "", 0, "the certified key page %s is not among the pages the report proved", page)
	}
	if !p.has(proofv2.RoleCertifiedKeyPage) && !p.declared(proofv2.RoleCertifiedKeyPage) {
		return ns(proofv2.StateCertifiedPageUnproven, p.proof.Partition, p.proof.Block,
			"the certified key page %s is proven (roles %v, declared %v) but not recorded as %s", page, p.proof.Roles, p.proof.Declared, proofv2.RoleCertifiedKeyPage)
	}
	book := canon(keyBookURL)
	if book == "" {
		return ns(proofv2.StateCertifiedPageUnproven, p.proof.Partition, p.proof.Block, "the certificate declares no key book for the certified key page %s", page)
	}
	var own string
	switch p.acct.(type) {
	case *protocol.KeyPage:
		pu, err := url.Parse(page)
		if err != nil {
			return fmt.Errorf("proof v2 binding: the certified key page %q: %w", page, err)
		}
		parent, ok := pu.Parent()
		if !ok {
			return ns(proofv2.StateCertifiedPageUnproven, p.proof.Partition, p.proof.Block, "the certified key page %s has no book", page)
		}
		own = canon(parent.String())
	case *protocol.LiteIdentity:
		own = page // a lite identity is its own book and page
	default:
		return ns(proofv2.StateCertifiedPageUnproven, p.proof.Partition, p.proof.Block, "the certified key page %s is %T, not a key page", page, p.acct)
	}
	if own != book {
		return ns(proofv2.StateCertifiedPageUnproven, p.proof.Partition, p.proof.Block,
			"the certified key page %s is a page of %s, the certificate declares the book %s", page, own, book)
	}
	for _, r := range p.proof.Roles {
		if r != proofv2.RoleCertifiedKeyPage {
			return nil
		}
	}
	return ns(proofv2.StateCertifiedPageUnproven, p.proof.Partition, p.proof.Block,
		"the certified key page %s proves no role of the governing set (roles %v): it is not a page the intent depends on", page, p.proof.Roles)
}

// executorVersions derives g1_executor_version_unsupported from the pinned activation table (proofv2.ExecutorFloorAt) for the
// transaction's (partition, block) and for every (partition, block) a proven page was judged at: a version Baikonur or later must be
// proven to govern it. A system-ledger page, when the document carries one, must not contradict the table.
func (b *binder) executorVersions() error {
	type where struct {
		partition string
		block     uint64
	}
	seen := map[where]bool{}
	check := func(partition string, block uint64, what string) error {
		w := where{proofv2.NormalizeExecutorPartition(partition), block}
		if seen[w] {
			return nil
		}
		seen[w] = true
		floor, ok := proofv2.ExecutorFloorAt(partition, block)
		if !ok {
			return ns(proofv2.StateExecutorVersionUnsupported, partition, block,
				"%s: the executor version governing block %d of %s is not established by the pinned activation table (an unknown partition, or a block at or before its activation)", what, block, partition)
		}
		if !floor.V2BaikonurEnabled() {
			return ns(proofv2.StateExecutorVersionUnsupported, partition, block,
				"%s: the pinned table proves executor version %d on %s, before Baikonur (%d)", what, floor, partition, protocol.ExecutorVersionV2Baikonur)
		}
		return nil
	}
	if err := check(b.rep.Partition, b.rep.AnchorBlock, "the transaction"); err != nil {
		return err
	}
	keys := make([]string, 0, len(b.pages))
	for k := range b.pages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, u := range keys {
		p := b.pages[u]
		if err := check(p.proof.Partition, p.proof.Block, u); err != nil {
			return err
		}
		if l, ok := p.acct.(*protocol.SystemLedger); ok {
			floor, _ := proofv2.ExecutorFloorAt(p.proof.Partition, p.proof.Block)
			if l.ExecutorVersion < floor {
				return ns(proofv2.StateExecutorVersionUnsupported, p.proof.Partition, p.proof.Block,
					"%s proves executor version %d at block %d of %s, the pinned table proves at least %d: the ledger page disagrees with the pinned table",
					u, l.ExecutorVersion, p.proof.Block, p.proof.Partition, floor)
			}
		}
	}
	return nil
}

// index builds the proven-page table, requiring rep.Proven to describe exactly rep.Pages, each page once, with a partition, a
// block and known roles.
func (b *binder) index() error {
	rep := b.rep
	if len(rep.Proven) == 0 || len(rep.Proven) != len(rep.Pages) {
		return ns(proofv2.StateCompletenessUnproven, "", 0, "the report proves %d pages and lists %d proven (partition, block, roles) records: evidence 2.1 lists every page", len(rep.Pages), len(rep.Proven))
	}
	for i, acct := range rep.Pages {
		pp := rep.Proven[i]
		if acct == nil || acct.GetUrl() == nil {
			return fmt.Errorf("proof v2 binding: page %d of the report has no account", i)
		}
		u := canon(acct.GetUrl().String())
		if canon(pp.URL) != u {
			return ns(proofv2.StatePageBlockMismatch, pp.Partition, pp.Block, "proven page %d is %s, the report's page is %s", i, pp.URL, u)
		}
		if _, dup := b.pages[u]; dup {
			return fmt.Errorf("proof v2 binding: page %s is proven twice", u)
		}
		if strings.TrimSpace(pp.Partition) == "" {
			return ns(proofv2.StateForeignPartitionMismatch, "", pp.Block, "%s is proven with no partition", u)
		}
		if pp.Block == 0 {
			return ns(proofv2.StatePageBlockMismatch, pp.Partition, 0, "%s is proven with no block", u)
		}
		roles, err := proofv2.CanonicalRoles(pp.Roles)
		if err != nil {
			return fmt.Errorf("proof v2 binding: %s: %w", u, err)
		}
		pp.Roles = roles
		b.pages[u] = &provenPage{acct: acct, proof: pp}
	}
	return nil
}

func samePartition(a, c string) bool {
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(a), "/"), strings.TrimSuffix(strings.TrimSpace(c), "/"))
}

// checkBlocks: a page on the transaction's partition is proven at the report's anchor block.
func (b *binder) checkBlocks() error {
	// In ascending order of the pages' canonical URLs: when more than one page is at another block the refusal names the first of them
	// in that order, a function of the report and not of the order a map is walked in (RB9-L).
	for _, u := range slices.Sorted(maps.Keys(b.pages)) {
		p := b.pages[u]
		if samePartition(p.proof.Partition, b.rep.Partition) && p.proof.Block != b.rep.AnchorBlock {
			return ns(proofv2.StatePageBlockMismatch, p.proof.Partition, p.proof.Block,
				"%s is on the transaction's partition and must be proven at its anchor block %d", u, b.rep.AnchorBlock)
		}
	}
	return nil
}

func (b *binder) needRole(u string, role proofv2.PageRole, code, what string) error {
	u = canon(u)
	p, ok := b.pages[u]
	if !ok {
		return ns(code, "", 0, "%s %s is not among the pages the report proved", what, u)
	}
	if !p.has(role) {
		return ns(code, p.proof.Partition, p.proof.Block, "%s %s %s", what, u, p.missing(role))
	}
	return nil
}

// principalChain walks the principal's authority set over the proven states as the executor resolves it, requires every account
// on the way as principal-chain on the transaction's partition, and returns the set the walk reaches.
func (b *binder) principalChain() ([]govvote.AccountAuthority, error) {
	cur, err := url.Parse(b.facts.Principal)
	if err != nil {
		return nil, fmt.Errorf("proof v2 binding: the principal %q: %w", b.facts.Principal, err)
	}
	for {
		u := canon(cur.String())
		p, ok := b.pages[u]
		if !ok {
			return nil, ns(proofv2.StateCompletenessUnproven, "", 0, "principal chain: %s is not among the pages the report proved", u)
		}
		if !p.has(proofv2.RolePrincipalChain) {
			return nil, ns(proofv2.StateCompletenessUnproven, p.proof.Partition, p.proof.Block, "principal chain: %s is proven (roles %v) but not as principal-chain", u, p.proof.Roles)
		}
		if !samePartition(p.proof.Partition, b.rep.Partition) {
			return nil, ns(proofv2.StateForeignPartitionMismatch, p.proof.Partition, p.proof.Block,
				"the principal chain account %s is proven on %s, the transaction executed on %s", u, p.proof.Partition, b.rep.Partition)
		}
		switch a := p.acct.(type) {
		case *protocol.LiteIdentity:
			return []govvote.AccountAuthority{{URL: canon(a.Url.String())}}, nil
		case *protocol.LiteTokenAccount:
			if a.Delegate != nil {
				return []govvote.AccountAuthority{{URL: canon(a.Delegate.String())}}, nil
			}
			return []govvote.AccountAuthority{{URL: canon(a.Url.RootIdentity().String())}}, nil
		case *protocol.LiteDataAccount:
			return nil, nil
		case protocol.FullAccount:
			if len(a.GetAuth().Authorities) > 0 {
				var out []govvote.AccountAuthority
				for _, e := range a.GetAuth().Authorities {
					out = append(out, govvote.AccountAuthority{URL: canon(e.Url.String()), Disabled: e.Disabled})
				}
				return out, nil
			}
			parent, ok := cur.Parent()
			if !ok {
				return nil, ns(proofv2.StateCompletenessUnproven, p.proof.Partition, p.proof.Block,
					"root identity %s lists no authority: its governing set cannot be derived", u)
			}
			cur = parent
		default:
			return nil, fmt.Errorf("proof v2 binding: the principal chain account %s is %T, which is not governed by key books", u, p.acct)
		}
	}
}

type bookEdge struct {
	book  string
	level int
}

// books requires every authority, header and outside-voter book and then, breadth first, every delegate book.
func (b *binder) books(derived []govvote.AccountAuthority) error {
	f := b.facts
	// The union of the set the intent was judged against and the set the proven principal chain resolves to: both are required.
	listed := map[string]bool{}
	var auths []govvote.AccountAuthority
	allDisabled := !f.Type.RequireAuthorization()
	for _, a := range append(append([]govvote.AccountAuthority(nil), f.Authorities...), derived...) {
		u := canon(a.URL)
		if !a.Disabled {
			allDisabled = false
		}
		if listed[u] {
			continue
		}
		listed[u] = true
		auths = append(auths, govvote.AccountAuthority{URL: u, Disabled: a.Disabled})
	}
	named := map[string]bool{}
	for _, h := range f.HeaderAuthorities {
		named[canon(h)] = true
	}
	visited := map[string]bool{}
	var queue []bookEdge
	expand := func(u string, level int, bookRole, pageRole proofv2.PageRole, missing string) error {
		edges, err := b.book(u, level, bookRole, pageRole, missing)
		if err != nil {
			return err
		}
		visited[u] = true
		queue = append(queue, edges...)
		return nil
	}
	for _, a := range auths {
		if err := expand(a.URL, 0, proofv2.RoleAuthorityBook, proofv2.RoleAuthorityPage, proofv2.StateAuthorityMissing); err != nil {
			return err
		}
	}
	for _, h := range f.HeaderAuthorities {
		h = canon(h)
		if err := expand(h, 0, proofv2.RoleHeaderAuthority, proofv2.RoleHeaderAuthority, proofv2.StateHeaderAuthorityMissing); err != nil {
			return err
		}
	}
	// When every listed authority is disabled the executor accepts any authority's single vote: that voter's whole book is the
	// authority that decided, and it is proven.
	if allDisabled {
		for _, v := range f.Votes {
			a := canon(v.Authority)
			if listed[a] || named[a] {
				continue
			}
			if err := expand(a, 0, proofv2.RoleVoter, proofv2.RoleVoter, proofv2.StateAuthorityMissing); err != nil {
				return err
			}
		}
	}
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		if visited[e.book] {
			continue
		}
		if e.level > protocol.DelegationDepthLimit {
			// No executed signature can have passed through a book this deep (sig_user.go:172): it is not required.
			continue
		}
		edges, err := b.book(e.book, e.level, proofv2.RoleDelegateBook, proofv2.RoleDelegatePage, proofv2.StateDelegateEntryAbsent)
		if err != nil {
			return err
		}
		visited[e.book] = true
		queue = append(queue, edges...)
	}
	return nil
}

// book requires book u with bookRole and each of its pages with pageRole, and returns the delegation edges of its pages, one
// level further down. A lite identity is its own book and page.
func (b *binder) book(u string, level int, bookRole, pageRole proofv2.PageRole, missing string) ([]bookEdge, error) {
	p, ok := b.pages[u]
	if !ok {
		return nil, ns(missing, "", 0, "the book %s (delegation level %d) is not among the pages the report proved", u, level)
	}
	if !p.has(bookRole) {
		return nil, ns(missing, p.proof.Partition, p.proof.Block, "the book %s %s", u, p.missing(bookRole))
	}
	switch bk := p.acct.(type) {
	case *protocol.LiteIdentity:
		if !p.has(pageRole) {
			return nil, ns(missing, p.proof.Partition, p.proof.Block, "%s is its own page and %s", u, p.missing(pageRole))
		}
		return nil, nil
	case *protocol.KeyBook:
		// A header authority's or a delegate's missing page is that class's state; an authority's is the book's page count.
		pageCode := proofv2.StateBookPageCountUnproven
		if missing != proofv2.StateAuthorityMissing {
			pageCode = missing
		}
		var edges []bookEdge
		for i := uint64(0); i < bk.PageCount; i++ {
			pu := canon(protocol.FormatKeyPageUrl(bk.Url, i).String())
			pg, ok := b.pages[pu]
			if !ok {
				return nil, ns(pageCode, p.proof.Partition, p.proof.Block,
					"page %d of %d of %s (%s) is not among the pages the report proved", i+1, bk.PageCount, u, pu)
			}
			if !pg.has(pageRole) {
				return nil, ns(pageCode, pg.proof.Partition, pg.proof.Block, "%s %s", pu, pg.missing(pageRole))
			}
			kp, ok := pg.acct.(*protocol.KeyPage)
			if !ok {
				return nil, fmt.Errorf("proof v2 binding: %s is %T, not a key page", pu, pg.acct)
			}
			for _, ks := range kp.Keys {
				if ks != nil && ks.Delegate != nil {
					edges = append(edges, bookEdge{book: canon(ks.Delegate.String()), level: level + 1})
				}
			}
		}
		return edges, nil
	default:
		return nil, fmt.Errorf("proof v2 binding: %s is %T, not a key book", u, p.acct)
	}
}

// voters requires the page behind every recorded vote and delegated arrival, and the blocks of the recorded votes.
func (b *binder) voters() error {
	f := b.facts
	for _, v := range f.Votes {
		// A vote whose origin is its authority was decided by no page (the abstain of a missing authority): there is no page.
		if v.Origin != "" && v.Origin != v.Authority {
			if err := b.needRole(v.Origin, proofv2.RoleVoter, proofv2.StateCompletenessUnproven, "the voter page"); err != nil {
				return err
			}
		}
		if v.Block > 0 && uint64(v.Block) > b.rep.AnchorBlock {
			return ns(proofv2.StateBlockBeforeArrival, b.rep.Partition, b.rep.AnchorBlock,
				"the vote of %s was recorded in block %d, after the anchor block %d the principal is proven at", v.Authority, v.Block, b.rep.AnchorBlock)
		}
	}
	for _, a := range f.Arrivals {
		pages := append([]string{a.Page, a.Origin}, a.Path...)
		for _, p := range pages {
			if err := b.needRole(p, proofv2.RoleVoter, proofv2.StateCompletenessUnproven, "the voter page of a delegated vote"); err != nil {
				return err
			}
		}
	}
	return nil
}

// arrivalBlocks requires, on each page's own partition, the block it is proven at not to precede a counted signature or delegated
// arrival it received.
func (b *binder) arrivalBlocks() error {
	check := func(page string, block int64, what string) error {
		p, ok := b.pages[canon(page)]
		if !ok || block <= 0 {
			return nil
		}
		if p.proof.Block < uint64(block) {
			return ns(proofv2.StateBlockBeforeArrival, p.proof.Partition, p.proof.Block,
				"%s arrived on %s in block %d, after the block %d the page is proven at", what, page, block, p.proof.Block)
		}
		return nil
	}
	for _, s := range b.facts.Signatures {
		if err := check(s.Signer, s.Block, "a signature"); err != nil {
			return err
		}
	}
	for _, a := range b.facts.Arrivals {
		if err := check(a.Page, a.Block, "a delegated vote"); err != nil {
			return err
		}
	}
	return nil
}
