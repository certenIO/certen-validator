// Copyright 2026 Certen Protocol
//
// The pages that decide who may approve a transaction, as proof v2 must prove them (docs/proof/G1_CROSS_PARTITION.md D1).
//
// The set is derived from the accounts as the executor sees them, read as of the block they are proven at, never from
// current state: the principal's inheritance chain (lite accounts included), every authority book of the resolved set on any
// identity - enabled or not, because a disabled authority may still vote - and every page 1..PageCount of each (the first
// ready page of a book decides its vote); the books the transaction header and body name; the authority that actually voted
// when every listed authority is disabled; every page entry that delegates, recursively to the protocol's depth limit; and the
// pages that initiated and paid for the transaction, which need not be authorities.

package proofv2shadow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ErrAccountMissing is what an AccountReader returns for an account that does not exist as of the block it is read at.
var ErrAccountMissing = errors.New("the account does not exist at the block")

// AccountMissingError is ErrAccountMissing with where it was judged: the partition the account routes to and the block of that
// partition it was read at (errors.Is(err, ErrAccountMissing) holds). A reader that cannot say where leaves both empty.
type AccountMissingError struct {
	Partition string
	Block     uint64
	Cause     error
}

func (e *AccountMissingError) Error() string {
	if e.Cause == nil {
		return ErrAccountMissing.Error()
	}
	return fmt.Sprintf("%v: %v", ErrAccountMissing, e.Cause)
}
func (e *AccountMissingError) Unwrap() error        { return e.Cause }
func (e *AccountMissingError) Is(target error) bool { return target == ErrAccountMissing }

// AccountReader reads one account as of the block its partition is read at.
type AccountReader func(ctx context.Context, u *url.URL) (protocol.Account, error)

// VoteFact is one authority vote recorded on the principal for the transaction.
type VoteFact struct {
	Authority *url.URL
	Origin    *url.URL
	Vote      protocol.VoteType
	// Delegators is the delegation path rebuilt from the cause chain (the principal's vote carries none): the Delegator list of
	// the key signature, nearest the key page first. Hops are the signature messages of the chain, each with the block it
	// arrived in on its page's partition.
	Delegators []*url.URL
	Hops       []Hop
	// Counted are the other signatures the pages on the cause chain recorded for the transaction.
	Counted []Hop
	Cause   *url.TxID
	Message [32]byte // the vote's entry hash in the principal's signature chain
	// Sequenced is false for a vote counted in the block that produced it (same root identity as the principal); a vote
	// from another root identity always travels as a sequenced synthetic message, even on the same partition.
	Sequenced           bool
	Source, Destination *url.URL
	Number              uint64
	// SeqHash is the hash of the SequencedMessage the source partition recorded in its synthetic ledger's main chain for a sequenced vote.
	SeqHash [32]byte
	// SeqRaw is that SequencedMessage, binary: the production of the vote carries it so the verifier can bind the ledger entry to the vote (verifier round VA, DEF-4).
	SeqRaw []byte
}

// Hop is one signature message of a vote's cause chain and the block of its page's partition it arrived in.
type Hop struct {
	Page  *url.URL
	ID    *url.TxID // the message, as recorded on Page
	Block uint64
	Sig   protocol.Signature // the signature the message carries
}

// SigRecord is one signature message recorded for the transaction in a signer page's signature set.
type SigRecord struct {
	ID  *url.TxID
	Sig protocol.Signature
}

// TxFacts is what the transaction record says about who approved it.
type TxFacts struct {
	Principal *url.URL
	Type      protocol.TransactionType
	// HeaderAuthorities are the authorities the transaction names beyond the principal's: Header.Authorities and the
	// authorities its body adds (GetAdditionalAuthorities). They are required voters and may be on any identity.
	HeaderAuthorities []*url.URL
	// Held is true when the transaction carries HoldUntil: a vote is then released in a later block than its signature.
	Held bool
	// Votes are the authority signatures recorded on the principal.
	Votes []VoteFact
	// Initiators are the pages that initiated the transaction and the pages that paid for it; InitiatorPath the pages in the
	// Delegator path of the initiating signature.
	Initiators    []*url.URL
	InitiatorPath []*url.URL
	// Certified is the key page the intent certificate names (ResolveSigningKeyPage), when it could be resolved.
	Certified *url.URL
	// KeySigs are the signature messages (ids at their signer page) recorded for the transaction that are not authority
	// votes, by signer page: the arrival of each is a lower bound of the block its page's partition is read at.
	KeySigs map[string][]*url.TxID
	// Txn is the governed transaction; PageSigs the signature messages recorded for it in each signer page's set (key signatures and
	// authority signatures alike), by page: the signatures a page's threshold counted besides the one that completed it.
	Txn      *protocol.Transaction
	PageSigs map[string][]SigRecord
}

// GovPage is one governing account and why it is governing.
type GovPage struct {
	URL   string
	Roles []proofv2.PageRole
}

// Closure is the governing set. Notes are named states that do not stop the capture (a vote counted although its authority
// is not listed, a chain of delegates that goes deeper than any signature can).
type Closure struct {
	Pages []GovPage
	Notes []*proofv2.NamedState
	// Counted are the votes the executor counts: those of an authority the principal lists, the header names, or - when
	// every listed authority is disabled - any authority.
	Counted []VoteFact
	// Absent are the listed authorities that do not exist at the block they were read at, with where that was judged (also in Notes):
	// evidence 2.1 cannot prove an account absent, so it is refused from them (Capture.Absent).
	Absent []*proofv2.NamedState
}

// URLs returns the governing accounts in order.
func (c *Closure) URLs() []string {
	out := make([]string, len(c.Pages))
	for i, p := range c.Pages {
		out[i] = p.URL
	}
	return out
}

func (c *Closure) rolesOf(url string) []proofv2.PageRole {
	for _, p := range c.Pages {
		if strings.EqualFold(p.URL, url) {
			return p.Roles
		}
	}
	return nil
}

type closureBuilder struct {
	pages []GovPage
	index map[string]int
	notes []*proofv2.NamedState
}

func key(u *url.URL) string { return strings.ToLower(u.String()) }

func (b *closureBuilder) add(u *url.URL, role proofv2.PageRole) {
	k := key(u)
	i, ok := b.index[k]
	if !ok {
		b.index[k] = len(b.pages)
		b.pages = append(b.pages, GovPage{URL: u.String()})
		i = len(b.pages) - 1
	}
	for _, r := range b.pages[i].Roles {
		if r == role {
			return
		}
	}
	b.pages[i].Roles = append(b.pages[i].Roles, role)
}

func (b *closureBuilder) note(code string, detail string) {
	b.notes = append(b.notes, &proofv2.NamedState{Code: code, Detail: detail})
}

// DelegationDepthLimit is the executor's bound on the delegators of one signature (protocol.DelegationDepthLimit).
const DelegationDepthLimit = protocol.DelegationDepthLimit

// governing derives the governing set of a transaction through get. See the file comment for the rules; each is cited in
// docs/proof/G1_CROSS_PARTITION.md D1 and R9 §1c/§4.2.
func governing(ctx context.Context, f *TxFacts, get AccountReader) (*Closure, error) {
	return governingWith(ctx, f, get, nil)
}

// DelegatesOf names, for a key page, the delegate books an EARLIER state of the page held (from its certified history): a delegation
// removed after a counted signature went through it still puts its book in the governing set (G1_CROSS_PARTITION.md section 5).
type DelegatesOf func(page *url.URL) []*url.URL

// governingWith is governing with the delegates of earlier page states followed too.
func governingWith(ctx context.Context, f *TxFacts, get AccountReader, hist DelegatesOf) (*Closure, error) {
	if f == nil || f.Principal == nil {
		return nil, fmt.Errorf("no principal to resolve the governing set of")
	}
	b := &closureBuilder{index: map[string]int{}}

	// (a) The principal and the accounts its authority set is inherited through.
	auths, err := principalAuthorities(ctx, f.Principal, get, b)
	if err != nil {
		return nil, err
	}

	// A signature path longer than the limit cannot have executed; a recorded one is refused by name.
	for _, v := range f.Votes {
		if len(v.Delegators) > DelegationDepthLimit {
			return nil, &proofv2.NamedState{Code: proofv2.StateDelegationDepthExceeded,
				Detail: fmt.Sprintf("the vote of %v records a delegation path of %d, the limit is %d", v.Authority, len(v.Delegators), DelegationDepthLimit)}
		}
	}

	listed := map[string]bool{}
	allDisabled := !f.Type.RequireAuthorization()
	for _, a := range auths {
		listed[key(a.Url)] = true
		if !a.Disabled {
			allDisabled = false
		}
	}
	named := map[string]bool{}
	for _, h := range f.HeaderAuthorities {
		named[key(h)] = true
	}

	ex := &expander{b: b, get: get, expanded: map[string]bool{}, hist: hist}

	// (b) Every listed authority, enabled or disabled, and its pages.
	for _, a := range auths {
		if err := ex.book(ctx, a.Url, proofv2.RoleAuthorityBook, proofv2.RoleAuthorityPage, a.Disabled); err != nil {
			return nil, err
		}
	}
	// (c) The books the header and body name, which must all approve.
	for _, h := range f.HeaderAuthorities {
		if err := ex.book(ctx, h, proofv2.RoleHeaderAuthority, proofv2.RoleHeaderAuthority, false); err != nil {
			var ns *proofv2.NamedState
			if errors.As(err, &ns) && ns.Code == proofv2.StateAuthorityMissing {
				return nil, &proofv2.NamedState{Code: proofv2.StateHeaderAuthorityMissing, Detail: fmt.Sprintf("%v: %v", h, ns.Detail)}
			}
			return nil, err
		}
	}

	// (d) The recorded votes. An authority signature the principal's chain holds was accepted when it arrived
	// (sig_authority.go:127-136 refuses the others), so every recorded vote counts; one by an authority that is neither listed
	// nor named is disclosed. When every listed authority is disabled the executor accepts any authority's single vote, so the
	// voter's whole book is proven (its first ready page decides); otherwise only the pages that voted are.
	counted := append([]VoteFact(nil), f.Votes...)
	for _, v := range f.Votes {
		if !(listed[key(v.Authority)] || named[key(v.Authority)]) {
			detail := fmt.Sprintf("%v voted although it is not listed or named", v.Authority)
			if allDisabled {
				detail += "; every listed authority is disabled, so the executor accepts it"
				if err := ex.book(ctx, v.Authority, proofv2.RoleVoter, proofv2.RoleVoter, false); err != nil {
					return nil, err
				}
			}
			b.notes = append(b.notes, &proofv2.NamedState{Code: proofv2.StateAuthorityVoterOutsideList, Detail: detail})
		}
		// A vote whose origin is the authority itself is the abstain of an authority that does not exist: no page decided it.
		if v.Origin != nil && !strings.EqualFold(v.Origin.String(), v.Authority.String()) {
			b.add(v.Origin, proofv2.RoleVoter)
		} else {
			b.notes = append(b.notes, &proofv2.NamedState{Code: proofv2.StateAuthorityMissing,
				Detail: fmt.Sprintf("the vote of %v was decided by no page", v.Authority)})
		}
		for _, h := range v.Hops {
			b.add(h.Page, proofv2.RoleVoter)
		}
		for _, d := range v.Delegators {
			b.add(d, proofv2.RoleVoter)
		}
		// A sequenced vote is produced in the source partition's synthetic ledger: its main chain places the vote's SequencedMessage in
		// the block that produced it (a HoldUntil release is judged there).
		if v.Sequenced && v.Source != nil {
			b.add(v.Source.JoinPath(protocol.Synthetic), proofv2.RoleSyntheticChain)
		}
	}

	// (e) Delegates, from every page captured so far.
	if err := ex.delegates(ctx); err != nil {
		return nil, err
	}

	// (f) The certified key page, whatever else it is; the pages that initiated and paid for the transaction and those in the
	// initiating signature's delegator path.
	if f.Certified != nil {
		b.add(f.Certified, proofv2.RoleCertifiedKeyPage)
	}
	for _, p := range f.Initiators {
		b.add(p, proofv2.RoleInitiatorSigner)
	}
	for _, p := range f.InitiatorPath {
		b.add(p, proofv2.RoleInitiatorSigner)
	}

	// Every page the closure names must be read, so that it is proven: the pages that voted or initiated were added by name,
	// not reached through a book.
	for _, p := range b.pages {
		if _, err := get(ctx, mustURL(p.URL)); err != nil {
			if errors.Is(err, ErrAccountMissing) {
				for _, r := range p.Roles {
					if r == proofv2.RoleInitiatorSigner {
						return nil, &proofv2.NamedState{Code: proofv2.StateInitiatorPageUnproven, Detail: fmt.Sprintf("%s does not exist at the block: %v", p.URL, err)}
					}
				}
			}
			return nil, fmt.Errorf("governing page %s: %w", p.URL, err)
		}
	}

	out := &Closure{Pages: b.pages, Notes: append(b.notes, ex.notes...), Counted: counted, Absent: ex.absent}
	for i := range out.Pages {
		roles, err := proofv2.CanonicalRoles(out.Pages[i].Roles)
		if err != nil {
			return nil, err
		}
		out.Pages[i].Roles = roles
	}
	return out, nil
}

// principalAuthorities resolves the authority set exactly as the executor does (internal/core/block/shared
// GetAccountAuthoritySet, internal/core/execute/v2/block getAccountAuthoritySet, Baikonur and later): a lite identity is its
// own authority; a lite token account is its delegate, else its root identity; a lite data account has none; a full account
// that lists any authority uses its list, one that lists none inherits its parent's, and a root identity that lists none is an
// executor error, not an empty set. Each account on the way is added, because its proven state is what shows the walk goes on.
func principalAuthorities(ctx context.Context, principal *url.URL, get AccountReader, b *closureBuilder) ([]protocol.AuthorityEntry, error) {
	for cur := principal; ; {
		acct, err := get(ctx, cur)
		if err != nil {
			return nil, fmt.Errorf("account %v: %w", cur, err)
		}
		b.add(cur, proofv2.RolePrincipalChain)
		switch a := acct.(type) {
		case *protocol.LiteIdentity:
			return []protocol.AuthorityEntry{{Url: a.Url}}, nil
		case *protocol.LiteTokenAccount:
			if a.Delegate != nil {
				return []protocol.AuthorityEntry{{Url: a.Delegate}}, nil
			}
			return []protocol.AuthorityEntry{{Url: a.Url.RootIdentity()}}, nil
		case *protocol.LiteDataAccount:
			return nil, nil
		case protocol.FullAccount:
			if len(a.GetAuth().Authorities) > 0 {
				return a.GetAuth().Authorities, nil
			}
			parent, ok := cur.Parent()
			if !ok {
				return nil, &proofv2.NamedState{Code: proofv2.StateCompletenessUnproven,
					Detail: fmt.Sprintf("root identity %v lists no authority: the executor refuses it (empty authority set), so its governing set cannot be derived", cur)}
			}
			cur = parent
		default:
			return nil, fmt.Errorf("account %v is %T, which is not governed by key books", cur, acct)
		}
	}
}

// expander adds books, their pages and their delegates.
type expander struct {
	b        *closureBuilder
	get      AccountReader
	expanded map[string]bool // books whose pages are in the closure
	pending  []delegateEdge  // page entries to follow, breadth first
	books    []bookRecord    // every book expanded, with its pages
	notes    []*proofv2.NamedState
	absent   []*proofv2.NamedState // the disabled authorities that do not exist (also in notes)
	hist     DelegatesOf           // delegates of earlier states of a page (nil: only the state read)
}

type delegateEdge struct {
	to    *url.URL
	depth int // the number of delegators a signature through the target's pages would carry
}

// book adds an authority book and every page 1..PageCount of it. A lite identity is its own book and page. A disabled
// authority that does not exist is named, not fatal: it can neither be required nor vote.
func (e *expander) book(ctx context.Context, u *url.URL, bookRole, pageRole proofv2.PageRole, disabled bool) error {
	return e.bookAt(ctx, u, bookRole, pageRole, disabled, 0)
}

func (e *expander) bookAt(ctx context.Context, u *url.URL, bookRole, pageRole proofv2.PageRole, disabled bool, depth int) error {
	k := key(u)
	if e.expanded[k] {
		// Reached again (a cycle, or a book that is both an authority and a delegate): its roles are added, its pages are not
		// read twice.
		e.b.add(u, bookRole)
		for _, p := range e.pagesOf(u) {
			e.b.add(p, pageRole)
		}
		return nil
	}
	acct, err := e.get(ctx, u)
	if err != nil {
		if errors.Is(err, ErrAccountMissing) {
			// Where the absence was judged: no receipt of the evidence proves an account absent, so the verifier and the binding (which
			// require every listed authority, disabled or not, to be a proven book) cannot carry it. A DISABLED authority that does not
			// exist is allowed by the executor, so a 2.0 capture notes it and goes on; the fact is kept (Capture.Absent) and a 2.1 build
			// is refused by it. An enabled one stops the capture, as before.
			var am *AccountMissingError
			ns := &proofv2.NamedState{Code: proofv2.StateAuthorityMissing}
			if errors.As(err, &am) {
				ns.Partition, ns.Block = am.Partition, am.Block
			}
			if disabled {
				ns.Detail = fmt.Sprintf("the disabled authority %v does not exist at the capture block", u)
				e.b.notes = append(e.b.notes, ns)
				e.absent = append(e.absent, ns)
				return nil
			}
			ns.Detail = fmt.Sprintf("the authority %v does not exist", u)
			return ns
		}
		return fmt.Errorf("key book %v: %w", u, err)
	}
	e.expanded[k] = true
	switch bk := acct.(type) {
	case *protocol.LiteIdentity:
		e.b.add(u, bookRole)
		e.b.add(u, pageRole)
		e.books = append(e.books, bookRecord{u: u, pages: []*url.URL{u}})
	case *protocol.KeyBook:
		e.b.add(u, bookRole)
		var pages []*url.URL
		for i := uint64(0); i < bk.PageCount; i++ {
			p := protocol.FormatKeyPageUrl(u, i)
			pages = append(pages, p)
			e.b.add(p, pageRole)
			pa, err := e.get(ctx, p)
			if err != nil {
				return fmt.Errorf("key page %v: %w", p, err)
			}
			kp, ok := pa.(*protocol.KeyPage)
			if !ok {
				return fmt.Errorf("%v is %T, not a key page", p, pa)
			}
			for _, ks := range kp.Keys {
				if ks.Delegate != nil {
					e.pending = append(e.pending, delegateEdge{to: ks.Delegate, depth: depth + 1})
				}
			}
			if e.hist != nil {
				for _, d := range e.hist(p) {
					e.pending = append(e.pending, delegateEdge{to: d, depth: depth + 1})
				}
			}
		}
		e.books = append(e.books, bookRecord{u: u, pages: pages})
	default:
		return fmt.Errorf("authority %v is %T, not a key book", u, acct)
	}
	return nil
}

type bookRecord struct {
	u     *url.URL
	pages []*url.URL
}

func (e *expander) pagesOf(u *url.URL) []*url.URL {
	for _, bk := range e.books {
		if key(bk.u) == key(u) {
			return bk.pages
		}
	}
	return nil
}

// delegates follows the delegate entries of the captured pages breadth first, so a book is reached by its shortest path.
// A signature carries at most DelegationDepthLimit delegators, so a book first reached deeper than that cannot have signed;
// it is named, not captured. The executor has no cycle detection and a cycle is legal: the visited set ends the walk.
func (e *expander) delegates(ctx context.Context) error {
	for len(e.pending) > 0 {
		edge := e.pending[0]
		e.pending = e.pending[1:]
		if e.expanded[key(edge.to)] {
			continue
		}
		if edge.depth > DelegationDepthLimit {
			e.notes = append(e.notes, &proofv2.NamedState{Code: proofv2.StateDelegationDepthExceeded,
				Detail: fmt.Sprintf("%v is delegated to %d levels down, beyond the limit of %d: no executed signature can pass through it", edge.to, edge.depth, DelegationDepthLimit)})
			e.expanded[key(edge.to)] = true // named once
			continue
		}
		if err := e.bookAt(ctx, edge.to, proofv2.RoleDelegateBook, proofv2.RoleDelegatePage, false, edge.depth); err != nil {
			var ns *proofv2.NamedState
			if errors.As(err, &ns) && ns.Code == proofv2.StateAuthorityMissing {
				return &proofv2.NamedState{Code: proofv2.StateDelegateEntryAbsent, Detail: fmt.Sprintf("the delegate %v does not exist", edge.to)}
			}
			return err
		}
	}
	return nil
}
