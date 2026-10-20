// Copyright 2026 Certen Protocol
//
// Verifying evidence 2.1 (docs/proof/G1_CROSS_PARTITION.md D1, D2, D2a, D4, D5, D6; RB9 Phase C1a).
//
// A governing page can live on a partition other than the transaction's. Each such page is proven at ITS partition's block B_Y:
// its receipt must end at the StateTreeAnchor of that partition's BlockValidatorAnchor, and the anchor, a transaction the
// Directory executed, is proven into the same certified Directory root as the transaction. Nothing a document says about where
// a page lives is trusted: the partition is DERIVED from the anchor message's Source, the derived partition is checked against
// the network's routing table (proven into the certified state tree root, D5), and the roles that say why each page is among
// the proven pages are re-derived from the proven states and compared.
//
// What this file establishes is exactly what the evidence can establish without re-evaluating the vote: anchors, pages, chain
// bindings, routing, the governing set and its completeness (every page 1..PageCount of every book), and that every counted
// signature is a member of its page's signature chain at that page's own B_Y (so B_Y is at or after its arrival block). The
// re-evaluation of the vote itself, the Directory as a partition, and the remaining named states are RB9 Phase C1b; the report
// says so by name (Report.Unproven) and is never a verified S3 on its own.

package proofv2

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/types/messaging"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Additional named states of the 2.1 verifier (the others are design D6's, in crosspartition.go).
const (
	// StateRoutingMismatch: a page's URL is routed by the proven routing table (unchanged since genesis) to a partition other than
	// the one its anchor names.
	StateRoutingMismatch = "g1_routing_mismatch"
	// StateRoleMismatch: a page's recorded roles differ from the roles re-derived from the proven states (a role claimed that the
	// proven state does not justify, or a justified role the evidence omits).
	StateRoleMismatch = "g1_role_mismatch"
)

// ProvenPage and Report carry the 2.1 results (see Report.Proven, Report.Unproven).

// declaredRoles are the roles whose justification can be a fact outside the evidence. Since RB9 Phase C1b-2 only RoleCertifiedKeyPage is
// declared always (it depends on the key book and page the INTENT declares, which only the intent certificate carries; BindProofV2,
// RB9 Phase C2, requires it against the certificate). RoleHeaderAuthority and RoleInitiatorSigner are derived from the transaction
// the evidence carries (xroles.go) and are declared only when it does not carry what derives them.
var declaredRoles = map[PageRole]bool{RoleHeaderAuthority: true, RoleInitiatorSigner: true, RoleCertifiedKeyPage: true}

// refusal21 is a verifier refusal that names the state, the partition and the block it was judged at.
func refusal21(code, partition string, block uint64, format string, a ...any) error {
	return &NamedState{Code: code, Partition: partition, Block: block, Detail: fmt.Sprintf(format, a...)}
}

// xAnchor is one partition's anchor as the verifier established it.
type xAnchor struct {
	source    string // the anchor message's Source, e.g. "acc://bvn-BVN2.acme": the DERIVED partition
	id        string // the partition ID, e.g. "BVN2"
	block     uint64 // B_Y
	stateRoot []byte
}

// xIn is what verifyFrom hands the 2.1 verifier: the certified root every anchor must be proven into, the transaction's
// partition anchor as already verified, and the state tree root the set check is bound to (the routing proof binds there too).
type xIn struct {
	certRoot []byte
	x        xAnchor
	setRoot  [32]byte
	// network is the name of the network the proven Network account (the validator set check) holds: the chain id of a typedData signature.
	network string
}

// kindOfAnchor says what a delivered anchor message carries, without requiring it to be a block validator anchor.
func kindOfAnchor(msgHex string) (protocol.TransactionType, *url.URL, error) {
	raw, err := hex.DecodeString(msgHex)
	if err != nil {
		return 0, nil, err
	}
	seq := new(messaging.SequencedMessage)
	if err := seq.UnmarshalBinary(raw); err != nil {
		return 0, nil, fmt.Errorf("partition anchor: %w", err)
	}
	txm, ok := seq.Message.(*messaging.TransactionMessage)
	if !ok || txm.Transaction == nil || txm.Transaction.Body == nil {
		return 0, nil, fmt.Errorf("partition anchor is %T, not a transaction", seq.Message)
	}
	return txm.Transaction.Body.Type(), seq.Source, nil
}

// verifyAnchor21 checks one partition anchor of the Anchors map: a BlockValidatorAnchor delivered to the Directory's anchor
// pool, from a block validator partition, proven into the certified root. key is the map key (the claimed partition).
func verifyAnchor21(key string, a PartitionAnchor, certRoot []byte) (*xAnchor, error) {
	// The anchor is of either kind (design D2b: the Directory is proven by its own DirectoryAnchor); its kind must be the one the
	// partition it names is proven by, and the partition is derived from its Source, never from the key.
	pa, err := decodeAnchor21(a.Message)
	if err != nil {
		return nil, fmt.Errorf("anchors[%s]: %w", key, err)
	}
	body, anchorTx := pa.body, pa.tx
	id, err := pa.partition()
	if err != nil {
		return nil, err
	}
	derived := pa.body.Source.String() // the committed value (partition() has required the wrapper to agree)
	if !strings.EqualFold(key, derived) {
		return nil, refusal21(StateForeignPartitionMismatch, id, body.MinorBlockIndex,
			"url anchors[%s]: claimed %s, derived %s", key, key, derived)
	}
	r, err := decodeReceipt(a.Receipt)
	if err != nil {
		return nil, fmt.Errorf("anchors[%s]: %w", key, err)
	}
	if len(anchorTx) != 32 || !bytes.Equal(r.Start, anchorTx) || !bytes.Equal(r.Anchor, certRoot) || !r.Validate(nil) {
		return nil, refusal21(StatePartitionAnchorUnavailable, id, body.MinorBlockIndex,
			"the receipt does not prove the anchor transaction into the certified Directory root")
	}
	return &xAnchor{source: derived, id: id, block: body.MinorBlockIndex, stateRoot: append([]byte(nil), body.StateTreeAnchor[:]...)}, nil
}

// provenAcct is one verified page with where it was proven.
type provenAcct struct {
	i      int
	acct   protocol.Account
	anchor *xAnchor
	chain  PageChain
}

func lk(u *url.URL) string { return strings.ToLower(u.String()) }

// verify21 verifies the 2.1 members of ev. rep already holds the transaction, the spine and the transaction's partition anchor.
func verify21(ev *Evidence, rep *Report, in xIn) error {
	rep.Version, rep.Tag = ev.Version, DomainG1V4
	if len(ev.Pages) == 0 {
		return refusal21(StateCompletenessUnproven, in.x.id, in.x.block, "evidence 2.1 carries no page")
	}
	// The evidence travels in one consensus transaction: a closure over the budget is a named state (xbudget.go).
	if err := CheckEvidenceBudget(ev, in.x); err != nil {
		return err
	}
	// A transaction whose executor replaces the default authorization rule is not judged by it (xoverride.go). A carried transaction that
	// does not decode or does not match is refused by its own name later, as before.
	if txn, err := carriedTransaction(ev, in.x); err == nil {
		if err := refuseExecutorOverride(txn, in.x); err != nil {
			return err
		}
	}

	// 1. Anchors: the transaction's own, and one per other partition, each proven into the certified root; the partition of each
	// is derived from the message. The entries are judged in ascending byte order of their keys (as the document spells them), so that
	// when more than one is defective the refusal names the first of them in that order - a function of the document, not of the
	// order a map happens to be walked in (RB9-L; the keys' order is the order of the UTF-8 bytes, not of UTF-16 code units).
	anchors := map[string]*xAnchor{strings.ToLower(in.x.source): &in.x}
	for _, k := range slices.Sorted(maps.Keys(ev.Anchors)) {
		a := ev.Anchors[k]
		if strings.EqualFold(k, in.x.source) {
			if a != ev.Anchor {
				return refusal21(StateForeignPartitionMismatch, in.x.id, in.x.block, "url anchors[%s]: the entry for the transaction's partition differs from its anchor", k)
			}
			continue
		}
		xa, err := verifyAnchor21(k, a, in.certRoot)
		if err != nil {
			return err
		}
		if _, dup := anchors[strings.ToLower(xa.source)]; dup {
			return refusal21(StateForeignPartitionMismatch, xa.id, xa.block, "url anchors[%s]: two anchors for one partition", k)
		}
		anchors[strings.ToLower(xa.source)] = xa
	}

	// 2. The routing table, proven into the certified state tree root the set check is bound to.
	var table *protocol.RoutingTable
	var routingHeight uint64
	switch {
	case ev.Check.Routing == nil:
		rep.Unproven = append(rep.Unproven, NamedState{Code: StateRoutingUnproven, Partition: in.x.id, Block: in.x.block,
			Detail: "the evidence carries no routing proof: Partition == route(URL) is unchecked"})
	default:
		t, h, err := proof.VerifyRoutingProof(ev.Check.Routing, hex.EncodeToString(in.setRoot[:]))
		if err != nil {
			return fmt.Errorf("set check: routing: %w", err)
		}
		table, routingHeight = t, h
		rep.RoutingHeight = h
		if h != 1 {
			rep.Unproven = append(rep.Unproven, NamedState{Code: StateRoutingHistoryUnproven, Partition: in.x.id, Block: in.x.block,
				Detail: fmt.Sprintf("the routing table was rewritten after genesis (main chain height %d): what it was at each partition block is not proven", h)})
		}
	}

	// 3. Every page against ITS partition's state root, chains bound there, partition derived and routed.
	byURL := map[string]*provenAcct{}
	for i := range ev.Pages {
		p := &ev.Pages[i]
		claimed := p.Partition
		xa, ok := anchors[strings.ToLower(claimed)]
		if !ok {
			if claimed == "" {
				return refusal21(StateForeignPartitionMismatch, in.x.id, in.x.block, "url %s: claimed none, derived %s", p.URL, in.x.source)
			}
			return refusal21(StatePartitionAnchorUnavailable, claimed, 0, "%s claims a partition the evidence holds no anchor for", p.URL)
		}
		if claimed != xa.source {
			return refusal21(StateForeignPartitionMismatch, xa.id, xa.block, "url %s: claimed %s, derived %s", p.URL, claimed, xa.source)
		}
		acct, pc, err := verifyPage(p, xa.stateRoot)
		if err != nil {
			if r, derr := decodeReceipt(p.Receipt); derr == nil && !bytes.Equal(r.Anchor, xa.stateRoot) {
				return refusal21(StatePageBlockMismatch, xa.id, xa.block, "%s: %v", p.URL, err)
			}
			return fmt.Errorf("page: %w", err)
		}
		if _, own := ledgerOf(acct, xa); table != nil && !own { // a partition's own system ledger is addressed by its partition, not routed by the table
			routed, err := proof.RoutePartition(table, acct.GetUrl().String())
			if err != nil {
				return fmt.Errorf("page %s: %w", p.URL, err)
			}
			if !strings.EqualFold(routed, xa.id) {
				if routingHeight == 1 {
					return refusal21(StateRoutingMismatch, xa.id, xa.block, "url %s: the routing table sends it to %s, its anchor names %s", p.URL, routed, xa.id)
				}
			}
		}
		k := lk(acct.GetUrl())
		if _, dup := byURL[k]; dup {
			return fmt.Errorf("page %s is proven twice", p.URL)
		}
		byURL[k] = &provenAcct{i: i, acct: acct, anchor: xa, chain: pc}
		rep.Pages = append(rep.Pages, acct)
		rep.PageChains = append(rep.PageChains, pc)
	}

	// The principal was read after the transaction executed; an UpdateAccountAuth that gave an account its first authorities cannot be
	// judged against the set the executor required (xoverride.go).
	if txn, terr := carriedTransaction(ev, in.x); terr == nil && txn != nil {
		if u, perr := url.Parse(ev.Account); perr == nil {
			if pa, ok := byURL[lk(u)]; ok {
				if fa, ok := pa.acct.(protocol.FullAccount); ok {
					if err := refuseUpdateAccountAuthInherited(txn, fa.GetAuth().Authorities, in.x); err != nil {
						return err
					}
				}
			}
		}
	}

	// 4. The governing set, re-derived from the proven states - and from every state a page with a certified history passed through, so a
	// delegate entry removed after a counted signature arrived still puts its book in the set; the recorded roles must equal it.
	if err := checkExecutorVersion(byURL); err != nil {
		return err
	}
	tl, err := foldTimelines(ev, byURL)
	if err != nil {
		return err
	}
	derived, err := deriveRoles(ev, byURL, anchors, tl, in.x, in.network)
	if err != nil {
		return err
	}
	var initiatorNotCarried []string
	for i := range ev.Pages {
		p := &ev.Pages[i]
		pa := byURL[strings.ToLower(rep.Pages[i].GetUrl().String())]
		recorded := map[PageRole]bool{}
		for _, r := range p.Roles {
			if _, err := CanonicalRoles([]PageRole{r}); err != nil {
				return refusal21(StateRoleMismatch, pa.anchor.id, pa.anchor.block, "url %s: %v", p.URL, err)
			}
			recorded[r] = true
		}
		if len(recorded) == 0 {
			return refusal21(StateRoleMismatch, pa.anchor.id, pa.anchor.block, "url %s: the page records no role", p.URL)
		}
		want := derived.want[lk(rep.Pages[i].GetUrl())]
		var roles, declared []PageRole
		for _, r := range KnownRoles {
			switch {
			case declaredRoles[r] && !derived.proves(r):
				if recorded[r] {
					declared = append(declared, r)
					if r == RoleInitiatorSigner {
						initiatorNotCarried = append(initiatorNotCarried, p.URL)
					}
				}
			case recorded[r] && !want[r]:
				return refusal21(StateRoleMismatch, pa.anchor.id, pa.anchor.block, "url %s: role %s is claimed but the proven states do not justify it", p.URL, r)
			case !recorded[r] && want[r]:
				return refusal21(StateRoleMismatch, pa.anchor.id, pa.anchor.block, "url %s: role %s is justified by the proven states but not recorded", p.URL, r)
			case recorded[r]:
				roles = append(roles, r)
			}
		}
		if len(roles) == 0 && len(declared) == 0 {
			return refusal21(StateRoleMismatch, pa.anchor.id, pa.anchor.block, "url %s: no recorded role is justified", p.URL)
		}
		rep.Proven = append(rep.Proven, ProvenPage{URL: p.URL, Partition: pa.anchor.source, Block: pa.anchor.block, Roles: roles, Declared: declared})
	}
	if len(initiatorNotCarried) > 0 && ev.Transaction != "" {
		rep.Unproven = append(rep.Unproven, NamedState{Code: StateInitiatorSignatureNotCarried, Partition: in.x.id, Block: in.x.block,
			Detail: fmt.Sprintf("%s records the role initiator-signer but the evidence carries no signature that initiated the transaction: the role is a recorded fact, listed as declared", strings.Join(initiatorNotCarried, ", "))})
	}

	// 5. The counted signatures are members of their pages' signature chains at their pages' own B_Y.
	if err := verifyVoteMembership(ev, in, byURL, anchors); err != nil {
		return err
	}

	// 6. The certified timeline (PROOF_V2 5.2 steps 2-5): every carried history was folded to its proven chain root and replayed (step 4
	// above); when the evidence carries all the votes need, each counted signature's arrival is derived and the vote model run on it.
	engaged, why := timelineEngaged(ev, tl)
	if !engaged {
		detail := "the votes are not re-evaluated (readiness, thresholds, per-arrival page states): this report proves the pages, not that the transaction was authorized"
		if len(tl) > 0 || ev.Transaction != "" {
			detail += "; the timeline is not complete: " + why
		}
		rep.Unproven = append(rep.Unproven, NamedState{Code: StateCompletenessUnproven, Partition: in.x.id, Block: in.x.block, Detail: detail})
		return nil
	}
	auths, err := principalAuthorities(ev, byURL, nil)
	if err != nil {
		return err
	}
	ti := timelineIn{ev: ev, rep: rep, x: in, byURL: byURL, auths: auths, anchor: anchors}
	if err := evaluateTimeline(ti, tl); err != nil {
		return err
	}
	return verifyProductions(ti)
}

// deriveRoles re-derives, from the proven accounts alone, why each page must be among the proven pages (D1(a), (b), (d), (e)),
// and requires every page it needs to be present: every page 1..PageCount of every book, every account on the principal's
// inheritance chain, every delegate book to the depth limit, every page a counted vote names. Roles that depend on facts outside
// the evidence (declaredRoles) are not derived; the books a header-authority declaration names are expanded as authorities.
func deriveRoles(ev *Evidence, byURL map[string]*provenAcct, anchors map[string]*xAnchor, tl states, x xAnchor, network string) (*derivedRoles, error) {
	out := map[string]map[PageRole]bool{}
	dr := &derivedRoles{want: out}
	// The transaction the evidence carries derives header-authority (and, with the initiating signature, initiator-signer): xroles.go.
	txn, err := carriedTransaction(ev, x)
	if err != nil {
		return nil, err
	}
	headerSet := map[string]bool{}
	var headerURLs []*url.URL
	if txn != nil {
		headerURLs = headerAuthorityURLs(txn)
		dr.header = true
		for _, h := range headerURLs {
			if _, ok := byURL[lk(h)]; !ok {
				return nil, refusal21(StateHeaderAuthorityMissing, x.id, x.block, "the transaction requires the authority %v, which has no proven pages", h)
			}
			headerSet[lk(h)] = true
		}
	}
	add := func(u *url.URL, r PageRole) {
		if out[lk(u)] == nil {
			out[lk(u)] = map[PageRole]bool{}
		}
		out[lk(u)][r] = true
	}
	get := func(u *url.URL, why string) (*provenAcct, error) {
		pa, ok := byURL[lk(u)]
		if !ok {
			return nil, refusal21(StateCompletenessUnproven, "", 0, "%s is %s but is not among the proven pages", u, why)
		}
		return pa, nil
	}

	// (a) The principal and the accounts its authority set is inherited through (internal/core/block/shared, Baikonur and later).
	auths, err := principalAuthorities(ev, byURL, func(u *url.URL) { add(u, RolePrincipalChain) })
	if err != nil {
		return nil, err
	}

	// (b), (c), (d) The books at level 0: every listed authority (enabled or not), every book a page declares as a header
	// authority, and - when every listed authority is disabled - the authority of each counted vote.
	type bookReq struct {
		book, page PageRole
	}
	roots := map[string]bookReq{}
	var order []*url.URL
	addRoot := func(u *url.URL, b, p PageRole) {
		if _, ok := roots[lk(u)]; !ok {
			order = append(order, u)
		}
		roots[lk(u)] = bookReq{b, p}
	}
	allDisabled := true
	listed := map[string]bool{}
	for _, a := range auths {
		listed[lk(a.Url)] = true
		if !a.Disabled {
			allDisabled = false
		}
		addRoot(a.Url, RoleAuthorityBook, RoleAuthorityPage)
	}
	// The all-authorities-disabled rule (the executor accepts any authority's vote then, sig_common.go:367-369) is not the rule of a
	// transaction type that requires authorization (protocol.TransactionType.RequireAuthorization: UpdateAccountAuth). evaluateTimeline
	// applies the same carve-out, so the pages a document needs are derived by the rule that judges its votes: the authority of a vote
	// outside the list is not a root there (RB9-K-F1, a vector of testdata/xpartition6). Without the transaction its type is not known
	// and the rule stands as it was.
	if txn != nil && txn.Body.Type().RequireAuthorization() {
		allDisabled = false
	}
	// The books the carried transaction names are roots whether or not they are listed authorities (their header-authority role is
	// added when each is expanded). Without a transaction the role is only a recorded fact and the books the pages record are expanded.
	for _, h := range headerURLs {
		if _, ok := roots[lk(h)]; !ok {
			addRoot(h, RoleHeaderAuthority, RoleHeaderAuthority)
		}
	}
	for i := 0; i < len(ev.Pages) && txn == nil; i++ {
		for _, r := range ev.Pages[i].Roles {
			if r == RoleHeaderAuthority {
				if u, err := url.Parse(ev.Pages[i].URL); err == nil {
					if _, isBook := byURL[lk(u)].acct.(*protocol.KeyBook); isBook {
						if _, ok := roots[lk(u)]; !ok {
							addRoot(u, RoleHeaderAuthority, RoleHeaderAuthority)
						}
					}
				}
			}
		}
	}
	for _, v := range ev.Votes {
		a, err := url.Parse(v.Authority)
		if err != nil {
			return nil, fmt.Errorf("vote authority %q: %w", v.Authority, err)
		}
		if !listed[lk(a)] && allDisabled {
			if _, ok := roots[lk(a)]; !ok {
				addRoot(a, RoleVoter, RoleVoter)
			}
		}
	}

	// Expand each book with every page 1..PageCount; follow the delegate entries breadth first, a book by its shortest path;
	// the Delegate entries of a page in a book at level 20 are not followed (a signature passes through at most 20 delegators).
	type item struct {
		u     *url.URL
		level int
	}
	var queue []item
	expanded := map[string]bool{}
	expand := func(u *url.URL, level int, bookRole, pageRole PageRole) error {
		pa, err := get(u, "a key book of the governing set")
		if err != nil {
			return err
		}
		expanded[lk(u)] = true
		var pages []*url.URL
		switch bk := pa.acct.(type) {
		case *protocol.LiteIdentity:
			add(u, bookRole)
			add(u, pageRole)
			if headerSet[lk(u)] {
				add(u, RoleHeaderAuthority)
			}
			return nil
		case *protocol.KeyBook:
			add(u, bookRole)
			if headerSet[lk(u)] {
				add(u, RoleHeaderAuthority)
			}
			for n := uint64(0); n < bk.PageCount; n++ {
				pages = append(pages, protocol.FormatKeyPageUrl(u, n))
			}
		default:
			return fmt.Errorf("authority %v is %T, not a key book", u, pa.acct)
		}
		for _, pu := range pages {
			pp, ok := byURL[lk(pu)]
			if !ok {
				return refusal21(StateBookPageCountUnproven, pa.anchor.id, pa.anchor.block,
					"%v proves PageCount %d but its page %v is not among the proven pages", u, len(pages), pu)
			}
			add(pu, pageRole)
			if headerSet[lk(u)] {
				add(pu, RoleHeaderAuthority)
			}
			kp, ok := pp.acct.(*protocol.KeyPage)
			if !ok {
				return fmt.Errorf("%v is %T, not a key page", pu, pp.acct)
			}
			for _, ks := range kp.Keys {
				if ks.Delegate != nil && level < protocol.DelegationDepthLimit {
					queue = append(queue, item{ks.Delegate, level + 1})
				}
			}
			// The delegates the page held at any earlier state of its certified history (the delegation a counted signature went
			// through may be gone by B_Y).
			for _, st := range tl[govvote.CanonicalAccSpelling(pu.String())] {
				for _, ks := range st.Page.Keys {
					if ks.Delegate != nil && level < protocol.DelegationDepthLimit {
						queue = append(queue, item{ks.Delegate, level + 1})
					}
				}
			}
		}
		return nil
	}
	for _, u := range order {
		rq := roots[lk(u)]
		if err := expand(u, 0, rq.book, rq.page); err != nil {
			return nil, err
		}
	}
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if expanded[lk(it.u)] {
			continue
		}
		if err := expand(it.u, it.level, RoleDelegateBook, RoleDelegatePage); err != nil {
			return nil, err
		}
	}

	// (d), (f) Every page a counted vote names: its origin page, every page its cause chain passes through, every page in the
	// delegator path of its key signature.
	for _, v := range ev.Votes {
		origin, err := url.Parse(v.Origin)
		if err != nil {
			return nil, fmt.Errorf("vote origin %q: %w", v.Origin, err)
		}
		if !strings.EqualFold(v.Origin, v.Authority) {
			if _, err := get(origin, "named by a counted vote's origin"); err != nil {
				return nil, err
			}
			add(origin, RoleVoter)
		}
		for _, h := range v.allHops() {
			hp, err := url.Parse(h.Page)
			if err != nil {
				return nil, fmt.Errorf("vote hop page %q: %w", h.Page, err)
			}
			if _, err := get(hp, "on a counted vote's cause chain"); err != nil {
				return nil, err
			}
			add(hp, RoleVoter)
		}
		if v.Produced != nil && !strings.EqualFold(v.Produced.Account, ev.Account) {
			pu, err := url.Parse(v.Produced.Account)
			if err != nil {
				return nil, fmt.Errorf("vote of %s: production account %q: %w", v.Authority, v.Produced.Account, err)
			}
			if _, err := get(pu, "named by a counted vote's production proof"); err != nil {
				return nil, err
			}
			add(pu, RoleSyntheticChain)
		}
		if len(v.Hops) > 0 {
			keySig := v.Hops[len(v.Hops)-1]
			raw, err := hex.DecodeString(keySig.Signature)
			if err != nil {
				return nil, fmt.Errorf("vote of %s: key signature: %w", v.Authority, err)
			}
			sig, err := protocol.UnmarshalSignature(raw)
			if err != nil {
				return nil, fmt.Errorf("vote of %s: key signature: %w", v.Authority, err)
			}
			if isNil(sig) { // the union decoder's answer for bytes that hold no type
				return nil, fmt.Errorf("vote of %s: key signature: it holds no signature", v.Authority)
			}
			path := delegatorPages(sig)
			if len(path) > protocol.DelegationDepthLimit {
				return nil, refusal21(StateDelegationDepthExceeded, "", 0, "the vote of %s was signed through %d delegators, the limit is %d", v.Authority, len(path), protocol.DelegationDepthLimit)
			}
			for _, d := range path {
				if _, err := get(d, "in the delegator path of a counted vote"); err != nil {
					return nil, err
				}
				add(d, RoleVoter)
			}
		}
	}

	// A partition's system ledger proven at the partition's block carries the executor version in force there (xexecutor.go).
	for _, pa := range byURL {
		if l, ok := ledgerOf(pa.acct, pa.anchor); ok {
			add(l.Url, RoleSystemLedger)
		}
	}

	// (f) The initiator's pages, from the initiating signature when the evidence carries it (xroles.go).
	if txn != nil {
		pages, found, err := initiatorPages(ev, txn, byURL, network)
		if err != nil {
			return nil, err
		}
		if found {
			dr.initiator = true
			for _, ip := range pages {
				if _, ok := byURL[lk(ip)]; !ok {
					return nil, refusal21(StateInitiatorPageUnproven, x.id, x.block, "%v initiated the transaction (or is in the path of the signature that did) but is not among the proven pages", ip)
				}
				add(ip, RoleInitiatorSigner)
			}
		}
	}
	return dr, nil
}

// derivedRoles is what deriveRoles established: the roles every page is justified to have, and which of the roles that can be declared
// were derived (proven) for this document.
type derivedRoles struct {
	want      map[string]map[PageRole]bool
	header    bool // the evidence carries the transaction: header-authority is derived, not declared
	initiator bool // the evidence carries the initiating signature: initiator-signer is derived, not declared
}

// proves says whether role r is a role this document's roles are re-derived for (never RoleCertifiedKeyPage).
func (d *derivedRoles) proves(r PageRole) bool {
	switch r {
	case RoleHeaderAuthority:
		return d.header
	case RoleInitiatorSigner:
		return d.initiator
	}
	return false
}

// delegatorPages returns the delegator pages a signature is wrapped in, outermost first.
func delegatorPages(sig protocol.Signature) []*url.URL {
	var out []*url.URL
	for {
		d, ok := sig.(*protocol.DelegatedSignature)
		if !ok {
			return out
		}
		if d.Delegator != nil {
			out = append(out, d.Delegator)
		}
		sig = d.Signature
	}
}

// chainAnchor is the bound root of the named chain of a page, when its chains are bound.
func chainAnchor(pa *provenAcct, p *PageState, name string) ([]byte, error) {
	if !pa.chain.Bound {
		code := StateChainUnboundPending
		if i := strings.Index(pa.chain.Note, ":"); i > 0 && strings.HasPrefix(pa.chain.Note, "g1_") {
			code = pa.chain.Note[:i]
		}
		return nil, refusal21(code, pa.anchor.id, pa.anchor.block, "%s: its chains are not bound at the block (%s)", p.URL, pa.chain.Note)
	}
	for _, c := range p.Chains {
		if c.Name == name && c.Count > 0 {
			b, err := hex.DecodeString(c.Anchor)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("%s: chain %s has no 32-byte root", p.URL, name)
			}
			return b, nil
		}
	}
	return nil, refusal21(StateBlockBeforeArrival, pa.anchor.id, pa.anchor.block, "%s has no %s chain at the block", p.URL, name)
}

// inChain requires a receipt that starts at message (hex32) and ends at root.
func inChain(receiptHex, messageHex string, root []byte) bool {
	msg, err := hex.DecodeString(messageHex)
	if err != nil || len(msg) != 32 {
		return false
	}
	r, err := decodeReceipt(receiptHex)
	if err != nil {
		return false
	}
	return bytes.Equal(r.Start, msg) && bytes.Equal(r.Anchor, root) && r.Validate(nil)
}

// verifyVoteMembership checks what the vote records can be checked for without re-evaluating the vote. Each vote is a member of
// the principal's signature chain at the transaction's block, its transport names proven partitions, and every signature on its
// cause chain is a member of its page's signature chain at that page's own B_Y. A message that is a member of a chain bound at
// B_Y arrived at or before B_Y, so a document whose B_Y precedes a counted signature's arrival cannot produce the membership: that
// is g1_block_before_signature (design D2: B_Y at or after every counted production and arrival block).
func verifyVoteMembership(ev *Evidence, in xIn, byURL map[string]*provenAcct, anchors map[string]*xAnchor) error {
	if len(ev.Votes) == 0 {
		return nil
	}
	principal, err := url.Parse(ev.Account)
	if err != nil {
		return err
	}
	pp, ok := byURL[lk(principal)]
	if !ok {
		return refusal21(StateCompletenessUnproven, in.x.id, in.x.block, "the principal %s is not among the proven pages", ev.Account)
	}
	for _, v := range ev.Votes {
		switch v.Vote {
		case "accept", "reject", "abstain", "suggest":
		default:
			return fmt.Errorf("vote of %s: %q is not a vote", v.Authority, v.Vote)
		}
		switch v.Transport.Kind {
		case TransportInline:
		case TransportSequenced:
			src, ok := anchors[strings.ToLower(v.Transport.Source)]
			if !ok {
				return refusal21(StatePartitionAnchorUnavailable, v.Transport.Source, 0, "the vote of %s was sequenced from a partition the evidence holds no anchor for", v.Authority)
			}
			if !strings.EqualFold(v.Transport.Destination, in.x.source) || v.Transport.Number == 0 {
				return refusal21(StateForeignPartitionMismatch, src.id, src.block, "url vote of %s: sequenced to %s, the transaction's partition is %s", v.Authority, v.Transport.Destination, in.x.source)
			}
		default:
			return fmt.Errorf("vote of %s: transport %q", v.Authority, v.Transport.Kind)
		}
		root, err := chainAnchor(pp, &ev.Pages[pp.i], "signature")
		if err != nil {
			return err
		}
		if !inChain(v.Receipt, v.Message, root) {
			return refusal21(StateBlockBeforeArrival, in.x.id, in.x.block, "the vote of %s is not a member of %s's signature chain at the transaction's block", v.Authority, ev.Account)
		}
		for _, h := range v.allHops() {
			hp, err := url.Parse(h.Page)
			if err != nil {
				return err
			}
			pa, ok := byURL[lk(hp)]
			if !ok {
				return refusal21(StateCompletenessUnproven, in.x.id, in.x.block, "%s is on a counted vote's cause chain but is not among the proven pages", h.Page)
			}
			if h.Block > pa.anchor.block {
				return refusal21(StateBlockBeforeArrival, pa.anchor.id, pa.anchor.block, "the signature on %s arrived in block %d, after the page's block", h.Page, h.Block)
			}
			root, err := chainAnchor(pa, &ev.Pages[pa.i], "signature")
			if err != nil {
				return err
			}
			if !inChain(h.Receipt, h.Message, root) {
				return refusal21(StateBlockBeforeArrival, pa.anchor.id, pa.anchor.block, "the signature on %s is not a member of the page's signature chain at the block", h.Page)
			}
		}
	}
	return nil
}

// principalAuthorities resolves the principal's authority list as the executor does, walking the inheritance chain through the proven
// accounts; onChain is called for each account on the walk. It requires every account it reads to be among the proven pages.
func principalAuthorities(ev *Evidence, byURL map[string]*provenAcct, onChain func(*url.URL)) ([]protocol.AuthorityEntry, error) {
	principal, err := url.Parse(ev.Account)
	if err != nil {
		return nil, fmt.Errorf("evidence account: %w", err)
	}
	for cur := principal; ; {
		pa, ok := byURL[lk(cur)]
		if !ok {
			return nil, refusal21(StateCompletenessUnproven, "", 0, "%s is on the principal's inheritance chain but is not among the proven pages", cur)
		}
		if onChain != nil {
			onChain(cur)
		}
		switch a := pa.acct.(type) {
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
				return nil, refusal21(StateCompletenessUnproven, pa.anchor.id, pa.anchor.block,
					"root identity %v lists no authority: the executor refuses it, so its governing set cannot be derived", cur)
			}
			cur = parent
		default:
			return nil, fmt.Errorf("account %v is %T, which is not governed by key books", cur, pa.acct)
		}
	}
}
