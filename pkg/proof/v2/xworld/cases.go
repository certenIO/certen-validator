// Copyright 2026 Certen Protocol

package xworld

import (
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Case is one document of the evidence 2.1 conformance suite and the verdict every verifier must reach on it: Expect is
// "verified" or "refused"; State, for a refusal that is a named state, is its code with the partition and block it was judged at;
// Unproven, for a verified document, lists the codes the report must carry (it is never empty: the vote re-evaluation is not part
// of this verifier build).
type Case struct {
	Name        string
	Description string
	Expect      string
	State       string
	Partition   string
	Block       uint64
	Unproven    []string
	Opts        Options
	Mutate      func(ev *proofv2.Evidence)
}

func idx(ev *proofv2.Evidence, u string) int {
	for i, p := range ev.Pages {
		if strings.EqualFold(p.URL, u) {
			return i
		}
	}
	panic("xworld: no page " + u)
}

func drop(ev *proofv2.Evidence, urls ...string) {
	for _, u := range urls {
		i := idx(ev, u)
		ev.Pages = append(ev.Pages[:i], ev.Pages[i+1:]...)
	}
}

const (
	refused  = "refused"
	verified = "verified"
)

// Cases returns the suite in a fixed order.
func Cases() []Case {
	bankToBVN3 := func(rt *protocol.RoutingTable) {
		rt.Overrides = append(rt.Overrides, protocol.RouteOverride{Account: url.MustParse("acc://pv2-bank-5.acme"), Partition: "BVN3"})
	}
	c := proofv2.StateCompletenessUnproven
	return []Case{
		{Name: "valid-mixed-partition", Description: "governing pages on three partitions, each at its own block through its own anchor; routing proven", Expect: verified,
			Unproven: []string{c}},
		{Name: "foreign-page-at-another-block", Description: "a BVN2 page proven at another BVN2 block (a valid receipt to a different state root)", Expect: refused,
			State: proofv2.StatePageBlockMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{AltBlockPage: BankPage1}},
		{Name: "delegate-page-at-another-block", Description: "a BVN3 delegate page proven at another BVN3 block", Expect: refused,
			State: proofv2.StatePageBlockMismatch, Partition: "BVN3", Block: BlockBVN3, Opts: Options{AltBlockPage: DelePage1}},
		{Name: "block-before-counted-arrival-claimed", Description: "the vote's key signature claims an arrival block after BVN2's B_Y", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: "BVN2", Block: BlockBVN2,
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Block = BlockBVN2 + 1 }},
		{Name: "block-before-counted-arrival-not-a-member", Description: "the key signature is not a member of its page's signature chain at BVN2's B_Y", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: "BVN2", Block: BlockBVN2,
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Hops[0].Message = strings.Repeat("ab", 32) }},
		{Name: "vote-not-in-principal-chain", Description: "the vote is not a member of the principal's signature chain at the transaction's block", Expect: refused,
			State: proofv2.StateBlockBeforeArrival, Partition: "BVN1", Block: BlockBVN1,
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Message = strings.Repeat("cd", 32) }},
		{Name: "anchor-source-not-claimed-partition", Description: "the BVN2 slot of anchors holds the anchor BVN3 produced", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: "BVN3", Block: BlockBVN3,
			Mutate: func(ev *proofv2.Evidence) { ev.Anchors[PartBVN2] = ev.Anchors[PartBVN3] }},
		{Name: "page-claims-other-partition-spelling", Description: "a BVN2 page claims acc://bvn-bvn2.acme, not the anchor's Source", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: "BVN2", Block: BlockBVN2,
			Mutate: func(ev *proofv2.Evidence) { ev.Pages[idx(ev, BankPage2)].Partition = "acc://bvn-bvn2.acme" }},
		{Name: "page-claims-no-partition", Description: "a 2.1 page that names no partition", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: "BVN1", Block: BlockBVN1,
			Mutate: func(ev *proofv2.Evidence) { ev.Pages[idx(ev, BankPage2)].Partition = "" }},
		{Name: "page-claims-partition-without-anchor", Description: "a page claims a partition the evidence holds no anchor for", Expect: refused,
			State: proofv2.StatePartitionAnchorUnavailable, Partition: "acc://bvn-BVN4.acme",
			Mutate: func(ev *proofv2.Evidence) { ev.Pages[idx(ev, DelePage1)].Partition = "acc://bvn-BVN4.acme" }},
		{Name: "understated-pagecount", Description: "BankBook proves PageCount 2 but its second page is not among the proven pages", Expect: refused,
			State: proofv2.StateBookPageCountUnproven, Partition: "BVN2", Block: BlockBVN2,
			Mutate: func(ev *proofv2.Evidence) { drop(ev, BankPage2) }},
		{Name: "delegate-page-omitted", Description: "the delegate book's only page is not among the proven pages", Expect: refused,
			State: proofv2.StateBookPageCountUnproven, Partition: "BVN3", Block: BlockBVN3,
			Mutate: func(ev *proofv2.Evidence) { drop(ev, DelePage1) }},
		{Name: "delegate-book-omitted", Description: "the book a page entry delegates to is not proven", Expect: refused,
			State:  proofv2.StateCompletenessUnproven,
			Mutate: func(ev *proofv2.Evidence) { drop(ev, DelePage1, DeleBook) }},
		{Name: "page-of-a-different-account", Description: "a page whose URL names another account than its proven state", Expect: refused,
			Mutate: func(ev *proofv2.Evidence) { ev.Pages[idx(ev, BankPage2)].URL = DelePage1 }},
		{Name: "role-claimed-not-derived", Description: "BankPage1 is recorded as a delegate page, which the proven states do not justify", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: "BVN2", Block: BlockBVN2,
			Mutate: func(ev *proofv2.Evidence) {
				p := &ev.Pages[idx(ev, BankPage1)]
				p.Roles = append(p.Roles, proofv2.RoleDelegatePage)
			}},
		{Name: "role-derived-not-recorded", Description: "the vote's origin page is not recorded as a voter", Expect: refused,
			State: proofv2.StateRoleMismatch, Partition: "BVN2", Block: BlockBVN2,
			Mutate: func(ev *proofv2.Evidence) {
				ev.Pages[idx(ev, BankPage1)].Roles = []proofv2.PageRole{proofv2.RoleAuthorityPage}
			}},
		{Name: "declared-role-listed", Description: "a certified-key-page role, which only the intent certificate can justify, is listed as declared", Expect: verified,
			Unproven: []string{c},
			Mutate: func(ev *proofv2.Evidence) {
				p := &ev.Pages[idx(ev, BankPage2)]
				p.Roles = append(p.Roles, proofv2.RoleCertifiedKeyPage)
			}},
		{Name: "routing-mismatch", Description: "the proven routing table, unchanged since genesis, sends pv2-bank-5.acme to BVN3 while its anchor names BVN2", Expect: refused,
			State: proofv2.StateRoutingMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{Routing: bankToBVN3}},
		{Name: "routing-history-unproven", Description: "the routing table was rewritten after genesis (main chain height 2): what it was at B_Y is a named state", Expect: verified,
			Unproven: []string{proofv2.StateRoutingHistoryUnproven, c}, Opts: Options{Routing: bankToBVN3, RoutingHeight: 2}},
		{Name: "routing-absent", Description: "no routing proof is carried: Partition == route(URL) is a named state", Expect: verified,
			Unproven: []string{proofv2.StateRoutingUnproven, c}, Opts: Options{NoRouting: true}},
		{Name: "routing-receipt-altered", Description: "a step of the routing proof's receipt altered", Expect: refused,
			Mutate: func(ev *proofv2.Evidence) { ev.Check.Routing.StateReceipt.Entries[0].Hash = strings.Repeat("11", 32) }},
		{Name: "evidence-20-with-21-members", Description: "a document that says 2.0 but carries anchors, votes and a routing proof", Expect: refused,
			Mutate: func(ev *proofv2.Evidence) { ev.Version = proofv2.Version }},
	}
}

// Document builds the case's world, applies its mutation, and returns it with its portable form.
func (c Case) Document() (*Built, *proofv2.Portable, error) {
	b, err := Build(c.Opts)
	if err != nil {
		return nil, nil, err
	}
	if c.Mutate != nil {
		c.Mutate(b.Evidence)
	}
	p, err := b.Portable()
	return b, p, err
}
