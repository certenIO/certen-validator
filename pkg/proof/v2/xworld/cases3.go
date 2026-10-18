// Copyright 2026 Certen Protocol

package xworld

import (
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Cases3 is the three-way partition suite (RB9 Phase C1b-2; testdata/xpartition3): one valid document and the adversarial ones that
// matter for each of design D2a (block validator partition to block validator partition), D2b (a governing book on the Directory)
// and D2c (the principal on the Directory). The anchor kind is checked per partition kind: a block validator partition is proven by
// a BlockValidatorAnchor, the Directory by a DirectoryAnchor. The earlier suites (Cases, Cases2) are untouched.
func Cases3() []Case {
	c := proofv2.StateCompletenessUnproven
	dnToBVN3 := func(rt *protocol.RoutingTable) {
		for i := range rt.Overrides {
			if rt.Overrides[i].Account.Equal(url.MustParse("acc://dn.acme")) {
				rt.Overrides[i].Partition = "BVN3"
			}
		}
	}
	d2b := Options{Layout: LayoutDirectoryAuthority}
	d2c := Options{Layout: LayoutDirectoryPrincipal}
	with := func(o Options, f func(*Options)) Options { f(&o); return o }
	return []Case{
		// D2a
		{Name: "d2a-bvn-to-bvn-valid", Description: "D2a: the principal on BVN1, the authority book on BVN2 and the delegate book on BVN3, each proven at its own block through a BlockValidatorAnchor", Expect: verified,
			Unproven: []string{c}},
		{Name: "d2a-bvn-slot-holds-a-directory-anchor", Description: "D2a: BVN2's anchor is a DirectoryAnchor naming BVN2 as its source, proven into the certified root: the kind does not fit a block validator partition", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: Options{SwapAnchorKind: 2}},

		// D2b: the authority book is on the Directory
		{Name: "d2b-directory-authority-valid", Description: "D2b: the principal on BVN1, its authority book acc://dn.acme/operators on the Directory, proven at Directory block 70 through the DirectoryAnchor the Directory executed for it; the vote is sequenced from the Directory", Expect: verified,
			Unproven: []string{c}, Opts: d2b},
		{Name: "d2b-directory-page-with-a-bvn-anchor", Description: "D2b: the Directory's anchor is a BlockValidatorAnchor naming the Directory as its source, proven into the certified root: the kind does not fit the Directory", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: protocol.Directory, Block: BlockDN, Opts: with(d2b, func(o *Options) { o.SwapAnchorKind = 2 })},
		{Name: "d2b-directory-page-at-another-block", Description: "D2b: a Directory page proven at another Directory block (a valid receipt to a different state root)", Expect: refused,
			State: proofv2.StatePageBlockMismatch, Partition: protocol.Directory, Block: BlockDN, Opts: with(d2b, func(o *Options) { o.AltBlockPage = DNPage1 })},
		{Name: "d2b-directory-book-routed-elsewhere", Description: "D2b: the proven routing table, unchanged since genesis, sends acc://dn.acme to BVN3 while the anchor names the Directory", Expect: refused,
			State: proofv2.StateRoutingMismatch, Partition: protocol.Directory, Block: BlockDN, Opts: with(d2b, func(o *Options) { o.Routing = dnToBVN3 })},
		{Name: "d2b-directory-anchor-under-a-bvn-key", Description: "D2b: the Directory's anchor is filed under BVN2's key in the anchors map: the partition is derived from the anchor, not the key", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: protocol.Directory, Block: BlockDN, Opts: d2b,
			Mutate: func(ev *proofv2.Evidence) {
				ev.Anchors[PartBVN2] = ev.Anchors[DirPartition]
				delete(ev.Anchors, DirPartition)
			}},

		// D2c: the principal is on the Directory
		{Name: "d2c-directory-principal-valid", Description: "D2c: the principal acc://dn.acme/pv2-data on the Directory, governed by a book on BVN2; the transaction's own anchor is a DirectoryAnchor and the vote is sequenced from BVN2 to the Directory", Expect: verified,
			Unproven: []string{c}, Opts: d2c},
		{Name: "d2c-directory-principal-with-a-bvn-anchor", Description: "D2c: the transaction's partition anchor is a BlockValidatorAnchor naming the Directory as its source: the kind does not fit the Directory", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: protocol.Directory, Block: BlockDNTx, Opts: with(d2c, func(o *Options) { o.SwapAnchorKind = 1 })},
		{Name: "d2c-directory-principal-at-another-block", Description: "D2c: the Directory principal proven at another Directory block", Expect: refused,
			State: proofv2.StatePageBlockMismatch, Partition: protocol.Directory, Block: BlockDNTx, Opts: with(d2c, func(o *Options) { o.AltBlockPage = DNPrincipal })},
		{Name: "d2c-vote-from-an-unanchored-partition", Description: "D2c: the vote claims to be sequenced from BVN4, whose anchor the evidence does not hold", Expect: refused,
			State: proofv2.StatePartitionAnchorUnavailable, Partition: "acc://bvn-BVN4.acme", Opts: d2c,
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Transport.Source = "acc://bvn-BVN4.acme" }},
		{Name: "d2c-vote-sequenced-to-another-partition", Description: "D2c: the vote was sequenced to BVN1, not to the Directory that holds the principal", Expect: refused,
			State: proofv2.StateForeignPartitionMismatch, Partition: "BVN2", Block: BlockBVN2, Opts: d2c,
			Mutate: func(ev *proofv2.Evidence) { ev.Votes[0].Transport.Destination = PartBVN1 }},
	}
}
