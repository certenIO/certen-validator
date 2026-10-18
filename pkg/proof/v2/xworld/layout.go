// Copyright 2026 Certen Protocol

package xworld

import (
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Layout says which partitions the three slots of the world sit on (RB9 Phase C1b-2, design D2a-D2c). The slots are fixed by the
// document: slot 0 holds the principal and its anchor is Evidence.Anchor, slot 1 holds the authority book whose vote is counted,
// slot 2 holds the delegate book. The default layout is D2a, three block validator partitions.
type Layout string

const (
	// LayoutBVN is D2a: the principal on BVN1, the authority book on BVN2, the delegate book on BVN3.
	LayoutBVN Layout = ""
	// LayoutDirectoryAuthority is D2b: the principal on BVN1 and the authority book on the Directory (acc://dn.acme/operators). The
	// Directory page is proven to the DirectoryAnchor the Directory executed for its block, not to a BlockValidatorAnchor.
	LayoutDirectoryAuthority Layout = "directory-authority"
	// LayoutDirectoryPrincipal is D2c: the principal on the Directory (acc://dn.acme/pv2-data), governed by a book on BVN2. The
	// transaction's own partition anchor is a DirectoryAnchor; the vote is a BlockValidatorAnchor-backed sequenced message from BVN2.
	LayoutDirectoryPrincipal Layout = "directory-principal"
)

// The Directory accounts and blocks of the D2b and D2c worlds.
const (
	DirPartition = "acc://dn.acme"
	DNBook       = "acc://dn.acme/operators"
	DNPage1      = "acc://dn.acme/operators/1"
	DNPage2      = "acc://dn.acme/operators/2"
	DNPrincipal  = "acc://dn.acme/pv2-data"
	BlockDN      = 70 // the Directory block the D2b authority pages are proven at
	BlockDNTx    = 50 // the Directory block the D2c principal executed in
)

// slot is one partition of the world: where its anchor comes from and which block its pages are proven at.
type slot struct {
	src   string
	id    string
	block uint64
	dir   bool // its anchor is the Directory's own DirectoryAnchor
}

type layout struct {
	principal, book, page1, page2 string
	x, a, d                       slot
}

func layoutOf(l Layout) layout {
	lay := layout{principal: Principal, book: BankBook, page1: BankPage1, page2: BankPage2,
		x: slot{PartBVN1, "BVN1", BlockBVN1, false}, a: slot{PartBVN2, "BVN2", BlockBVN2, false}, d: slot{PartBVN3, "BVN3", BlockBVN3, false}}
	switch l {
	case LayoutBVN:
	case LayoutDirectoryAuthority:
		lay.book, lay.page1, lay.page2 = DNBook, DNPage1, DNPage2
		lay.a = slot{DirPartition, protocol.Directory, BlockDN, true}
	case LayoutDirectoryPrincipal:
		lay.principal = DNPrincipal
		lay.x = slot{DirPartition, protocol.Directory, BlockDNTx, true}
	default:
		panic("xworld: unknown layout " + string(l))
	}
	return lay
}

// swapKind rebuilds a partition anchor body in the other kind: a BlockValidatorAnchor where the slot's partition is the Directory
// and a DirectoryAnchor where it is a block validator partition. The anchor is still proven into the certified root, so only the
// per-kind check can refuse it.
func swapKind(pa protocol.PartitionAnchor, dir bool) protocol.TransactionBody {
	if dir {
		return &protocol.BlockValidatorAnchor{PartitionAnchor: pa}
	}
	return &protocol.DirectoryAnchor{PartitionAnchor: pa}
}

// slotNames key the anchors of the three slots while the world is built.
var slotNames = [3]string{"x", "a", "d"}
