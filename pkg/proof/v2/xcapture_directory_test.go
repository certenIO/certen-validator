// Copyright 2026 Certen Protocol

package proofv2

import (
	"context"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// dirLog is the Directory's record of its own anchors: each is the DirectoryAnchor the Directory produced for its block.
type dirLog struct {
	sliceLog
	bvn bool // answer with a BlockValidatorAnchor instead: the wrong kind for the Directory
}

func (l dirLog) Produced(_ context.Context, p string, i uint64) (*protocol.Transaction, error) {
	pa := protocol.PartitionAnchor{Source: protocol.PartitionUrl(p), MinorBlockIndex: l.blocks[i], RootChainIndex: i, StateTreeAnchor: [32]byte{byte(i) + 1}}
	if l.bvn {
		return &protocol.Transaction{Body: &protocol.BlockValidatorAnchor{PartitionAnchor: pa}}, nil
	}
	return &protocol.Transaction{Body: &protocol.DirectoryAnchor{PartitionAnchor: pa}}, nil
}

// The Directory's block is chosen from its own DirectoryAnchors exactly as a block validator partition's is chosen from the anchors it
// sent: the admissible anchors are those executed at or before the limit, the smallest at or after the bound, and the anchor's state
// root is the one the page is proven to.
func TestSelectPartitionBlockOverTheDirectorysOwnAnchors(t *testing.T) {
	l := dirLog{sliceLog: sliceLog{dn: []uint64{100, 110, 120}, blocks: []uint64{4000, 4010, 4020}}}
	pb, err := SelectPartitionBlock(context.Background(), l, protocol.Directory, 115, 4001)
	if err != nil {
		t.Fatal(err)
	}
	if pb.Block != 4010 || pb.Index != 1 || pb.DNBlock != 110 || pb.Latest != 1 || pb.Anchor.StateTreeAnchor != ([32]byte{2}) {
		t.Fatalf("selected %+v", pb)
	}
	if _, ok := pb.Txn.Body.(*protocol.DirectoryAnchor); !ok {
		t.Fatalf("the Directory's anchor is %T, not a DirectoryAnchor", pb.Txn.Body)
	}
	// A BlockValidatorAnchor is not the Directory's anchor: the selection refuses it by name of the kind.
	l.bvn = true
	if _, err := SelectPartitionBlock(context.Background(), l, protocol.Directory, 115, 0); err == nil {
		t.Fatal("a BlockValidatorAnchor was taken for the Directory's anchor")
	}
	// And a DirectoryAnchor is not a block validator partition's.
	l.bvn = false
	if _, err := SelectPartitionBlock(context.Background(), l, "BVN2", 115, 0); err == nil {
		t.Fatal("a DirectoryAnchor was taken for BVN2's anchor")
	}
}

func TestAnchorKindFitsThePartitionKind(t *testing.T) {
	bva, dir := &protocol.BlockValidatorAnchor{}, &protocol.DirectoryAnchor{}
	for _, c := range []struct {
		partition string
		body      protocol.TransactionBody
		want      bool
	}{
		{protocol.Directory, dir, true}, {"directory", dir, true}, {protocol.Directory, bva, false},
		{"BVN1", bva, true}, {"BVN1", dir, false}, {"BVN3", &protocol.WriteData{}, false},
	} {
		if got := anchorKindFits(c.partition, c.body); got != c.want {
			t.Errorf("anchorKindFits(%s, %T) = %v", c.partition, c.body, got)
		}
	}
}
