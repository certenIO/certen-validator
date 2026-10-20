// Copyright 2026 Certen Protocol
//
// Capturing a transaction whose principal is on the Directory (docs/proof/G1_CROSS_PARTITION.md D2c; RB9 Phase C1b-2).
//
// A block validator partition's transaction is placed by the Directory's record of that partition's anchor: the block it executed
// in, the Directory block that executed the anchor, and the partition's state root at it (Builder.Position). The Directory has no
// such leg: it anchors itself, the DirectoryAnchor it produced for the transaction's block B is one entry of its own
// anchor(directory)-root chain, and the transaction's receipt passes through that anchor's root chain anchor. The limit on the
// blocks other partitions' pages are read at is B itself (D2c: the latest Y block whose anchor the Directory executed at or before
// the principal's Directory block B), so a Directory TxPosition carries B as its DNBlock.

package proofv2

import (
	"context"
	"fmt"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// DirectoryPosition reads a transaction on the Directory: its block B, and the state root and root chain of the DirectoryAnchor the
// Directory produced for B. The anchor is found in the Directory's own anchor sequence (the smallest anchor whose block is at or after
// B must be for B exactly: a Directory block that wrote nothing it anchors is a named state, never a neighbouring block's root).
func (b *Builder) DirectoryPosition(ctx context.Context, account, txHash string) (*TxPosition, error) {
	l1, err := chained_proof.NewLayer1Builder(b.C, false).Build(ctx, account, txHash)
	if err != nil {
		return nil, err
	}
	block := l1.BVNMinorBlockIndex
	log := NetLog{Net: b.C}
	unavailable := func(format string, a ...any) error {
		return &NamedState{Code: StatePartitionAnchorUnavailable, Partition: protocol.Directory, Block: block, Detail: fmt.Sprintf(format, a...)}
	}
	n, err := log.Len(ctx, protocol.Directory)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, unavailable("the Directory holds no anchor of its own")
	}
	lo, hi := uint64(0), n-1
	top, err := log.Block(ctx, protocol.Directory, hi)
	if err != nil {
		return nil, err
	}
	if top < block {
		return nil, unavailable("the Directory's latest anchor is for block %d, before the transaction's block", top)
	}
	for lo < hi { // the smallest anchor for a block at or after the transaction's
		mid := lo + (hi-lo)/2
		bl, err := log.Block(ctx, protocol.Directory, mid)
		if err != nil {
			return nil, err
		}
		if bl >= block {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	txn, err := log.Produced(ctx, protocol.Directory, lo)
	if err != nil {
		return nil, err
	}
	body, ok := anchorFields(txn.Body)
	if !ok || !anchorKindFits(protocol.Directory, txn.Body) {
		return nil, unavailable("anchor %d of the Directory is %v, not a directory anchor", lo, txn.Body.Type())
	}
	if body.MinorBlockIndex != block {
		return nil, unavailable("the smallest Directory anchor at or after the transaction's block is for block %d: the Directory produced none for block %d", body.MinorBlockIndex, block)
	}
	var rc [32]byte
	if err := hex32(l1.BVNRootChainAnchor, rc[:]); err != nil {
		return nil, err
	}
	if rc != body.RootChainAnchor {
		return nil, &NamedState{Code: StateChainMoved, Partition: protocol.Directory, Block: block,
			Detail: fmt.Sprintf("the transaction's receipt ends at the root chain anchor %x, the Directory's anchor for the block holds %x", rc, body.RootChainAnchor)}
	}
	return &TxPosition{Block: block, DNBlock: block, StateRoot: body.StateTreeAnchor, RootChain: body.RootChainAnchor}, nil
}
