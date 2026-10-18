// Copyright 2026 Certen Protocol
//
// The Directory as a partition of the capture (docs/proof/G1_CROSS_PARTITION.md D2b and D2c; RB9 Phase C1b-2).
//
// A governing page on the Directory (D2b) is read at a Directory block B_Y chosen from the Directory's own anchors exactly as a block
// validator partition's is chosen from the anchors it sent (proofv2.SelectPartitionBlock over the anchor(directory)-root chain of
// the Directory's anchor pool and its anchor sequence): the smallest anchor-bearing block at or after every counted signature's
// arrival, none later than the Directory block that executed the transaction's partition's anchor. A principal on the Directory
// (D2c) keeps its block B and the DirectoryAnchor the Directory produced for it; the pages of the other partitions are read at the
// latest block whose anchor the Directory executed at or before B. Nothing here falls back: an anchor the Directory has not produced
// is the named state g1_partition_anchor_unavailable with the partition and block.

package proofv2shadow

import (
	"context"
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// PositionFor places a transaction in its own partition: through the Directory's record of a block validator partition's anchor
// (Builder.Position), or, for a principal on the Directory, through the Directory's own anchor for the block
// (Builder.DirectoryPosition). It is the Position a live Collector is wired with.
func PositionFor(ctx context.Context, b *proofv2.Builder, account, tx, label string) (*proofv2.TxPosition, error) {
	if isDirectory(strings.TrimSpace(label)) {
		return b.DirectoryPosition(ctx, account, tx)
	}
	return b.Position(ctx, account, tx, label)
}
