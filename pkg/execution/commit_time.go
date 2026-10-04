// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// A member's commit time (RB5-F57, part 2).
//
// Since a v4 leaf binds notBefore = the member's commit time, every validator must compute the same commit time for a
// member or they form different leaves, roots and bundle ids, and no v4 batch reaches quorum. It is therefore defined
// ONCE: the consensus time of the member's COMMIT BLOCK - the BVN minor block its intent was written in
// (PendingBatchIntent.ExecPartition/ExecBlock) - which every validator reads alike.
//
//   - Admission takes it from discovery, which read exactly that block's record (CertenIntent.BlockTime, ProofPartition,
//     ProofBlockIndex; LiteClientAdapter.SearchCertenTransactions).
//   - Any path that finds it missing - the on-demand lane, the cadence lane, a co-signing peer - reads it with
//     ResolveCommitTime from the same block.
//   - The backfill reads it with ResolveCommitTime from the block its chain entry's receipt names
//     (AccumulateIntentSource.SignedIntent).
//
// The Directory block that anchored the intent (CommitPartition/CommitHeight, the member's period) is later, and its
// time is never a member's commit time: the on-demand resolver used to read it, so a member whose time was resolved
// there had another notBefore than its peers.

// ErrNoCommitBlock: the member does not name its commit block, so its commit time cannot be read.
var ErrNoCommitBlock = errors.New("the member names no commit block")

// ResolveCommitTime is the consensus time of a commit block - partition, a BVN's URL, and block, its index - read
// through read (LiteClientAdapter.MinorBlockTime). The one way a member's commit time is read from the chain.
func ResolveCommitTime(ctx context.Context, read CommitTimeResolver, partition string, block uint64) (time.Time, error) {
	if partition == "" || block == 0 {
		return time.Time{}, fmt.Errorf("%w (partition %q, block %d)", ErrNoCommitBlock, partition, block)
	}
	if accumulate.BVNNameOf(partition) == "" {
		return time.Time{}, fmt.Errorf("commit block %d is on %s, which is no BVN: a commit block is the BVN block the intent "+
			"was written in", block, partition)
	}
	if read == nil {
		return time.Time{}, fmt.Errorf("no minor block reader to read commit block %d on %s with", block, partition)
	}
	t, err := read(ctx, partition, block)
	if err != nil {
		return time.Time{}, err
	}
	if t.IsZero() {
		return time.Time{}, fmt.Errorf("commit block %d on %s has no time", block, partition)
	}
	return t.UTC(), nil
}

// executionBlockStater is the round's snapshot as admission reads the intent's commit block (consensus.PendingAttestation).
type executionBlockStater interface {
	ExecutionBlock() (partition string, index int64)
}

// commitBlockOf is the commit block the round's snapshot states: the BVN's partition URL and the block index.
func commitBlockOf(attestation interface{}) (string, uint64) {
	s, ok := attestation.(executionBlockStater)
	if !ok || attestation == nil {
		return "", 0
	}
	name, index := s.ExecutionBlock()
	if url := accumulate.BVNPartitionURL(name); url != "" && index > 0 {
		return url, uint64(index)
	}
	return "", 0
}

// commitTimeTarget is where a resolved commit time is recorded: the queued member, persisted.
type commitTimeTarget interface {
	SetCommitTime(chainID int64, opID [32]byte, t time.Time) bool
}

// ensureCommitTimes reads, with ResolveCommitTime, the commit time of every member that lacks it and names its commit
// block, records it on the member and in the mempool, and returns the members still without one. Used by both lanes
// and by co-signing peers before any leaf is formed, so a member on a v4 chain is never held for a commit time that
// can be read, and never given one from anything but its commit block.
func ensureCommitTimes(ctx context.Context, read CommitTimeResolver, target commitTimeTarget, members []*PendingBatchIntent,
	logf func(string, ...interface{})) []*PendingBatchIntent {
	var missing []*PendingBatchIntent
	for _, p := range members {
		if p == nil || !p.CommitTime.IsZero() {
			continue
		}
		t, err := ResolveCommitTime(ctx, read, p.ExecPartition, p.ExecBlock)
		if err != nil {
			if logf != nil {
				logf("[COMMIT-TIME] intent %s on chain %d: %v", p.IntentID, p.ChainID, err)
			}
			missing = append(missing, p)
			continue
		}
		if target == nil || !target.SetCommitTime(p.ChainID, p.OperationID, t) {
			p.CommitTime = t
		}
	}
	return missing
}
