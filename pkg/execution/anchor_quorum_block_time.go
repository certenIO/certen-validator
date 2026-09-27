// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// BlockTimedAnchorQuorumStore fills a record's completion time from its chain before storing it.
//
// consensus_completed_at is the time the quorum was confirmed on-chain: the verify block's timestamp. The
// live writer stored this validator's clock after it had confirmed the anchor - 1 to 4 seconds late on all
// 50 live rows checked on 2026-09-27 (RB3-F133) - and the backfill stored the anchor's creation time when it
// could not read the block (RB3-F131). A record without the time is completed here from the chain; a
// block that cannot be read yet is an error, so the writer retries and the outbox keeps the record - it is
// never stored with another time, and never dropped.
type BlockTimedAnchorQuorumStore struct {
	Store     AnchorQuorumStore
	BlockTime func(ctx context.Context, chainID int64, block uint64) (time.Time, error)
}

// RecordAnchorQuorum implements AnchorQuorumStore.
func (s BlockTimedAnchorQuorumStore) RecordAnchorQuorum(ctx context.Context, rec *database.AnchorQuorumRecord) (bool, error) {
	if rec != nil && rec.VerifiedAt.IsZero() {
		if rec.VerifyBlock <= 0 {
			return false, fmt.Errorf("anchor %s: no verify block to take its completion time from", rec.BundleID)
		}
		if s.BlockTime == nil {
			return false, fmt.Errorf("anchor %s: no chain to read verify block %d's time from", rec.BundleID, rec.VerifyBlock)
		}
		t, err := s.BlockTime(ctx, rec.ChainID, uint64(rec.VerifyBlock))
		if err != nil {
			return false, fmt.Errorf("anchor %s: verify block %d's time is not read yet; kept for retry: %w", rec.BundleID, rec.VerifyBlock, err)
		}
		if t.IsZero() {
			return false, fmt.Errorf("anchor %s: verify block %d has no time", rec.BundleID, rec.VerifyBlock)
		}
		rec.VerifiedAt = t
	}
	return s.Store.RecordAnchorQuorum(ctx, rec)
}
