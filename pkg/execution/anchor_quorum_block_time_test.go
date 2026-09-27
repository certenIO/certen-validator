package execution

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

type capturingQuorumStore struct {
	got []*database.AnchorQuorumRecord
}

func (s *capturingQuorumStore) RecordAnchorQuorum(_ context.Context, rec *database.AnchorQuorumRecord) (bool, error) {
	s.got = append(s.got, rec)
	return true, nil
}

// RB3-F133: the completion time stored is the verify block's, read from its chain; a block not yet readable
// is an error the writer retries and the outbox keeps - never another time, never a drop.
func TestTheCompletionTimeStoredIsTheVerifyBlocks(t *testing.T) {
	inner := &capturingQuorumStore{}
	blockTime := time.Date(2026, 9, 15, 11, 59, 58, 0, time.UTC)
	var asked [2]int64
	store := BlockTimedAnchorQuorumStore{Store: inner, BlockTime: func(_ context.Context, chainID int64, block uint64) (time.Time, error) {
		asked = [2]int64{chainID, int64(block)}
		return blockTime, nil
	}}
	rec := recordFixture()
	rec.VerifiedAt, rec.VerifyBlock = time.Time{}, 47002149
	if _, err := store.RecordAnchorQuorum(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if len(inner.got) != 1 || !inner.got[0].VerifiedAt.Equal(blockTime) || asked != [2]int64{rec.ChainID, rec.VerifyBlock} {
		t.Fatalf("stored %v after asking chain %d block %d", inner.got[0].VerifiedAt, asked[0], asked[1])
	}

	unread := &capturingQuorumStore{}
	store = BlockTimedAnchorQuorumStore{Store: unread, BlockTime: func(context.Context, int64, uint64) (time.Time, error) {
		return time.Time{}, errors.New("header not found")
	}}
	rec = recordFixture()
	rec.VerifiedAt, rec.VerifyBlock = time.Time{}, 47002149
	if _, err := store.RecordAnchorQuorum(context.Background(), rec); err == nil || len(unread.got) != 0 {
		t.Fatalf("a record whose verify block was not read was stored (%v)", err)
	}
}
