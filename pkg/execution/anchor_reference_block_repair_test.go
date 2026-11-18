package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

type fakeAnchorRefStore struct {
	rows   []database.AnchorReferenceBlockRow
	filled map[uuid.UUID][2]string
	fills  int
}

func (s *fakeAnchorRefStore) ListAnchorReferencesMissingBlock(_ context.Context, since time.Time) ([]database.AnchorReferenceBlockRow, error) {
	var out []database.AnchorReferenceBlockRow
	for _, r := range s.rows {
		if _, done := s.filled[r.ProofID]; !done && !r.CreatedAt.Before(since) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *fakeAnchorRefStore) FillAnchorReferenceBlock(_ context.Context, row database.AnchorReferenceBlockRow, hash string, ts time.Time) (bool, error) {
	s.fills++
	if _, done := s.filled[row.ProofID]; done {
		return false, nil
	}
	s.filled[row.ProofID] = [2]string{hash, ts.UTC().Format(time.RFC3339)}
	return true, nil
}

type fakeAnchorTxReader struct{ byTx map[string]*AnchorTxReading }

func (r *fakeAnchorTxReader) ReadAnchorTx(_ context.Context, _ int64, tx string) (*AnchorTxReading, error) {
	if x, ok := r.byTx[strings.ToLower(tx)]; ok {
		return x, nil
	}
	return nil, errors.New("not found")
}

func (r *fakeAnchorTxReader) LocateAnchorCreate(context.Context, int64, string, [32]byte, [32]byte, uint64) (*AnchorCreateLocation, error) {
	return nil, errors.New("not used")
}

func anchorRefRepairFixture() (*fakeAnchorRefStore, *fakeAnchorTxReader, uuid.UUID, uuid.UUID, uuid.UUID) {
	good, bad, old := uuid.New(), uuid.New(), uuid.New()
	mismatchTx := "0x" + strings.Repeat("11", 32)
	at := time.Date(2026, 11, 18, 11, 31, 0, 0, time.UTC)
	store := &fakeAnchorRefStore{filled: map[uuid.UUID][2]string{}, rows: []database.AnchorReferenceBlockRow{
		{ProofID: good, ChainID: "84532", AnchorTxHash: scene1AnchorTx, AnchorBlockNumber: scene1AnchorBlock, CreatedAt: at},
		{ProofID: bad, ChainID: "84532", AnchorTxHash: mismatchTx, AnchorBlockNumber: 100, CreatedAt: at},
		{ProofID: old, ChainID: "84532", AnchorTxHash: scene1AnchorTx, AnchorBlockNumber: scene1AnchorBlock, CreatedAt: AnchorBlockFieldsSince.Add(-time.Hour)},
	}}
	reader := &fakeAnchorTxReader{byTx: map[string]*AnchorTxReading{
		scene1AnchorTx: {Found: true, Succeeded: true, BlockNumber: scene1AnchorBlock, BlockHash: scene1AnchorHash, BlockTime: uint64(scene1AnchorTime.Unix())},
		mismatchTx:     {Found: true, Succeeded: true, BlockNumber: 101, BlockHash: "0x" + strings.Repeat("22", 32), BlockTime: 1_790_000_000},
	}}
	return store, reader, good, bad, old
}

// The repair fills from the chain, refuses a mismatched block by name, is idempotent, and its dry run only counts.
func TestRepairAnchorBlockFields(t *testing.T) {
	store, reader, good, bad, old := anchorRefRepairFixture()
	ctx := context.Background()

	dry, err := RepairAnchorBlockFields(ctx, store, reader, AnchorBlockFieldsSince, false, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Rows != 2 || dry.WouldFill != 1 || dry.Refused != 1 || store.fills != 0 {
		t.Fatalf("dry run: %+v, fills %d", dry, store.fills)
	}

	rep, err := RepairAnchorBlockFields(ctx, store, reader, AnchorBlockFieldsSince, true, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Filled != 1 || rep.Refused != 1 || len(rep.RefusedIDs) != 1 || rep.RefusedIDs[0] != bad.String() {
		t.Fatalf("apply: %+v", rep)
	}
	if got := store.filled[good]; got[0] != scene1AnchorHash || got[1] != "2026-11-18T11:30:20Z" {
		t.Fatalf("filled %v", got)
	}
	if _, touched := store.filled[bad]; touched {
		t.Fatal("a mismatched row was written")
	}
	if _, touched := store.filled[old]; touched {
		t.Fatal("a row before the defect window was written")
	}

	again, err := RepairAnchorBlockFields(ctx, store, reader, AnchorBlockFieldsSince, true, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if again.Filled != 0 || again.Rows != 1 || again.Refused != 1 {
		t.Fatalf("second run is not idempotent: %+v", again)
	}
}
