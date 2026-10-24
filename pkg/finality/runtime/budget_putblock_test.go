// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-DBFIX D7: a captured block is stored WHOLE or not at all. The budget of the block is reserved for the planned total before the
// first row is written; a block that does not fit is refused with nothing stored, so the row that names the block as captured is
// never there without the rows it lists.

func inboxRows(block uint64, sizes ...int) []finality.CaptureRow {
	rows := []finality.CaptureRow{{CaptureKey: rtKey(block, 1, "inbox"), Bytes: []byte("lists-the-txs")}}
	for i, n := range sizes {
		rows = append(rows, finality.CaptureRow{CaptureKey: rtKey(block, 1, "tx/"+string(rune('a'+i))), Bytes: bytes.Repeat([]byte{byte(i + 1)}, n)})
	}
	return rows
}

func TestRTBudgetABlockThatCrossesTheBoundIsRefusedWholeAndNothingIsStored(t *testing.T) {
	s, mem, p := rtNewBudget(100)
	ctx := context.Background()
	rows := inboxRows(10, 40, 40, 40) // the inbox row (13 bytes) + 120: the crossing row would be the LAST one
	err := finality.PutBlock(ctx, s, rows)
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "capture.block" || st.Fields["count"] != uint64(133) || st.Fields["limit"] != uint64(100) {
		t.Fatalf("PutBlock: %v (fields %v), want finality_evidence_too_large capture.block 133/100", err, st)
	}
	listed, _ := mem.ListByBlock(ctx, 84532, 10)
	if len(listed) != 0 {
		t.Fatalf("a partial block was stored: %d rows (the inbox row would list transactions that are not there)", len(listed))
	}
	if len(p.refused) != 1 || len(p.puts) != 0 {
		t.Fatalf("refused %v, stored %v: want one refusal and no stored bytes", p.refused, p.puts)
	}
	// the refusal consumed no budget: a block that fits still goes in whole (13 + 40 + 40 = 93)
	if err := finality.PutBlock(ctx, s, inboxRows(10, 40, 40)); err != nil {
		t.Fatalf("a block that fits: %v", err)
	}
	if listed, _ := mem.ListByBlock(ctx, 84532, 10); len(listed) != 3 {
		t.Fatalf("%d rows stored, want 3", len(listed))
	}
	// and the block is now full: one more row is refused (93 + 8 > 100)
	if err := s.Put(ctx, rtKey(10, 1, "late"), make([]byte, 8)); err == nil {
		t.Fatal("a row over the remaining budget of a stored block was accepted")
	}
}

func TestRTBudgetPutBlockCountsAnIdenticalRowOnceAndAConflictStoresNoRowOfTheCall(t *testing.T) {
	s, mem, p := rtNewBudget(100)
	ctx := context.Background()
	if err := finality.PutBlock(ctx, s, inboxRows(10, 40)); err != nil {
		t.Fatal(err)
	}
	before := len(p.puts)
	// the same block again, identical: counts nothing and stores nothing new
	if err := finality.PutBlock(ctx, s, inboxRows(10, 40)); err != nil {
		t.Fatalf("an identical block: %v", err)
	}
	if len(p.puts) != before {
		t.Fatalf("an identical block was counted again: %v", p.puts)
	}
	// a call with one new row and one row whose key holds other bytes: the store refuses the call, so the new row is not stored either
	bad := []finality.CaptureRow{
		{CaptureKey: rtKey(10, 1, "tx/z"), Bytes: []byte("new")},
		{CaptureKey: rtKey(10, 1, "tx/a"), Bytes: bytes.Repeat([]byte{9}, 40)},
	}
	if err := finality.PutBlock(ctx, s, bad); !errors.Is(err, finality.ErrCaptureConflict) {
		t.Fatalf("error %v, want ErrCaptureConflict", err)
	}
	if _, found, _ := mem.Get(ctx, rtKey(10, 1, "tx/z")); found {
		t.Fatal("a row of a refused call was stored")
	}
	// the reservation of the refused call was given back: the budget still has 100 - 53 = 47 bytes
	if err := s.Put(ctx, rtKey(10, 1, "tx/y"), make([]byte, 47)); err != nil {
		t.Fatalf("the refused call kept its reservation: %v", err)
	}
}

func TestRTBudgetPutBlockOverSeveralBlocksIsAllOrNothing(t *testing.T) {
	s, mem, _ := rtNewBudget(100)
	ctx := context.Background()
	rows := append(inboxRows(10, 20), finality.CaptureRow{CaptureKey: rtKey(11, 1, "big"), Bytes: make([]byte, 101)})
	if err := finality.PutBlock(ctx, s, rows); err == nil {
		t.Fatal("a row over the bound was accepted")
	}
	for _, blk := range []uint64{10, 11} {
		if listed, _ := mem.ListByBlock(ctx, 84532, blk); len(listed) != 0 {
			t.Fatalf("block %d: %d rows stored by a refused call", blk, len(listed))
		}
	}
	two := append(inboxRows(10, 20), inboxRows(11, 90)...) // block 11 is 13 + 90 = 103: crosses
	if err := finality.PutBlock(ctx, s, two); err == nil {
		t.Fatal("a call with a crossing block was accepted")
	}
	for _, blk := range []uint64{10, 11} {
		if listed, _ := mem.ListByBlock(ctx, 84532, blk); len(listed) != 0 {
			t.Fatalf("block %d: %d rows stored although the other block of the call crossed", blk, len(listed))
		}
	}
}

// failAfter is an inner store without BlockPutter whose Put fails from the nth call on.
type failAfter struct {
	mem      *finality.MemCaptureStore
	n, calls int
}

func (f *failAfter) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	f.calls++
	if f.calls > f.n {
		return errors.New("disk full")
	}
	return f.mem.Put(ctx, k, b)
}
func (f *failAfter) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	return f.mem.Get(ctx, k)
}
func (f *failAfter) ListByBlock(ctx context.Context, c, b uint64) ([]finality.CaptureRow, error) {
	return f.mem.ListByBlock(ctx, c, b)
}
func (f *failAfter) ListByRange(ctx context.Context, c, from, to uint64, p string) ([]finality.CaptureKey, error) {
	return f.mem.ListByRange(ctx, c, from, to, p)
}

func TestRTBudgetAnIOFailureGivesBackTheReservationOfTheRowsNotWritten(t *testing.T) {
	ctx := context.Background()
	inner := &failAfter{mem: finality.NewMemCaptureStore(), n: 1}
	s := NewBudgetedStore(inner, 100)
	s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	if err := finality.PutBlock(ctx, s, inboxRows(10, 40, 40)); err == nil {
		t.Fatal("the store failure was swallowed")
	}
	// one row (13 bytes) was written before the failure; the 80 reserved for the rows that were not written are free again
	inner.n = 100
	if err := s.Put(ctx, rtKey(10, 1, "later"), make([]byte, 87)); err != nil {
		t.Fatalf("the failed call kept the reservation of rows it never wrote: %v", err)
	}
}
