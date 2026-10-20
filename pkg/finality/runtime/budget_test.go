// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

type rtBudgetProbe struct {
	puts    []int
	refused []string
}

func rtNewBudget(limit int64) (*BudgetedStore, *finality.MemCaptureStore, *rtBudgetProbe) {
	mem := finality.NewMemCaptureStore()
	p := &rtBudgetProbe{}
	s := NewBudgetedStore(mem, limit)
	s.OnPut = func(chain uint64, n int) { p.puts = append(p.puts, n) }
	s.OnRefused = func(chain uint64, code string) { p.refused = append(p.refused, code) }
	return s, mem, p
}

func rtKey(block uint64, hash byte, item string) finality.CaptureKey {
	var h [32]byte
	h[0] = hash
	return finality.CaptureKey{Chain: 84532, L1Block: block, L1Hash: h, Item: item}
}

func TestRTBudgetRefusesARowOverTheBoundWithTheNamedStateAndStoresNothing(t *testing.T) {
	s, mem, p := rtNewBudget(100)
	ctx := context.Background()
	err := s.Put(ctx, rtKey(10, 1, "big"), make([]byte, 101))
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != finality.CodeEvidenceTooLarge {
		t.Fatalf("error %v, want the named state %s", err, finality.CodeEvidenceTooLarge)
	}
	if st.Fields["part"] != "capture.row:big" || st.Fields["count"] != uint64(101) || st.Fields["limit"] != uint64(100) {
		t.Fatalf("fields %v, want part capture.row:big count 101 limit 100", st.Fields)
	}
	if _, found, _ := mem.Get(ctx, rtKey(10, 1, "big")); found {
		t.Fatal("a refused row was stored")
	}
	if len(p.refused) != 1 || p.refused[0] != finality.CodeEvidenceTooLarge || len(p.puts) != 0 {
		t.Fatalf("refused hook %v, put hook %v: want one refusal, no stored bytes counted", p.refused, p.puts)
	}
	// exactly at the bound is accepted
	if err := s.Put(ctx, rtKey(11, 1, "edge"), make([]byte, 100)); err != nil {
		t.Fatalf("a row of exactly the bound was refused: %v", err)
	}
}

func TestRTBudgetRefusesTheSecondRowOfABlockThatSumsOverTheBoundAndKeepsTheFirst(t *testing.T) {
	s, mem, p := rtNewBudget(100)
	ctx := context.Background()
	a, b, c := bytes.Repeat([]byte{1}, 60), bytes.Repeat([]byte{2}, 60), bytes.Repeat([]byte{3}, 40)
	if err := s.Put(ctx, rtKey(10, 1, "a"), a); err != nil {
		t.Fatal(err)
	}
	err := s.Put(ctx, rtKey(10, 1, "b"), b)
	st, ok := finality.AsNamed(err)
	if !ok || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "capture.block" || st.Fields["count"] != uint64(120) || st.Fields["limit"] != uint64(100) {
		t.Fatalf("second row: %v (fields %v), want finality_evidence_too_large capture.block 120/100", err, st)
	}
	if _, found, _ := mem.Get(ctx, rtKey(10, 1, "b")); found {
		t.Fatal("the refusing row was written: a partial block must never be stored")
	}
	if got, found, _ := mem.Get(ctx, rtKey(10, 1, "a")); !found || !bytes.Equal(got, a) {
		t.Fatal("the first row of the block was lost")
	}
	// the refusal did not consume budget: a row that fits still does (60 + 40 = 100)
	if err := s.Put(ctx, rtKey(10, 1, "c"), c); err != nil {
		t.Fatalf("a row that fits the remaining budget was refused: %v", err)
	}
	// a different block, and the same height under another hash (a reorg), have their own budgets
	if err := s.Put(ctx, rtKey(11, 1, "b"), b); err != nil {
		t.Fatalf("another block: %v", err)
	}
	if err := s.Put(ctx, rtKey(10, 2, "b"), b); err != nil {
		t.Fatalf("the same height under another hash: %v", err)
	}
	if len(p.refused) != 1 || len(p.puts) != 4 {
		t.Fatalf("refused %v, put %v: want 1 refusal and 4 stored rows", p.refused, p.puts)
	}
}

func TestRTBudgetAnIdenticalRePutDoesNotDoubleCountAndAConflictDoesNotChangeTheAccount(t *testing.T) {
	s, mem, p := rtNewBudget(100)
	ctx := context.Background()
	a := bytes.Repeat([]byte{1}, 60)
	for i := 0; i < 3; i++ {
		if err := s.Put(ctx, rtKey(10, 1, "a"), a); err != nil {
			t.Fatalf("re-put %d of the same row: %v", i, err)
		}
	}
	if len(p.puts) != 1 {
		t.Fatalf("OnPut called %d times for one distinct row, want 1", len(p.puts))
	}
	// 3 x 60 would be 180 if re-puts double counted: a 40-byte row must still fit
	if err := s.Put(ctx, rtKey(10, 1, "b"), make([]byte, 40)); err != nil {
		t.Fatalf("an identical re-put consumed budget: %v", err)
	}
	// the same key with other bytes is the store's conflict, insert-only, and the account stays as it was
	err := s.Put(ctx, rtKey(10, 1, "a"), bytes.Repeat([]byte{9}, 60))
	if !errors.Is(err, finality.ErrCaptureConflict) {
		t.Fatalf("error %v, want ErrCaptureConflict", err)
	}
	if got, _, _ := mem.Get(ctx, rtKey(10, 1, "a")); !bytes.Equal(got, a) {
		t.Fatal("a conflicting put changed a stored row")
	}
	if err := s.Put(ctx, rtKey(10, 1, "c"), make([]byte, 1)); err == nil {
		t.Fatal("the block is exactly full (60 + 40): one more byte must be refused")
	}
}

func TestRTBudgetReadsPassThroughToTheInnerStore(t *testing.T) {
	s, mem, _ := rtNewBudget(1000)
	ctx := context.Background()
	for _, k := range []finality.CaptureKey{rtKey(10, 1, "x/a"), rtKey(10, 1, "x/b"), rtKey(12, 1, "y")} {
		if err := mem.Put(ctx, k, []byte(k.Item)); err != nil {
			t.Fatal(err)
		}
	}
	if b, ok, err := s.Get(ctx, rtKey(10, 1, "x/a")); err != nil || !ok || string(b) != "x/a" {
		t.Fatalf("Get: %q %v %v", b, ok, err)
	}
	rows, err := s.ListByBlock(ctx, 84532, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListByBlock: %d rows, %v", len(rows), err)
	}
	keys, err := s.ListByRange(ctx, 84532, 0, finality.MaxCaptureBlock, "x/")
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListByRange(prefix x/): %d keys, %v", len(keys), err)
	}
	keys, err = s.ListByRange(ctx, 84532, 11, 20, "")
	if err != nil || len(keys) != 1 || keys[0].L1Block != 12 {
		t.Fatalf("ListByRange(11..20): %v %v", keys, err)
	}
}

func TestRTBudgetTheAccountingIsBoundedAndEvictionDoesNotPanic(t *testing.T) {
	s, _, p := rtNewBudget(100)
	ctx := context.Background()
	n := maxBudgetGroups + 50
	for i := 0; i < n; i++ {
		if err := s.Put(ctx, rtKey(uint64(i), 1, "r"), []byte{1}); err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
	}
	if s.lru.Len() > maxBudgetGroups || len(s.groups) > maxBudgetGroups {
		t.Fatalf("accounting holds %d/%d groups, bound %d", s.lru.Len(), len(s.groups), maxBudgetGroups)
	}
	if len(p.puts) != n {
		t.Fatalf("%d stored rows counted, want %d", len(p.puts), n)
	}
	// the oldest group was evicted: its account starts again (the durable store's insert-only key is the bound that survives)
	if err := s.Put(ctx, rtKey(0, 1, "s"), make([]byte, 99)); err != nil {
		t.Fatalf("an evicted block's account restarts: %v", err)
	}
}

func TestRTBudgetZeroBoundTakesTheSpecDefault(t *testing.T) {
	s, _, _ := rtNewBudget(0)
	ctx := context.Background()
	if err := s.Put(ctx, rtKey(1, 1, "a"), make([]byte, DefaultMaxCaptureBytesPerLeg)); err != nil {
		t.Fatalf("a row of exactly 4 MiB: %v", err)
	}
	if err := s.Put(ctx, rtKey(2, 1, "a"), make([]byte, DefaultMaxCaptureBytesPerLeg+1)); err == nil {
		t.Fatal("a row over 4 MiB was accepted")
	}
}
