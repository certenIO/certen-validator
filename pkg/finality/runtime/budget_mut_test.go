// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// Mutation-gate killers of the BudgetedStore (RB12-DBFIX): what the accounting reads, in what order, and what it counts once.

// sizerStore is an inner store that has BlockSizes: the budget must read sizes from it and never list the bytes of a block.
type sizerStore struct {
	mem       *finality.MemCaptureStore
	sizeCalls []string
	listCalls int
	sizesErr  error
}

func (s *sizerStore) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	return s.mem.Put(ctx, k, b)
}
func (s *sizerStore) PutBlock(ctx context.Context, rows []finality.CaptureRow) error {
	return s.mem.PutBlock(ctx, rows)
}
func (s *sizerStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	return s.mem.Get(ctx, k)
}
func (s *sizerStore) ListByBlock(ctx context.Context, c, b uint64) ([]finality.CaptureRow, error) {
	s.listCalls++
	return s.mem.ListByBlock(ctx, c, b)
}
func (s *sizerStore) ListByRange(ctx context.Context, c, from, to uint64, p string) ([]finality.CaptureKey, error) {
	return s.mem.ListByRange(ctx, c, from, to, p)
}
func (s *sizerStore) BlockSizes(ctx context.Context, c, b uint64, h [32]byte) (map[string]int64, error) {
	s.sizeCalls = append(s.sizeCalls, fmt.Sprintf("%d/%d/%x", c, b, h[0]))
	if s.sizesErr != nil {
		return nil, s.sizesErr
	}
	return s.mem.BlockSizes(ctx, c, b, h)
}

func rowOf(chain, block uint64, hash byte, item string, n int) finality.CaptureRow {
	var h [32]byte
	h[0] = hash
	return finality.CaptureRow{CaptureKey: finality.CaptureKey{Chain: chain, L1Block: block, L1Hash: h, Item: item}, Bytes: make([]byte, n)}
}

func TestRTBudgetReadsTheSizesOfExactlyTheBlocksOfTheCallInAscendingChainBlockHashOrderAndNeverListsBytes(t *testing.T) {
	inner := &sizerStore{mem: finality.NewMemCaptureStore()}
	s := NewBudgetedStore(inner, 100)
	s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	rows := []finality.CaptureRow{
		rowOf(84532, 20, 2, "a", 1), rowOf(84532, 20, 1, "a", 1), rowOf(11155111, 30, 9, "a", 1), rowOf(84532, 10, 5, "a", 1),
		rowOf(11155111, 5, 3, "a", 1), rowOf(84532, 50, 1, "a", 1), // the chain order and the block order disagree here
		rowOf(84532, 20, 1, "b", 1), // a second row of an already listed block adds no read
	}
	if err := s.PutBlock(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	// ascending by chain first (84532 < 11155111), then block, then hash
	want := []string{"84532/10/5", "84532/20/1", "84532/20/2", "84532/50/1", "11155111/5/3", "11155111/30/9"}
	if fmt.Sprint(inner.sizeCalls) != fmt.Sprint(want) {
		t.Fatalf("sizes read in the order %v, want %v", inner.sizeCalls, want)
	}
	if inner.listCalls != 0 {
		t.Fatalf("%d block listings: a store that reports sizes must not be asked for the bytes", inner.listCalls)
	}
}

func TestRTBudgetAStoreThatCannotReportABlocksSizesRefusesTheWholeCallAndStoresNothing(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("sizes unavailable")
	inner := &sizerStore{mem: finality.NewMemCaptureStore(), sizesErr: boom}
	s := NewBudgetedStore(inner, 100)
	if err := s.PutBlock(ctx, []finality.CaptureRow{rowOf(84532, 1, 1, "a", 1)}); !errors.Is(err, boom) {
		t.Fatalf("error %v, want the store's", err)
	}
	if n := inner.mem.Len(); n != 0 {
		t.Fatalf("%d rows stored although the accounting could not be read", n)
	}
	// a store with no BlockSizes whose listing fails is the same refusal
	lister := &failAfter{mem: finality.NewMemCaptureStore(), n: 100}
	broken := &listFails{failAfter: lister, err: boom}
	s2 := NewBudgetedStore(broken, 100)
	if err := s2.PutBlock(ctx, []finality.CaptureRow{rowOf(84532, 1, 1, "a", 1)}); !errors.Is(err, boom) {
		t.Fatalf("error %v, want the listing's", err)
	}
	if lister.calls != 0 {
		t.Fatalf("%d Puts reached a store whose block could not be listed", lister.calls)
	}
}

type listFails struct {
	*failAfter
	err error
}

func (l *listFails) ListByBlock(context.Context, uint64, uint64) ([]finality.CaptureRow, error) {
	return nil, l.err
}

func TestRTBudgetACallCountsARowThatItListsTwiceOnce(t *testing.T) {
	s, mem, _ := rtNewBudget(100)
	ctx := context.Background()
	// 60 + 60 listed twice is 60, not 120: the same key with the same bytes is one row
	r := rowOf(84532, 1, 1, "same", 60)
	if err := s.PutBlock(ctx, []finality.CaptureRow{r, r}); err != nil {
		t.Fatalf("one row listed twice: %v", err)
	}
	if rows, _ := mem.ListByBlock(ctx, 84532, 1); len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
}

func TestRTBudgetABoundOfOneByteIsOneByteNotTheDefault(t *testing.T) {
	s, _, _ := rtNewBudget(1)
	ctx := context.Background()
	if err := s.Put(ctx, rtKey(1, 1, "a"), []byte{1}); err != nil {
		t.Fatalf("a row of exactly the bound: %v", err)
	}
	if err := s.Put(ctx, rtKey(2, 1, "a"), []byte{1, 2}); err == nil {
		t.Fatal("two bytes were accepted under a bound of one")
	}
}

// a store with no PutBlock, whose first Put fails and later ones succeed: the budget stops at the first failure and reports it
type firstFails struct {
	mem   *finality.MemCaptureStore
	calls int
}

func (f *firstFails) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	f.calls++
	if f.calls == 1 {
		return errors.New("disk hiccup")
	}
	return f.mem.Put(ctx, k, b)
}
func (f *firstFails) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	return f.mem.Get(ctx, k)
}
func (f *firstFails) ListByBlock(ctx context.Context, c, b uint64) ([]finality.CaptureRow, error) {
	return f.mem.ListByBlock(ctx, c, b)
}
func (f *firstFails) ListByRange(ctx context.Context, c, from, to uint64, p string) ([]finality.CaptureKey, error) {
	return f.mem.ListByRange(ctx, c, from, to, p)
}

func TestRTBudgetARowByRowStoreStopsAtTheFirstFailureAndReportsIt(t *testing.T) {
	inner := &firstFails{mem: finality.NewMemCaptureStore()}
	s := NewBudgetedStore(inner, 100)
	s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	err := s.PutBlock(context.Background(), []finality.CaptureRow{rowOf(84532, 1, 1, "a", 1), rowOf(84532, 1, 1, "b", 1), rowOf(84532, 1, 1, "c", 1)})
	if err == nil || inner.calls != 1 {
		t.Fatalf("error %v after %d Puts: want the first failure reported and no row attempted after it", err, inner.calls)
	}
}
