package ledger

import (
	"errors"
	"testing"
	"time"
)

type mapKV map[string][]byte

func (m mapKV) Get(k []byte) ([]byte, error) { return m[string(k)], nil }
func (m mapKV) Set(k, v []byte) error        { m[string(k)] = append([]byte(nil), v...); return nil }

func entry(v, op string, h int64, bundle string) CommittedOperationEntry {
	return CommittedOperationEntry{ValidatorID: v, OperationID: op,
		Committed: CommittedOperation{Height: h, BundleID: bundle, TxHash: "AB", BlockTime: time.Unix(h, 0).UTC()}}
}

// RB3-F141: the index keeps each operation's first commit, covers heights contiguously, treats a height it
// already covers as a replay, and refuses to skip one.
func TestTheCommittedOperationIndexKeepsTheFirstCommitAndNeverSkipsAHeight(t *testing.T) {
	s := NewLedgerStore(mapKV{})
	if err := s.RecordCommittedBlock(1, []CommittedOperationEntry{entry("v1", "op", 1, "b1")}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCommittedBlock(2, []CommittedOperationEntry{entry("v1", "op", 2, "b2"), entry("v2", "op", 2, "b3")}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetCommittedOperation("v1", "op"); got == nil || got.Height != 1 || got.BundleID != "b1" {
		t.Fatalf("first commit replaced: %+v", got)
	}
	if got, _ := s.GetCommittedOperation("v2", "op"); got == nil || got.Height != 2 {
		t.Fatalf("another validator's block for the operation: %+v", got)
	}
	if got, _ := s.GetCommittedOperation("v3", "op"); got != nil {
		t.Fatalf("a block that never committed: %+v", got)
	}
	if err := s.RecordCommittedBlock(2, nil); err != nil {
		t.Fatalf("a replayed height: %v", err)
	}
	if upTo, _ := s.CommittedOperationsUpTo(); upTo != 2 {
		t.Fatalf("covers %d, want 2", upTo)
	}
	if err := s.RecordCommittedBlock(4, nil); !errors.Is(err, ErrCommittedOperationsGap) {
		t.Fatalf("height 4 recorded over a missing 3: %v", err)
	}
	if _, err := s.GetCommittedOperation("", "op"); err == nil {
		t.Fatal("an operation named by no validator")
	}
}

func TestTheIndexStartsWhereTheChainStarts(t *testing.T) {
	s := NewLedgerStore(mapKV{})
	if err := s.StartCommittedOperations(100); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCommittedBlock(100, nil); err != nil {
		t.Fatalf("the chain's first block: %v", err)
	}
	if err := s.StartCommittedOperations(500); err != nil {
		t.Fatal(err)
	}
	if upTo, _ := s.CommittedOperationsUpTo(); upTo != 100 {
		t.Fatalf("a covering index was moved: %d", upTo)
	}
}

func TestTheFirstVerdictIsNeverMovedLater(t *testing.T) {
	s := NewLedgerStore(mapKV{})
	for _, h := range []int64{50, 70, 40} {
		if err := s.SaveRulesFirstVerdict(9, h); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.RulesFirstVerdict(9); got != 40 {
		t.Fatalf("first v9 verdict %d, want 40", got)
	}
	if got, _ := s.RulesFirstVerdict(8); got != 0 {
		t.Fatalf("v8 has none, got %d", got)
	}
}
