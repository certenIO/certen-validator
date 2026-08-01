package execution

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Two validators hold the same intents but received them in different orders, at different
// local times. They MUST select the same members for a period, or their trees differ, their
// bundleIds differ, and no quorum can ever form over one batch. This is the exact failure
// observed live on 2026-08-01 (v2 formed 0xe4c950df…, v3 formed 0x5e71d83a…).
func TestPeekForPeriod_IsIdenticalAcrossValidators(t *testing.T) {
	mk := func(id string, height uint64, enqueued time.Time) *PendingBatchIntent {
		return &PendingBatchIntent{
			IntentID:     id,
			ADIURL:       "acc://" + id + ".acme",
			ChainID:      11155111,
			Account:      common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"),
			OperationID:  opid(byte(len(id))),
			Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
			CommitHeight: height,
			EnqueuedAt:   enqueued,
		}
	}

	now := time.Now()
	// Validator A: arrives c, a, b — and with wall-clock times in that order.
	a := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	for _, p := range []*PendingBatchIntent{
		mk("c", 100, now), mk("a", 100, now.Add(time.Second)), mk("b", 90, now.Add(2*time.Second)),
	} {
		if err := a.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	// Validator B: same intents, reverse arrival, different clock entirely.
	b := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	for _, p := range []*PendingBatchIntent{
		mk("b", 90, now.Add(-time.Hour)), mk("a", 100, now.Add(-time.Minute)), mk("c", 100, now),
	} {
		if err := b.Add(p); err != nil {
			t.Fatal(err)
		}
	}

	ga := a.PeekForPeriod(11155111, 100)
	gb := b.PeekForPeriod(11155111, 100)

	if len(ga) != 3 || len(gb) != 3 {
		t.Fatalf("expected 3 members each, got %d and %d", len(ga), len(gb))
	}
	for i := range ga {
		if ga[i].IntentID != gb[i].IntentID {
			t.Fatalf("position %d differs: %q vs %q — trees would diverge",
				i, ga[i].IntentID, gb[i].IntentID)
		}
	}
	// Ordering is (CommitHeight, IntentID) — so b(90) first, then a(100), then c(100).
	if ga[0].IntentID != "b" || ga[1].IntentID != "a" || ga[2].IntentID != "c" {
		t.Fatalf("unexpected order: %s %s %s", ga[0].IntentID, ga[1].IntentID, ga[2].IntentID)
	}
}

// Members committed after the cutoff belong to the NEXT period. Including them would make a
// validator that has not yet seen them compute a different root.
func TestPeekForPeriod_ExcludesAboveCutoff(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	add := func(id string, h uint64) {
		if err := m.Add(&PendingBatchIntent{
			IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: 11155111,
			Account: common.HexToAddress("0x01"), OperationID: opid(1),
			Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
			CommitHeight: h,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("early", 50)
	add("onCutoff", 100)
	add("late", 101)

	got := m.PeekForPeriod(11155111, 100)
	if len(got) != 2 {
		t.Fatalf("expected 2 (<= cutoff), got %d", len(got))
	}
	for _, p := range got {
		if p.IntentID == "late" {
			t.Fatal("a member committed above the cutoff must not be in this period")
		}
	}
}

// A member with no commit height cannot be placed deterministically — a validator that has it
// would diverge from one that does not. It must be skipped, not guessed at.
func TestPeekForPeriod_SkipsUnknownCommitHeight(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	if err := m.Add(&PendingBatchIntent{
		IntentID: "noheight", ADIURL: "acc://x.acme", ChainID: 11155111,
		Account: common.HexToAddress("0x01"), OperationID: opid(1),
		Legs: []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
		// CommitHeight deliberately zero
	}); err != nil {
		t.Fatal(err)
	}
	if got := m.PeekForPeriod(11155111, 1000); len(got) != 0 {
		t.Fatal("a member with no commit height must be skipped")
	}
}

// Peek must not consume: an attester needs its copy back if the proposer never lands the batch.
func TestPeekForPeriod_DoesNotConsume(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	if err := m.Add(&PendingBatchIntent{
		IntentID: "x", ADIURL: "acc://x.acme", ChainID: 11155111,
		Account: common.HexToAddress("0x01"), OperationID: opid(1),
		Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
		CommitHeight: 10,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if len(m.PeekForPeriod(11155111, 100)) != 1 {
			t.Fatalf("peek %d lost the member", i)
		}
	}
	if m.PendingCount() != 1 {
		t.Fatal("peek must leave the pool intact")
	}
	if len(m.TakeForPeriod(11155111, 100)) != 1 {
		t.Fatal("take should return the member")
	}
	if m.PendingCount() != 0 {
		t.Fatal("take must consume")
	}
}

// The cap must be applied AFTER sorting, or two validators holding the same members could
// truncate to different subsets and diverge.
func TestPeekForPeriod_CapAppliedAfterSort(t *testing.T) {
	mkPool := func(order []string) *BatchMempool {
		m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 2})
		for i, id := range order {
			if err := m.Add(&PendingBatchIntent{
				IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: 11155111,
				Account: common.HexToAddress("0x01"), OperationID: opid(byte(i + 1)),
				Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
				CommitHeight: 10,
			}); err != nil {
				t.Fatal(err)
			}
		}
		return m
	}
	g1 := mkPool([]string{"aaa", "bbb", "ccc"}).PeekForPeriod(11155111, 100)
	g2 := mkPool([]string{"ccc", "bbb", "aaa"}).PeekForPeriod(11155111, 100)

	if len(g1) != 2 || len(g2) != 2 {
		t.Fatalf("cap not applied: %d %d", len(g1), len(g2))
	}
	if g1[0].IntentID != g2[0].IntentID || g1[1].IntentID != g2[1].IntentID {
		t.Fatal("truncation must pick the same subset regardless of arrival order")
	}
	if g1[0].IntentID != "aaa" || g1[1].IntentID != "bbb" {
		t.Fatalf("expected the lowest two by ID, got %s %s", g1[0].IntentID, g1[1].IntentID)
	}
}

func TestBatchPeriodCutoff(t *testing.T) {
	cases := []struct{ h, period, want uint64 }{
		{100, 10, 100},
		{105, 10, 100},
		{109, 10, 100},
		{110, 10, 110},
		{7, 0, 7}, // zero period must not divide by zero
	}
	for _, c := range cases {
		if got := BatchPeriodCutoff(c.h, c.period); got != c.want {
			t.Fatalf("cutoff(%d, %d) = %d, want %d", c.h, c.period, got, c.want)
		}
	}
}

func TestDropMembers(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	var all []*PendingBatchIntent
	for _, id := range []string{"a", "b", "c"} {
		p := &PendingBatchIntent{
			IntentID: id, ADIURL: "acc://" + id + ".acme", ChainID: 11155111,
			Account: common.HexToAddress("0x01"), OperationID: opid(1),
			Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
			CommitHeight: 10,
		}
		if err := m.Add(p); err != nil {
			t.Fatal(err)
		}
		all = append(all, p)
	}
	m.DropMembers(all[:2])
	if m.PendingCount() != 1 {
		t.Fatalf("expected 1 remaining, got %d", m.PendingCount())
	}
	// Dropped members must be re-addable — fallback does not permanently blacklist them.
	if err := m.Add(all[0]); err != nil {
		t.Fatalf("a dropped member must be re-addable: %v", err)
	}
}
