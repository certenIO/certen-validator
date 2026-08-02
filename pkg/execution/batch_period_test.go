package execution

import (
	"fmt"
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

	ga := a.PeekForPeriod(11155111, 50, 100)
	gb := b.PeekForPeriod(11155111, 50, 100)

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

// A member belongs to EXACTLY ONE period: the half-open window [start, start+width).
//
// The rule used to be the open-ended "CommitHeight <= cutoff", which was correct only while
// every validator removed taken members in lockstep. Attesters deliberately do not remove, so
// after the first batch an attester still held the previous period's members and folded them
// into the next period's tree — different root, different bundleId, permanent refusal.
func TestPeekForPeriod_SelectsExactlyOneWindow(t *testing.T) {
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
	add("previousPeriod", 99) // below the window — belongs to [90,100)
	add("windowStart", 100)   // inclusive lower bound
	add("windowEnd", 109)     // last height inside [100,110)
	add("nextPeriod", 110)    // exclusive upper bound

	got := m.PeekForPeriod(11155111, 100, 10)
	if len(got) != 2 {
		ids := make([]string, len(got))
		for i, p := range got {
			ids[i] = p.IntentID
		}
		t.Fatalf("expected exactly the 2 members of [100,110), got %d: %v", len(got), ids)
	}
	for _, p := range got {
		if p.IntentID == "previousPeriod" {
			t.Fatal("a member from an EARLIER period leaked in — this is the bug that made every " +
				"batch after the first fail quorum")
		}
		if p.IntentID == "nextPeriod" {
			t.Fatal("a member committed at the exclusive upper bound must belong to the next period")
		}
	}
}

// Selecting the same period twice must give the same answer even after a neighbouring period
// was taken. Bucket scoping is what makes an attester's Peek reproducible against a leader's
// Take, no matter what either removed.
func TestPeekForPeriod_IsUnaffectedByNeighbouringPeriods(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	for _, c := range []struct {
		id string
		h  uint64
	}{{"p1a", 100}, {"p1b", 105}, {"p2a", 110}, {"p2b", 115}} {
		if err := m.Add(&PendingBatchIntent{
			IntentID: c.id, ADIURL: "acc://" + c.id + ".acme", ChainID: 11155111,
			Account: common.HexToAddress("0x01"), OperationID: opid(1),
			Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
			CommitHeight: c.h,
		}); err != nil {
			t.Fatal(err)
		}
	}
	before := m.PeekForPeriod(11155111, 110, 10)
	if len(before) != 2 {
		t.Fatalf("period [110,120) should hold 2, got %d", len(before))
	}
	// A leader takes the EARLIER period. The later one must be untouched.
	if taken := m.TakeForPeriod(11155111, 100, 10); len(taken) != 2 {
		t.Fatalf("period [100,110) should hold 2, got %d", len(taken))
	}
	after := m.PeekForPeriod(11155111, 110, 10)
	if len(after) != len(before) || after[0].IntentID != before[0].IntentID {
		t.Fatal("taking one period changed another period's membership")
	}
}

// PendingPeriods drives the flush loop. It must report every CLOSED period holding members, so
// a straggler whose leader was down is picked up by a later one rather than stranded.
func TestPendingPeriods_ReportsClosedPeriodsOnly(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	for _, h := range []uint64{100, 105, 130, 200} {
		if err := m.Add(&PendingBatchIntent{
			IntentID: fmt.Sprintf("i%d", h), ADIURL: "acc://x.acme", ChainID: 11155111,
			Account: common.HexToAddress("0x01"), OperationID: opid(1),
			Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
			CommitHeight: h,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Current period starts at 200, so 200 is still open and must NOT be offered.
	got := m.PendingPeriods(11155111, 10, 200)
	want := []uint64{100, 130}
	if len(got) != len(want) {
		t.Fatalf("expected periods %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected periods %v (ascending), got %v", want, got)
		}
	}
}

// The memory backstop must not touch members whose period is still within the horizon.
func TestPruneOlderThan(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MinBatchSize: 1, MaxBatchSize: 64})
	for _, h := range []uint64{10, 500, 900} {
		if err := m.Add(&PendingBatchIntent{
			IntentID: fmt.Sprintf("i%d", h), ADIURL: "acc://x.acme", ChainID: 11155111,
			Account: common.HexToAddress("0x01"), OperationID: opid(1),
			Legs:         []LegExecution{{LegID: "l", ChainID: 11155111, Target: tgt(1), Value: big.NewInt(1)}},
			CommitHeight: h,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n := m.PruneOlderThan(500); n != 1 {
		t.Fatalf("pruned %d, expected exactly the one below the horizon", n)
	}
	if m.PendingCount() != 2 {
		t.Fatalf("expected 2 remaining, got %d", m.PendingCount())
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
	if got := m.PeekForPeriod(11155111, 1000, 100); len(got) != 0 {
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
		if len(m.PeekForPeriod(11155111, 10, 100)) != 1 {
			t.Fatalf("peek %d lost the member", i)
		}
	}
	if m.PendingCount() != 1 {
		t.Fatal("peek must leave the pool intact")
	}
	if len(m.TakeForPeriod(11155111, 10, 100)) != 1 {
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
	g1 := mkPool([]string{"aaa", "bbb", "ccc"}).PeekForPeriod(11155111, 10, 100)
	g2 := mkPool([]string{"ccc", "bbb", "aaa"}).PeekForPeriod(11155111, 10, 100)

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
