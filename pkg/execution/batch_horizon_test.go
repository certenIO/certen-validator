package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// outcomeBook answers MemberOutcomeOf from a fixed table: a recorded outcome, none, or an unreadable store.
type outcomeBook map[string]string

func (b outcomeBook) MemberOutcomeOf(_ context.Context, intentID string, _ int64) (*database.RecordedMemberOutcome, error) {
	switch b[intentID] {
	case "settled":
		return &database.RecordedMemberOutcome{Settlement: "settled", RecordedAt: time.Now()}, nil
	case "unreadable":
		return nil, errors.New("the database is unreachable")
	default:
		return nil, nil
	}
}

type dropLog struct {
	dropped map[string]string
}

func (d *dropLog) fn(_ context.Context, m *PendingBatchIntent, cause string) {
	d.dropped[m.IntentID] = cause
}

func horizonMember(id string, height uint64) *PendingBatchIntent {
	p := certifiedMember(id, byte(len(id)+40), [32]byte{})
	p.CommitHeight = height
	return p
}

// At the retention horizon no member leaves without an outcome: another validator's record lets this node's copy go,
// no outcome anywhere is a refusal by name, and an unreadable outcome keeps the member for a later pass.
func TestNoMemberLeavesAtTheRetentionHorizonWithoutAnOutcome(t *testing.T) {
	m := newTestMempool(BatchMempoolConfig{MaxBatchSize: 10})
	s := &BatchStack{Mempool: m, MemberOutcomes: outcomeBook{"elsewhere": "settled", "unreadable": "unreadable"}}
	for _, id := range []string{"elsewhere", "nowhere", "unreadable", "young"} {
		h := uint64(5)
		if id == "young" {
			h = 900
		}
		if err := m.Add(horizonMember(id, h)); err != nil {
			t.Fatal(err)
		}
	}
	drops := &dropLog{dropped: map[string]string{}}
	notLeader := func(*PendingBatchIntent) bool { return false }
	if keep := s.settleAtRetentionHorizon(4, 100, notLeader, drops.fn, t.Logf); len(drops.dropped) != 0 || !keep[m.pool[11155111][1]] {
		t.Fatalf("a validator that does not lead the member refused it, or let it go unrecorded: %v %v", drops.dropped, keep)
	}
	keep := s.settleAtRetentionHorizon(4, 100, func(*PendingBatchIntent) bool { return true }, drops.fn, t.Logf)
	if n := m.PruneOlderThanExcept(100, keep); n != 2 {
		t.Fatalf("pruned %d, want the settled-elsewhere copy and the refused member", n)
	}
	if len(drops.dropped) != 1 || !strings.Contains(drops.dropped["nowhere"], "no outcome recorded by any validator") {
		t.Fatalf("refusals: %v", drops.dropped)
	}
	left := map[string]bool{}
	for _, p := range m.pool[11155111] {
		left[p.IntentID] = true
	}
	if !left["unreadable"] || !left["young"] || left["nowhere"] || left["elsewhere"] {
		t.Fatalf("left in the pool: %v", left)
	}
	// Without a drop handler nothing unrecorded is removed.
	m2 := newTestMempool(BatchMempoolConfig{MaxBatchSize: 10})
	s2 := &BatchStack{Mempool: m2, MemberOutcomes: outcomeBook{}}
	_ = m2.Add(horizonMember("nowhere", 5))
	if n := m2.PruneOlderThanExcept(100, s2.settleAtRetentionHorizon(4, 100, func(*PendingBatchIntent) bool { return true }, nil, t.Logf)); n != 0 {
		t.Fatal("a member with no outcome was pruned with no handler to record it")
	}
}

// The on-demand pool: the same three outcomes when its TTL prune would remove a member.
func TestNoOnDemandMemberLeavesAtItsTTLWithoutAnOutcome(t *testing.T) {
	m := newTestMempool(BatchMempoolConfig{MaxBatchSize: 10})
	s := &BatchStack{Mempool: m, MemberOutcomes: outcomeBook{"elsewhere": "settled", "unreadable": "unreadable"}}
	old := time.Now().Add(-72 * time.Hour)
	for i, id := range []string{"elsewhere", "nowhere", "unreadable"} {
		p := horizonMember(id, 5)
		p.OperationID = fill32(byte(0x70 + i))
		p.CommitTime = old
		if err := m.AddOnDemand(p); err != nil {
			t.Fatal(err)
		}
		m.onDemand[p.ChainID][p.OperationID].EnqueuedAt = old
	}
	drops := &dropLog{dropped: map[string]string{}}
	if n := s.settleOnDemandAtTTL(time.Hour, time.Now(), func(*PendingBatchIntent) bool { return false }, drops.fn, t.Logf); n != 1 ||
		len(drops.dropped) != 0 {
		t.Fatalf("not this node's to decide: pruned %d, refused %v", n, drops.dropped)
	}
	if n := s.settleOnDemandAtTTL(time.Hour, time.Now(), func(*PendingBatchIntent) bool { return true }, drops.fn, t.Logf); n != 1 {
		t.Fatalf("pruned %d", n)
	}
	if len(drops.dropped) != 1 || drops.dropped["nowhere"] == "" {
		t.Fatalf("refusals: %v", drops.dropped)
	}
	if left := m.PendingOnDemandCount(); left != 1 {
		t.Fatalf("%d left, want the unreadable one", left)
	}
}
