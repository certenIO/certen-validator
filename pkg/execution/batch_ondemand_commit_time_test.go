package execution

import (
	"context"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

const odPartition = "acc://bvn-bvn1.acme/ledger"

// leaderAt returns which roster member leads the member at elapsed.
func leaderAt(t *testing.T, member *PendingBatchIntent, elapsed time.Duration) string {
	t.Helper()
	var leader string
	for _, id := range odRoster() {
		if odSubmitter(t, id).isLeaderFor(member, elapsed) {
			if leader != "" {
				t.Fatalf("both %s and %s lead at %s", leader, id, elapsed)
			}
			leader = id
		}
	}
	return leader
}

// THE defect: the rotation ran from a local, unpersisted clock, so a restart put the restarted
// validator back at the start of it. A member 9 minutes past its block is two handoffs in, on every
// validator, before and after a restart.
func TestOnDemandFailover_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mempool.json")
	st, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := NewBatchMempool(BatchMempoolConfig{})
	pool.SetStore(st, nil)

	blockTime := time.Now().Add(-9 * time.Minute).Truncate(time.Millisecond)
	m := odMember(1, odChain, 105)
	m.CommitPartition, m.CommitTime = odPartition, blockTime
	if err := pool.AddOnDemand(m); err != nil {
		t.Fatal(err)
	}

	// A new process: the member is restored with a fresh local EnqueuedAt.
	st2, err := NewBatchMempoolStore(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := NewBatchMempool(BatchMempoolConfig{})
	after.SetStore(st2, nil)
	restored := after.PendingOnDemand(odChain)
	if len(restored) != 1 {
		t.Fatalf("restored %d members", len(restored))
	}
	r := restored[0]
	if !r.CommitTime.Equal(blockTime) || r.CommitPartition != odPartition {
		t.Fatalf("block time not persisted: %s %q, want %s %q", r.CommitTime, r.CommitPartition, blockTime, odPartition)
	}
	if time.Since(r.EnqueuedAt) > time.Minute {
		t.Fatalf("test premise: a restored member's EnqueuedAt is local and fresh (%s)", r.EnqueuedAt)
	}

	s := odSubmitter(t, "validator-1")
	s.cfg.Stack.Mempool = after
	elapsed := s.failoverElapsed(context.Background(), r)
	if elapsed < 9*time.Minute || elapsed > 10*time.Minute {
		t.Fatalf("failover elapsed %s after a restart, want ~9m from the block", elapsed)
	}
	if got, want := leaderAt(t, r, elapsed), leaderAt(t, m, 2*OnDemandFailoverAfter+time.Second); got != want {
		t.Fatalf("after a restart the member is led by %s, want the second handoff %s", got, want)
	}
}

// Validators queue a member at different local times; the rotation must not depend on it.
func TestOnDemandFailover_ValidatorsAgreeWhateverTheirLocalClocks(t *testing.T) {
	blockTime := time.Now().Add(-5 * time.Minute)
	var leaders []string
	for i, id := range odRoster() {
		m := odMember(1, odChain, 105)
		m.CommitPartition, m.CommitTime = odPartition, blockTime
		m.EnqueuedAt = time.Now().Add(-time.Duration(i) * 70 * time.Second)
		m.FirstSeen = m.EnqueuedAt
		s := odSubmitter(t, id)
		if s.isLeaderFor(m, s.failoverElapsed(context.Background(), m)) {
			leaders = append(leaders, id)
		}
	}
	if len(leaders) != 1 {
		t.Fatalf("leaders %v: validators disagree on whose turn it is", leaders)
	}
}

func TestOnDemandFailover_ReadsAMissingBlockTimeOnceAndKeepsIt(t *testing.T) {
	blockTime := time.Now().Add(-5 * time.Minute).Truncate(time.Millisecond)
	calls := 0
	s := odSubmitter(t, "validator-1")
	s.cfg.CommitTime = func(_ context.Context, partition string, height uint64) (time.Time, error) {
		calls++
		if partition != odPartition || height != 105 {
			t.Fatalf("asked for %s@%d", partition, height)
		}
		return blockTime, nil
	}
	m := odMember(1, odChain, 105)
	m.CommitPartition = odPartition
	if err := s.cfg.Stack.Mempool.AddOnDemand(m); err != nil {
		t.Fatal(err)
	}
	queued := s.cfg.Stack.Mempool.PendingOnDemand(odChain)[0]

	if e := s.failoverElapsed(context.Background(), queued); e < 5*time.Minute {
		t.Fatalf("elapsed %s, want from the block time", e)
	}
	if !queued.CommitTime.Equal(blockTime) {
		t.Fatalf("block time not recorded on the queued member: %s", queued.CommitTime)
	}
	s.failoverElapsed(context.Background(), queued)
	if calls != 1 {
		t.Fatalf("read the block time %d times, want once", calls)
	}
}

func TestOnDemandFailover_UnreadableBlockTimeFallsBackToFirstSightingAndRetriesLater(t *testing.T) {
	calls := 0
	s := odSubmitter(t, "validator-1")
	s.cfg.CommitTime = func(context.Context, string, uint64) (time.Time, error) {
		calls++
		return time.Time{}, errors.New("api down")
	}
	m := odMember(1, odChain, 105)
	m.CommitPartition = odPartition
	m.FirstSeen = time.Now().Add(-6 * time.Minute) // persisted: survives a restart
	m.EnqueuedAt = time.Now()                      // local: reset by one

	e := s.failoverElapsed(context.Background(), m)
	if e < 6*time.Minute {
		t.Fatalf("elapsed %s: fell back to the local enqueue time, not the persisted first sighting", e)
	}
	s.failoverElapsed(context.Background(), m)
	if calls != 1 {
		t.Fatalf("an unreadable block time was asked for %d times within the retry interval", calls)
	}
	s.commitTimeTried[memberWorkKey(m.ChainID, m.OperationID)] = time.Now().Add(-onDemandCommitTimeRetry)
	s.failoverElapsed(context.Background(), m)
	if calls != 2 {
		t.Fatalf("not retried after the interval (%d reads)", calls)
	}
}

// The gas-deferral deadline is the promise to the ADI: an outcome within the hour of its intent. A
// restart must not restart it - measured from EnqueuedAt, a node restarting within the hour
// deferred a member for ever.
func TestMemberPastDeadline_MeasuredFromTheBlockNotTheLocalQueue(t *testing.T) {
	o := &BatchOrchestrator{}
	m := odMember(1, odChain, 105)
	m.EnqueuedAt = time.Now()
	m.CommitTime = time.Now().Add(-maxGasDeferral - time.Minute)
	if !o.memberPastDeadline(m) {
		t.Fatal("a member an hour past its block is not past its deadline after a restart")
	}
	m.CommitTime = time.Now().Add(-time.Minute)
	if o.memberPastDeadline(m) {
		t.Fatal("a fresh member is past its deadline")
	}

	legacy := odMember(2, odChain, 106) // queued before the block time was carried
	legacy.EnqueuedAt = time.Now()
	legacy.FirstSeen = time.Now().Add(-maxGasDeferral - time.Minute)
	if !o.memberPastDeadline(legacy) {
		t.Fatal("without a block time the deadline must run from the persisted first sighting")
	}
}

// The 2-hour prune is a memory backstop and stays on the local clock on purpose: measured from the
// block, a validator back from a 2-hour outage would drop every member it holds unrecorded.
func TestOnDemandPrune_DoesNotDropMembersAfterAnOutage(t *testing.T) {
	pool := NewBatchMempool(BatchMempoolConfig{})
	m := odMember(1, odChain, 105)
	m.CommitTime = time.Now().Add(-3 * time.Hour)
	if err := pool.AddOnDemand(m); err != nil {
		t.Fatal(err)
	}
	if n := pool.PruneOnDemandOlderThan(DefaultOnDemandTTL, time.Now()); n != 0 {
		t.Fatalf("pruned %d member(s) just restored after an outage", n)
	}
}

func TestEnqueueOnDemand_CarriesTheBlock(t *testing.T) {
	s := stackForChain(t, odChain)
	legs := []mirrorLeg{{LegID: "l0", ChainID: odChain, Target: tgt(1), Value: big.NewInt(1)}}
	blockTime := time.Date(2026, 7, 27, 23, 43, 8, 0, time.UTC)
	if err := s.EnqueueOnDemand("i", "acc://a.acme", odChain, acct(1), opid(1), legs, "att", 4242,
		odPartition, blockTime, "0xaccumfictional"); err != nil {
		t.Fatal(err)
	}
	got := s.Mempool.PendingOnDemand(odChain)
	if len(got) != 1 || got[0].CommitPartition != odPartition || !got[0].CommitTime.Equal(blockTime) {
		t.Fatalf("block not carried onto the member: %+v", got)
	}
	if origin, consensus := got[0].Origin(); !consensus || !origin.Equal(blockTime) {
		t.Fatalf("origin %s consensus=%v", origin, consensus)
	}
}
