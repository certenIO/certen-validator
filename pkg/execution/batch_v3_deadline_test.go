package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A cadence member whose intent CERTEN's quorum never certified waits while it may still be certified, and once past
// its settlement deadline leaves the batch path by name - decided by its own leader alone, so exactly one validator
// records it; the others keep their copy until then.
func TestANeverCertifiedMemberIsRefusedByNameAtItsDeadline(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})
	m.SetIntentCertificates(fakeCerts{})
	s := &BatchStack{Mempool: m}
	fresh := certifiedMember("fresh", 7, fill32(0xaa))
	fresh.CommitTime = time.Now().Add(-time.Minute)
	stale := certifiedMember("stale", 8, fill32(0xbb))
	stale.CommitTime = time.Now().Add(-30 * 24 * time.Hour)
	for _, p := range []*PendingBatchIntent{fresh, stale} {
		if err := m.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	drops := &dropLog{dropped: map[string]string{}}
	notLeader := func(*PendingBatchIntent) bool { return false }
	s.settleNeverCertified(notLeader, drops.fn, t.Logf)
	if len(drops.dropped) != 0 || !stale.pending() {
		t.Fatal("a validator that does not lead the member recorded its outcome")
	}
	leader := func(*PendingBatchIntent) bool { return true }
	s.settleNeverCertified(leader, drops.fn, t.Logf)
	if len(drops.dropped) != 1 || !strings.Contains(drops.dropped["stale"], "did not certify its intent") {
		t.Fatalf("refusals: %v", drops.dropped)
	}
	if stale.Outcome != MemberDropped || !fresh.pending() {
		t.Fatalf("outcomes: stale %q, fresh %q", stale.Outcome, fresh.Outcome)
	}
}

// The member's leader is its commit period's, rotating as periods elapse - the period path's own rule.
func TestAMembersLeaderIsItsPeriodsRotatingLeader(t *testing.T) {
	s := &BatchStack{}
	var got [3]uint64
	leads := s.memberLeader(500, 100, func(chainID int64, start, elapsed uint64) bool {
		got = [3]uint64{uint64(chainID), start, elapsed}
		return true
	})
	if !leads(&PendingBatchIntent{ChainID: 7, CommitHeight: 230}) || got != [3]uint64{7, 200, 3} {
		t.Fatalf("leader asked about %v", got)
	}
	if !s.memberLeader(500, 100, nil)(&PendingBatchIntent{}) {
		t.Fatal("with no leader function (single node) this node does not lead")
	}
}

// The on-demand lane: an uncertified member defers while within its deadline and is refused by name past it.
func TestAnOnDemandMemberWaitsForItsCertificateUntilItsDeadline(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})
	m.SetIntentCertificates(fakeCerts{})
	f := &fakeODChain{}
	o := odOrchestrator(f)
	o.mempool = m

	p := certifiedMember("od", 9, fill32(0xcc))
	p.CommitTime = time.Now().Add(-time.Minute)
	out, err := o.SettleOnDemandMember(context.Background(), p, nil)
	if err != nil || out == nil || !out.Deferred {
		t.Fatalf("within its deadline: (%+v, %v)", out, err)
	}
	p.CommitTime = time.Now().Add(-30 * 24 * time.Hour)
	if _, err := o.SettleOnDemandMember(context.Background(), p, nil); err == nil ||
		!strings.Contains(err.Error(), "did not certify its intent") {
		t.Fatalf("past its deadline: %v", err)
	}
	if err := (*BatchMempool)(nil).RequireCertified(p); err == nil {
		t.Fatal("a certified member passed with no mempool to read its certificate from")
	}
}

// RB5-F31: the on-demand lane formed its tree from a leaf input taken BEFORE its certificate was read, so the first time
// the certificate existed the tree committed no certified message (a v2 operation id) while every validator that had
// read it earlier committed v3. The tree is formed only from the certified message, and a leaf is never built for an
// intent still awaiting its certificate.
func TestAnOnDemandTreeCommitsTheCertifiedMessageTheFirstTimeItIsFormed(t *testing.T) {
	certified := fill32(0xbb)
	certs := fakeCerts{}
	certs[fill32(9)] = struct {
		height uint64
		msg    [32]byte
	}{height: 250, msg: certified}
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})
	m.SetIntentCertificates(certs)
	f := &fakeODChain{}
	o := odOrchestrator(f)
	o.mempool = m

	p := certifiedMember("od", 9, fill32(0xcc))
	p.CommitTime = time.Now().Add(-time.Minute)
	var formed *BatchTree
	_, _ = o.SettleOnDemandMember(context.Background(), p, func(_ context.Context, tree *BatchTree) error {
		formed = tree
		return errors.New("stop after forming")
	})
	if formed == nil {
		t.Fatal("no tree was formed")
	}
	want, _, err := batchOperationIDOf([]BatchLeafInput{{ADIURL: p.ADIURL, OperationID: p.OperationID,
		GovernanceCommitment: p.GovernanceCommitment, IntentMessage: certified}})
	if err != nil {
		t.Fatal(err)
	}
	if formed.BatchOperationIDVersion != BatchOperationIDV3 || formed.BatchOperationID != want {
		t.Fatalf("the first tree committed (%s, %x), want the certified message under v3 (%x)",
			formed.BatchOperationIDVersion, formed.BatchOperationID[:8], want[:8])
	}

	waiting := certifiedMember("waiting", 10, fill32(0xdd))
	if _, err := waiting.LeafInput(); !errors.Is(err, ErrIntentNotYetCertified) {
		t.Fatalf("a leaf was built for an intent awaiting its certificate: %v", err)
	}
}
