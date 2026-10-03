package execution

import (
	"context"
	"testing"
	"time"
)

// The cadence lane resolves a member's missing commit time from its commit block before it forms the period's trees,
// as the on-demand lane does: a v4 member is not held for a commit time that can be read.
func TestTheCadenceLaneResolvesAMissingCommitTime(t *testing.T) {
	withAccountLeafVersions(t, "84532=v4")
	s := stackForChain(t, 84532)
	chain := &ctChain{}
	f57SetStackCommitTime(s, chain.read)
	att := f57AttWithCommitBlock(ctBVN, ctBVNBlock)
	if err := s.EnqueueForBatch("ct-cad", "acc://a.acme", 84532, acct(1), opid(32), admissionLeg(84532), att, testGov,
		ctDNHeight, ctDN, time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	periodBlocks := uint64(100)
	start := ctDNHeight - ctDNHeight%periodBlocks
	m := s.Mempool.PeriodMembers(84532, start, periodBlocks)
	if len(m) != 1 {
		t.Fatalf("period holds %d members", len(m))
	}
	certifiedForTest(m[0])
	// The flush (which errors on this stack's missing chain client after the resolver ran) is the cadence lane's entry.
	s.flushOneChain(context.Background(), 84532, start, periodBlocks, nil, nil, t.Logf)

	if got := m[0].CommitTime; !got.Equal(ctTime(ctAdmission)) {
		t.Fatalf("the cadence member's commit time is %v (asked %v), want its commit block's %s", got, chain.asked, ctAdmission)
	}
	if _, err := m[0].LeafInput(); err != nil {
		t.Fatalf("the cadence member still has no v4 leaf: %v", err)
	}
}

// f57SetStackCommitTime wires the cadence lane's commit-time reader.
func f57SetStackCommitTime(s *BatchStack, read CommitTimeResolver) { s.CommitTime = read }
