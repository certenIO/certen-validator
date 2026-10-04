package execution

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// RB5-F57 part 2: a member's commit time is its commit block's time on every path, so every validator forms the same
// v4 leaf. The tests state it through admission (EnqueueOnDemand / EnqueueForBatch with the round's snapshot), the
// on-demand resolver and the cadence flush; only the fixtures in commit_time_fixture_test.go use the part-2 API.

// The intent of the live Kermit evidence (RUNLOG_RB5): written in BVN1 block 13430413 at 01:23:32Z, discovered in a later
// Directory block. The Directory block's time here is a stand-in; the live test reads the real one.
const (
	ctBVN       = "bvn1"
	ctBVNURL    = "acc://bvn-bvn1.acme"
	ctBVNBlock  = int64(13430413)
	ctDN        = "acc://dn.acme"
	ctDNHeight  = uint64(10237400)
	ctAdmission = "2026-10-03T01:23:32Z"
	ctDNTime    = "2026-10-03T01:23:41Z"
)

func ctTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

// ctChain answers minor block times as Accumulate would: the BVN block and the Directory block that anchored it have
// different times. It counts what it was asked.
type ctChain struct{ asked []string }

func (c *ctChain) read(_ context.Context, partition string, height uint64) (time.Time, error) {
	c.asked = append(c.asked, fmt.Sprintf("%s@%d", partition, height))
	switch {
	case partition == ctBVNURL && height == uint64(ctBVNBlock):
		return ctTime(ctAdmission), nil
	case partition == ctDN && height == ctDNHeight:
		return ctTime(ctDNTime), nil
	}
	return time.Time{}, errors.New("no such block")
}

// Two validators admit one on-demand intent on Base (v4): A's discovery read its commit block's time, B's could not and
// B resolves it. Both must hold the same commit time - the BVN block's, never the Directory block's - and so the same
// window and the same v4 leaf; otherwise no v4 batch reaches quorum.
func TestEveryValidatorDerivesOneCommitTime(t *testing.T) {
	withAccountLeafVersions(t, "84532=v4")
	att := f57AttWithCommitBlock(ctBVN, ctBVNBlock)
	admit := func(commitTime time.Time) *PendingBatchIntent {
		s := stackForChain(t, 84532)
		if err := s.EnqueueOnDemand("ct", "acc://a.acme", 84532, acct(1), opid(31), admissionLeg(84532), att, testGov,
			ctDNHeight, ctDN, commitTime, ""); err != nil {
			t.Fatal(err)
		}
		return s.Mempool.PendingOnDemand(84532)[0]
	}
	a := admit(ctTime(ctAdmission)) // discovery read the BVN block
	b := admit(time.Time{})         // discovery could not: the on-demand submitter resolves it

	chain := &ctChain{}
	sub := odSubmitter(t, "validator-1")
	sub.cfg.CommitTime = chain.read
	sub.resolveCommitTime(context.Background(), b)

	if !b.CommitTime.Equal(a.CommitTime) {
		t.Fatalf("validator B resolved commit time %s (asked %v), validator A admitted %s: two notBefores for one member",
			b.CommitTime.Format(time.RFC3339), chain.asked, a.CommitTime.Format(time.RFC3339))
	}
	certifiedForTest(a)
	certifiedForTest(b)
	la, errA := a.Leaf()
	lb, errB := b.Leaf()
	if errA != nil || errB != nil || la != lb {
		t.Fatalf("leaves %x (%v) and %x (%v)", la, errA, lb, errB)
	}
}
