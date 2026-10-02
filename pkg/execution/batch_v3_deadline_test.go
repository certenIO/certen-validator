package execution

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A cadence member whose intent CERTEN's quorum never certified waits while it may still be certified, and once past
// its settlement deadline leaves the batch path by name - never waits for ever, never enters a batch uncertified.
func TestANeverCertifiedMemberIsRefusedByNameAtItsDeadline(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 10})
	m.SetIntentCertificates(fakeCerts{})
	fresh := certifiedMember("fresh", 7, fill32(0xaa))
	fresh.CommitTime = time.Now().Add(-time.Minute)
	if err := m.Add(fresh); err != nil {
		t.Fatal(err)
	}
	o := &BatchOrchestrator{incarnation: testIncarnation, mempool: m, ecm: &EthereumContractManager{}, logf: t.Logf}

	res, err := o.FlushChain(context.Background(), 11155111, 100, 100)
	if err != nil || res != nil {
		t.Fatalf("a member still within its deadline: (%+v, %v)", res, err)
	}
	if !fresh.pending() {
		t.Fatal("a member within its deadline was given an outcome")
	}

	stale := certifiedMember("stale", 8, fill32(0xbb))
	stale.CommitTime = time.Now().Add(-30 * 24 * time.Hour)
	if err := m.Add(stale); err != nil {
		t.Fatal(err)
	}
	res, err = o.FlushChain(context.Background(), 11155111, 100, 100)
	if err != nil || res == nil || len(res.Dropped) != 1 || res.Dropped[0].IntentID != "stale" {
		t.Fatalf("the member past its deadline: (%+v, %v)", res, err)
	}
	if cause := res.DropCauseOf(res.Dropped[0]); !strings.Contains(cause, "did not certify its intent") {
		t.Fatalf("cause %q", cause)
	}
	if stale.Outcome != MemberDropped || !fresh.pending() {
		t.Fatalf("outcomes: stale %q, fresh %q", stale.Outcome, fresh.Outcome)
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
