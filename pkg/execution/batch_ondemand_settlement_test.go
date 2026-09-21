package execution

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// =============================================================================
// On-demand settlement decisions, driven over a fake chain
// =============================================================================
//
// These cover the branches that only occur when something else went wrong — an anchor another
// validator attested, a settlement that reverted, two validators racing one member — which is
// exactly where the lane failed live on 2026-09-20 (intent 5a2ebba0): the leader's settlement
// reverted, the gateway was never told, the failure was never written back, and every failover
// validator then attested the member again with no transaction.

type costCall struct{ anchorTx, verifyTx, settleTx string }

type fakeODChain struct {
	mu sync.Mutex

	attested   bool
	consumed   bool
	consumeErr error
	// consumeOnSettle: the leaf reads consumed once settleMember has run (another validator's
	// settlement landed first, or this one's did).
	consumeOnSettle bool
	settleTx        string
	settleErr       error
	anchorTx        string
	verifyTx        string
	// statuses answers settlementStatus, keyed by tx hash: found, mined, reverted.
	statuses  map[string][3]bool
	statusErr error

	createCalls int
	settleCalls int
	costs       []costCall
	settledLegs int
	failedLegs  int
}

func (f *fakeODChain) memberAccountUsable(context.Context, *PendingBatchIntent) error { return nil }
func (f *fakeODChain) anchorAlreadyAttested(context.Context, [32]byte) (bool, error) {
	return f.attested, nil
}
func (f *fakeODChain) memberLeafConsumed(context.Context, *PendingBatchIntent) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.consumed, f.consumeErr
}
func (f *fakeODChain) verifyLeavesAgainstAccounts(context.Context, []*PendingBatchIntent, *BatchTree) error {
	return nil
}
func (f *fakeODChain) beginSettlementSequence(context.Context) error { return nil }
func (f *fakeODChain) endSettlementSequence()                        {}
func (f *fakeODChain) createBatchAnchor(context.Context, *BatchTree) (string, uint64, uint64, error) {
	f.createCalls++
	return f.anchorTx, 100, 1, nil
}
func (f *fakeODChain) verifyLeavesAgainstAnchor(context.Context, *BatchTree) error { return nil }
func (f *fakeODChain) settleMember(_ context.Context, p *PendingBatchIntent, _ *BatchTree, _ [][32]byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settleCalls++
	// What the real settleMember records before it awaits the receipt.
	p.SettlementTx = f.settleTx
	if f.consumeOnSettle {
		f.consumed = true
	}
	return f.settleTx, f.settleErr
}
func (f *fakeODChain) settlementStatus(_ context.Context, tx string) (bool, bool, bool, error) {
	st := f.statuses[tx]
	return st[0], st[1], st[2], f.statusErr
}
func (f *fakeODChain) memberPastDeadline(*PendingBatchIntent) bool { return false }
func (f *fakeODChain) lastVerifyTx() string                        { return f.verifyTx }
func (f *fakeODChain) reportOnDemandCosts(_ context.Context, m *PendingBatchIntent, settleTx string) {
	f.costs = append(f.costs, costCall{m.AnchorTx, m.VerifyTx, settleTx})
}
func (f *fakeODChain) recordLegProgress(_ context.Context, settled, failed []*PendingBatchIntent) {
	f.settledLegs += len(settled)
	f.failedLegs += len(failed)
}

func odOrchestrator(f *fakeODChain) *BatchOrchestrator {
	return &BatchOrchestrator{odChain: f, logf: func(string, ...interface{}) {}, attempts: map[uint64]int{}}
}

const (
	odRevertTx = "0x54562d54d6c38a858fda1bdd9cffb95cffb688b2f2f685468ba4752ddd3c8b0b"
	odSettleTx = "0x1111111111111111111111111111111111111111111111111111111111111111"
	odAnchorTx = "0x2222222222222222222222222222222222222222222222222222222222222222"
	odVerifyTx = "0x3333333333333333333333333333333333333333333333333333333333333333"
)

func proveOK(context.Context, *BatchTree) error { return nil }

func settle(t *testing.T, f *fakeODChain, m *PendingBatchIntent) *OnDemandOutcome {
	t.Helper()
	out, err := odOrchestrator(f).SettleOnDemandMember(context.Background(), m, proveOK)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	return out
}

// Defect 1 and the leader's half of Defect 2: this validator's own settlement reverts with the
// leaf unspent. It is the member's failure against that transaction: the reverted vault_execute is
// reported to the gateway beside the anchor and verify this validator paid for, the legs are
// recorded failed, and the outcome carries the transaction Phase 7 proves.
func TestOD_OwnRevertIsReportedWithItsTransaction(t *testing.T) {
	f := &fakeODChain{settleTx: odRevertTx, settleErr: errSettlementReverted, anchorTx: odAnchorTx, verifyTx: odVerifyTx}
	m := odMember(1, odChain, 100)
	out := settle(t, f, m)
	if !out.Reverted || out.Settled || out.Released || out.TxHash != odRevertTx {
		t.Fatalf("outcome %+v; want reverted with its transaction", out)
	}
	if len(f.costs) != 1 || f.costs[0] != (costCall{odAnchorTx, odVerifyTx, odRevertTx}) {
		t.Fatalf("costs %+v; the gateway must be told of the anchor, the verify and the reverted settlement", f.costs)
	}
	if f.failedLegs != 1 || f.settledLegs != 0 {
		t.Fatalf("legs settled=%d failed=%d; want the member's legs failed", f.settledLegs, f.failedLegs)
	}
	if !m.AnchorProved || m.AnchorTx != odAnchorTx || m.VerifyTx != odVerifyTx {
		t.Fatalf("member %+v does not record that this validator proved its anchor", m)
	}
}

// A settlement that reverted because another validator's settlement spent the leaf first is a
// lost race, not a failure. Reporting it would tell the gateway a payment that went through failed.
func TestOD_LostSettlementRaceIsReleasedNotReported(t *testing.T) {
	f := &fakeODChain{settleTx: odRevertTx, settleErr: errSettlementReverted, consumeOnSettle: true, anchorTx: odAnchorTx}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Released || out.Reverted || out.Settled {
		t.Fatalf("outcome %+v; want released", out)
	}
	if len(f.costs) != 0 || f.failedLegs != 0 {
		t.Fatalf("costs %+v failed legs %d; a lost race reports nothing", f.costs, f.failedLegs)
	}
}

// Defect 3, the live case. Another validator anchored, attested and settled (its settlement
// reverted, rolling the leaf back). A failover validator reaching the member finds the anchor
// attested and the leaf unspent. It must not attest (it has no transaction), must not settle again
// (that could execute an intent whose failure is on record), and must not report anything.
func TestOD_FailoverReleasesAMemberAnotherValidatorAttested(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		f := &fakeODChain{attested: true, consumed: consumed, settleTx: odSettleTx}
		out := settle(t, f, odMember(1, odChain, 100))
		if !out.Released || out.Settled || out.Reverted || out.TxHash != "" {
			t.Fatalf("consumed=%t: outcome %+v; want released with nothing to attest", consumed, out)
		}
		if f.settleCalls != 0 || f.createCalls != 0 || len(f.costs) != 0 {
			t.Fatalf("consumed=%t: settle=%d create=%d costs=%+v; a failover validator only reads",
				consumed, f.settleCalls, f.createCalls, f.costs)
		}
	}
}

// The validator that attested the anchor and stopped before sending (a restart between the two)
// still holds its persisted record, and it - only it - settles under its own anchor.
func TestOD_ValidatorThatAttestedTheAnchorSettlesAfterARestart(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx}
	m := odMember(1, odChain, 100)
	m.AnchorProved, m.AnchorTx = true, odAnchorTx
	out := settle(t, f, m)
	if !out.Settled || out.TxHash != odSettleTx {
		t.Fatalf("outcome %+v; want settled by this validator", out)
	}
	if f.createCalls != 0 || f.settleCalls != 1 {
		t.Fatalf("create=%d settle=%d; want one settlement under the existing anchor", f.createCalls, f.settleCalls)
	}
	if len(f.costs) != 1 || f.costs[0] != (costCall{odAnchorTx, "", odSettleTx}) {
		t.Fatalf("costs %+v", f.costs)
	}
}

// A settlement sent but not observed is not a revert. The member stays queued with the send
// recorded, and the next pass - which finds the anchor attested - reads its outcome.
func TestOD_UnobservedSettlementIsResolvedFromItsOwnRecord(t *testing.T) {
	f := &fakeODChain{settleTx: odSettleTx, anchorTx: odAnchorTx,
		settleErr: &SettlementOutcomeUnknownError{TxHash: odSettleTx, Err: context.DeadlineExceeded}}
	m := odMember(1, odChain, 100)
	out := settle(t, f, m)
	if !out.Deferred || out.Settled || out.Reverted || out.Released {
		t.Fatalf("outcome %+v; want deferred", out)
	}
	if m.SettlementTx != odSettleTx || len(f.costs) != 0 {
		t.Fatalf("send not recorded (%q) or costs reported early (%+v)", m.SettlementTx, f.costs)
	}

	cases := []struct {
		name   string
		status [3]bool
		err    error
		leaf   bool
		check  func(*OnDemandOutcome) bool
		costs  int
	}{
		{"still pending", [3]bool{true, false, false}, nil, false, func(o *OnDemandOutcome) bool { return o.Deferred }, 0},
		{"unknown to the endpoint", [3]bool{false, false, false}, nil, false, func(o *OnDemandOutcome) bool { return o.Deferred }, 0},
		{"unreadable", [3]bool{}, errors.New("rpc down"), false, func(o *OnDemandOutcome) bool { return o.Deferred }, 0},
		{"succeeded", [3]bool{true, true, false}, nil, true, func(o *OnDemandOutcome) bool { return o.Settled && o.TxHash == odSettleTx }, 1},
		{"reverted, leaf unspent", [3]bool{true, true, true}, nil, false, func(o *OnDemandOutcome) bool { return o.Reverted && o.TxHash == odSettleTx }, 1},
		{"reverted, leaf spent by another", [3]bool{true, true, true}, nil, true, func(o *OnDemandOutcome) bool { return o.Released && o.TxHash == "" }, 0},
	}
	for _, c := range cases {
		g := &fakeODChain{attested: true, consumed: c.leaf, statuses: map[string][3]bool{odSettleTx: c.status}, statusErr: c.err}
		out := settle(t, g, m)
		if !c.check(out) {
			t.Errorf("%s: outcome %+v", c.name, out)
		}
		if len(g.costs) != c.costs || g.settleCalls != 0 || g.createCalls != 0 {
			t.Errorf("%s: costs=%+v settle=%d create=%d", c.name, g.costs, g.settleCalls, g.createCalls)
		}
	}
}

// Reading the leaf failed: that says nothing about the member, so nothing is concluded.
func TestOD_UnreadableLeafDefers(t *testing.T) {
	f := &fakeODChain{attested: true, consumeErr: errors.New("rpc down")}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Deferred || out.Released {
		t.Fatalf("outcome %+v; want deferred", out)
	}
	g := &fakeODChain{settleTx: odRevertTx, settleErr: errSettlementReverted, consumeErr: errors.New("rpc down")}
	out = settle(t, g, odMember(1, odChain, 100))
	if !out.Deferred || out.Reverted || len(g.costs) != 0 {
		t.Fatalf("outcome %+v costs %+v; a revert whose leaf cannot be read is not yet a failure", out, g.costs)
	}
}

// ---- dispose -------------------------------------------------------------------------------

type attestCall struct {
	tx string
	ok bool
}

func settlementSubmitter(t *testing.T, f *fakeODChain) (*OnDemandSubmitter, *[]attestCall) {
	t.Helper()
	stack := &BatchStack{
		Mempool:       NewBatchMempool(BatchMempoolConfig{}),
		Orchestrators: map[int64]*BatchOrchestrator{odChain: odOrchestrator(f)},
	}
	var calls []attestCall
	cfg := OnDemandSubmitterConfig{
		Stack:       stack,
		ValidatorID: "validator-5",
		Roster:      func() []string { return nil },
		Attest: func(_ context.Context, _ interface{}, tx string, _ int64, ok bool) {
			calls = append(calls, attestCall{tx, ok})
		},
	}
	cfg.withDefaults()
	return &OnDemandSubmitter{cfg: cfg, wake: make(chan struct{}, 1), inWork: map[string]bool{}}, &calls
}

func TestOD_DisposeReleasedDoesNotAttest(t *testing.T) {
	s, calls := settlementSubmitter(t, &fakeODChain{})
	m := odMember(1, odChain, 100)
	_ = s.cfg.Stack.Mempool.AddOnDemand(m)
	s.dispose(context.Background(), m, &OnDemandOutcome{Released: true}, true, nil)
	if len(*calls) != 0 {
		t.Fatalf("attested %+v for a member whose outcome is another validator's", *calls)
	}
	if s.cfg.Stack.Mempool.GetOnDemand(odChain, m.OperationID) != nil {
		t.Fatal("member not released")
	}
}

func TestOD_DisposeOwnRevertAttestsTheFailureWithItsTx(t *testing.T) {
	s, calls := settlementSubmitter(t, &fakeODChain{})
	m := odMember(1, odChain, 100)
	_ = s.cfg.Stack.Mempool.AddOnDemand(m)
	s.dispose(context.Background(), m, &OnDemandOutcome{Reverted: true, TxHash: odRevertTx}, true, nil)
	if len(*calls) != 1 || (*calls)[0] != (attestCall{odRevertTx, false}) {
		t.Fatalf("attest calls %+v; want one failure attestation carrying the reverted tx", *calls)
	}
}

// The whole submitter pass over the live case, on a failover validator: nothing attested, nothing
// executed, the local copy released.
func TestOD_FailoverPassAttestsNothing(t *testing.T) {
	f := &fakeODChain{attested: true}
	s, calls := settlementSubmitter(t, f)
	m := odMember(1, odChain, 100)
	_ = s.cfg.Stack.Mempool.AddOnDemand(m)
	s.consider(context.Background(), m)
	if len(*calls) != 0 || f.settleCalls != 0 {
		t.Fatalf("attest calls %+v settle calls %d; a failover validator must only read", *calls, f.settleCalls)
	}
	if s.cfg.Stack.Mempool.GetOnDemand(odChain, m.OperationID) != nil {
		t.Fatal("member not released")
	}
}

// The progress that decides whose outcome a member is survives a restart.
func TestOD_ProgressIsPersistedWithTheMember(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mempool.json")
	store, err := NewBatchMempoolStore(path, nil, func(string, ...interface{}) {})
	if err != nil {
		t.Fatal(err)
	}
	m := NewBatchMempool(BatchMempoolConfig{})
	m.SetStore(store, func(string, ...interface{}) {})
	p := odMember(1, odChain, 100)
	if err := m.AddOnDemand(p); err != nil {
		t.Fatal(err)
	}
	if !m.NoteOnDemandProgress(odChain, p.OperationID, func(q *PendingBatchIntent) {
		q.AnchorProved, q.AnchorTx, q.VerifyTx, q.SettlementTx = true, odAnchorTx, odVerifyTx, odSettleTx
	}) {
		t.Fatal("progress not noted on a queued member")
	}
	if m.NoteOnDemandProgress(odChain, [32]byte{9}, func(*PendingBatchIntent) {}) {
		t.Fatal("progress noted on a member that is not queued")
	}

	restored := NewBatchMempool(BatchMempoolConfig{})
	if n, err := store.Load(restored); err != nil || n != 1 {
		t.Fatalf("load: %d, %v", n, err)
	}
	got := restored.GetOnDemand(odChain, p.OperationID)
	if got == nil || !got.AnchorProved || got.AnchorTx != odAnchorTx || got.VerifyTx != odVerifyTx || got.SettlementTx != odSettleTx {
		t.Fatalf("restored %+v", got)
	}
}
