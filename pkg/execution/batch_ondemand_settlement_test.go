package execution

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
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
	// spentBy answers leafConsumedTx: the transaction that spent the leaf and its sender, when
	// spentByKnown.
	spentBy      string
	spentFrom    common.Address
	spentByKnown bool
	// history answers settlementHashesAt: the sender's record of hashes per nonce.
	history map[uint64][]string
	// attester answers anchorAttester (the ProofExecuted transaction's sender); attesterUnknown
	// makes it not in view.
	attester        common.Address
	attesterUnknown bool
	// inFlight answers settlementInFlight by nonce.
	inFlight map[uint64]bool
	// beginErr and createErr fail the nonce pin and the anchor creation.
	beginErr  error
	createErr error

	// Settlement windows. attTime is T (default odT0); head and finalized are chain times (default
	// T+1m and T: window 0); prior* answers priorSettlementAttempt; timing marks reverts caused by the
	// settlement's own timing fields.
	attTime      time.Time
	head         time.Time
	finalized    time.Time
	priorTx      string
	priorFrom    common.Address
	priorFound   bool
	priorAsked   []common.Address
	timing       map[string]bool
	lastFence    time.Time
	rosterFailed bool

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
func (f *fakeODChain) beginSettlementSequence(context.Context) error { return f.beginErr }
func (f *fakeODChain) endSettlementSequence()                        {}
func (f *fakeODChain) createBatchAnchor(context.Context, *BatchTree) (string, uint64, uint64, error) {
	f.createCalls++
	if f.createErr != nil {
		return "", 0, 0, f.createErr
	}
	return f.anchorTx, 100, 1, nil
}
func (f *fakeODChain) verifyLeavesAgainstAnchor(context.Context, *BatchTree) error { return nil }
func (f *fakeODChain) settleMember(_ context.Context, p *PendingBatchIntent, _ *BatchTree, _ [][32]byte, fence time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settleCalls++
	f.lastFence = fence
	// What the real settleMember records before it awaits the receipt: the hash and its nonce.
	p.SettlementTx = f.settleTx
	p.SettlementTxs = append(p.SettlementTxs, f.settleTx)
	p.SettlementNonce, p.SettlementNonceSet = odSettleNonce, true
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
func (f *fakeODChain) lastVerifyTx([32]byte) string                { return f.verifyTx }
func (f *fakeODChain) reportOnDemandCosts(_ context.Context, m *PendingBatchIntent, settleTx string) {
	f.costs = append(f.costs, costCall{m.AnchorTx, m.VerifyTx, settleTx})
}
func (f *fakeODChain) recordLegProgress(_ context.Context, settled, failed []*PendingBatchIntent) {
	f.settledLegs += len(settled)
	f.failedLegs += len(failed)
}

func (f *fakeODChain) leafConsumedTx(context.Context, *PendingBatchIntent, [32]byte) (string, common.Address, bool, error) {
	return f.spentBy, f.spentFrom, f.spentByKnown, nil
}
func (f *fakeODChain) settlementHashesAt(_ *PendingBatchIntent, nonce uint64) []string {
	return f.history[nonce]
}
func (f *fakeODChain) anchorAttester(context.Context, [32]byte, uint64) (string, common.Address, bool, error) {
	if f.attesterUnknown {
		return "", common.Address{}, false, nil
	}
	return odVerifyTx, f.attester, true, nil
}
func (f *fakeODChain) ownAddress() common.Address { return odOwnAddr }

// odT0 is the fake attestation's block time.
var odT0 = time.Unix(1_800_000_000, 0)

func (f *fakeODChain) anchorAttestation(context.Context, [32]byte, uint64) (anchorAttestation, bool, error) {
	if f.attesterUnknown {
		return anchorAttestation{}, false, nil
	}
	a := f.attester
	if a == (common.Address{}) {
		a = odOwnAddr // a freshly attested anchor is this node's
	}
	t := f.attTime
	if t.IsZero() {
		t = odT0
	}
	return anchorAttestation{Tx: odVerifyTx, From: a, Time: t}, true, nil
}
func (f *fakeODChain) settlementRoster(context.Context) ([]common.Address, error) {
	if f.rosterFailed {
		return nil, errors.New("roster does not match the anchor")
	}
	return []common.Address{odOwnAddr, odOtherAddr, odThirdAddr}, nil
}
func (f *fakeODChain) chainTimes(context.Context) (time.Time, time.Time, error) {
	h, fin := f.head, f.finalized
	if h.IsZero() {
		h = odT0.Add(time.Minute)
	}
	if fin.IsZero() {
		fin = odT0
	}
	return h, fin, nil
}
func (f *fakeODChain) priorSettlementAttempt(_ context.Context, _ *PendingBatchIntent, _ *BatchTree, settlers []common.Address) (string, common.Address, bool, error) {
	f.priorAsked = settlers
	return f.priorTx, f.priorFrom, f.priorFound, nil
}
func (f *fakeODChain) settlementRevertCause(_ context.Context, tx string) (bool, string, error) {
	if f.timing[tx] {
		return true, "mined after its expiresAt", nil
	}
	return false, "", nil
}

var odThirdAddr = common.HexToAddress("0x6ACaa68417F5ad5d4a02D9d3d72E291efFcDf30A")

var (
	odOwnAddr   = common.HexToAddress("0xd4A3dBbAE0C04D4307c5E00A5E05b66AcC289f5D")
	odOtherAddr = common.HexToAddress("0x5555afA8Ff8048BddAAC1554AFd790c9bf7ec6E0")
)

func (f *fakeODChain) settlementInFlight(nonce uint64) bool { return f.inFlight[nonce] }

func odOrchestrator(f *fakeODChain) *BatchOrchestrator {
	return &BatchOrchestrator{odChain: f, logf: func(string, ...interface{}) {}, attempts: map[uint64]int{}}
}

const odSettleNonce = 42

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
	f := &fakeODChain{settleTx: odRevertTx, settleErr: errSettlementReverted, consumeOnSettle: true, anchorTx: odAnchorTx,
		spentBy: odSettleTx, spentFrom: odOtherAddr, spentByKnown: true}
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
		f := &fakeODChain{attested: true, consumed: consumed, settleTx: odSettleTx,
			attester: odOtherAddr, spentBy: odRevertTx, spentFrom: odOtherAddr, spentByKnown: true}
		out := settle(t, f, odMember(1, odChain, 100))
		// Spent: its sender's outcome, released. Unspent inside the attester's own window: held,
		// because the member is this validator's to take over if the attester dies.
		if consumed && (!out.Released || out.Settled || out.Reverted || out.TxHash != "") {
			t.Fatalf("consumed: outcome %+v; want released with nothing to attest", out)
		}
		if !consumed && (!out.Deferred || out.Released || out.Settled || out.Reverted) {
			t.Fatalf("unspent in the attester's window: outcome %+v; want held", out)
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
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr}
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
		g := &fakeODChain{attested: true, consumed: c.leaf, statuses: map[string][3]bool{odSettleTx: c.status}, statusErr: c.err,
			inFlight: map[uint64]bool{odSettleNonce: true}}
		if c.leaf {
			// A spent leaf is decided by the LeafConsumed log's sender: this node's settlement when it
			// succeeded, another sender's when this node's reverted.
			g.spentByKnown = true
			if c.status[2] {
				g.spentBy, g.spentFrom = odRevertTx, odOtherAddr
			} else {
				g.spentBy, g.spentFrom = odSettleTx, odOwnAddr
			}
		}
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

// The whole submitter pass over the live case, on a failover validator: another validator attested
// and its settlement reverted. Once that window is final the failover validator finds the attempt on
// chain - nothing attested, nothing executed, the local copy released.
func TestOD_FailoverPassAttestsNothing(t *testing.T) {
	f := &fakeODChain{attested: true, attester: odThirdAddr,
		head: odT0.Add(SettlementWindow + time.Minute), finalized: odT0.Add(SettlementWindow - time.Minute),
		priorTx: odRevertTx, priorFrom: odThirdAddr, priorFound: true}
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
		q.SettlementTxs, q.SettlementNonce, q.SettlementNonceSet = []string{odSettleTx, odReplacementTx}, 7, true
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
	if got == nil || !got.AnchorProved || got.AnchorTx != odAnchorTx || got.VerifyTx != odVerifyTx || got.SettlementTx != odSettleTx ||
		len(got.SettlementTxs) != 2 || got.SettlementTxs[1] != odReplacementTx || !got.SettlementNonceSet || got.SettlementNonce != 7 {
		t.Fatalf("restored %+v", got)
	}
}

// ---- the sender's outcomes, as the on-demand lane sees them ----------------------------------

const odReplacementTx = "0x4444444444444444444444444444444444444444444444444444444444444444"

func withOwnSettlement(m *PendingBatchIntent, nonce uint64, hashes ...string) *PendingBatchIntent {
	m.AnchorProved = true
	m.SettlementTxs = append([]string(nil), hashes...)
	m.SettlementTx = hashes[len(hashes)-1]
	m.SettlementNonce, m.SettlementNonceSet = nonce, true
	return m
}

// The settlement was replaced at the same nonce; the REPLACEMENT mined. Every hash is checked, so
// the member is settled with the one that actually executed.
func TestOD_ReplacedSettlementIsResolvedByTheHashThatMined(t *testing.T) {
	m := withOwnSettlement(odMember(1, odChain, 100), 7, odSettleTx, odReplacementTx)
	f := &fakeODChain{attested: true, consumed: true,
		statuses: map[string][3]bool{odReplacementTx: {true, true, false}},
		spentBy:  odReplacementTx, spentFrom: odOwnAddr, spentByKnown: true}
	out := settle(t, f, m)
	if !out.Settled || out.TxHash != odReplacementTx || f.settleCalls != 0 {
		t.Fatalf("outcome %+v settle calls %d; want settled with the replacement, nothing re-sent", out, f.settleCalls)
	}
}

// None of its hashes mined and the sender no longer has the nonce in flight: the settlement never
// reached the chain. It is forgotten and the member is settled afresh - not deferred for ever.
func TestOD_SettlementThatNeverExecutedIsForgottenAndResent(t *testing.T) {
	m := withOwnSettlement(odMember(1, odChain, 100), 7, odSettleTx)
	f := &fakeODChain{attested: true, settleTx: odReplacementTx, inFlight: map[uint64]bool{7: false}, attester: odOwnAddr}
	out := settle(t, f, m)
	if f.settleCalls != 1 || !out.Settled || out.TxHash != odReplacementTx {
		t.Fatalf("outcome %+v settle calls %d; want one fresh settlement", out, f.settleCalls)
	}
}

// Still in flight: nothing is concluded and nothing is sent.
func TestOD_SettlementStillInFlightDefers(t *testing.T) {
	m := withOwnSettlement(odMember(1, odChain, 100), 7, odSettleTx)
	f := &fakeODChain{attested: true, inFlight: map[uint64]bool{7: true}}
	out := settle(t, f, m)
	if !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("outcome %+v settle calls %d; want deferred", out, f.settleCalls)
	}
}

// The leaf is spent and no receipt of ours is visible yet (a lagging RPC node). The account's own
// LeafConsumed log names the spender: ours is settled, anyone else's is released, and no log in view
// decides nothing.
func TestOD_SpentLeafIsDecidedByItsLeafConsumedLog(t *testing.T) {
	cases := []struct {
		name         string
		spentBy      string
		from         common.Address
		known        bool
		wantSettled  bool
		wantReleased bool
		wantDeferred bool
	}{
		{"our replacement spent it", odReplacementTx, odOwnAddr, true, true, false, false},
		// A replacement Resume made while nobody was listening: on no record of the member's, but
		// sent by this node's key - so it is this node's settlement.
		{"an unrecorded replacement of ours spent it", "0x5555555555555555555555555555555555555555555555555555555555555555", odOwnAddr, true, true, false, false},
		{"another settlement spent it", odRevertTx, odOtherAddr, true, false, true, false},
		{"the log is not in view yet", "", common.Address{}, false, false, false, true},
	}
	for _, c := range cases {
		m := withOwnSettlement(odMember(1, odChain, 100), 7, odSettleTx, odReplacementTx)
		f := &fakeODChain{attested: true, consumed: true, spentBy: c.spentBy, spentFrom: c.from, spentByKnown: c.known,
			inFlight: map[uint64]bool{7: true}}
		out := settle(t, f, m)
		if out.Settled != c.wantSettled || out.Released != c.wantReleased || out.Deferred != c.wantDeferred {
			t.Errorf("%s: outcome %+v", c.name, out)
		}
		if c.wantSettled && out.TxHash != c.spentBy {
			t.Errorf("%s: settled with %s, want %s", c.name, out.TxHash, c.spentBy)
		}
	}
}

// Every transient send outcome defers the member; none records a failure.
func TestOD_TransientSendsDeferAndNeverFail(t *testing.T) {
	wait := &ChainWaitError{Label: "anchor", Nonce: 3, Hashes: []string{odAnchorTx}, Err: context.DeadlineExceeded}
	priced := &NotBroadcastError{Err: &ErrTxCostCeilingExceeded{ChainID: odChain}}

	f := &fakeODChain{beginErr: wait}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred || f.createCalls != 0 {
		t.Errorf("a key with a transaction still in flight: outcome %+v create calls %d", out, f.createCalls)
	}
	f = &fakeODChain{createErr: wait}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred {
		t.Errorf("an anchor with no result yet: outcome %+v", out)
	}
	f = &fakeODChain{settleTx: "", settleErr: priced, anchorTx: odAnchorTx}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred || out.Reverted || f.failedLegs != 0 {
		t.Errorf("a settlement refused on cost: outcome %+v failed legs %d", out, f.failedLegs)
	}
	f = &fakeODChain{settleTx: "", settleErr: ErrNonceConsumedElsewhere, anchorTx: odAnchorTx}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred || out.Reverted {
		t.Errorf("a settlement whose nonce went elsewhere: outcome %+v", out)
	}
}

// The leaf was already spent when this node went to settle: another settlement executed the member.
func TestOD_LeafSpentAtSendIsReleased(t *testing.T) {
	f := &fakeODChain{anchorTx: odAnchorTx, settleErr: fmt.Errorf("leaf 0xaa already consumed: %w", errLeafAlreadyConsumed),
		spentBy: odRevertTx, spentFrom: odOtherAddr, spentByKnown: true}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Released || out.Reverted || f.failedLegs != 0 {
		t.Fatalf("outcome %+v failed legs %d; want released", out, f.failedLegs)
	}
}

// This node BROADCAST the quorum attestation and did not see its result. It may land, so this node
// is a settler from now on: noted and persisted, so the next pass settles instead of releasing.
func TestOD_BroadcastAttestationMakesThisNodeTheSettler(t *testing.T) {
	for _, proveErr := range []error{
		fmt.Errorf("submitting batch quorum proof: %w", &ChainWaitError{Label: "verify", Nonce: 4,
			Hashes: []string{odVerifyTx}, Err: context.DeadlineExceeded}),
		&AnchorConfirmUnreadError{VerifyTx: odVerifyTx, Err: errors.New("rpc down")},
	} {
		f := &fakeODChain{anchorTx: odAnchorTx}
		m := odMember(1, odChain, 100)
		out, err := odOrchestrator(f).SettleOnDemandMember(context.Background(), m,
			func(context.Context, *BatchTree) error { return proveErr })
		if err != nil || !out.Deferred {
			t.Fatalf("%v: outcome %+v err %v; want deferred", proveErr, out, err)
		}
		if !m.AnchorProved || m.VerifyTx != odVerifyTx || m.AnchorTx != odAnchorTx {
			t.Fatalf("%v: member %+v not marked as the settler", proveErr, m)
		}
		// Next pass: the anchor reads attested, and this node settles it.
		g := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr}
		if out := settle(t, g, m); !out.Settled || g.settleCalls != 1 {
			t.Fatalf("%v: next pass outcome %+v; want this node to settle", proveErr, out)
		}
	}
}

// The leaf was already spent at send time by a settlement of THIS node's that landed meanwhile (the
// sender drove it to a result while pinning the sequence): that is the member's success, not a
// release.
func TestOD_LeafSpentAtSendByOurOwnEarlierSettlementIsSettled(t *testing.T) {
	f := &fakeODChain{anchorTx: odAnchorTx, settleErr: fmt.Errorf("leaf 0xaa already consumed: %w", errLeafAlreadyConsumed),
		spentBy: odReplacementTx, spentFrom: odOwnAddr, spentByKnown: true}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Settled || out.TxHash != odReplacementTx {
		t.Fatalf("outcome %+v; want settled with this node's earlier settlement", out)
	}
}

// Hashes the sender broadcast while no caller was listening are consulted from its history: a
// replacement that REVERTED is found there and recorded as the member's failure.
func TestOD_RevertedReplacementFromTheSendersHistoryIsTheFailure(t *testing.T) {
	m := withOwnSettlement(odMember(1, odChain, 100), 7, odSettleTx)
	f := &fakeODChain{attested: true, history: map[uint64][]string{7: {odSettleTx, odReplacementTx}},
		statuses: map[string][3]bool{odReplacementTx: {true, true, true}}}
	out := settle(t, f, m)
	if !out.Reverted || out.TxHash != odReplacementTx || f.settleCalls != 0 {
		t.Fatalf("outcome %+v settle calls %d; want the replacement's revert recorded, nothing re-sent", out, f.settleCalls)
	}
}

// A key that cannot send (a transaction still in flight) marks the outcome busy, so the pass skips
// the rest of that chain instead of waiting on the same thing member after member.
func TestOD_BusyKeyIsReported(t *testing.T) {
	f := &fakeODChain{beginErr: &ChainWaitError{Label: "settle", Nonce: 3, Err: context.DeadlineExceeded}}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred || !out.KeyBusy {
		t.Fatalf("outcome %+v; want deferred with the key busy", out)
	}
	f = &fakeODChain{beginErr: &SenderUnavailableError{Err: errors.New("outbox corrupt")}}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred || !out.KeyBusy {
		t.Fatalf("an unavailable sender: outcome %+v; want deferred, never failed", out)
	}
}

// Who settles under an attested anchor is decided by who ATTESTED it, read from the chain - not by
// this node's memory. A node whose own attestation landed without it recording that (a crash, a wait
// that ran out) still settles; a node that recorded "I proved it" but whose attestation was NOT the
// one that landed does not.
func TestOD_TheChainsAttesterDecidesWhoSettles(t *testing.T) {
	m := odMember(1, odChain, 100) // no local record at all
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr}
	if out := settle(t, f, m); !out.Settled || f.settleCalls != 1 {
		t.Fatalf("own attestation, no local record: outcome %+v; want this node to settle", out)
	}
	m = odMember(1, odChain, 100)
	m.AnchorProved = true // believed it proved the anchor
	f = &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOtherAddr}
	if out := settle(t, f, m); !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("another validator's attestation, in its window: outcome %+v; want held, not settled", out)
	}
	f = &fakeODChain{attested: true, attesterUnknown: true}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("attester not in view: outcome %+v; want deferred", out)
	}
}

// This node's attestation reverted because another validator's landed first: the root is attested,
// but not by this node, so it releases to that validator instead of claiming to be the settler.
func TestOD_AttestedByAnotherValidatorIsDecidedFromTheChain(t *testing.T) {
	f := &fakeODChain{anchorTx: odAnchorTx, attester: odOtherAddr}
	m := odMember(1, odChain, 100)
	out, err := odOrchestrator(f).SettleOnDemandMember(context.Background(), m, func(context.Context, *BatchTree) error {
		return fmt.Errorf("submitting batch quorum proof: executeComprehensiveProof 0xab: %w", ErrAttestedByAnother)
	})
	if err != nil || !out.Deferred || m.AnchorProved || f.settleCalls != 0 {
		t.Fatalf("outcome %+v err %v member %+v; want held in the attester's window, not the settler", out, err, m)
	}
}

// The 2-hour prune never drops a member this validator has acted on: its settlement may still land,
// or it must settle under its own attestation. Such a member leaves the queue only through its outcome.
func TestOD_PruneKeepsMembersThisValidatorActedOn(t *testing.T) {
	m := NewBatchMempool(BatchMempoolConfig{})
	idle, sent, proved := odMember(1, odChain, 100), odMember(2, odChain, 101), odMember(3, odChain, 102)
	for _, p := range []*PendingBatchIntent{idle, sent, proved} {
		if err := m.AddOnDemand(p); err != nil {
			t.Fatal(err)
		}
	}
	m.NoteOnDemandProgress(odChain, sent.OperationID, func(p *PendingBatchIntent) {
		p.SettlementTx, p.SettlementNonce, p.SettlementNonceSet = odSettleTx, 9, true
	})
	m.NoteOnDemandProgress(odChain, proved.OperationID, func(p *PendingBatchIntent) { p.AnchorProved = true })

	pruned := m.PruneOnDemandOlderThan(time.Minute, time.Now().Add(3*time.Hour))
	if pruned != 1 || m.GetOnDemand(odChain, idle.OperationID) != nil {
		t.Fatalf("pruned %d; want only the member nobody acted on", pruned)
	}
	if m.GetOnDemand(odChain, sent.OperationID) == nil || m.GetOnDemand(odChain, proved.OperationID) == nil {
		t.Fatal("a member with a settlement in flight or an own attestation was pruned")
	}
}

// A member queued by an older binary carries a settlement hash but no nonce. A hash no node knows
// was dropped: it is not treated as in flight for ever. Who settles is then read from the chain.
func TestOD_LegacySettlementWithNoNonceIsNotInFlightForever(t *testing.T) {
	m := odMember(1, odChain, 100)
	m.SettlementTx = odSettleTx // legacy: no SettlementNonce
	f := &fakeODChain{attested: true, attester: odOwnAddr, settleTx: odReplacementTx}
	out := settle(t, f, m)
	if !out.Settled || f.settleCalls != 1 {
		t.Fatalf("outcome %+v settle calls %d; a dropped legacy settlement must not defer for ever", out, f.settleCalls)
	}
}

// A settlement whose first broadcast was definitively rejected put nothing in flight: its hash is
// removed from the member, so the next pass is not held waiting on it.
func TestOD_RejectedBroadcastLeavesNoSettlementInFlight(t *testing.T) {
	m := odMember(1, odChain, 100)
	o := odOrchestrator(&fakeODChain{})
	// What settleMember's broadcast hook and its NotBroadcast branch do, in order.
	o.noteOnDemandProgress(m, func(p *PendingBatchIntent) {
		p.SettlementTx, p.SettlementTxs = odSettleTx, []string{odSettleTx}
		p.SettlementNonce, p.SettlementNonceSet = 7, true
	})
	o.forgetUnbroadcastSettlement(m, odSettleTx)
	if m.SettlementNonceSet || len(m.SettlementTxs) != 0 || m.SettlementTx != "" {
		t.Fatalf("member %+v still claims a settlement that never left", m)
	}
}
