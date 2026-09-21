package execution

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

var odRoster3 = []common.Address{odOwnAddr, odOtherAddr, odThirdAddr}

func TestSettlementWindows_RotateFromTheAttester(t *testing.T) {
	w, err := newSettlementWindows(odT0, odRoster3, odOtherAddr, odChain, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	for j, want := range []common.Address{odOtherAddr, odThirdAddr, odOwnAddr, odOtherAddr} {
		if got := w.settler(j); got != want {
			t.Fatalf("window %d settler %s, want %s", j, got.Hex(), want.Hex())
		}
	}
	for _, c := range []struct {
		at   time.Duration
		want int
	}{{-time.Minute, 0}, {0, 0}, {SettlementWindow - time.Second, 0}, {SettlementWindow, 1}, {5*SettlementWindow + 1, 5}} {
		if got := w.index(odT0.Add(c.at)); got != c.want {
			t.Fatalf("index at T%+v = %d, want %d", c.at, got, c.want)
		}
	}
	if got, want := w.fence(0), odT0.Add(SettlementWindow-settlementFenceMargin); !got.Equal(want) {
		t.Fatalf("fence(0) %s, want %s", got, want)
	}
	if got, want := w.fence(2), odT0.Add(3*SettlementWindow-settlementFenceMargin); !got.Equal(want) {
		t.Fatalf("fence(2) %s, want %s", got, want)
	}
	// Every window's fence is inside the window: no settlement of window j can execute in j+1.
	for j := 0; j < 10; j++ {
		start := odT0.Add(time.Duration(j) * SettlementWindow)
		if !w.fence(j).After(start) || !w.fence(j).Before(start.Add(SettlementWindow)) {
			t.Fatalf("fence(%d) %s outside its window", j, w.fence(j))
		}
	}
}

// The anchor's attest call is open to anyone. An attester outside the roster starts the rotation at
// the member's election index, which every validator computes identically.
func TestSettlementWindows_OutsideAttesterUsesTheElection(t *testing.T) {
	outsider := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	op := [32]byte{7}
	w, err := newSettlementWindows(odT0, odRoster3, outsider, odChain, op)
	if err != nil {
		t.Fatal(err)
	}
	if want := odRoster3[onDemandLeaderIndex(odChain, op, 3)]; w.settler(0) != want {
		t.Fatalf("window 0 settler %s, want the elected %s", w.settler(0).Hex(), want.Hex())
	}
	if _, err := newSettlementWindows(time.Time{}, odRoster3, outsider, odChain, op); err == nil {
		t.Fatal("a schedule without an attestation time")
	}
	if _, err := newSettlementWindows(odT0, nil, outsider, odChain, op); err == nil {
		t.Fatal("a schedule without a roster")
	}
}

// Window 0 is the attester's. Its settlement carries window 0's fence as its expiresAt.
func TestOD_AttesterSettlesWithItsWindowsFence(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Settled || f.settleCalls != 1 {
		t.Fatalf("outcome %+v; want settled", out)
	}
	if want := odT0.Add(SettlementWindow - settlementFenceMargin); !f.lastFence.Equal(want) {
		t.Fatalf("fence %s, want %s", f.lastFence, want)
	}
}

// A fresh attestation by this node settles in window 0 under its fence too.
func TestOD_FreshAttestationSettlesUnderItsFence(t *testing.T) {
	f := &fakeODChain{settleTx: odSettleTx, anchorTx: odAnchorTx, verifyTx: odVerifyTx}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Settled || f.lastFence.IsZero() {
		t.Fatalf("outcome %+v fence %s; want settled under a fence", out, f.lastFence)
	}
}

// THE takeover. The attester died after attesting: nothing of it is on chain. In window 1, once a
// finalized block is past window 0's fence, window 1's settler settles - under window 1's fence.
func TestOD_DeadAttesterIsTakenOverInTheNextWindow(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odThirdAddr, // window 1 = own
		head:      odT0.Add(SettlementWindow + 2*time.Minute),
		finalized: odT0.Add(SettlementWindow + time.Minute)} // past fence(0) + the reorg margin
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Settled || f.settleCalls != 1 {
		t.Fatalf("outcome %+v; want this validator to take over and settle", out)
	}
	if want := odT0.Add(2*SettlementWindow - settlementFenceMargin); !f.lastFence.Equal(want) {
		t.Fatalf("fence %s, want window 1's %s", f.lastFence, want)
	}
	if want := odT0.Add(SettlementWindow - settlementFenceMargin + settlementReorgMargin); !f.priorUntil.Equal(want) {
		t.Fatalf("earlier windows scanned until %s, want window 0's fence plus the reorg margin %s", f.priorUntil, want)
	}
}

// Until a finalized block is past window 0's fence, the attester's settlement may still land; the
// next settler waits.
func TestOD_TakeoverWaitsForFinalityPastThePreviousFence(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odThirdAddr,
		head:      odT0.Add(SettlementWindow + time.Minute),
		finalized: odT0.Add(SettlementWindow - settlementFenceMargin + settlementReorgMargin)} // not past fence(0)+margin
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("outcome %+v; want held until finality passes the fence", out)
	}
}

// The attester did settle in its window and the settlement reverted: that attempt is on chain, it is
// the attester's outcome to record, and the next settler releases instead of executing again.
func TestOD_AnEarlierSettlersMinedAttemptIsItsOutcome(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odThirdAddr,
		head: odT0.Add(SettlementWindow + 2*time.Minute), finalized: odT0.Add(SettlementWindow + time.Minute),
		priorTx: odRevertTx, priorFrom: odThirdAddr, priorFound: true, priorReverted: true}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Released || f.settleCalls != 0 || len(f.costs) != 0 || f.failedLegs != 0 {
		t.Fatalf("outcome %+v settle=%d; want released with nothing sent or reported", out, f.settleCalls)
	}
}

// Another validator's window: hold, whatever this node recorded.
func TestOD_AnotherValidatorsWindowIsHeld(t *testing.T) {
	m := odMember(1, odChain, 100)
	m.AnchorProved = true
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr,
		head: odT0.Add(SettlementWindow + time.Minute), finalized: odT0.Add(SettlementWindow)} // window 1 = other
	out := settle(t, f, m)
	if !out.Deferred || out.Released || f.settleCalls != 0 {
		t.Fatalf("outcome %+v; want held for window 1's settler", out)
	}
}

// Too little of the window left to land a settlement before its fence: wait, do not send a
// transaction that would most likely revert on its expiresAt.
func TestOD_NoSettlementLateInTheWindow(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr,
		head: odT0.Add(SettlementWindow - settlementFenceMargin - settlementMinLanding)}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("outcome %+v; want deferred", out)
	}
}

// A settlement that reverted because it was mined after its own expiresAt never tried the intent. It
// is not the member's failure: nothing is reported and the member stays queued.
func TestOD_TimingRevertIsNotTheMembersFailure(t *testing.T) {
	f := &fakeODChain{settleTx: odRevertTx, settleErr: errSettlementReverted, anchorTx: odAnchorTx,
		timing: map[string]bool{odRevertTx: true}}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Deferred || out.Reverted || len(f.costs) != 0 || f.failedLegs != 0 {
		t.Fatalf("outcome %+v costs %v failed %d; want deferred and nothing reported", out, f.costs, f.failedLegs)
	}
}

// The same, found later among this node's own hashes: not an outcome; the window decides afresh.
func TestOD_OwnTimingRevertFromHistoryIsNotAnOutcome(t *testing.T) {
	m := odMember(1, odChain, 100)
	m.SettlementTxs = []string{odRevertTx}
	m.SettlementNonce, m.SettlementNonceSet = 9, true
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr,
		statuses: map[string][3]bool{odRevertTx: {true, true, true}}, timing: map[string]bool{odRevertTx: true}}
	out := settle(t, f, m)
	if out.Reverted || !out.Settled || f.settleCalls != 1 {
		t.Fatalf("outcome %+v; want the timing revert ignored and a fresh settlement", out)
	}
}

// A roster the anchor does not commit to decides nothing.
func TestOD_UnconfirmedRosterDefers(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr, rosterFailed: true}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("outcome %+v; want deferred", out)
	}
}

func mustLeaf(t *testing.T, m *PendingBatchIntent) BatchLeafInput {
	t.Helper()
	in, err := m.LeafInput()
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestTimingRevert(t *testing.T) {
	p := contracts.AccountProofV7{Timestamp: big.NewInt(100), ExpiresAt: big.NewInt(200)}
	for _, c := range []struct {
		at   uint64
		want bool
	}{{99, true}, {100, false}, {200, false}, {201, true}} {
		if got, _ := timingRevert(p, c.at); got != c.want {
			t.Fatalf("mined at %d: timing=%t, want %t", c.at, got, c.want)
		}
	}
}

// The proof a settlement carries is read back from its calldata exactly - it is how a revert's cause
// and an earlier settler's attempt are judged.
func TestSettlementProofOfRoundTrip(t *testing.T) {
	if certenAccountV7ABIErr != nil {
		t.Fatal(certenAccountV7ABIErr)
	}
	want := contracts.AccountProofV7{
		AdiURL: "acc://a.acme", AnchorId: [32]byte{9}, MerkleProof: [][32]byte{},
		OperationID: [32]byte{3}, Timestamp: big.NewInt(1000), ExpiresAt: big.NewInt(1480),
		Nonce: big.NewInt(0), RequiredLevel: 1,
	}
	data, err := certenAccountV7ABI.Pack("executeGovernanceProofDirect",
		common.HexToAddress("0x1111111111111111111111111111111111111111"), big.NewInt(0), []byte{0xde, 0xad}, want)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := settlementProofOf(data)
	if !ok || got.AnchorId != want.AnchorId || got.OperationID != want.OperationID ||
		got.Timestamp.Cmp(want.Timestamp) != 0 || got.ExpiresAt.Cmp(want.ExpiresAt) != 0 {
		t.Fatalf("decoded %+v ok=%t; want %+v", got, ok, want)
	}
	if _, ok := settlementProofOf([]byte{1, 2, 3, 4, 5}); ok {
		t.Fatal("decoded a proof from calldata that is not a settlement")
	}
}

func TestIsCallVerdict(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{errors.New("execution reverted"), true},
		{rpcErr{3, "execution reverted: leaf mismatch"}, true},
		{rpcErr{-32000, "header not found"}, false},
		{rpcErr{-32005, "rate limited"}, false},
		{rpcErr{-32603, "internal error"}, false},
		{errors.New("abi: attempting to unmarshall an empty string while arguments are expected"), false},
		{errors.New("no contract code at given address"), false},
		{errors.New("Post \"https://rpc\": dial tcp: i/o timeout"), false},
		{errors.New("429 Too Many Requests"), false},
		{context.DeadlineExceeded, false},
	} {
		if got := isCallVerdict(c.err); got != c.want {
			t.Fatalf("%v: verdict=%t, want %t", c.err, got, c.want)
		}
	}
}

// rpcErr is a JSON-RPC error body as go-ethereum surfaces it: a code, a message and data.
type rpcErr struct {
	code int
	msg  string
}

func (e rpcErr) Error() string          { return e.msg }
func (e rpcErr) ErrorCode() int         { return e.code }
func (e rpcErr) ErrorData() interface{} { return "0x" }

var _ rpc.Error = rpcErr{}
var _ rpc.DataError = rpcErr{}

// A taker acts only once finality passes the previous fence. If a window were shorter than the
// finality lag plus the margins, no taker could ever act inside its own window and a dead attester's
// member would never be taken over. 21 minutes is the largest lag measured on the live testnets.
func TestSettlementWindowExceedsFinalityLag(t *testing.T) {
	const measuredLag = 21 * time.Minute
	if SettlementWindow-settlementFenceMargin-settlementMinLanding-settlementReorgMargin <= measuredLag {
		t.Fatalf("window %s leaves no room to act after a %s finality lag", SettlementWindow, measuredLag)
	}
}

// Validators whose rosters are configured in different orders still get one rotation.
func TestSettlementRosterIsOrderIndependent(t *testing.T) {
	a := sortedRoster([]common.Address{odThirdAddr, odOwnAddr, odOtherAddr})
	b := sortedRoster([]common.Address{odOtherAddr, odThirdAddr, odOwnAddr})
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("rosters differ at %d: %v vs %v", i, a, b)
		}
		if i > 0 && bytes.Compare(a[i-1][:], a[i][:]) >= 0 {
			t.Fatalf("not ascending: %v", a)
		}
	}
}

// The live defect's other half: the attester reverted, recorded the failure and is now unreachable. Its
// revert is in the finalized chain, so the taker finds it there and releases - it never executes a
// member whose failure is on record.
func TestOD_RecordedRevertOfAnUnreachableAttesterIsFoundOnChain(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odThirdAddr,
		head: odT0.Add(SettlementWindow + 2*time.Minute), finalized: odT0.Add(SettlementWindow + time.Minute),
		priorTx: odRevertTx, priorFrom: odThirdAddr, priorFound: true, priorReverted: true}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Released || f.settleCalls != 0 {
		t.Fatalf("outcome %+v settle=%d; want released", out, f.settleCalls)
	}
}

// This validator's own earlier attempt, which its record lost: found on chain, it is recorded now by
// this validator, not released to nobody.
func TestOD_OwnAttemptFoundOnChainIsRecorded(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr,
		head:      odT0.Add(3*SettlementWindow + 2*time.Minute), // window 3 = own again (roster of 3)
		finalized: odT0.Add(3*SettlementWindow + time.Minute),
		priorTx:   odRevertTx, priorFrom: odOwnAddr, priorFound: true, priorReverted: true}
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Reverted || out.TxHash != odRevertTx || f.settleCalls != 0 || f.failedLegs != 1 {
		t.Fatalf("outcome %+v; want this validator's own revert recorded", out)
	}
}

// Window 0 never needs the finalized block: the attester settles its fresh attestation even if the
// provider cannot serve "finalized".
func TestOD_WindowZeroDoesNotReadFinality(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odOwnAddr, finalizedErr: errors.New("finalized not supported")}
	if out := settle(t, f, odMember(1, odChain, 100)); !out.Settled {
		t.Fatalf("outcome %+v; want settled without a finality read", out)
	}
}

// A settlement reached without a fence is a coding error: nothing is sent and nothing is recorded -
// in particular no failure.
func TestOD_ZeroFenceDefersWithoutAFailure(t *testing.T) {
	f := &fakeODChain{settleTx: odSettleTx}
	tree, err := BuildBatchTree(odChain, []BatchLeafInput{mustLeaf(t, odMember(1, odChain, 100))}, 100)
	if err != nil {
		t.Fatal(err)
	}
	out, err := odOrchestrator(f).settleAndClassify(context.Background(), f, odMember(1, odChain, 100), tree, &OnDemandOutcome{})
	if err != nil || !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("outcome %+v err %v; want deferred, nothing sent", out, err)
	}
}

// Every validator that reaches an attested member marks it, and the memory-backstop prune then keeps
// it: a later settlement window may be this validator's.
func TestOD_AttestedMemberIsHeldPastTheTTL(t *testing.T) {
	pool := NewBatchMempool(BatchMempoolConfig{})
	m := odMember(1, odChain, 100)
	if err := pool.AddOnDemand(m); err != nil {
		t.Fatal(err)
	}
	f := &fakeODChain{attested: true, attester: odOtherAddr}
	o := odOrchestrator(f)
	o.mempool = pool
	if out, err := o.SettleOnDemandMember(context.Background(), pool.PendingOnDemand(odChain)[0], proveOK); err != nil || !out.Deferred {
		t.Fatalf("outcome %+v err %v", out, err)
	}
	if n := pool.PruneOnDemandOlderThan(time.Nanosecond, time.Now().Add(3*time.Hour)); n != 0 {
		t.Fatalf("pruned %d attested member(s); a later window may be this validator's", n)
	}
}

// Only a roster validator's transaction to the member's account is a candidate. Transaction types the
// client cannot decode never reach this point: the scan reads raw JSON.
func TestSettlementCandidates(t *testing.T) {
	acct := common.HexToAddress("0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B")
	other := common.HexToAddress("0x1111111111111111111111111111111111111111")
	outsider := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	txs := []scanTx{
		{Hash: common.Hash{1}, From: odOtherAddr, To: &acct},
		{Hash: common.Hash{2}, From: outsider, To: &acct},
		{Hash: common.Hash{3}, From: odOtherAddr, To: &other},
		{Hash: common.Hash{4}, From: odOwnAddr, To: nil},
		{Hash: common.Hash{5}, From: odOwnAddr, To: &acct},
	}
	got := settlementCandidates(txs, acct, odRoster3)
	if len(got) != 2 || got[0].Hash != (common.Hash{1}) || got[1].Hash != (common.Hash{5}) {
		t.Fatalf("candidates %+v", got)
	}
}

// The pre-check tells a validator whether an attested member is its business now, and makes the next
// window's settler scan ahead, lock-free, so its own turn is short.
func TestOD_PrecheckAndPrescan(t *testing.T) {
	m := odMember(1, odChain, 100)
	// Window 0 is the attester's (other); window 1 is third; roster [own, other, third].
	f := &fakeODChain{attested: true, attester: odOtherAddr, head: odT0.Add(time.Minute)}
	needed, err := odOrchestrator(f).OnDemandMemberNeedsThisValidator(context.Background(), m)
	if err != nil || needed || f.prescans != 0 {
		t.Fatalf("needed=%t err=%v prescans=%d; own is neither this window's nor the next", needed, err, f.prescans)
	}
	if !m.AttestedSeen {
		t.Fatal("an attested member was not marked held")
	}
	f = &fakeODChain{attested: true, attester: odThirdAddr, head: odT0.Add(time.Minute)} // window 1 = own
	needed, err = odOrchestrator(f).OnDemandMemberNeedsThisValidator(context.Background(), odMember(1, odChain, 100))
	if err != nil || needed || f.prescans != 1 {
		t.Fatalf("needed=%t err=%v prescans=%d; the next settler pre-scans but does not act yet", needed, err, f.prescans)
	}
	f = &fakeODChain{attested: true, attester: odThirdAddr, head: odT0.Add(SettlementWindow + time.Minute)}
	if needed, _ := odOrchestrator(f).OnDemandMemberNeedsThisValidator(context.Background(), odMember(1, odChain, 100)); !needed {
		t.Fatal("own window: not reported as needed")
	}
	f = &fakeODChain{attested: true, consumed: true, attester: odOtherAddr}
	if needed, _ := odOrchestrator(f).OnDemandMemberNeedsThisValidator(context.Background(), odMember(1, odChain, 100)); !needed {
		t.Fatal("a spent leaf must bring every holder to release its copy")
	}
	f = &fakeODChain{attested: false}
	if needed, _ := odOrchestrator(f).OnDemandMemberNeedsThisValidator(context.Background(), odMember(1, odChain, 100)); needed {
		t.Fatal("an unattested member is the anchoring leader's, not this validator's")
	}
}
