package execution

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"path/filepath"
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
	got := w.earlierSettlers(4, odOwnAddr) // windows 0..3: other, third, own, other
	if len(got) != 2 || got[0] != odOtherAddr || got[1] != odThirdAddr {
		t.Fatalf("earlier settlers %v", got)
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
		head:      odT0.Add(SettlementWindow + time.Minute),
		finalized: odT0.Add(SettlementWindow - time.Minute)} // past fence(0) = T+8m
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Settled || f.settleCalls != 1 {
		t.Fatalf("outcome %+v; want this validator to take over and settle", out)
	}
	if want := odT0.Add(2*SettlementWindow - settlementFenceMargin); !f.lastFence.Equal(want) {
		t.Fatalf("fence %s, want window 1's %s", f.lastFence, want)
	}
	if len(f.priorAsked) != 1 || f.priorAsked[0] != odThirdAddr {
		t.Fatalf("asked %v for earlier attempts; want the attester", f.priorAsked)
	}
}

// Until a finalized block is past window 0's fence, the attester's settlement may still land; the
// next settler waits.
func TestOD_TakeoverWaitsForFinalityPastThePreviousFence(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odThirdAddr,
		head:      odT0.Add(SettlementWindow + time.Minute),
		finalized: odT0.Add(SettlementWindow - settlementFenceMargin)} // exactly at fence(0): not past
	out := settle(t, f, odMember(1, odChain, 100))
	if !out.Deferred || f.settleCalls != 0 {
		t.Fatalf("outcome %+v; want held until finality passes the fence", out)
	}
}

// The attester did settle in its window and the settlement reverted: that attempt is on chain, it is
// the attester's outcome to record, and the next settler releases instead of executing again.
func TestOD_AnEarlierSettlersMinedAttemptIsItsOutcome(t *testing.T) {
	f := &fakeODChain{attested: true, settleTx: odSettleTx, attester: odThirdAddr,
		head: odT0.Add(SettlementWindow + time.Minute), finalized: odT0.Add(SettlementWindow),
		priorTx: odRevertTx, priorFrom: odThirdAddr, priorFound: true}
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

// An on-demand settlement is never sent without a fence.
func TestOD_SettlementWithoutAFenceIsRefused(t *testing.T) {
	f := &fakeODChain{settleTx: odSettleTx}
	tree, err := BuildBatchTree(odChain, []BatchLeafInput{mustLeaf(t, odMember(1, odChain, 100))}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := odOrchestrator(f).settleAndClassify(context.Background(), f, odMember(1, odChain, 100), tree, &OnDemandOutcome{}); err == nil || f.settleCalls != 0 {
		t.Fatalf("err %v settle calls %d; want refused before sending", err, f.settleCalls)
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

// The evidence a validator serves is every hash its outbox holds for the member's settlement - and
// nothing else's.
func TestOutboxHashesForOwner(t *testing.T) {
	o, err := openTxOutbox(filepath.Join(t.TempDir(), "o.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*outboxEntry{
		{Nonce: 5, Owner: "settle:a", Hashes: []string{"0x05a", "0x05b"}},
		{Nonce: 3, Owner: "settle:a", Hashes: []string{"0x03"}},
		{Nonce: 4, Owner: "settle:b", Hashes: []string{"0x04"}},
	} {
		if err := o.put(e); err != nil {
			t.Fatal(err)
		}
	}
	got := o.hashesForOwner("settle:a")
	if len(got) != 3 || got[0] != "0x03" || got[1] != "0x05a" || got[2] != "0x05b" {
		t.Fatalf("hashes %v", got)
	}
	if len(o.hashesForOwner("")) != 0 {
		t.Fatal("hashes for no owner")
	}
}

func TestIsCallVerdict(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{errors.New("execution reverted"), true},
		{errors.New("abi: attempting to unmarshall an empty string while arguments are expected"), true},
		{errors.New("no contract code at given address"), true},
		{errors.New("Post \"https://rpc\": dial tcp: i/o timeout"), false},
		{errors.New("429 Too Many Requests"), false},
		{context.DeadlineExceeded, false},
	} {
		if got := isCallVerdict(c.err); got != c.want {
			t.Fatalf("%v: verdict=%t, want %t", c.err, got, c.want)
		}
	}
	var _ rpc.DataError // the typed revert error is also a verdict
}

// A taker acts only once finality passes the previous fence. If a window were shorter than the
// finality lag plus the margins, no taker could ever act inside its own window and a dead attester's
// member would never be taken over. 21 minutes is the largest lag measured on the live testnets.
func TestSettlementWindowExceedsFinalityLag(t *testing.T) {
	const measuredLag = 21 * time.Minute
	if SettlementWindow-settlementFenceMargin-settlementMinLanding <= measuredLag {
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
