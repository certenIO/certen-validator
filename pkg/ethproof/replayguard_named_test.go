// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

func namedOf(w *replayworld.World, state, reason string, f func(st *ethproof.ReplayNamedState)) *ethproof.ReplayGuardEvidence {
	st := &ethproof.ReplayNamedState{State: state, Reason: reason, ChainID: replayworld.ChainID, TxHash: w.Tx.Hash(),
		BlockNumber: w.HeaderN.Number.Uint64(), BlockHash: w.HeaderN.Hash(), Contract: w.Contract}
	if f != nil {
		f(st)
	}
	return &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: st}
}

func judgeNamed(w *replayworld.World, ev *ethproof.ReplayGuardEvidence) (*ethproof.ReplayGuardCheck, error) {
	return ev.VerifyAgainst(w.HeaderN, w.Tx, true, w.Receipt.Logs)
}

func wantRefused(t *testing.T, what string, err error, reason string) {
	t.Helper()
	var re *ethproof.ReplayError
	if !errors.As(err, &re) || re.Reason != reason {
		t.Fatalf("%s: want refused {%s}, got %v", what, reason, err)
	}
}

// V-R10B note: a named s6_replay_refuted{slot_set_at_parent} states that the slot was already 1 at the parent. It is
// stated only when the Before it carries verifies: the parent header is the settlement block's parent and the proof
// proves the slot of the receipt's LeafConsumed key 1 at its state root. Without it, or with another world's, it is
// refused.
func TestANamedRefutationIsStatedOnlyWithItsVerifiedBefore(t *testing.T) {
	set := replayworld.New(t, replayworld.Opts{BeforeValue: big.NewInt(1)})
	other := replayworld.New(t, replayworld.Opts{BeforeValue: big.NewInt(1), BeforeCode: []byte{0x60, 0x00}})
	unset := replayworld.New(t, replayworld.Opts{})

	chk, err := judgeNamed(set, namedOf(set, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent,
		func(st *ethproof.ReplayNamedState) { st.Before = set.Proof.Before }))
	if err != nil || chk.State != ethproof.ReplayRefuted || !chk.BeforeVerified {
		t.Fatalf("a refutation carrying its own verified Before: want stated with BeforeVerified, got %+v %v", chk, err)
	}
	_, err = judgeNamed(set, namedOf(set, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent, nil))
	wantRefused(t, "a refutation without its Before", err, ethproof.ReasonProofDoesNotVerify)
	_, err = judgeNamed(set, namedOf(set, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent,
		func(st *ethproof.ReplayNamedState) { st.Before = other.Proof.Before }))
	wantRefused(t, "a refutation carrying another chain's parent", err, ethproof.ReasonParentHeaderUnproven)
	_, err = judgeNamed(unset, namedOf(unset, ethproof.ReplayRefuted, ethproof.ReasonSlotSetAtParent,
		func(st *ethproof.ReplayNamedState) { st.Before = unset.Proof.Before }))
	wantRefused(t, "a refutation whose Before proves the slot 0", err, ethproof.ReasonProofDoesNotVerify)
}

// V-R10B note: a named state's chainId and contract are held to the settlement inside VerifyAgainst (the vectors'
// verifier), not only at layer 6.
func TestANamedStateIsHeldToTheSettlementsChainAndContract(t *testing.T) {
	w := replayworld.New(t, replayworld.Opts{})
	if _, err := judgeNamed(w, namedOf(w, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable, nil)); err != nil {
		t.Fatalf("the honest named state: %v", err)
	}
	_, err := judgeNamed(w, namedOf(w, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable,
		func(st *ethproof.ReplayNamedState) { st.ChainID = replayworld.ChainID + 1 }))
	wantRefused(t, "a named state of another chain", err, ethproof.ReasonContractMismatch)
	_, err = judgeNamed(w, namedOf(w, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable,
		func(st *ethproof.ReplayNamedState) {
			st.Contract = common.HexToAddress("0x00000000000000000000000000000000000000aa")
		}))
	wantRefused(t, "a named state of another contract", err, ethproof.ReasonContractMismatch)
	// The capture names receipt_unavailable before it has the transaction: no contract is known, none is stated.
	if _, err := judgeNamed(w, namedOf(w, ethproof.ReplayUnproven, ethproof.ReasonReceiptUnavailable,
		func(st *ethproof.ReplayNamedState) { st.Contract = common.Address{} })); err != nil {
		t.Fatalf("receipt_unavailable without a contract: %v", err)
	}
	_, err = judgeNamed(w, namedOf(w, ethproof.ReplayUnproven, ethproof.ReasonStateUnavailable,
		func(st *ethproof.ReplayNamedState) { st.Contract = common.Address{} }))
	wantRefused(t, "state_unavailable with no contract stated", err, ethproof.ReasonContractMismatch)
}

// V-R10B note (header hashing): SPEC §4 hashes the raw header RLP. A header is accepted only in its canonical encoding,
// so the raw bytes' hash and the decoded header's hash are the same header: a non-canonical encoding (a long-form list
// prefix for the same fields) is refused.
func TestANonCanonicalHeaderEncodingIsRefused(t *testing.T) {
	w := replayworld.New(t, replayworld.Opts{After: 1})
	raw := []byte(w.Proof.Headers[0])
	nc := nonCanonicalList(t, raw)
	if bytes.Equal(nc, raw) {
		t.Fatal("the non-canonical form equals the canonical one")
	}
	p := *w.Proof
	p.Headers = append(p.Headers[:0:0], nc)
	ev := &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: &p}
	_, err := ev.VerifyAgainst(w.HeaderN, w.Tx, true, w.Receipt.Logs)
	wantRefused(t, "a non-canonical header", err, ethproof.ReasonProofDoesNotVerify)
}

// nonCanonicalList re-encodes an RLP list with a list prefix one byte longer than needed (a leading zero length byte).
func nonCanonicalList(t *testing.T, raw []byte) []byte {
	t.Helper()
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		t.Fatal(err)
	}
	n := len(content)
	var lenBytes []byte
	for v := n; v > 0; v >>= 8 {
		lenBytes = append([]byte{byte(v)}, lenBytes...)
	}
	lenBytes = append([]byte{0}, lenBytes...)
	out := append([]byte{byte(0xf7 + len(lenBytes))}, lenBytes...)
	return append(out, content...)
}

// V-R10B note: a panic inside Bind's goroutine becomes the named state of the settlement, never a crash of the
// observer process.
func TestAPanicInBindIsANamedState(t *testing.T) {
	w := replayworld.New(t, replayworld.Opts{})
	store := ethproof.NewReplayGuardStore(16)
	var panicked int32
	cfg := ethproof.ReplayCaptureConfig{ChainID: replayworld.ChainID, Budget: 50 * time.Millisecond, Poll: time.Millisecond,
		Logf: func(format string, args ...interface{}) {
			if strings.Contains(format, "does not hold against the proven settlement") {
				atomic.StoreInt32(&panicked, 1)
				panic("logger failed")
			}
		}}
	c := ethproof.NewReplayGuardCapturer(cfg, store)
	// RB10-B8 D2: a capture that stated no block is now re-stated from the proven settlement and holds, so the evidence that
	// does not hold is one that states another block (a state of block 7, the settlement is in another).
	store.Put(replayworld.ChainID, w.Tx.Hash(), &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{
		State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: replayworld.ChainID, TxHash: w.Tx.Hash(),
		BlockNumber: 7, BlockHash: common.Hash{7}, Contract: w.Contract, Detail: "captured at another block"}}, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Bind(w.Settlement)
	for {
		ev, bound, ok := store.Get(replayworld.ChainID, w.Tx.Hash())
		if ok && bound {
			if atomic.LoadInt32(&panicked) == 0 {
				t.Fatal("the logger never ran")
			}
			if ev.State == nil || ev.State.Reason == "" || !strings.Contains(ev.State.Detail, "logger failed") {
				t.Fatalf("the panic is not the named state: %+v", ev.State)
			}
			return
		}
		if ctx.Err() != nil {
			t.Fatal("Bind never stored a result")
		}
		time.Sleep(time.Millisecond)
	}
}
