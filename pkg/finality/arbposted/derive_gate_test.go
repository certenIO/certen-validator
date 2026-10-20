// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// delayedDeposit builds a block made of one ETH-deposit delayed message k and the evidence that carries it.
func delayedDeposit(k uint64, kind uint8, data []byte, blockTxs func(want [][]byte) [][]byte) (Evidence, common.Hash, common.Hash, Delayed) {
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	msg := Delayed{MsgKind: kind, Sender: user, MsgBlockNumber: 10, MsgTimestamp: 20, Data: data, K: k}
	prev := common.Hash{}
	if k > 0 {
		prev = crypto.Keccak256Hash([]byte("predecessor"))
	}
	mh := DelayedMessageHash(msg)
	accK := crypto.Keccak256Hash(prev[:], mh[:])
	want, _ := deriveDelayed(421614, msg)
	txs := blockTxs(want)
	e := calldataEvidence(txs, payloadOf(seg(segDelayed, nil)), 3, [5]uint64{1, 2, 3, 4, k + 1}, accK)
	e.Delayed = &msg
	return e, accK, prev, msg
}

func depositData() []byte {
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	return append(append([]byte(nil), to[:]...), common.LeftPadBytes(big.NewInt(77).Bytes(), 32)...)
}

func withInternal(want [][]byte) [][]byte { return append([][]byte{{0x6a, 0xc0}}, want...) }

// Both accumulators the delayed proof needs (k and k-1) must be PROVEN: a missing node is a state-proof failure, not a mismatch.
func TestTheDelayedAccumulatorsOfKAndItsPredecessorMustBeProven(t *testing.T) {
	const k = 6
	e, accK, prev, _ := delayedDeposit(k, msgKindEthDeposit, depositData(), withInternal)
	dm := map[uint64]common.Hash{k: accK, k - 1: prev}
	if _, err := runState(t, e, dm, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
	defer func() { skipProve = nil }()
	for name, slot := range map[string]uint64{"k": k, "k-1": k - 1} {
		skipProve = []common.Hash{arrayElementSlot(6, slot)}
		if _, err := runState(t, e, dm, nil); canon(err) != want("l1_state_proof_invalid", "which", "slot") {
			t.Errorf("the slot of %s left out of the nodes: %s", name, canon(err))
		}
	}
}

// The predecessor is read for every k >= 1 and for no other: k = 1 reads slot 0, k = 0 reads nothing (a value at index 2^64-1, which an
// unsigned wrap of k-1 would read, must not be taken for a predecessor).
func TestThePredecessorIsReadForEveryKFromOneAndNotForZero(t *testing.T) {
	e1, acc1, prev1, _ := delayedDeposit(1, msgKindEthDeposit, depositData(), withInternal)
	if _, err := runState(t, e1, map[uint64]common.Hash{1: acc1, 0: prev1}, nil); err != nil {
		t.Fatalf("k = 1: %v", err)
	}
	e0, acc0, _, _ := delayedDeposit(0, msgKindEthDeposit, depositData(), withInternal)
	bogus := crypto.Keccak256Hash([]byte("not a predecessor"))
	if _, err := runState(t, e0, map[uint64]common.Hash{0: acc0, math.MaxUint64: bogus}, nil); err != nil {
		t.Fatalf("k = 0 with a value at index 2^64-1: %v", err)
	}
}

// A delayed message kind with no derivation stays unproven even when the block holds nothing but internal transactions (the empty
// derivation would otherwise equal the empty block).
func TestAKindWithNoDerivationIsUnprovenEvenForABlockOfInternalTransactionsOnly(t *testing.T) {
	e := func() Evidence {
		x, _, _, _ := delayedDeposit(4, 13, []byte{1, 2, 3}, func([][]byte) [][]byte { return [][]byte{{0x6a, 0xc0}} })
		return x
	}()
	// the accumulators of kind 13 are built by the helper from the message itself
	msg := *e.Delayed
	mh := DelayedMessageHash(msg)
	prev := crypto.Keccak256Hash([]byte("predecessor"))
	accK := crypto.Keccak256Hash(prev[:], mh[:])
	e.DelayedAcc = accK
	_, err := runState(t, e, map[uint64]common.Hash{4: accK, 3: prev}, nil)
	if canon(err) != want("l1_posted_delayed_origin_unproven", "block_tx_types", []uint64{0x6a}, "header_nonce", uint64(7), "k", uint64(4), "message_kind", uint8(13)) {
		t.Fatalf("%s", canon(err))
	}
}

// Nested messages of a sequencer batch: the largest nested message that fits in a top-level message within the size limit is read in
// full, one byte more makes the TOP-LEVEL message larger than the limit and Nitro drops the whole message (ParseL2Transactions), and the
// first byte of a signed transaction is judged at the 0xc0 boundary. (A nested message of the limit itself cannot sit inside a
// top-level message within the limit.)
func TestNestedSizeLimitAndSignedTransactionFirstByteBoundaries(t *testing.T) {
	t1 := legacyTx(1)
	tx := func(n int) []byte { return append([]byte{l2SignedTx, 0xc0}, bytes.Repeat([]byte{0}, n-2)...) } // a message of n bytes
	// the top-level message is 1 (kind) + 8 + len(first) + 8 + n bytes
	biggest := maxL2MessageSize - 1 - 8 - len(signedTxMsg(t1)) - 8
	fits := batchMsg(signedTxMsg(t1), tx(biggest))
	if len(fits) != maxL2MessageSize {
		t.Fatalf("fixture: %d bytes, want %d", len(fits), maxL2MessageSize)
	}
	if got, ok := parseL2(fits, 0); !ok || len(got) != 2 {
		t.Errorf("the largest nested message that fits the top-level limit: ok %v, %d txs", ok, len(got))
	}
	if got, ok := parseL2(batchMsg(signedTxMsg(t1), tx(biggest+1)), 0); ok || got != nil {
		t.Errorf("a nested message one byte more makes the top-level message too large: ok %v, %d txs", ok, len(got))
	}
	for _, n := range []int{maxL2MessageSize, maxL2MessageSize + 1} {
		if got, ok := parseL2(batchMsg(signedTxMsg(t1), tx(n)), 0); ok || got != nil {
			t.Errorf("a nested message of %d bytes: ok %v, %d txs", n, ok, len(got))
		}
	}
	// a length prefix above the limit (no data behind it) ends the batch quietly with what it has
	if got, ok := parseL2(append(batchMsg(signedTxMsg(t1)), binary.BigEndian.AppendUint64(nil, maxL2MessageSize+1)...), 0); !ok || len(got) != 1 {
		t.Errorf("an oversize nested length with no data: ok %v, %d txs", ok, len(got))
	}
	for name, c := range map[string]struct {
		tx []byte
		ok bool
	}{"0xc0": {[]byte{0xc0}, true}, "0xc1": {[]byte{0xc1, 0x00}, true}, "0xbf": {[]byte{0xbf, 0x00}, false}, "0xbe": {[]byte{0xbe}, false}} {
		got, ok := parseL2(signedTxMsg(c.tx), 0)
		if ok != c.ok || (ok && len(got) != 1) {
			t.Errorf("signed tx starting %s: ok %v, %d txs", name, ok, len(got))
		}
	}
	// a nested length that cannot be a uint64 count of bytes (the top bit set) also ends the batch quietly
	huge := append(append([]byte(nil), batchMsg(signedTxMsg(t1))...), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00)
	if got, ok := parseL2(huge, 0); !ok || len(got) != 1 {
		t.Errorf("a nested length with every bit set: ok %v, %d txs", ok, len(got))
	}
}
