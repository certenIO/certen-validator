package execution

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestBatchExecutionCommitment_MatchesSolidity pins the Go batch commitment to the exact
// value produced by CertenAccountV6.computeBatchCommitment() in Solidity.
//
// The identical vector is asserted by
// certen-contracts/evm/test/CertenAccountV6BatchVector.t.sol
// (test_BatchCommitmentVector). If either encoding drifts, one of the two tests fails —
// otherwise the validator would mint batch commitments the account can never satisfy, and
// every batch would revert on-chain after the anchor had already been paid for.
func TestBatchExecutionCommitment_MatchesSolidity(t *testing.T) {
	const sepoliaChainID = int64(11155111)

	calls := []BatchCall{
		{
			Target: common.HexToAddress("0x1111111111111111111111111111111111111111"),
			Value:  big.NewInt(1),
			Data:   []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			Target: common.HexToAddress("0x2222222222222222222222222222222222222222"),
			Value:  new(big.Int).SetUint64(1_000_000_000_000_000_000), // 1 ether
			Data:   []byte{},
		},
	}

	const want = "be97a82752d8d731bf1cd7e0a1d7a13ed6b5d79dbe6447be6267b80018fa2a0b"

	got := computeBatchExecutionCommitment(sepoliaChainID, calls)
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("batch commitment mismatch\n got: %s\nwant: %s", hex.EncodeToString(got[:]), want)
	}
}

// TestBatchExecutionCommitment_OrderIsSignificant confirms the commitment binds an ORDERED
// sequence. CertenAccountV6 rejects a reordered batch, so the validator must never treat two
// orderings as interchangeable when selecting which anchor to spend.
func TestBatchExecutionCommitment_OrderIsSignificant(t *testing.T) {
	a := BatchCall{Target: common.HexToAddress("0xaa"), Value: big.NewInt(1), Data: []byte{0x01}}
	b := BatchCall{Target: common.HexToAddress("0xbb"), Value: big.NewInt(2), Data: []byte{0x02}}

	forward := computeBatchExecutionCommitment(1, []BatchCall{a, b})
	reversed := computeBatchExecutionCommitment(1, []BatchCall{b, a})

	if forward == reversed {
		t.Fatal("reordering a batch must change its commitment")
	}
}

// TestBatchExecutionCommitment_DisjointFromSingle confirms the domain tag keeps batch
// commitments separate from single-call ones. Without this, a one-element batch could be
// spent through the single-call path (or vice versa), bypassing the per-element authority
// checks that only the batch path applies.
func TestBatchExecutionCommitment_DisjointFromSingle(t *testing.T) {
	target := common.HexToAddress("0x1111111111111111111111111111111111111111")
	value := big.NewInt(1)
	data := []byte{0xde, 0xad, 0xbe, 0xef}

	single := computeExecutionCommitment(11155111, target, value, data)
	batch := computeBatchExecutionCommitment(11155111, []BatchCall{
		{Target: target, Value: value, Data: data},
	})

	if single == batch {
		t.Fatal("single and batch commitments must not collide for the same call")
	}
}

// TestBatchExecutionCommitment_ChainBound confirms a batch authorized for one chain cannot be
// replayed on another.
func TestBatchExecutionCommitment_ChainBound(t *testing.T) {
	calls := []BatchCall{
		{Target: common.HexToAddress("0x1111"), Value: big.NewInt(1), Data: []byte{0x01}},
	}

	if computeBatchExecutionCommitment(1, calls) == computeBatchExecutionCommitment(11155111, calls) {
		t.Fatal("batch commitment must be bound to the chain id")
	}
}

// TestBatchExecutionCommitment_NilValueIsZero confirms a nil *big.Int encodes as zero rather
// than panicking, matching how the single-call path already treats nil.
func TestBatchExecutionCommitment_NilValueIsZero(t *testing.T) {
	target := common.HexToAddress("0x1111")

	withNil := computeBatchExecutionCommitment(1, []BatchCall{{Target: target, Value: nil, Data: nil}})
	withZero := computeBatchExecutionCommitment(1, []BatchCall{{Target: target, Value: big.NewInt(0), Data: []byte{}}})

	if withNil != withZero {
		t.Fatal("nil value must encode identically to zero")
	}
}
