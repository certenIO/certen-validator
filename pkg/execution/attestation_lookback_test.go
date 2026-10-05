package execution

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// RB7-ARB-F1: the attestation search stopped a fixed 60,000 blocks before the attempt. On Arbitrum Sepolia (~4 blocks
// a second) that is about four hours, so an anchor attested 100,000 blocks (about seven hours) before a reverted
// attempt read as "not attested before the attempt" although it was. The search now runs back to the anchor's own
// creation time, on any chain.
func arbitrumLikeTime(n uint64) uint64 { return 1_791_000_000 + n/4 }

func TestAnchorAttestedHoursBeforeTheAttemptOnArbitrum(t *testing.T) {
	anchor := common.HexToAddress("0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6")
	id := [32]byte{0xa7}
	const created, attested, attempt = 315_899_990, 315_900_000, 316_000_000
	receipt := &types.Receipt{BlockNumber: big.NewInt(attempt), TransactionIndex: 2}
	chain := &logChain{logs: []types.Log{{BlockNumber: attested}}, blockTime: arbitrumLikeTime}
	ok, err := anchorAttestedBefore(context.Background(), chain, anchor, id, arbitrumLikeTime(created), receipt)
	if err != nil || !ok {
		t.Fatalf("an attestation %d blocks (%d s) before the attempt was not found: ok=%v err=%v", attempt-attested,
			arbitrumLikeTime(attempt)-arbitrumLikeTime(attested), ok, err)
	}
}

// The search never runs before the anchor existed: with no attestation, it ends at the first block of the anchor's
// creation second, not at genesis.
func TestAttestationSearchStopsAtTheAnchorsCreation(t *testing.T) {
	anchor := common.HexToAddress("0x3F5B4d4371f06bdFff341d08Ca72A156233e3eA6")
	const created, attempt = 315_899_990, 316_000_000
	receipt := &types.Receipt{BlockNumber: big.NewInt(attempt)}
	var lowest uint64 = attempt
	chain := &floorChain{logChain: logChain{blockTime: arbitrumLikeTime}, lowest: &lowest}
	ok, err := anchorAttestedBefore(context.Background(), chain, anchor, [32]byte{1}, arbitrumLikeTime(created), receipt)
	if err != nil || ok {
		t.Fatalf("no attestation: ok=%v err=%v", ok, err)
	}
	// The first block of the creation block's second: blocks 315,899,988..991 share it.
	if lowest != 315_899_988 {
		t.Fatalf("searched down to block %d; the anchor's creation second starts at 315,899,988", lowest)
	}
	// An attestation in the block before that second is not searched for, as none can exist.
	f, err := firstBlockAtOrAfter(context.Background(), chain, arbitrumLikeTime(created), attempt)
	if err != nil || f != 315_899_988 {
		t.Fatalf("firstBlockAtOrAfter = %d, %v", f, err)
	}
}

type floorChain struct {
	logChain
	lowest *uint64
}

func (c *floorChain) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	if q.FromBlock.Uint64() < *c.lowest {
		*c.lowest = q.FromBlock.Uint64()
	}
	return c.logChain.FilterLogs(ctx, q)
}
