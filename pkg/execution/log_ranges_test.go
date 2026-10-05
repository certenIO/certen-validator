package execution

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// RB3-F43: every log scan asked for 2,000-block windows, "a range a public RPC will serve". The public
// Base Sepolia RPC serves 1,000 and refuses the rest, so a reverted intent could not be proven there
// (TestVerifyRevertedCall_LiveBaseSepolia failed live: "eth_getLogs is limited to a 1,000 range").

// rangeCappedChain refuses any log query wider than maxSpan blocks, as range-capped RPCs do.
type rangeCappedChain struct {
	logChain
	maxSpan uint64
}

func (c *rangeCappedChain) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	if span := q.ToBlock.Uint64() - q.FromBlock.Uint64() + 1; span > c.maxSpan {
		c.calls++
		return nil, fmt.Errorf("eth_getLogs is limited to a %d range", c.maxSpan)
	}
	return c.logChain.FilterLogs(ctx, q)
}

func TestAnchorAttestedBeforeOnARangeCappedRPC(t *testing.T) {
	anchor := common.HexToAddress("0xEA9eeeE42a7971792B11Fd2f682C9c1172490272")
	receipt := &types.Receipt{BlockNumber: big.NewInt(50000), TransactionIndex: 3}
	chain := &rangeCappedChain{logChain: logChain{logs: []types.Log{{BlockNumber: 46500}}}, maxSpan: 1000}
	ok, err := anchorAttestedBefore(context.Background(), chain, anchor, [32]byte{0x5f}, 0, receipt)
	if err != nil || !ok {
		t.Fatalf("an attestation 3,500 blocks earlier was not found on a 1,000-block RPC: ok=%v err=%v", ok, err)
	}
}

// The split keeps ascending order - scanForward takes the first log, scanBack the last.
func TestFilterLogsSplittingKeepsOrder(t *testing.T) {
	chain := &rangeCappedChain{logChain: logChain{logs: []types.Log{{BlockNumber: 10}, {BlockNumber: 900}, {BlockNumber: 1999}}}, maxSpan: 700}
	logs, err := filterLogsSplitting(context.Background(), chain, ethereum.FilterQuery{}, 0, 1999)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 3 || logs[0].BlockNumber != 10 || logs[2].BlockNumber != 1999 {
		t.Fatalf("logs out of order or missing: %+v", logs)
	}
}

// A query the RPC refuses at any width is an error, named with the range - never an empty result.
func TestFilterLogsSplittingReportsARefusal(t *testing.T) {
	chain := &rangeCappedChain{maxSpan: 0}
	if _, err := filterLogsSplitting(context.Background(), chain, ethereum.FilterQuery{}, 0, 1999); err == nil {
		t.Fatal("an RPC that refuses every query produced a result")
	}
}
