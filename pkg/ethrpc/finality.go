package ethrpc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// ErrNotYetFinalized: a transaction's block is not yet at or below the chain's finalized block, by this node's view of
// the chain - not a verdict on the transaction (RB5-F49).
var ErrNotYetFinalized = errors.New("transaction not yet finalized")

// FinalityBound is how long a settlement may take to reach its chain's finalized block (RB5-F49): every observation that
// waits for finality is bounded by it. Measured 2026-10-02 (finalized head behind the latest): Sepolia ~13 min,
// Arbitrum Sepolia ~20 min, Base Sepolia 24-61 min - an OP-stack block is final only once its batch is on L1 and that L1
// block is final. Twice the worst observed.
const FinalityBound = 2 * time.Hour

// FinalityReader is what SettledInFinalizedChain reads; *ethclient.Client is one.
type FinalityReader interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	BlockReceipts(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) ([]*types.Receipt, error)
}

// SettledInFinalizedChain returns txHash's receipt as the FINALIZED chain holds it (RB5-F49): its block is at or below the
// chain's "finalized" block tag, it is the canonical block at its height, and the receipt is that block's own.
//
// Finality is the chain's own finalized tag - what an intent requires (finality_requirements: finalized) - not a count of
// confirmations. On 2026-10-02 a Sepolia tip reorg replaced block 11832868 (0x032d2bfd… -> 0x7bec386b…) seconds after a
// settlement landed in it: the canonical block re-included it, but the RPC's index kept answering with the orphaned hash,
// and the settlement was failed for good at one confirmation.
//
// Once the receipt's height is final, the block at that height is canonical, and the receipt is read from that block
// itself when the index names another one. A transaction the canonical block at that height does not hold was re-mined
// elsewhere or dropped: it is followed - its receipt read again - until the deadline.
func SettledInFinalizedChain(ctx context.Context, c FinalityReader, txHash common.Hash, deadline time.Time,
	poll time.Duration, logf func(string, ...interface{})) (*types.Receipt, error) {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	if poll <= 0 {
		poll = 12 * time.Second
	}
	var missing error // the finalized block at the receipt's height did not hold the transaction
	for {
		receipt, err := waitForReceipt(ctx, c, txHash, deadline, poll, logf)
		if err != nil {
			if missing != nil {
				return nil, fmt.Errorf("%w; and it was not found re-mined before the deadline (%v)", missing, err)
			}
			return nil, fmt.Errorf("wait for receipt: %w", err)
		}
		if err := WaitForFinalizedHeight(ctx, c, receipt.BlockNumber, deadline, poll, logf); err != nil {
			return nil, err
		}
		header, err := c.HeaderByNumber(ctx, receipt.BlockNumber)
		if err != nil {
			return nil, fmt.Errorf("get the finalized header at %d: %w", receipt.BlockNumber.Uint64(), err)
		}
		if header.Hash() == receipt.BlockHash {
			return receipt, nil
		}
		logf("⚠️ [FINALITY] tx %s: its receipt names block %s, the finalized block at %d is %s - reading that block's receipts",
			txHash.Hex(), receipt.BlockHash.Hex(), receipt.BlockNumber.Uint64(), header.Hash().Hex())
		receipts, err := c.BlockReceipts(ctx, rpc.BlockNumberOrHashWithHash(header.Hash(), true))
		if err != nil {
			return nil, fmt.Errorf("read the receipts of finalized block %s: %w", header.Hash().Hex(), err)
		}
		for _, r := range receipts {
			if r != nil && r.TxHash == txHash {
				if r.BlockHash != header.Hash() || r.BlockNumber == nil || r.BlockNumber.Cmp(receipt.BlockNumber) != 0 {
					return nil, fmt.Errorf("finalized block %s returned a receipt for %s naming block %s", header.Hash().Hex(),
						txHash.Hex(), r.BlockHash.Hex())
				}
				return r, nil
			}
		}
		logf("⚠️ [FINALITY] tx %s is not in finalized block %d (%s): re-mined elsewhere or dropped - following it",
			txHash.Hex(), receipt.BlockNumber.Uint64(), header.Hash().Hex())
		missing = fmt.Errorf("tx %s is not in the finalized chain at block %d (%s)", txHash.Hex(), receipt.BlockNumber.Uint64(),
			header.Hash().Hex())
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w, and was not found re-mined before the deadline", missing)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// WaitForFinalizedHeight waits until the chain's finalized block is at or past height.
func WaitForFinalizedHeight(ctx context.Context, c FinalityReader, height *big.Int, deadline time.Time, poll time.Duration,
	logf func(string, ...interface{})) error {
	for {
		fin, err := c.HeaderByNumber(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)))
		switch {
		case err != nil:
			logf("⚠️ [FINALITY] reading the finalized block: %v", err)
		case fin.Number.Cmp(height) >= 0:
			return nil
		default:
			logf("⏳ [FINALITY] waiting for finality: block %d, finalized %d", height.Uint64(), fin.Number.Uint64())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("block %d is not finalized before the deadline: %w", height.Uint64(), ErrNotYetFinalized)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func waitForReceipt(ctx context.Context, c FinalityReader, txHash common.Hash, deadline time.Time, poll time.Duration,
	logf func(string, ...interface{})) (*types.Receipt, error) {
	for {
		receipt, err := c.TransactionReceipt(ctx, txHash)
		switch {
		case err == nil:
			return receipt, nil
		case errors.Is(err, ethereum.NotFound):
		default:
			logf("⚠️ [FINALITY] reading the receipt of %s: %v", txHash.Hex(), err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for receipt")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}
