package execution

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// minLogSpan is the narrowest block range filterLogsSplitting will ask for before it accepts that the
// RPC is refusing the query itself rather than its width.
const minLogSpan = 16

// logFilterer is the one call a log scan needs (ethereum.LogFilterer without subscriptions).
type logFilterer interface {
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
}

// filterLogsSplitting returns the logs matching q in blocks lo..hi, in ascending order.
//
// RPCs cap eth_getLogs ranges differently, and the cap is not discoverable up front: the public Base
// Sepolia endpoint refuses more than 1,000 blocks ("eth_getLogs is limited to a 1,000 range"), where
// the 2,000-block window every scan here used was chosen as "a range a public RPC will serve". On
// such an RPC a reverted intent could not be proven and an attribution scan could not run. A refused
// range is split in two and each half asked for; a range already at minLogSpan that is still refused
// is reported with the RPC's error.
func filterLogsSplitting(ctx context.Context, f logFilterer, q ethereum.FilterQuery, lo, hi uint64) ([]types.Log, error) {
	q.FromBlock = new(big.Int).SetUint64(lo)
	q.ToBlock = new(big.Int).SetUint64(hi)
	logs, err := f.FilterLogs(ctx, q)
	if err == nil {
		return logs, nil
	}
	// A provider that cannot answer now (ethrpc.IsTransient) is not refusing the range: halving it only multiplies the
	// queries a throttled provider is sent.
	if ctx.Err() != nil || hi-lo+1 <= minLogSpan || ethrpc.IsTransient(err) {
		return nil, fmt.Errorf("logs %d-%d: %w", lo, hi, err)
	}
	mid := lo + (hi-lo)/2
	first, err := filterLogsSplitting(ctx, f, q, lo, mid)
	if err != nil {
		return nil, err
	}
	second, err := filterLogsSplitting(ctx, f, q, mid+1, hi)
	if err != nil {
		return nil, err
	}
	return append(first, second...), nil
}
