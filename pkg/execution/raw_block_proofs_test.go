package execution

import (
	"context"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// TestRawBlockRootsAgainstLiveChains proves the hand-written encodings against real blocks:
// fetch the latest block on each chain, encode every transaction and receipt, and require both
// trie roots to equal the header's. Network-bound, so it runs only when RAW_BLOCK_RPCS is set,
// e.g.
//
//	RAW_BLOCK_RPCS=https://sepolia.base.org,https://sepolia-rollup.arbitrum.io/rpc go test ./pkg/execution -run TestRawBlockRoots -v
//
// A failure here means an encoder is wrong for that chain and the observer would (correctly)
// refuse to prove there — which is exactly what to know before shipping.
func TestRawBlockRootsAgainstLiveChains(t *testing.T) {
	urls := os.Getenv("RAW_BLOCK_RPCS")
	if urls == "" {
		t.Skip("RAW_BLOCK_RPCS not set")
	}
	for _, url := range strings.Split(urls, ",") {
		url = strings.TrimSpace(url)
		t.Run(url, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			rc, err := rpc.DialContext(ctx, url)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			ec := ethclient.NewClient(rc)
			o := &ExternalChainObserver{ethClient: ec, rpcClient: rc}

			// A few blocks back, so every RPC in a load-balanced pool has it.
			n, err := ec.BlockNumber(ctx)
			if err != nil {
				t.Fatalf("block number: %v", err)
			}
			header, err := ec.HeaderByNumber(ctx, new(big.Int).SetUint64(n-3))
			if err != nil {
				t.Fatalf("header: %v", err)
			}
			// Show whether go-ethereum's own decoder copes with this chain; the raw path must work either way.
			if _, err := ec.BlockByNumber(ctx, header.Number); err != nil {
				t.Logf("go-ethereum BlockByNumber fails on this chain (expected on OP-stack / Arbitrum): %v", err)
			}
			rb, err := o.fetchRawBlockProofs(ctx, header)
			if err != nil {
				t.Fatalf("raw block proofs: %v", err)
			}
			t.Logf("block %d: %d txs, tx root and receipt root both match the header", header.Number.Uint64(), len(rb.txs))
			if len(rb.txs) > 0 {
				txp, rp, err := o.inclusionProofsFromRaw(ctx, header, 0)
				if err != nil {
					t.Fatalf("inclusion proofs: %v", err)
				}
				if !txp.Verify() || !rp.Verify() {
					t.Fatalf("proofs built but do not verify against the header roots")
				}
				t.Logf("index 0: tx and receipt inclusion proofs verify")
			}
		})
	}
}
