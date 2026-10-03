//go:build live

// Copyright 2026 Certen Protocol

package ethproof_test

// The encodings and the agreed reads against the supported chains' recent blocks: every transaction and receipt of a
// block a little below the head is encoded, both roots must equal the header's, and every entry is proven and verified.
// Behind the live build tag rather than a skip (00_STANDARD §2); a missing input is a failure. Run with the same
// variables as pkg/chain/strategy's live test:
//
//	CERTEN_LIVE_SEPOLIA_RPCS=https://ethereum-sepolia-rpc.publicnode.com,https://sepolia.gateway.tenderly.co \
//	CERTEN_LIVE_BASE_SEPOLIA_RPCS=https://base-sepolia-rpc.publicnode.com,https://sepolia.base.org \
//	CERTEN_LIVE_ARBITRUM_SEPOLIA_RPCS=https://arbitrum-sepolia-rpc.publicnode.com,https://sepolia-rollup.arbitrum.io/rpc \
//	go test -tags live ./pkg/ethproof -run Live

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

func TestLiveRecentBlocksProveEveryEntry(t *testing.T) {
	for _, c := range []struct {
		env     string
		chainID int64
	}{
		{"CERTEN_LIVE_SEPOLIA_RPCS", 11155111},
		{"CERTEN_LIVE_BASE_SEPOLIA_RPCS", 84532},
		{"CERTEN_LIVE_ARBITRUM_SEPOLIA_RPCS", 421614},
	} {
		urls := strings.Split(os.Getenv(c.env), ",")
		if len(urls) < ethrpc.MinAgreeingProviders || urls[0] == "" {
			t.Fatalf("the live build requires %s: at least %d providers", c.env, ethrpc.MinAgreeingProviders)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		r, err := ethrpc.NewAgreeingReader(ctx, c.chainID, urls, 30*time.Second)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		head, err := r.RecentAgreedHeader(ctx)
		if err != nil {
			cancel()
			t.Fatalf("chain %d: %v", c.chainID, err)
		}
		b, err := ethproof.ReadBlock(ctx, r, head.Hash())
		cancel()
		if err != nil {
			t.Fatalf("chain %d block %d: %v", c.chainID, head.Number, err)
		}
		for i := range b.Txs {
			s, err := b.Prove(crypto.Keccak256Hash(b.Txs[i]), uint64(i))
			if err != nil {
				t.Fatalf("chain %d block %d entry %d: %v", c.chainID, head.Number, i, err)
			}
			if _, _, err := s.Verify(); err != nil {
				t.Fatalf("chain %d block %d entry %d: %v", c.chainID, head.Number, i, err)
			}
		}
		t.Logf("chain %d block %d: %d entries proven from %v", c.chainID, head.Number, len(b.Txs), r.Hosts())
	}
}
