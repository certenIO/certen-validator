//go:build live

// Copyright 2026 Certen Protocol

package execution

// The anchor event monitor's query and decoding against the three live CertenAnchorV8_1 deployments
// (RB3-F72): each has anchored batches before its settlement of intent 47b7e925, and every event the
// query returns decodes. Run with:
//
//	CERTEN_LIVE_SEPOLIA_RPC=https://ethereum-sepolia-rpc.publicnode.com \
//	CERTEN_LIVE_BASE_SEPOLIA_RPC=https://sepolia.base.org \
//	CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC=https://sepolia-rollup.arbitrum.io/rpc \
//	go test -tags live ./pkg/execution -run LiveAnchorEvents
//
// Behind the live build tag rather than a skip (00_STANDARD §2).

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TestLiveAnchorEvents(t *testing.T) {
	for _, c := range []struct {
		env    string
		chain  int64
		anchor string
		upTo   uint64 // a block at or after the member's settlement
		span   uint64 // blocks per query
		chunks int
	}{
		{"CERTEN_LIVE_SEPOLIA_RPC", 11155111, "0xb39b707D50089C9Eb92818f9B2870eba6DA5C2a0", 11792612, 1000, 20},
		{"CERTEN_LIVE_BASE_SEPOLIA_RPC", 84532, "0xEA9eeeE42a7971792B11Fd2f682C9c1172490272", 47368146, 1000, 40},
		{"CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC", 421614, "0x4b9eA187772E115641Fd40F35BF7a84925e7A035", 312921216, 5000, 60},
	} {
		rpc := os.Getenv(c.env)
		if rpc == "" {
			t.Fatalf("the live build requires %s", c.env)
		}
		client, err := ethclient.Dial(rpc)
		if err != nil {
			t.Fatal(err)
		}
		batches := 0
		for i := 0; i < c.chunks && batches == 0; i++ {
			to := c.upTo - uint64(i)*c.span
			logs, err := client.FilterLogs(context.Background(), anchorEventsQuery(common.HexToAddress(c.anchor), to-c.span+1, to))
			if err != nil {
				t.Fatalf("chain %d: %v", c.chain, err)
			}
			for _, lg := range logs {
				d := describeAnchorEvent(c.chain, lg)
				if strings.HasPrefix(d, "❌ [ANCHOR-EVENTS] chain") && strings.Contains(d, "undecodable") || strings.Contains(d, "unexpected event") {
					t.Fatalf("chain %d: %s", c.chain, d)
				}
				if strings.Contains(d, "BatchAnchorCreated") {
					batches++
					t.Log(d)
				}
			}
		}
		if batches == 0 {
			t.Fatalf("chain %d: no BatchAnchorCreated found before block %d on the live anchor", c.chain, c.upTo)
		}
	}
}
