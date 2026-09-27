//go:build live

// Copyright 2026 Certen Protocol

package strategy

// The strategy observer on the three supported chains' real settlements, after RB3-F69 made an
// unreadable header, transaction or sender an error there. Run with:
//
//	CERTEN_LIVE_SEPOLIA_RPC=https://ethereum-sepolia-rpc.publicnode.com \
//	CERTEN_LIVE_BASE_SEPOLIA_RPC=https://sepolia.base.org \
//	CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC=https://sepolia-rollup.arbitrum.io/rpc \
//	go test -tags live ./pkg/chain/strategy -run LiveSupportedChainObservation
//
// Behind the live build tag rather than a skip (00_STANDARD §2).

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TestLiveSupportedChainObservation(t *testing.T) {
	for _, c := range []struct {
		env     string
		chainID int64
		tx      string
	}{
		{"CERTEN_LIVE_SEPOLIA_RPC", 11155111, "0x9d980cdd503a56a0b306e3215166280cffd9ee398a27fc645f86bfa59df55f3e"},
		{"CERTEN_LIVE_BASE_SEPOLIA_RPC", 84532, "0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7"},
		{"CERTEN_LIVE_ARBITRUM_SEPOLIA_RPC", 421614, "0x5ec65d4bc78f40810366c785c9d823ad307ab0f2e58a0ed1c6b629d979ff5aa9"},
	} {
		rpc := os.Getenv(c.env)
		if rpc == "" {
			t.Fatalf("the live build requires %s", c.env)
		}
		client, err := ethclient.Dial(rpc)
		if err != nil {
			t.Fatal(err)
		}
		obs, err := NewEVMObserver(&EVMObserverConfig{Client: client, ChainID: c.chainID, ValidatorID: "live",
			RequiredConfirmations: 1, PollingInterval: 2 * time.Second, Timeout: 2 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		res, err := obs.ObserveTransaction(context.Background(), common.HexToHash(c.tx))
		if err != nil {
			t.Fatalf("chain %d: observing its real settlement: %v", c.chainID, err)
		}
		header, err := client.HeaderByHash(context.Background(), common.HexToHash(res.BlockHash))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsFinalized || res.Status != 1 || res.TxFrom == "" || res.BlockTimestamp.Unix() != int64(header.Time) {
			t.Fatalf("chain %d: finalized=%v status=%d from=%q time=%v (header %d)", c.chainID, res.IsFinalized, res.Status, res.TxFrom, res.BlockTimestamp, header.Time)
		}
	}
}
