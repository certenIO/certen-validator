//go:build live

// Copyright 2026 Certen Protocol

package strategy

// The strategy observer on the three supported chains' real settlements, through each chain's agreeing providers
// (RB5-F53), proving each settlement in its block (RB5-F16). Run with at least two independent providers per chain:
//
//	CERTEN_LIVE_SEPOLIA_RPCS=https://ethereum-sepolia-rpc.publicnode.com,https://sepolia.gateway.tenderly.co \
//	CERTEN_LIVE_BASE_SEPOLIA_RPCS=https://base-sepolia-rpc.publicnode.com,https://sepolia.base.org \
//	CERTEN_LIVE_ARBITRUM_SEPOLIA_RPCS=https://arbitrum-sepolia-rpc.publicnode.com,https://sepolia-rollup.arbitrum.io/rpc \
//	go test -tags live ./pkg/chain/strategy -run LiveSupportedChainObservation
//
// Behind the live build tag rather than a skip (00_STANDARD §2).

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

func TestLiveSupportedChainObservation(t *testing.T) {
	for _, c := range []struct {
		env     string
		chainID int64
		tx      string
	}{
		{"CERTEN_LIVE_SEPOLIA_RPCS", 11155111, "0x9d980cdd503a56a0b306e3215166280cffd9ee398a27fc645f86bfa59df55f3e"},
		{"CERTEN_LIVE_BASE_SEPOLIA_RPCS", 84532, "0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7"},
		{"CERTEN_LIVE_ARBITRUM_SEPOLIA_RPCS", 421614, "0x5ec65d4bc78f40810366c785c9d823ad307ab0f2e58a0ed1c6b629d979ff5aa9"},
	} {
		urls := strings.Split(os.Getenv(c.env), ",")
		if len(urls) < ethrpc.MinAgreeingProviders || urls[0] == "" {
			t.Fatalf("the live build requires %s: at least %d providers", c.env, ethrpc.MinAgreeingProviders)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		reader, err := ethrpc.NewAgreeingReader(ctx, c.chainID, urls, 30*time.Second)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		client, err := ethclient.Dial(urls[0])
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		obs, err := NewEVMObserver(&EVMObserverConfig{Client: client, Finality: reader, ChainID: c.chainID, ValidatorID: "live",
			RequiredConfirmations: 1, PollingInterval: 2 * time.Second, Timeout: 2 * time.Minute})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		res, err := obs.ObserveTransaction(ctx, common.HexToHash(c.tx))
		if err != nil {
			cancel()
			t.Fatalf("chain %d: observing its real settlement: %v", c.chainID, err)
		}
		header, _, err := VerifyObservationProofs(res)
		cancel()
		if err != nil {
			t.Fatalf("chain %d: %v", c.chainID, err)
		}
		if !res.IsFinalized || res.Status != 1 || res.TxFrom == "" || res.BlockTimestamp.Unix() != int64(header.Time) {
			t.Fatalf("chain %d: finalized=%v status=%d from=%q time=%v (header %d)", c.chainID, res.IsFinalized, res.Status, res.TxFrom, res.BlockTimestamp, header.Time)
		}
	}
}
