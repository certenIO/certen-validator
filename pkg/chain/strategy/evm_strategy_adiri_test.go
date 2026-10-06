// Copyright 2026 Certen Protocol

package strategy

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
)

// RB7 Phase A F-RPC-10: go-ethereum's BlockByHash/BlockByNumber refuse every Telcoin Adiri (2017) block - "server
// returned empty uncle list but block header indicates uncles": Telcoin stores a batch digest in sha3Uncles. The
// strategy read its receipt's block that way for the block's time, ignored the error, and returned the receipt with a
// ZERO timestamp. These are the real Adiri blocks captured in Phase A (pkg/ethproof/testdata).

func adiriStrategy(t *testing.T, p *ethprooftest.Provider) *EVMStrategy {
	t.Helper()
	c, err := ethclient.Dial(ethprooftest.URLs(t, p)[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return &EVMStrategy{client: c, chainID: big.NewInt(2017),
		config: &EVMStrategyConfig{ChainConfig: &ChainConfig{RequiredConfirmations: 1}}}
}

func TestAnAdiriReceiptCarriesItsBlocksTime(t *testing.T) {
	for _, name := range []string{"telcoin_adiri_498759", "telcoin_adiri_499961"} {
		t.Run(name, func(t *testing.T) {
			f := ethprooftest.Load(t, name)
			want := time.Unix(int64(f.Header(t).Time), 0)
			res, err := adiriStrategy(t, &ethprooftest.Provider{F: f}).GetTransactionReceipt(context.Background(), f.SettlementTx.Hex())
			if err != nil {
				t.Fatalf("the receipt of %s on an Adiri block is not read: %v", f.SettlementTx.Hex(), err)
			}
			if res.BlockTimestamp.IsZero() || !res.BlockTimestamp.Equal(want) {
				t.Fatalf("THE regression (F-RPC-10): the receipt's block time is %v, the block's is %v", res.BlockTimestamp, want)
			}
			if res.BlockHash != f.BlockHash().Hex() {
				t.Fatalf("block %s, want %s", res.BlockHash, f.BlockHash().Hex())
			}
		})
	}
}

// A block that cannot be read is a refusal, never a receipt with a zero time.
func TestABlockReadErrorNeverYieldsAZeroTime(t *testing.T) {
	f := ethprooftest.Load(t, "telcoin_adiri_498759")
	for _, tc := range []struct {
		name   string
		mutate func(method string, params []json.RawMessage, result json.RawMessage) json.RawMessage
	}{
		{"the block is not served", func(method string, _ []json.RawMessage, r json.RawMessage) json.RawMessage {
			if method == "eth_getBlockByHash" {
				return json.RawMessage("null")
			}
			return r
		}},
		{"another block is served", func(method string, _ []json.RawMessage, r json.RawMessage) json.RawMessage {
			if method != "eth_getBlockByHash" {
				return r
			}
			var b map[string]interface{}
			_ = json.Unmarshal(r, &b)
			b["timestamp"] = "0x1"
			out, _ := json.Marshal(b)
			return out
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := adiriStrategy(t, &ethprooftest.Provider{F: f, Mutate: tc.mutate}).GetTransactionReceipt(context.Background(), f.SettlementTx.Hex())
			if err == nil {
				t.Fatalf("THE regression: an unreadable block yielded a receipt with block time %v", res.BlockTimestamp)
			}
		})
	}
}
