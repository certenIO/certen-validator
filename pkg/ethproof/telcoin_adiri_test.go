// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
)

// RB7 Task 4 (V-4): Telcoin Network's Adiri testnet (chain 2017) runs a reth-derived execution layer under Narwhal/Bullshark
// consensus. A settlement on it can be proven only if go-ethereum's header re-hashes a Telcoin header to the hash the chain
// states, and the transaction and receipt encodings re-derive the header's roots. These are real Adiri blocks, captured
// read-only on 2026-10-05 from https://rpc.telcoin.network (eth_chainId 0x7e1), each read byte-for-byte identical from
// https://adiri.tel:
//   - 498759: two transactions, one EIP-1559 (0x2) and one legacy (0x0), no logs;
//   - 499961: one EIP-1559 transaction whose receipt carries 13 logs.
//
// Telcoin's headers are not Ethereum's in content: sha3Uncles is not the empty-uncles hash although the block has no
// uncles, difficulty is 0x10000, and nonce and mixHash carry consensus data. They are Prague headers in form
// (withdrawalsRoot, blob gas, parentBeaconBlockRoot, requestsHash), which is what the hash is computed over.
var telcoinAdiriBlocks = []string{"telcoin_adiri_498759", "telcoin_adiri_499961"}

func TestTelcoinAdiriBlocksReHashAndRebuildTheirRoots(t *testing.T) {
	for _, name := range telcoinAdiriBlocks {
		t.Run(name, func(t *testing.T) {
			f := ethprooftest.Load(t, name)
			if f.ChainID != 2017 {
				t.Fatalf("fixture chain %d, want 2017", f.ChainID)
			}

			// 1. The header, as the chain serves it, re-hashes to the block hash the chain states.
			h := f.Header(t)
			if h.Hash() != f.BlockHash() {
				t.Fatalf("go-ethereum hashes the header to %s; the chain states %s", h.Hash().Hex(), f.BlockHash().Hex())
			}
			if h.RequestsHash == nil || h.ParentBeaconRoot == nil || h.WithdrawalsHash == nil || h.BlobGasUsed == nil {
				t.Fatalf("the header is not read as a Prague header: %+v", h)
			}
			// What makes a Telcoin header unlike an Ethereum one, so that a regression to Ethereum assumptions is visible here.
			if h.UncleHash == types.EmptyUncleHash {
				t.Fatalf("sha3Uncles is the empty-uncles hash; the captured Telcoin headers state another value")
			}

			// 2. The transaction and receipt encodings re-derive transactionsRoot and receiptsRoot, from two agreeing
			// providers, exactly as a settlement on 2017 would be read.
			b, err := ethproof.ReadBlock(context.Background(),
				agreed(t, honest(f), &ethprooftest.Provider{F: f, NoBlockReceipts: true}), f.BlockHash())
			if err != nil {
				t.Fatalf("the block cannot be read as a provable block: %v", err)
			}
			if ethproof.TrieRoot(b.Txs) != h.TxHash || ethproof.TrieRoot(b.Receipts) != h.ReceiptHash {
				t.Fatalf("roots %s / %s, header %s / %s", ethproof.TrieRoot(b.Txs).Hex(), ethproof.TrieRoot(b.Receipts).Hex(),
					h.TxHash.Hex(), h.ReceiptHash.Hex())
			}
			if len(b.Txs) != len(f.Transactions()) || len(b.Receipts) != len(f.ReceiptList()) {
				t.Fatalf("%d/%d encodings for %d/%d entries", len(b.Txs), len(b.Receipts), len(f.Transactions()), len(f.ReceiptList()))
			}

			// 3. Every entry proves against those roots and verifies offline from its emitted JSON, and its transaction
			// encoding hashes to the hash the chain states for it.
			for i, tx := range f.Transactions() {
				var want common.Hash
				_ = json.Unmarshal(tx["hash"], &want)
				if got := crypto.Keccak256Hash(b.Txs[i]); got != want {
					t.Fatalf("entry %d encodes to %s; the chain states %s", i, got.Hex(), want.Hex())
				}
				p, err := b.Prove(want, uint64(i))
				if err != nil {
					t.Fatalf("entry %d: %v", i, err)
				}
				enc, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				var back ethproof.Settlement
				if err := json.Unmarshal(enc, &back); err != nil {
					t.Fatal(err)
				}
				header, receipt, err := back.Verify()
				if err != nil {
					t.Fatalf("entry %d does not verify offline: %v", i, err)
				}
				if header.Hash() != f.BlockHash() || !receipt.Succeeded() {
					t.Fatalf("entry %d verified against %s, status %x", i, header.Hash().Hex(), receipt.PostStateOrStatus)
				}
				var logs []json.RawMessage
				_ = json.Unmarshal(f.ReceiptList()[i]["logs"], &logs)
				if len(receipt.Logs) != len(logs) {
					t.Fatalf("entry %d: %d logs proven, the receipt has %d", i, len(receipt.Logs), len(logs))
				}
			}

			// 4. The production canary's check (cmd/blockproofcheck) proves the block by number.
			c, err := ethproof.CheckBlock(context.Background(),
				agreed(t, honest(f), &ethprooftest.Provider{F: f, NoBlockReceipts: true}), h.Number.Uint64())
			if err != nil {
				t.Fatalf("blockproofcheck refuses the block: %v", err)
			}
			if c.Hash != f.BlockHash() || c.Entries != len(f.Transactions()) {
				t.Fatalf("checked %s with %d entries", c.Hash.Hex(), c.Entries)
			}
			t.Logf("%s: header %s re-hashed; %d transactions (types %v) and their receipts rebuild the header's roots",
				name, f.BlockHash().Hex(), c.Entries, c.Types)
		})
	}
}

// The captured blocks hold what they are kept for: a legacy and an EIP-1559 transaction, and a receipt with logs.
func TestTheTelcoinAdiriBlocksCoverLegacy1559AndLogs(t *testing.T) {
	types := map[string]bool{}
	logs := 0
	for _, name := range telcoinAdiriBlocks {
		f := ethprooftest.Load(t, name)
		for _, tx := range f.Transactions() {
			var typ string
			_ = json.Unmarshal(tx["type"], &typ)
			types[typ] = true
		}
		for _, r := range f.ReceiptList() {
			var l []json.RawMessage
			_ = json.Unmarshal(r["logs"], &l)
			logs += len(l)
		}
	}
	if !types["0x0"] || !types["0x2"] || logs == 0 {
		t.Fatalf("types %v, %d logs: the fixtures must hold a legacy and a 1559 transaction and a receipt with logs", types, logs)
	}
}
