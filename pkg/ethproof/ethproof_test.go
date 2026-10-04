// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// RB5-F16: the settlement's transaction and receipt are proven against the block's own roots, from agreed reads, on real
// blocks of the three supported chains, and every proof verifies offline - while every tampering of it fails.

func agreed(t *testing.T, ps ...*ethprooftest.Provider) *ethrpc.AgreeingReader {
	t.Helper()
	r, err := ethrpc.NewAgreeingReader(context.Background(), ps[0].F.ChainID, ethprooftest.URLs(t, ps...), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func honest(f *ethprooftest.Fixture) *ethprooftest.Provider { return &ethprooftest.Provider{F: f} }

func settlement(t *testing.T, name string) (*ethprooftest.Fixture, *ethproof.Block, *ethproof.Settlement) {
	t.Helper()
	f := ethprooftest.Load(t, name)
	// sepolia.base.org serves no eth_getBlockReceipts; the second provider answers as it does.
	b, err := ethproof.ReadBlock(context.Background(), agreed(t, honest(f), &ethprooftest.Provider{F: f, NoBlockReceipts: true}), f.BlockHash())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	s, err := b.Prove(f.SettlementTx, f.SettlementIndex())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f, b, s
}

func TestRealBlocksProveEveryEntryAgainstTheHeaderRoots(t *testing.T) {
	for _, name := range ethprooftest.All {
		t.Run(name, func(t *testing.T) {
			f, b, s := settlement(t, name)
			if len(b.Txs) != len(f.Transactions()) {
				t.Fatalf("%d transactions encoded, the block has %d", len(b.Txs), len(f.Transactions()))
			}
			// Offline, from the emitted JSON alone.
			enc, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var back ethproof.Settlement
			if err := json.Unmarshal(enc, &back); err != nil {
				t.Fatal(err)
			}
			header, receipt, err := back.Verify()
			if err != nil {
				t.Fatalf("the emitted proof does not verify offline: %v", err)
			}
			if header.Hash() != f.BlockHash() || !receipt.Succeeded() {
				t.Fatalf("verified block %s status %x", header.Hash().Hex(), receipt.PostStateOrStatus)
			}
			// Every entry of every type in the block proves and verifies, not only the settlement's.
			types := map[byte]bool{}
			for i := range b.Txs {
				txHash := crypto.Keccak256Hash(b.Txs[i])
				p, err := b.Prove(txHash, uint64(i))
				if err != nil {
					t.Fatalf("entry %d: %v", i, err)
				}
				if _, _, err := p.Verify(); err != nil {
					t.Fatalf("entry %d: %v", i, err)
				}
				typ := byte(0)
				if b.Txs[i][0] < 0x80 {
					typ = b.Txs[i][0]
				}
				types[typ] = true
			}
			t.Logf("%s: %d entries proven, types %v", name, len(b.Txs), types)
		})
	}
}

// The captured blocks cover the transaction types the supported chains carry.
func TestTheCapturedBlocksCoverTheChainsTransactionTypes(t *testing.T) {
	want := map[string][]byte{
		ethprooftest.Sepolia:          {0x0, 0x2, 0x3},
		ethprooftest.SepoliaSetCode:   {0x0, 0x2, 0x3, 0x4},
		ethprooftest.BaseSepolia:      {0x0, 0x2, 0x7e},
		ethprooftest.ArbitrumSepolia:  {0x2, 0x6a},
		ethprooftest.ArbitrumRetry:    {0x68, 0x69, 0x6a},
		ethprooftest.ArbitrumDeposit:  {0x64, 0x6a},
		ethprooftest.ArbitrumUnsigned: {0x65, 0x6a},
		ethprooftest.ArbitrumContract: {0x66, 0x6a},
		ethprooftest.ArbitrumRedeem:   {0x0, 0x2, 0x68, 0x6a},
	}
	for name, types := range want {
		_, b, _ := settlement(t, name)
		have := map[byte]bool{}
		for _, tx := range b.Txs {
			if tx[0] < 0x80 {
				have[tx[0]] = true
			} else {
				have[0] = true
			}
		}
		for _, typ := range types {
			if !have[typ] {
				t.Fatalf("%s holds no type-0x%x transaction", name, typ)
			}
		}
	}
}

// mustFail requires err to be a verification failure.
func mustFail(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: a tampered proof verified", what)
	}
	if !errors.Is(err, ethproof.ErrProofInvalid) {
		t.Fatalf("%s: failed, but not as an invalid proof: %v", what, err)
	}
}

func clone(t *testing.T, s *ethproof.Settlement) *ethproof.Settlement {
	t.Helper()
	enc, _ := json.Marshal(s)
	var c ethproof.Settlement
	if err := json.Unmarshal(enc, &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func verify(s *ethproof.Settlement) error {
	_, _, err := s.Verify()
	return err
}

func TestEveryTamperingOfASettlementProofFails(t *testing.T) {
	for _, name := range ethprooftest.All {
		t.Run(name, func(t *testing.T) {
			f, b, s := settlement(t, name)
			idx := f.SettlementIndex()
			other := uint64(0)
			if idx == 0 {
				other = 1
			}
			otherProof, err := b.Prove(crypto.Keccak256Hash(b.Txs[other]), other)
			if err != nil {
				t.Fatal(err)
			}

			// Transaction bytes: one byte of the proven transaction changed, its leaf hash made consistent.
			c := clone(t, s)
			c.Tx.LeafValue[len(c.Tx.LeafValue)-1] ^= 1
			c.Tx.LeafHash = crypto.Keccak256Hash(c.Tx.LeafValue)
			mustFail(t, "tx bytes", verify(c))

			// Index: the transaction proof claims another index.
			c = clone(t, s)
			c.Tx.LeafIndex = other
			mustFail(t, "tx index", verify(c))

			// Index: another entry's (valid) transaction proof, presented for this transaction.
			c = clone(t, s)
			c.Tx = otherProof.Tx
			mustFail(t, "another entry's tx proof", verify(c))

			// Index: another entry's (valid) receipt proof, presented as this transaction's receipt.
			c = clone(t, s)
			c.Receipt = otherProof.Receipt
			mustFail(t, "another entry's receipt", verify(c))

			// Receipt: the status flipped in the proven receipt, its leaf hash made consistent.
			c = clone(t, s)
			c.Receipt.LeafValue = flipStatus(t, c.Receipt.LeafValue)
			c.Receipt.LeafHash = crypto.Keccak256Hash(c.Receipt.LeafValue)
			mustFail(t, "receipt status", verify(c))

			// Receipt: a forged receipt list whose own trie proves the forged receipt - self-consistent, wrong root.
			forged := append([][]byte(nil), b.Receipts...)
			forged[idx] = flipStatus(t, forged[idx])
			fp, err := ethproof.Prove(forged, idx, ethproof.TrieRoot(forged))
			if err != nil {
				t.Fatal(err)
			}
			if fp.Check() != nil {
				t.Fatal("the forged proof should be self-consistent")
			}
			c = clone(t, s)
			c.Receipt = fp
			mustFail(t, "forged receipt trie", verify(c))

			// Root: the header rewritten to commit to the forged receipts root; it no longer hashes to the block.
			c = clone(t, s)
			c.Receipt = fp
			var h types.Header
			if err := rlp.DecodeBytes(c.Header, &h); err != nil {
				t.Fatal(err)
			}
			h.ReceiptHash = ethproof.TrieRoot(forged)
			c.Header, _ = rlp.EncodeToBytes(&h)
			mustFail(t, "rewritten header root", verify(c))

			// Root: the proof's own root changed.
			c = clone(t, s)
			c.Tx.ExpectedRoot[0] ^= 1
			mustFail(t, "tx expected root", verify(c))

			// A proof node altered.
			c = clone(t, s)
			n := c.Receipt.ProofNodes[len(c.Receipt.ProofNodes)-1]
			n[len(n)/2] ^= 1
			c.Receipt.ProofHashes[len(c.Receipt.ProofNodes)-1] = crypto.Keccak256Hash(n)
			mustFail(t, "receipt proof node", verify(c))

			// Another transaction's hash claimed for the proven one.
			c = clone(t, s)
			c.TxHash = crypto.Keccak256Hash(b.Txs[other])
			mustFail(t, "transaction hash", verify(c))

			// The untampered proof still verifies.
			if err := verify(clone(t, s)); err != nil {
				t.Fatalf("the honest proof: %v", err)
			}
		})
	}
}

// flipStatus returns the receipt encoding with its status changed (1 <-> 0).
func flipStatus(t *testing.T, enc []byte) []byte {
	t.Helper()
	prefix, body := []byte(nil), enc
	if enc[0] < 0x80 {
		prefix, body = []byte{enc[0]}, enc[1:]
	}
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(body, &fields); err != nil {
		t.Fatal(err)
	}
	status, _ := rlp.EncodeToBytes([]byte{1})
	if string(fields[0]) == string(status) {
		fields[0], _ = rlp.EncodeToBytes([]byte{})
	} else {
		fields[0] = status
	}
	out, err := rlp.EncodeToBytes(fields)
	if err != nil {
		t.Fatal(err)
	}
	return append(prefix, out...)
}

// A provider serving a forged receipt - the settlement's status flipped - is a disagreement: nothing is proven.
func TestALyingProviderIsRefusedNotProvenFrom(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.Sepolia)
	idx := f.SettlementIndex()
	liar := &ethprooftest.Provider{F: f, Mutate: func(method string, _ []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method != "eth_getBlockReceipts" {
			return res
		}
		var rs []map[string]json.RawMessage
		_ = json.Unmarshal(res, &rs)
		rs[idx]["status"] = json.RawMessage(`"0x0"`)
		out, _ := json.Marshal(rs)
		return out
	}}
	_, err := ethproof.ReadBlock(context.Background(), agreed(t, honest(f), liar), f.BlockHash())
	if !errors.Is(err, ethrpc.ErrProvidersDisagree) || !errors.Is(err, ethproof.ErrRefused) {
		t.Fatalf("a forged receipt from one provider: %v", err)
	}

	// Two providers serving the same forgery: they agree, and the header's receiptsRoot refuses it.
	_, err = ethproof.ReadBlock(context.Background(), agreed(t, liar, &ethprooftest.Provider{F: f, Mutate: liar.Mutate}), f.BlockHash())
	if err == nil || !strings.Contains(err.Error(), "receiptsRoot") {
		t.Fatalf("an agreed forgery: %v", err)
	}

	// One provider answering is not agreement.
	_, err = ethproof.ReadBlock(context.Background(), agreed(t, honest(f), &ethprooftest.Provider{F: f, Down: true}), f.BlockHash())
	if !errors.Is(err, ethrpc.ErrTooFewProviders) {
		t.Fatalf("one answering provider: %v", err)
	}
}

// A block that does not hold the transaction at the stated index proves nothing.
func TestAProofIsRefusedForATransactionNotAtItsIndex(t *testing.T) {
	f, b, _ := settlement(t, ethprooftest.BaseSepolia)
	if _, err := b.Prove(f.SettlementTx, f.SettlementIndex()+1); !errors.Is(err, ethproof.ErrRefused) {
		t.Fatalf("a transaction at another index: %v", err)
	}
	if _, err := b.Prove(common.Hash{1}, 0); !errors.Is(err, ethproof.ErrRefused) {
		t.Fatalf("a transaction the block does not hold: %v", err)
	}
}

// The commitment a signature binds changes with every byte of a proof.
func TestTheCommitmentBindsEveryByteOfTheProof(t *testing.T) {
	_, _, s := settlement(t, ethprooftest.ArbitrumSepolia)
	base := s.Receipt.Commitment()
	c := clone(t, s)
	if c.Receipt.Commitment() != base {
		t.Fatal("the commitment is not a function of the proof")
	}
	c.Receipt.ProofNodes[0][3] ^= 1
	if c.Receipt.Commitment() == base {
		t.Fatal("a changed node left the commitment unchanged")
	}
	c = clone(t, s)
	c.Receipt.LeafIndex++
	if c.Receipt.Commitment() == base {
		t.Fatal("a changed index left the commitment unchanged")
	}
}

// An Arbitrum Nitro transaction whose JSON lacks a field its consensus encoding carries is refused by name, never
// encoded with a zero in its place.
func TestANitroTransactionMissingAConsensusFieldIsRefused(t *testing.T) {
	for _, c := range []struct {
		name, typ, field string
	}{
		{ethprooftest.ArbitrumRetry, "0x68", "ticketId"},
		{ethprooftest.ArbitrumRetry, "0x69", "retryData"},
		{ethprooftest.ArbitrumRetry, "0x69", "beneficiary"},
		{ethprooftest.ArbitrumDeposit, "0x64", "requestId"},
		{ethprooftest.ArbitrumUnsigned, "0x65", "maxFeePerGas"},
		{ethprooftest.ArbitrumUnsigned, "0x65", "value"},
		{ethprooftest.ArbitrumContract, "0x66", "requestId"},
		{ethprooftest.ArbitrumContract, "0x66", "maxFeePerGas"},
	} {
		f := ethprooftest.Load(t, c.name)
		found := false
		for _, tx := range f.Transactions() {
			var typ string
			_ = json.Unmarshal(tx["type"], &typ)
			if typ != c.typ {
				continue
			}
			found = true
			raw, _ := json.Marshal(tx)
			if _, _, err := ethproof.EncodeTxJSON(raw); err != nil {
				t.Fatalf("%s type %s as served: %v", c.name, c.typ, err)
			}
			delete(tx, c.field)
			raw, _ = json.Marshal(tx)
			if _, _, err := ethproof.EncodeTxJSON(raw); err == nil || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("%s type %s without %s: %v", c.name, c.typ, c.field, err)
			}
		}
		if !found {
			t.Fatalf("%s holds no type-%s transaction", c.name, c.typ)
		}
	}
}
