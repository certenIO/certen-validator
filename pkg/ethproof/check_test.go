// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/ethprooftest"
)

func fixtureNumber(t *testing.T, f *ethprooftest.Fixture) uint64 {
	t.Helper()
	return f.Header(t).Number.Uint64()
}

// Every captured block checks: each entry proven, the transaction types counted as the block holds them.
func TestCheckBlockProvesEveryCapturedBlock(t *testing.T) {
	for _, name := range ethprooftest.All {
		f := ethprooftest.Load(t, name)
		c, err := ethproof.CheckBlock(context.Background(), agreed(t, honest(f), &ethprooftest.Provider{F: f, NoBlockReceipts: true}),
			fixtureNumber(t, f))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Hash != f.BlockHash() || c.Entries != len(f.Transactions()) {
			t.Fatalf("%s: checked block %s with %d entries; the block is %s with %d", name, c.Hash.Hex(), c.Entries,
				f.BlockHash().Hex(), len(f.Transactions()))
		}
		want := map[uint8]int{}
		for _, tx := range f.Transactions() {
			var typ string
			_ = json.Unmarshal(tx["type"], &typ)
			var n uint8
			for _, ch := range strings.TrimPrefix(typ, "0x") {
				n = n*16 + uint8(strings.IndexRune("0123456789abcdef", ch))
			}
			want[n]++
		}
		for typ, n := range want {
			if c.Types[typ] != n {
				t.Fatalf("%s: %d transactions of type 0x%x counted, the block holds %d", name, c.Types[typ], typ, n)
			}
		}
	}
}

// retype serves every full transaction list with its first transaction restated as type typ: a transaction type the
// encoders do not know, as a chain upgrade would introduce.
func retype(typ string) func(string, []json.RawMessage, json.RawMessage) json.RawMessage {
	return func(method string, _ []json.RawMessage, res json.RawMessage) json.RawMessage {
		if method != "eth_getBlockByHash" && method != "eth_getBlockByNumber" {
			return res
		}
		var b map[string]json.RawMessage
		if json.Unmarshal(res, &b) != nil {
			return res
		}
		var txs []map[string]json.RawMessage
		if json.Unmarshal(b["transactions"], &txs) != nil || len(txs) == 0 {
			return res // hashes only
		}
		txs[0]["type"] = json.RawMessage(`"` + typ + `"`)
		b["transactions"], _ = json.Marshal(txs)
		out, _ := json.Marshal(b)
		return out
	}
}

// A block holding a transaction type no encoder knows - both providers agreeing on it - cannot be proven, and the check
// says so as a refusal naming the type, never as an unread block.
func TestCheckBlockRefusesABlockItCannotProve(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.ArbitrumSepolia)
	_, err := ethproof.CheckBlock(context.Background(), agreed(t, &ethprooftest.Provider{F: f, Mutate: retype("0x7d")},
		&ethprooftest.Provider{F: f, Mutate: retype("0x7d")}), fixtureNumber(t, f))
	if err == nil {
		t.Fatal("a block holding an unknown transaction type checked")
	}
	if errors.Is(err, ethproof.ErrUnread) {
		t.Fatalf("an unprovable block reported as unread: %v", err)
	}
	if !strings.Contains(err.Error(), "0x7d") {
		t.Fatalf("refused, but not by name: %v", err)
	}
}

// A block the providers do not answer or agree on is unread: neither proven nor refused.
func TestCheckBlockNamesAnUnreadBlock(t *testing.T) {
	f := ethprooftest.Load(t, ethprooftest.BaseSepolia)
	_, err := ethproof.CheckBlock(context.Background(), agreed(t, honest(f), &ethprooftest.Provider{F: f, Down: true}), fixtureNumber(t, f))
	if !errors.Is(err, ethproof.ErrUnread) {
		t.Fatalf("one answering provider: %v", err)
	}
	_, err = ethproof.CheckBlock(context.Background(), agreed(t, honest(f), &ethprooftest.Provider{F: f, Mutate: retype("0x7d")}),
		fixtureNumber(t, f))
	if !errors.Is(err, ethproof.ErrUnread) {
		t.Fatalf("disagreeing providers: %v", err)
	}
}

func TestTxTypeOfAnEncoding(t *testing.T) {
	for enc, want := range map[string]uint8{"\xf8\x6b": 0, "\x02\xf8": 2, "\x68\xf8": 0x68, "\x7e\xf8": 0x7e, "": 0} {
		if got := ethproof.TxType([]byte(enc)); got != want {
			t.Fatalf("TxType(%x) = %d, want %d", enc, got, want)
		}
	}
}
