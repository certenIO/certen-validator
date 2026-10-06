// Copyright 2026 Certen Protocol

package billing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// RB7 Task 4 (V-3): the fee token, the fee-model family and the fee model of a catalogued chain come from the chain
// catalogue. The live chains answer exactly as before; Telcoin Adiri (2017) answers TEL and the EVM fee model, where
// before it had no symbol and no fee model and every one of its cost events was dropped.

func TestTheLiveChainsFeeTokensAndFamiliesAreUnchanged(t *testing.T) {
	for name, family := range map[string]string{
		"ethereum-sepolia": "ethereum", "sepolia": "ethereum", "eth-sepolia": "ethereum", "Ethereum Sepolia": "ethereum",
		"ETHEREUM_SEPOLIA": "ethereum", "base-sepolia": "base", "Base Sepolia": "base", "arbitrum-sepolia": "arbitrum",
		"Arbitrum Sepolia": "arbitrum", "ethereum  sepolia": "ethereum",
		// Not catalogued: the table, unchanged.
		"ethereum": "ethereum", "arb": "arbitrum", "polygon-amoy": "polygon", "moonbase-alpha": "moonbeam", "bsc-testnet": "bsc",
	} {
		if got := normalizeChain(name); got != family {
			t.Fatalf("normalizeChain(%q) = %q, want %q", name, got, family)
		}
		if NativeSymbolFor(name) == "" {
			t.Fatalf("%q has no fee token", name)
		}
	}
	for name, sym := range map[string]string{
		"ethereum-sepolia": "ETH", "base-sepolia": "ETH", "arbitrum-sepolia": "ETH", "bsc-testnet": "BNB", "polygon-amoy": "POL",
	} {
		if got := NativeSymbolFor(name); got != sym {
			t.Fatalf("NativeSymbolFor(%q) = %q, want %q", name, got, sym)
		}
	}
}

func TestTelcoinAdiriPaysInTELUnderTheEVMFeeModel(t *testing.T) {
	for _, name := range []string{"telcoin-adiri", "Telcoin Adiri", "adiri", "TELCOIN_ADIRI"} {
		if got := NativeSymbolFor(name); got != "TEL" {
			t.Fatalf("NativeSymbolFor(%q) = %q, want TEL", name, got)
		}
		if got := normalizeChain(name); got != "telcoin" {
			t.Fatalf("normalizeChain(%q) = %q", name, got)
		}
		p, err := NewProbe(ProbeConfig{Chain: name, RPCURL: "http://127.0.0.1:1"})
		if err != nil {
			t.Fatalf("NewProbe(%q): %v", name, err)
		}
		if _, ok := p.(*evmProbe); !ok {
			t.Fatalf("NewProbe(%q) = %T", name, p)
		}
	}
	// "telcoin" alone is not a catalogued name (it would be the mainnet): no fee model is guessed for it.
	if _, err := NewProbe(ProbeConfig{Chain: "telcoin", RPCURL: "http://127.0.0.1:1"}); err == nil {
		t.Fatal(`"telcoin" was given a fee model`)
	}
}

// A real Adiri transaction (block 498759, index 0) measured end to end: a valid cost in TEL, not a dropped event.
func TestATelcoinAdiriCostEventIsMeasuredInTEL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method != "eth_getTransactionReceipt" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32601,"message":"no"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"type":"0x2","status":"0x1",` +
			`"gasUsed":"0x76677","effectiveGasPrice":"0x7","blockNumber":"0x79c47",` +
			`"transactionHash":"0x805f571a907aa8e263c1839b63b43b1ed754d019a1be20c383978c6e8fa4b0e8"}}`))
	}))
	defer srv.Close()
	p, err := NewProbe(ProbeConfig{Chain: "telcoin-adiri", ChainID: 2017, RPCURL: srv.URL, Leg: LegAnchor})
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.ObservedCost(context.Background(), "0x805f571a907aa8e263c1839b63b43b1ed754d019a1be20c383978c6e8fa4b0e8")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("the 2017 cost event would be dropped: %v", err)
	}
	if c.NativeSymbol != "TEL" || c.WeiPerNative.String() != "1000000000000000000" || c.NativeAmount.Int64() != 0x76677*7 {
		t.Fatalf("2017 cost %s %s %s", c.NativeSymbol, c.WeiPerNative, c.NativeAmount)
	}
}
