package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

const (
	readerTx        = "0xbafab491071b28f21956c82317abe2a531bb41ad89880153901991f15fb3da58"
	readerBlockHash = "0x0f5a778e4b18d354c87f9e6ea965b0832cb7fa71e92710abddd69308d5fdf0a1"
	readerBlock     = 46979071
)

// rpcEndpoint is a JSON-RPC endpoint holding one transaction, with a chosen amount of its history.
type rpcEndpoint struct {
	hasTx, receiptByHash, receiptInBlock bool
	status                               string
	calls                                map[string]int
}

func (e *rpcEndpoint) serve(t *testing.T) string {
	t.Helper()
	e.calls = map[string]int{}
	receipt := map[string]any{
		"transactionHash": readerTx, "transactionIndex": "0x0", "blockHash": readerBlockHash,
		"blockNumber": fmt.Sprintf("0x%x", readerBlock), "cumulativeGasUsed": "0x43e41", "gasUsed": "0x43e41",
		"effectiveGasPrice": "0x1", "logs": []any{}, "logsBloom": "0x" + strings.Repeat("00", 256),
		"status": e.status, "type": "0x2", "contractAddress": nil,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		e.calls[req.Method]++
		var result any
		switch req.Method {
		case "eth_getTransactionByHash":
			if e.hasTx {
				result = map[string]any{"hash": readerTx, "blockNumber": fmt.Sprintf("0x%x", readerBlock),
					"blockHash": readerBlockHash, "input": "0x34597e5a00"}
			}
		case "eth_getTransactionReceipt":
			if e.receiptByHash {
				result = receipt
			}
		case "eth_getBlockReceipts":
			result = []any{}
			// Only the transaction's own block holds its receipt.
			if e.receiptInBlock && strings.Contains(string(req.Params), readerBlockHash) {
				result = []any{receipt}
			}
		case "eth_blockNumber":
			result = fmt.Sprintf("0x%x", readerBlock+99)
		case "eth_chainId":
			result = "0x14a34"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func readerOver(t *testing.T, endpoints ...*rpcEndpoint) *EthAnchorTxReader {
	t.Helper()
	urls := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		urls = append(urls, e.serve(t))
	}
	pool, err := ethrpc.NewPool(urls, time.Minute, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	r := NewEthAnchorTxReader()
	r.pools[84532] = pool
	return r
}

// Production, 2026-09-19: publicnode returns an anchor transaction from two days earlier but holds no
// receipts for its block. The read moves on to the next provider rather than refusing the anchor.
func TestAnAnchorReadMovesPastAnEndpointWithoutTheReceipt(t *testing.T) {
	pruned := &rpcEndpoint{hasTx: true, status: "0x1"}
	full := &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x1"}
	reading, err := readerOver(t, pruned, full).ReadAnchorTx(context.Background(), 84532, readerTx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !reading.Found || !reading.Succeeded || reading.BlockNumber != readerBlock || reading.BlockHash != readerBlockHash || reading.Head != readerBlock+99 {
		t.Fatalf("reading: %+v", reading)
	}
	if pruned.calls["eth_getBlockReceipts"] != 1 || full.calls["eth_getTransactionReceipt"] != 1 {
		t.Fatalf("calls: pruned %v, full %v", pruned.calls, full.calls)
	}
}

// A receipt missing by hash is taken from its block's receipts, which do not depend on the tx index.
func TestAnAnchorReceiptIsTakenFromItsBlockWhenTheIndexLacksIt(t *testing.T) {
	endpoint := &rpcEndpoint{hasTx: true, receiptInBlock: true, status: "0x1"}
	reading, err := readerOver(t, endpoint).ReadAnchorTx(context.Background(), 84532, readerTx)
	if err != nil || reading.BlockNumber != readerBlock || !reading.Succeeded {
		t.Fatalf("reading %+v, %v", reading, err)
	}
}

// When no provider holds the history the read fails; it never reports the transaction as absent.
func TestAnAnchorNoProviderHoldsIsUnreadableNotAbsent(t *testing.T) {
	_, err := readerOver(t, &rpcEndpoint{hasTx: true, status: "0x1"}, &rpcEndpoint{}).ReadAnchorTx(context.Background(), 84532, readerTx)
	if !errors.Is(err, ethrpc.ErrEndpointLacksHistory) {
		t.Fatalf("err = %v, want every endpoint to lack the history", err)
	}
}

// A reverted anchor transaction reads as reverted.
func TestARevertedAnchorReadsAsReverted(t *testing.T) {
	reading, err := readerOver(t, &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x0"}).ReadAnchorTx(context.Background(), 84532, readerTx)
	if err != nil || !reading.Found || reading.Succeeded {
		t.Fatalf("reading %+v, %v", reading, err)
	}
}
