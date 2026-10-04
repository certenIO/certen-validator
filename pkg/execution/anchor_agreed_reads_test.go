// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// The repairs that write to the database (`validator repair anchor-blocks`, `repair projections`) read the anchor's
// receipt, block and record through agreeing providers (the rule of RB5-F53). They used to read through ethrpc.Pool: one
// provider at a time, so one provider's word was written as the chain's.

// A single provider serving a forged receipt - success, for a transaction that reverted - is the first one asked.
func TestASingleLyingProvidersReceiptIsNotWrittenAsTheChains(t *testing.T) {
	liar := &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x1"}
	honest := &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x0"}
	reading, err := readerOver(t, liar, honest).ReadAnchorTx(context.Background(), readerChain, readerTx)
	if err == nil {
		t.Fatalf("THE regression: one provider's forged receipt was read as the chain's: succeeded=%v block %d", reading.Succeeded, reading.BlockNumber)
	}
	if !strings.Contains(err.Error(), "providers disagree") {
		t.Fatalf("refused, but not by name: %v", err)
	}
}

// A chain configured with one provider has no agreement to read from: the repair refuses it.
func TestARepairReadOverOneProviderIsRefused(t *testing.T) {
	reading, err := readerOver(t, &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x1"}).ReadAnchorTx(context.Background(), readerChain, readerTx)
	if err == nil {
		t.Fatalf("THE regression: a repair read one provider's receipt as the chain's: %+v", reading)
	}
}

// locateChain is a chain of synthetic blocks 0..locateHead whose block n has time 1000+2n, holding one anchor created in
// block locateCreated by createTx; logs, when set, replaces what the endpoint returns for eth_getLogs (a lying provider).
type locateChain struct {
	logs  func(real []*types.Log) []*types.Log
	calls map[string]int
}

const (
	locateHead    = 110
	locateCreated = 105
)

var (
	locateAnchor    = common.HexToAddress("0x00000000000000000000000000000000000a1c41")
	locateBundle    = [32]byte{0xb1}
	locateRoot      = [32]byte{0x7e}
	locateValidator = common.HexToAddress("0x00000000000000000000000000000000000000c7")
	locateCreateTx  = common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000c7ea7")
	locateForgedTx  = common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000f0f6e")
)

func locateHeader(n uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(n), Time: 1000 + 2*n, Difficulty: big.NewInt(0)}
}

func locateLog(tx common.Hash) *types.Log {
	event := anchorEventsABI.Events["BatchAnchorCreated"]
	h := locateHeader(locateCreated)
	return &types.Log{Address: locateAnchor, Topics: []common.Hash{event.ID, common.Hash(locateBundle), common.Hash(locateRoot),
		common.BytesToHash(locateValidator.Bytes())}, Data: []byte{}, BlockNumber: locateCreated, TxHash: tx, BlockHash: h.Hash()}
}

// anchorsReturn is anchors(bundle) of a V8.1 anchor created by locateValidator at block locateCreated's time.
func anchorsReturn() []byte {
	words := make([][32]byte, 15)
	words[0], words[1] = locateBundle, locateRoot
	words[8] = common.BigToHash(big.NewInt(7))
	words[9] = common.BigToHash(new(big.Int).SetUint64(locateHeader(locateCreated).Time))
	words[10] = common.BytesToHash(locateValidator.Bytes())
	words[11] = common.BigToHash(big.NewInt(1))
	out := make([]byte, 0, 15*32)
	for _, w := range words {
		out = append(out, w[:]...)
	}
	return out
}

func (c *locateChain) serve(t *testing.T, host string) string {
	t.Helper()
	c.calls = map[string]int{}
	real := locateLog(locateCreateTx)
	h := locateHeader(locateCreated)
	receipt := &types.Receipt{Type: types.DynamicFeeTxType, Status: 1, CumulativeGasUsed: 50000, Logs: []*types.Log{real},
		TxHash: locateCreateTx, GasUsed: 50000, BlockHash: h.Hash(), BlockNumber: h.Number, EffectiveGasPrice: big.NewInt(1)}
	receipt.Bloom = types.CreateBloom(receipt)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		c.calls[req.Method]++
		var result any
		switch req.Method {
		case "eth_chainId":
			result = "0x14a34"
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(req.Params[0], &tag)
			if tag == "latest" {
				result = locateHeader(locateHead)
			} else if n, ok := new(big.Int).SetString(strings.TrimPrefix(tag, "0x"), 16); ok && n.Uint64() <= locateHead {
				result = locateHeader(n.Uint64())
			}
		case "eth_call":
			result = "0x" + common.Bytes2Hex(anchorsReturn())
		case "eth_getLogs":
			logs := []*types.Log{real}
			if c.logs != nil {
				logs = c.logs(logs)
			}
			result = logs
		case "eth_getTransactionReceipt":
			var asked common.Hash
			_ = json.Unmarshal(req.Params[0], &asked)
			if asked == locateCreateTx {
				result = receipt
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	})
	l, err := net.Listen("tcp", host)
	if err != nil {
		t.Fatalf("listen on %s: %v", host, err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = l
	server.Start()
	t.Cleanup(server.Close)
	return server.URL
}

func locatorOver(t *testing.T, chains ...*locateChain) *EthAnchorTxReader {
	t.Helper()
	urls := make([]string, 0, len(chains))
	for i, c := range chains {
		urls = append(urls, c.serve(t, endpointHosts[i]))
	}
	t.Setenv("BASE_SEPOLIA_RPC_URL", urls[0])
	t.Setenv("BASE_SEPOLIA_URL_FALLBACKS", strings.Join(urls[1:], ","))
	t.Setenv("INFURA_BASE_SEPOLIA_URL", "")
	t.Setenv("ALCHEMY_BASE_SEPOLIA_URL", "")
	r := NewEthAnchorTxReader()
	t.Cleanup(r.Close)
	return r
}

func TestAnAnchorsCreateIsLocatedThroughAgreeingProviders(t *testing.T) {
	loc, err := locatorOver(t, &locateChain{}, &locateChain{}).LocateAnchorCreate(context.Background(), readerChain, locateAnchor.Hex(),
		locateBundle, locateRoot, locateHead)
	if err != nil {
		t.Fatal(err)
	}
	if loc.TxHash != locateCreateTx.Hex() || loc.Block != locateCreated || loc.Validator != locateValidator {
		t.Fatalf("located %+v", loc)
	}
}

// One provider hides the real create log and invents another; it is the first one asked.
func TestALyingProvidersInventedCreateLogIsNeverTheLocatedCreate(t *testing.T) {
	liar := &locateChain{logs: func([]*types.Log) []*types.Log { return []*types.Log{locateLog(locateForgedTx)} }}
	loc, err := locatorOver(t, liar, &locateChain{}).LocateAnchorCreate(context.Background(), readerChain, locateAnchor.Hex(),
		locateBundle, locateRoot, locateHead)
	if err == nil {
		t.Fatalf("THE regression: one provider's invented log was located as the anchor's create: %s in block %d", loc.TxHash, loc.Block)
	}
	if !strings.Contains(err.Error(), locateForgedTx.Hex()) {
		t.Fatalf("refused, but not naming the invented log's transaction: %v", err)
	}
}

// Keep the helper honest: the forged transaction hash is not one the chain holds.
func TestTheLocateFixtureHoldsOneCreate(t *testing.T) {
	if locateForgedTx == locateCreateTx || crypto.Keccak256Hash(locateForgedTx[:]) == crypto.Keccak256Hash(locateCreateTx[:]) {
		t.Fatal("the fixture's two transactions are one")
	}
	if fmt.Sprint(locateHeader(locateCreated).Hash()) == fmt.Sprint(locateHeader(locateCreated+1).Hash()) {
		t.Fatal("the fixture's blocks are not distinct")
	}
}
