package execution

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
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

	"github.com/certen/independant-validator/pkg/ethrpc"
)

const (
	readerBlock     = 46979071
	readerBlockTime = 1_790_000_000
	readerChain     = 84532
)

// readerHeader is the block the transaction was mined in; its hash is the block hash the endpoint names.
var readerHeader = &types.Header{Number: big.NewInt(readerBlock), Time: readerBlockTime, Difficulty: big.NewInt(0)}

var readerBlockHash = readerHeader.Hash().Hex()

// readerKey signs the endpoint's transaction; a test key derived from a label, never a real one.
var readerKey = func() *ecdsa.PrivateKey {
	seed := sha256.Sum256([]byte("anchor tx reader test key"))
	k, err := crypto.ToECDSA(seed[:])
	if err != nil {
		panic(err)
	}
	return k
}()

var readerAnchor = common.HexToAddress("0x00000000000000000000000000000000000a1c40")

// readerSignedTx is the transaction the endpoint holds: a real signed EIP-1559 call, so its hash, calldata
// and signer are its own.
var readerSignedTx = signReaderTx(readerKey, readerChain, []byte{0x34, 0x59, 0x7e, 0x5a, 0x00})

func signReaderTx(key *ecdsa.PrivateKey, chainID int64, data []byte) *types.Transaction {
	to := readerAnchor
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(chainID)), &types.DynamicFeeTx{
		ChainID: big.NewInt(chainID), Nonce: 7, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 500000, To: &to, Data: data,
	})
	if err != nil {
		panic(err)
	}
	return tx
}

var readerTx = readerSignedTx.Hash().Hex()

// rpcEndpoint is a JSON-RPC endpoint holding one transaction, with a chosen amount of its history.
// body, when set, replaces the transaction it returns (a lying or confused endpoint); from, when set,
// replaces the sender it states. pruned makes it answer null for the block's receipts, as a backend
// without the block's history does (publicnode, measured 2026-10-03).
type rpcEndpoint struct {
	hasTx, receiptByHash, receiptInBlock, pruned bool
	status                                       string
	body                                         *types.Transaction
	from                                         string
	calls                                        map[string]int
}

// txResult is eth_getTransactionByHash's answer: the signed transaction plus where it was mined and who
// the endpoint says sent it.
func (e *rpcEndpoint) txResult() map[string]any {
	body := readerSignedTx
	if e.body != nil {
		body = e.body
	}
	raw, err := body.MarshalJSON()
	if err != nil {
		panic(err)
	}
	result := map[string]any{}
	if err := json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	from := strings.ToLower(crypto.PubkeyToAddress(readerKey.PublicKey).Hex())
	if e.from != "" {
		from = e.from
	}
	result["from"] = from
	result["blockNumber"] = fmt.Sprintf("0x%x", readerBlock)
	result["blockHash"] = readerBlockHash
	result["transactionIndex"] = "0x0"
	return result
}

// endpointHosts are distinct loopback hosts, so that each endpoint is an independent provider.
var endpointHosts = []string{"127.0.0.1:0", "[::1]:0", "127.0.0.2:0"}

func (e *rpcEndpoint) serve(t *testing.T, host string) string {
	t.Helper()
	e.calls = map[string]int{}
	receipt := map[string]any{
		"transactionHash": readerTx, "transactionIndex": "0x0", "blockHash": readerBlockHash,
		"blockNumber": fmt.Sprintf("0x%x", readerBlock), "cumulativeGasUsed": "0x43e41", "gasUsed": "0x43e41",
		"effectiveGasPrice": "0x1", "logs": []any{}, "logsBloom": "0x" + strings.Repeat("00", 256),
		"status": e.status, "type": "0x2", "contractAddress": nil,
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				result = e.txResult()
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
			if e.pruned {
				result = nil
			}
		case "eth_blockNumber":
			result = fmt.Sprintf("0x%x", readerBlock+99)
		case "eth_getBlockByHash":
			if strings.Contains(string(req.Params), readerBlockHash) {
				result = readerHeader
			}
		case "eth_getBlockByNumber":
			switch {
			case strings.Contains(string(req.Params), fmt.Sprintf(`"0x%x"`, readerBlock)):
				result = readerHeader
			case strings.Contains(string(req.Params), `"latest"`):
				result = &types.Header{Number: big.NewInt(readerBlock + 99), Time: readerBlockTime + 99, Difficulty: big.NewInt(0)}
			}
		case "eth_chainId":
			result = "0x14a34"
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

// readerOver is the repair's reader for Base Sepolia, configured as production configures it: the endpoints, in order,
// as BASE_SEPOLIA_RPC_URL and BASE_SEPOLIA_URL_FALLBACKS, each on its own host.
func readerOver(t *testing.T, endpoints ...*rpcEndpoint) *EthAnchorTxReader {
	t.Helper()
	urls := make([]string, 0, len(endpoints))
	for i, e := range endpoints {
		urls = append(urls, e.serve(t, endpointHosts[i]))
	}
	t.Setenv("BASE_SEPOLIA_RPC_URL", urls[0])
	t.Setenv("BASE_SEPOLIA_URL_FALLBACKS", strings.Join(urls[1:], ","))
	t.Setenv("INFURA_BASE_SEPOLIA_URL", "")
	t.Setenv("ALCHEMY_BASE_SEPOLIA_URL", "")
	r := NewEthAnchorTxReader()
	t.Cleanup(r.Close)
	return r
}

// Production, 2026-09-19: publicnode returns an anchor transaction from two days earlier but holds no
// receipts for its block. The receipt is the one the other providers agree on: the pruned provider is not
// an answer, and is never outvoted by one provider alone.
func TestAnAnchorReadTakesTheReceiptTheOtherProvidersAgreeOn(t *testing.T) {
	pruned := &rpcEndpoint{hasTx: true, status: "0x1", pruned: true}
	full1 := &rpcEndpoint{hasTx: true, receiptByHash: true, receiptInBlock: true, status: "0x1"}
	full2 := &rpcEndpoint{hasTx: true, receiptByHash: true, receiptInBlock: true, status: "0x1"}
	reading, err := readerOver(t, pruned, full1, full2).ReadAnchorTx(context.Background(), 84532, readerTx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !reading.Found || !reading.Succeeded || reading.BlockNumber != readerBlock || reading.BlockHash != readerBlockHash || reading.Head != readerBlock+99 {
		t.Fatalf("reading: %+v", reading)
	}
	signer := strings.ToLower(crypto.PubkeyToAddress(readerKey.PublicKey).Hex())
	if reading.BlockTime != readerBlockTime {
		t.Fatalf("block time %d, want %d from the header its block hash names", reading.BlockTime, readerBlockTime)
	}
	if reading.From != signer || reading.To != strings.ToLower(readerAnchor.Hex()) || !bytes.Equal(reading.Input, readerSignedTx.Data()) {
		t.Fatalf("reading from=%s to=%s input=%x; want the signed transaction's own", reading.From, reading.To, reading.Input)
	}
	if pruned.calls["eth_getBlockReceipts"] == 0 || full1.calls["eth_getBlockReceipts"] == 0 || full2.calls["eth_getBlockReceipts"] == 0 {
		t.Fatalf("every provider is asked: pruned %v, full %v %v", pruned.calls, full1.calls, full2.calls)
	}
}

// A receipt missing by hash is taken from its block's receipts, which do not depend on the tx index.
func TestAnAnchorReceiptIsTakenFromItsBlockWhenTheIndexLacksIt(t *testing.T) {
	reading, err := readerOver(t, &rpcEndpoint{hasTx: true, receiptInBlock: true, status: "0x1"},
		&rpcEndpoint{hasTx: true, receiptInBlock: true, status: "0x1"}).ReadAnchorTx(context.Background(), 84532, readerTx)
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
	reading, err := readerOver(t, &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x0"},
		&rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x0"}).ReadAnchorTx(context.Background(), 84532, readerTx)
	if err != nil || !reading.Found || reading.Succeeded {
		t.Fatalf("reading %+v, %v", reading, err)
	}
}

// RB3-F127: the sender is recovered from the signature, and a transaction is taken only as signed - an
// endpoint that returns another transaction's body, a body signed for another chain, or a sender the
// signature does not bear is refused, never believed.
func TestAnAnchorReadIsTheSignedTransactionAndItsSigner(t *testing.T) {
	stranger, _ := crypto.GenerateKey()
	cases := map[string]func() *rpcEndpoint{
		"another transaction's body": func() *rpcEndpoint {
			return &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x1", body: signReaderTx(readerKey, readerChain, []byte{0xde, 0xad})}
		},
		"signed for another chain": func() *rpcEndpoint {
			return &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x1", body: signReaderTx(readerKey, 11155111, readerSignedTx.Data())}
		},
		"a sender the signature does not bear": func() *rpcEndpoint {
			return &rpcEndpoint{hasTx: true, receiptByHash: true, status: "0x1", from: strings.ToLower(crypto.PubkeyToAddress(stranger.PublicKey).Hex())}
		},
	}
	for name, endpoint := range cases {
		t.Run(name, func(t *testing.T) {
			reading, err := readerOver(t, endpoint(), endpoint()).ReadAnchorTx(context.Background(), readerChain, readerTx)
			if err == nil {
				t.Fatalf("accepted: %+v", reading)
			}
		})
	}
}
