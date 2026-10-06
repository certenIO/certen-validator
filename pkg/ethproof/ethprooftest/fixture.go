// Copyright 2026 Certen Protocol

// Package ethprooftest serves real blocks, captured read-only from the public RPCs of the supported chains, as JSON-RPC
// providers for tests: honest, lying, or down. Tests of the proof builder, the observers and the agreed reads share it.
package ethprooftest

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

// Fixture is one real block: its JSON with full transactions and its receipts, as one provider served them.
type Fixture struct {
	Name         string
	ChainID      int64           `json:"chain_id"`
	Source       string          `json:"source"`
	Captured     string          `json:"captured"`
	SettlementTx common.Hash     `json:"settlement_tx"`
	Block        json.RawMessage `json:"block"`
	Receipts     json.RawMessage `json:"receipts"`

	once     sync.Once
	byHash   map[string]json.RawMessage // transaction objects by lower-case hash
	rcByHash map[string]json.RawMessage // receipt objects by lower-case transaction hash
	light    json.RawMessage            // the block with transaction hashes only
}

func (f *Fixture) index() {
	f.once.Do(func() {
		f.byHash, f.rcByHash = map[string]json.RawMessage{}, map[string]json.RawMessage{}
		var b map[string]json.RawMessage
		_ = json.Unmarshal(f.Block, &b)
		var txs []json.RawMessage
		_ = json.Unmarshal(b["transactions"], &txs)
		var hashes []json.RawMessage
		for _, tx := range txs {
			var h struct {
				Hash json.RawMessage `json:"hash"`
			}
			_ = json.Unmarshal(tx, &h)
			f.byHash[str(h.Hash)] = tx
			hashes = append(hashes, h.Hash)
		}
		b["transactions"], _ = json.Marshal(hashes)
		f.light, _ = json.Marshal(b)
		var rs []json.RawMessage
		_ = json.Unmarshal(f.Receipts, &rs)
		for _, r := range rs {
			var h struct {
				Hash json.RawMessage `json:"transactionHash"`
			}
			_ = json.Unmarshal(r, &h)
			f.rcByHash[str(h.Hash)] = r
		}
	})
}

// The captured blocks (pkg/ethproof/testdata):
//   - Sepolia 11792612: 224 transactions of types 0, 2 and 3 (blob), holding the real settlement 0x9d980cdd… at index 163;
//   - Sepolia 11837286: 79 transactions of types 0, 2, 3 and 4 (EIP-7702 set-code); its "settlement" is the type-4 one;
//   - Base Sepolia 47368146: types 0, 2 and the OP-stack deposit 0x7e, holding the real settlement 0x7a2c8522… at index 7;
//   - Arbitrum Sepolia 312921216: types 2 and Nitro's internal 0x6a, holding the real settlement 0x5ec65d4b… at index 19;
//   - Arbitrum Sepolia 315455204: Nitro's submit-retryable 0x69, its auto-redeem retry 0x68 and the internal 0x6a; its
//     "settlement" is the submit-retryable;
//   - Arbitrum Sepolia 313235886: Nitro's L1 ETH deposit 0x64 and the internal 0x6a; its "settlement" is the deposit;
//   - Arbitrum Sepolia 315677780: Nitro's unsigned 0x65 (delivered by Inbox.sendUnsignedTransaction, Sepolia tx
//     0x14ce4671…) and the internal 0x6a; its "settlement" is the unsigned transaction;
//   - Arbitrum Sepolia 315677781: Nitro's contract 0x66 (Inbox.sendContractTransaction, Sepolia tx 0x997addbc…) and the
//     internal 0x6a; its "settlement" is the contract transaction;
//   - Arbitrum Sepolia 315690738: an ordinary sequencer block - other parties' signed transactions of types 0 and 2 - holding
//     a signed ArbRetryableTx.redeem (0xa67138f2…) and the Nitro retry 0x68 it scheduled: the one Nitro type that shares a
//     block with signed transactions, so a settlement can land beside it. Its "settlement" is the signed redeem.
const (
	Sepolia          = "sepolia_11792612"
	SepoliaSetCode   = "sepolia_11837286"
	BaseSepolia      = "base_sepolia_47368146"
	ArbitrumSepolia  = "arbitrum_sepolia_312921216"
	ArbitrumRetry    = "arbitrum_sepolia_315455204"
	ArbitrumDeposit  = "arbitrum_sepolia_313235886"
	ArbitrumUnsigned = "arbitrum_sepolia_315677780"
	ArbitrumContract = "arbitrum_sepolia_315677781"
	ArbitrumRedeem   = "arbitrum_sepolia_315690738"
)

// All names every captured block.
var All = []string{Sepolia, SepoliaSetCode, BaseSepolia, ArbitrumSepolia, ArbitrumRetry, ArbitrumDeposit, ArbitrumUnsigned,
	ArbitrumContract, ArbitrumRedeem}

// Settlements names the captured blocks whose "settlement" is a signed transaction, as every CERTEN settlement is. The
// Nitro blocks' stand-ins (a submit-retryable, a deposit, an unsigned and a contract transaction) are system transactions no relayer signs: Nitro gives every
// delayed message its own block, so a settlement never shares one with them; they prove the encoders.
var Settlements = []string{Sepolia, SepoliaSetCode, BaseSepolia, ArbitrumSepolia, ArbitrumRedeem}

func testdataDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata")
}

// Load reads a captured block.
func Load(t testing.TB, name string) *Fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdataDir(), name+".json.gz"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	doc, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	f := &Fixture{Name: name}
	if err := json.Unmarshal(doc, f); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return f
}

// Header is the block's header.
func (f *Fixture) Header(t testing.TB) *types.Header {
	t.Helper()
	var h types.Header
	if err := json.Unmarshal(f.Block, &h); err != nil {
		t.Fatalf("fixture %s header: %v", f.Name, err)
	}
	return &h
}

// BlockHash is the block's hash, as the JSON states it.
func (f *Fixture) BlockHash() common.Hash {
	var b struct {
		Hash common.Hash `json:"hash"`
	}
	_ = json.Unmarshal(f.Block, &b)
	return b.Hash
}

// Transactions are the block's transaction objects.
func (f *Fixture) Transactions() []map[string]json.RawMessage {
	var b struct {
		Transactions []map[string]json.RawMessage `json:"transactions"`
	}
	_ = json.Unmarshal(f.Block, &b)
	return b.Transactions
}

// ReceiptList is the block's receipt objects.
func (f *Fixture) ReceiptList() []map[string]json.RawMessage {
	var rs []map[string]json.RawMessage
	_ = json.Unmarshal(f.Receipts, &rs)
	return rs
}

// SettlementIndex is the settlement transaction's index in the block.
func (f *Fixture) SettlementIndex() uint64 {
	for i, tx := range f.Transactions() {
		var h common.Hash
		_ = json.Unmarshal(tx["hash"], &h)
		if h == f.SettlementTx {
			return uint64(i)
		}
	}
	panic(fmt.Sprintf("fixture %s does not hold its settlement", f.Name))
}

// AdiriGenesisJSON is Telcoin Adiri's (2017) block 0 as https://rpc.telcoin.network served it on 2026-10-05
// (eth_getBlockByNumber "0x0", identical on adiri.tel and node1-4.telcoin.network): the genesis the chain catalogue pins
// (RB7 D8). A provider of a captured Adiri block serves it as its block 0, as the real providers do.
const AdiriGenesisJSON = `{"hash":"0x3577ee7223cf0d9a1da1293fd12a47e0e45bb97afcd0427bccd4954cb704baef","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x0eecd2892fe819ad315aa6adbfe965378cbc63659b091539a7e7ea9362aea224","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","logsBloom":"0x` +
	`00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000` +
	`","difficulty":"0x0","number":"0x0","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x69fceea7","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x7","withdrawalsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","blobGasUsed":"0x0","excessBlobGas":"0x0","parentBeaconBlockRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","requestsHash":"0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`

// genesisByChain is the block 0 a provider of a chain's captured block serves.
var genesisByChain = map[int64]string{2017: AdiriGenesisJSON}

// Provider serves a fixture over JSON-RPC.
//
//   - Mutate, when set, may replace the result of any method before it is served (a lying provider);
//   - Down makes every method but eth_chainId fail (a provider that answers nothing);
//   - NoBlockReceipts makes eth_getBlockReceipts unsupported, as sepolia.base.org does.
type Provider struct {
	F               *Fixture
	Mutate          func(method string, params []json.RawMessage, result json.RawMessage) json.RawMessage
	Down            bool
	NoBlockReceipts bool

	mu    sync.Mutex
	calls map[string]int
}

// Calls is how often method was asked.
func (p *Provider) Calls(method string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[method]
}

type request struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

func (p *Provider) answer(req request) (json.RawMessage, *rpcError) {
	p.mu.Lock()
	if p.calls == nil {
		p.calls = map[string]int{}
	}
	p.calls[req.Method]++
	p.mu.Unlock()
	if req.Method == "eth_chainId" {
		return json.RawMessage(fmt.Sprintf(`"%s"`, hexutil.EncodeUint64(uint64(p.F.ChainID)))), nil
	}
	if p.Down {
		return nil, &rpcError{Code: -32000, Message: "backend unavailable"}
	}
	res, rerr := p.honest(req)
	if rerr != nil {
		return nil, rerr
	}
	if p.Mutate != nil {
		res = p.Mutate(req.Method, req.Params, res)
	}
	return res, nil
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// str is a string parameter, lower-cased; a block given as {"blockHash": ...} (rpc.BlockNumberOrHash) is its hash.
func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		var o struct {
			BlockHash string `json:"blockHash"`
		}
		_ = json.Unmarshal(raw, &o)
		s = o.BlockHash
	}
	return strings.ToLower(s)
}

func (p *Provider) honest(req request) (json.RawMessage, *rpcError) {
	f := p.F
	f.index()
	block := func(full bool) json.RawMessage {
		if full {
			return f.Block
		}
		return f.light
	}
	param := func(i int) json.RawMessage {
		if i < len(req.Params) {
			return req.Params[i]
		}
		return nil
	}
	full := func() bool {
		var b bool
		_ = json.Unmarshal(param(1), &b)
		return b
	}
	switch req.Method {
	case "eth_blockNumber":
		var b struct {
			Number string `json:"number"`
		}
		_ = json.Unmarshal(f.Block, &b)
		return json.RawMessage(`"` + b.Number + `"`), nil
	case "eth_getBlockByHash":
		if str(param(0)) != strings.ToLower(f.BlockHash().Hex()) {
			return json.RawMessage("null"), nil
		}
		return block(full()), nil
	case "eth_getBlockByNumber":
		// The captured block is the head, the finalized block and the block at its own height.
		var b struct {
			Number string `json:"number"`
		}
		_ = json.Unmarshal(f.Block, &b)
		switch tag := str(param(0)); tag {
		case "latest", "finalized", "safe", strings.ToLower(b.Number):
			return block(full()), nil
		case "0x0":
			if g, ok := genesisByChain[f.ChainID]; ok {
				return json.RawMessage(g), nil
			}
			return json.RawMessage("null"), nil
		default:
			return json.RawMessage("null"), nil
		}
	case "eth_getBlockReceipts":
		if p.NoBlockReceipts {
			return nil, &rpcError{Code: -32601, Message: "the method eth_getBlockReceipts does not exist/is not available"}
		}
		if str(param(0)) != strings.ToLower(f.BlockHash().Hex()) {
			return json.RawMessage("null"), nil
		}
		return f.Receipts, nil
	case "eth_getTransactionReceipt":
		if r, ok := f.rcByHash[str(param(0))]; ok {
			return r, nil
		}
		return json.RawMessage("null"), nil
	case "eth_getTransactionByHash":
		if tx, ok := f.byHash[str(param(0))]; ok {
			return tx, nil
		}
		return json.RawMessage("null"), nil
	default:
		return nil, &rpcError{Code: -32601, Message: "not served by the fixture: " + req.Method}
	}
}

// ServeHTTP answers single and batched JSON-RPC requests.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	reply := func(req request) map[string]interface{} {
		res, rerr := p.answer(req)
		out := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		if rerr != nil {
			out["error"] = rerr
		} else {
			out["result"] = res
		}
		return out
	}
	w.Header().Set("Content-Type", "application/json")
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '[' {
		var reqs []request
		_ = json.Unmarshal(trimmed, &reqs)
		outs := make([]map[string]interface{}, len(reqs))
		for i, req := range reqs {
			outs[i] = reply(req)
		}
		_ = json.NewEncoder(w).Encode(outs)
		return
	}
	var req request
	_ = json.Unmarshal(body, &req)
	_ = json.NewEncoder(w).Encode(reply(req))
}

// hosts are distinct loopback hosts, so that each provider counts as an independent one (ethrpc.ProviderHosts).
var hosts = []string{"127.0.0.1:0", "[::1]:0", "127.0.0.2:0"}

// URLs serves each provider on its own loopback host and returns their URLs, in order.
func URLs(t testing.TB, ps ...*Provider) []string {
	t.Helper()
	if len(ps) > len(hosts) {
		t.Fatalf("at most %d providers", len(hosts))
	}
	urls := make([]string, len(ps))
	for i, p := range ps {
		l, err := net.Listen("tcp", hosts[i])
		if err != nil {
			t.Fatalf("listen on %s: %v", hosts[i], err)
		}
		srv := httptest.NewUnstartedServer(p)
		srv.Listener = l
		srv.Start()
		t.Cleanup(srv.Close)
		urls[i] = srv.URL
	}
	return urls
}
