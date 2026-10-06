// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/supportedchains"
)

// =============================================================================
// A simulated chain whose blocks exist only when a transaction lands (Telcoin Adiri, RB7 Phase A F-BLK-1)
// =============================================================================
//
// Block n has the time the chain committed it at (commitAt, the consensus time - never decreasing), finalized == latest,
// and a block is made only by mine: a transaction sent to the chain, or an epoch close the test makes. It is read both
// directly (HeaderByNumber: a chain clock's source) and over JSON-RPC (serve: what a validator's single client and its
// sender use), so the production sender, settleMember and the heartbeat all run against it.

type simIdleChain struct {
	mu       sync.Mutex
	chainID  int64
	headers  []*types.Header
	receipts map[common.Hash]*types.Receipt
	nonces   map[common.Address]uint64
	balance  *big.Int
	baseFee  *big.Int
	// commitAt is the consensus time a block made now is committed at.
	commitAt func() uint64
	// sent are the transactions that landed, in order.
	sent []*types.Transaction
	// reads counts JSON-RPC calls by method.
	reads map[string]int
}

func newSimIdleChain(chainID int64, genesisTime uint64) *simIdleChain {
	c := &simIdleChain{chainID: chainID, receipts: map[common.Hash]*types.Receipt{}, nonces: map[common.Address]uint64{},
		balance: new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), baseFee: big.NewInt(7), reads: map[string]int{}}
	c.headers = []*types.Header{c.headerAt(0, genesisTime, common.Hash{})}
	return c
}

func (c *simIdleChain) headerAt(n, t uint64, parent common.Hash) *types.Header {
	return &types.Header{ParentHash: parent, Number: new(big.Int).SetUint64(n), Time: t, Difficulty: big.NewInt(0),
		GasLimit: 30_000_000, BaseFee: new(big.Int).Set(c.baseFee), Extra: []byte(fmt.Sprintf("sim-%d", c.chainID)),
		UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash}
}

// mine makes one block at time t (never before its parent's), holding txs.
func (c *simIdleChain) mine(t uint64, txs ...*types.Transaction) *types.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mineLocked(t, txs...)
}

func (c *simIdleChain) mineLocked(t uint64, txs ...*types.Transaction) *types.Header {
	parent := c.headers[len(c.headers)-1]
	if t < parent.Time {
		t = parent.Time // a block's time is at least its parent's (F-BLK-6)
	}
	h := c.headerAt(parent.Number.Uint64()+1, t, parent.Hash())
	c.headers = append(c.headers, h)
	for i, tx := range txs {
		r := &types.Receipt{Type: tx.Type(), Status: types.ReceiptStatusSuccessful, CumulativeGasUsed: 21000, TxHash: tx.Hash(),
			GasUsed: 21000, BlockHash: h.Hash(), BlockNumber: h.Number, TransactionIndex: uint(i), EffectiveGasPrice: c.baseFee,
			Logs: []*types.Log{}}
		r.Bloom = types.CreateBloom(r)
		c.receipts[tx.Hash()] = r
		c.sent = append(c.sent, tx)
	}
	return h
}

func (c *simIdleChain) head() *types.Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.headers[len(c.headers)-1]
}

func (c *simIdleChain) sentCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

// HeaderByNumber is the chain read directly: latest, safe and finalized are all the head (F-FIN-1).
func (c *simIdleChain) HeaderByNumber(_ context.Context, number *big.Int) (*types.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if number == nil || number.Sign() < 0 {
		return c.headers[len(c.headers)-1], nil
	}
	if n := number.Uint64(); n < uint64(len(c.headers)) {
		return c.headers[n], nil
	}
	return nil, ethereum.NotFound
}

// sendRaw lands a signed transaction in a block of its own, committed at commitAt.
func (c *simIdleChain) sendRaw(raw []byte) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return common.Hash{}, err
	}
	from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(c.chainID)), tx)
	if err != nil {
		return common.Hash{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.receipts[tx.Hash()]; ok {
		return tx.Hash(), nil
	}
	if tx.Nonce() != c.nonces[from] {
		return common.Hash{}, fmt.Errorf("nonce too low")
	}
	cost := new(big.Int).Mul(tx.GasFeeCap(), new(big.Int).SetUint64(tx.Gas()))
	if c.balance.Cmp(cost) < 0 {
		return common.Hash{}, fmt.Errorf("insufficient funds for gas * price + value")
	}
	c.nonces[from]++
	c.mineLocked(c.commitAt(), tx)
	return tx.Hash(), nil
}

// serve answers the JSON-RPC a validator's client and sender use, and returns a client of it.
func (c *simIdleChain) serve(t *testing.T) *ethclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		c.mu.Lock()
		c.reads[req.Method]++
		c.mu.Unlock()
		var result interface{}
		var rerr string
		param := func(i int) string {
			var s string
			if i < len(req.Params) {
				_ = json.Unmarshal(req.Params[i], &s)
			}
			return s
		}
		switch req.Method {
		case "eth_chainId":
			result = hexutil.EncodeUint64(uint64(c.chainID))
		case "eth_blockNumber":
			result = hexutil.EncodeUint64(c.head().Number.Uint64())
		case "eth_getBlockByNumber":
			var n *big.Int
			switch tag := param(0); tag {
			case "latest", "finalized", "safe", "pending":
			default:
				v, _ := hexutil.DecodeUint64(tag)
				n = new(big.Int).SetUint64(v)
			}
			h, err := c.HeaderByNumber(r.Context(), n)
			if err == nil {
				result = h
			}
		case "eth_getTransactionCount":
			var a common.Address
			_ = json.Unmarshal(req.Params[0], &a)
			c.mu.Lock()
			result = hexutil.EncodeUint64(c.nonces[a])
			c.mu.Unlock()
		case "eth_getBalance":
			c.mu.Lock()
			result = (*hexutil.Big)(new(big.Int).Set(c.balance))
			c.mu.Unlock()
		case "eth_maxPriorityFeePerGas":
			result = "0x0"
		case "eth_gasPrice":
			result = (*hexutil.Big)(c.head().BaseFee)
		case "eth_call":
			result = hexutil.Bytes(make([]byte, 32)) // isLeafConsumed: false
		case "eth_getCode":
			result = hexutil.Bytes{0x60}
		case "eth_getLogs":
			result = []interface{}{}
		case "eth_sendRawTransaction":
			raw, _ := hexutil.Decode(param(0))
			h, err := c.sendRaw(raw)
			if err != nil {
				rerr = err.Error()
			} else {
				result = h
			}
		case "eth_getTransactionReceipt":
			var h common.Hash
			_ = json.Unmarshal(req.Params[0], &h)
			c.mu.Lock()
			if rc, ok := c.receipts[h]; ok {
				result = rc
			}
			c.mu.Unlock()
		default:
			rerr = "not simulated: " + req.Method
		}
		w.Header().Set("Content-Type", "application/json")
		if rerr != "" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]interface{}{"code": -32000, "message": rerr}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "result": result})
	}))
	t.Cleanup(srv.Close)
	cl, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cl.Close)
	return cl
}

// =============================================================================
// A validator on the simulated chain
// =============================================================================

// simValidator is one validator's view of a simulated chain: its key, its orchestrator (single client and sender), and
// the process's clock and heartbeat for the chain.
type simValidator struct {
	ordinal int
	key     *ecdsa.PrivateKey
	orch    *BatchOrchestrator
	beat    *chainHeartbeat
	clock   *ChainClock
	wall    *time.Time
}

// newSimValidator wires validator `ordinal` to chain: the chain's clock reads the chain, the heartbeat sends through the
// orchestrator's real sender (sendHeartbeat) and is triggered by *wall. register installs the clock as the process's
// clock of the chain, as NewBatchStack does.
func newSimValidator(t *testing.T, chain *simIdleChain, ordinal int, wall *time.Time, register bool) *simValidator {
	t.Helper()
	t.Setenv("CERTEN_TX_OUTBOX_DIR", t.TempDir())
	// The simulated chain is its own incarnation: pinned, as an operator re-pins a chain (RB7 D8).
	t.Setenv(supportedchains.GenesisEnvFor(chain.chainID), chain.headers[0].Hash().Hex())
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(chain.chainID))
	if err != nil {
		t.Fatal(err)
	}
	client := chain.serve(t)
	ecm := &EthereumContractManager{client: client, auth: auth, config: &CertenContractConfig{ChainID: chain.chainID, MaxGasPriceGwei: 1}}
	o := &BatchOrchestrator{ecm: ecm, logf: t.Logf, attempts: map[[32]byte]int{}}
	clock := newChainClock(chain.chainID, chain)
	if register {
		clock = installSimClock(t, chain.chainID, chain)
	}
	o.clock = clock
	v := &simValidator{ordinal: ordinal, key: key, orch: o, clock: clock, wall: wall}
	v.beat = newChainHeartbeat(clock, func(context.Context) (int, error) { return ordinal, nil }, o.sendHeartbeat, t.Logf)
	v.beat.now = func() time.Time { return *wall }
	if err := clock.setHeartbeat(v.beat); err != nil {
		t.Fatal(err)
	}
	return v
}

// installSimClock makes src the process's clock of chainID for the test.
func installSimClock(t *testing.T, chainID int64, src chainClockSource) *ChainClock {
	t.Helper()
	chainClocks.Lock()
	prev, had := chainClocks.m[chainID]
	c := newChainClock(chainID, src)
	chainClocks.m[chainID] = c
	chainClocks.Unlock()
	t.Cleanup(func() {
		chainClocks.Lock()
		defer chainClocks.Unlock()
		if had {
			chainClocks.m[chainID] = prev
		} else {
			delete(chainClocks.m, chainID)
		}
	})
	return c
}

// simResolver is the batch path's chain managers over simulated chains: what resolverNonSettlementChain reads.
type simResolver map[int64]*EthereumContractManager

func (r simResolver) ManagerForChain(chainID int64) (*EthereumContractManager, common.Address, error) {
	m, ok := r[chainID]
	if !ok {
		return nil, common.Address{}, fmt.Errorf("no chain %d", chainID)
	}
	return m, common.Address{}, nil
}

// tick is one heartbeat round of v at its wall time.
func (v *simValidator) tick(t *testing.T) HeartbeatOutcome {
	t.Helper()
	o, err := v.beat.Tick(context.Background())
	if err != nil && o != HeartbeatUnfunded && o != HeartbeatGasCeiling && o != HeartbeatRefused {
		t.Fatalf("validator %d heartbeat: %s: %v", v.ordinal, o, err)
	}
	return o
}

// rpcFinalized is the finalized tag as a *big.Int, for direct reads.
var rpcFinalized = big.NewInt(int64(rpc.FinalizedBlockNumber))
