package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// RB5-F49: a settlement is observed in the FINALIZED chain, bound to the canonical block at its height, and read from that
// block when the RPC's index names a block a reorg replaced. Live 2026-10-02: Sepolia block 11832868 was replaced
// (0x032d2bfd… -> 0x7bec386b…) seconds after settlement 0x261b7ed5… landed; the canonical block re-included it, the index
// kept the orphaned hash, and the member was failed for good at one confirmation.

type reorgNode struct {
	tx        common.Hash
	height    uint64
	finalized uint64
	canonical *types.Header // the block at height now
	orphan    common.Hash   // the hash the index still names
	inBlock   bool          // the canonical block holds tx
	signed    *types.Transaction
}

func (n *reorgNode) serve(t *testing.T) *ethclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := func(v interface{}) {
			b, _ := json.Marshal(v)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, b)
		}
		receipt := func(block common.Hash) map[string]interface{} {
			return map[string]interface{}{"transactionHash": n.tx, "blockHash": block, "blockNumber": fmt.Sprintf("0x%x", n.height),
				"transactionIndex": "0x0", "status": "0x1", "cumulativeGasUsed": "0x5208", "gasUsed": "0x5208",
				"logs": []interface{}{}, "logsBloom": "0x" + strings.Repeat("00", 256), "type": "0x2", "effectiveGasPrice": "0x1",
				"contractAddress": nil, "from": common.Address{}, "to": common.Address{}}
		}
		switch req.Method {
		case "eth_getTransactionReceipt":
			reply(receipt(n.orphan))
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(req.Params[0], &tag)
			h := *n.canonical
			if tag == "finalized" {
				h.Number = new(big.Int).SetUint64(n.finalized)
			}
			reply(&h)
		case "eth_getTransactionByHash":
			raw, _ := n.signed.MarshalJSON()
			var m map[string]interface{}
			_ = json.Unmarshal(raw, &m)
			m["blockHash"], m["blockNumber"], m["transactionIndex"] = n.orphan, fmt.Sprintf("0x%x", n.height), "0x0"
			reply(m)
		case "eth_blockNumber":
			reply(fmt.Sprintf("0x%x", n.finalized+40))
		case "eth_getBlockReceipts":
			if n.inBlock {
				reply([]interface{}{receipt(n.canonical.Hash())})
			} else {
				reply([]interface{}{})
			}
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not stubbed: %s"}}`, req.ID, req.Method)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func reorgObserver(c *ethclient.Client) *ExternalChainObserver {
	return &ExternalChainObserver{ethClient: c, chainID: 11155111, pollingInterval: 5 * time.Millisecond}
}

func canonicalAt(height uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(height), Difficulty: big.NewInt(0), GasLimit: 30_000_000,
		Time: 1_790_000_000, Extra: []byte("canonical"), BaseFee: big.NewInt(1)}
}

func TestASettlementIsReadFromTheFinalizedCanonicalBlockWhenTheIndexIsStale(t *testing.T) {
	tx := common.HexToHash("0x261b7ed5bd643d79b4b5867377fbd161d13002864ee77d868e9af775800d7c64")
	canon := canonicalAt(11832868)
	n := &reorgNode{tx: tx, height: 11832868, finalized: 11832900, canonical: canon,
		orphan: common.HexToHash("0x032d2bfd7e06588657809c63cf8cc64276aa14e777cf8e8eb12f669bb5a8b32c"), inBlock: true}
	got, err := reorgObserver(n.serve(t)).settledInFinalizedChain(context.Background(), tx, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("THE regression: a settlement re-included by the canonical block was refused: %v", err)
	}
	if got.BlockHash != canon.Hash() || got.Status != 1 {
		t.Fatalf("the receipt names %s, the canonical block is %s", got.BlockHash.Hex(), canon.Hash().Hex())
	}
}

func TestASettlementIsNotObservedBeforeItsBlockIsFinalized(t *testing.T) {
	tx := common.HexToHash("0x01")
	canon := canonicalAt(500)
	n := &reorgNode{tx: tx, height: 500, finalized: 499, canonical: canon, orphan: canon.Hash(), inBlock: true}
	_, err := reorgObserver(n.serve(t)).settledInFinalizedChain(context.Background(), tx, time.Now().Add(50*time.Millisecond))
	if !errors.Is(err, ErrNotYetFinalized) {
		t.Fatalf("one block short of finality: %v", err)
	}
}

func TestASettlementWhoseIndexIsCurrentIsReadDirectly(t *testing.T) {
	tx := common.HexToHash("0x02")
	canon := canonicalAt(600)
	n := &reorgNode{tx: tx, height: 600, finalized: 600, canonical: canon, orphan: canon.Hash()}
	got, err := reorgObserver(n.serve(t)).settledInFinalizedChain(context.Background(), tx, time.Now().Add(time.Second))
	if err != nil || got.BlockHash != canon.Hash() {
		t.Fatalf("(%v, %v)", got, err)
	}
}

func TestASettlementTheFinalizedBlockDoesNotHoldIsFollowedNotAccepted(t *testing.T) {
	tx := common.HexToHash("0x03")
	canon := canonicalAt(700)
	n := &reorgNode{tx: tx, height: 700, finalized: 800, canonical: canon, orphan: common.HexToHash("0xdead"), inBlock: false}
	_, err := reorgObserver(n.serve(t)).settledInFinalizedChain(context.Background(), tx, time.Now().Add(50*time.Millisecond))
	if err == nil || !strings.Contains(err.Error(), "not in the finalized chain") {
		t.Fatalf("a transaction the finalized block does not hold: %v", err)
	}
}

// Through the observer's public entry point, as Phase 7 and the settlement gate call it. Before RB5-F49 the stale index's
// orphaned hash met the canonical header at its height and the observation failed ("header binding failed") - the live
// failure of the cross-chain intent's Sepolia leg.
func TestTheObserverReportsTheSettlementInItsFinalizedCanonicalBlock(t *testing.T) {
	key, _ := crypto.GenerateKey()
	signed, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 80, GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2), Gas: 21000, To: &common.Address{0x10}, Value: big.NewInt(1)}),
		types.LatestSignerForChainID(big.NewInt(11155111)), key)
	if err != nil {
		t.Fatal(err)
	}
	canon := canonicalAt(11832868)
	n := &reorgNode{tx: signed.Hash(), height: 11832868, finalized: 11832900, canonical: canon, signed: signed,
		orphan: common.HexToHash("0x032d2bfd7e06588657809c63cf8cc64276aa14e777cf8e8eb12f669bb5a8b32c"), inBlock: true}
	o := reorgObserver(n.serve(t))
	o.timeout, o.requiredConfirmations = time.Second, 1
	got, err := o.ObserveTransaction(context.Background(), signed.Hash())
	if err != nil {
		t.Fatalf("THE regression: a settlement the finalized canonical block holds was not observed: %v", err)
	}
	if got.BlockHash != canon.Hash() || got.BlockNumber.Uint64() != 11832868 || got.Status != 1 {
		t.Fatalf("observed block %s at %d status %d; want the canonical %s", got.BlockHash.Hex(), got.BlockNumber, got.Status, canon.Hash().Hex())
	}
}
