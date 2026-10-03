package strategy

import (
	"context"
	"encoding/json"
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

// RB5-F49: the strategy observer reports a settlement finalized only in the chain's finalized, canonical block. Live
// 2026-10-02 a Sepolia tip reorg replaced block 11832868 (0x032d2bfd… -> 0x7bec386b…) seconds after a settlement landed;
// the RPC's index kept the orphaned hash, and the observer - counting two confirmations past the block the receipt named -
// would call the orphan final.
func TestTheStrategyObserverReportsTheFinalizedCanonicalBlock(t *testing.T) {
	key, _ := crypto.GenerateKey()
	signed, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 80, GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2), Gas: 21000, To: &common.Address{0x10}, Value: big.NewInt(1)}), types.LatestSignerForChainID(big.NewInt(11155111)), key)
	if err != nil {
		t.Fatal(err)
	}
	tx := signed.Hash()
	orphan := common.HexToHash("0x032d2bfd7e06588657809c63cf8cc64276aa14e777cf8e8eb12f669bb5a8b32c")
	canon := &types.Header{Number: big.NewInt(11832868), Difficulty: big.NewInt(0), GasLimit: 30_000_000, Time: 1_790_000_000,
		Extra: []byte("canonical"), BaseFee: big.NewInt(1)}
	finalized := uint64(11832900)

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
			return map[string]interface{}{"transactionHash": tx, "blockHash": block, "blockNumber": "0xb48e24",
				"transactionIndex": "0x0", "status": "0x1", "cumulativeGasUsed": "0x5208", "gasUsed": "0x5208",
				"logs": []interface{}{}, "logsBloom": "0x" + strings.Repeat("00", 256), "type": "0x2", "effectiveGasPrice": "0x1",
				"contractAddress": nil, "from": common.Address{}, "to": common.Address{}}
		}
		switch req.Method {
		case "eth_getTransactionReceipt":
			reply(receipt(orphan))
		case "eth_getBlockByNumber":
			var tag string
			_ = json.Unmarshal(req.Params[0], &tag)
			h := *canon
			if tag == "finalized" {
				h.Number = new(big.Int).SetUint64(finalized)
			}
			reply(&h)
		case "eth_getBlockByHash":
			// The orphaned block is still served by hash, as a node that saw it does.
			h := *canon
			h.Extra = []byte("orphaned")
			reply(&h)
		case "eth_getBlockReceipts":
			reply([]interface{}{receipt(canon.Hash())})
		case "eth_getTransactionByHash":
			raw, _ := signed.MarshalJSON()
			var m map[string]interface{}
			_ = json.Unmarshal(raw, &m)
			m["blockHash"], m["blockNumber"], m["transactionIndex"] = orphan, "0xb48e24", "0x0"
			m["from"] = crypto.PubkeyToAddress(key.PublicKey)
			reply(m)
		case "eth_blockNumber":
			reply(fmt.Sprintf("0x%x", finalized+40))
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"not stubbed: %s"}}`, req.ID, req.Method)
		}
	}))
	defer srv.Close()
	c, err := ethclient.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewEVMObserver(&EVMObserverConfig{Client: c, ChainID: 11155111, ValidatorID: "validator-4",
		RequiredConfirmations: 2, PollingInterval: 5 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.ObserveTransaction(context.Background(), tx)
	if err != nil {
		t.Fatalf("THE regression: a settlement the canonical block holds was not observed: %v", err)
	}
	if !got.IsFinalized || got.BlockHash != canon.Hash().Hex() || got.BlockNumber != 11832868 || got.Status != 1 {
		t.Fatalf("observed %+v; want finalized in the canonical block %s", got, canon.Hash().Hex())
	}

	// One block short of finality: not observed as final.
	finalized = 11832867
	o2, _ := NewEVMObserver(&EVMObserverConfig{Client: c, ChainID: 11155111, RequiredConfirmations: 2,
		PollingInterval: 5 * time.Millisecond, Timeout: 50 * time.Millisecond})
	if res, err := o2.ObserveTransaction(context.Background(), tx); err == nil {
		t.Fatalf("a block not yet finalized was observed: %+v", res)
	}
}
