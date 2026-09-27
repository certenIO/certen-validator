// Copyright 2026 Certen Protocol

package strategy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// An RPC that has the settlement's receipt but cannot serve its block header - on a supported chain,
// a node or network fault. The observer used to answer it with a "receipt-only" observation: a block
// timestamp of the validator's own clock, and, when confirmations could not be counted before its
// deadline, the receipt "accepted as finalized". That path exists for TRON's non-standard headers
// alone (RB8); on the supported chains it is an error.
func headerlessRPC(t *testing.T) (string, common.Hash) {
	t.Helper()
	txHash := common.HexToHash("0x7a2c8522fb60d37e63fa2b68bf1abc69c6a70dd25da501ab21ec02c1b50204e7")
	blockHash := common.HexToHash("0x0101010101010101010101010101010101010101010101010101010101010101")
	receipt := map[string]interface{}{
		"type": "0x2", "status": "0x1", "cumulativeGasUsed": "0x5208", "gasUsed": "0x5208",
		"logsBloom": "0x" + strings.Repeat("00", 256), "logs": []interface{}{},
		"transactionHash": txHash.Hex(), "transactionIndex": "0x0",
		"blockHash": blockHash.Hex(), "blockNumber": "0x10", "effectiveGasPrice": "0x1",
		"from": "0x184aef98beacaf3e73ca4a77c72e8f11e9b790a7", "to": "0x184aef98beacaf3e73ca4a77c72e8f11e9b790a7",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := map[string]interface{}{"jsonrpc": "2.0", "id": req.ID}
		switch req.Method {
		case "eth_getTransactionReceipt":
			resp["result"] = receipt
		case "eth_blockNumber":
			resp["result"] = "0x10" // the receipt's own block: never enough confirmations
		default:
			resp["error"] = map[string]interface{}{"code": -32000, "message": fmt.Sprintf("%s unavailable", req.Method)}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, txHash
}

func TestSupportedChainObservationNeverInventsFinality(t *testing.T) {
	url, txHash := headerlessRPC(t)
	client, err := ethclient.Dial(url)
	if err != nil {
		t.Fatal(err)
	}
	for _, chainID := range []int64{11155111, 84532, 421614} {
		obs, err := NewEVMObserver(&EVMObserverConfig{Client: client, ChainID: chainID, ValidatorID: "v",
			RequiredConfirmations: 1, PollingInterval: 10 * time.Millisecond, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		res, err := obs.ObserveTransaction(context.Background(), txHash)
		if err == nil {
			t.Fatalf("chain %d: a settlement whose block header could not be read was observed as finalized=%v at %v (the validator's clock)",
				chainID, res.IsFinalized, res.BlockTimestamp)
		}
	}
}
